use crate::detect;
use crate::dict;
use crate::http;
use crate::output::OutputWriter;

use futures::stream::{FuturesUnordered, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use rand::seq::SliceRandom;
use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE, LOCATION};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// 扫描运行的核心配置
pub struct ScanConfig {
    pub targets: Vec<String>,
    pub max_workers: usize,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    pub max_timeouts: usize,
    pub proxies: Vec<String>,
    pub output: Arc<OutputWriter>,
    pub prefixes: Vec<String>,
    pub min_delay_ms: u64,
    pub max_delay_ms: u64,
    pub min_size: u64,
    pub resume: bool,
}

// ── 进度文件辅助函数 ────────────────────────────────────────────

fn progress_file_path() -> PathBuf {
    PathBuf::from(".progress")
}

/// 加载已扫描的URL进度
fn load_progress() -> HashSet<String> {
    let path = progress_file_path();
    match std::fs::read_to_string(&path) {
        Ok(content) => content.lines().map(|l| l.trim().to_string()).collect(),
        Err(_) => HashSet::new(),
    }
}

/// 保存单条URL到进度文件
fn save_progress(url: &str) {
    use std::io::Write;
    let path = progress_file_path();
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(f, "{}", url);
    }
}

/// 清除进度文件（非恢复模式时调用）
fn clear_progress() {
    let path = progress_file_path();
    let _ = std::fs::remove_file(&path);
}

// ── 站点可达性检测 ───────────────────────────────────────────────

/// 检测目标站点是否可访问，只在网络层不可达时跳过
async fn is_site_accessible(base_url: &str, client: &reqwest::Client) -> (bool, String) {
    match client
        .get(base_url)
        .headers(http::make_headers())
        .send()
        .await
    {
        Ok(resp) => {
            let code = resp.status().as_u16();
            (true, format!("http_status_{}", code))
        }
        Err(e) => {
            if e.is_connect() {
                (false, format!("连接错误: {}", e))
            } else if e.is_timeout() {
                (false, format!("超时: {}", e))
            } else {
                (false, format!("请求错误: {}", e))
            }
        }
    }
}

// ── 404指纹探测 ────────────────────────────────────────────────

/// 请求一个随机不存在的文件，采集其响应指纹用于后续过滤假阳性
async fn get_not_found_fingerprint(
    base_url: &str,
    client: &reqwest::Client,
) -> Option<detect::ResponseFingerprint> {
    let marker = format!(
        "__ihoney_not_found__{}.txt",
        uuid::Uuid::new_v4().as_simple()
    );
    let base = base_url.trim_end_matches('/');
    let probe_url = format!("{}/{}", base, marker);

    let resp = match client
        .get(&probe_url)
        .headers(http::make_range_headers())
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return None,
    };

    let status = resp.status().as_u16();
    let headers = resp.headers().clone();

    // 读取少量样本用于指纹识别
    let body = resp.bytes().await.unwrap_or_default();
    let sample: Vec<u8> = body.iter().take(64).copied().collect();

    if [404, 410, 301, 302, 303, 307, 308, 200, 403].contains(&status) {
        Some(detect::build_fingerprint(status, &headers, &sample))
    } else {
        None
    }
}

// ── 单URL检测（单阶段GET请求）──────────────────────────────────

/// 单条URL检测结果
enum CheckResult {
    Hit { url: String, size: u64 },   // 命中：发现备份文件
    Timeout,                           // 超时
    Skip,                              // 跳过：非备份文件
}

/// 对单个候选URL执行检测
/// 使用一次 GET Range: bytes=0-63 请求完成全部判断，无需两阶段 HEAD+GET
async fn check_url(
    url: &str,
    client: &reqwest::Client,
    not_found_fp: &Option<detect::ResponseFingerprint>,
    min_size: u64,
) -> CheckResult {
    // 单次 GET 请求，仅获取前64字节
    let resp = match client
        .get(url)
        .headers(http::make_range_headers())
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return if e.is_timeout() {
                CheckResult::Timeout
            } else {
                CheckResult::Skip
            };
        }
    };

    let status = resp.status().as_u16();
    let headers = resp.headers().clone();

    let content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();
    let content_length: u64 = headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let location = headers
        .get(LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let suffix = detect::get_candidate_suffix(url);

    // 快速排除（读取body前）
    if status == 404 || status == 410 {
        return CheckResult::Skip;
    }
    if detect::is_probably_redirect_trap(status, &location) {
        return CheckResult::Skip;
    }

    // Content-Disposition: attachment + 足够大小 → 命中
    if detect::has_download_disposition(&headers) && content_length > min_size {
        return CheckResult::Hit {
            url: url.to_string(),
            size: content_length,
        };
    }

    // 备份文件MIME类型 + 足够大小 → 命中（后续还需指纹校验）
    if detect::is_likely_backup_response(status, &content_type) && content_length > min_size {
        // 先不急着返回命中，等下面读取body后做指纹校验
    }

    // 读取响应体前64字节用于深度检测
    let body = resp.bytes().await.unwrap_or_default();
    let sample: Vec<u8> = body.iter().take(64).copied().collect();

    // 与已知404指纹比对 → 跳过
    if detect::fingerprint_matches(status, &headers, &sample, not_found_fp) {
        return CheckResult::Skip;
    }

    // 指纹校验后重新检查 Content-Disposition
    if detect::has_download_disposition(&headers) && content_length > min_size {
        return CheckResult::Hit {
            url: url.to_string(),
            size: content_length,
        };
    }

    // 备份文件MIME类型 + 足够大小 → 命中
    if detect::is_likely_backup_response(status, &content_type) && content_length > min_size {
        return CheckResult::Hit {
            url: url.to_string(),
            size: content_length,
        };
    }

    // Magic bytes 文件头检测
    if !sample.is_empty() && detect::has_known_magic(&sample, suffix) {
        let size = if content_length > 0 {
            content_length
        } else {
            sample.len() as u64
        };
        return CheckResult::Hit {
            url: url.to_string(),
            size,
        };
    }

    // 文本备份检测（如 .sql 导出文件以 text/plain 返回）
    if detect::looks_like_text_backup(suffix, &content_type)
        && !detect::is_likely_text_error(&sample)
    {
        let size = if content_length > 0 {
            content_length
        } else {
            sample.len() as u64
        };
        if size >= min_size || min_size == 0 {
            return CheckResult::Hit {
                url: url.to_string(),
                size,
            };
        }
    }

    CheckResult::Skip
}

// ── 主扫描入口 ────────────────────────────────────────────────

/// 批量扫描所有目标站点
pub async fn scan_targets(config: ScanConfig) {
    let total_sites = config.targets.len();
    let resumed_urls = if config.resume {
        load_progress()
    } else {
        clear_progress();
        HashSet::new()
    };

    for (idx, base_url) in config.targets.iter().enumerate() {
        println!("[{}/{}] {}", idx + 1, total_sites, base_url);

        // 每个站点构建新客户端（多代理时自动轮换）
        let client = http::build_client(config.connect_timeout, config.read_timeout, &config.proxies);

        // 站点可达性检测
        let (accessible, reason) = is_site_accessible(base_url, &client).await;
        if !accessible {
            println!("  -> 跳过: {}", reason);
            continue;
        }

        // 采集404指纹
        let not_found_fp = get_not_found_fingerprint(base_url, &client).await;

        // 生成候选URL列表
        let mut candidates = dict::generate_candidates(
            base_url,
            &config.prefixes,
            dict::SUFFIX_FORMAT,
            dict::SUB_PATHS,
        );

        if candidates.is_empty() {
            println!("  -> 跳过: 未生成候选URL");
            continue;
        }

        // 恢复模式下过滤已扫描的URL
        if config.resume && !resumed_urls.is_empty() {
            candidates.retain(|c| !resumed_urls.contains(c));
            if candidates.is_empty() {
                println!("  -> 跳过: 所有候选URL已扫描过（恢复模式）");
                continue;
            }
        }

        // 打乱候选顺序，避免被WAF识别扫描模式
        {
            let mut rng = rand::thread_rng();
            candidates.shuffle(&mut rng);
        }

        let site_count = candidates.len();
        let pb = ProgressBar::new(site_count as u64);
        pb.set_style(
            ProgressStyle::with_template("  {msg} [{bar:40}] {pos}/{len} ({per_sec})")
                .unwrap()
                .progress_chars("=> "),
        );
        pb.set_message("扫描中".to_string());

        let timeout_count = Arc::new(AtomicUsize::new(0));
        let aborted = Arc::new(AtomicBool::new(false));
        let semaphore = Arc::new(Semaphore::new(config.max_workers));

        let mut futs = FuturesUnordered::new();

        for candidate in candidates {
            if aborted.load(Ordering::Relaxed) {
                pb.inc(1);
                continue;
            }

            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let client = client.clone();
            let not_found_fp = not_found_fp.clone();
            let output = config.output.clone();
            let timeout_count = timeout_count.clone();
            let aborted = aborted.clone();
            let pb = pb.clone();
            let max_timeouts = config.max_timeouts;
            let min_size = config.min_size;
            let min_delay_ms = config.min_delay_ms;
            let max_delay_ms = config.max_delay_ms;
            let resume = config.resume;

            futs.push(tokio::spawn(async move {
                let _permit = permit; // 持有信号量直到任务完成

                if aborted.load(Ordering::Relaxed) {
                    pb.inc(1);
                    return;
                }

                // 请求间随机延迟（限速）
                http::random_delay(min_delay_ms, max_delay_ms).await;

                let result = check_url(&candidate, &client, &not_found_fp, min_size).await;
                pb.inc(1);

                match result {
                    CheckResult::Hit { ref url, size } => {
                        if !output.is_duplicate(url) {
                            output.write_hit(url, size).await;
                            let size_str = crate::output::humanize_size(size);
                            eprintln!("[ 发现 ] {}  大小: {}", url, size_str);
                        }
                    }
                    CheckResult::Timeout => {
                        let count = timeout_count.fetch_add(1, Ordering::Relaxed) + 1;
                        if count >= max_timeouts {
                            aborted.store(true, Ordering::Relaxed);
                            eprintln!(
                                "  -> 跳过: 超时次数过多 ({}>{})",
                                count, max_timeouts
                            );
                        }
                    }
                    CheckResult::Skip => {}
                }

                // 保存扫描进度
                if resume {
                    save_progress(&candidate);
                }
            }));
        }

        // 等待所有异步任务完成
        while futs.next().await.is_some() {}

        pb.finish_and_clear();
    }

    println!("扫描完成。");
}
