mod detect;
mod dict;
mod http;
mod output;
mod scanner;

use clap::Parser;
use output::{OutputFormat, OutputWriter};
use scanner::ScanConfig;
use std::collections::HashSet;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "bakscan",
    about = "网站备份文件泄露扫描工具",
    after_help = "示例:\n  bakscan -t 20 -f url.txt -o result.txt\n  bakscan -u https://www.example.com/ -o result.txt\n  bakscan -u https://example.com/ -p socks5://127.0.0.1:1080 -p http://proxy2:8080"
)]
struct Cli {
    /// 批量URL文件（每行一个）
    #[arg(short = 'f', long = "url-file")]
    url_file: Option<PathBuf>,

    /// 最大并发请求数（默认20）
    #[arg(short = 't', long = "thread", default_value_t = 20)]
    max_threads: usize,

    /// 单个目标URL
    #[arg(short = 'u', long = "url")]
    url: Option<String>,

    /// 自定义字典文件（追加到默认字典）
    #[arg(short = 'd', long = "dict-file")]
    dict_file: Option<PathBuf>,

    /// 输出结果文件（默认 result.txt）
    #[arg(short = 'o', long = "output-file", default_value = "result.txt")]
    output_file: PathBuf,

    /// 代理地址（可多次指定：-p socks5://a -p http://b）
    #[arg(short = 'p', long = "proxy")]
    proxy: Vec<String>,

    /// 输出格式：txt、json、csv（默认 txt）
    #[arg(long = "format", default_value = "txt")]
    format: OutputFormat,

    /// TCP 连接超时秒数
    #[arg(long, default_value_t = 3)]
    connect_timeout: u64,

    /// 响应读取超时秒数
    #[arg(long, default_value_t = 10)]
    read_timeout: u64,

    /// 单站超时次数超过此值后跳过
    #[arg(long, default_value_t = 10)]
    max_timeouts: usize,

    /// 请求间最小延迟（毫秒）
    #[arg(long, default_value_t = 0)]
    min_delay: u64,

    /// 请求间最大延迟（毫秒）
    #[arg(long, default_value_t = 0)]
    max_delay: u64,

    /// 最小文件大小过滤（字节，默认1024）
    #[arg(long, default_value_t = 1024)]
    min_size: u64,

    /// 从上次扫描进度恢复
    #[arg(long)]
    resume: bool,
}

use dict::normalize_targets;

fn main() {
    let cli = Cli::parse();

    if cli.max_threads < 1 {
        eprintln!("错误：--thread 必须大于 0");
        std::process::exit(1);
    }

    // ── 加载目标 ──────────────────────────────────────────────
    let targets: Vec<String> = if let Some(ref url) = cli.url {
        normalize_targets(&[url.clone()])
    } else if let Some(ref url_file) = cli.url_file {
        match std::fs::read_to_string(url_file) {
            Ok(content) => {
                let lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
                normalize_targets(&lines)
            }
            Err(e) => {
                eprintln!("[错误] 无法读取文件 {:?}: {}", url_file, e);
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("错误：必须指定 -u 或 -f");
        std::process::exit(1);
    };

    if targets.is_empty() {
        eprintln!("错误：未找到有效目标");
        std::process::exit(1);
    }

    // ── 构建前缀列表 ─────────────────────────────────────────
    let mut active_prefixes: Vec<String> = dict::DEFAULT_PREFIXES
        .iter()
        .map(|s| s.to_string())
        .collect();

    // 添加日期变体前缀
    let date_prefixes = dict::generate_date_prefixes();
    let mut seen: HashSet<String> = active_prefixes.iter().cloned().collect();
    for dp in date_prefixes {
        if seen.insert(dp.clone()) {
            active_prefixes.push(dp);
        }
    }

    // 添加自定义字典条目
    if let Some(ref dict_file) = cli.dict_file {
        match std::fs::read_to_string(dict_file) {
            Ok(content) => {
                let custom: Vec<String> = content
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect();
                for c in custom {
                    if seen.insert(c.clone()) {
                        active_prefixes.push(c);
                    }
                }
            }
            Err(e) => {
                eprintln!("警告：加载自定义字典失败: {}", e);
            }
        }
    }

    // ── 创建输出写入器 ──────────────────────────────────────
    // 确保输出文件存在
    let _ = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&cli.output_file);
    let output = Arc::new(OutputWriter::new(cli.output_file, cli.format));
    if cli.resume {
        output.load_existing();
    }

    // ── 构建扫描配置 ─────────────────────────────────────────
    let config = ScanConfig {
        targets,
        max_workers: cli.max_threads,
        connect_timeout: Duration::from_secs(cli.connect_timeout),
        read_timeout: Duration::from_secs(cli.read_timeout),
        max_timeouts: cli.max_timeouts,
        proxies: cli.proxy,
        output,
        prefixes: active_prefixes,
        min_delay_ms: cli.min_delay,
        max_delay_ms: cli.max_delay,
        min_size: cli.min_size,
        resume: cli.resume,
    };

    // ── 启动扫描 ─────────────────────────────────────────────
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("构建 tokio 运行时失败");

    rt.block_on(scanner::scan_targets(config));
}
