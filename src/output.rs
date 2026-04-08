use parking_lot::Mutex;
use serde::Serialize;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

/// 输出格式枚举
#[derive(Clone, Debug, Default)]
pub enum OutputFormat {
    #[default]
    Txt,
    Json,
    Csv,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "txt" | "text" => Ok(Self::Txt),
            "json" => Ok(Self::Json),
            "csv" => Ok(Self::Csv),
            _ => Err(format!("未知格式: {}", s)),
        }
    }
}

/// 命中记录结构体
#[derive(Serialize)]
struct HitRecord {
    url: String,
    size: u64,
    size_human: String,
    timestamp: String,
}

/// 输出写入器，支持去重和多种输出格式
pub struct OutputWriter {
    path: PathBuf,
    format: OutputFormat,
    seen: Mutex<HashSet<String>>, // 去重集合
}

impl OutputWriter {
    pub fn new(path: PathBuf, format: OutputFormat) -> Self {
        Self {
            path,
            format,
            seen: Mutex::new(HashSet::new()),
        }
    }

    /// 写入一条命中记录，返回 true 表示写入成功（false 表示重复跳过）
    /// 通过 Mutex 保证线程安全
    pub async fn write_hit(&self, url: &str, size: u64) -> bool {
        // 原子性检查并插入
        {
            let mut seen = self.seen.lock();
            if !seen.insert(url.to_string()) {
                return false;
            }
        }

        let record = HitRecord {
            url: url.to_string(),
            size,
            size_human: humanize_size(size),
            timestamp: chrono::Local::now()
                .format("%Y-%m-%d %H:%M:%S")
                .to_string(),
        };

        match self.format {
            OutputFormat::Txt => {
                if let Ok(mut f) = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.path)
                {
                    let _ = writeln!(f, "{} size:{}", record.url, record.size_human);
                }
            }
            OutputFormat::Json => {
                // JSONL格式：每行一个JSON对象
                if let Ok(json_line) = serde_json::to_string(&record) {
                    if let Ok(mut f) = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(&self.path)
                    {
                        let _ = writeln!(f, "{}", json_line);
                    }
                }
            }
            OutputFormat::Csv => {
                let file_exists = self.path.exists() && {
                    fs::metadata(&self.path)
                        .map(|m| m.len() > 0)
                        .unwrap_or(false)
                };

                if let Ok(f) = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&self.path)
                {
                    let mut wtr = csv::WriterBuilder::new()
                        .has_headers(!file_exists)
                        .from_writer(f);
                    let _ = wtr.serialize(&record);
                    let _ = wtr.flush();
                }
            }
        }

        true
    }

    /// 检查URL是否已记录过
    pub fn is_duplicate(&self, url: &str) -> bool {
        let seen = self.seen.lock();
        seen.contains(url)
    }

    /// 从已有输出文件加载记录用于去重（恢复扫描时使用）
    pub fn load_existing(&self) {
        let content = match fs::read_to_string(&self.path) {
            Ok(c) => c,
            Err(_) => return,
        };

        let mut seen = self.seen.lock();

        match self.format {
            OutputFormat::Txt => {
                // 格式："URL size:SIZE"
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    // 提取URL（" size:" 之前的部分）
                    if let Some(url) = line.split(" size:").next() {
                        let url = url.trim();
                        if !url.is_empty() {
                            seen.insert(url.to_string());
                        }
                    }
                }
            }
            OutputFormat::Json => {
                // JSONL格式：每行一个JSON对象
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    if let Ok(record) =
                        serde_json::from_str::<serde_json::Value>(line)
                    {
                        if let Some(url) = record.get("url").and_then(|v| v.as_str()) {
                            seen.insert(url.to_string());
                        }
                    }
                }
            }
            OutputFormat::Csv => {
                let mut rdr = csv::ReaderBuilder::new()
                    .has_headers(true)
                    .from_reader(content.as_bytes());
                for result in rdr.records() {
                    if let Ok(record) = result {
                        // 第一个字段是URL
                        if let Some(url) = record.get(0) {
                            if !url.is_empty() {
                                seen.insert(url.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
}

/// 将字节数转为人类可读的文件大小（如 "1.5 MiB"、"320 KiB"）
pub fn humanize_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    if bytes == 0 {
        return "0 B".to_string();
    }
    let mut size = bytes as f64;
    for unit in UNITS {
        if size < 1024.0 {
            return if size.fract() < 0.05 {
                format!("{:.0} {}", size, unit)
            } else {
                format!("{:.1} {}", size, unit)
            };
        }
        size /= 1024.0;
    }
    format!("{:.1} TiB", size * 1024.0)
}
