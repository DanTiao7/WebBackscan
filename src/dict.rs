use std::collections::{BTreeSet, HashSet};
use url::Url;

/// 备份文件后缀列表（34种）
pub const SUFFIX_FORMAT: &[&str] = &[
    ".7z",
    ".backup",
    ".bak",
    ".bak.sql",
    ".bz2",
    ".db",
    ".dmp",
    ".dump",
    ".dump.sql",
    ".gz",
    ".jar",
    ".rar",
    ".sql",
    ".sql.bak",
    ".sql.gz",
    ".sql.zip",
    ".sql.tar.gz",
    ".sqlite",
    ".sqlite3",
    ".tar",
    ".tar.bz2",
    ".tar.gz",
    ".tar.tgz",
    ".tar.xz",
    ".tbz",
    ".tbz2",
    ".tgz",
    ".txz",
    ".war",
    ".xz",
    ".zip",
    ".mdb",
    ".accdb",
    ".csv.gz",
];

/// 默认文件名前缀字典（77个原始 + 26个新增）
pub const DEFAULT_PREFIXES: &[&str] = &[
    // 77个原始前缀
    "1",
    "127.0.0.1",
    "2010",
    "2011",
    "2012",
    "2013",
    "2014",
    "2015",
    "2016",
    "2017",
    "2018",
    "2019",
    "2020",
    "2021",
    "2022",
    "2023",
    "2024",
    "2025",
    "2026",
    "admin",
    "archive",
    "asp",
    "aspx",
    "auth",
    "back",
    "backup",
    "backups",
    "bak",
    "bbs",
    "bin",
    "clients",
    "code",
    "com",
    "customers",
    "dat",
    "data",
    "database",
    "db",
    "dump",
    "engine",
    "error_log",
    "faisunzip",
    "files",
    "forum",
    "home",
    "html",
    "index",
    "joomla",
    "js",
    "jsp",
    "local",
    "localhost",
    "master",
    "media",
    "members",
    "my",
    "mysql",
    "new",
    "old",
    "orders",
    "php",
    "sales",
    "site",
    "sql",
    "store",
    "tar",
    "test",
    "user",
    "users",
    "vb",
    "web",
    "website",
    "wordpress",
    "wp",
    "www",
    "wwwroot",
    "root",
    "log",
    // 新增前缀
    "htdocs",
    "public_html",
    "public",
    "src",
    "source",
    "dist",
    "release",
    "config",
    "conf",
    "www-data",
    "webroot",
    "inetpub",
    "app",
    "application",
    "upload",
    "download",
    "temp",
    "cache",
    "static",
    "assets",
    "server",
    "production",
    "prod",
    "staging",
    "dev",
    "development",
];

/// 扫描子路径列表（17个），空字符串表示网站根目录
pub const SUB_PATHS: &[&str] = &[
    "",
    "backup/",
    "backups/",
    "bak/",
    "admin/",
    "tmp/",
    "temp/",
    "old/",
    "data/",
    "uploads/",
    "db/",
    "database/",
    "sql/",
    "dump/",
    "archive/",
    "export/",
    "download/",
];

/// 生成日期相关的文件名前缀
/// 基于当前时间，为近4年生成如 "20250101"、"2025-01"、"backup_20250101" 等变体
pub fn generate_date_prefixes() -> Vec<String> {
    let now = chrono::Local::now();
    let current_year = now.format("%Y").to_string().parse::<i32>().unwrap_or(2026);

    let mut prefixes = Vec::new();

    for offset in 0..=3 {
        let year = current_year - offset;
        let y = year.to_string();

        // 纯年份："2025"
        prefixes.push(y.clone());

        // 年月："2025-01" ~ "2025-12"
        for month in 1..=12 {
            prefixes.push(format!("{}-{:02}", year, month));
            prefixes.push(format!("{}{:02}", year, month));
        }

        // 年月日（每月1日和15日）："20250101"、"2025-01-01"
        for month in 1..=12 {
            for day in &[1, 15] {
                prefixes.push(format!("{}{:02}{:02}", year, month, day));
                prefixes.push(format!("{}-{:02}-{:02}", year, month, day));
            }
        }

        // 带标签的变体："backup_2025"、"db_202501"、"dump_20250101"
        for label in &["backup", "db", "data", "dump", "sql", "site", "web"] {
            prefixes.push(format!("{}_{}", label, y));
            for month in 1..=12 {
                prefixes.push(format!("{}_{}{:02}", label, year, month));
            }
            // 每季度首月
            for month in &[1, 4, 7, 10] {
                prefixes.push(format!("{}_{}{:02}01", label, year, month));
            }
        }
    }

    // 去重并保持顺序
    let mut seen = HashSet::new();
    prefixes.retain(|p| seen.insert(p.clone()));

    prefixes
}

/// 生成所有候选URL
/// 1. 解析域名，生成域名变体（IPv4特殊处理、域名拆分）
/// 2. 合并域名变体 + 字典前缀（去重）
/// 3. 对每个子路径 × 每个前缀 × 每个后缀 → 构建候选URL
/// 4. 返回排序去重后的列表
pub fn generate_candidates(
    base_url: &str,
    prefixes: &[String],
    suffixes: &[&str],
    sub_paths: &[&str],
) -> Vec<String> {
    let parsed = match Url::parse(base_url) {
        Ok(u) => u,
        Err(_) => return vec![],
    };

    let domain = parsed
        .host_str()
        .unwrap_or("")
        .to_lowercase()
        .trim_end_matches('.')
        .to_string();

    let parts: Vec<&str> = domain.split('.').collect();
    let mut variants: HashSet<String> = HashSet::new();

    // 判断是否为纯IPv4地址（如 192.168.2.111）
    let is_ipv4 = parts.len() == 4
        && parts.iter().all(|p| {
            p.parse::<u16>()
                .map(|n| n <= 255)
                .unwrap_or(false)
        });

    if is_ipv4 {
        variants.insert(domain.clone()); // 192.168.2.111
        variants.insert(parts.join("")); // 1921682111
        variants.insert(parts.join("_")); // 192_168_2_111
    } else {
        // 普通域名变体逻辑
        if !parts.is_empty() {
            variants.insert(domain.clone()); // 完整域名
            variants.insert(parts[0].to_string()); // 第一部分
            variants.insert(parts.join("")); // 所有部分拼接
            if parts.len() > 1 {
                variants.insert(parts[1..].join(".")); // 去掉第一部分（点连接）
                variants.insert(parts[1..].join("_")); // 去掉第一部分（下划线连接）
            }
        }
        if parts.len() > 2 {
            // 去掉TLD
            let without_tld = &parts[..parts.len() - 1];
            variants.insert(without_tld.join(".")); // 点连接
            variants.insert(without_tld.join("")); // 直接拼接
            variants.insert(without_tld.join("_")); // 下划线连接
        }
    }

    // 合并字典前缀
    for p in prefixes {
        variants.insert(p.clone());
    }
    variants.retain(|v| !v.is_empty());

    let base_path = format!("{}/", base_url.trim_end_matches('/'));
    let mut candidates = BTreeSet::new();

    for sub_path in sub_paths {
        for prefix in &variants {
            for suffix in suffixes {
                let filename = if suffix.starts_with('.') {
                    format!("{}{}", prefix, suffix)
                } else {
                    format!("{}.{}", prefix, suffix)
                };
                candidates.insert(format!("{}{}{}", base_path, sub_path, filename));
            }
        }
    }

    candidates.into_iter().collect()
}

/// 标准化目标列表：去空格、确保末尾斜杠、去重
pub fn normalize_targets(raw: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for t in raw {
        let v = t.trim().to_string();
        if v.is_empty() {
            continue;
        }
        let normalized = format!("{}/", v.trim_end_matches('/'));
        if seen.insert(normalized.clone()) {
            result.push(normalized);
        }
    }
    result
}
