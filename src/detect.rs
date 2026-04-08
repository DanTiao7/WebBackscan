use reqwest::header::{HeaderMap, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE, LOCATION};

use crate::dict::SUFFIX_FORMAT;

/// 响应指纹结构体，用于识别自定义错误页面（假200等）
#[derive(Clone, Debug)]
pub struct ResponseFingerprint {
    pub status: String,
    pub content_type: String,
    pub content_length: String,
    pub location: String,
    pub sample_hex: String,
}

/// 标准化头部值：去空格并转小写
fn normalize_header_value(value: &str) -> String {
    value.trim().to_lowercase()
}

/// 将字节数组编码为十六进制字符串
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// 安全获取头部字段字符串值
fn header_str<'a>(headers: &'a HeaderMap, key: reqwest::header::HeaderName) -> &'a str {
    headers
        .get(key)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
}

/// 根据响应状态码、头部和样本字节构建指纹
pub fn build_fingerprint(status: u16, headers: &HeaderMap, sample: &[u8]) -> ResponseFingerprint {
    let raw_ct = header_str(headers, CONTENT_TYPE);
    let ct = normalize_header_value(raw_ct.split(';').next().unwrap_or(""));

    ResponseFingerprint {
        status: status.to_string(),
        content_type: ct,
        content_length: normalize_header_value(header_str(headers, CONTENT_LENGTH)),
        location: normalize_header_value(header_str(headers, LOCATION)),
        sample_hex: hex_encode(&sample[..sample.len().min(64)]),
    }
}

/// 检查响应是否匹配已知的指纹（如404错误页面）
/// 匹配规则：状态码相同 + (Location相同 或 类型+长度相同 或 类型+样本相同)
pub fn fingerprint_matches(
    status: u16,
    headers: &HeaderMap,
    sample: &[u8],
    fp: &Option<ResponseFingerprint>,
) -> bool {
    let fp = match fp {
        Some(f) => f,
        None => return false,
    };

    let current = build_fingerprint(status, headers, sample);

    if current.status != fp.status {
        return false;
    }

    // Location 相同说明是同一个错误页面
    if !fp.location.is_empty() && current.location == fp.location {
        return true;
    }

    let same_type = current.content_type == fp.content_type;
    let same_length = !fp.content_length.is_empty() && current.content_length == fp.content_length;
    let same_sample = !fp.sample_hex.is_empty() && current.sample_hex == fp.sample_hex;

    if same_type && same_length {
        return true;
    }

    if same_type && same_sample {
        return true;
    }

    false
}

/// 通过文件头 magic bytes 检测文件真实格式
/// 支持：ZIP/JAR/WAR、GZ、BZ2、XZ、7Z、RAR、SQLite、TAR、MDB、ACCDB
pub fn has_known_magic(sample: &[u8], suffix: &str) -> bool {
    match suffix {
        ".zip" | ".jar" | ".war" => {
            sample.starts_with(b"PK\x03\x04")
                || sample.starts_with(b"PK\x05\x06")
                || sample.starts_with(b"PK\x07\x08")
        }
        ".gz" | ".sql.gz" | ".tgz" | ".tar.gz" | ".csv.gz" => {
            sample.starts_with(b"\x1f\x8b\x08")
        }
        ".bz2" | ".tar.bz2" => sample.starts_with(b"BZh"),
        ".xz" | ".txz" | ".tar.xz" => sample.starts_with(b"\xfd7zXZ\x00"),
        ".7z" => sample.starts_with(b"7z\xbc\xaf\x27\x1c"),
        ".rar" => {
            sample.starts_with(b"Rar!\x1a\x07\x00")
                || sample.starts_with(b"Rar!\x1a\x07\x01\x00")
        }
        ".sqlite" | ".sqlite3" | ".db" => sample.starts_with(b"SQLite format 3\x00"),
        ".tar" => {
            // tar 的 ustar 标识在偏移 257 处，样本不够长则不确认也不拒绝
            if sample.len() < 262 {
                false
            } else {
                &sample[257..262] == b"ustar"
            }
        }
        ".mdb" => {
            // Access 97-2003 数据库：\x00\x01\x00\x00Standard Jet
            let magic = b"\x00\x01\x00\x00Standard Jet";
            sample.len() >= magic.len() && sample.starts_with(magic)
        }
        ".accdb" => {
            // Access 2007+ 数据库：\x00\x01\x00\x00Standard ACE
            let magic = b"\x00\x01\x00\x00Standard ACE";
            sample.len() >= magic.len() && sample.starts_with(magic)
        }
        _ => false,
    }
}

/// 检测前64字节是否像HTML错误页面
pub fn is_likely_text_error(sample: &[u8]) -> bool {
    let probe: Vec<u8> = sample
        .iter()
        .take(64)
        .map(|b| b.to_ascii_lowercase())
        .collect();
    [
        b"<!doctype".as_slice(),
        b"<html",
        b"<head",
        b"<body",
        b"404",
        b"not found",
        b"access denied",
    ]
    .iter()
    .any(|token| probe.windows(token.len()).any(|w| w == *token))
}

/// 检查 Content-Type 是否表明备份文件
/// application/* 或空 Content-Type，且不是 html/text/xml/json/image 等
pub fn is_likely_backup_response(status: u16, content_type: &str) -> bool {
    let forbidden = [
        "html",
        "text",
        "xml",
        "json",
        "javascript",
        "image",
        "css",
        "font",
        "audio",
        "video",
    ];
    status == 200
        && !forbidden.iter().any(|t| content_type.contains(t))
        && (content_type.contains("application") || content_type.trim().is_empty())
}

/// 检查 Content-Disposition 是否包含 attachment 或 filename（表示下载文件）
pub fn has_download_disposition(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_DISPOSITION)
        .and_then(|v| v.to_str().ok())
        .map(|v| {
            let lower = v.to_lowercase();
            lower.contains("attachment") || lower.contains("filename=")
        })
        .unwrap_or(false)
}

/// 检查重定向是否为陷阱（跳转到登录页/错误页/首页等）
pub fn is_probably_redirect_trap(status: u16, location: &str) -> bool {
    if ![301u16, 302, 303, 307, 308].contains(&status) {
        return false;
    }
    let loc = location.to_lowercase();
    ["login", "signin", "index.", "home", "default", "error", "404"]
        .iter()
        .any(|kw| loc.contains(kw))
}

/// 检查后缀+Content-Type组合是否为文本类备份文件（.sql、.dump等）
pub fn looks_like_text_backup(suffix: &str, content_type: &str) -> bool {
    let text_suffixes = [".sql", ".bak.sql", ".dump", ".dump.sql", ".sql.bak"];
    text_suffixes.contains(&suffix)
        && ["text/plain", "application/sql", "application/octet-stream"]
            .iter()
            .any(|t| content_type.contains(t))
}

/// 从URL路径中提取匹配的备份文件后缀（最长匹配优先）
pub fn get_candidate_suffix(url: &str) -> &'static str {
    let path = url.to_lowercase();
    let mut sorted: Vec<&&str> = SUFFIX_FORMAT.iter().collect();
    sorted.sort_by(|a, b| b.len().cmp(&a.len()));
    for suffix in sorted {
        if path.ends_with(*suffix) {
            return suffix;
        }
    }
    ""
}
