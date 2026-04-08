# BakScan

一款高性能网站备份文件泄露扫描工具，使用 Rust 编写。

自动根据域名生成变体字典，结合常见备份文件模式生成候选URL，通过 HTTP 响应分析、文件头 Magic Bytes 校验和 404 指纹识别来检测真实的备份文件泄露。

## 功能特性

- **异步高并发** — 基于 Tokio 异步 I/O，信号量控制并发数
- **单阶段探测** — 每个候选URL仅一次 GET Range 请求（无冗余 HEAD+GET）
- **智能404指纹** — 探测随机不存在路径，过滤自定义错误页面
- **Magic Bytes 校验** — 通过文件头识别 ZIP、GZ、BZ2、XZ、7Z、RAR、TAR、SQLite、MDB、ACCDB
- **子路径扫描** — 扫描17个常见目录（`/backup/`、`/admin/`、`/tmp/`、`/old/` 等）
- **增强字典** — 103个前缀 + 动态日期变体 + 34种备份后缀 + 域名自动变体
- **反检测** — 30+ User-Agent、随机请求顺序、可配置延迟
- **多代理轮换** — 支持多个 SOCKS5/HTTP 代理自动轮换
- **多输出格式** — TXT、JSON（JSONL）、CSV
- **自动去重** — 跳过已记录的URL
- **断点续扫** — `--resume` 加载已有结果跳过已扫描URL
- **最小大小过滤** — `--min-size` 过滤误报

## 安装

### 预编译二进制

从 [Releases](https://github.com/DanTiao7/WebBackscan/releases) 下载。

### 从源码编译

```bash
# 需要 Rust 工具链 (https://rustup.rs)
cargo build --release
```

输出路径：`target/release/bakscan`（Linux）或 `target/release/bakscan.exe`（Windows）

## 使用方法

```bash
# 批量扫描
bakscan -t 100 -f url.txt -o result.txt

# 单站点扫描
bakscan -u https://example.com -t 50 -o result.txt

# JSON输出 + 多代理 + 限速
bakscan -t 50 -f url.txt -o result.json --format json \
  -p socks5://127.0.0.1:1080 -p http://proxy2:8080 \
  --min-delay 100 --max-delay 500

# 断点续扫 + CSV输出 + 最小文件大小过滤
bakscan -t 100 -f url.txt -o result.csv --format csv --resume --min-size 4096
```

### URL文件格式

每行一个URL：

```
https://www.example.com
http://test.com:8080
https://sub.domain.net/
```

### 全部参数

```
参数:
  -f, --url-file <URL_FILE>          批量URL文件（每行一个）
  -t, --thread <MAX_THREADS>         最大并发请求数 [默认: 20]
  -u, --url <URL>                    单个目标URL
  -d, --dict-file <DICT_FILE>        自定义字典文件（追加到默认字典）
  -o, --output-file <OUTPUT_FILE>    输出结果文件 [默认: result.txt]
  -p, --proxy <PROXY>                代理地址（可多次指定）
      --format <FORMAT>              输出格式：txt、json、csv [默认: txt]
      --connect-timeout <SECONDS>    TCP连接超时秒数 [默认: 3]
      --read-timeout <SECONDS>       读取超时秒数 [默认: 10]
      --max-timeouts <N>             单站超时超过N次后跳过 [默认: 10]
      --min-delay <MS>               请求间最小延迟毫秒 [默认: 0]
      --max-delay <MS>               请求间最大延迟毫秒 [默认: 0]
      --min-size <BYTES>             最小文件大小过滤 [默认: 1024]
      --resume                       从上次进度恢复扫描
  -h, --help                         显示帮助信息
```

## 工作原理

```
1. 目标标准化
   └─ 确保末尾斜杠，去重

2. 对每个目标站点：
   ├─ 可达性检测（GET 探测）
   ├─ 404指纹采集（请求随机不存在的路径）
   └─ 生成候选URL：
       ├─ 域名变体（如 www.example.com → example, www, examplecom ...）
       ├─ 103个内置前缀 + 日期变体（20240101, 2024-01, backup_2024 ...）
       ├─ 自定义字典条目
       ├─ × 34种备份后缀（.zip, .sql.gz, .tar.gz, .rar, .7z, .db ...）
       └─ × 17个子路径（/, /backup/, /admin/, /tmp/ ...）

3. 对每个候选URL（异步，随机打乱顺序）：
   GET 请求 Range: bytes=0-63
   ├─ 匹配404指纹？ → 跳过
   ├─ 状态码 404/410？ → 跳过
   ├─ 重定向到登录页/错误页？ → 跳过（陷阱检测）
   ├─ Content-Disposition: attachment？ → 命中
   ├─ Content-Type: application/* + 大小 > 阈值？ → 命中
   ├─ Magic Bytes 匹配（PK, 1f8b, BZh, 7z, Rar!, SQLite ...）？ → 命中
   ├─ 文本备份（.sql）+ 非HTML错误页？ → 命中
   └─ 否则 → 跳过
```

## 支持的备份格式

| 格式 | 后缀 | 检测方式 |
|------|------|----------|
| ZIP | `.zip` | Magic: `PK\x03\x04` |
| GZIP | `.gz`、`.sql.gz`、`.tgz`、`.tar.gz` | Magic: `\x1f\x8b\x08` |
| BZIP2 | `.bz2`、`.tar.bz2` | Magic: `BZh` |
| XZ | `.xz`、`.tar.xz`、`.txz` | Magic: `\xfd7zXZ\x00` |
| 7-Zip | `.7z` | Magic: `7z\xbc\xaf'\x1c` |
| RAR | `.rar` | Magic: `Rar!\x1a\x07` |
| TAR | `.tar` | Magic: `ustar` @257 |
| SQLite | `.sqlite`、`.sqlite3`、`.db` | Magic: `SQLite format 3` |
| Access | `.mdb`、`.accdb` | Magic: `Standard Jet/ACE` |
| SQL | `.sql`、`.sql.bak`、`.dump.sql` | Content-Type + 文本分析 |
| JAR/WAR | `.jar`、`.war` | Magic: `PK\x03\x04` |
| 通用 | `.backup`、`.bak`、`.dmp`、`.dump` | Content-Type / Content-Disposition |

## 免责声明

**仅限合法授权的安全测试使用。** 严禁对未经授权的系统进行扫描。

## 许可证

MIT
