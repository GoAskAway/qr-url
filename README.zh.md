# qr-url

[![CI](https://github.com/GoAskAway/qr-url/actions/workflows/ci.yml/badge.svg)](https://github.com/GoAskAway/qr-url/actions/workflows/ci.yml)

在线示例（GitHub Pages）：https://goaskaway.github.io/qr-url/

使用 Base44 将定制 UUID 标识符编码为紧凑的 QR 友好 URL。这是一个**带固定签名的 UUID v4 变种**，专为 QR 码字母数字模式优化。

## 概述

本库实现了**定制 UUID 标识符**（非标准 UUID v4，而是可识别的变种）的紧凑编码方案：

- **输入**: 带签名的定制 UUID `0xxxxxxx-xxxx-41c2-aexx-xxxxxxxxxxxx`（128 位，首个十六进制字符为 0-7）
- **优化**: 移除 25 个确定性位（1 位首位 + 4 位版本 + 2 位变体 + 18 位签名）→ 103 位熵
- **编码**: Base44 最优位级编码（QR 字母数字字符集，不含空格）
- **输出**: 紧凑的 URL 安全字符串（精确 19 字符）

### 为什么选择 Base44 而不是 Base45？

Base45（[RFC 9285](https://datatracker.ietf.org/doc/html/rfc9285)）使用完整的 QR 码字母数字字符集：`0-9A-Z $%*+-./:`（45 个字符）。但是，**空格字符**在 URL 嵌入时会造成问题：

- ❌ **需要 URL 编码**: 空格必须编码为 `%20` 或 `+`，增加长度
- ❌ **代理问题**: 某些 HTTP 代理和服务器会删除首尾空格
- ❌ **复制粘贴问题**: 用户从浏览器或日志复制 URL 时可能丢失空格
- ❌ **处理不一致**: 不同系统对空格处理不同（百分号编码 vs 加号编码）

**Base44** 从字母表中移除了空格字符，提供：

- ✅ **真正的 URL 安全**: 任何字符都不需要百分号编码
- ✅ **QR 最优**: 仍使用 QR 字母数字模式（平均 5.5 位/字符）
- ✅ **可靠**: URL 处理在不同系统间无歧义
- ✅ **紧凑**: 由于字母表略小，仅比 Base45 稍长

### 主要特性

- ✅ 生成带固定签名 `41c2-ae` 的定制 UUID 变种，用于领域特定识别
- ✅ 将定制 UUID（128 位）通过移除 25 个固定位转换为紧凑 Base44，保留 103 位熵
- ✅ 首个十六进制字符始终为 0-7，提供额外的可识别模式
- ✅ 完美适配 QR 码生成（字母数字模式优化，精确 19 字符）
- ✅ URL 嵌入无需任何百分号编码
- ✅ 无损双向转换（解码还原带签名的原始 UUID）
- ✅ 仅编码具有必需签名且首位为 0 的 UUID（拒绝无签名的标准 UUID v4）
- ✅ 提供 Rust 库、CLI 工具和 WASM 绑定用于 Web 应用

**重要**: 本库生成和编码的是**定制 UUID 变种**，而非标准 RFC4122 UUID v4。固定签名 `41c2-ae` 使这些 UUID 易于在应用领域中识别。

详细的英文文档请参阅 [README.md](README.md)

## 安装

### 前置条件

安装 Rust 工具链（如未安装）：

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 安装 CLI

```bash
# 从 crates.io 安装（发布后可用）
cargo install qr-url

# 从 GitHub 安装
cargo install --git https://github.com/GoAskAway/qr-url.git

# 从本地源码安装
git clone https://github.com/GoAskAway/qr-url.git
cd qr-url
cargo install --path .

# 启用 HTTP 服务器功能
cargo install --path . --features server
```

### 作为库使用

在 `Cargo.toml` 中添加：
```toml
[dependencies]
qr-url = { git = "https://github.com/GoAskAway/qr-url.git" }
```

## 命令行用法

```
qr-url

命令：
  gen                       生成带签名 '41c2ae' 的随机定制 UUID，并打印 Base44 与 UUID
  encode <UUID|HEX|@->     将定制 UUID 编码为 Base44（需要 '41c2ae' 签名）。支持：
                           - 标准 UUID 字符串（xxxxxxxx-xxxx-41c2-aexx-xxxxxxxxxxxx）
                           - 32 位十六进制（无连字符）
                           - 通过 @- 从 stdin 读入 16 字节原始数据
  decode <BASE44|@->       将 Base44 字符串解码回 UUID 字符串与字节（hex）

选项：
  -q, --quiet              仅输出主要结果
  -h, --help               显示帮助
```

示例：
```bash
# 生成新的定制 UUID（19 字符）
$ qr-url gen
Base44: 3FV.2BWT9L7S.OBAZ4G (length: 19)
UUID:   0xxxxxxx-xxxx-41c2-aexx-xxxxxxxxxxxx

# 编码现有定制 UUID（必须有 '41c2ae' 签名且首字符为 0-7）
$ qr-url encode 454f7792-6670-41c2-ae4d-4a05f3000f3f
Base44: 3856ECXC*$A2D-ASF2- (length: 19)

# 解码 Base44 回定制 UUID
$ qr-url decode 3856ECXC*$A2D-ASF2-
UUID:   454f7792-6670-41c2-ae4d-4a05f3000f3f
```

## HTTP 服务器

`server` 功能提供了一个轻量级 HTTP/HTTPS 服务器，用于通过 HTTP 请求解码 Base44 编码。

### 启动服务器

```bash
# 基本 HTTP 服务器（默认端口 8080）
qr-url server

# 自定义端口
qr-url server --port 3000

# 使用 TLS 证书启用 HTTPS
qr-url server --port 443 --cert /path/to/cert.pem --key /path/to/key.pem

# 使用不同的输出模式
qr-url server --mode json                           # JSON 响应（默认）
qr-url server --mode 301:https://example.com/       # 301 重定向
qr-url server --mode 302:https://example.com/       # 302 重定向
qr-url server --mode html:/path/to/template.html    # HTML 模板
```

### API 端点

**解码 Base44**
```bash
# 请求: GET /{base44}
curl http://localhost:8080/3856ECXC*%24A2D-ASF2-

# 响应（JSON 模式）:
{
  "uuid": "454f7792-6670-41c2-ae4d-4a05f3000f3f",
  "base44": "3856ECXC*$A2D-ASF2-",
  "bytes": "454f7792667041c2ae4d4a05f3000f3f"
}
```

**健康检查**
```bash
curl http://localhost:8080/health
# 响应: OK
```

### 输出模式

| 模式 | 描述 | 响应 |
|------|------|------|
| `json` | 包含 uuid、base44、bytes 的 JSON | `{"uuid":"...","base44":"...","bytes":"..."}` |
| `301:<url>` | 301 重定向到 `<url>{{uuid}}` | HTTP 301 带 Location 头 |
| `302:<url>` | 302 重定向到 `<url>{{uuid}}` | HTTP 302 带 Location 头 |
| `html:<path>` | 渲染 HTML 模板 | 替换占位符后的 HTML |

### HTML 模板占位符

`html:` 模式的模板文件可使用以下占位符：
- `{{uuid}}` - 解码后的 UUID 字符串
- `{{base44}}` - 原始 Base44 编码
- `{{bytes}}` - 十六进制原始字节

### URL 编码

Base44 使用的特殊字符（`$ % * + - . / :`）在 HTTP 请求中可能需要 URL 编码：

| 字符 | URL 编码 |
|------|----------|
| `$` | `%24` |
| `%` | `%25` |
| `*` | `%2A` |
| `+` | `%2B` |
| `/` | `%2F` |
| `:` | `%3A` |

服务器会根据长度自动检测并解码 URL 编码的 Base44 码（19 字符 = 原始，>19 字符 = URL 编码）。

## GitHub Pages 示例

项目会自动发布一个在线示例到 GitHub Pages：
- https://goaskaway.github.io/qr-url/

## 为什么是 103 位？

我们的定制 UUID 变种固定了以下位：
- 1 位首位（始终为 0，确保首个十六进制字符为 0-7）
- 4 位版本（0100 = 4，保持 RFC4122 兼容性）
- 2 位变体（10 = RFC4122）
- 18 位应用签名 "41c2ae"（不包括已计入的版本/变体位）

总固定位数：1 + 4 + 2 + 18 = 25 位

移除后得到 128 - 25 = 103 位实际熵。我们将其打包为 13 字节（最后一个字节使用 7 位）。使用最优 Base44 位级编码，精确产生 19 字符（理论最小值：`ceil(103 * log(2) / log(44)) = 19`）。

**注意**: 虽然保持了 RFC4122 结构，但固定签名 `41c2ae` 使其成为**定制变种**，而非标准 UUID v4。

## 许可证

Apache-2.0
