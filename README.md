# qr-url-uuid4

[![CI](https://github.com/GoAskAway/qr-url/actions/workflows/ci.yml/badge.svg)](https://github.com/GoAskAway/qr-url/actions/workflows/ci.yml)

Live demo (GitHub Pages): https://goaskaway.github.io/qr-url/

Encode UUID v4 into compact QR-friendly URLs using Base44. Removes the 6 fixed bits (version + variant) for optimal QR code alphanumeric mode encoding.

## Overview

This library implements a compact encoding scheme for UUID v4 identifiers:

- **Input**: Standard UUID v4 (128 bits)
- **Optimization**: Remove 6 deterministic bits (4-bit version + 2-bit variant) → 122 bits of entropy
- **Encoding**: Base44 (QR alphanumeric alphabet excluding space)
- **Output**: Compact URL-safe string (typically 24-25 characters)

### Why Base44 instead of Base45?

[Base45](https://datatracker.ietf.org/doc/html/rfc9285) (RFC 9285) uses the full QR code alphanumeric character set: `0-9A-Z $%*+-./:` (45 characters). However, the **space character** creates problems for URL embedding:

- ❌ **URL encoding required**: Spaces must be encoded as `%20` or `+`, increasing length
- ❌ **Proxy issues**: Some HTTP proxies and servers strip trailing/leading spaces
- ❌ **Copy-paste problems**: Spaces may be lost when users copy URLs from browsers or logs
- ❌ **Inconsistent handling**: Different systems treat spaces differently (percent-encode vs plus-encode)

**Base44** removes the space character from the alphabet (`0-9A-Z $%*+-./:` → `0-9A-Z $%*+-./:` without space), providing:

- ✅ **True URL-safe**: No percent-encoding needed for any character
- ✅ **QR-optimal**: Still uses QR alphanumeric mode (5.5 bits/char avg)
- ✅ **Reliable**: No ambiguity in URL handling across different systems
- ✅ **Compact**: Only marginally longer than Base45 due to slightly smaller alphabet

### Features

- ✅ Convert UUID v4 (128-bit) to compact Base44 by removing 6 fixed bits, leaving 122 bits of entropy
- ✅ Perfect for QR code generation (alphanumeric mode optimization)
- ✅ URL embedding without any percent-encoding required
- ✅ Lossless bidirectional conversion (decode restores exact original UUID)
- ✅ Rust library, CLI tool, and WASM bindings for web applications

## Install

- Build CLI: `cargo install --path .`
- Use as a lib: add `qr-url-uuid4 = { git = "https://github.com/GoAskAway/qr-url.git" }` or use a local path dependency.

## CLI usage

```
qr-url-uuid4

Commands:
  gen                       Generate a random UUID v4 and print Base44 and UUID
  encode <UUID|HEX|@->     Encode a UUID into Base44. Accepts:
                           - canonical UUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
                           - 32-hex (no dashes)
                           - raw 16-byte via stdin with @-
  decode <BASE44|@->       Decode Base44 string back to UUID string and bytes (hex)

Options:
  -q, --quiet              Only print the primary output
  -h, --help               Show this help
```

Examples:
- `qr-url-uuid4 gen`
- `qr-url-uuid4 encode 550e8400-e29b-41d4-a716-446655440000`
- `qr-url-uuid4 decode <base44-string>`

## Library API

- `generate_v4() -> Uuid`
- `encode_uuid(uuid: Uuid) -> String`
- `encode_uuid_str(s: &str) -> Result<String, Uuid45Error>`
- `encode_uuid_bytes(bytes: &[u8; 16]) -> String`
- `decode_to_uuid(s: &str) -> Result<Uuid, Uuid45Error>`
- `decode_to_bytes(s: &str) -> Result<[u8; 16], Uuid45Error>`
- `decode_to_string(s: &str) -> Result<String, Uuid45Error>`

## WASM usage

This crate exposes the following bindings when compiled for `wasm32-unknown-unknown` with `wasm-bindgen`:
- `wasm_gen_v4() -> String`
- `wasm_encode_uuid_str(s: &str) -> Result<String, JsValue>`
- `wasm_decode_to_uuid_str(s: &str) -> Result<String, JsValue>`
- `wasm_decode_to_bytes(s: &str) -> Result<Uint8Array, JsValue>`

Example site at `examples/wasm/index.html`.

### Build WASM locally (wasm-pack alternative included)

- Install wasm target and wasm-bindgen-cli:

```
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
wasm-bindgen --target web --no-typescript \
  --out-dir examples/wasm/pkg \
  --out-name qr_url_uuid4 \
  target/wasm32-unknown-unknown/release/qr_url_uuid4.wasm

# Or using wasm-pack
# cargo install wasm-pack
# wasm-pack build --target web --out-dir examples/wasm/pkg --out-name qr_url_uuid4
```

- Open `examples/wasm/index.html` via a static server (e.g., `python3 -m http.server`) and navigate to it.

## GitHub Pages

A live demo is automatically published to GitHub Pages:
- https://goaskaway.github.io/qr-url/

## Download artifacts

- From CI (latest run): Navigate to Actions, select the latest successful run of the CI workflow, and download the artifact named "wasm-demo". Link: https://github.com/GoAskAway/qr-url/actions
- From Releases: For tagged releases (v*), download the attached wasm-demo.tar.gz from the Releases page. Link: https://github.com/GoAskAway/qr-url/releases

### Using the wasm-demo artifact locally
- Unpack wasm-demo.tar.gz
- Serve the unzipped folder with a static server, e.g.:
  - python3 -m http.server 8080 (then open http://localhost:8080)

## Tests

`cargo test` includes:
- Random UUID roundtrips
- Known UUID roundtrip
- Padding bits verification

## Why 122 bits?

UUID v4 reserves 4 bits for version and 2 bits for variant. These are fixed values (0100 and 10). Removing them yields 128-6 = 122 bits of entropy. We pack these into 16 bytes, with only 2 bits used in the last byte; the upper 6 bits of the last byte are zero padding. Base45 then encodes these bytes.

## License

Apache-2.0

