# qr-url

[![CI](https://github.com/GoAskAway/qr-url/actions/workflows/ci.yml/badge.svg)](https://github.com/GoAskAway/qr-url/actions/workflows/ci.yml)

Live demo (GitHub Pages): https://goaskaway.github.io/qr-url/

Encode UUID v4 into compact QR-friendly URLs using Base44. Removes 25 fixed bits (first bit + version + variant + signature "41c2ae") for optimal QR code alphanumeric mode encoding.

## Overview

This library implements a compact encoding scheme for UUID v4 identifiers with a recognizable signature:

- **Input**: UUID v4 with signature `0xxxxxxx-xxxx-41c2-aexx-xxxxxxxxxxxx` (128 bits, first hex char is 0-7)
- **Optimization**: Remove 25 deterministic bits (1-bit first + 4-bit version + 2-bit variant + 18-bit signature) → 103 bits of entropy
- **Encoding**: Optimal Base44 using big-integer encoding (103 bits → 19 chars)
- **Output**: Compact URL-safe string (**exactly 19 characters**)

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

- ✅ Convert UUID v4 (128-bit) to compact Base44 by removing 25 fixed bits (first bit + version + variant + signature), leaving 103 bits of entropy
- ✅ Generated UUIDs have recognizable signature `41c2-ae` and first hex char 0-7 for easy identification
- ✅ Perfect for QR code generation (alphanumeric mode optimization)
- ✅ URL embedding without any percent-encoding required
- ✅ Lossless bidirectional conversion (decode restores exact original UUID with signature)
- ✅ Only encodes UUIDs with the required signature and first bit = 0 (rejects non-matching UUIDs)
- ✅ Rust library, CLI tool, and WASM bindings for web applications

## Install

- Build CLI: `cargo install --path .`
- Use as a lib: add `qr-url = { git = "https://github.com/GoAskAway/qr-url.git" }` or use a local path dependency.

## CLI usage

```
qr-url

Commands:
  gen                       Generate a random UUID v4 with signature '41c2ae' and print Base44 and UUID
  encode <UUID|HEX|@->     Encode a UUID into Base44 (requires '41c2ae' signature). Accepts:
                           - canonical UUID string (xxxxxxxx-xxxx-41c2-aexx-xxxxxxxxxxxx)
                           - 32-hex (no dashes)
                           - raw 16-byte via stdin with @-
  decode <BASE44|@->       Decode Base44 string back to UUID string and bytes (hex)

Options:
  -q, --quiet              Only print the primary output
  -h, --help               Show this help
```

Examples:
- `qr-url gen`
- `qr-url encode 454f7792-6670-41c2-ae4d-4a05f3000f3f`
- `qr-url decode 2OLHMVYLDMPNRBLK50W5`

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
  --out-name qr_url \
  target/wasm32-unknown-unknown/release/qr_url.wasm

# Or using wasm-pack
# cargo install wasm-pack
# wasm-pack build --target web --out-dir examples/wasm/pkg --out-name qr_url
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
- Random UUID roundtrips with signature and first bit verification
- Signature and first bit requirement enforcement
- Compact size validation (13 bytes for 103 bits)
- Version and variant preservation

## Why 103 bits → 19 chars?

**Fixed bits in UUID v4:**
- 1 bit: first bit (always 0)
- 4 bits: version (0100 = 4)
- 2 bits: variant (10 = RFC4122)
- 18 bits: our signature "41c2ae"

Total fixed: 1 + 4 + 2 + 18 = **25 bits**

**Entropy after optimization:**
- 128 - 25 = **103 bits of entropy**
- Storage: 13 bytes (103 bits + 1 padding bit)

**Optimal Base44 encoding:**
- Mathematical bound: 2¹⁰³ < 44¹⁹ (all 103-bit values fit in 19 Base44 chars)
- Algorithm: Big-integer encoding (treat 103 bits as single u128 value)
- Result: **Exactly 19 characters** (vs 20 with byte-pair encoding)

## License

Apache-2.0

