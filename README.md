# qr-url

[![CI](https://github.com/GoAskAway/qr-url/actions/workflows/ci.yml/badge.svg)](https://github.com/GoAskAway/qr-url/actions/workflows/ci.yml)

Live demo (GitHub Pages): https://goaskaway.github.io/qr-url/

Encode custom UUID identifiers into compact QR-friendly URLs using Base44. This is a **UUID v4 variant** with a fixed signature pattern, optimized for QR code alphanumeric mode encoding.

## Overview

This library implements a compact encoding scheme for **custom UUID identifiers** (not standard UUID v4, but a recognizable variant):

- **Input**: Custom UUID with signature `0xxxxxxx-xxxx-41c2-aexx-xxxxxxxxxxxx` (128 bits, first hex char is 0-7)
- **Optimization**: Remove 25 deterministic bits (1-bit first + 4-bit version + 2-bit variant + 18-bit signature) → 103 bits of entropy
- **Encoding**: Base44 optimal bit encoding (QR alphanumeric alphabet excluding space)
- **Output**: Compact URL-safe string (exactly 19 characters)

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

- ✅ Generate custom UUID variant with fixed signature `41c2-ae` for domain-specific identification
- ✅ Convert custom UUID (128-bit) to compact Base44 by removing 25 fixed bits, leaving 103 bits of entropy
- ✅ First hex character is always 0-7, providing additional recognizable pattern
- ✅ Perfect for QR code generation (alphanumeric mode optimization, exactly 19 characters)
- ✅ URL embedding without any percent-encoding required
- ✅ Lossless bidirectional conversion (decode restores exact original UUID with signature)
- ✅ Only encodes UUIDs with the required signature and first bit = 0 (rejects standard UUID v4 without signature)
- ✅ Rust library, CLI tool, and WASM bindings for web applications

**Important**: This library generates and encodes a **custom UUID variant**, not standard RFC4122 UUID v4. The fixed signature `41c2-ae` makes these UUIDs easily identifiable for your application domain.

## Install

- Build CLI: `cargo install --path .`
- Use as a lib: add `qr-url = { git = "https://github.com/GoAskAway/qr-url.git" }` or use a local path dependency.

## CLI usage

```
qr-url

Commands:
  gen                       Generate a random custom UUID with signature '41c2ae' and print Base44 and UUID
  encode <UUID|HEX|@->     Encode a custom UUID into Base44 (requires '41c2ae' signature). Accepts:
                           - canonical UUID string (xxxxxxxx-xxxx-41c2-aexx-xxxxxxxxxxxx)
                           - 32-hex (no dashes)
                           - raw 16-byte via stdin with @-
  decode <BASE44|@->       Decode Base44 string back to UUID string and bytes (hex)

Options:
  -q, --quiet              Only print the primary output
  -h, --help               Show this help
```

Examples:
```bash
# Generate a new custom UUID with signature (19 characters)
$ qr-url gen
Base44: 3FV.2BWT9L7S.OBAZ4G (length: 19)
UUID:   0xxxxxxx-xxxx-41c2-aexx-xxxxxxxxxxxx
Bytes:  0xxxxxxxxxxxxxxx41c2aexxxxxxxxxxxxxx

# Encode an existing custom UUID (must have '41c2ae' signature and first char 0-7)
$ qr-url encode 454f7792-6670-41c2-ae4d-4a05f3000f3f
Base44: 3856ECXC*$A2D-ASF2- (length: 19)
UUID:   454f7792-6670-41c2-ae4d-4a05f3000f3f

# Decode Base44 back to custom UUID
$ qr-url decode 3856ECXC*$A2D-ASF2-
UUID:   454f7792-6670-41c2-ae4d-4a05f3000f3f
Bytes:  454f7792667041c2ae4d4a05f3000f3f
```

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

## Encoding Implementation

This project uses the [qr-base44](https://github.com/kookyleo/qr-base44) library for optimal bit-level encoding:

- **Method**: Treats 103 bits as a single `u128` integer and converts directly to Base44
- **Efficiency**: Achieves theoretical minimum of 19 characters (vs 20 with byte-pair encoding)
- **Performance**: Fast u128 path with zero dependencies (≤128 bits)

The encoding is done through thin wrapper functions in `src/lib.rs`:
- `encode_base44_optimal(bytes: &[u8; 13]) -> String` - calls `qr_base44::encode_bits(103, bytes)`
- `decode_base44_optimal(s: &str) -> Result<[u8; 13], Uuid45Error>` - calls `qr_base44::decode_bits(103, s)`

## Why 103 bits?

Our custom UUID variant reserves:
- 1 bit for first bit (always 0, ensures first hex char is 0-7)
- 4 bits for version (0100 = 4, for RFC4122 compatibility)
- 2 bits for variant (10 = RFC4122)
- 18 bits for our application signature "41c2ae" (excluding the version/variant bits already counted)

Total fixed bits: 1 + 4 + 2 + 18 = 25 bits

Removing them yields 128 - 25 = 103 bits of actual entropy. We pack these into 13 bytes (last byte uses 7 bits). Using optimal Base44 bit-level encoding, this produces exactly 19 characters (theoretical minimum: `ceil(103 * log(2) / log(44)) = 19`).

**Note**: While this maintains RFC4122 structure, the fixed signature `41c2ae` makes it a **custom variant**, not a standard UUID v4.

## License

Apache-2.0

