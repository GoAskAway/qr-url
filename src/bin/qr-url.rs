use qr_url::{decode_to_bytes, decode_to_string, encode_uuid, encode_uuid_bytes, generate_v4};
use std::io::{self, Read};
use uuid::Uuid;

fn print_usage() {
    eprintln!(
        "qr-url CLI - Custom UUID variant encoder\n\n\
        IMPORTANT: This tool works with custom UUID variants (signature '41c2ae'), NOT standard UUID v4.\n\n\
        Commands:\n  \
        gen                       Generate a random custom UUID with signature '41c2ae' (19-char Base44)\n  \
        encode <UUID|HEX|@->     Encode a custom UUID into Base44 (requires '41c2ae' signature). Accepts:\n                           \
        - canonical UUID string (0xxxxxxx-xxxx-41c2-aexx-xxxxxxxxxxxx, first char 0-7)\n                           \
        - 32-hex (no dashes)\n                           \
        - raw 16-byte via stdin with @-\n  \
        decode <BASE44|@->       Decode Base44 string back to custom UUID (19 chars)\n  \
        server [OPTIONS]         Start HTTP server (requires 'server' feature)\n\n\
        Server Options:\n  \
        -p, --port <PORT>        Listen port (default: 3000)\n  \
        -b, --bind <ADDR>        Bind address (default: 127.0.0.1)\n  \
        -t, --template <URL>     Redirect URL template, use {{uuid}} or {{base44}} as placeholder\n  \
        -m, --mode <MODE>        Output mode: redirect, json, html (default: json)\n\n\
        Options:\n  \
        -q, --quiet              Only print the primary output\n  \
        -h, --help               Show this help\n\n\
        Examples:\n  \
        qr-url gen\n  \
        qr-url encode 454f7792-6670-41c2-ae4d-4a05f3000f3f\n  \
        qr-url decode 3856ECXC*$A2D-ASF2-\n  \
        qr-url server -p 8080 -m redirect -t 'https://example.com/item/{{uuid}}'\n"
    );
}

fn parse_uuid_input(arg: &str) -> io::Result<[u8; 16]> {
    // @- => read raw bytes from stdin
    if arg == "@-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf)?;
        if buf.len() != 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("stdin must be 16 bytes, got {}", buf.len()),
            ));
        }
        let mut arr = [0u8; 16];
        arr.copy_from_slice(&buf);
        return Ok(arr);
    }

    // Try UUID parse
    if let Ok(u) = Uuid::parse_str(arg) {
        return Ok(u.into_bytes());
    }

    // Try 32-hex
    if arg.len() == 32 && arg.chars().all(|c| c.is_ascii_hexdigit()) {
        let mut bytes = [0u8; 16];
        for i in 0..16 {
            let hi = u8::from_str_radix(&arg[i * 2..i * 2 + 1], 16).unwrap();
            let lo = u8::from_str_radix(&arg[i * 2 + 1..i * 2 + 2], 16).unwrap();
            bytes[i] = (hi << 4) | lo;
        }
        return Ok(bytes);
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "invalid UUID input format",
    ))
}

#[cfg(feature = "server")]
mod server {
    use axum::{
        Router,
        extract::{Path, State},
        http::{StatusCode, header},
        response::{Html, IntoResponse, Redirect, Response},
        routing::get,
    };
    use qr_url::{decode_to_bytes, decode_to_string};
    use serde::Serialize;
    use std::sync::Arc;

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum OutputMode {
        Redirect,
        Json,
        Html,
    }

    impl std::str::FromStr for OutputMode {
        type Err = String;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            match s.to_lowercase().as_str() {
                "redirect" | "r" => Ok(OutputMode::Redirect),
                "json" | "j" => Ok(OutputMode::Json),
                "html" | "h" => Ok(OutputMode::Html),
                _ => Err(format!("unknown mode: {s}, expected: redirect, json, html")),
            }
        }
    }

    #[derive(Clone)]
    pub struct AppState {
        pub mode: OutputMode,
        pub template: Option<String>,
    }

    #[derive(Serialize)]
    struct DecodeResponse {
        base44: String,
        uuid: String,
        bytes: String,
    }

    async fn handle_base44(
        Path(base44): Path<String>,
        State(state): State<Arc<AppState>>,
    ) -> Response {
        // Decode Base44 to UUID
        let uuid_str = match decode_to_string(&base44) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(base44 = %base44, error = %e, "decode failed");
                return (StatusCode::BAD_REQUEST, format!("Invalid Base44: {e}")).into_response();
            }
        };

        let bytes = decode_to_bytes(&base44).unwrap();
        let bytes_hex = hex::encode(bytes);

        tracing::info!(base44 = %base44, uuid = %uuid_str, "decoded");

        match state.mode {
            OutputMode::Json => {
                let resp = DecodeResponse {
                    base44: base44.clone(),
                    uuid: uuid_str,
                    bytes: bytes_hex,
                };
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    serde_json::to_string_pretty(&resp).unwrap(),
                )
                    .into_response()
            }
            OutputMode::Html => {
                let html = format!(
                    r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>QR-URL Decode</title>
    <style>
        body {{ font-family: system-ui, sans-serif; padding: 2rem; max-width: 600px; margin: 0 auto; }}
        .field {{ margin: 1rem 0; }}
        .label {{ font-weight: bold; color: #666; }}
        .value {{ font-family: monospace; background: #f4f4f4; padding: 0.5rem; border-radius: 4px; word-break: break-all; }}
    </style>
</head>
<body>
    <h1>QR-URL Decode Result</h1>
    <div class="field">
        <div class="label">Base44:</div>
        <div class="value">{base44}</div>
    </div>
    <div class="field">
        <div class="label">UUID:</div>
        <div class="value">{uuid_str}</div>
    </div>
    <div class="field">
        <div class="label">Bytes (hex):</div>
        <div class="value">{bytes_hex}</div>
    </div>
</body>
</html>"#
                );
                Html(html).into_response()
            }
            OutputMode::Redirect => {
                let target = if let Some(ref tpl) = state.template {
                    tpl.replace("{{uuid}}", &uuid_str)
                        .replace("{{base44}}", &base44)
                        .replace("{{bytes}}", &bytes_hex)
                } else {
                    // Default: just return the UUID as path
                    format!("/{uuid_str}")
                };
                tracing::info!(target = %target, "redirecting");
                Redirect::temporary(&target).into_response()
            }
        }
    }

    async fn health() -> &'static str {
        "OK"
    }

    pub async fn run(bind: &str, port: u16, mode: OutputMode, template: Option<String>) {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("qr_url=info".parse().unwrap()),
            )
            .init();

        let state = Arc::new(AppState { mode, template });

        let app = Router::new()
            .route("/health", get(health))
            .route("/{base44}", get(handle_base44))
            .with_state(state);

        let addr = format!("{bind}:{port}");
        tracing::info!(addr = %addr, mode = ?mode, "starting server");

        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();
    }
}

#[cfg(feature = "server")]
fn run_server(args: &[String]) {
    let mut port: u16 = 3000;
    let mut bind = "127.0.0.1".to_string();
    let mut mode = server::OutputMode::Json;
    let mut template: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-p" | "--port" => {
                i += 1;
                if i < args.len() {
                    port = args[i].parse().unwrap_or_else(|_| {
                        eprintln!("Invalid port: {}", args[i]);
                        std::process::exit(2);
                    });
                }
            }
            "-b" | "--bind" => {
                i += 1;
                if i < args.len() {
                    bind = args[i].clone();
                }
            }
            "-m" | "--mode" => {
                i += 1;
                if i < args.len() {
                    mode = args[i].parse().unwrap_or_else(|e| {
                        eprintln!("{e}");
                        std::process::exit(2);
                    });
                }
            }
            "-t" | "--template" => {
                i += 1;
                if i < args.len() {
                    template = Some(args[i].clone());
                }
            }
            _ => {}
        }
        i += 1;
    }

    // Validate: redirect mode requires template
    if mode == server::OutputMode::Redirect && template.is_none() {
        eprintln!("Redirect mode requires --template <URL>");
        eprintln!("Example: --template 'https://example.com/item/{{{{uuid}}}}'");
        std::process::exit(2);
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(server::run(&bind, port, mode, template));
}

#[cfg(not(feature = "server"))]
fn run_server(_args: &[String]) {
    eprintln!("Server feature not enabled. Rebuild with: cargo build --features server");
    std::process::exit(2);
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    if args.len() <= 1 {
        print_usage();
        return;
    }

    let mut quiet = false;
    args.retain(|a| match a.as_str() {
        "-q" | "--quiet" => {
            quiet = true;
            false
        }
        _ => true,
    });

    match args.get(1).map(String::as_str) {
        Some("-h") | Some("--help") => {
            print_usage();
        }
        Some("gen") => {
            let u = generate_v4();
            let b45 = encode_uuid(u).expect("generate_v4 should produce valid signature UUID");
            if quiet {
                println!("{b45}");
                return;
            }
            println!("Base44: {b45}");
            println!("UUID:   {}", u.hyphenated());
            println!("Bytes:  {}", hex::encode(u.into_bytes()));
        }
        Some("encode") => {
            if args.len() < 3 {
                eprintln!("encode requires an input");
                std::process::exit(2);
            }
            match parse_uuid_input(&args[2]) {
                Ok(bytes) => match encode_uuid_bytes(&bytes) {
                    Ok(s) => {
                        if quiet {
                            println!("{s}");
                        } else {
                            println!("Base44: {s}");
                        }
                    }
                    Err(e) => {
                        eprintln!("Encode error: {e}");
                        std::process::exit(2);
                    }
                },
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(2);
                }
            }
        }
        Some("decode") => {
            if args.len() < 3 {
                eprintln!("decode requires a Base44 string or @-");
                std::process::exit(2);
            }
            let input = if args[2].as_str() == "@-" {
                let mut s = String::new();
                io::stdin().read_to_string(&mut s).unwrap();
                s.trim().to_string()
            } else {
                args[2].clone()
            };
            match decode_to_string(&input) {
                Ok(uuid_str) => {
                    let bytes = decode_to_bytes(&input).unwrap();
                    if quiet {
                        println!("{uuid_str}");
                    } else {
                        println!("UUID:   {uuid_str}");
                        println!("Bytes:  {}", hex::encode(bytes));
                    }
                }
                Err(e) => {
                    eprintln!("{e}");
                    std::process::exit(2);
                }
            }
        }
        Some("server") => {
            let server_args: Vec<String> = args[2..].to_vec();
            run_server(&server_args);
        }
        _ => {
            print_usage();
        }
    }
}
