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
        -p, --port <PORT>        Listen port (default: 3000, or 443 with TLS)\n  \
        -b, --bind <ADDR>        Bind address (default: 127.0.0.1)\n  \
        -m, --mode <MODE>        Output mode (default: json). Formats:\n                           \
        - json                   Return JSON {{base44, uuid, bytes}}\n                           \
        - 301 <URL>              Redirect with 301 (permanent), e.g. '301 https://x.com/{{uuid}}'\n                           \
        - 302 <URL>              Redirect with 302 (temporary), e.g. '302 https://x.com/{{uuid}}'\n                           \
        - html <PATH>            Render HTML template file, supports {{uuid}}, {{base44}}, {{bytes}}\n\n\
        TLS Options:\n  \
        --cert <PATH>            Path to TLS certificate file (PEM format)\n  \
        --key <PATH>             Path to TLS private key file (PEM format)\n\n\
        Options:\n  \
        -q, --quiet              Only print the primary output\n  \
        -h, --help               Show this help\n\n\
        Examples:\n  \
        qr-url gen\n  \
        qr-url encode 454f7792-6670-41c2-ae4d-4a05f3000f3f\n  \
        qr-url decode 3856ECXC*$A2D-ASF2-\n  \
        qr-url server -m json\n  \
        qr-url server -m '301 https://example.com/item/{{uuid}}'\n  \
        qr-url server -m '302 https://example.com/go/{{base44}}'\n  \
        qr-url server -m 'html /path/to/landing.html'\n  \
        qr-url server -p 443 --cert cert.pem --key key.pem\n"
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

    /// Output mode parsed from --mode argument
    #[derive(Debug, Clone)]
    pub enum OutputMode {
        Json,
        Redirect301(String),  // URL template
        Redirect302(String),  // URL template
        HtmlTemplate(String), // File path to HTML template
    }

    impl OutputMode {
        pub fn parse(s: &str) -> Result<Self, String> {
            let s = s.trim();
            if s.eq_ignore_ascii_case("json") {
                return Ok(OutputMode::Json);
            }
            if let Some(url) = s.strip_prefix("301 ") {
                return Ok(OutputMode::Redirect301(url.trim().to_string()));
            }
            if let Some(url) = s.strip_prefix("302 ") {
                return Ok(OutputMode::Redirect302(url.trim().to_string()));
            }
            if let Some(path) = s.strip_prefix("html ") {
                let path = path.trim().to_string();
                // Validate file exists
                if !std::path::Path::new(&path).exists() {
                    return Err(format!("HTML template file not found: {path}"));
                }
                return Ok(OutputMode::HtmlTemplate(path));
            }
            Err(format!(
                "Invalid mode: '{s}'\nExpected: json, '301 <URL>', '302 <URL>', or 'html <PATH>'"
            ))
        }
    }

    #[derive(Clone)]
    pub struct AppState {
        pub mode: OutputMode,
        pub html_template: Option<String>, // Cached HTML template content
    }

    #[derive(Serialize)]
    struct DecodeResponse {
        base44: String,
        uuid: String,
        bytes: String,
    }

    fn render_template(template: &str, base44: &str, uuid_str: &str, bytes_hex: &str) -> String {
        template
            .replace("{{uuid}}", uuid_str)
            .replace("{{base44}}", base44)
            .replace("{{bytes}}", bytes_hex)
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

        match &state.mode {
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
            OutputMode::Redirect301(url_template) => {
                let target = render_template(url_template, &base44, &uuid_str, &bytes_hex);
                tracing::info!(target = %target, "redirecting 301");
                Redirect::permanent(&target).into_response()
            }
            OutputMode::Redirect302(url_template) => {
                let target = render_template(url_template, &base44, &uuid_str, &bytes_hex);
                tracing::info!(target = %target, "redirecting 302");
                Redirect::temporary(&target).into_response()
            }
            OutputMode::HtmlTemplate(_) => {
                if let Some(ref tpl) = state.html_template {
                    let html = render_template(tpl, &base44, &uuid_str, &bytes_hex);
                    Html(html).into_response()
                } else {
                    (StatusCode::INTERNAL_SERVER_ERROR, "Template not loaded").into_response()
                }
            }
        }
    }

    async fn health() -> &'static str {
        "OK"
    }

    pub struct TlsConfig {
        pub cert_path: String,
        pub key_path: String,
    }

    pub async fn run(bind: &str, port: u16, mode: OutputMode, tls: Option<TlsConfig>) {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::from_default_env()
                    .add_directive("qr_url=info".parse().unwrap()),
            )
            .init();

        // Load HTML template if needed
        let html_template = if let OutputMode::HtmlTemplate(ref path) = mode {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    tracing::info!(path = %path, "loaded HTML template");
                    Some(content)
                }
                Err(e) => {
                    eprintln!("Failed to read HTML template: {e}");
                    std::process::exit(2);
                }
            }
        } else {
            None
        };

        let state = Arc::new(AppState {
            mode: mode.clone(),
            html_template,
        });

        let app = Router::new()
            .route("/health", get(health))
            .route("/{base44}", get(handle_base44))
            .with_state(state);

        let addr = format!("{bind}:{port}");

        if let Some(tls_cfg) = tls {
            tracing::info!(addr = %addr, mode = ?mode, "starting HTTPS server");

            let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
                &tls_cfg.cert_path,
                &tls_cfg.key_path,
            )
            .await
            .unwrap_or_else(|e| {
                eprintln!("Failed to load TLS config: {e}");
                eprintln!("  cert: {}", tls_cfg.cert_path);
                eprintln!("  key: {}", tls_cfg.key_path);
                std::process::exit(2);
            });

            axum_server::bind_rustls(addr.parse().unwrap(), rustls_config)
                .serve(app.into_make_service())
                .await
                .unwrap();
        } else {
            tracing::info!(addr = %addr, mode = ?mode, "starting HTTP server");

            let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
            axum::serve(listener, app).await.unwrap();
        }
    }
}

#[cfg(feature = "server")]
fn run_server(args: &[String]) {
    let mut port: Option<u16> = None;
    let mut bind = "127.0.0.1".to_string();
    let mut mode_str: Option<String> = None;
    let mut cert_path: Option<String> = None;
    let mut key_path: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-p" | "--port" => {
                i += 1;
                if i < args.len() {
                    port = Some(args[i].parse().unwrap_or_else(|_| {
                        eprintln!("Invalid port: {}", args[i]);
                        std::process::exit(2);
                    }));
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
                    mode_str = Some(args[i].clone());
                }
            }
            "--cert" => {
                i += 1;
                if i < args.len() {
                    cert_path = Some(args[i].clone());
                }
            }
            "--key" => {
                i += 1;
                if i < args.len() {
                    key_path = Some(args[i].clone());
                }
            }
            _ => {}
        }
        i += 1;
    }

    // Parse mode (default: json)
    let mode = match &mode_str {
        Some(s) => server::OutputMode::parse(s).unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(2);
        }),
        None => server::OutputMode::Json,
    };

    // Build TLS config if both cert and key are provided
    let tls = match (&cert_path, &key_path) {
        (Some(cert), Some(key)) => Some(server::TlsConfig {
            cert_path: cert.clone(),
            key_path: key.clone(),
        }),
        (Some(_), None) => {
            eprintln!("--cert requires --key");
            std::process::exit(2);
        }
        (None, Some(_)) => {
            eprintln!("--key requires --cert");
            std::process::exit(2);
        }
        (None, None) => None,
    };

    // Default port: 443 for TLS, 3000 for HTTP
    let port = port.unwrap_or(if tls.is_some() { 443 } else { 3000 });

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(server::run(&bind, port, mode, tls));
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
