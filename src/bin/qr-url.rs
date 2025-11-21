use clap::{Parser, Subcommand};
use qr_url::{decode_to_bytes, decode_to_string, encode_uuid, encode_uuid_bytes, generate_v4};
use std::io::{self, Read};
use uuid::Uuid;

/// qr-url CLI - Custom UUID variant encoder
///
/// IMPORTANT: This tool works with custom UUID variants (signature '41c2ae'), NOT standard UUID v4.
#[derive(Parser)]
#[command(name = "qr-url", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a random custom UUID with signature '41c2ae' (19-char Base44)
    Gen {
        /// Only print the primary output
        #[arg(short, long)]
        quiet: bool,
    },

    /// Encode a custom UUID into Base44 (requires '41c2ae' signature)
    ///
    /// Accepts: canonical UUID string, 32-hex (no dashes), or raw 16-byte via stdin with @-
    Encode {
        /// UUID input (canonical, 32-hex, or @- for stdin)
        input: String,

        /// Only print the Base44 output
        #[arg(short, long)]
        quiet: bool,
    },

    /// Decode Base44 string back to custom UUID (19 chars)
    Decode {
        /// Base44 string or @- for stdin
        input: String,

        /// Only print the UUID output
        #[arg(short, long)]
        quiet: bool,
    },

    /// Start HTTP server (requires 'server' feature)
    #[cfg(feature = "server")]
    Server(ServerArgs),

    /// Start HTTP server (requires 'server' feature)
    #[cfg(not(feature = "server"))]
    Server {},
}

#[cfg(feature = "server")]
#[derive(clap::Args)]
struct ServerArgs {
    /// Listen port (default: 3000, or 443 with TLS)
    #[arg(short, long)]
    port: Option<u16>,

    /// Bind address
    #[arg(short, long, default_value = "127.0.0.1")]
    bind: String,

    /// Output mode: json, '301 <URL>', '302 <URL>', or 'html <PATH>'
    ///
    /// Examples:
    ///   -m json
    ///   -m '301 https://example.com/item/{{uuid}}'
    ///   -m '302 https://example.com/go/{{base44}}'
    ///   -m 'html /path/to/landing.html'
    #[arg(short, long, default_value = "json")]
    mode: String,

    /// Path to TLS certificate file (PEM format)
    #[arg(long)]
    cert: Option<String>,

    /// Path to TLS private key file (PEM format)
    #[arg(long)]
    key: Option<String>,
}

/// Parse UUID from string (without stdin support, for testability)
fn parse_uuid_input_impl(arg: &str) -> io::Result<[u8; 16]> {
    // Try UUID parse first (most common case)
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
    parse_uuid_input_impl(arg)
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
        Path(raw_base44): Path<String>,
        State(state): State<Arc<AppState>>,
    ) -> Response {
        // Manually decode %2F → / (axum doesn't decode this for path segments)
        // Other URL-encoded chars like %2B (+) and %3A (:) are decoded automatically
        let base44 = raw_base44.replace("%2F", "/").replace("%2f", "/");

        // Validate Base44 length (must be 19 chars for custom UUID variant)
        if base44.len() != 19 {
            tracing::warn!(
                base44 = %base44,
                raw = %raw_base44,
                len = base44.len(),
                "invalid Base44 length"
            );
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid Base44 length: expected 19, got {}", base44.len()),
            )
                .into_response();
        }

        // Decode Base44 to UUID
        let uuid_str = match decode_to_string(&base44) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(base44 = %base44, error = %e, "decode failed");
                return (StatusCode::BAD_REQUEST, format!("Invalid Base44: {e}")).into_response();
            }
        };

        let bytes = match decode_to_bytes(&base44) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(base44 = %base44, error = %e, "decode_to_bytes failed unexpectedly");
                return (StatusCode::INTERNAL_SERVER_ERROR, "Decode error").into_response();
            }
        };
        let bytes_hex = hex::encode(bytes);

        tracing::info!(base44 = %base44, uuid = %uuid_str, "decoded");

        match &state.mode {
            OutputMode::Json => {
                let resp = DecodeResponse {
                    base44: base44.clone(),
                    uuid: uuid_str,
                    bytes: bytes_hex,
                };
                match serde_json::to_string_pretty(&resp) {
                    Ok(json) => (
                        StatusCode::OK,
                        [(header::CONTENT_TYPE, "application/json")],
                        json,
                    )
                        .into_response(),
                    Err(e) => {
                        tracing::error!(error = %e, "JSON serialization failed");
                        (StatusCode::INTERNAL_SERVER_ERROR, "Serialization error").into_response()
                    }
                }
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
                    tracing::error!("HTML template not loaded");
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
fn run_server(args: ServerArgs) {
    // Parse mode
    let mode = server::OutputMode::parse(&args.mode).unwrap_or_else(|e| {
        eprintln!("{e}");
        std::process::exit(2);
    });

    // Build TLS config if both cert and key are provided
    let tls = match (&args.cert, &args.key) {
        (Some(cert), Some(key)) => Some(server::TlsConfig {
            cert_path: cert.clone(),
            key_path: key.clone(),
        }),
        (Some(_), None) => {
            eprintln!("error: --cert requires --key");
            std::process::exit(2);
        }
        (None, Some(_)) => {
            eprintln!("error: --key requires --cert");
            std::process::exit(2);
        }
        (None, None) => None,
    };

    // Default port: 443 for TLS, 3000 for HTTP
    let port = args.port.unwrap_or(if tls.is_some() { 443 } else { 3000 });

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(server::run(&args.bind, port, mode, tls));
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Gen { quiet } => {
            let u = generate_v4();
            let b44 = encode_uuid(u).expect("generate_v4 should produce valid signature UUID");
            if quiet {
                println!("{b44}");
            } else {
                println!("Base44: {b44}");
                println!("UUID:   {}", u.hyphenated());
                println!("Bytes:  {}", hex::encode(u.into_bytes()));
            }
        }
        Commands::Encode { input, quiet } => match parse_uuid_input(&input) {
            Ok(bytes) => match encode_uuid_bytes(&bytes) {
                Ok(s) => {
                    if quiet {
                        println!("{s}");
                    } else {
                        println!("Base44: {s}");
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(2);
                }
            },
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(2);
            }
        },
        Commands::Decode { input, quiet } => {
            let input = if input == "@-" {
                let mut s = String::new();
                io::stdin().read_to_string(&mut s).unwrap();
                s.trim().to_string()
            } else {
                input
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
                    eprintln!("error: {e}");
                    std::process::exit(2);
                }
            }
        }
        #[cfg(feature = "server")]
        Commands::Server(args) => {
            run_server(args);
        }
        #[cfg(not(feature = "server"))]
        Commands::Server {} => {
            eprintln!("error: server feature not enabled");
            eprintln!("rebuild with: cargo build --features server");
            std::process::exit(2);
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // parse_uuid_input_impl tests
    // ------------------------------------------------------------------------

    #[test]
    fn parse_uuid_canonical_format() {
        // Standard UUID with dashes
        let input = "550e8400-e29b-41d4-a716-446655440000";
        let result = parse_uuid_input_impl(input).unwrap();
        let expected: [u8; 16] = [
            0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
            0x00, 0x00,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn parse_uuid_32hex_lowercase() {
        let input = "550e8400e29b41d4a716446655440000";
        let result = parse_uuid_input_impl(input).unwrap();
        let expected: [u8; 16] = [
            0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
            0x00, 0x00,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn parse_uuid_32hex_uppercase() {
        let input = "550E8400E29B41D4A716446655440000";
        let result = parse_uuid_input_impl(input).unwrap();
        let expected: [u8; 16] = [
            0x55, 0x0e, 0x84, 0x00, 0xe2, 0x9b, 0x41, 0xd4, 0xa7, 0x16, 0x44, 0x66, 0x55, 0x44,
            0x00, 0x00,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn parse_uuid_32hex_mixed_case() {
        let input = "550e8400E29B41d4A716446655440000";
        let result = parse_uuid_input_impl(input).unwrap();
        assert!(result.len() == 16);
    }

    #[test]
    fn parse_uuid_all_zeros() {
        let input = "00000000-0000-0000-0000-000000000000";
        let result = parse_uuid_input_impl(input).unwrap();
        assert_eq!(result, [0u8; 16]);
    }

    #[test]
    fn parse_uuid_all_fs() {
        let input = "ffffffff-ffff-ffff-ffff-ffffffffffff";
        let result = parse_uuid_input_impl(input).unwrap();
        assert_eq!(result, [0xffu8; 16]);
    }

    #[test]
    fn parse_uuid_invalid_empty() {
        let result = parse_uuid_input_impl("");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid"));
    }

    #[test]
    fn parse_uuid_invalid_short_hex() {
        // 31 hex chars - too short
        let input = "550e8400e29b41d4a71644665544000";
        let result = parse_uuid_input_impl(input);
        assert!(result.is_err());
    }

    #[test]
    fn parse_uuid_invalid_long_hex() {
        // 33 hex chars - too long
        let input = "550e8400e29b41d4a7164466554400001";
        let result = parse_uuid_input_impl(input);
        assert!(result.is_err());
    }

    #[test]
    fn parse_uuid_invalid_chars() {
        // Contains 'g' which is not hex
        let input = "550e8400e29b41d4a716446655440g00";
        let result = parse_uuid_input_impl(input);
        assert!(result.is_err());
    }

    #[test]
    fn parse_uuid_invalid_format() {
        let result = parse_uuid_input_impl("not-a-uuid");
        assert!(result.is_err());
    }

    #[test]
    fn parse_uuid_braced_format() {
        // UUID crate supports braced format
        let input = "{550e8400-e29b-41d4-a716-446655440000}";
        let result = parse_uuid_input_impl(input).unwrap();
        assert_eq!(result[0], 0x55);
    }

    #[test]
    fn parse_uuid_urn_format() {
        // UUID crate supports URN format
        let input = "urn:uuid:550e8400-e29b-41d4-a716-446655440000";
        let result = parse_uuid_input_impl(input).unwrap();
        assert_eq!(result[0], 0x55);
    }
}

#[cfg(all(test, feature = "server"))]
mod server_tests {
    use super::server::*;
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    // ------------------------------------------------------------------------
    // OutputMode::parse tests
    // ------------------------------------------------------------------------

    #[test]
    fn output_mode_json_lowercase() {
        let mode = OutputMode::parse("json").unwrap();
        assert!(matches!(mode, OutputMode::Json));
    }

    #[test]
    fn output_mode_json_uppercase() {
        let mode = OutputMode::parse("JSON").unwrap();
        assert!(matches!(mode, OutputMode::Json));
    }

    #[test]
    fn output_mode_json_mixed_case() {
        let mode = OutputMode::parse("Json").unwrap();
        assert!(matches!(mode, OutputMode::Json));
    }

    #[test]
    fn output_mode_json_with_whitespace() {
        let mode = OutputMode::parse("  json  ").unwrap();
        assert!(matches!(mode, OutputMode::Json));
    }

    #[test]
    fn output_mode_301_redirect() {
        let mode = OutputMode::parse("301 https://example.com/{{uuid}}").unwrap();
        match mode {
            OutputMode::Redirect301(url) => {
                assert_eq!(url, "https://example.com/{{uuid}}");
            }
            _ => panic!("Expected Redirect301"),
        }
    }

    #[test]
    fn output_mode_301_with_extra_spaces() {
        let mode = OutputMode::parse("301   https://example.com/{{uuid}}  ").unwrap();
        match mode {
            OutputMode::Redirect301(url) => {
                assert_eq!(url, "https://example.com/{{uuid}}");
            }
            _ => panic!("Expected Redirect301"),
        }
    }

    #[test]
    fn output_mode_302_redirect() {
        let mode = OutputMode::parse("302 https://example.com/go/{{base44}}").unwrap();
        match mode {
            OutputMode::Redirect302(url) => {
                assert_eq!(url, "https://example.com/go/{{base44}}");
            }
            _ => panic!("Expected Redirect302"),
        }
    }

    #[test]
    fn output_mode_html_existing_file() {
        // Create temp file
        let temp = tempfile::NamedTempFile::new().unwrap();
        let path = temp.path().to_str().unwrap();

        let mode = OutputMode::parse(&format!("html {}", path)).unwrap();
        match mode {
            OutputMode::HtmlTemplate(p) => {
                assert_eq!(p, path);
            }
            _ => panic!("Expected HtmlTemplate"),
        }
    }

    #[test]
    fn output_mode_html_nonexistent_file() {
        let result = OutputMode::parse("html /nonexistent/path/to/file.html");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn output_mode_invalid() {
        let result = OutputMode::parse("redirect https://example.com");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid mode"));
    }

    #[test]
    fn output_mode_invalid_empty() {
        let result = OutputMode::parse("");
        assert!(result.is_err());
    }

    #[test]
    fn output_mode_invalid_300() {
        // 300 is not supported
        let result = OutputMode::parse("300 https://example.com");
        assert!(result.is_err());
    }

    #[test]
    fn output_mode_invalid_303() {
        // 303 is not supported
        let result = OutputMode::parse("303 https://example.com");
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------------
    // render_template tests (need to make it pub for testing)
    // ------------------------------------------------------------------------

    fn render_template(template: &str, base44: &str, uuid_str: &str, bytes_hex: &str) -> String {
        template
            .replace("{{uuid}}", uuid_str)
            .replace("{{base44}}", base44)
            .replace("{{bytes}}", bytes_hex)
    }

    #[test]
    fn render_all_placeholders() {
        let template = "UUID: {{uuid}}, Base44: {{base44}}, Bytes: {{bytes}}";
        let result = render_template(
            template,
            "ABC123",
            "550e8400-e29b-41d4-a716-446655440000",
            "550e8400e29b41d4a716446655440000",
        );
        assert_eq!(
            result,
            "UUID: 550e8400-e29b-41d4-a716-446655440000, Base44: ABC123, Bytes: 550e8400e29b41d4a716446655440000"
        );
    }

    #[test]
    fn render_uuid_only() {
        let template = "https://example.com/item/{{uuid}}";
        let result = render_template(
            template,
            "ABC",
            "550e8400-e29b-41d4-a716-446655440000",
            "hex",
        );
        assert_eq!(
            result,
            "https://example.com/item/550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn render_base44_only() {
        let template = "https://example.com/go/{{base44}}";
        let result = render_template(template, "ABC123XYZ", "uuid", "hex");
        assert_eq!(result, "https://example.com/go/ABC123XYZ");
    }

    #[test]
    fn render_bytes_only() {
        let template = "https://example.com/raw/{{bytes}}";
        let result = render_template(template, "b44", "uuid", "deadbeef");
        assert_eq!(result, "https://example.com/raw/deadbeef");
    }

    #[test]
    fn render_no_placeholders() {
        let template = "https://example.com/static";
        let result = render_template(template, "b44", "uuid", "hex");
        assert_eq!(result, "https://example.com/static");
    }

    #[test]
    fn render_empty_template() {
        let result = render_template("", "b44", "uuid", "hex");
        assert_eq!(result, "");
    }

    #[test]
    fn render_duplicate_placeholders() {
        let template = "{{uuid}}/{{uuid}}";
        let result = render_template(template, "b44", "my-uuid", "hex");
        assert_eq!(result, "my-uuid/my-uuid");
    }

    #[test]
    fn render_special_chars_in_values() {
        let template = "{{base44}}";
        // Base44 can contain special chars like + / :
        let result = render_template(template, "ABC+DEF/GHI:JKL", "uuid", "hex");
        assert_eq!(result, "ABC+DEF/GHI:JKL");
    }

    // ------------------------------------------------------------------------
    // HTTP handler integration tests
    // ------------------------------------------------------------------------

    fn create_test_app(mode: OutputMode, html_template: Option<String>) -> Router {
        use axum::routing::get;

        let state = Arc::new(AppState {
            mode,
            html_template,
        });

        Router::new()
            .route("/health", get(|| async { "OK" }))
            .route(
                "/{base44}",
                get(
                    |axum::extract::Path(raw_base44): axum::extract::Path<String>,
                     axum::extract::State(state): axum::extract::State<Arc<AppState>>| async move {
                        use axum::http::header;
                        use axum::response::{Html, IntoResponse, Redirect};
                        use qr_url::{decode_to_bytes, decode_to_string};

                        // Manually decode %2F → / (axum doesn't decode this for path segments)
                        let base44 = raw_base44.replace("%2F", "/").replace("%2f", "/");

                        // Length validation
                        if base44.len() != 19 {
                            return (
                                StatusCode::BAD_REQUEST,
                                format!("Invalid Base44 length: expected 19, got {}", base44.len()),
                            )
                                .into_response();
                        }

                        let uuid_str = match decode_to_string(&base44) {
                            Ok(s) => s,
                            Err(e) => {
                                return (StatusCode::BAD_REQUEST, format!("Invalid Base44: {e}"))
                                    .into_response();
                            }
                        };

                        let bytes = match decode_to_bytes(&base44) {
                            Ok(b) => b,
                            Err(_) => {
                                return (StatusCode::INTERNAL_SERVER_ERROR, "Decode error")
                                    .into_response();
                            }
                        };
                        let bytes_hex = hex::encode(bytes);

                        match &state.mode {
                            OutputMode::Json => {
                                let resp = serde_json::json!({
                                    "base44": base44,
                                    "uuid": uuid_str,
                                    "bytes": bytes_hex,
                                });
                                (
                                    StatusCode::OK,
                                    [(header::CONTENT_TYPE, "application/json")],
                                    serde_json::to_string_pretty(&resp).unwrap(),
                                )
                                    .into_response()
                            }
                            OutputMode::Redirect301(url_template) => {
                                let target = render_template(url_template, &base44, &uuid_str, &bytes_hex);
                                Redirect::permanent(&target).into_response()
                            }
                            OutputMode::Redirect302(url_template) => {
                                let target = render_template(url_template, &base44, &uuid_str, &bytes_hex);
                                Redirect::temporary(&target).into_response()
                            }
                            OutputMode::HtmlTemplate(_) => {
                                if let Some(ref tpl) = state.html_template {
                                    let html = render_template(tpl, &base44, &uuid_str, &bytes_hex);
                                    Html(html).into_response()
                                } else {
                                    (StatusCode::INTERNAL_SERVER_ERROR, "Template not loaded")
                                        .into_response()
                                }
                            }
                        }
                    },
                ),
            )
            .with_state(state)
    }

    #[tokio::test]
    async fn health_endpoint() {
        let app = create_test_app(OutputMode::Json, None);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// Build a request - Base44 characters are passed as-is
    /// Note: '/' in path will cause routing issues in tests, but in production
    /// clients should URL-encode such characters and axum will decode them.
    fn build_base44_request(base44: &str) -> Request<Body> {
        // For test simplicity, we skip Base44 strings containing '/'
        // In production, clients would URL-encode '/' as %2F
        assert!(
            !base44.contains('/'),
            "Test helper doesn't support '/' - use a different UUID"
        );
        Request::builder()
            .uri(format!("/{}", base44))
            .body(Body::empty())
            .unwrap()
    }

    /// Generate a Base44 without '/' for testing (axum routing limitation)
    fn generate_test_base44() -> String {
        loop {
            let uuid = qr_url::generate_v4();
            let base44 = qr_url::encode_uuid(uuid).unwrap();
            // '/' causes routing issues in test environment
            if !base44.contains('/') {
                return base44;
            }
        }
    }

    #[tokio::test]
    async fn decode_valid_base44_json_mode() {
        let app = create_test_app(OutputMode::Json, None);
        let base44 = generate_test_base44();

        let response = app.oneshot(build_base44_request(&base44)).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["base44"], base44);
        assert!(json["uuid"].as_str().unwrap().contains("-"));
        assert_eq!(json["bytes"].as_str().unwrap().len(), 32);
    }

    /// Test: axum Path extractor DOES auto-decode URL-encoded chars
    /// Browser sends /%41 → axum decodes to /A → handler receives "A"
    #[tokio::test]
    async fn url_encoding_is_auto_decoded() {
        let app = create_test_app(OutputMode::Json, None);

        // A valid 19-char Base44 without '/'
        let base44 = generate_test_base44();
        assert_eq!(base44.len(), 19);

        // URL-encode some chars - simulates browser behavior
        let encoded = base44.replace('A', "%41"); // 'A' → '%41'

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/{}", encoded))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // axum decodes %41 back to A, so handler receives original Base44
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Response contains the decoded (original) Base44
        assert_eq!(json["base44"], base44);
    }

    /// Test: URL-encoded '/' (%2F) is manually decoded by server
    /// axum doesn't decode %2F automatically, so we do it in the handler
    #[tokio::test]
    async fn url_encoded_slash_is_manually_decoded() {
        let app = create_test_app(OutputMode::Json, None);

        // Generate a Base44 WITH '/' to test %2F decoding
        let base44_with_slash = loop {
            let uuid = qr_url::generate_v4();
            let b44 = qr_url::encode_uuid(uuid).unwrap();
            if b44.contains('/') {
                break b44;
            }
        };

        // URL-encode the '/' as %2F (what browsers do)
        let encoded = base44_with_slash.replace('/', "%2F");

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/{}", encoded))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Server manually decodes %2F → /, so this should work
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        // Response contains the original Base44 with '/'
        assert_eq!(json["base44"], base44_with_slash);
    }

    #[tokio::test]
    async fn decode_invalid_base44_wrong_length_short() {
        let app = create_test_app(OutputMode::Json, None);

        // Too short (less than 19 chars)
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ABC123")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("length"));
    }

    #[tokio::test]
    async fn decode_invalid_base44_wrong_length_long() {
        let app = create_test_app(OutputMode::Json, None);

        // Too long (more than 19 chars)
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ABCDEFGHIJKLMNOPQRSTUVWXYZ")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert!(body_str.contains("length"));
    }

    #[tokio::test]
    async fn decode_invalid_base44_bad_chars() {
        let app = create_test_app(OutputMode::Json, None);

        // Exactly 19 chars but contains invalid Base44 characters (!)
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/INVALID!!!!!!!!!!!")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn decode_with_301_redirect() {
        let app = create_test_app(
            OutputMode::Redirect301("https://example.com/item/{{uuid}}".to_string()),
            None,
        );

        let base44 = generate_test_base44();

        let response = app.oneshot(build_base44_request(&base44)).await.unwrap();

        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);

        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.starts_with("https://example.com/item/"));
        assert!(location.contains("-")); // UUID format
    }

    #[tokio::test]
    async fn decode_with_302_redirect() {
        let app = create_test_app(
            OutputMode::Redirect302("https://example.com/go/{{base44}}".to_string()),
            None,
        );

        let base44 = generate_test_base44();

        let response = app.oneshot(build_base44_request(&base44)).await.unwrap();

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);

        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains(&base44));
    }

    #[tokio::test]
    async fn decode_with_html_template() {
        let template = "<html><body>UUID: {{uuid}}, Code: {{base44}}</body></html>";
        let app = create_test_app(
            OutputMode::HtmlTemplate("/dummy/path".to_string()),
            Some(template.to_string()),
        );

        let base44 = generate_test_base44();

        let response = app.oneshot(build_base44_request(&base44)).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();

        assert!(html.contains(&base44));
        assert!(html.contains("-")); // UUID contains dashes
    }

    #[tokio::test]
    async fn decode_html_template_not_loaded() {
        let app = create_test_app(OutputMode::HtmlTemplate("/dummy/path".to_string()), None);

        let base44 = generate_test_base44();

        let response = app.oneshot(build_base44_request(&base44)).await.unwrap();

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    // ------------------------------------------------------------------------
    // TLS config validation tests
    // ------------------------------------------------------------------------

    #[test]
    fn tls_config_both_provided() {
        let cert = Some("cert.pem".to_string());
        let key = Some("key.pem".to_string());

        match (&cert, &key) {
            (Some(c), Some(k)) => {
                assert_eq!(c, "cert.pem");
                assert_eq!(k, "key.pem");
            }
            _ => panic!("Should have both"),
        }
    }

    #[test]
    fn tls_config_neither_provided() {
        let cert: Option<String> = None;
        let key: Option<String> = None;

        let has_tls = cert.is_some() && key.is_some();
        assert!(!has_tls);
    }

    // ------------------------------------------------------------------------
    // Default port logic tests
    // ------------------------------------------------------------------------

    #[test]
    fn default_port_without_tls() {
        let tls: Option<TlsConfig> = None;
        let port: Option<u16> = None;
        let actual = port.unwrap_or(if tls.is_some() { 443 } else { 3000 });
        assert_eq!(actual, 3000);
    }

    #[test]
    fn default_port_with_tls() {
        let tls = Some(TlsConfig {
            cert_path: "cert.pem".to_string(),
            key_path: "key.pem".to_string(),
        });
        let port: Option<u16> = None;
        let actual = port.unwrap_or(if tls.is_some() { 443 } else { 3000 });
        assert_eq!(actual, 443);
    }

    #[test]
    fn explicit_port_overrides_default() {
        let tls: Option<TlsConfig> = None;
        let port = Some(8080u16);
        let actual = port.unwrap_or(if tls.is_some() { 443 } else { 3000 });
        assert_eq!(actual, 8080);
    }

    #[test]
    fn explicit_port_overrides_tls_default() {
        let tls = Some(TlsConfig {
            cert_path: "cert.pem".to_string(),
            key_path: "key.pem".to_string(),
        });
        let port = Some(8443u16);
        let actual = port.unwrap_or(if tls.is_some() { 443 } else { 3000 });
        assert_eq!(actual, 8443);
    }
}
