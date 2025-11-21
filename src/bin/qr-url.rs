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
    use qr_url::{decode_to_bytes, decode_to_string};
    use serde::Serialize;
    use std::sync::Arc;
    use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

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
        pub html_template: Option<String>,
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

    /// HTTP response builder
    struct HttpResponse {
        status: u16,
        status_text: &'static str,
        headers: Vec<(String, String)>,
        body: String,
    }

    impl HttpResponse {
        fn new(status: u16, status_text: &'static str) -> Self {
            Self {
                status,
                status_text,
                headers: Vec::new(),
                body: String::new(),
            }
        }

        fn header(mut self, name: &str, value: &str) -> Self {
            self.headers.push((name.to_string(), value.to_string()));
            self
        }

        fn body(mut self, body: String) -> Self {
            self.body = body;
            self
        }

        fn build(self) -> Vec<u8> {
            let mut response = format!("HTTP/1.1 {} {}\r\n", self.status, self.status_text);
            for (name, value) in &self.headers {
                response.push_str(&format!("{}: {}\r\n", name, value));
            }
            response.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
            response.push_str("Connection: close\r\n");
            response.push_str("\r\n");
            response.push_str(&self.body);
            response.into_bytes()
        }

        fn ok() -> Self {
            Self::new(200, "OK")
        }

        fn bad_request() -> Self {
            Self::new(400, "Bad Request")
        }

        fn not_found() -> Self {
            Self::new(404, "Not Found")
        }

        fn internal_error() -> Self {
            Self::new(500, "Internal Server Error")
        }

        fn redirect(status: u16, location: &str) -> Self {
            let status_text = if status == 301 {
                "Moved Permanently"
            } else {
                "Found"
            };
            Self::new(status, status_text).header("Location", location)
        }
    }

    /// Parse raw HTTP request path (preserves all characters including //)
    fn parse_request_path(request_line: &str) -> Option<String> {
        // Format: "GET /path HTTP/1.1"
        let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
        if parts.len() >= 2 && parts[0] == "GET" {
            Some(parts[1].to_string())
        } else {
            None
        }
    }

    /// Handle a single HTTP request
    pub async fn handle_request(raw_path: &str, state: &AppState) -> Vec<u8> {
        // Health check
        if raw_path == "/health" {
            return HttpResponse::ok()
                .header("Content-Type", "text/plain")
                .body("OK".to_string())
                .build();
        }

        // Extract base44 from path (skip leading /)
        // Path could be "/ABC" or "//ABC" (when Base44 starts with /)
        let raw = match raw_path.strip_prefix('/') {
            Some(r) if !r.is_empty() => r,
            _ => {
                return HttpResponse::not_found()
                    .body("Not Found".to_string())
                    .build();
            }
        };

        // Handle //ABC case: if raw starts with /, it means original Base44 starts with /
        // We keep the leading / as part of the Base44
        // raw = "/ABC..." means path was "//ABC..."

        // Normalize input: raw Base44 (19 chars) or URL-encoded (>19 chars)
        let base44 = if raw.len() == 19 {
            raw.to_string()
        } else if raw.len() > 19 {
            match urlencoding::decode(raw) {
                Ok(decoded) if decoded.len() == 19 => decoded.into_owned(),
                Ok(decoded) => {
                    tracing::warn!(raw = %raw, decoded_len = decoded.len(), "invalid Base44 length after decode");
                    return HttpResponse::bad_request()
                        .header("Content-Type", "text/plain")
                        .body(format!(
                            "Invalid Base44 length: expected 19, got {}",
                            decoded.len()
                        ))
                        .build();
                }
                Err(e) => {
                    tracing::warn!(raw = %raw, error = %e, "URL decode failed");
                    return HttpResponse::bad_request()
                        .header("Content-Type", "text/plain")
                        .body("Invalid URL encoding".to_string())
                        .build();
                }
            }
        } else {
            tracing::warn!(raw = %raw, len = raw.len(), "invalid Base44 length");
            return HttpResponse::bad_request()
                .header("Content-Type", "text/plain")
                .body(format!(
                    "Invalid Base44 length: expected 19, got {}",
                    raw.len()
                ))
                .build();
        };

        // Decode Base44 to UUID
        let uuid_str = match decode_to_string(&base44) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(base44 = %base44, error = %e, "decode failed");
                return HttpResponse::bad_request()
                    .header("Content-Type", "text/plain")
                    .body(format!("Invalid Base44: {e}"))
                    .build();
            }
        };

        let bytes = match decode_to_bytes(&base44) {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(base44 = %base44, error = %e, "decode_to_bytes failed");
                return HttpResponse::internal_error()
                    .body("Decode error".to_string())
                    .build();
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
                    Ok(json) => HttpResponse::ok()
                        .header("Content-Type", "application/json")
                        .body(json)
                        .build(),
                    Err(e) => {
                        tracing::error!(error = %e, "JSON serialization failed");
                        HttpResponse::internal_error()
                            .body("Serialization error".to_string())
                            .build()
                    }
                }
            }
            OutputMode::Redirect301(url_template) => {
                let target = render_template(url_template, &base44, &uuid_str, &bytes_hex);
                tracing::info!(target = %target, "redirecting 301");
                HttpResponse::redirect(301, &target).build()
            }
            OutputMode::Redirect302(url_template) => {
                let target = render_template(url_template, &base44, &uuid_str, &bytes_hex);
                tracing::info!(target = %target, "redirecting 302");
                HttpResponse::redirect(302, &target).build()
            }
            OutputMode::HtmlTemplate(_) => {
                if let Some(ref tpl) = state.html_template {
                    let html = render_template(tpl, &base44, &uuid_str, &bytes_hex);
                    HttpResponse::ok()
                        .header("Content-Type", "text/html; charset=utf-8")
                        .body(html)
                        .build()
                } else {
                    tracing::error!("HTML template not loaded");
                    HttpResponse::internal_error()
                        .body("Template not loaded".to_string())
                        .build()
                }
            }
        }
    }

    /// Handle a connection (generic over stream type for HTTP/HTTPS)
    async fn handle_connection<S>(stream: S, state: Arc<AppState>)
    where
        S: AsyncBufRead + AsyncWrite + Unpin,
    {
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader);
        let mut request_line = String::new();

        // Read the request line
        if reader.read_line(&mut request_line).await.is_err() {
            return;
        }

        // Parse path from request
        let response = if let Some(path) = parse_request_path(request_line.trim()) {
            handle_request(&path, &state).await
        } else {
            HttpResponse::bad_request()
                .body("Bad Request".to_string())
                .build()
        };

        // Drain remaining headers (we don't need them)
        let mut line = String::new();
        while reader.read_line(&mut line).await.is_ok() {
            if line.trim().is_empty() {
                break;
            }
            line.clear();
        }

        // Send response
        let _ = writer.write_all(&response).await;
    }

    pub struct TlsConfig {
        pub cert_path: String,
        pub key_path: String,
    }

    fn load_tls_config(cfg: &TlsConfig) -> Result<Arc<tokio_rustls::rustls::ServerConfig>, String> {
        use std::fs::File;
        use std::io::BufReader as StdBufReader;
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};

        // Load certificates
        let cert_file = File::open(&cfg.cert_path)
            .map_err(|e| format!("Failed to open cert file '{}': {}", cfg.cert_path, e))?;
        let mut cert_reader = StdBufReader::new(cert_file);
        let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("Failed to parse certificates: {e}"))?;

        if certs.is_empty() {
            return Err("No certificates found in cert file".to_string());
        }

        // Load private key
        let key_file = File::open(&cfg.key_path)
            .map_err(|e| format!("Failed to open key file '{}': {}", cfg.key_path, e))?;
        let mut key_reader = StdBufReader::new(key_file);
        let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|e| format!("Failed to parse private key: {e}"))?
            .ok_or("No private key found in key file")?;

        // Build server config
        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| format!("Failed to build TLS config: {e}"))?;

        Ok(Arc::new(config))
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

        let addr = format!("{bind}:{port}");
        let listener = TcpListener::bind(&addr).await.unwrap_or_else(|e| {
            eprintln!("Failed to bind to {addr}: {e}");
            std::process::exit(2);
        });

        if let Some(tls_cfg) = tls {
            // HTTPS mode
            let tls_config = load_tls_config(&tls_cfg).unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(2);
            });
            let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

            tracing::info!(addr = %addr, mode = ?mode, "starting HTTPS server");

            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let acceptor = acceptor.clone();
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => {
                                    handle_connection(BufReader::new(tls_stream), state).await;
                                }
                                Err(e) => {
                                    tracing::warn!(error = %e, "TLS handshake failed");
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "accept failed");
                    }
                }
            }
        } else {
            // HTTP mode
            tracing::info!(addr = %addr, mode = ?mode, "starting HTTP server");

            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let state = Arc::clone(&state);
                        tokio::spawn(async move {
                            handle_connection(BufReader::new(stream), state).await;
                        });
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "accept failed");
                    }
                }
            }
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
    // HTTP handler integration tests (using handle_request directly)
    // ------------------------------------------------------------------------

    fn create_test_state(mode: OutputMode, html_template: Option<String>) -> AppState {
        AppState {
            mode,
            html_template,
        }
    }

    /// Known test Base44 values (pre-generated, stable)
    const TEST_BASE44_VALUES: &[&str] = &[
        "DPN.M2YT.%YDYX+OYZV", // 611f75c3-4fc2-41c2-aee6-5d5ad69ddf41
        "G96+RDOEF+:I3F6J4RZ", // 717f31e8-e58e-41c2-aea8-a036a576ca39
        "O5297/8PQ+J609-Z$K:", // 6c30c039-89a0-41c2-ae5f-2b641ee3a917
        "B2A/MHJ-YA-%H%BUQ3J", // 76a9f155-710f-41c2-ae69-ae4412f26956
        "G0VWCXC*/51RPWDRTXS", // 0d312c41-ceab-41c2-aea4-214ed1f05e59
    ];

    fn get_test_base44(index: usize) -> &'static str {
        TEST_BASE44_VALUES[index % TEST_BASE44_VALUES.len()]
    }

    /// Parse HTTP response to extract status code
    fn parse_status(response: &[u8]) -> u16 {
        let response_str = String::from_utf8_lossy(response);
        // HTTP/1.1 200 OK
        if let Some(line) = response_str.lines().next() {
            if let Some(status) = line.split_whitespace().nth(1) {
                return status.parse().unwrap_or(0);
            }
        }
        0
    }

    /// Parse HTTP response to extract body
    fn parse_body(response: &[u8]) -> String {
        let response_str = String::from_utf8_lossy(response);
        // Body comes after \r\n\r\n
        if let Some(pos) = response_str.find("\r\n\r\n") {
            return response_str[pos + 4..].to_string();
        }
        String::new()
    }

    /// Parse HTTP response to extract header value
    fn parse_header(response: &[u8], header_name: &str) -> Option<String> {
        let response_str = String::from_utf8_lossy(response);
        let header_lower = header_name.to_lowercase();
        for line in response_str.lines() {
            if line.is_empty() || line == "\r" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.trim().to_lowercase() == header_lower {
                    return Some(value.trim().to_string());
                }
            }
        }
        None
    }

    #[tokio::test]
    async fn health_endpoint() {
        let state = create_test_state(OutputMode::Json, None);
        let response = handle_request("/health", &state).await;
        assert_eq!(parse_status(&response), 200);
        assert_eq!(parse_body(&response), "OK");
    }

    #[tokio::test]
    async fn decode_valid_base44_json_mode() {
        let state = create_test_state(OutputMode::Json, None);
        let base44 = get_test_base44(0);
        let encoded = urlencoding::encode(base44);
        let path = format!("/{}", encoded);

        let response = handle_request(&path, &state).await;
        assert_eq!(parse_status(&response), 200);

        let body = parse_body(&response);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["base44"], base44);
        assert!(json["uuid"].as_str().unwrap().contains("-"));
        assert_eq!(json["bytes"].as_str().unwrap().len(), 32);
    }

    #[tokio::test]
    async fn url_encoding_decoded_by_handler() {
        let state = create_test_state(OutputMode::Json, None);
        let base44_with_slash = "O5297/8PQ+J609-Z$K:";
        let encoded = urlencoding::encode(base44_with_slash);
        let path = format!("/{}", encoded);

        let response = handle_request(&path, &state).await;
        assert_eq!(parse_status(&response), 200);

        let body = parse_body(&response);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["base44"], base44_with_slash);
    }

    #[tokio::test]
    async fn url_encoding_special_chars_decoded() {
        let state = create_test_state(OutputMode::Json, None);
        let base44_special = "G96+RDOEF+:I3F6J4RZ";
        let encoded = urlencoding::encode(base44_special);
        let path = format!("/{}", encoded);

        let response = handle_request(&path, &state).await;
        assert_eq!(parse_status(&response), 200);

        let body = parse_body(&response);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["base44"], base44_special);
    }

    #[tokio::test]
    async fn url_encoding_percent_char_decoded() {
        let state = create_test_state(OutputMode::Json, None);
        let base44_with_percent = "DPN.M2YT.%YDYX+OYZV";
        let encoded = urlencoding::encode(base44_with_percent);
        assert!(encoded.contains("%25"));

        let path = format!("/{}", encoded);
        let response = handle_request(&path, &state).await;
        assert_eq!(parse_status(&response), 200);

        let body = parse_body(&response);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["base44"], base44_with_percent);
    }

    #[tokio::test]
    async fn raw_base44_with_percent_preserved() {
        let state = create_test_state(OutputMode::Json, None);
        // Raw 19-char path with invalid %XX (not URL-encoded)
        let raw_base44 = "DPN.M2YT.%YDYX+OYZV";
        let path = format!("/{}", raw_base44);

        let response = handle_request(&path, &state).await;
        assert_eq!(parse_status(&response), 200);

        let body = parse_body(&response);
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(json["base44"], raw_base44);
    }

    // ------------------------------------------------------------------------
    // Raw transmission edge case tests (direct path handling)
    // ------------------------------------------------------------------------

    /// Helper: normalize input like the handler does
    fn normalize_input(raw: &str) -> String {
        if raw.len() == 19 {
            raw.to_string()
        } else if raw.len() > 19 {
            urlencoding::decode(raw)
                .map(|d| d.into_owned())
                .unwrap_or_else(|_| format!("DECODE_ERROR:{}", raw))
        } else {
            format!("TOO_SHORT:{}", raw)
        }
    }

    #[test]
    fn raw_transmission_dot_at_start() {
        let input = ".AAAAAAAAAAAAAAAAAA"; // 19 chars
        assert_eq!(normalize_input(input), input);
    }

    #[test]
    fn raw_transmission_double_dot() {
        let input = "AAAA..AAAAAAAAAAAAA"; // 19 chars
        assert_eq!(normalize_input(input), input);
    }

    #[test]
    fn raw_transmission_colon_at_start() {
        let input = ":AAAAAAAAAAAAAAAAAA"; // 19 chars
        assert_eq!(normalize_input(input), input);
    }

    #[test]
    fn raw_transmission_safe_special_chars() {
        let input = "$%Y*+-.::$%Z*+-.::A"; // 19 chars, no /
        assert_eq!(normalize_input(input), input);
    }

    #[test]
    fn encoded_transmission_slash_at_start() {
        let input = "/AAAAAAAAAAAAAAAAAA"; // 19 chars
        let encoded = urlencoding::encode(input);
        assert_eq!(normalize_input(&encoded), input);
    }

    #[test]
    fn encoded_transmission_double_slash() {
        let input = "AAAA//AAAAAAAAAAAAA"; // 19 chars
        let encoded = urlencoding::encode(input);
        assert_eq!(normalize_input(&encoded), input);
    }

    #[test]
    fn encoded_transmission_percent_with_valid_hex() {
        let input = "AAA%41AAAAAAAAAAAAA"; // 19 chars
        let encoded = urlencoding::encode(input);
        assert_eq!(normalize_input(&encoded), input);
    }

    #[test]
    fn encoded_transmission_all_special_chars() {
        let input = "$%*+-./:$%*+-./:$%*"; // 19 chars
        let encoded = urlencoding::encode(input);
        assert_eq!(normalize_input(&encoded), input);
    }

    #[test]
    fn encoded_transmission_consecutive_slashes() {
        let input = "///AAAAAAAAAAAAAAAA"; // 19 chars
        let encoded = urlencoding::encode(input);
        assert_eq!(normalize_input(&encoded), input);
    }

    #[test]
    fn encoded_transmission_mixed_edge_cases() {
        let input = "/%41//..::$%*+-.ABC"; // 19 chars
        let encoded = urlencoding::encode(input);
        assert_eq!(normalize_input(&encoded), input);
    }

    #[tokio::test]
    async fn decode_invalid_base44_wrong_length_short() {
        let state = create_test_state(OutputMode::Json, None);
        let response = handle_request("/ABC123", &state).await;
        assert_eq!(parse_status(&response), 400);
        assert!(parse_body(&response).contains("length"));
    }

    #[tokio::test]
    async fn decode_invalid_base44_wrong_length_long() {
        let state = create_test_state(OutputMode::Json, None);
        let response = handle_request("/ABCDEFGHIJKLMNOPQRSTUVWXYZ", &state).await;
        assert_eq!(parse_status(&response), 400);
        assert!(parse_body(&response).contains("length"));
    }

    #[tokio::test]
    async fn decode_invalid_base44_bad_chars() {
        let state = create_test_state(OutputMode::Json, None);
        let response = handle_request("/INVALID!!!!!!!!!!!", &state).await;
        assert_eq!(parse_status(&response), 400);
    }

    #[tokio::test]
    async fn decode_with_301_redirect() {
        let state = create_test_state(
            OutputMode::Redirect301("https://example.com/item/{{uuid}}".to_string()),
            None,
        );
        let base44 = get_test_base44(1);
        let encoded = urlencoding::encode(base44);
        let path = format!("/{}", encoded);

        let response = handle_request(&path, &state).await;
        assert_eq!(parse_status(&response), 301);

        let location = parse_header(&response, "Location").unwrap();
        assert!(location.starts_with("https://example.com/item/"));
        assert!(location.contains("-")); // UUID format
    }

    #[tokio::test]
    async fn decode_with_302_redirect() {
        let state = create_test_state(
            OutputMode::Redirect302("https://example.com/go/{{base44}}".to_string()),
            None,
        );
        let base44 = get_test_base44(2);
        let encoded = urlencoding::encode(base44);
        let path = format!("/{}", encoded);

        let response = handle_request(&path, &state).await;
        assert_eq!(parse_status(&response), 302);

        let location = parse_header(&response, "Location").unwrap();
        assert!(location.contains(base44));
    }

    #[tokio::test]
    async fn decode_with_html_template() {
        let template = "<html><body>UUID: {{uuid}}, Code: {{base44}}</body></html>";
        let state = create_test_state(
            OutputMode::HtmlTemplate("/dummy/path".to_string()),
            Some(template.to_string()),
        );
        let base44 = get_test_base44(3);
        let encoded = urlencoding::encode(base44);
        let path = format!("/{}", encoded);

        let response = handle_request(&path, &state).await;
        assert_eq!(parse_status(&response), 200);

        let html = parse_body(&response);
        assert!(html.contains(base44));
        assert!(html.contains("-")); // UUID contains dashes
    }

    #[tokio::test]
    async fn decode_html_template_not_loaded() {
        let state = create_test_state(OutputMode::HtmlTemplate("/dummy/path".to_string()), None);
        let base44 = get_test_base44(4);
        let encoded = urlencoding::encode(base44);
        let path = format!("/{}", encoded);

        let response = handle_request(&path, &state).await;
        assert_eq!(parse_status(&response), 500);
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
