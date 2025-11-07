use qr_url_uuid4::{
    decode_to_bytes, decode_to_string, encode_uuid, encode_uuid_bytes, generate_v4,
};
use std::io::{self, Read};
use uuid::Uuid;

fn print_usage() {
    eprintln!("qr-url-uuid4 CLI\n\nCommands:\n  gen                       Generate a random UUID v4 and print Base44 and UUID\n  encode <UUID|HEX|@->     Encode a UUID into Base44. Accepts:\n                           - canonical UUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)\n                           - 32-hex (no dashes)\n                           - raw 16-byte hex prefixed with 0x? use stdin with @- to read 16 bytes\n  decode <BASE44|@->       Decode Base44 string back to UUID string and bytes (hex)\n\nOptions:\n  -q, --quiet              Only print the primary output\n  -h, --help               Show this help\n\nExamples:\n  qr-url-uuid4 gen\n  qr-url-uuid4 encode 550e8400-e29b-41d4-a716-446655440000\n  qr-url-uuid4 decode XYZ...\n");
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
        _ => {
            print_usage();
        }
    }
}
