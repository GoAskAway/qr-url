//! qr-url: Compact Base44 codec for UUID v4 by stripping 25 fixed bits.
//! - 128-bit UUID v4 -> remove version(4b) + variant(2b) + signature "41c2ae"(18b) + first bit(1b) => 103 bits, pack to 13 bytes => Base44
//! - First bit (bit 0 of byte 0) is always 0, removed during encoding
//! - Reverse to reconstruct a canonical UUID v4 with signature "0xxxxxxx-xxxx-41c2-aexx-xxxxxxxxxxxx"
//! - Optimized for QR code alphanumeric mode and URL embedding (Base44 = Base45 without space character)
//!   Provides: library API, WASM bindings (target wasm32), and CLI tool.

use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum Uuid45Error {
    #[error("Invalid UUID: {0}")]
    InvalidUuid(String),
    #[error("Invalid Base44: {0}")]
    InvalidBase44(String),
    #[error("Invalid length: expected {expected} got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("UUID does not have required signature '41c2ae' at positions 13-18")]
    InvalidSignature,
}

/// Encode 13 bytes (103 bits) as Base44 string (19 characters) using qr-base44's optimal encoding.
fn encode_base44_optimal(bytes: &[u8; 13]) -> String {
    qr_base44::encode_bits(103, bytes)
}

/// Decode Base44 string (19 characters) back to 13 bytes (103 bits) using qr-base44.
fn decode_base44_optimal(s: &str) -> Result<[u8; 13], Uuid45Error> {
    // Enforce 19-character length for our 103-bit encoding
    if s.len() != 19 {
        return Err(Uuid45Error::InvalidBase44(format!(
            "Expected 19 characters, got {}",
            s.len()
        )));
    }

    let vec =
        qr_base44::decode_bits(103, s).map_err(|e| Uuid45Error::InvalidBase44(e.to_string()))?;

    if vec.len() != 13 {
        return Err(Uuid45Error::InvalidLength {
            expected: 13,
            actual: vec.len(),
        });
    }

    let mut bytes = [0u8; 13];
    bytes.copy_from_slice(&vec);
    Ok(bytes)
}

/// Fixed bits in our UUID v4 variant with signature "41c2ae":
/// - Byte 6: 0x41 (version 4 in high nibble + signature '1' in low nibble)
/// - Byte 7: 0xc2 (signature)
/// - Byte 8: 0xae (variant '10' in high 2 bits + signature '2e' in low 6 bits)
const SIGNATURE_BYTE6: u8 = 0x41;
const SIGNATURE_BYTE7: u8 = 0xc2;
const SIGNATURE_BYTE8: u8 = 0xae;

/// Extract 103-bit compact representation from a canonical UUID v4 byte array.
/// Removes 25 fixed bits: first bit(1) + version(4) + variant(2) + signature "41c2ae"(18).
/// Returns 13 bytes containing 103 bits (last byte uses 7 bits, MSB is 0).
/// Returns error if UUID does not have the required signature or first bit is not 0.
pub fn uuid_to_compact_bytes(uuid_bytes: &[u8; 16]) -> Result<[u8; 13], Uuid45Error> {
    // Verify UUID has the required signature
    if uuid_bytes[6] != SIGNATURE_BYTE6
        || uuid_bytes[7] != SIGNATURE_BYTE7
        || uuid_bytes[8] != SIGNATURE_BYTE8
    {
        return Err(Uuid45Error::InvalidSignature);
    }

    // Verify first bit (MSB of byte 0) is 0
    if uuid_bytes[0] & 0b1000_0000 != 0 {
        return Err(Uuid45Error::InvalidSignature);
    }

    // Gather all 128 bits, skip the 25 fixed ones:
    // - byte 0 bit 7: skip (first bit, always 0)
    // - byte 6: skip all 8 bits (version + signature)
    // - byte 7: skip all 8 bits (signature)
    // - byte 8: skip all 8 bits (variant + signature)
    let mut out_bits = Vec::with_capacity(103);
    for (byte_idx, b) in uuid_bytes.iter().copied().enumerate().take(16) {
        // Skip bytes 6, 7, 8 entirely (they are all fixed)
        if byte_idx == 6 || byte_idx == 7 || byte_idx == 8 {
            continue;
        }
        // For byte 0, skip the first bit (bit 7)
        let bit_range = if byte_idx == 0 {
            (0..7).rev()
        } else {
            (0..8).rev()
        };
        for bit in bit_range {
            let mask = 1u8 << bit;
            out_bits.push((b & mask) != 0);
        }
    }
    assert_eq!(out_bits.len(), 103);

    // Pack into 13 bytes (ceil(103/8) = 13, last byte uses 7 bits).
    // We pack LSB-first for consistency.
    let mut out = [0u8; 13];
    let mut bit_idx = 0;
    for item in &mut out {
        let mut acc = 0u8;
        for bit in 0..8 {
            if bit_idx < 103 {
                acc |= (out_bits[bit_idx] as u8) << bit;
                bit_idx += 1;
            }
        }
        *item = acc;
    }

    Ok(out)
}

/// Reconstruct full 128-bit UUID bytes from a compact 103-bit packed representation.
/// Accepts 13 bytes containing 103 bits. Restores first bit (0), signature bytes 6, 7, 8.
pub fn compact_bytes_to_uuid(compact: &[u8]) -> Result<[u8; 16], Uuid45Error> {
    if compact.len() != 13 {
        return Err(Uuid45Error::InvalidLength {
            expected: 13,
            actual: compact.len(),
        });
    }

    // Unpack 103 bits LSB-first from each byte
    let mut bits: Vec<bool> = Vec::with_capacity(103);
    for &b in compact.iter() {
        for bit in 0..8 {
            if bits.len() < 103 {
                bits.push(((b >> bit) & 1) != 0);
            }
        }
    }

    // Reinsert into 16-byte array, injecting fixed bit 0 and bytes 6, 7, 8
    let mut out = [0u8; 16];
    let mut bit_iter = bits.into_iter();

    for (byte_idx, item) in out.iter_mut().enumerate() {
        if byte_idx == 6 {
            // Fixed byte: version 4 + signature
            *item = SIGNATURE_BYTE6;
        } else if byte_idx == 7 {
            // Fixed byte: signature
            *item = SIGNATURE_BYTE7;
        } else if byte_idx == 8 {
            // Fixed byte: variant + signature
            *item = SIGNATURE_BYTE8;
        } else if byte_idx == 0 {
            // Byte 0: first bit is 0 (fixed), then 7 bits from stream
            let mut acc = 0u8;
            for bit in (0..7).rev() {
                let v = bit_iter.next().unwrap_or(false) as u8;
                acc |= v << bit;
            }
            // MSB (bit 7) is always 0
            *item = acc & 0b0111_1111;
        } else {
            // Reconstruct from bit stream (MSB first, all 8 bits)
            let mut acc = 0u8;
            for bit in (0..8).rev() {
                let v = bit_iter.next().unwrap_or(false) as u8;
                acc |= v << bit;
            }
            *item = acc;
        }
    }

    Ok(out)
}

/// Encode a UUID into Base44 compact string (19 characters).
/// Returns error if UUID does not have the required signature '41c2ae'.
pub fn encode_uuid(uuid: Uuid) -> Result<String, Uuid45Error> {
    let bytes = uuid.into_bytes();
    let compact = uuid_to_compact_bytes(&bytes)?;
    Ok(encode_base44_optimal(&compact))
}

/// Try to encode a UUID string into Base44 compact string.
pub fn encode_uuid_str(s: &str) -> Result<String, Uuid45Error> {
    let uuid = Uuid::parse_str(s).map_err(|e| Uuid45Error::InvalidUuid(e.to_string()))?;
    encode_uuid(uuid)
}

/// Encode raw 16-byte UUID into Base44 compact string (19 characters).
/// Returns error if UUID does not have the required signature '41c2ae'.
pub fn encode_uuid_bytes(bytes: &[u8; 16]) -> Result<String, Uuid45Error> {
    let compact = uuid_to_compact_bytes(bytes)?;
    Ok(encode_base44_optimal(&compact))
}

/// Decode Base44 compact string (19 characters) into a UUID.
pub fn decode_to_uuid(s: &str) -> Result<Uuid, Uuid45Error> {
    let compact = decode_base44_optimal(s)?;
    let arr = compact_bytes_to_uuid(&compact)?;
    Ok(Uuid::from_bytes(arr))
}

/// Decode Base44 compact string back to canonical 16-byte UUID bytes.
pub fn decode_to_bytes(s: &str) -> Result<[u8; 16], Uuid45Error> {
    let u = decode_to_uuid(s)?;
    Ok(u.into_bytes())
}

/// Decode to hyphenated UUID string.
pub fn decode_to_string(s: &str) -> Result<String, Uuid45Error> {
    Ok(decode_to_uuid(s)?.hyphenated().to_string())
}

/// Generate a random UUID v4 with fixed bits at positions 13-18 (hex): 41c2ae and first bit 0
/// This maintains UUID v4 compatibility while adding a recognizable signature.
/// Format: 0xxxxxxx-xxxx-41c2-aexx-xxxxxxxxxxxx (first hex char is 0-7)
pub fn generate_v4() -> Uuid {
    let uuid = Uuid::new_v4();
    let mut bytes = uuid.into_bytes();

    // Fix positions 13-18 in hex representation to "41c2ae"
    // Position 13-14: byte 6 = 0x41 (version 4 + nibble 1)
    // Position 15-16: byte 7 = 0xc2
    // Position 17-18: byte 8 = 0xae (10101110 in binary, high 2 bits '10' satisfy RFC4122 variant)
    bytes[6] = 0x41;
    bytes[7] = 0xc2;
    bytes[8] = 0xae;

    // Fix first bit (MSB of byte 0) to 0
    bytes[0] &= 0b0111_1111;

    Uuid::from_bytes(bytes)
}

// ===== WASM bindings =====
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn wasm_gen_v4() -> String {
    generate_v4().hyphenated().to_string()
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn wasm_encode_uuid_str(s: &str) -> Result<String, JsValue> {
    encode_uuid_str(s).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn wasm_decode_to_uuid_str(s: &str) -> Result<String, JsValue> {
    decode_to_string(s).map_err(|e| JsValue::from_str(&e.to_string()))
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub fn wasm_decode_to_bytes(s: &str) -> Result<js_sys::Uint8Array, JsValue> {
    let arr = decode_to_bytes(s).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(js_sys::Uint8Array::from(&arr[..]))
}

// ===== Tests =====
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_random_v4() {
        for _ in 0..200 {
            let u = generate_v4();
            let s = encode_uuid(u).unwrap();
            let d = decode_to_uuid(&s).unwrap();
            assert_eq!(u, d);
        }
    }

    #[test]
    fn signature_required() {
        // UUID without our signature should fail to encode
        let u = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let err = encode_uuid(u).unwrap_err();
        assert!(matches!(err, Uuid45Error::InvalidSignature));
    }

    #[test]
    fn first_bit_must_be_zero() {
        // UUID with first bit = 1 should fail to encode (even with correct signature)
        let u = Uuid::parse_str("ffffffff-ffff-41c2-aeff-ffffffffffff").unwrap();
        let err = encode_uuid(u).unwrap_err();
        assert!(matches!(err, Uuid45Error::InvalidSignature));

        // UUID with first bit = 0 should succeed
        let u_ok = Uuid::parse_str("7fffffff-ffff-41c2-aeff-ffffffffffff").unwrap();
        assert!(encode_uuid(u_ok).is_ok());
    }

    #[test]
    fn compact_size() {
        let u = generate_v4();
        let s = encode_uuid(u).unwrap();
        // Optimal encoding: 103 bits -> 19 characters
        assert_eq!(s.len(), 19);
    }

    #[test]
    fn invalid_base44_char() {
        // Test invalid characters
        assert!(decode_to_uuid("A😀BCDEFGHIJ1234567").is_err());
        assert!(decode_to_uuid("abcdefghij123456789").is_err()); // lowercase not allowed
        assert!(decode_to_uuid("ABC!EFGHIJ123456789").is_err()); // '!' not in alphabet
    }

    #[test]
    fn invalid_base44_length() {
        // Test invalid lengths (not 19 characters)
        assert!(decode_to_uuid("TOOSHORT").is_err());
        assert!(decode_to_uuid("WAYTOOLONGFORBASE44ENCODED").is_err());
        assert!(decode_to_uuid("0123456789ABCDEFGH").is_err()); // 18 chars
        assert!(decode_to_uuid("0123456789ABCDEFGHIJ").is_err()); // 20 chars
    }

    #[test]
    fn invalid_length_rejected() {
        // Try with wrong length (12 bytes instead of 13)
        let twelve = [0u8; 12];
        let err = compact_bytes_to_uuid(&twelve).unwrap_err();
        match err {
            Uuid45Error::InvalidLength {
                expected: 13,
                actual: 12,
            } => {}
            _ => panic!("expected InvalidLength, got {err:?}"),
        }
    }

    #[test]
    fn version_and_variant_preserved() {
        for _ in 0..100 {
            let u = generate_v4();
            let s = encode_uuid(u).unwrap();
            let d = decode_to_uuid(&s).unwrap();
            assert_eq!(d.get_version_num(), 4);
            assert!(matches!(d.get_variant(), uuid::Variant::RFC4122));
            // Verify signature is preserved
            let bytes = d.into_bytes();
            assert_eq!(bytes[6], 0x41);
            assert_eq!(bytes[7], 0xc2);
            assert_eq!(bytes[8], 0xae);
        }
    }

    #[test]
    fn reencode_stability() {
        for _ in 0..50 {
            let u = generate_v4();
            let s1 = encode_uuid(u).unwrap();
            let u2 = decode_to_uuid(&s1).unwrap();
            let s2 = encode_uuid(u2).unwrap();
            assert_eq!(s1, s2);
        }
    }

    #[test]
    fn extreme_known_values() {
        // Minimal with signature and first bit 0
        let u_min = Uuid::parse_str("00000000-0000-41c2-ae00-000000000000").unwrap();
        let s = encode_uuid(u_min).unwrap();
        let d = decode_to_uuid(&s).unwrap();
        assert_eq!(u_min, d);

        // Maximal with signature and first bit 0 (first byte max is 0x7F)
        let u_max = Uuid::parse_str("7fffffff-ffff-41c2-aeff-ffffffffffff").unwrap();
        let s2 = encode_uuid(u_max).unwrap();
        let d2 = decode_to_uuid(&s2).unwrap();
        assert_eq!(u_max, d2);
    }

    #[test]
    fn encode_uuid_str_invalid() {
        let err = encode_uuid_str("not-a-uuid").unwrap_err();
        // Ensure it's the InvalidUuid variant message path
        assert!(matches!(err, Uuid45Error::InvalidUuid(_)));
    }

    #[test]
    fn base44_optimal_encoding_length() {
        // Verify all generated UUIDs encode to exactly 19 characters
        for _ in 0..20 {
            let u = generate_v4();
            let encoded = encode_uuid(u).unwrap();
            assert_eq!(
                encoded.len(),
                19,
                "Expected 19 chars, got {}",
                encoded.len()
            );
            // Verify decode works
            let decoded = decode_to_uuid(&encoded).unwrap();
            assert_eq!(u, decoded);
        }
    }
}
