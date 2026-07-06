//! Unpadded base64url (RFC 4648 §5), the encoding used throughout JOSE and AAuth.
//!
//! Decoding is strict: padding characters, whitespace, and characters outside
//! the base64url alphabet are rejected, as are non-canonical trailing bits.

const ENC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Encode bytes as unpadded base64url.
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ENC[(n >> 18) as usize & 63] as char);
        out.push(ENC[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ENC[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ENC[n as usize & 63] as char);
        }
    }
    out
}

fn dec(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a' + 26) as u32),
        b'0'..=b'9' => Some((c - b'0' + 52) as u32),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Decode unpadded base64url. Strict: rejects padding, whitespace, invalid
/// characters, impossible lengths, and non-zero trailing bits.
pub fn decode(s: &str) -> Result<Vec<u8>, &'static str> {
    let bytes = s.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err("invalid base64url length");
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            let v = dec(c).ok_or("invalid base64url character")?;
            n |= v << (18 - 6 * i);
        }
        match chunk.len() {
            4 => {
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
                out.push(n as u8);
            }
            3 => {
                // 18 bits present, 16 bits of output: low 2 payload bits must be 0
                if n & 0xC0 != 0 {
                    return Err("non-canonical base64url");
                }
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
            }
            2 => {
                // 12 bits present, 8 bits of output: low 4 payload bits must be 0
                if n & 0xF000 != 0 {
                    return Err("non-canonical base64url");
                }
                out.push((n >> 16) as u8);
            }
            _ => return Err("invalid base64url length"),
        }
    }
    Ok(out)
}

/// Decode exactly `N` bytes.
pub fn decode_fixed<const N: usize>(s: &str) -> Result<[u8; N], &'static str> {
    let v = decode(s)?;
    v.try_into().map_err(|_| "unexpected length")
}

const ENC_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Encode standard base64 **with** padding — RFC 8941 Byte Sequences
/// (e.g. the `Signature` header value) use this alphabet.
pub fn encode_std(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ENC_STD[(n >> 18) as usize & 63] as char);
        out.push(ENC_STD[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ENC_STD[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ENC_STD[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn dec_std(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some((c - b'A') as u32),
        b'a'..=b'z' => Some((c - b'a' + 26) as u32),
        b'0'..=b'9' => Some((c - b'0' + 52) as u32),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode standard base64; padding optional (RFC 8941 parsers tolerate
/// unpadded input), whitespace rejected.
pub fn decode_std(s: &str) -> Result<Vec<u8>, &'static str> {
    let trimmed = s.trim_end_matches('=');
    if s.len() - trimmed.len() > 2 {
        return Err("invalid base64 padding");
    }
    let bytes = trimmed.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err("invalid base64 length");
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            let v = dec_std(c).ok_or("invalid base64 character")?;
            n |= v << (18 - 6 * i);
        }
        match chunk.len() {
            4 => {
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
                out.push(n as u8);
            }
            3 => {
                out.push((n >> 16) as u8);
                out.push((n >> 8) as u8);
            }
            2 => out.push((n >> 16) as u8),
            _ => return Err("invalid base64 length"),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        for len in 0..64 {
            let data: Vec<u8> = (0..len as u8).collect();
            assert_eq!(decode(&encode(&data)).unwrap(), data);
        }
    }

    #[test]
    fn known_vectors() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "Zg");
        assert_eq!(encode(b"fo"), "Zm8");
        assert_eq!(encode(b"foo"), "Zm9v");
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
    }

    #[test]
    fn strictness() {
        assert!(decode("Zg==").is_err(), "padding rejected");
        assert!(decode("Zm 9v").is_err(), "whitespace rejected");
        assert!(decode("Zm9v\n").is_err(), "newline rejected");
        assert!(decode("Z").is_err(), "length 1 mod 4 rejected");
        assert!(
            decode("Zh").is_err(),
            "non-canonical trailing bits rejected"
        );
        assert!(decode("+/8").is_err(), "standard alphabet rejected");
    }
}
