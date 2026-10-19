//! TOTP exactly as otplib 12's `authenticator` computes it (Rust-only module; `mfa.ts` uses otplib): base32 secrets
//! (thirty-two), HMAC-SHA1, 6 digits, 30-second steps, an optional window of neighbouring steps, and `keyuri`.

use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::crypto::random_bytes;
use crate::util::encode_uri_component;

const CHAR_TABLE: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BYTE_TABLE: [u8; 80] = [
    0xff, 0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
];

/// thirty-two's `encode` without the `=` padding (otplib's key encoder strips it).
pub fn base32_encode(plain: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    let mut shift: u32 = 0;
    while i < plain.len() {
        let current = plain[i];
        let digit;
        if shift > 3 {
            let mut d = u32::from(current) & (0xff >> shift);
            shift = (shift + 5) % 8;
            let next = if i + 1 < plain.len() {
                u32::from(plain[i + 1])
            } else {
                0
            };
            d = (d << shift) | (next >> (8 - shift));
            digit = d;
            i += 1;
        } else {
            digit = (u32::from(current) >> (8 - (shift + 5))) & 0x1f;
            shift = (shift + 5) % 8;
            if shift == 0 {
                i += 1;
            }
        }
        out.push(CHAR_TABLE[digit as usize] as char);
    }
    out
}

/// thirty-two's `decode` of the UTF-8 bytes of `encoded`; None where it throws ("not base32 encoded").
pub fn base32_decode(encoded: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut shift: u32 = 0;
    let mut plain: u32 = 0;
    for byte in encoded.bytes() {
        if byte == b'=' {
            break;
        }
        let index = i32::from(byte) - 0x30;
        if index >= BYTE_TABLE.len() as i32 {
            return None;
        }
        // A negative index reads `undefined`, which the bit operations treat as 0.
        let digit = if index < 0 {
            0
        } else {
            u32::from(BYTE_TABLE[index as usize])
        };
        if shift <= 3 {
            shift = (shift + 5) % 8;
            if shift == 0 {
                plain |= digit;
                out.push((plain & 0xff) as u8);
                plain = 0;
            } else {
                plain |= 0xff & (digit << (8 - shift));
            }
        } else {
            shift = (shift + 5) % 8;
            plain |= 0xff & (digit >> shift);
            out.push((plain & 0xff) as u8);
            plain = 0xff & (digit << (8 - shift));
        }
    }
    Some(out)
}

/// `authenticator.generateSecret(bytes)`: random bytes, read through Node's `ascii` decoding (which clears each
/// byte's high bit) before base32 encoding, exactly as otplib's key encoder does.
pub fn generate_secret(length: usize) -> String {
    secret_from_bytes(&random_bytes(length))
}

/// The encoded secret otplib produces for the given random bytes.
pub fn secret_from_bytes(bytes: &[u8]) -> String {
    let masked: Vec<u8> = bytes.iter().map(|byte| byte & 0x7f).collect();
    base32_encode(&masked)
}

/// `Buffer.from(hex, 'hex')`: pairs of hex digits until the first pair that is not one.
fn hex_decode(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let pair = std::str::from_utf8(&bytes[i..i + 2]).ok();
        match pair.and_then(|pair| u8::from_str_radix(pair, 16).ok()) {
            Some(byte) if bytes[i].is_ascii_hexdigit() && bytes[i + 1].is_ascii_hexdigit() => {
                out.push(byte)
            }
            _ => break,
        }
        i += 2;
    }
    out
}

/// `totpCreateHmacKey('sha1', hexSecret, 'hex')`: secrets shorter than 20 hex characters are repeated.
fn hmac_key(secret: &[u8]) -> Vec<u8> {
    let hex_secret = crate::util::hex(secret);
    let length = hex_secret.len();
    if length < 20 {
        let repeated = hex_secret.repeat(20 - length);
        let mut bytes = hex_decode(&repeated);
        bytes.truncate(20);
        return bytes;
    }
    secret.to_vec()
}

/// `hotpCounter(counter)`: the counter as 16 hex digits (a negative counter keeps its sign, which `Buffer.from`
/// then stops at).
fn counter_bytes(counter: i64) -> Vec<u8> {
    let text = if counter < 0 {
        format!("-{:x}", counter.unsigned_abs())
    } else {
        format!("{counter:x}")
    };
    let padded = if text.len() >= 16 {
        text
    } else {
        format!("{}{}", "0".repeat(16 - text.len()), text)
    };
    hex_decode(&padded)
}

fn hotp(secret: &[u8], counter: i64) -> String {
    let mut mac = Hmac::<Sha1>::new_from_slice(&hmac_key(secret)).expect("any key length");
    mac.update(&counter_bytes(counter));
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0xf);
    let binary = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    format!("{:06}", binary % 1_000_000)
}

fn counter_at(epoch: f64) -> i64 {
    (epoch / 30.0 / 1000.0).floor() as i64
}

/// `authenticator.generate(secret)` at `epoch` (milliseconds); None when the secret is not base32.
pub fn generate(secret: &str, epoch: f64) -> Option<String> {
    Some(hotp(&base32_decode(secret)?, counter_at(epoch)))
}

fn check(token: &str, secret: &[u8], epoch: f64) -> bool {
    !token.is_empty()
        && token.bytes().all(|c| c.is_ascii_digit())
        && hotp(secret, counter_at(epoch)) == token
}

/// `authenticator.checkDelta(token, secret)` with `{ epoch, window }`: 0 for the current step, -n for a past step,
/// +n for a future one, None when no step in the window matches. The current step is tried first, then the past,
/// then the future ones.
pub fn check_delta(token: &str, secret: &str, epoch: f64, window: u32) -> Option<i64> {
    let secret = base32_decode(secret)?;
    if check(token, &secret, epoch) {
        return Some(0);
    }
    for i in 1..=window {
        if check(token, &secret, epoch - f64::from(i) * 30_000.0) {
            return Some(-i64::from(i));
        }
    }
    for i in 1..=window {
        if check(token, &secret, epoch + f64::from(i) * 30_000.0) {
            return Some(i64::from(i));
        }
    }
    None
}

/// `authenticator.keyuri(account, issuer, secret)`.
pub fn keyuri(account: &str, issuer: &str, secret: &str) -> String {
    let label = encode_uri_component(if issuer.is_empty() { account } else { issuer });
    let mut uri = format!(
        "otpauth://totp/{label}:{}?secret={secret}&period=30&digits=6&algorithm=SHA1",
        encode_uri_component(account)
    );
    if !issuer.is_empty() {
        uri.push_str("&issuer=");
        uri.push_str(&encode_uri_component(issuer));
    }
    uri
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_secret_round_trips() {
        let decoded = base32_decode("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(base32_encode(&decoded), "JBSWY3DPEHPK3PXP");
        assert_eq!(
            generate("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", 0.0).unwrap(),
            "702218"
        );
    }
}
