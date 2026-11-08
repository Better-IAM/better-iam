//! Port of `packages/ldap/src/ber.ts`: the subset of ASN.1 BER (X.690) that LDAPv3 (RFC 4511) uses: definite
//! lengths, INTEGER/ENUMERATED, BOOLEAN, OCTET STRING, NULL, SEQUENCE/SET and context/application tags. Decoding is
//! strict (no indefinite lengths, lengths at most four bytes) and bounds-checked; anything malformed is a
//! [`BerError`].

use std::fmt;

/// `BerError`: malformed BER.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BerError(pub String);

impl BerError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// The error message.
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BerError {}

/// `Tag`: the universal tags LDAP uses.
pub mod tag {
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const ENUMERATED: u8 = 0x0a;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;
}

/// A decoded element: its tag byte and raw content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BerElement<'a> {
    pub tag: u8,
    /// The content octets.
    pub value: &'a [u8],
    /// Total encoded size (tag + length + content).
    pub size: usize,
}

fn length_bytes(length: usize) -> Vec<u8> {
    if length < 0x80 {
        return vec![length as u8];
    }
    let mut bytes = Vec::new();
    let mut rest = length;
    while rest > 0 {
        bytes.insert(0, (rest & 0xff) as u8);
        rest >>= 8;
    }
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    out
}

/// One TLV.
pub fn element(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(length_bytes(value.len()));
    out.extend_from_slice(value);
    out
}

/// The content octets of an INTEGER (two's complement, minimal).
pub fn integer_bytes(value: i64) -> Result<Vec<u8>, BerError> {
    const MAX_SAFE: i64 = 9_007_199_254_740_991;
    if !(-MAX_SAFE..=MAX_SAFE).contains(&value) {
        return Err(BerError::new("Integer out of range"));
    }
    let mut bytes = Vec::new();
    let mut rest = value;
    loop {
        bytes.insert(0, (rest & 0xff) as u8);
        rest >>= 8;
        if rest == 0 || rest == -1 {
            break;
        }
    }
    // Keep the sign bit right: a positive value whose top bit is set needs a leading 0x00, a negative one 0xff.
    if value >= 0 && bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    if value < 0 && bytes[0] & 0x80 == 0 {
        bytes.insert(0, 0xff);
    }
    Ok(bytes)
}

/// An INTEGER (or another tag carrying an integer). Values beyond the safe range are clamped to it, which the
/// message IDs, result codes and sizes LDAP encodes never reach.
pub fn integer(value: i64, tag: u8) -> Vec<u8> {
    let bytes = integer_bytes(value).unwrap_or_else(|_| {
        integer_bytes(value.clamp(-(1 << 53) + 1, (1 << 53) - 1)).unwrap_or_default()
    });
    element(tag, &bytes)
}

/// An ENUMERATED.
pub fn enumerated(value: i64) -> Vec<u8> {
    integer(value, tag::ENUMERATED)
}

/// An OCTET STRING (or another primitive tag) of bytes.
pub fn octets(value: &[u8], tag: u8) -> Vec<u8> {
    element(tag, value)
}

/// An OCTET STRING of UTF-8 text.
pub fn text(value: &str, tag: u8) -> Vec<u8> {
    element(tag, value.as_bytes())
}

/// A BOOLEAN.
pub fn boolean(value: bool, tag: u8) -> Vec<u8> {
    element(tag, &[if value { 0xff } else { 0 }])
}

/// A SEQUENCE (or another constructed tag) of encoded items.
pub fn sequence(items: &[Vec<u8>], tag: u8) -> Vec<u8> {
    element(tag, &items.concat())
}

/// A SET of encoded items.
pub fn set(items: &[Vec<u8>], tag: u8) -> Vec<u8> {
    element(tag, &items.concat())
}

/// Reads one element at `offset`, or None when `buffer` does not yet hold all of it (stream framing). `max_size`
/// bounds the content length a peer may announce.
pub fn read_element(
    buffer: &[u8],
    offset: usize,
    max_size: usize,
) -> Result<Option<BerElement<'_>>, BerError> {
    if offset >= buffer.len() {
        return Ok(None);
    }
    let tag = buffer[offset];
    if tag & 0x1f == 0x1f {
        return Err(BerError::new("Multi-byte tags are not supported"));
    }
    if offset + 1 >= buffer.len() {
        return Ok(None);
    }
    let mut length = buffer[offset + 1] as usize;
    let mut header = 2;
    if length & 0x80 != 0 {
        let count = length & 0x7f;
        if count == 0 {
            return Err(BerError::new("Indefinite lengths are not allowed"));
        }
        if count > 4 {
            return Err(BerError::new("Length too long"));
        }
        if offset + 2 + count > buffer.len() {
            return Ok(None);
        }
        length = 0;
        for index in 0..count {
            length = length * 256 + buffer[offset + 2 + index] as usize;
        }
        header += count;
    }
    if length > max_size {
        return Err(BerError::new("Element exceeds the size limit"));
    }
    if offset + header + length > buffer.len() {
        return Ok(None);
    }
    Ok(Some(BerElement {
        tag,
        value: &buffer[offset + header..offset + header + length],
        size: header + length,
    }))
}

/// The default `maxSize` of `readElement` (1 MiB).
pub const DEFAULT_MAX_SIZE: usize = 1 << 20;

/// The elements inside a constructed value.
pub fn children(value: &[u8]) -> Result<Vec<BerElement<'_>>, BerError> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset < value.len() {
        let Some(item) = read_element(value, offset, DEFAULT_MAX_SIZE)? else {
            return Err(BerError::new("Truncated element"));
        };
        offset += item.size;
        result.push(item);
    }
    Ok(result)
}

/// An INTEGER (or ENUMERATED with `tag`) of at most six content bytes.
pub fn read_integer(item: Option<&BerElement<'_>>, tag: u8) -> Result<i64, BerError> {
    let Some(item) =
        item.filter(|item| item.tag == tag && !item.value.is_empty() && item.value.len() <= 6)
    else {
        return Err(BerError::new("Expected an integer"));
    };
    let mut value: i64 = if item.value[0] & 0x80 != 0 { -1 } else { 0 };
    for byte in item.value {
        value = (value << 8) | *byte as i64;
    }
    Ok(value)
}

/// The content of an OCTET STRING (or `tag`).
pub fn read_octets<'a>(item: Option<&BerElement<'a>>, tag: u8) -> Result<&'a [u8], BerError> {
    match item {
        Some(item) if item.tag == tag => Ok(item.value),
        _ => Err(BerError::new("Expected an octet string")),
    }
}

/// An OCTET STRING as UTF-8 text (`toString('utf8')`: invalid sequences become U+FFFD).
pub fn read_string(item: Option<&BerElement<'_>>, tag: u8) -> Result<String, BerError> {
    Ok(String::from_utf8_lossy(read_octets(item, tag)?).into_owned())
}

/// A BOOLEAN (or `tag`).
pub fn read_boolean(item: Option<&BerElement<'_>>, tag: u8) -> Result<bool, BerError> {
    match item {
        Some(item) if item.tag == tag && item.value.len() == 1 => Ok(item.value[0] != 0),
        _ => Err(BerError::new("Expected a boolean")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_round_trip() {
        for value in [
            0,
            1,
            127,
            128,
            255,
            256,
            -1,
            -128,
            -129,
            65535,
            2147483647,
            -2147483648,
        ] {
            let encoded = integer(value, tag::INTEGER);
            let item = read_element(&encoded, 0, DEFAULT_MAX_SIZE)
                .unwrap()
                .unwrap();
            assert_eq!(
                read_integer(Some(&item), tag::INTEGER).unwrap(),
                value,
                "{value}"
            );
        }
        assert_eq!(integer_bytes(128).unwrap(), vec![0, 0x80]);
        assert_eq!(integer_bytes(-129).unwrap(), vec![0xff, 0x7f]);
    }

    #[test]
    fn long_lengths_and_framing() {
        let encoded = text(&"a".repeat(300), tag::OCTET_STRING);
        assert_eq!(&encoded[..4], &[0x04, 0x82, 0x01, 0x2c]);
        assert_eq!(
            read_element(&encoded[..10], 0, DEFAULT_MAX_SIZE).unwrap(),
            None
        );
        assert!(read_element(&encoded, 0, 100).is_err());
        assert!(read_element(&[0x30, 0x80], 0, 100).is_err());
        assert!(read_element(&[0x1f, 0x00], 0, 100).is_err());
    }
}
