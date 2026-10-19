//! CBOR exactly as `@levischuck/tiny-cbor` (which `@simplewebauthn/server` uses) decodes and re-encodes it.
//!
//! The verifier re-encodes the credential public key it decodes from authenticator data and advances by the
//! re-encoded length, and the re-encoded bytes are what gets stored; mirroring the library's codec (minimal lengths
//! only, numbers as JavaScript numbers, text decoded lossily) keeps the stored key and every accept/reject decision
//! identical.

/// A decoded CBOR item. Numbers are JavaScript numbers.
#[derive(Debug, Clone, PartialEq)]
pub enum Cbor {
    Number(f64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    /// Keys are numbers or strings, in encoded order, without duplicates.
    Map(Vec<(Cbor, Cbor)>),
    Tag(u64, Box<Cbor>),
    Bool(bool),
    Null,
    Undefined,
}

impl Cbor {
    /// `map.get(key)` for a number key.
    pub fn get_int(&self, key: i64) -> Option<&Cbor> {
        self.get(&Cbor::Number(key as f64))
    }

    /// `map.get(key)` for a string key.
    pub fn get_str(&self, key: &str) -> Option<&Cbor> {
        self.get(&Cbor::Text(key.to_owned()))
    }

    fn get(&self, key: &Cbor) -> Option<&Cbor> {
        match self {
            Cbor::Map(entries) => entries
                .iter()
                .find(|(candidate, _)| same_value_zero(candidate, key))
                .map(|(_, value)| value),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Cbor::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub fn as_number(&self) -> Option<f64> {
        match self {
            Cbor::Number(number) => Some(*number),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Cbor::Text(text) => Some(text),
            _ => None,
        }
    }

    /// JavaScript truthiness of the decoded value.
    pub fn truthy(&self) -> bool {
        match self {
            Cbor::Number(number) => *number != 0.0 && !number.is_nan(),
            Cbor::Text(text) => !text.is_empty(),
            Cbor::Bool(flag) => *flag,
            Cbor::Null | Cbor::Undefined => false,
            _ => true,
        }
    }
}

/// `Map` key equality (SameValueZero) for the key types the decoder allows.
fn same_value_zero(left: &Cbor, right: &Cbor) -> bool {
    match (left, right) {
        (Cbor::Number(a), Cbor::Number(b)) => a == b || (a.is_nan() && b.is_nan()),
        (Cbor::Text(a), Cbor::Text(b)) => a == b,
        _ => false,
    }
}

/// Why decoding failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct CborError(pub String);

fn error(message: &str) -> CborError {
    CborError(message.to_owned())
}

const MAX_SAFE: u64 = 9_007_199_254_740_991;

/// `decodeLength(data, argument, index)`: only minimal-form lengths of at least 24 are accepted past the initial
/// byte.
fn decode_length(data: &[u8], argument: u8, index: usize) -> Result<(u64, usize), CborError> {
    if argument < 24 {
        return Ok((u64::from(argument), 1));
    }
    let remaining = data.len().saturating_sub(index + 1);
    let at = |offset: usize| data[index + 1 + offset];
    let (value, bytes) = match argument {
        24 if remaining > 0 => (u64::from(at(0)), 2),
        25 if remaining > 1 => (u64::from(u16::from_be_bytes([at(0), at(1)])), 3),
        26 if remaining > 3 => (
            u64::from(u32::from_be_bytes([at(0), at(1), at(2), at(3)])),
            5,
        ),
        27 if remaining > 7 => {
            let mut buffer = [0u8; 8];
            for (offset, byte) in buffer.iter_mut().enumerate() {
                *byte = at(offset);
            }
            let value = u64::from_be_bytes(buffer);
            if (24..=MAX_SAFE).contains(&value) {
                return Ok((value, 9));
            }
            return Err(error("Length not supported or not well formed"));
        }
        _ => return Err(error("Length not supported or not well formed")),
    };
    if value >= 24 {
        Ok((value, bytes))
    } else {
        Err(error("Length not supported or not well formed"))
    }
}

fn decode_byte_string(
    data: &[u8],
    argument: u8,
    index: usize,
) -> Result<(Vec<u8>, usize), CborError> {
    let (length, consumed) = decode_length(data, argument, index)?;
    let start = index + consumed;
    // `ArrayBuffer#slice` clamps to the end of the buffer.
    let end = (start as u64).saturating_add(length).min(data.len() as u64) as usize;
    let bytes = data
        .get(start.min(data.len())..end)
        .unwrap_or_default()
        .to_vec();
    Ok((bytes, consumed + length as usize))
}

fn decode_next(data: &[u8], index: usize) -> Result<(Cbor, usize), CborError> {
    if index >= data.len() {
        return Err(error("CBOR stream ended before tag value"));
    }
    let byte = data[index];
    let major = byte >> 5;
    let argument = byte & 0x1f;
    match major {
        0 => {
            let (value, length) = decode_length(data, argument, index)?;
            Ok((Cbor::Number(value as f64), length))
        }
        1 => {
            let (value, length) = decode_length(data, argument, index)?;
            Ok((Cbor::Number(-(value as f64) - 1.0), length))
        }
        2 => {
            let (bytes, length) = decode_byte_string(data, argument, index)?;
            Ok((Cbor::Bytes(bytes), length))
        }
        3 => {
            let (bytes, length) = decode_byte_string(data, argument, index)?;
            Ok((
                Cbor::Text(String::from_utf8_lossy(&bytes).into_owned()),
                length,
            ))
        }
        4 => {
            if argument == 0 {
                return Ok((Cbor::Array(Vec::new()), 1));
            }
            let (count, mut consumed) = decode_length(data, argument, index)?;
            let mut items = Vec::new();
            for _ in 0..count {
                if data.len() as i64 - index as i64 - consumed as i64 <= 0 {
                    return Err(error("array is not supported or well formed"));
                }
                let (item, used) = decode_next(data, index + consumed)?;
                items.push(item);
                consumed += used;
            }
            Ok((Cbor::Array(items), consumed))
        }
        5 => {
            const MAP_ERROR: &str = "Map is not supported or well formed";
            if argument == 0 {
                return Ok((Cbor::Map(Vec::new()), 1));
            }
            let (count, mut consumed) = decode_length(data, argument, index)?;
            let mut entries: Vec<(Cbor, Cbor)> = Vec::new();
            for _ in 0..count {
                let mut remaining = data.len() as i64 - index as i64 - consumed as i64;
                if remaining <= 0 {
                    return Err(error(MAP_ERROR));
                }
                let (key, used) = decode_next(data, index + consumed)?;
                consumed += used;
                remaining -= used as i64;
                if remaining <= 0 {
                    return Err(error(MAP_ERROR));
                }
                if !matches!(key, Cbor::Number(_) | Cbor::Text(_)) {
                    return Err(error(MAP_ERROR));
                }
                if entries
                    .iter()
                    .any(|(existing, _)| same_value_zero(existing, &key))
                {
                    return Err(error(MAP_ERROR));
                }
                let (value, used) = decode_next(data, index + consumed)?;
                consumed += used;
                entries.push((key, value));
            }
            Ok((Cbor::Map(entries), consumed))
        }
        6 => {
            let (tag, used) = decode_length(data, argument, index)?;
            let (value, value_used) = decode_next(data, index + used)?;
            Ok((Cbor::Tag(tag, Box::new(value)), used + value_used))
        }
        _ => match argument {
            20 => Ok((Cbor::Bool(false), 1)),
            21 => Ok((Cbor::Bool(true), 1)),
            22 => Ok((Cbor::Null, 1)),
            23 => Ok((Cbor::Undefined, 1)),
            25 => {
                if index + 3 > data.len() {
                    return Err(error("CBOR stream ended before end of Float 16"));
                }
                match u16::from_be_bytes([data[index + 1], data[index + 2]]) {
                    0x7c00 => Ok((Cbor::Number(f64::INFINITY), 3)),
                    0x7e00 => Ok((Cbor::Number(f64::NAN), 3)),
                    0xfc00 => Ok((Cbor::Number(f64::NEG_INFINITY), 3)),
                    _ => Err(error("Float16 data is unsupported")),
                }
            }
            26 => {
                if index + 5 > data.len() {
                    return Err(error("CBOR stream ended before end of Float 32"));
                }
                let bits = u32::from_be_bytes([
                    data[index + 1],
                    data[index + 2],
                    data[index + 3],
                    data[index + 4],
                ]);
                Ok((Cbor::Number(f64::from(f32::from_bits(bits))), 5))
            }
            27 => {
                if index + 9 > data.len() {
                    return Err(error("CBOR stream ended before end of Float 64"));
                }
                let mut buffer = [0u8; 8];
                buffer.copy_from_slice(&data[index + 1..index + 9]);
                Ok((Cbor::Number(f64::from_bits(u64::from_be_bytes(buffer))), 9))
            }
            _ => Err(CborError(format!(
                "Unsupported or not well formed at {index}"
            ))),
        },
    }
}

/// `decodeFirst(input)`: the first item of a CBOR sequence.
pub fn decode_first(input: &[u8]) -> Result<Cbor, CborError> {
    if input.is_empty() {
        return Err(error("No data"));
    }
    decode_next(input, 0).map(|(value, _)| value)
}

fn encode_length(out: &mut Vec<u8>, major: u8, argument: u64) {
    let head = major << 5;
    if argument <= 23 {
        out.push(head | argument as u8);
    } else if argument <= 255 {
        out.push(head | 24);
        out.push(argument as u8);
    } else if argument <= 65_535 {
        out.push(head | 25);
        out.extend_from_slice(&(argument as u16).to_be_bytes());
    } else if argument <= u64::from(u32::MAX) {
        out.push(head | 26);
        out.extend_from_slice(&(argument as u32).to_be_bytes());
    } else {
        out.push(head | 27);
        out.extend_from_slice(&argument.to_be_bytes());
    }
}

fn encode_into(value: &Cbor, out: &mut Vec<u8>) {
    match value {
        Cbor::Bool(true) => out.push(0xf5),
        Cbor::Bool(false) => out.push(0xf4),
        Cbor::Null => out.push(0xf6),
        Cbor::Undefined => out.push(0xf7),
        Cbor::Number(number) => {
            let number = *number;
            let safe =
                number.is_finite() && number.fract() == 0.0 && number.abs() <= MAX_SAFE as f64;
            if safe {
                if number < 0.0 {
                    // Negative integers encode |n| - 1.
                    encode_length(out, 1, (-number) as u64 - 1);
                } else {
                    encode_length(out, 0, number as u64);
                }
            } else if f64::from(number as f32) == number || !number.is_finite() {
                out.push(0xfa);
                out.extend_from_slice(&(number as f32).to_bits().to_be_bytes());
            } else {
                out.push(0xfb);
                out.extend_from_slice(&number.to_bits().to_be_bytes());
            }
        }
        Cbor::Text(text) => {
            // tiny-cbor writes the UTF-16 length as the byte count, then the UTF-8 bytes.
            encode_length(out, 3, text.encode_utf16().count() as u64);
            out.extend_from_slice(text.as_bytes());
        }
        Cbor::Bytes(bytes) => {
            encode_length(out, 2, bytes.len() as u64);
            out.extend_from_slice(bytes);
        }
        Cbor::Array(items) => {
            encode_length(out, 4, items.len() as u64);
            for item in items {
                encode_into(item, out);
            }
        }
        Cbor::Map(entries) => {
            encode_length(out, 5, entries.len() as u64);
            for (key, item) in entries {
                encode_into(key, out);
                encode_into(item, out);
            }
        }
        Cbor::Tag(tag, item) => {
            encode_length(out, 6, *tag);
            encode_into(item, out);
        }
    }
}

/// `encode(input)`.
pub fn encode(value: &Cbor) -> Vec<u8> {
    let mut out = Vec::new();
    encode_into(value, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_cose_keys_and_rejects_non_minimal_lengths() {
        let key = Cbor::Map(vec![
            (Cbor::Number(1.0), Cbor::Number(2.0)),
            (Cbor::Number(3.0), Cbor::Number(-7.0)),
            (Cbor::Number(-1.0), Cbor::Number(1.0)),
            (Cbor::Number(-2.0), Cbor::Bytes(vec![1; 32])),
            (Cbor::Number(-3.0), Cbor::Bytes(vec![2; 32])),
        ]);
        let bytes = encode(&key);
        assert_eq!(decode_first(&bytes).unwrap(), key);
        assert_eq!(encode(&decode_first(&bytes).unwrap()), bytes);
        assert!(decode_first(&[0x18, 0x05]).is_err());
        assert!(decode_first(&[0xa2, 0x01, 0x02, 0x01, 0x03]).is_err());
    }
}
