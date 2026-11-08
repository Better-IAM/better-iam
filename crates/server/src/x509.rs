//! Port of `packages/server/src/x509.ts`.
//!
//! The X.509 layer of the private certificate authority (pki.rs): a DER encoder and a bounds-checked DER reader,
//! PKCS#10 certification requests (built for clients and tests, parsed and verified for issuance), certificates, and
//! certificate revocation lists (RFC 5280).
//!
//! TypeScript leans on `node:crypto` for keys (`createPublicKey`, `sign`, `verify`) and for reading certificates
//! (`X509Certificate`). The Rust port does the same work on RustCrypto (`p256`, `p384`, `ed25519-dalek`, `rsa`):
//! [`PublicKey`] reads a SubjectPublicKeyInfo as `createPublicKey` does, [`PrivateKey`] a PKCS#8 key, and
//! [`X509Certificate`] the members of Node's `X509Certificate` that pki.ts uses (raw bytes, serial number, validity,
//! subject, subject alternative names, `ca`, `checkIssued`, `verify`), formatted as Node formats them.

use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use better_iam_core::js as core_js;
use better_iam_core::{IamError, IamResult};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::signature::{SignatureEncoding, Signer};
use p256::pkcs8::{DecodePrivateKey, EncodePublicKey};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::js::utf16_len;

// ---------------------------------------------------------------------------------------------------------------
// DER encoding

fn length(size: usize) -> Vec<u8> {
    if size < 0x80 {
        return vec![size as u8];
    }
    let mut bytes = Vec::new();
    let mut rest = size;
    while rest > 0 {
        bytes.insert(0, (rest & 0xff) as u8);
        rest /= 256;
    }
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    out
}

pub fn tlv(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(length(contents.len()));
    out.extend_from_slice(contents);
    out
}

fn concat<I, B>(items: I) -> Vec<u8>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    let mut out = Vec::new();
    for item in items {
        out.extend_from_slice(item.as_ref());
    }
    out
}

pub fn sequence<I, B>(items: I) -> Vec<u8>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    tlv(0x30, &concat(items))
}

pub fn set<I, B>(items: I) -> Vec<u8>
where
    I: IntoIterator<Item = B>,
    B: AsRef<[u8]>,
{
    tlv(0x31, &concat(items))
}

pub fn null_value() -> Vec<u8> {
    vec![0x05, 0x00]
}

pub fn boolean_value(value: bool) -> Vec<u8> {
    tlv(0x01, &[if value { 0xff } else { 0x00 }])
}

pub fn octet_string(value: &[u8]) -> Vec<u8> {
    tlv(0x04, value)
}

pub fn utf8_string(value: &str) -> Vec<u8> {
    tlv(0x0c, value.as_bytes())
}

/// `Buffer.from(value, 'ascii')`: one byte per UTF-16 code unit (its low byte).
fn ascii_bytes(value: &str) -> Vec<u8> {
    value.encode_utf16().map(|unit| unit as u8).collect()
}

pub fn printable_string(value: &str) -> Vec<u8> {
    tlv(0x13, &ascii_bytes(value))
}

pub fn ia5_string(value: &str) -> Vec<u8> {
    tlv(0x16, &ascii_bytes(value))
}

/// `[n] EXPLICIT`: a constructed context-specific wrapper.
pub fn explicit(tag: u8, value: &[u8]) -> Vec<u8> {
    tlv(0xa0 | tag, value)
}

/// A non-negative INTEGER in minimal two's complement form, from its big-endian bytes.
pub fn integer_bytes(value: &[u8]) -> Vec<u8> {
    let mut start = 0;
    while start + 1 < value.len() && value[start] == 0 && (value[start + 1] & 0x80) == 0 {
        start += 1;
    }
    let mut bytes = value[start..].to_vec();
    if bytes.is_empty() {
        bytes = vec![0];
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    tlv(0x02, &bytes)
}

/// A non-negative INTEGER from a number.
pub fn integer(value: u64) -> Vec<u8> {
    let mut hex = format!("{value:x}");
    if hex.len() % 2 == 1 {
        hex.insert(0, '0');
    }
    integer_bytes(&hex::decode(hex).unwrap_or_default())
}

/// An OBJECT IDENTIFIER from its dotted form (the OIDs this module names; an invalid one encodes as given parts).
pub fn oid(dotted: &str) -> Vec<u8> {
    let parts: Vec<u128> = dotted
        .split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect();
    if parts.len() < 2 {
        panic!("Invalid OID {dotted}");
    }
    let mut bytes = vec![(parts[0] * 40 + parts[1]) as u8];
    for part in &parts[2..] {
        let mut chunk = Vec::new();
        let mut rest = *part;
        loop {
            chunk.insert(0, (rest & 0x7f) as u8);
            rest >>= 7;
            if rest == 0 {
                break;
            }
        }
        let last = chunk.len() - 1;
        for byte in &mut chunk[..last] {
            *byte |= 0x80;
        }
        bytes.extend(chunk);
    }
    tlv(0x06, &bytes)
}

/// A BIT STRING of whole bytes (no unused bits).
pub fn bit_string(value: &[u8]) -> Vec<u8> {
    let mut contents = vec![0];
    contents.extend_from_slice(value);
    tlv(0x03, &contents)
}

/// A named-bit BIT STRING (key usage): bits numbered from the most significant bit, trailing zeros removed.
pub fn named_bits(bits: &[usize]) -> Vec<u8> {
    let highest = bits.iter().copied().max().unwrap_or(0);
    let mut bytes = vec![0u8; highest / 8 + 1];
    for bit in bits {
        bytes[bit / 8] |= 0x80 >> (bit % 8);
    }
    let last = bytes[bytes.len() - 1];
    let mut unused = 0;
    while unused < 7 && (last & (1 << unused)) == 0 {
        unused += 1;
    }
    let mut contents = vec![unused as u8];
    contents.extend(bytes);
    tlv(0x03, &contents)
}

/// UTCTime through 2049, GeneralizedTime from 2050 (RFC 5280 4.1.2.5).
pub fn time(at: f64) -> Vec<u8> {
    let seconds = (at / 1000.0).floor() as i64;
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    let (year, month, day) = core_js::civil_from_days(days);
    let body = format!(
        "{month:02}{day:02}{:02}{:02}{:02}Z",
        rest / 3600,
        (rest / 60) % 60,
        rest % 60
    );
    if (1950..2050).contains(&year) {
        return tlv(0x17, format!("{:02}{body}", year % 100).as_bytes());
    }
    tlv(0x18, format!("{year:04}{body}").as_bytes())
}

// ---------------------------------------------------------------------------------------------------------------
// DER reading

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerNode {
    pub tag: u8,
    /// Offset of the tag byte.
    pub start: usize,
    /// Offset of the first content byte.
    pub content_start: usize,
    /// Offset just past the node.
    pub end: usize,
}

fn malformed() -> IamError {
    IamError::with_status(
        "INVALID_CSR",
        "The certificate request is not valid DER",
        400,
    )
}

pub fn read_node(buffer: &[u8], offset: usize, limit: usize) -> IamResult<DerNode> {
    if offset + 2 > limit {
        return Err(malformed());
    }
    let tag = buffer[offset];
    if (tag & 0x1f) == 0x1f {
        return Err(malformed());
    }
    let mut size = buffer[offset + 1] as usize;
    let mut content_start = offset + 2;
    if size & 0x80 != 0 {
        let count = size & 0x7f;
        if count == 0 || count > 4 || content_start + count > limit {
            return Err(malformed());
        }
        size = 0;
        for index in 0..count {
            size = size * 256 + buffer[content_start + index] as usize;
        }
        content_start += count;
        if size < 0x80 {
            return Err(malformed());
        }
    }
    let end = content_start + size;
    if end > limit {
        return Err(malformed());
    }
    Ok(DerNode {
        tag,
        start: offset,
        content_start,
        end,
    })
}

/// `readNode(buffer, 0)`: the node at the start of a buffer, bounded by the buffer.
pub fn read_root(buffer: &[u8]) -> IamResult<DerNode> {
    read_node(buffer, 0, buffer.len())
}

pub fn children_of(buffer: &[u8], node: &DerNode) -> IamResult<Vec<DerNode>> {
    let mut children = Vec::new();
    let mut offset = node.content_start;
    while offset < node.end {
        let child = read_node(buffer, offset, node.end)?;
        children.push(child);
        offset = child.end;
        if children.len() > 1000 {
            return Err(malformed());
        }
    }
    Ok(children)
}

fn contents<'a>(buffer: &'a [u8], node: &DerNode) -> &'a [u8] {
    &buffer[node.content_start..node.end]
}

fn whole<'a>(buffer: &'a [u8], node: &DerNode) -> &'a [u8] {
    &buffer[node.start..node.end]
}

pub fn decode_oid(bytes: &[u8]) -> IamResult<String> {
    if bytes.is_empty() {
        return Err(malformed());
    }
    let first = bytes[0] as u64;
    let mut parts: Vec<u64> = if first < 80 {
        vec![first / 40, first % 40]
    } else {
        vec![2, first - 80]
    };
    let mut value: u64 = 0;
    for byte in &bytes[1..] {
        value = value * 128 + (byte & 0x7f) as u64;
        if value > core_js::MAX_SAFE_INTEGER as u64 {
            return Err(malformed());
        }
        if byte & 0x80 == 0 {
            parts.push(value);
            value = 0;
        }
    }
    Ok(parts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join("."))
}

// ---------------------------------------------------------------------------------------------------------------
// Names and algorithms

/// `OIDS`.
pub mod oids {
    pub const COMMON_NAME: &str = "2.5.4.3";
    pub const COUNTRY: &str = "2.5.4.6";
    pub const LOCALITY: &str = "2.5.4.7";
    pub const STATE: &str = "2.5.4.8";
    pub const ORGANIZATION: &str = "2.5.4.10";
    pub const ORGANIZATIONAL_UNIT: &str = "2.5.4.11";
    pub const SUBJECT_KEY_IDENTIFIER: &str = "2.5.29.14";
    pub const KEY_USAGE: &str = "2.5.29.15";
    pub const SUBJECT_ALT_NAME: &str = "2.5.29.17";
    pub const BASIC_CONSTRAINTS: &str = "2.5.29.19";
    pub const CRL_NUMBER: &str = "2.5.29.20";
    pub const CRL_REASON: &str = "2.5.29.21";
    pub const NAME_CONSTRAINTS: &str = "2.5.29.30";
    pub const CRL_DISTRIBUTION_POINTS: &str = "2.5.29.31";
    pub const AUTHORITY_KEY_IDENTIFIER: &str = "2.5.29.35";
    pub const EXT_KEY_USAGE: &str = "2.5.29.37";
    pub const SERVER_AUTH: &str = "1.3.6.1.5.5.7.3.1";
    pub const CLIENT_AUTH: &str = "1.3.6.1.5.5.7.3.2";
    pub const EXTENSION_REQUEST: &str = "1.2.840.113549.1.9.14";
    pub const ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
    pub const ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
    pub const ECDSA_SHA512: &str = "1.2.840.10045.4.3.4";
    pub const RSA_SHA256: &str = "1.2.840.113549.1.1.11";
    pub const RSA_SHA384: &str = "1.2.840.113549.1.1.12";
    pub const RSA_SHA512: &str = "1.2.840.113549.1.1.13";
    pub const ED25519: &str = "1.3.101.112";
}

/// A distinguished name; every part optional.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DistinguishedName {
    #[serde(
        rename = "commonName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub common_name: Option<String>,
    #[serde(
        rename = "organization",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub organization: Option<String>,
    #[serde(
        rename = "organizationalUnit",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub organizational_unit: Option<String>,
    #[serde(rename = "locality", default, skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    #[serde(rename = "state", default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(rename = "country", default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl DistinguishedName {
    /// `{ commonName }`.
    pub fn common(common_name: &str) -> Self {
        Self {
            common_name: Some(common_name.to_owned()),
            ..Self::default()
        }
    }
}

fn present(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|text| !text.is_empty())
}

/// Encodes a name in the conventional order (C, ST, L, O, OU, CN), one attribute per RDN.
pub fn encode_name(name: &DistinguishedName) -> Vec<u8> {
    let rdn = |kind: &str, value: Vec<u8>| set([sequence([oid(kind), value])]);
    let mut parts = Vec::new();
    if let Some(country) = present(&name.country) {
        parts.push(rdn(oids::COUNTRY, printable_string(country)));
    }
    if let Some(state) = present(&name.state) {
        parts.push(rdn(oids::STATE, utf8_string(state)));
    }
    if let Some(locality) = present(&name.locality) {
        parts.push(rdn(oids::LOCALITY, utf8_string(locality)));
    }
    if let Some(organization) = present(&name.organization) {
        parts.push(rdn(oids::ORGANIZATION, utf8_string(organization)));
    }
    if let Some(unit) = present(&name.organizational_unit) {
        parts.push(rdn(oids::ORGANIZATIONAL_UNIT, utf8_string(unit)));
    }
    if let Some(common_name) = present(&name.common_name) {
        parts.push(rdn(oids::COMMON_NAME, utf8_string(common_name)));
    }
    sequence(parts)
}

/// `'ES256' | 'ES384' | 'EdDSA' | 'RS256' | 'RS384' | 'RS512'`.
pub type SignatureAlgorithm = String;

fn algorithm_oid(algorithm: &str) -> &'static str {
    match algorithm {
        "ES384" => oids::ECDSA_SHA384,
        "EdDSA" => oids::ED25519,
        "RS256" => oids::RSA_SHA256,
        "RS384" => oids::RSA_SHA384,
        "RS512" => oids::RSA_SHA512,
        _ => oids::ECDSA_SHA256,
    }
}

pub fn algorithm_identifier(algorithm: &str) -> Vec<u8> {
    if algorithm.starts_with("RS") {
        sequence([oid(algorithm_oid(algorithm)), null_value()])
    } else {
        sequence([oid(algorithm_oid(algorithm))])
    }
}

/// The hash of a signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha256 => Sha256::digest(data).to_vec(),
            Hash::Sha384 => Sha384::digest(data).to_vec(),
            Hash::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// The hash for a signature OID, `Some(None)` for Ed25519; None for anything else (RSA-PSS included).
fn hash_for_oid(value: &str) -> Option<Option<Hash>> {
    match value {
        oids::ECDSA_SHA256 | oids::RSA_SHA256 => Some(Some(Hash::Sha256)),
        oids::ECDSA_SHA384 | oids::RSA_SHA384 => Some(Some(Hash::Sha384)),
        oids::ECDSA_SHA512 | oids::RSA_SHA512 => Some(Some(Hash::Sha512)),
        oids::ED25519 => Some(None),
        _ => None,
    }
}

const EC_PUBLIC_KEY: &str = "1.2.840.10045.2.1";
const PRIME256V1: &str = "1.2.840.10045.3.1.7";
const SECP384R1: &str = "1.3.132.0.34";
const RSA_ENCRYPTION: &str = "1.2.840.113549.1.1.1";

/// A public key as `createPublicKey({ key: spki, format: 'der', type: 'spki' })` reads it.
#[derive(Debug, Clone)]
pub enum PublicKey {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    /// Ed25519: any 32 bytes are a readable key (the point is checked when a signature is verified).
    Ed25519([u8; 32]),
    /// RSA: the modulus and public exponent (big-endian, without leading zeros) and the modulus length in bits.
    Rsa {
        modulus: Vec<u8>,
        exponent: Vec<u8>,
        bits: usize,
    },
    /// A key Node reads but nothing here accepts, by its `asymmetricKeyType` (`ec` on another curve, `rsa-pss`,
    /// `dsa`, `dh`, `x25519`, `x448`, `ed448`).
    Other(String),
}

fn strip_zeros(bytes: &[u8]) -> Vec<u8> {
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    bytes[start..].to_vec()
}

fn bit_length(bytes: &[u8]) -> usize {
    let bytes = strip_zeros(bytes);
    match bytes.first() {
        None => 0,
        Some(first) => (bytes.len() - 1) * 8 + (8 - first.leading_zeros() as usize),
    }
}

impl PublicKey {
    /// Reads a DER SubjectPublicKeyInfo; None when Node could not read it either.
    pub fn from_spki(spki: &[u8]) -> Option<PublicKey> {
        let root = read_root(spki).ok()?;
        if root.tag != 0x30 || root.end != spki.len() {
            return None;
        }
        let parts = children_of(spki, &root).ok()?;
        let [algorithm, bits] = parts.as_slice() else {
            return None;
        };
        if algorithm.tag != 0x30 || bits.tag != 0x03 {
            return None;
        }
        let identifiers = children_of(spki, algorithm).ok()?;
        let kind = identifiers.first().filter(|node| node.tag == 0x06)?;
        let kind = decode_oid(contents(spki, kind)).ok()?;
        let parameters = identifiers.get(1);
        let bits = contents(spki, bits);
        if bits.first() != Some(&0) {
            return None;
        }
        let key = &bits[1..];
        match kind.as_str() {
            EC_PUBLIC_KEY => {
                let parameters = parameters?;
                if parameters.tag == 0x30 {
                    return Some(PublicKey::Other("ec".into()));
                }
                if parameters.tag != 0x06 {
                    return None;
                }
                match decode_oid(contents(spki, parameters)).ok()?.as_str() {
                    PRIME256V1 => p256::ecdsa::VerifyingKey::from_sec1_bytes(key)
                        .ok()
                        .map(PublicKey::P256),
                    SECP384R1 => p384::ecdsa::VerifyingKey::from_sec1_bytes(key)
                        .ok()
                        .map(PublicKey::P384),
                    // P-521, secp256k1 and the Brainpool curves: keys Node reads, on curves nothing here accepts.
                    "1.3.132.0.35"
                    | "1.3.132.0.10"
                    | "1.3.36.3.3.2.8.1.1.7"
                    | "1.3.36.3.3.2.8.1.1.11"
                    | "1.3.36.3.3.2.8.1.1.13" => {
                        (!key.is_empty()).then(|| PublicKey::Other("ec".into()))
                    }
                    _ => None,
                }
            }
            oids::ED25519 => key.try_into().ok().map(PublicKey::Ed25519),
            RSA_ENCRYPTION => {
                let root = read_root(key).ok()?;
                if root.tag != 0x30 || root.end != key.len() {
                    return None;
                }
                let numbers = children_of(key, &root).ok()?;
                let [modulus, exponent] = numbers.as_slice() else {
                    return None;
                };
                if modulus.tag != 0x02 || exponent.tag != 0x02 {
                    return None;
                }
                let (modulus, exponent) = (contents(key, modulus), contents(key, exponent));
                if modulus.is_empty()
                    || exponent.is_empty()
                    || modulus[0] & 0x80 != 0
                    || exponent[0] & 0x80 != 0
                {
                    return None;
                }
                let (modulus, exponent) = (strip_zeros(modulus), strip_zeros(exponent));
                if modulus.is_empty() || exponent.is_empty() {
                    return None;
                }
                let bits = bit_length(&modulus);
                Some(PublicKey::Rsa {
                    modulus,
                    exponent,
                    bits,
                })
            }
            "1.2.840.113549.1.1.10" => Some(PublicKey::Other("rsa-pss".into())),
            "1.2.840.10040.4.1" => Some(PublicKey::Other("dsa".into())),
            "1.2.840.113549.1.3.1" | "1.2.840.10046.2.1" => Some(PublicKey::Other("dh".into())),
            "1.3.101.110" if key.len() == 32 => Some(PublicKey::Other("x25519".into())),
            "1.3.101.111" if key.len() == 56 => Some(PublicKey::Other("x448".into())),
            "1.3.101.113" if key.len() == 57 => Some(PublicKey::Other("ed448".into())),
            _ => None,
        }
    }

    /// `asymmetricKeyType`.
    pub fn key_type(&self) -> &str {
        match self {
            PublicKey::P256(_) | PublicKey::P384(_) => "ec",
            PublicKey::Ed25519(_) => "ed25519",
            PublicKey::Rsa { .. } => "rsa",
            PublicKey::Other(kind) => kind,
        }
    }

    /// `verify(hash, data, key, signature)`: false for a signature that does not verify or does not fit the key.
    pub fn verify(&self, hash: Option<Hash>, data: &[u8], signature: &[u8]) -> bool {
        match (self, hash) {
            (PublicKey::Ed25519(bytes), None) => {
                let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(bytes) else {
                    return false;
                };
                let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
                    return false;
                };
                // Cofactorless with a canonical `s`, as OpenSSL verifies Ed25519.
                ed25519_dalek::Verifier::verify(&key, data, &signature).is_ok()
            }
            (PublicKey::P256(key), Some(hash)) => {
                let Ok(signature) = p256::ecdsa::Signature::from_der(signature) else {
                    return false;
                };
                key.verify_prehash(&hash.digest(data), &signature).is_ok()
            }
            (PublicKey::P384(key), Some(hash)) => {
                let Ok(signature) = p384::ecdsa::Signature::from_der(signature) else {
                    return false;
                };
                key.verify_prehash(&hash.digest(data), &signature).is_ok()
            }
            (
                PublicKey::Rsa {
                    modulus, exponent, ..
                },
                Some(hash),
            ) => {
                let Ok(key) = rsa::RsaPublicKey::new_with_max_size(
                    rsa::BigUint::from_bytes_be(modulus),
                    rsa::BigUint::from_bytes_be(exponent),
                    16384,
                ) else {
                    return false;
                };
                let scheme = match hash {
                    Hash::Sha256 => rsa::Pkcs1v15Sign::new::<Sha256>(),
                    Hash::Sha384 => rsa::Pkcs1v15Sign::new::<Sha384>(),
                    Hash::Sha512 => rsa::Pkcs1v15Sign::new::<Sha512>(),
                };
                key.verify(scheme, &hash.digest(data), signature).is_ok()
            }
            _ => false,
        }
    }
}

/// A private key (`createPrivateKey`): ECDSA P-256/P-384, Ed25519 or RSA.
#[derive(Clone)]
pub enum PrivateKey {
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    Ed25519(ed25519_dalek::SigningKey),
    Rsa(rsa::RsaPrivateKey),
}

fn invalid_key() -> IamError {
    IamError::new(
        "INVALID_INPUT",
        "Keys must be ECDSA P-256/P-384, Ed25519 or RSA",
    )
}

impl PrivateKey {
    /// A PKCS#8 private key in PEM (`-----BEGIN PRIVATE KEY-----`).
    pub fn from_pkcs8_pem(pem_text: &str) -> IamResult<PrivateKey> {
        let body = pem_text
            .replacen("-----BEGIN PRIVATE KEY-----", "", 1)
            .replacen("-----END PRIVATE KEY-----", "", 1)
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();
        let der = STANDARD.decode(body).map_err(|_| invalid_key())?;
        PrivateKey::from_pkcs8_der(&der)
    }

    /// A PKCS#8 private key in DER.
    pub fn from_pkcs8_der(der: &[u8]) -> IamResult<PrivateKey> {
        let algorithm = (|| {
            let root = read_root(der).ok()?;
            let parts = children_of(der, &root).ok()?;
            let identifier = parts.get(1).filter(|node| node.tag == 0x30)?;
            let identifiers = children_of(der, identifier).ok()?;
            let kind = decode_oid(contents(der, identifiers.first()?)).ok()?;
            let curve = identifiers
                .get(1)
                .filter(|node| node.tag == 0x06)
                .and_then(|node| decode_oid(contents(der, node)).ok());
            Some((kind, curve))
        })()
        .ok_or_else(invalid_key)?;
        match (algorithm.0.as_str(), algorithm.1.as_deref()) {
            (EC_PUBLIC_KEY, Some(PRIME256V1)) => p256::SecretKey::from_pkcs8_der(der)
                .map(PrivateKey::P256)
                .map_err(|_| invalid_key()),
            (EC_PUBLIC_KEY, Some(SECP384R1)) => p384::SecretKey::from_pkcs8_der(der)
                .map(PrivateKey::P384)
                .map_err(|_| invalid_key()),
            (oids::ED25519, _) => ed25519_dalek::SigningKey::from_pkcs8_der(der)
                .map(PrivateKey::Ed25519)
                .map_err(|_| invalid_key()),
            (RSA_ENCRYPTION, _) => rsa::RsaPrivateKey::from_pkcs8_der(der)
                .map(PrivateKey::Rsa)
                .map_err(|_| invalid_key()),
            _ => Err(invalid_key()),
        }
    }

    /// `createPublicKey(key).export({ format: 'der', type: 'spki' })`.
    pub fn spki(&self) -> IamResult<Vec<u8>> {
        let document = match self {
            PrivateKey::P256(key) => key.public_key().to_public_key_der(),
            PrivateKey::P384(key) => key.public_key().to_public_key_der(),
            PrivateKey::Ed25519(key) => key.verifying_key().to_public_key_der(),
            PrivateKey::Rsa(key) => rsa::RsaPublicKey::from(key).to_public_key_der(),
        };
        document
            .map(|document| document.as_bytes().to_vec())
            .map_err(|_| invalid_key())
    }
}

/// The signature algorithm a private key signs certificates and requests with.
pub fn algorithm_for_key(key: &PrivateKey) -> SignatureAlgorithm {
    match key {
        PrivateKey::Ed25519(_) => "EdDSA",
        PrivateKey::P384(_) => "ES384",
        PrivateKey::P256(_) => "ES256",
        PrivateKey::Rsa(_) => "RS256",
    }
    .to_owned()
}

/// Checks a subject public key: ECDSA P-256/P-384, Ed25519, or RSA of 2048 bits or more.
pub fn acceptable_public_key(key: &PublicKey) -> IamResult<String> {
    match key {
        PublicKey::Ed25519(_) => return Ok("ed25519".into()),
        PublicKey::P256(_) => return Ok("ecc-p256".into()),
        PublicKey::P384(_) => return Ok("ecc-p384".into()),
        PublicKey::Rsa { exponent, bits, .. } => {
            // A huge public exponent makes every verification slow; real keys use 65537 (or 3).
            let exponent = if exponent.len() > 8 {
                u64::MAX
            } else {
                exponent
                    .iter()
                    .fold(0u64, |value, byte| value * 256 + *byte as u64)
            };
            if (2048..=8192).contains(bits) && (3..=65537).contains(&exponent) {
                return Ok(format!("rsa-{bits}"));
            }
        }
        PublicKey::Other(_) => {}
    }
    Err(IamError::with_status(
        "INVALID_CSR",
        "The requested key must be ECDSA P-256 or P-384, Ed25519, or RSA of 2048 to 8192 bits",
        400,
    ))
}

fn sign_with(key: &PrivateKey, algorithm: &str, data: &[u8]) -> IamResult<Vec<u8>> {
    match (key, algorithm) {
        (PrivateKey::Ed25519(key), _) => Ok(key.sign(data).to_bytes().to_vec()),
        (PrivateKey::P256(key), _) => {
            let signer = p256::ecdsa::SigningKey::from(key);
            let signature: p256::ecdsa::Signature = signer.sign(data);
            Ok(signature.to_der().as_bytes().to_vec())
        }
        (PrivateKey::P384(key), _) => {
            let signer = p384::ecdsa::SigningKey::from(key);
            let signature: p384::ecdsa::Signature = signer.sign(data);
            Ok(signature.to_der().as_bytes().to_vec())
        }
        (PrivateKey::Rsa(key), algorithm) => {
            let signature = if algorithm.ends_with("384") {
                rsa::pkcs1v15::SigningKey::<Sha384>::new(key.clone()).sign(data)
            } else if algorithm.ends_with("512") {
                rsa::pkcs1v15::SigningKey::<Sha512>::new(key.clone()).sign(data)
            } else {
                rsa::pkcs1v15::SigningKey::<Sha256>::new(key.clone()).sign(data)
            };
            Ok(signature.to_vec())
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Subject alternative names

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SubjectAltNames {
    #[serde(rename = "dnsNames")]
    pub dns_names: Vec<String>,
    #[serde(rename = "uris")]
    pub uris: Vec<String>,
    #[serde(rename = "ipAddresses")]
    pub ip_addresses: Vec<String>,
    #[serde(rename = "emails")]
    pub emails: Vec<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl SubjectAltNames {
    fn total(&self) -> usize {
        self.dns_names.len() + self.uris.len() + self.ip_addresses.len() + self.emails.len()
    }

    /// The names as the JSON object `subjectAltNames` reads.
    pub fn to_value(&self) -> Value {
        json!({
            "dnsNames": self.dns_names,
            "uris": self.uris,
            "ipAddresses": self.ip_addresses,
            "emails": self.emails,
        })
    }
}

static DNS_NAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    )
    .expect("dnsName")
});
/// Printable ASCII only: IA5String names are encoded byte for byte, so what is decided is what is signed.
static EMAIL_ADDRESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+$").expect("email")
});
/// The SPIFFE ID grammar: a lowercase trust domain and path segments of letters, digits, dots, dashes, underscores.
static SPIFFE_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^spiffe://[a-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$").expect("spiffe"));

/// `dnsName`: a lowercase DNS name, optionally a wildcard (`*.example.internal`).
pub fn dns_name() -> &'static Regex {
    &DNS_NAME
}

fn canonical_uri(value: &str) -> IamResult<String> {
    let invalid = || IamError::new("INVALID_INPUT", format!("Invalid URI {value}"));
    if utf16_len(value) > 2048
        || value.is_empty()
        || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        || value.contains('\\')
    {
        return Err(invalid());
    }
    if core_js::to_lower(value).starts_with("spiffe:") {
        if !SPIFFE_ID.is_match(value)
            || value
                .split('/')
                .any(|segment| segment == "." || segment == "..")
        {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!(
                    "Invalid SPIFFE ID {value}: spiffe://{{trust domain}}/{{path}}, with no dot segments, query or fragment"
                ),
            ));
        }
        return Ok(value.to_owned());
    }
    let parsed = url::Url::parse(value).map_err(|_| invalid())?;
    // Only a URI already in canonical form is accepted, so policies decide on the exact string that is encoded
    // (dot segments, percent-encoded dots, host case and default ports are all resolved by the parser).
    if parsed.as_str() != value || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(invalid());
    }
    Ok(value.to_owned())
}

/// `isIP(value)` and the address bytes, for the forms Node's `isIP` accepts (dotted IPv4 without leading zeros,
/// IPv6 with an optional IPv4 tail).
fn ip_bytes(value: &str) -> Option<Vec<u8>> {
    if let Ok(address) = value.parse::<std::net::Ipv4Addr>() {
        return Some(address.octets().to_vec());
    }
    value
        .parse::<std::net::Ipv6Addr>()
        .ok()
        .map(|address| address.octets().to_vec())
}

/// An IP address in canonical text: dotted IPv4 (IPv4-mapped IPv6 included), RFC 5952 compressed IPv6.
fn canonical_ip(value: &str) -> IamResult<String> {
    let bytes = match ip_bytes(value) {
        Some(bytes) if !value.contains('%') => bytes,
        _ => {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!("Invalid IP address {value}"),
            ));
        }
    };
    let mapped = bytes.len() == 16
        && bytes[..10].iter().all(|byte| *byte == 0)
        && bytes[10] == 0xff
        && bytes[11] == 0xff;
    Ok(ip_text(if mapped { &bytes[12..] } else { &bytes }))
}

/// Validates and canonicalizes requested names, at most 100 in total: lowercase DNS names and email addresses
/// (ASCII only), URIs in canonical form (SPIFFE IDs by the SPIFFE grammar), and IP addresses in canonical text.
pub fn subject_alt_names(input: &Value) -> IamResult<SubjectAltNames> {
    let list = |key: &str| -> IamResult<Vec<String>> {
        match input.get(key) {
            None => Ok(Vec::new()),
            Some(Value::Array(items)) if items.iter().all(Value::is_string) => Ok(items
                .iter()
                .map(|item| item.as_str().unwrap_or_default().to_owned())
                .collect()),
            Some(_) => Err(IamError::new(
                "INVALID_INPUT",
                format!("{key} must be a list of strings"),
            )),
        }
    };
    let unique = |values: Vec<String>| crate::js::unique(values);
    let dns_names = unique(
        list("dnsNames")?
            .iter()
            .map(|value| core_js::to_lower(value))
            .collect(),
    );
    for value in &dns_names {
        if utf16_len(value) > 253 || !DNS_NAME.is_match(value) {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!("Invalid DNS name {value}"),
            ));
        }
    }
    let emails = unique(
        list("emails")?
            .iter()
            .map(|value| core_js::to_lower(value))
            .collect(),
    );
    for value in &emails {
        if utf16_len(value) > 254 || !EMAIL_ADDRESS.is_match(value) {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!("Invalid email address {value}"),
            ));
        }
    }
    let uris = unique(
        list("uris")?
            .iter()
            .map(|value| canonical_uri(value))
            .collect::<IamResult<Vec<_>>>()?,
    );
    let ip_addresses = unique(
        list("ipAddresses")?
            .iter()
            .map(|value| canonical_ip(value))
            .collect::<IamResult<Vec<_>>>()?,
    );
    let names = SubjectAltNames {
        dns_names,
        uris,
        ip_addresses,
        emails,
        extra: Map::new(),
    };
    if names.total() > 100 {
        return Err(IamError::new(
            "INVALID_INPUT",
            "At most 100 subject alternative names",
        ));
    }
    Ok(names)
}

/// Dotted IPv4, or IPv6 in RFC 5952 form (lowercase, the longest run of two or more zero groups as `::`).
fn ip_text(bytes: &[u8]) -> String {
    if bytes.len() == 4 {
        return bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(".");
    }
    let groups: Vec<u16> = (0..8)
        .map(|index| ((bytes[index * 2] as u16) << 8) | bytes[index * 2 + 1] as u16)
        .collect();
    let (mut best_start, mut best_length) = (0usize, 0usize);
    let mut start = 0;
    while start < 8 {
        if groups[start] != 0 {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < 8 && groups[end] == 0 {
            end += 1;
        }
        if end - start > best_length {
            best_start = start;
            best_length = end - start;
        }
        start = end;
    }
    let text: Vec<String> = groups.iter().map(|group| format!("{group:x}")).collect();
    if best_length < 2 {
        return text.join(":");
    }
    format!(
        "{}::{}",
        text[..best_start].join(":"),
        text[best_start + best_length..].join(":")
    )
}

pub fn encode_general_names(names: &SubjectAltNames) -> Vec<u8> {
    let mut items = Vec::new();
    items.extend(
        names
            .emails
            .iter()
            .map(|value| tlv(0x81, &ascii_bytes(value))),
    );
    items.extend(
        names
            .dns_names
            .iter()
            .map(|value| tlv(0x82, &ascii_bytes(value))),
    );
    items.extend(
        names
            .uris
            .iter()
            .map(|value| tlv(0x86, &ascii_bytes(value))),
    );
    items.extend(
        names
            .ip_addresses
            .iter()
            .map(|value| tlv(0x87, &ip_bytes(value).unwrap_or_default())),
    );
    sequence(items)
}

/// `buffer.toString('ascii')`: each byte with its high bit cleared.
fn ascii_text(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| (byte & 0x7f) as char).collect()
}

fn decode_general_names(buffer: &[u8], node: &DerNode) -> IamResult<SubjectAltNames> {
    let mut names = SubjectAltNames::default();
    for child in children_of(buffer, node)? {
        let value = contents(buffer, &child);
        match child.tag {
            0x82 => names.dns_names.push(ascii_text(value)),
            0x86 => names.uris.push(ascii_text(value)),
            0x81 => names.emails.push(ascii_text(value)),
            0x87 if value.len() == 4 || value.len() == 16 => {
                names.ip_addresses.push(ip_text(value))
            }
            _ => {
                return Err(IamError::with_status(
                    "INVALID_CSR",
                    "The request names an unsupported kind of name",
                    400,
                ));
            }
        }
    }
    Ok(names)
}

// ---------------------------------------------------------------------------------------------------------------
// Extensions

pub fn extension(kind: &str, critical: bool, value: &[u8]) -> Vec<u8> {
    if critical {
        sequence([oid(kind), boolean_value(true), octet_string(value)])
    } else {
        sequence([oid(kind), octet_string(value)])
    }
}

/// RFC 5280 key identifier (method 1): SHA-1 of the subject public key bits.
pub fn key_identifier(spki: &[u8]) -> IamResult<Vec<u8>> {
    let root = read_root(spki)?;
    let parts = children_of(spki, &root)?;
    let bits = parts
        .get(1)
        .filter(|bits| bits.tag == 0x03)
        .ok_or_else(malformed)?;
    let bits = contents(spki, bits);
    Ok(Sha1::digest(bits.get(1..).unwrap_or_default()).to_vec())
}

// ---------------------------------------------------------------------------------------------------------------
// PKCS#10 certification requests

/// `CertificateRequestInput`: a private key, a subject, and the requested subject alternative names.
#[derive(Clone)]
pub struct CertificateRequestInput {
    /// ECDSA P-256/P-384, Ed25519 or RSA.
    pub private_key: PrivateKey,
    pub subject: Option<DistinguishedName>,
    pub dns_names: Option<Vec<String>>,
    pub uris: Option<Vec<String>>,
    pub ip_addresses: Option<Vec<String>>,
    pub emails: Option<Vec<String>>,
}

impl CertificateRequestInput {
    /// A request for a key with no subject and no names (set the members to add them).
    pub fn new(private_key: PrivateKey) -> Self {
        Self {
            private_key,
            subject: None,
            dns_names: None,
            uris: None,
            ip_addresses: None,
            emails: None,
        }
    }
}

/// Builds a PEM PKCS#10 certification request for `privateKey` with a subject and subject alternative names, signed
/// with the key (proof of possession). Clients call it to request certificates without OpenSSL.
pub fn create_certificate_request(input: &CertificateRequestInput) -> IamResult<String> {
    let key = &input.private_key;
    let algorithm = algorithm_for_key(key);
    let spki = key.spki()?;
    let mut requested = Map::new();
    for (name, value) in [
        ("dnsNames", &input.dns_names),
        ("uris", &input.uris),
        ("ipAddresses", &input.ip_addresses),
        ("emails", &input.emails),
    ] {
        if let Some(values) = value {
            requested.insert(name.into(), json!(values));
        }
    }
    let names = subject_alt_names(&Value::Object(requested))?;
    let has_names = names.total() > 0;
    let attributes = if has_names {
        set([sequence([
            oid(oids::EXTENSION_REQUEST),
            set([sequence([extension(
                oids::SUBJECT_ALT_NAME,
                false,
                &encode_general_names(&names),
            )])]),
        ])])
    } else {
        Vec::new()
    };
    let attributes_contents = if has_names {
        contents(&attributes, &read_root(&attributes)?).to_vec()
    } else {
        Vec::new()
    };
    let info = sequence([
        integer(0),
        encode_name(&input.subject.clone().unwrap_or_default()),
        spki,
        // attributes [0] IMPLICIT SET OF Attribute
        tlv(0xa0, &attributes_contents),
    ]);
    let signature = sign_with(key, &algorithm, &info)?;
    let request = sequence([
        info,
        algorithm_identifier(&algorithm),
        bit_string(&signature),
    ]);
    Ok(pem("CERTIFICATE REQUEST", &request))
}

/// `ParsedCertificateRequest`.
#[derive(Debug, Clone)]
pub struct ParsedCertificateRequest {
    /// The subject public key (SPKI DER).
    pub spki: Vec<u8>,
    pub public_key: PublicKey,
    /// `ecc-p256`, `ecc-p384`, `ed25519` or `rsa-{bits}`.
    pub key_type: String,
    pub common_name: Option<String>,
    pub names: SubjectAltNames,
}

fn name_value(buffer: &[u8], node: &DerNode) -> IamResult<Option<String>> {
    if ![0x0c, 0x13, 0x16, 0x14, 0x1e].contains(&node.tag) {
        return Ok(None);
    }
    let value = contents(buffer, node);
    if node.tag != 0x1e {
        return Ok(Some(String::from_utf8_lossy(value).into_owned()));
    }
    // BMPString: UTF-16BE, so an even length.
    if value.len() % 2 == 1 {
        return Err(malformed());
    }
    let units: Vec<u16> = value
        .chunks(2)
        .map(|pair| ((pair[0] as u16) << 8) | pair[1] as u16)
        .collect();
    Ok(Some(String::from_utf16_lossy(&units)))
}

/// Which key types each signature algorithm belongs to: a request's algorithm must match its key.
fn algorithm_fits(oid_value: &str, key_type: &str) -> bool {
    if oid_value == oids::ED25519 {
        return key_type == "ed25519";
    }
    if [oids::ECDSA_SHA256, oids::ECDSA_SHA384, oids::ECDSA_SHA512].contains(&oid_value) {
        return key_type.starts_with("ecc-");
    }
    key_type.starts_with("rsa-")
}

fn invalid_csr(message: &str) -> IamError {
    IamError::with_status("INVALID_CSR", message, 400)
}

/// Parses and verifies a PEM (or base64 DER) PKCS#10 request: the signature must verify with the request's own key
/// (proof of possession), and the key must be of an accepted kind. Returns the key, the subject common name and the
/// requested subject alternative names.
pub fn parse_certificate_request(value: Option<&Value>) -> IamResult<ParsedCertificateRequest> {
    let text = match value {
        Some(Value::String(text)) if utf16_len(text) <= 65536 => text,
        _ => return Err(invalid_csr("csr must be a PEM certificate request")),
    };
    static BEGIN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new("-----BEGIN (NEW )?CERTIFICATE REQUEST-----").expect("begin"));
    static END: LazyLock<Regex> =
        LazyLock::new(|| Regex::new("-----END (NEW )?CERTIFICATE REQUEST-----").expect("end"));
    static BODY: LazyLock<Regex> =
        LazyLock::new(|| Regex::new("^[A-Za-z0-9+/]+={0,2}$").expect("body"));
    let body = BEGIN.replace(text, "");
    let body = END.replace(&body, "");
    let body: String = body
        .chars()
        .filter(|c| !core_js::is_js_whitespace(*c))
        .collect();
    if !BODY.is_match(&body) {
        return Err(invalid_csr("csr must be a PEM certificate request"));
    }
    let der = node_base64(&body);
    let root = read_root(&der)?;
    if root.tag != 0x30 || root.end != der.len() {
        return Err(malformed());
    }
    let parts = children_of(&der, &root)?;
    let (Some(info), Some(algorithm), Some(signature)) =
        (parts.first(), parts.get(1), parts.get(2))
    else {
        return Err(malformed());
    };
    if info.tag != 0x30 || signature.tag != 0x03 {
        return Err(malformed());
    }
    let fields = children_of(&der, info)?;
    let (Some(version), Some(subject), Some(spki_node)) =
        (fields.first(), fields.get(1), fields.get(2))
    else {
        return Err(malformed());
    };
    if version.tag != 0x02 || subject.tag != 0x30 {
        return Err(malformed());
    }
    let attributes = fields.get(3);
    // PKCS#10 version 1 is encoded as 0.
    if contents(&der, version) != [0] {
        return Err(malformed());
    }
    let spki = whole(&der, spki_node).to_vec();
    let public_key = PublicKey::from_spki(&spki)
        .ok_or_else(|| invalid_csr("The request carries an unreadable public key"))?;
    let key_type = acceptable_public_key(&public_key)?;
    let algorithm_oid = children_of(&der, algorithm)?;
    let algorithm_oid = algorithm_oid
        .first()
        .filter(|node| node.tag == 0x06)
        .ok_or_else(malformed)?;
    let algorithm_value = decode_oid(contents(&der, algorithm_oid))?;
    let hash = match hash_for_oid(&algorithm_value) {
        Some(hash) if algorithm_fits(&algorithm_value, &key_type) => hash,
        _ => {
            return Err(invalid_csr(
                "The request is signed with an unsupported algorithm",
            ));
        }
    };
    let bits = contents(&der, signature);
    if bits.first() != Some(&0) {
        return Err(malformed());
    }
    if !public_key.verify(hash, whole(&der, info), &bits[1..]) {
        return Err(invalid_csr(
            "The request signature does not verify with its key",
        ));
    }
    let mut common_name: Option<String> = None;
    for rdn in children_of(&der, subject)? {
        for attribute in children_of(&der, &rdn)? {
            let items = children_of(&der, &attribute)?;
            if let (Some(kind), Some(item)) = (items.first(), items.get(1))
                && kind.tag == 0x06
                && decode_oid(contents(&der, kind))? == oids::COMMON_NAME
            {
                common_name = name_value(&der, item)?;
            }
        }
    }
    // The request's common name follows the same rules as one given explicitly: never truncated or cleaned up.
    if let Some(name) = &common_name
        && (core_js::trim(name).is_empty()
            || utf16_len(name) > 64
            || name.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}'))
    {
        return Err(invalid_csr("The request has an invalid common name"));
    }
    let mut names = SubjectAltNames::default();
    if let Some(attributes) = attributes.filter(|node| node.tag == 0xa0) {
        for attribute in children_of(&der, attributes)? {
            let items = children_of(&der, &attribute)?;
            let Some(kind) = items.first().filter(|node| node.tag == 0x06) else {
                continue;
            };
            if decode_oid(contents(&der, kind))? != oids::EXTENSION_REQUEST {
                continue;
            }
            let Some(values) = items.get(1) else {
                continue;
            };
            for extensions in children_of(&der, values)? {
                for item in children_of(&der, &extensions)? {
                    let parts = children_of(&der, &item)?;
                    let (Some(id), Some(value_node)) = (parts.first(), parts.last()) else {
                        continue;
                    };
                    if id.tag != 0x06 || value_node.tag != 0x04 {
                        continue;
                    }
                    if decode_oid(contents(&der, id))? != oids::SUBJECT_ALT_NAME {
                        continue;
                    }
                    let inner = contents(&der, value_node);
                    names = decode_general_names(inner, &read_root(inner)?)?;
                }
            }
        }
    }
    Ok(ParsedCertificateRequest {
        spki,
        public_key,
        key_type,
        common_name: common_name.filter(|name| !name.is_empty()),
        names: subject_alt_names(&names.to_value())?,
    })
}

// ---------------------------------------------------------------------------------------------------------------
// Certificates and CRLs

pub fn pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let lines: Vec<&str> = encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        lines.join("\n")
    )
}

/// A positive random serial number (about 123 random bits), as lowercase hex whose first digit is never `0`, so it
/// reads the same with or without leading-zero stripping (Node's `X509Certificate.serialNumber` strips them).
pub fn random_serial() -> String {
    let mut bytes: [u8; 16] = rand::random();
    bytes[0] = (bytes[0] & 0x7f) | 0x10;
    hex::encode(bytes)
}

/// `{ pathLength? }` of a CA certificate.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CaSpec {
    pub path_length: Option<f64>,
}

/// Name constraints: permitted DNS suffixes and URI hosts (`{ dnsNames?, uriHosts? }`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PermittedNames {
    #[serde(rename = "dnsNames", default, skip_serializing_if = "Option::is_none")]
    pub dns_names: Option<Vec<String>>,
    #[serde(rename = "uriHosts", default, skip_serializing_if = "Option::is_none")]
    pub uri_hosts: Option<Vec<String>>,
}

/// `CertificateSpec`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CertificateSpec {
    pub serial_number: String,
    /// DER of the issuer's subject name, byte for byte.
    pub issuer: Vec<u8>,
    pub subject: DistinguishedName,
    /// DER SubjectPublicKeyInfo of the certified key.
    pub spki: Vec<u8>,
    pub not_before: f64,
    pub not_after: f64,
    pub names: Option<SubjectAltNames>,
    /// A CA certificate (with an optional path length) or an end-entity certificate.
    pub ca: Option<CaSpec>,
    /// End-entity usages: `server`, `client` or `both`.
    pub usage: Option<String>,
    /// The issuing key's identifier (authority key identifier); omitted on self-signed roots.
    pub authority_key_id: Option<Vec<u8>>,
    pub crl_url: Option<String>,
    /// Name constraints for CA certificates: permitted DNS suffixes and URI hosts.
    pub permitted: Option<PermittedNames>,
}

/// `Buffer.from(value, 'hex')`: pairs of hex digits up to the first pair that is not one.
pub fn node_hex(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut out = Vec::new();
    for pair in bytes.chunks(2) {
        if pair.len() < 2 {
            break;
        }
        let digit = |byte: u8| (byte as char).to_digit(16);
        match (digit(pair[0]), digit(pair[1])) {
            (Some(high), Some(low)) => out.push((high * 16 + low) as u8),
            _ => break,
        }
    }
    out
}

/// `Buffer.from(value, 'base64')`: standard or URL-safe characters, anything else skipped, decoding ends at `=`.
pub fn node_base64(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut buffer, mut count) = (0u32, 0u32);
    for c in value.chars() {
        let sextet = match c {
            'A'..='Z' => c as u32 - 'A' as u32,
            'a'..='z' => c as u32 - 'a' as u32 + 26,
            '0'..='9' => c as u32 - '0' as u32 + 52,
            '+' | '-' => 62,
            '/' | '_' => 63,
            '=' => break,
            _ => continue,
        };
        buffer = (buffer << 6) | sextet;
        count += 1;
        if count == 4 {
            out.extend([(buffer >> 16) as u8, (buffer >> 8) as u8, buffer as u8]);
            buffer = 0;
            count = 0;
        }
    }
    match count {
        2 => out.push((buffer >> 4) as u8),
        3 => out.extend([(buffer >> 10) as u8, (buffer >> 2) as u8]),
        _ => {}
    }
    out
}

/// The TBSCertificate DER for a spec, signed by the caller with the issuer's key.
pub fn tbs_certificate(spec: &CertificateSpec, algorithm: &str) -> IamResult<Vec<u8>> {
    let subject_key_id = key_identifier(&spec.spki)?;
    let mut extensions: Vec<Vec<u8>> = Vec::new();
    if let Some(ca) = &spec.ca {
        let mut constraints = vec![boolean_value(true)];
        if let Some(path_length) = ca.path_length {
            constraints.push(integer(path_length as u64));
        }
        extensions.push(extension(
            oids::BASIC_CONSTRAINTS,
            true,
            &sequence(constraints),
        ));
        extensions.push(extension(oids::KEY_USAGE, true, &named_bits(&[0, 5, 6])));
        if let Some(permitted) = &spec.permitted {
            let dns_names = permitted.dns_names.clone().unwrap_or_default();
            let uri_hosts = permitted.uri_hosts.clone().unwrap_or_default();
            if !dns_names.is_empty() || !uri_hosts.is_empty() {
                let subtree = |tag: u8, value: &str| sequence([tlv(tag, &ascii_bytes(value))]);
                let mut subtrees: Vec<Vec<u8>> =
                    dns_names.iter().map(|value| subtree(0x82, value)).collect();
                // RFC 5280: a URI host constraint matches that host exactly, `.host` its subdomains; both, to mean
                // what the authority enforces at issuance (the host and everything below it).
                for value in &uri_hosts {
                    subtrees.push(subtree(0x86, value));
                    subtrees.push(subtree(0x86, &format!(".{value}")));
                }
                extensions.push(extension(
                    oids::NAME_CONSTRAINTS,
                    true,
                    &sequence([tlv(0xa0, &concat(subtrees))]),
                ));
            }
        }
    } else {
        let rsa = PublicKey::from_spki(&spec.spki)
            .ok_or_else(crate::js::internal_error)?
            .key_type()
            == "rsa";
        let mut usages = Vec::new();
        if spec.usage.as_deref() != Some("client") {
            usages.push(oid(oids::SERVER_AUTH));
        }
        if spec.usage.as_deref() != Some("server") {
            usages.push(oid(oids::CLIENT_AUTH));
        }
        extensions.push(extension(
            oids::BASIC_CONSTRAINTS,
            true,
            &sequence(Vec::<Vec<u8>>::new()),
        ));
        extensions.push(extension(
            oids::KEY_USAGE,
            true,
            &named_bits(if rsa { &[0, 2] } else { &[0] }),
        ));
        extensions.push(extension(oids::EXT_KEY_USAGE, false, &sequence(usages)));
    }
    extensions.push(extension(
        oids::SUBJECT_KEY_IDENTIFIER,
        false,
        &octet_string(&subject_key_id),
    ));
    if let Some(authority_key_id) = &spec.authority_key_id {
        extensions.push(extension(
            oids::AUTHORITY_KEY_IDENTIFIER,
            false,
            &sequence([tlv(0x80, authority_key_id)]),
        ));
    }
    let subject = &spec.subject;
    let empty_subject = [
        &subject.common_name,
        &subject.organization,
        &subject.organizational_unit,
        &subject.locality,
        &subject.state,
        &subject.country,
    ]
    .iter()
    .all(|part| present(part).is_none());
    if let Some(names) = spec.names.as_ref().filter(|names| names.total() > 0) {
        // An empty subject makes the alternative names critical (RFC 5280 4.2.1.6), as in SPIFFE SVIDs.
        extensions.push(extension(
            oids::SUBJECT_ALT_NAME,
            empty_subject,
            &encode_general_names(names),
        ));
    }
    if let Some(crl_url) = spec.crl_url.as_deref().filter(|url| !url.is_empty()) {
        extensions.push(extension(
            oids::CRL_DISTRIBUTION_POINTS,
            false,
            &sequence([sequence([explicit(
                0,
                &tlv(0xa0, &tlv(0x86, &ascii_bytes(crl_url))),
            )])]),
        ));
    }
    Ok(sequence([
        explicit(0, &integer(2)),
        integer_bytes(&node_hex(&spec.serial_number)),
        algorithm_identifier(algorithm),
        spec.issuer.clone(),
        sequence([time(spec.not_before), time(spec.not_after)]),
        encode_name(&spec.subject),
        spec.spki.clone(),
        explicit(3, &sequence(extensions)),
    ]))
}

/// Wraps a signed TBS structure (certificate or CRL).
pub fn signed_structure(tbs: &[u8], algorithm: &str, signature: &[u8]) -> Vec<u8> {
    sequence([
        tbs.to_vec(),
        algorithm_identifier(algorithm),
        bit_string(signature),
    ])
}

/// `'unspecified' | 'keyCompromise' | 'caCompromise' | 'affiliationChanged' | 'superseded' | 'cessationOfOperation'
/// | 'certificateHold' | 'privilegeWithdrawn'`.
pub type RevocationReason = String;

pub static REVOCATION_REASONS: std::sync::LazyLock<Value> = std::sync::LazyLock::new(
    || json!({"unspecified":0,"keyCompromise":1,"caCompromise":2,"affiliationChanged":3,"superseded":4,"cessationOfOperation":5,"certificateHold":6,"privilegeWithdrawn":9}),
);

/// `revocationReasons[reason]`.
pub fn revocation_reason_code(reason: &str) -> Option<u8> {
    REVOCATION_REASONS
        .get(reason)
        .and_then(Value::as_u64)
        .map(|code| code as u8)
}

/// A revoked certificate on a CRL.
#[derive(Debug, Clone, PartialEq)]
pub struct RevokedEntry {
    pub serial_number: String,
    pub revoked_at: f64,
    pub reason: Option<RevocationReason>,
}

/// The spec of a TBSCertList.
#[derive(Debug, Clone, PartialEq)]
pub struct CertListSpec {
    pub issuer: Vec<u8>,
    pub this_update: f64,
    pub next_update: f64,
    pub crl_number: f64,
    pub authority_key_id: Vec<u8>,
    pub revoked: Vec<RevokedEntry>,
}

/// A TBSCertList (RFC 5280 5.1) with a CRL number and the issuer's key identifier.
pub fn tbs_cert_list(spec: &CertListSpec, algorithm: &str) -> Vec<u8> {
    let entries: Vec<Vec<u8>> = spec
        .revoked
        .iter()
        .map(|entry| {
            let mut parts = vec![
                integer_bytes(&node_hex(&entry.serial_number)),
                time(entry.revoked_at),
            ];
            if let Some(reason) = entry
                .reason
                .as_deref()
                .filter(|reason| !reason.is_empty() && *reason != "unspecified")
            {
                parts.push(sequence([extension(
                    oids::CRL_REASON,
                    false,
                    &tlv(0x0a, &[revocation_reason_code(reason).unwrap_or(0)]),
                )]));
            }
            sequence(parts)
        })
        .collect();
    let mut parts = vec![
        integer(1),
        algorithm_identifier(algorithm),
        spec.issuer.clone(),
        time(spec.this_update),
        time(spec.next_update),
    ];
    if !entries.is_empty() {
        parts.push(sequence(entries));
    }
    parts.push(explicit(
        0,
        &sequence([
            extension(
                oids::AUTHORITY_KEY_IDENTIFIER,
                false,
                &sequence([tlv(0x80, &spec.authority_key_id)]),
            ),
            extension(oids::CRL_NUMBER, false, &integer(spec.crl_number as u64)),
        ]),
    ));
    sequence(parts)
}

pub fn sha256_fingerprint(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

/// The DER bytes of a PEM certificate.
pub fn certificate_der(pem_text: &str) -> Vec<u8> {
    let body = pem_text
        .replacen("-----BEGIN CERTIFICATE-----", "", 1)
        .replacen("-----END CERTIFICATE-----", "", 1);
    let body: String = body
        .chars()
        .filter(|c| !core_js::is_js_whitespace(*c))
        .collect();
    node_base64(&body)
}

// ---------------------------------------------------------------------------------------------------------------
// Reading certificates (Node's `X509Certificate`, for what pki.ts uses of it)

/// A certificate as Node's `new X509Certificate(pem)` reads it: the members pki.ts uses, formatted as Node formats
/// them.
#[derive(Debug, Clone)]
pub struct X509Certificate {
    /// The DER bytes (`raw`).
    pub raw: Vec<u8>,
    tbs: (usize, usize),
    inner_algorithm: Vec<u8>,
    outer_algorithm: Vec<u8>,
    signature_oid: String,
    signature: Vec<u8>,
    serial: Vec<u8>,
    issuer: Vec<u8>,
    subject: Vec<u8>,
    spki: Vec<u8>,
    not_before: f64,
    not_after: f64,
    subject_key_id: Option<Vec<u8>>,
    authority_key_id: Option<Vec<u8>>,
    /// The key usage bits (the BIT STRING contents after the unused-bits byte).
    key_usage: Option<Vec<u8>>,
    basic_constraints_ca: Option<bool>,
    alt_names: Option<Vec<(u8, Vec<u8>)>>,
}

/// The time of a UTCTime or GeneralizedTime (`Date.parse(validFrom)`), whole seconds.
fn parse_time(node: &DerNode, buffer: &[u8]) -> Option<f64> {
    let text = std::str::from_utf8(contents(buffer, node)).ok()?;
    let digits = text.strip_suffix('Z')?;
    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let number = |range: std::ops::Range<usize>| digits.get(range)?.parse::<i64>().ok();
    let (year, rest) = match (node.tag, digits.len()) {
        (0x17, 12) => {
            let year = number(0..2)?;
            (if year < 50 { 2000 + year } else { 1900 + year }, 2)
        }
        (0x18, 14) => (number(0..4)?, 4),
        _ => return None,
    };
    let (month, day) = (number(rest..rest + 2)?, number(rest + 2..rest + 4)?);
    let (hour, minute, second) = (
        number(rest + 4..rest + 6)?,
        number(rest + 6..rest + 8)?,
        number(rest + 8..rest + 10)?,
    );
    if !(1..=12).contains(&month)
        || day < 1
        || day > core_js::days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let days = core_js::days_from_civil(year, month, day);
    Some(((days * 86_400 + hour * 3600 + minute * 60 + second) * 1000) as f64)
}

/// The short name OpenSSL prints for an attribute type (`XN_FLAG_FN_SN`).
fn short_name(kind: &str) -> String {
    match kind {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "street",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "title",
        "2.5.4.42" => "GN",
        "2.5.4.43" => "initials",
        "2.5.4.46" => "dnQualifier",
        "2.5.4.65" => "pseudonym",
        "1.2.840.113549.1.9.1" => "emailAddress",
        "0.9.2342.19200300.100.1.1" => "UID",
        "0.9.2342.19200300.100.1.25" => "DC",
        other => return other.to_owned(),
    }
    .to_owned()
}

/// An attribute value as OpenSSL prints it with `ASN1_STRFLGS_ESC_2253 | ASN1_STRFLGS_ESC_CTRL |
/// ASN1_STRFLGS_UTF8_CONVERT`.
fn escape_name_value(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    let mut out = String::new();
    for (index, c) in chars.iter().enumerate() {
        let first = index == 0;
        let last = index + 1 == chars.len();
        if (*c as u32) < 0x20 || *c == '\u{7f}' {
            out.push_str(&format!("\\{:02X}", *c as u32));
        } else if matches!(c, ',' | '+' | '"' | '\\' | '<' | '>' | ';')
            || (first && (*c == '#' || *c == ' '))
            || (last && *c == ' ')
        {
            out.push('\\');
            out.push(*c);
        } else {
            out.push(*c);
        }
    }
    out
}

/// Node's `PrintAltName`: a name with characters that would make the list ambiguous is quoted as a JSON string.
fn alt_name_text(value: &[u8]) -> String {
    let safe = value
        .iter()
        .all(|byte| !matches!(byte, b'"' | b'\\' | b',' | b'\'') && (b' '..=b'~').contains(byte));
    if safe {
        return value.iter().map(|byte| *byte as char).collect();
    }
    let mut out = String::from("\"");
    for byte in value {
        match byte {
            b'"' | b'\\' => {
                out.push('\\');
                out.push(*byte as char);
            }
            b' '..=b'~' => out.push(*byte as char),
            _ => out.push_str(&format!("\\u{:04x}", byte)),
        }
    }
    out.push('"');
    out
}

/// The key family a signature algorithm OID signs with, and its hash.
fn signature_scheme(oid_value: &str) -> Option<(&'static str, Option<Hash>)> {
    let hash = hash_for_oid(oid_value)?;
    Some(match oid_value {
        oids::ED25519 => ("ed25519", hash),
        oids::ECDSA_SHA256 | oids::ECDSA_SHA384 | oids::ECDSA_SHA512 => ("ec", hash),
        _ => ("rsa", hash),
    })
}

impl X509Certificate {
    /// `new X509Certificate(pem)`: None when Node could not read it.
    pub fn from_pem(pem_text: &str) -> Option<X509Certificate> {
        let start = pem_text.find("-----BEGIN CERTIFICATE-----")?;
        let rest = &pem_text[start + "-----BEGIN CERTIFICATE-----".len()..];
        let end = rest.find("-----END CERTIFICATE-----")?;
        let body: String = rest[..end]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let der = STANDARD.decode(body).ok()?;
        X509Certificate::from_der(&der)
    }

    /// Reads a DER certificate.
    pub fn from_der(der: &[u8]) -> Option<X509Certificate> {
        let root = read_root(der).ok()?;
        if root.tag != 0x30 || root.end != der.len() {
            return None;
        }
        let parts = children_of(der, &root).ok()?;
        let [tbs, outer_algorithm, signature] = parts.as_slice() else {
            return None;
        };
        if tbs.tag != 0x30 || outer_algorithm.tag != 0x30 || signature.tag != 0x03 {
            return None;
        }
        let signature_bits = contents(der, signature);
        if signature_bits.first() != Some(&0) {
            return None;
        }
        let algorithm_parts = children_of(der, outer_algorithm).ok()?;
        let signature_oid = decode_oid(contents(
            der,
            algorithm_parts.first().filter(|node| node.tag == 0x06)?,
        ))
        .ok()?;
        let fields = children_of(der, tbs).ok()?;
        let mut index = 0;
        if fields.first()?.tag == 0xa0 {
            index = 1;
        }
        let serial = fields.get(index).filter(|node| node.tag == 0x02)?;
        let inner_algorithm = fields.get(index + 1).filter(|node| node.tag == 0x30)?;
        let issuer = fields.get(index + 2).filter(|node| node.tag == 0x30)?;
        let validity = fields.get(index + 3).filter(|node| node.tag == 0x30)?;
        let subject = fields.get(index + 4).filter(|node| node.tag == 0x30)?;
        let spki = fields.get(index + 5).filter(|node| node.tag == 0x30)?;
        let times = children_of(der, validity).ok()?;
        let [not_before, not_after] = times.as_slice() else {
            return None;
        };
        let mut certificate = X509Certificate {
            raw: der.to_vec(),
            tbs: (tbs.start, tbs.end),
            inner_algorithm: whole(der, inner_algorithm).to_vec(),
            outer_algorithm: whole(der, outer_algorithm).to_vec(),
            signature_oid,
            signature: signature_bits[1..].to_vec(),
            serial: contents(der, serial).to_vec(),
            issuer: whole(der, issuer).to_vec(),
            subject: whole(der, subject).to_vec(),
            spki: whole(der, spki).to_vec(),
            not_before: parse_time(not_before, der)?,
            not_after: parse_time(not_after, der)?,
            subject_key_id: None,
            authority_key_id: None,
            key_usage: None,
            basic_constraints_ca: None,
            alt_names: None,
        };
        // The names must read as names.
        children_of(der, issuer).ok()?;
        children_of(der, subject).ok()?;
        for field in &fields[index + 6..] {
            if field.tag != 0xa3 {
                continue;
            }
            let wrapper = children_of(der, field).ok()?;
            let extensions = wrapper.first().filter(|node| node.tag == 0x30)?;
            for item in children_of(der, extensions).ok()? {
                let parts = children_of(der, &item).ok()?;
                let kind =
                    decode_oid(contents(der, parts.first().filter(|n| n.tag == 0x06)?)).ok()?;
                let value = parts.last().filter(|node| node.tag == 0x04)?;
                let value = contents(der, value);
                certificate.read_extension(&kind, value)?;
            }
        }
        Some(certificate)
    }

    fn read_extension(&mut self, kind: &str, value: &[u8]) -> Option<()> {
        let root = read_root(value).ok()?;
        match kind {
            oids::SUBJECT_KEY_IDENTIFIER if root.tag == 0x04 => {
                self.subject_key_id = Some(contents(value, &root).to_vec());
            }
            oids::AUTHORITY_KEY_IDENTIFIER if root.tag == 0x30 => {
                for child in children_of(value, &root).ok()? {
                    if child.tag == 0x80 {
                        self.authority_key_id = Some(contents(value, &child).to_vec());
                    }
                }
            }
            oids::KEY_USAGE if root.tag == 0x03 => {
                self.key_usage = Some(contents(value, &root).get(1..)?.to_vec());
            }
            oids::BASIC_CONSTRAINTS if root.tag == 0x30 => {
                let children = children_of(value, &root).ok()?;
                let ca = children
                    .first()
                    .filter(|node| node.tag == 0x01)
                    .is_some_and(|node| contents(value, node).first().is_some_and(|b| *b != 0));
                self.basic_constraints_ca = Some(ca);
            }
            oids::SUBJECT_ALT_NAME if root.tag == 0x30 => {
                self.alt_names = Some(
                    children_of(value, &root)
                        .ok()?
                        .iter()
                        .map(|child| (child.tag, contents(value, child).to_vec()))
                        .collect(),
                );
            }
            _ => {}
        }
        Some(())
    }

    /// `serialNumber`: uppercase hex of the serial (OpenSSL's `BN_bn2hex`).
    pub fn serial_number(&self) -> String {
        let negative = self.serial.first().is_some_and(|byte| byte & 0x80 != 0);
        let magnitude = if negative {
            // Two's complement magnitude.
            let mut bytes: Vec<u8> = self.serial.iter().map(|byte| !byte).collect();
            for byte in bytes.iter_mut().rev() {
                let (sum, carry) = byte.overflowing_add(1);
                *byte = sum;
                if !carry {
                    break;
                }
            }
            strip_zeros(&bytes)
        } else {
            strip_zeros(&self.serial)
        };
        let text = if magnitude.is_empty() {
            "0".to_owned()
        } else {
            hex::encode_upper(magnitude)
        };
        if negative { format!("-{text}") } else { text }
    }

    /// `Date.parse(validFrom)`.
    pub fn valid_from(&self) -> f64 {
        self.not_before
    }

    /// `Date.parse(validTo)`.
    pub fn valid_to(&self) -> f64 {
        self.not_after
    }

    /// The DER SubjectPublicKeyInfo (`publicKey`).
    pub fn public_key(&self) -> &[u8] {
        &self.spki
    }

    /// `subject`: one `SN=value` line per attribute; None for an empty subject (Node's `undefined`).
    pub fn subject(&self) -> Option<String> {
        let der = &self.subject;
        let root = read_root(der).ok()?;
        let mut lines = Vec::new();
        for rdn in children_of(der, &root).ok()? {
            let mut values = Vec::new();
            for attribute in children_of(der, &rdn).ok()? {
                let items = children_of(der, &attribute).ok()?;
                let (Some(kind), Some(item)) = (items.first(), items.get(1)) else {
                    continue;
                };
                let kind = decode_oid(contents(der, kind)).ok()?;
                let text = name_value(der, item)
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| String::from_utf8_lossy(contents(der, item)).into_owned());
                values.push(format!(
                    "{}={}",
                    short_name(&kind),
                    escape_name_value(&text)
                ));
            }
            if !values.is_empty() {
                lines.push(values.join(" + "));
            }
        }
        (!lines.is_empty()).then(|| lines.join("\n"))
    }

    /// `subjectAltName`: `DNS:…, URI:…, IP Address:…, email:…`, in certificate order; None without the extension.
    pub fn subject_alt_name(&self) -> Option<String> {
        let names = self.alt_names.as_ref()?;
        Some(
            names
                .iter()
                .map(|(tag, value)| match tag {
                    0x82 => format!("DNS:{}", alt_name_text(value)),
                    0x86 => format!("URI:{}", alt_name_text(value)),
                    0x81 => format!("email:{}", alt_name_text(value)),
                    0x87 if value.len() == 4 => format!(
                        "IP Address:{}.{}.{}.{}",
                        value[0], value[1], value[2], value[3]
                    ),
                    0x87 if value.len() == 16 => format!(
                        "IP Address:{}",
                        (0..8)
                            .map(|index| format!(
                                "{:X}",
                                ((value[index * 2] as u16) << 8) | value[index * 2 + 1] as u16
                            ))
                            .collect::<Vec<_>>()
                            .join(":")
                    ),
                    0x87 => format!("IP Address:<invalid length={}>", value.len()),
                    0xa0 => "othername:<unsupported>".to_owned(),
                    0xa3 => "X400Name:<unsupported>".to_owned(),
                    0xa4 => "DirName:<unsupported>".to_owned(),
                    0xa5 => "EdiPartyName:<unsupported>".to_owned(),
                    0x88 => "Registered ID:<unsupported>".to_owned(),
                    _ => "<unsupported>".to_owned(),
                })
                .collect::<Vec<_>>()
                .join(", "),
        )
    }

    /// `ca`: a CA certificate by its basic constraints (and key usage, when present).
    pub fn ca(&self) -> bool {
        if let Some(usage) = &self.key_usage
            && usage.first().is_none_or(|byte| byte & 0x04 == 0)
        {
            return false;
        }
        self.basic_constraints_ca == Some(true)
    }

    /// `checkIssued(issuer)`: names, key identifiers, the signature algorithm's key type, and the issuer's key usage
    /// (OpenSSL's `X509_check_issued`).
    pub fn check_issued(&self, issuer: &X509Certificate) -> bool {
        if issuer.subject != self.issuer {
            return false;
        }
        if let (Some(authority), Some(subject)) = (&self.authority_key_id, &issuer.subject_key_id)
            && authority != subject
        {
            return false;
        }
        let Some((family, _)) = signature_scheme(&self.signature_oid) else {
            return false;
        };
        match PublicKey::from_spki(&issuer.spki) {
            Some(key) if key.key_type() == family => {}
            _ => return false,
        }
        if let Some(usage) = &issuer.key_usage
            && usage.first().is_none_or(|byte| byte & 0x04 == 0)
        {
            return false;
        }
        true
    }

    /// `verify(publicKey)`: the signature over the TBS with the given SubjectPublicKeyInfo.
    pub fn verify(&self, spki: &[u8]) -> bool {
        if self.inner_algorithm != self.outer_algorithm {
            return false;
        }
        let Some((family, hash)) = signature_scheme(&self.signature_oid) else {
            return false;
        };
        let Some(key) = PublicKey::from_spki(spki) else {
            return false;
        };
        if key.key_type() != family {
            return false;
        }
        key.verify(hash, &self.raw[self.tbs.0..self.tbs.1], &self.signature)
    }
}
