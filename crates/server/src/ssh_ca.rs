//! Port of `packages/server/src/ssh-ca.ts`.
//!
//! OpenSSH certificate authority primitives: the SSH wire encoding (RFC 4251), public key parsing, certificates as
//! specified in OpenSSH's PROTOCOL.certkeys, and key revocation lists (PROTOCOL.krl). Authorities are Ed25519 keys;
//! the keys they certify may be Ed25519, ECDSA (P-256/384/521), RSA (2048 bits or more), or FIDO security keys
//! (`sk-*`). Nothing here touches storage; `api/ssh.rs` seals authority keys and records what was issued.

use std::sync::LazyLock;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use better_iam_auth::crypto::random_bytes;
use better_iam_auth::util::node_base64_decode;
use better_iam_core::{IamError, IamResult, js as core_js};
use ed25519_dalek::{Signer, SigningKey, Verifier};
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::js::internal_error;

/// Public key algorithms accepted in certificates, with their certificate type names (`sshKeyTypes`).
pub const SSH_KEY_TYPES: [(&str, &str); 7] = [
    ("ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com"),
    (
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    ),
    (
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp384-cert-v01@openssh.com",
    ),
    (
        "ecdsa-sha2-nistp521",
        "ecdsa-sha2-nistp521-cert-v01@openssh.com",
    ),
    ("ssh-rsa", "ssh-rsa-cert-v01@openssh.com"),
    (
        "sk-ssh-ed25519@openssh.com",
        "sk-ssh-ed25519-cert-v01@openssh.com",
    ),
    (
        "sk-ecdsa-sha2-nistp256@openssh.com",
        "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
    ),
];

/// The certificate type name of a key type (`sshKeyTypes[type]`).
pub fn ssh_certificate_type(key_type: &str) -> Option<&'static str> {
    SSH_KEY_TYPES
        .iter()
        .find(|(name, _)| *name == key_type)
        .map(|(_, certificate)| *certificate)
}

pub const SSH_CERT_HOST: f64 = 2.0;

/// Certificate kinds (PROTOCOL.certkeys `type`).
pub const SSH_CERT_USER: f64 = 1.0;

/// Extensions a user certificate may carry; `permit-pty` and `permit-user-rc` are granted to every login.
pub const SSH_EXTENSIONS: [&str; 6] = [
    "permit-X11-forwarding",
    "permit-agent-forwarding",
    "permit-port-forwarding",
    "permit-pty",
    "permit-user-rc",
    "no-touch-required",
];

/// The curve of an ECDSA key type: its name in the key data, and its coordinate size.
fn curve_of(key_type: &str) -> Option<(&'static str, usize)> {
    match key_type {
        "ecdsa-sha2-nistp256" | "sk-ecdsa-sha2-nistp256@openssh.com" => Some(("nistp256", 32)),
        "ecdsa-sha2-nistp384" => Some(("nistp384", 48)),
        "ecdsa-sha2-nistp521" => Some(("nistp521", 66)),
        _ => None,
    }
}

const DEFAULT_INVALID_KEY: &str = "Enter an OpenSSH public key such as \"ssh-ed25519 AAAA...\"";

fn invalid_key(message: &str) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

/// `value.slice(0, max)` in UTF-16 code units (a cut surrogate pair is dropped whole).
pub(crate) fn slice_utf16(value: &str, max: usize) -> String {
    let mut out = String::new();
    let mut units = 0;
    for c in value.chars() {
        units += c.len_utf16();
        if units > max {
            break;
        }
        out.push(c);
    }
    out
}

/// `text.trim().split(/\s+/)` (JavaScript whitespace).
fn split_whitespace(text: &str) -> Vec<&str> {
    core_js::trim(text)
        .split(core_js::is_js_whitespace)
        .filter(|part| !part.is_empty())
        .collect()
}

/// Builds SSH wire-format data: bytes, uint32/uint64 big-endian, length-prefixed strings.
#[derive(Debug, Clone, Default)]
pub struct SshWriter {
    parts: Vec<u8>,
}

impl SshWriter {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn byte(mut self, value: u8) -> Self {
        self.parts.push(value);
        self
    }
    pub fn u32(mut self, value: u32) -> Self {
        self.parts.extend_from_slice(&value.to_be_bytes());
        self
    }
    pub fn u64(mut self, value: u64) -> Self {
        self.parts.extend_from_slice(&value.to_be_bytes());
        self
    }
    pub fn string(self, value: impl AsRef<[u8]>) -> Self {
        let data = value.as_ref();
        let mut writer = self.u32(data.len() as u32);
        writer.parts.extend_from_slice(data);
        writer
    }
    pub fn raw(mut self, value: impl AsRef<[u8]>) -> Self {
        self.parts.extend_from_slice(value.as_ref());
        self
    }
    pub fn to_buffer(&self) -> Vec<u8> {
        self.parts.clone()
    }
    pub fn into_buffer(self) -> Vec<u8> {
        self.parts
    }
}

/// Reads SSH wire-format data; every read is bounds-checked and a short buffer is an invalid key.
#[derive(Debug, Clone)]
pub struct SshReader<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> SshReader<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, offset: 0 }
    }
    fn take(&mut self, length: usize) -> IamResult<&'a [u8]> {
        if self.offset + length > self.buffer.len() {
            return Err(invalid_key("Truncated data"));
        }
        let slice = &self.buffer[self.offset..self.offset + length];
        self.offset += length;
        Ok(slice)
    }
    pub fn byte(&mut self) -> IamResult<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u32(&mut self) -> IamResult<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
    pub fn u64(&mut self) -> IamResult<u64> {
        let bytes = self.take(8)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(array))
    }
    pub fn string(&mut self) -> IamResult<&'a [u8]> {
        let length = self.u32()? as usize;
        self.take(length)
    }
    pub fn text(&mut self) -> IamResult<String> {
        Ok(String::from_utf8_lossy(self.string()?).into_owned())
    }
    pub fn position(&self) -> usize {
        self.offset
    }
    pub fn done(&self) -> bool {
        self.offset == self.buffer.len()
    }
}

/// A parsed OpenSSH public key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SshPublicKey {
    #[serde(rename = "type")]
    pub r#type: String,
    /// The full key blob (type string included), as base64 in an `authorized_keys` line.
    #[serde(rename = "blob")]
    pub blob: Vec<u8>,
    /// The blob after its type string: what a certificate embeds after the nonce.
    #[serde(rename = "fields")]
    pub fields: Vec<u8>,
    /// `SHA256:...`, as `ssh-keygen -l` prints it.
    #[serde(rename = "fingerprint")]
    pub fingerprint: String,
    /// Hardware security key (FIDO) types.
    #[serde(rename = "securityKey")]
    pub security_key: bool,
    /// RSA modulus size.
    #[serde(rename = "bits", default, skip_serializing_if = "Option::is_none")]
    pub bits: Option<f64>,
    #[serde(rename = "comment", default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `SHA256:` plus the unpadded base64 SHA-256 of a key blob.
pub fn ssh_fingerprint(blob: &[u8]) -> String {
    let digest = STANDARD.encode(Sha256::digest(blob));
    format!("SHA256:{}", digest.trim_end_matches('='))
}

/// An `authorized_keys`-style line for a key blob.
pub fn ssh_key_line(blob: &[u8], comment: Option<&str>) -> IamResult<String> {
    let key_type = SshReader::new(blob).text()?;
    Ok(format!(
        "{key_type} {}{}",
        STANDARD.encode(blob),
        match comment {
            Some(comment) if !comment.is_empty() => format!(" {comment}"),
            _ => String::new(),
        }
    ))
}

fn mpint_bits(value: &[u8]) -> u32 {
    let mut start = 0;
    while start < value.len() && value[start] == 0 {
        start += 1;
    }
    if start == value.len() {
        return 0;
    }
    ((value.len() - start - 1) * 8) as u32 + (32 - u32::from(value[start]).leading_zeros())
}

fn check_ec_point(key_type: &str, curve_name: &str, point: &[u8]) -> IamResult<()> {
    let Some((name, size)) = curve_of(key_type) else {
        return Err(internal_error());
    };
    if curve_name != name {
        return Err(invalid_key("The ECDSA curve does not match the key type"));
    }
    if point.len() != 1 + 2 * size || point[0] != 4 {
        return Err(invalid_key("ECDSA keys must be uncompressed points"));
    }
    let on_curve = match size {
        32 => p256::PublicKey::from_sec1_bytes(point).is_ok(),
        48 => p384::PublicKey::from_sec1_bytes(point).is_ok(),
        _ => p521::PublicKey::from_sec1_bytes(point).is_ok(),
    };
    if !on_curve {
        return Err(invalid_key("The ECDSA point is not on its curve"));
    }
    Ok(())
}

static BASE64_DATA: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9+/]+={0,2}$").expect("regex"));

/// Parses and validates one public key line (`type base64 [comment]`). Certificates, DSA keys, RSA keys under 2048
/// bits, malformed points and trailing data are refused. `min_rsa_bits` is `options.minRsaBits` (default 2048).
pub fn parse_ssh_public_key(
    line: Option<&Value>,
    min_rsa_bits: Option<f64>,
) -> IamResult<SshPublicKey> {
    let Some(Value::String(line)) = line else {
        return Err(invalid_key(DEFAULT_INVALID_KEY));
    };
    if core_js::utf16_len(line) > 16384 {
        return Err(invalid_key(DEFAULT_INVALID_KEY));
    }
    let parts = split_whitespace(line);
    let (Some(type_name), Some(data)) = (parts.first().copied(), parts.get(1).copied()) else {
        return Err(invalid_key(DEFAULT_INVALID_KEY));
    };
    let rest = &parts[2..];
    if ssh_certificate_type(type_name).is_none() {
        if type_name.contains("-cert-v01@") {
            return Err(invalid_key("Send the public key, not a certificate"));
        }
        return Err(invalid_key(&format!(
            "Unsupported key type {}",
            slice_utf16(type_name, 64)
        )));
    }
    let key_type = type_name;
    if !BASE64_DATA.is_match(data) {
        return Err(invalid_key(DEFAULT_INVALID_KEY));
    }
    let blob = node_base64_decode(data);
    let mut reader = SshReader::new(&blob);
    if reader.text()? != key_type {
        return Err(invalid_key("The key data does not match its type"));
    }
    let fields_start = 4 + key_type.len();
    let mut bits: Option<u32> = None;
    if key_type == "ssh-ed25519" || key_type == "sk-ssh-ed25519@openssh.com" {
        if reader.string()?.len() != 32 {
            return Err(invalid_key("Ed25519 keys are 32 bytes"));
        }
    } else if key_type == "ssh-rsa" {
        let e = reader.string()?;
        let n = reader.string()?;
        // Canonical mpints only: a padded encoding would fingerprint differently from the key sshd logs.
        for part in [e, n] {
            if part.is_empty()
                || part[0] & 0x80 != 0
                || (part[0] == 0 && (part.len() == 1 || part[1] & 0x80 == 0))
            {
                return Err(invalid_key("The RSA key is not canonically encoded"));
            }
        }
        let size = mpint_bits(n);
        bits = Some(size);
        let minimum = min_rsa_bits.unwrap_or(2048.0);
        if f64::from(size) < minimum {
            return Err(invalid_key(&format!(
                "RSA keys must have at least {} bits",
                core_js::number_to_string(minimum)
            )));
        }
        if size > 16384 {
            return Err(invalid_key("RSA keys may have at most 16384 bits"));
        }
        // `createPublicKey({ kty: 'RSA', n, e })` accepts any modulus and exponent that decode, as these do.
    } else {
        let curve_name = reader.text()?;
        let point = reader.string()?;
        check_ec_point(key_type, &curve_name, point)?;
    }
    let security_key = key_type.starts_with("sk-");
    if security_key {
        let application = reader.text()?;
        if !application.starts_with("ssh:") {
            return Err(invalid_key("Security keys need an ssh: application"));
        }
    }
    if !reader.done() {
        return Err(invalid_key("Unexpected data after the key"));
    }
    let comment = slice_utf16(&rest.join(" "), 256);
    Ok(SshPublicKey {
        r#type: key_type.to_owned(),
        fields: blob[fields_start..].to_vec(),
        fingerprint: ssh_fingerprint(&blob),
        blob,
        security_key,
        bits: bits.map(f64::from),
        comment: (!comment.is_empty()).then_some(comment),
        extra: Map::new(),
    })
}

/// An Ed25519 certificate authority key: its public blob and the private key that signs.
#[derive(Debug, Clone, PartialEq)]
pub struct SshSigningKey {
    pub public_blob: Vec<u8>,
    pub private_key: SigningKey,
}

/// A new authority key: its public blob and the private key as base64 PKCS#8 DER (the caller seals it).
#[derive(Debug, Clone, PartialEq)]
pub struct GeneratedSshAuthorityKey {
    pub public_blob: Vec<u8>,
    pub private_pkcs8: String,
}

/// The PKCS#8 (RFC 8410) prefix of an Ed25519 private key: what Node exports before the 32-byte seed.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// A new Ed25519 authority key, with the private key as base64 PKCS#8 DER (the caller seals it).
pub fn generate_ssh_authority_key() -> GeneratedSshAuthorityKey {
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&random_bytes(32));
    let key = SigningKey::from_bytes(&seed);
    let raw = key.verifying_key().to_bytes();
    let mut der = ED25519_PKCS8_PREFIX.to_vec();
    der.extend_from_slice(&seed);
    GeneratedSshAuthorityKey {
        public_blob: SshWriter::new()
            .string("ssh-ed25519")
            .string(raw)
            .into_buffer(),
        private_pkcs8: STANDARD.encode(der),
    }
}

/// One DER element: its tag, its content, and what follows it.
fn der_element(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *data.first()?;
    let first = *data.get(1)? as usize;
    let (length, header) = if first < 0x80 {
        (first, 2)
    } else {
        let count = first & 0x7f;
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for index in 0..count {
            length = (length << 8) | *data.get(2 + index)? as usize;
        }
        (length, 2 + count)
    };
    let end = header.checked_add(length)?;
    if end > data.len() {
        return None;
    }
    Some((tag, &data[header..end], &data[end..]))
}

/// The seed of an Ed25519 PKCS#8 private key (`OneAsymmetricKey`, version 0 or 1, optional attributes and public
/// key), as `createPrivateKey({ format: 'der', type: 'pkcs8' })` reads it.
fn ed25519_seed(der: &[u8]) -> Option<[u8; 32]> {
    let (tag, body, rest) = der_element(der)?;
    if tag != 0x30 || !rest.is_empty() {
        return None;
    }
    let (tag, version, body) = der_element(body)?;
    if tag != 0x02 || (version != [0] && version != [1]) {
        return None;
    }
    let (tag, algorithm, body) = der_element(body)?;
    if tag != 0x30 || algorithm != [0x06, 0x03, 0x2b, 0x65, 0x70] {
        return None;
    }
    let (tag, private_key, mut body) = der_element(body)?;
    if tag != 0x04 {
        return None;
    }
    let (tag, seed, rest) = der_element(private_key)?;
    if tag != 0x04 || seed.len() != 32 || !rest.is_empty() {
        return None;
    }
    let mut last_tag = 0u8;
    while !body.is_empty() {
        let (tag, _, rest) = der_element(body)?;
        if (tag != 0xa0 && tag != 0x81 && tag != 0xa1) || tag <= last_tag {
            return None;
        }
        last_tag = tag;
        body = rest;
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(seed);
    Some(array)
}

/// Opens a stored authority key.
pub fn ssh_signing_key(public_blob: &[u8], private_pkcs8: &str) -> IamResult<SshSigningKey> {
    // A key that does not open is an exception in TypeScript (not an IamError).
    let seed = ed25519_seed(&node_base64_decode(private_pkcs8)).ok_or_else(internal_error)?;
    Ok(SshSigningKey {
        public_blob: public_blob.to_vec(),
        private_key: SigningKey::from_bytes(&seed),
    })
}

/// A random non-zero 63-bit serial (KRLs cannot revoke serial 0).
pub fn ssh_serial() -> u64 {
    loop {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&random_bytes(8));
        let value = u64::from_be_bytes(bytes) & 0x7fff_ffff_ffff_ffff;
        if value != 0 {
            return value;
        }
    }
}

/// What a certificate states (`SshCertificateSpec`).
#[derive(Debug, Clone, PartialEq)]
pub struct SshCertificateSpec {
    pub key: SshPublicKey,
    pub serial: u64,
    /// [`SSH_CERT_USER`] or [`SSH_CERT_HOST`].
    pub kind: u32,
    pub key_id: String,
    pub principals: Vec<String>,
    /// Seconds since the epoch.
    pub valid_after: u64,
    pub valid_before: u64,
    /// Critical options by name (`force-command`, `source-address`, `verify-required`); the value may be empty.
    pub critical_options: IndexMap<String, String>,
    pub extensions: Vec<String>,
}

/// A signed certificate: its blob and its `*-cert.pub` line.
#[derive(Debug, Clone, PartialEq)]
pub struct SignedSshCertificate {
    pub blob: Vec<u8>,
    pub line: String,
}

/// Options and extensions are name/data pairs in lexical order; an option's data is itself a string.
fn pack_options(entries: &[(String, Option<String>)]) -> Vec<u8> {
    let mut sorted: Vec<&(String, Option<String>)> = entries.iter().collect();
    sorted.sort_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));
    let mut writer = SshWriter::new();
    for (name, value) in sorted {
        writer = writer.string(name);
        writer = match value {
            None => writer.string([]),
            Some(value) if value.is_empty() => writer.string([]),
            Some(value) => writer.string(SshWriter::new().string(value).into_buffer()),
        };
    }
    writer.into_buffer()
}

/// Signs `data` with an Ed25519 authority: an `ssh-ed25519` signature blob.
pub fn ssh_sign(key: &SshSigningKey, data: &[u8]) -> Vec<u8> {
    SshWriter::new()
        .string("ssh-ed25519")
        .string(key.private_key.sign(data).to_bytes())
        .into_buffer()
}

/// Issues an OpenSSH certificate; returns the certificate blob and its `*-cert.pub` line.
pub fn sign_ssh_certificate(
    authority: &SshSigningKey,
    spec: &SshCertificateSpec,
    comment: Option<&str>,
) -> IamResult<SignedSshCertificate> {
    let certificate_type =
        ssh_certificate_type(&spec.key.r#type).ok_or_else(|| invalid_key(DEFAULT_INVALID_KEY))?;
    let mut principals = SshWriter::new();
    for principal in &spec.principals {
        principals = principals.string(principal);
    }
    let options: Vec<(String, Option<String>)> = spec
        .critical_options
        .iter()
        .map(|(name, value)| (name.clone(), Some(value.clone())))
        .collect();
    let extensions: Vec<(String, Option<String>)> = spec
        .extensions
        .iter()
        .map(|name| (name.clone(), None))
        .collect();
    let body = SshWriter::new()
        .string(certificate_type)
        .string(random_bytes(32))
        .raw(&spec.key.fields)
        .u64(spec.serial)
        .u32(spec.kind)
        .string(&spec.key_id)
        .string(principals.into_buffer())
        .u64(spec.valid_after)
        .u64(spec.valid_before)
        .string(pack_options(&options))
        .string(pack_options(&extensions))
        .string([])
        .string(&authority.public_blob)
        .into_buffer();
    let mut blob = body.clone();
    blob.extend(
        SshWriter::new()
            .string(ssh_sign(authority, &body))
            .into_buffer(),
    );
    let line = format!(
        "{certificate_type} {}{}",
        STANDARD.encode(&blob),
        match comment {
            Some(comment) if !comment.is_empty() => format!(" {comment}"),
            _ => String::new(),
        }
    );
    Ok(SignedSshCertificate { blob, line })
}

/// A decoded certificate (the fields PROTOCOL.certkeys defines), with its signature checked.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedSshCertificate {
    pub r#type: String,
    pub key_type: String,
    pub public_key_fingerprint: String,
    pub serial: u64,
    pub kind: u32,
    pub key_id: String,
    pub principals: Vec<String>,
    pub valid_after: f64,
    pub valid_before: f64,
    pub critical_options: IndexMap<String, String>,
    pub extensions: Vec<String>,
    pub signature_key: Vec<u8>,
    pub signature_key_fingerprint: String,
    /// The authority's Ed25519 signature verifies over the certificate body.
    pub signature_valid: bool,
}

fn unpack_options(data: &[u8], with_values: bool) -> IamResult<Vec<(String, String)>> {
    let mut reader = SshReader::new(data);
    let mut result = Vec::new();
    while !reader.done() {
        let name = reader.text()?;
        let value = reader.string()?;
        result.push((
            name,
            if with_values && !value.is_empty() {
                SshReader::new(value).text()?
            } else {
                String::new()
            },
        ));
    }
    Ok(result)
}

/// Decodes a certificate line (`*-cert-v01@openssh.com base64 [comment]`). Only Ed25519 authorities verify.
pub fn parse_ssh_certificate(line: &str) -> IamResult<ParsedSshCertificate> {
    let parts = split_whitespace(line);
    let type_name = parts.first().copied().unwrap_or("");
    let key_type = SSH_KEY_TYPES
        .iter()
        .find(|(_, certificate)| *certificate == type_name)
        .map(|(key, _)| *key);
    let (Some(key_type), Some(data)) = (key_type, parts.get(1).copied()) else {
        return Err(invalid_key("Not an OpenSSH certificate"));
    };
    let blob = node_base64_decode(data);
    let mut cert = SshReader::new(&blob);
    if cert.text()? != type_name {
        return Err(invalid_key("The certificate data does not match its type"));
    }
    cert.string()?; // nonce
    // The embedded public key fields, by type (ed25519: pk; sk-ed25519: pk, application; rsa: e, n;
    // ecdsa: curve, point; sk-ecdsa: curve, point, application), rebuild the plain key blob.
    let key_start = cert.position();
    let field_count = if key_type == "ssh-ed25519" {
        1
    } else if key_type == "sk-ecdsa-sha2-nistp256@openssh.com" {
        3
    } else {
        2
    };
    for _ in 0..field_count {
        cert.string()?;
    }
    let mut key_blob = SshWriter::new().string(key_type).into_buffer();
    key_blob.extend_from_slice(&blob[key_start..cert.position()]);
    let serial = cert.u64()?;
    let kind = cert.u32()?;
    let key_id = cert.text()?;
    let principal_data = cert.string()?;
    let mut principal_reader = SshReader::new(principal_data);
    let mut principals = Vec::new();
    while !principal_reader.done() {
        principals.push(principal_reader.text()?);
    }
    let valid_after = cert.u64()? as f64;
    let valid_before = cert.u64()?;
    let mut critical_options: IndexMap<String, String> = IndexMap::new();
    for (name, value) in unpack_options(cert.string()?, true)? {
        critical_options.insert(name, value);
    }
    let extensions = unpack_options(cert.string()?, false)?
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    cert.string()?; // reserved
    let signature_key = cert.string()?.to_vec();
    let body_length = cert.position();
    let mut signature = SshReader::new(cert.string()?);
    if !cert.done() {
        return Err(invalid_key("Unexpected data after the certificate"));
    }
    let algorithm = signature.text()?;
    let value = signature.string()?;
    let mut signature_valid = false;
    let mut ca_reader = SshReader::new(&signature_key);
    if algorithm == "ssh-ed25519" && ca_reader.text()? == "ssh-ed25519" {
        let raw = ca_reader.string()?;
        signature_valid = (|| {
            let raw: [u8; 32] = raw.try_into().ok()?;
            let key = ed25519_dalek::VerifyingKey::from_bytes(&raw).ok()?;
            let signature = ed25519_dalek::Signature::from_slice(value).ok()?;
            Some(key.verify(&blob[..body_length], &signature).is_ok())
        })()
        .unwrap_or(false);
    }
    Ok(ParsedSshCertificate {
        r#type: type_name.to_owned(),
        key_type: key_type.to_owned(),
        public_key_fingerprint: ssh_fingerprint(&key_blob),
        serial,
        kind,
        key_id,
        principals,
        valid_after,
        // "Forever" (2^64-1) does not fit a safe integer; it is never issued here.
        valid_before: if valid_before as f64 > core_js::MAX_SAFE_INTEGER {
            core_js::MAX_SAFE_INTEGER
        } else {
            valid_before as f64
        },
        critical_options,
        extensions,
        signature_key_fingerprint: ssh_fingerprint(&signature_key),
        signature_key,
        signature_valid,
    })
}

const KRL_MAGIC: u64 = 0x5353_484b_524c_0a00;
const KRL_SECTION_CERTIFICATES: u8 = 1;
const KRL_SECTION_EXPLICIT_KEY: u8 = 2;
const KRL_SECTION_CERT_SERIAL_LIST: u8 = 0x20;
const KRL_SECTION_CERT_KEY_ID: u8 = 0x23;

/// What one authority revokes.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct KrlAuthoritySection {
    pub authority: Vec<u8>,
    pub serials: Vec<u64>,
    pub key_ids: Vec<String>,
}

/// The input of [`build_ssh_krl`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SshKrlInput {
    pub version: u64,
    /// Milliseconds since the epoch.
    pub generated_at: f64,
    pub comment: Option<String>,
    pub authorities: Vec<KrlAuthoritySection>,
    pub keys: Vec<Vec<u8>>,
}

/// A binary OpenSSH key revocation list (PROTOCOL.krl) for sshd `RevokedKeys` and ssh `RevokedHostKeys`:
/// certificate serials and key IDs per authority, plus plain keys revoked outright (such as a disabled host's key).
pub fn build_ssh_krl(input: &SshKrlInput) -> Vec<u8> {
    let mut writer = SshWriter::new()
        .u64(KRL_MAGIC)
        .u32(1)
        .u64(input.version)
        .u64((input.generated_at / 1000.0).floor() as u64)
        .u64(0)
        .string([])
        .string(input.comment.as_deref().unwrap_or(""));
    for section in &input.authorities {
        let mut serials: Vec<u64> = section
            .serials
            .iter()
            .copied()
            .collect::<IndexSet<u64>>()
            .into_iter()
            .filter(|serial| *serial > 0)
            .collect();
        serials.sort_unstable();
        let mut key_ids: Vec<String> = section
            .key_ids
            .iter()
            .cloned()
            .collect::<IndexSet<String>>()
            .into_iter()
            .collect();
        key_ids.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        if serials.is_empty() && key_ids.is_empty() {
            continue;
        }
        let mut body = SshWriter::new().string(&section.authority).string([]);
        if !serials.is_empty() {
            let mut list = SshWriter::new();
            for serial in &serials {
                list = list.u64(*serial);
            }
            body = body
                .byte(KRL_SECTION_CERT_SERIAL_LIST)
                .string(list.into_buffer());
        }
        if !key_ids.is_empty() {
            let mut list = SshWriter::new();
            for key_id in &key_ids {
                list = list.string(key_id);
            }
            body = body
                .byte(KRL_SECTION_CERT_KEY_ID)
                .string(list.into_buffer());
        }
        writer = writer
            .byte(KRL_SECTION_CERTIFICATES)
            .string(body.into_buffer());
    }
    let mut keys: Vec<Vec<u8>> = input
        .keys
        .iter()
        .cloned()
        .collect::<IndexSet<Vec<u8>>>()
        .into_iter()
        .collect();
    if !keys.is_empty() {
        keys.sort();
        let mut list = SshWriter::new();
        for key in &keys {
            list = list.string(key);
        }
        writer = writer
            .byte(KRL_SECTION_EXPLICIT_KEY)
            .string(list.into_buffer());
    }
    writer.into_buffer()
}

const V4_SEGMENT: &str = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])";
const V6_SEGMENT: &str = "(?:[0-9a-fA-F]{1,4})";

static IPV4: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"^(?:{V4_SEGMENT}\.){{3}}{V4_SEGMENT}$")).expect("regex")
});

static IPV6: LazyLock<Regex> = LazyLock::new(|| {
    let v4 = format!(r"(?:{V4_SEGMENT}\.){{3}}{V4_SEGMENT}");
    let s = V6_SEGMENT;
    let pattern = format!(
        "^(?:\
         (?:{s}:){{7}}(?:{s}|:)|\
         (?:{s}:){{6}}(?:{v4}|:{s}|:)|\
         (?:{s}:){{5}}(?::{v4}|(?::{s}){{1,2}}|:)|\
         (?:{s}:){{4}}(?:(?::{s}){{0,1}}:{v4}|(?::{s}){{1,3}}|:)|\
         (?:{s}:){{3}}(?:(?::{s}){{0,2}}:{v4}|(?::{s}){{1,4}}|:)|\
         (?:{s}:){{2}}(?:(?::{s}){{0,3}}:{v4}|(?::{s}){{1,5}}|:)|\
         (?:{s}:){{1}}(?:(?::{s}){{0,4}}:{v4}|(?::{s}){{1,6}}|:)|\
         (?::(?:(?::{s}){{0,5}}:{v4}|(?::{s}){{1,7}}|:))\
         )(?:%[0-9a-zA-Z.:-]{{1,}})?$"
    );
    Regex::new(&pattern).expect("regex")
});

/// `isIP(value)` (node:net): 4 for an IPv4 address, 6 for an IPv6 address (zone IDs included), 0 otherwise.
pub(crate) fn is_ip(value: &str) -> u8 {
    if IPV4.is_match(value) {
        4
    } else if IPV6.is_match(value) {
        6
    } else {
        0
    }
}

/// `/^(?!-)[a-z0-9-]{1,63}(?<!-)$/i`.
fn host_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

static NUMERIC_LABEL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(?:[0-9]+|0x[0-9a-f]+)$").expect("regex"));

/// A host certificate principal: a DNS name (a leading `*.` is refused), or an IPv4/IPv6 address.
pub fn ssh_host_address(value: Option<&Value>) -> IamResult<String> {
    let Some(Value::String(value)) = value else {
        return Err(IamError::new("INVALID_INPUT", "Invalid host address"));
    };
    let lowered = core_js::to_lower(core_js::trim(value));
    let address = lowered.strip_suffix('.').unwrap_or(&lowered).to_owned();
    // No IPv6 zone IDs (`fe80::1%eth0`): they name an interface, not a host.
    if is_ip(&address) != 0 && !address.contains('%') {
        return Ok(address);
    }
    let labels: Vec<&str> = address.split('.').collect();
    if core_js::utf16_len(&address) > 253
        || address.contains('%')
        || !labels.iter().all(|label| host_label(label))
        || (labels.len() > 1 && NUMERIC_LABEL.is_match(labels[labels.len() - 1]))
    {
        return Err(IamError::new(
            "INVALID_INPUT",
            format!("Invalid host address {}", slice_utf16(&address, 64)),
        ));
    }
    Ok(address)
}

/// A Unix login name, as certificate principals carry them: portable user names only.
pub fn ssh_login(value: Option<&Value>) -> IamResult<String> {
    let valid = match value {
        Some(Value::String(value)) => {
            let bytes = value.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= 32
                && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
                && bytes[1..]
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
                && !value.ends_with('.')
        }
        _ => false,
    };
    match value {
        Some(Value::String(value)) if valid => Ok(value.clone()),
        _ => Err(IamError::new(
            "INVALID_INPUT",
            "Logins are 1-32 letters, digits, \"_\", \".\" or \"-\" and start with a letter or \"_\"",
        )),
    }
}

/// The principal a host accepts for a login: `{login}@{host}`, so a certificate names the hosts it opens.
pub fn ssh_login_principal(login: &str, host: &str) -> String {
    format!("{login}@{host}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_is_ip() {
        for (value, family) in [
            ("10.0.0.5", 4),
            ("01.0.0.5", 0),
            ("256.0.0.1", 0),
            ("2001:db8::1", 6),
            ("::1", 6),
            ("::", 6),
            ("fe80::1%eth0", 6),
            ("::ffff:10.0.0.1", 6),
            ("1:2:3:4:5:6:7::", 6),
            ("1:2:3:4:5:6:7:8:9", 0),
            ("example.com", 0),
        ] {
            assert_eq!(is_ip(value), family, "{value}");
        }
    }

    #[test]
    fn pkcs8_round_trip() {
        let generated = generate_ssh_authority_key();
        let key = ssh_signing_key(&generated.public_blob, &generated.private_pkcs8).unwrap();
        let mut reader = SshReader::new(&generated.public_blob);
        assert_eq!(reader.text().unwrap(), "ssh-ed25519");
        assert_eq!(
            reader.string().unwrap(),
            key.private_key.verifying_key().to_bytes()
        );
        assert!(ssh_signing_key(&generated.public_blob, "AAAA").is_err());
    }
}
