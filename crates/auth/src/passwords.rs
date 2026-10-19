//! Password hashing compatible with node-argon2 0.44 (Rust-only module; the TypeScript service calls
//! `argon2.hash(password, { type: argon2.argon2id })` and `argon2.verify(digest, password)`).
//!
//! Hashes are PHC strings `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>` (standard base64 without padding, 16-byte
//! random salt, 32-byte hash). Verification reads the parameters from the PHC string exactly as node-argon2 and
//! `@phc/format` do, so hashes written by either implementation verify on the other.

use argon2::{Algorithm, Argon2, AssociatedData, Params, Version};
use better_iam_core::{IamResult, js};
use subtle::ConstantTimeEq;

use crate::crypto::random_bytes;
use crate::util::{base64_unpadded, internal_error, node_base64_decode};

/// The Argon2 variants node-argon2 names (`argon2d`, `argon2i`, `argon2id`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2Type {
    Argon2d,
    Argon2i,
    Argon2id,
}

impl Argon2Type {
    fn name(self) -> &'static str {
        match self {
            Self::Argon2d => "argon2d",
            Self::Argon2i => "argon2i",
            Self::Argon2id => "argon2id",
        }
    }

    fn algorithm(self) -> Algorithm {
        match self {
            Self::Argon2d => Algorithm::Argon2d,
            Self::Argon2i => Algorithm::Argon2i,
            Self::Argon2id => Algorithm::Argon2id,
        }
    }
}

/// node-argon2's hashing options (defaults: argon2id, m=65536, t=3, p=4, 32-byte hash, version 0x13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashOptions {
    pub kind: Argon2Type,
    pub memory_cost: u32,
    pub time_cost: u32,
    pub parallelism: u32,
    pub hash_length: usize,
    pub version: u32,
}

impl Default for HashOptions {
    fn default() -> Self {
        Self {
            kind: Argon2Type::Argon2id,
            memory_cost: 1 << 16,
            time_cost: 3,
            parallelism: 4,
            hash_length: 32,
            version: 0x13,
        }
    }
}

/// Why a digest could not be checked (node-argon2 rejects instead of returning false).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct PasswordHashError(pub String);

#[allow(clippy::too_many_arguments)]
fn raw_hash(
    password: &[u8],
    salt: &[u8],
    data: &[u8],
    kind: Argon2Type,
    version: u32,
    m: u32,
    t: u32,
    p: u32,
    length: usize,
) -> Result<Vec<u8>, PasswordHashError> {
    let version = match version {
        0x10 => Version::V0x10,
        0x13 => Version::V0x13,
        other => {
            return Err(PasswordHashError(format!(
                "Unsupported Argon2 version {other}"
            )));
        }
    };
    let mut builder = argon2::ParamsBuilder::new();
    builder.m_cost(m).t_cost(t).p_cost(p).output_len(length);
    if !data.is_empty() {
        let data =
            AssociatedData::new(data).map_err(|error| PasswordHashError(error.to_string()))?;
        builder.data(data);
    }
    let params: Params = builder
        .build()
        .map_err(|error| PasswordHashError(error.to_string()))?;
    let hasher = Argon2::new(kind.algorithm(), version, params);
    let mut out = vec![0u8; length];
    hasher
        .hash_password_into(password, salt, &mut out)
        .map_err(|error| PasswordHashError(error.to_string()))?;
    Ok(out)
}

/// `argon2.hash(password, options)` with a given salt (vectors and tests). Blocking: run it off async threads.
pub fn hash_with_salt(
    password: &str,
    salt: &[u8],
    options: &HashOptions,
) -> Result<String, PasswordHashError> {
    let hash = raw_hash(
        password.as_bytes(),
        salt,
        &[],
        options.kind,
        options.version,
        options.memory_cost,
        options.time_cost,
        options.parallelism,
        options.hash_length,
    )?;
    Ok(format!(
        "${}$v={}$m={},t={},p={}${}${}",
        options.kind.name(),
        options.version,
        options.memory_cost,
        options.time_cost,
        options.parallelism,
        base64_unpadded(salt),
        base64_unpadded(hash)
    ))
}

/// `argon2.hash(password, options)` with a fresh 16-byte salt. Blocking.
pub fn hash_sync(password: &str, options: &HashOptions) -> Result<String, PasswordHashError> {
    hash_with_salt(password, &random_bytes(16), options)
}

/// A parsed PHC string (`@phc/format` deserialize).
struct Phc {
    id: String,
    version: Option<u32>,
    params: Option<Vec<(String, String)>>,
    salt: Option<Vec<u8>>,
    hash: Option<Vec<u8>>,
}

fn id_like(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

fn value_like(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'/' || c == b'+' || c == b'.' || c == b'-')
}

fn b64_like(value: &str) -> bool {
    value.is_empty() || value_like(value)
}

fn version_of(field: &str) -> Option<u64> {
    let digits = field.strip_prefix("v=")?;
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    // parseInt of a long digit run loses precision; anything that large is refused later anyway.
    Some(digits.parse::<u64>().unwrap_or(u64::MAX))
}

fn deserialize(phc: &str) -> Result<Phc, PasswordHashError> {
    let invalid = |message: &str| PasswordHashError(message.to_owned());
    if phc.is_empty() {
        return Err(invalid("pchstr must be a non-empty string"));
    }
    if !phc.starts_with('$') {
        return Err(invalid("pchstr must contain a $ as first char"));
    }
    let mut fields: Vec<&str> = phc.split('$').collect();
    fields.remove(0);
    let mut max = 5;
    if fields.get(1).and_then(|field| version_of(field)).is_none() {
        max -= 1;
    }
    if fields.len() > max {
        return Err(invalid("pchstr contains too many fileds"));
    }
    let id = fields.remove(0);
    if !id_like(id) {
        return Err(invalid("id must satisfy /^[a-z0-9-]{1,32}$/"));
    }
    let mut version = None;
    if let Some(parsed) = fields.first().and_then(|field| version_of(field)) {
        fields.remove(0);
        version = Some(parsed);
    }
    let mut hash = None;
    let mut salt = None;
    if fields.last().is_some_and(|field| b64_like(field)) {
        if fields.len() > 1 && b64_like(fields[fields.len() - 2]) {
            hash = Some(node_base64_decode(fields.pop().unwrap_or_default()));
            salt = Some(node_base64_decode(fields.pop().unwrap_or_default()));
        } else {
            salt = Some(node_base64_decode(fields.pop().unwrap_or_default()));
        }
    }
    let mut params = None;
    if let Some(text) = fields.pop() {
        let mut list: Vec<(String, String)> = Vec::new();
        for pair in text.split(',') {
            let mut parts = pair.split('=');
            let name = parts.next().unwrap_or_default();
            let rest: Vec<&str> = parts.collect();
            if rest.is_empty() {
                return Err(invalid("params must be in the format name=value"));
            }
            let value = rest.join("=");
            if let Some(existing) = list.iter_mut().find(|(key, _)| key == name) {
                existing.1 = value;
            } else {
                list.push((name.to_owned(), value));
            }
        }
        if !list.iter().all(|(name, _)| id_like(name)) {
            return Err(invalid("params names must satisfy /^[a-z0-9-]{1,32}$/"));
        }
        if !list.iter().all(|(_, value)| value_like(value)) {
            return Err(invalid("params values must satisfy /^[a-zA-Z0-9/+.-]+$/"));
        }
        params = Some(list);
    }
    if !fields.is_empty() {
        return Err(invalid("pchstr contains unrecognized fileds"));
    }
    Ok(Phc {
        id: id.to_owned(),
        // `if (version) phcobj.version = version`: v=0 counts as absent.
        version: version
            .filter(|v| *v != 0)
            .map(|v| u32::try_from(v).unwrap_or(u32::MAX)),
        params,
        salt,
        hash,
    })
}

/// `+value` of a PHC parameter (decimal strings were already numbers; anything else goes through `Number()`).
fn parameter_number(value: Option<&String>) -> f64 {
    match value {
        None => f64::NAN,
        Some(text) => js::string_to_number(text),
    }
}

fn u32_parameter(value: f64, name: &str) -> Result<u32, PasswordHashError> {
    if value.is_finite() && value >= 0.0 && value.fract() == 0.0 && value <= f64::from(u32::MAX) {
        Ok(value as u32)
    } else {
        Err(PasswordHashError(format!("Invalid {name}")))
    }
}

/// `argon2.verify(digest, password)`: false for a wrong password or a digest of an unknown algorithm, an error for
/// a malformed digest. Blocking: run it off async threads.
pub fn verify_sync(digest: &str, password: &str) -> Result<bool, PasswordHashError> {
    let phc = deserialize(digest)?;
    let kind = match phc.id.as_str() {
        "argon2d" => Argon2Type::Argon2d,
        "argon2i" => Argon2Type::Argon2i,
        "argon2id" => Argon2Type::Argon2id,
        // `id in types` also finds the inherited `constructor`, which the binding then refuses.
        "constructor" => return Err(PasswordHashError("Invalid type".to_owned())),
        _ => return Ok(false),
    };
    let params = phc
        .params
        .ok_or_else(|| PasswordHashError("Cannot read properties of undefined".to_owned()))?;
    let lookup = |name: &str| {
        params
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    };
    let m = u32_parameter(parameter_number(lookup("m")), "memoryCost")?;
    let t = u32_parameter(parameter_number(lookup("t")), "timeCost")?;
    let p = u32_parameter(parameter_number(lookup("p")), "parallelism")?;
    let data = lookup("data")
        .map(|value| node_base64_decode(value))
        .unwrap_or_default();
    let salt = phc
        .salt
        .ok_or_else(|| PasswordHashError("Invalid salt".to_owned()))?;
    let expected = phc
        .hash
        .ok_or_else(|| PasswordHashError("Cannot read properties of undefined".to_owned()))?;
    let actual = raw_hash(
        password.as_bytes(),
        &salt,
        &data,
        kind,
        phc.version.unwrap_or(0x10),
        m,
        t,
        p,
        expected.len(),
    )?;
    Ok(bool::from(actual.ct_eq(&expected)))
}

/// [`hash_sync`] with the defaults, on the blocking pool; failures become an internal error.
pub async fn hash(password: &str) -> IamResult<String> {
    let password = password.to_owned();
    tokio::task::spawn_blocking(move || hash_sync(&password, &HashOptions::default()))
        .await
        .map_err(|_| internal_error())?
        .map_err(|_| internal_error())
}

/// [`verify_sync`] on the blocking pool; a malformed digest is an internal error, as the rejected promise is in
/// TypeScript.
pub async fn verify(digest: &str, password: &str) -> IamResult<bool> {
    let digest = digest.to_owned();
    let password = password.to_owned();
    tokio::task::spawn_blocking(move || verify_sync(&digest, &password))
        .await
        .map_err(|_| internal_error())?
        .map_err(|_: PasswordHashError| internal_error())
}
