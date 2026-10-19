//! Identifiers, tokens, token hashes, prefixed credential tokens, and sealed values (`crypto.ts`).
//!
//! Every format here is shared with the TypeScript implementation: a token issued by one server validates on the
//! others, and a value sealed by one opens on the others.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use better_iam_core::{IamError, IamResult};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::util::{base64url, hex, node_base64_decode};

/// `randomBytes(n)`.
pub fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; length];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
}

/// `newId(prefix)`: `{prefix}_` + base64url of 16 random bytes.
pub fn new_id(prefix: &str) -> String {
    format!("{prefix}_{}", base64url(random_bytes(16)))
}

/// `newToken()`: base64url of 32 random bytes (43 characters).
pub fn new_token() -> String {
    base64url(random_bytes(32))
}

/// `hashToken(token)`: hex SHA-256 of the UTF-8 token.
pub fn hash_token(token: &str) -> String {
    hex(Sha256::digest(token.as_bytes()))
}

/// The type part of a prefixed credential token (`CredentialTokenType`): `ses` (user and impersonation sessions),
/// `key` (API keys), `rol` (role sessions, including web identity), `sts` (session tokens) and `dlg` (delegated
/// agent sessions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CredentialTokenType {
    Ses,
    Key,
    Rol,
    Sts,
    Dlg,
}

impl CredentialTokenType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ses => "ses",
            Self::Key => "key",
            Self::Rol => "rol",
            Self::Sts => "sts",
            Self::Dlg => "dlg",
        }
    }

    /// The type named by `value`, if it is one.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ses" => Some(Self::Ses),
            "key" => Some(Self::Key),
            "rol" => Some(Self::Rol),
            "sts" => Some(Self::Sts),
            "dlg" => Some(Self::Dlg),
            _ => None,
        }
    }

    /// The session kind the token type must resolve to (`credentialTokenKinds[type]`).
    pub fn kind(self) -> &'static str {
        match self {
            Self::Ses => "user",
            Self::Key => "api-key",
            Self::Rol => "role",
            Self::Sts => "session-token",
            Self::Dlg => "delegated",
        }
    }
}

/// `credentialTokenKinds`: the session kind each credential token type must resolve to; the stored kind stays
/// authoritative.
pub const CREDENTIAL_TOKEN_KINDS: [(&str, &str); 5] = [
    ("ses", "user"),
    ("key", "api-key"),
    ("rol", "role"),
    ("sts", "session-token"),
    ("dlg", "delegated"),
];

/// `credentialTokenScanPattern`: a pattern secret scanners can use to find better-iam credential tokens in text. It
/// needs lookbehind support; without it, use `biam_(ses|key|rol|sts|dlg)_[A-Za-z0-9_-]{49}` with explicit boundary
/// rules.
pub const CREDENTIAL_TOKEN_SCAN_PATTERN: &str =
    "(?<![A-Za-z0-9_-])biam_(?:ses|key|rol|sts|dlg)_[A-Za-z0-9_-]{49}(?![A-Za-z0-9_-])";

/// The base64url of the big-endian CRC-32 (IEEE, as zlib computes it) of the token body.
pub fn credential_token_check(body: &str) -> String {
    base64url(crc32fast::hash(body.as_bytes()).to_be_bytes())
}

/// `newCredentialToken(type)`: `biam_<type>_` + 43 random base64url characters + a 6-character CRC-32 checksum (58
/// characters in all). The checksum lets scanners and the server reject garbage early; it authenticates nothing.
pub fn new_credential_token(kind: CredentialTokenType) -> String {
    let body = format!("biam_{}_{}", kind.as_str(), new_token());
    let check = credential_token_check(&body);
    body + &check
}

/// `newCredentialToken(type)` for an untrusted type name: INVALID_INPUT for an unknown one.
pub fn new_credential_token_named(kind: &str) -> IamResult<String> {
    CredentialTokenType::parse(kind)
        .map(new_credential_token)
        .ok_or_else(|| IamError::new("INVALID_INPUT", "Unknown credential token type"))
}

fn base64url_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
}

/// `parseCredentialToken(value)`: the type when the shape and checksum match, otherwise None. The type is a
/// routing hint only; authorization always uses the stored session.
pub fn parse_credential_token(value: &str) -> Option<CredentialTokenType> {
    // /^biam_(ses|key|rol|sts|dlg)_([A-Za-z0-9_-]{43})([A-Za-z0-9_-]{6})$/
    let bytes = value.as_bytes();
    if bytes.len() != 58 || !value.is_ascii() || !value.starts_with("biam_") || bytes[8] != b'_' {
        return None;
    }
    let kind = CredentialTokenType::parse(&value[5..8])?;
    if !bytes[9..].iter().all(|c| base64url_char(*c)) {
        return None;
    }
    let body = &value[..52];
    if credential_token_check(body) != value[52..] {
        return None;
    }
    Some(kind)
}

fn sealing_key(secret: &str) -> Aes256Gcm {
    let key = Sha256::digest(secret.as_bytes());
    Aes256Gcm::new_from_slice(&key).expect("a 256-bit key")
}

/// `encryptSecret(value, secret, context)`: AES-256-GCM with key SHA-256(secret), a random 96-bit IV and the context
/// as additional data; `base64url(iv).base64url(tag).base64url(ciphertext)`. The secret must be a high-entropy,
/// stable secret.
pub fn encrypt_secret(value: &str, secret: &str, context: &str) -> String {
    let iv = random_bytes(12);
    encrypt_secret_with_iv(value, secret, context, &iv)
}

/// [`encrypt_secret`] with a given 12-byte IV (vectors and tests).
pub fn encrypt_secret_with_iv(value: &str, secret: &str, context: &str, iv: &[u8]) -> String {
    let cipher = sealing_key(secret);
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(iv),
            Payload {
                msg: value.as_bytes(),
                aad: context.as_bytes(),
            },
        )
        .expect("AES-GCM encryption");
    let (encrypted, tag) = sealed.split_at(sealed.len() - 16);
    [base64url(iv), base64url(tag), base64url(encrypted)].join(".")
}

/// The default sealing context.
pub const DEFAULT_CONTEXT: &str = "better-iam";

/// `openSecret(value, secrets, context)`: opens a sealed value with the first of `secrets` that authenticates it,
/// and says which one (0 is the current secret; higher indexes are previous ones kept during a rotation). None when
/// none does.
pub fn open_secret<S: AsRef<str>>(
    value: &str,
    secrets: &[S],
    context: &str,
) -> Option<(String, usize)> {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let iv = node_base64_decode(parts[0]);
    let tag = node_base64_decode(parts[1]);
    let encrypted = node_base64_decode(parts[2]);
    // Exactly what encryptSecret writes: a 96-bit IV and a full 128-bit tag.
    if iv.len() != 12 || tag.len() != 16 {
        return None;
    }
    let mut sealed = encrypted;
    sealed.extend_from_slice(&tag);
    for (index, secret) in secrets.iter().enumerate() {
        let cipher = sealing_key(secret.as_ref());
        if let Ok(plain) = cipher.decrypt(
            Nonce::from_slice(&iv),
            Payload {
                msg: &sealed,
                aad: context.as_bytes(),
            },
        ) {
            // Buffer#toString('utf8') replaces invalid sequences.
            return Some((String::from_utf8_lossy(&plain).into_owned(), index));
        }
    }
    None
}

/// `decryptSecret(value, secrets, context)`: INVALID_SEALED_VALUE when no secret opens it.
pub fn decrypt_secret<S: AsRef<str>>(
    value: &str,
    secrets: &[S],
    context: &str,
) -> IamResult<String> {
    open_secret(value, secrets, context)
        .map(|(value, _)| value)
        .ok_or_else(|| IamError::new("INVALID_SEALED_VALUE", "Invalid sealed value"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_tokens_round_trip() {
        for kind in [
            CredentialTokenType::Ses,
            CredentialTokenType::Key,
            CredentialTokenType::Rol,
            CredentialTokenType::Sts,
            CredentialTokenType::Dlg,
        ] {
            let token = new_credential_token(kind);
            assert_eq!(token.len(), 58);
            assert_eq!(parse_credential_token(&token), Some(kind));
        }
        assert!(new_credential_token_named("xyz").is_err());
    }

    #[test]
    fn sealed_values_bind_their_context() {
        let sealed = encrypt_secret("private value", "s".repeat(32).as_str(), "tenant:a");
        assert_eq!(
            decrypt_secret(&sealed, &["s".repeat(32)], "tenant:a").unwrap(),
            "private value"
        );
        assert!(decrypt_secret(&sealed, &["s".repeat(32)], "tenant:b").is_err());
    }
}
