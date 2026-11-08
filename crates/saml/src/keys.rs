//! Errors, Node's lenient base64, PEM handling and the RSA operations the SAML code signs and verifies with
//! (`crypto.createSign` / `createVerify` with `RSA-SHA1|256|512`, `publicEncrypt` / `privateDecrypt`).

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use better_iam_core::IamError;
use der::{Decode, Encode};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

/// A failure of the SAML code: an [`IamError`] (what the TypeScript code throws as `IamError`), or a plain error
/// with its message (what Node-SAML, `xml-crypto` and `xml-encryption` throw as `Error`).
#[derive(Debug, Clone, PartialEq)]
pub enum SamlError {
    Iam(IamError),
    Plain(String),
}

impl SamlError {
    /// `new Error(message)`.
    pub fn plain(message: impl Into<String>) -> Self {
        SamlError::Plain(message.into())
    }

    /// The `IamError` code, when it is one.
    pub fn code(&self) -> Option<&str> {
        match self {
            SamlError::Iam(error) => Some(&error.code),
            SamlError::Plain(_) => None,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            SamlError::Iam(error) => &error.message,
            SamlError::Plain(message) => message,
        }
    }

    /// The `IamError`, when it is one.
    pub fn as_iam(&self) -> Option<&IamError> {
        match self {
            SamlError::Iam(error) => Some(error),
            SamlError::Plain(_) => None,
        }
    }
}

impl fmt::Display for SamlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for SamlError {}

impl From<IamError> for SamlError {
    fn from(error: IamError) -> Self {
        SamlError::Iam(error)
    }
}

/// `Result` with [`SamlError`].
pub type SamlResult<T> = Result<T, SamlError>;

/// `Buffer.from(text, 'base64')`: characters outside the alphabet (both the standard and the URL-safe one) are
/// skipped, and decoding stops at the first `=`.
pub fn base64_decode(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let mut group = [0u8; 4];
    let mut count = 0;
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => continue,
        };
        group[count] = value;
        count += 1;
        if count == 4 {
            out.push((group[0] << 2) | (group[1] >> 4));
            out.push((group[1] << 4) | (group[2] >> 2));
            out.push((group[2] << 6) | group[3]);
            count = 0;
        }
    }
    if count >= 2 {
        out.push((group[0] << 2) | (group[1] >> 4));
    }
    if count >= 3 {
        out.push((group[1] << 4) | (group[2] >> 2));
    }
    out
}

/// `buffer.toString('base64')`.
pub fn base64_encode(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// A PEM block: its label and DER contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemBlock {
    pub label: String,
    pub der: Vec<u8>,
}

/// The PEM blocks of a text, in order.
pub fn pem_blocks(text: &str) -> Vec<PemBlock> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("-----BEGIN ") {
        let after = &rest[start + 11..];
        let Some(label_end) = after.find("-----") else {
            break;
        };
        let label = after[..label_end].to_owned();
        let body_start = &after[label_end + 5..];
        let footer = format!("-----END {label}-----");
        let Some(end) = body_start.find(&footer) else {
            break;
        };
        out.push(PemBlock {
            label,
            der: base64_decode(&body_start[..end]),
        });
        rest = &body_start[end + footer.len()..];
    }
    out
}

/// The RSA public key of a PEM certificate, SubjectPublicKeyInfo or PKCS #1 public key (what Node's `createVerify`
/// accepts as a key).
pub fn public_key(pem: &str) -> Result<RsaPublicKey, SamlError> {
    let invalid = || SamlError::plain("error:1E08010C:DECODER routines::unsupported");
    let block = pem_blocks(pem).into_iter().next().ok_or_else(invalid)?;
    match block.label.as_str() {
        "CERTIFICATE" => {
            let certificate =
                x509_cert::Certificate::from_der(&block.der).map_err(|_| invalid())?;
            let spki = certificate
                .tbs_certificate
                .subject_public_key_info
                .to_der()
                .map_err(|_| invalid())?;
            RsaPublicKey::from_public_key_der(&spki).map_err(|_| invalid())
        }
        "PUBLIC KEY" => RsaPublicKey::from_public_key_der(&block.der).map_err(|_| invalid()),
        "RSA PUBLIC KEY" => RsaPublicKey::from_pkcs1_der(&block.der).map_err(|_| invalid()),
        // A private key verifies with its public half.
        "PRIVATE KEY" | "RSA PRIVATE KEY" => Ok(private_key(pem)?.to_public_key()),
        _ => Err(invalid()),
    }
}

/// The RSA private key of a PKCS #8 or PKCS #1 PEM.
pub fn private_key(pem: &str) -> Result<RsaPrivateKey, SamlError> {
    let invalid = || SamlError::plain("error:1E08010C:DECODER routines::unsupported");
    let block = pem_blocks(pem).into_iter().next().ok_or_else(invalid)?;
    match block.label.as_str() {
        "PRIVATE KEY" => RsaPrivateKey::from_pkcs8_der(&block.der).map_err(|_| invalid()),
        "RSA PRIVATE KEY" => RsaPrivateKey::from_pkcs1_der(&block.der).map_err(|_| invalid()),
        _ => Err(invalid()),
    }
}

/// The hash of an `RSA-SHA*` signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha1,
    Sha256,
    Sha512,
}

impl Hash {
    fn scheme(self) -> Pkcs1v15Sign {
        match self {
            Hash::Sha1 => Pkcs1v15Sign::new::<Sha1>(),
            Hash::Sha256 => Pkcs1v15Sign::new::<Sha256>(),
            Hash::Sha512 => Pkcs1v15Sign::new::<Sha512>(),
        }
    }

    /// The digest of `data`.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha1 => Sha1::digest(data).to_vec(),
            Hash::Sha256 => Sha256::digest(data).to_vec(),
            Hash::Sha512 => Sha512::digest(data).to_vec(),
        }
    }
}

/// `createSign('RSA-SHA*').update(data).sign(privateKey, 'base64')`.
pub fn rsa_sign(private_key_pem: &str, hash: Hash, data: &[u8]) -> Result<String, SamlError> {
    let key = private_key(private_key_pem)?;
    let signature = key
        .sign(hash.scheme(), &hash.digest(data))
        .map_err(|error| SamlError::plain(error.to_string()))?;
    Ok(base64_encode(&signature))
}

/// `createVerify('RSA-SHA*').update(data).verify(key, signature, 'base64')`.
pub fn rsa_verify(
    key_pem: &str,
    hash: Hash,
    data: &[u8],
    signature: &str,
) -> Result<bool, SamlError> {
    let key = public_key(key_pem)?;
    Ok(key
        .verify(hash.scheme(), &hash.digest(data), &base64_decode(signature))
        .is_ok())
}

/// `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))`.
pub fn timing_safe_equal(a: &str, b: &str) -> Result<bool, SamlError> {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return Err(SamlError::plain(
            "Input buffers must have the same byte length",
        ));
    }
    Ok(a.as_bytes().ct_eq(b.as_bytes()).into())
}

/// `createHash('sha256').update(value).digest('hex')`.
pub fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lenient_base64() {
        assert_eq!(base64_decode("aGVs\nbG8="), b"hello");
        assert_eq!(base64_decode("aGVsbG8"), b"hello");
        assert_eq!(base64_decode("aG*Vs bG8=ignored"), b"hello");
        assert_eq!(base64_decode("_-8"), vec![0xff, 0xef]);
    }
}
