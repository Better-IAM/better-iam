//! COSE keys and signature verification (`helpers/cose.ts`, `helpers/iso/isoCrypto/*` of `@simplewebauthn/server`),
//! on RustCrypto: ECDSA over P-256, P-384 and P-521 with any of the SHA hashes WebCrypto allows, RSASSA-PKCS1-v1_5
//! and RSA-PSS, and Ed25519.

use rsa::{BigUint, RsaPublicKey};
use sha2::Digest;
use sha2::{Sha256, Sha384, Sha512};

use super::WebAuthnError;
use super::cbor::{Cbor, decode_first};

pub const KTY: i64 = 1;
pub const ALG: i64 = 3;
pub const CRV: i64 = -1;
pub const X: i64 = -2;
pub const Y: i64 = -3;
pub const N: i64 = -1;
pub const E: i64 = -2;

pub const KTY_OKP: f64 = 1.0;
pub const KTY_EC2: f64 = 2.0;
pub const KTY_RSA: f64 = 3.0;

/// `COSEALG` values.
pub const COSE_ALGS: [i64; 12] = [
    -7, -8, -35, -36, -37, -38, -39, -47, -257, -258, -259, -65535,
];
/// `COSECRV` values.
pub const COSE_CRVS: [i64; 5] = [1, 2, 3, 6, 8];

/// `isCOSEAlg(value)`.
pub fn is_cose_alg(value: Option<&Cbor>) -> bool {
    value
        .and_then(Cbor::as_number)
        .is_some_and(|alg| COSE_ALGS.iter().any(|known| *known as f64 == alg))
}

fn err(message: impl Into<String>) -> WebAuthnError {
    WebAuthnError(message.into())
}

/// The SHA hash `mapCoseAlgToWebCryptoAlg(alg)` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hash {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl Hash {
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Hash::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Hash::Sha256 => Sha256::digest(data).to_vec(),
            Hash::Sha384 => Sha384::digest(data).to_vec(),
            Hash::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    fn length(self) -> usize {
        match self {
            Hash::Sha1 => 20,
            Hash::Sha256 => 32,
            Hash::Sha384 => 48,
            Hash::Sha512 => 64,
        }
    }
}

/// `mapCoseAlgToWebCryptoAlg(alg)`.
pub fn hash_for(alg: f64) -> Result<Hash, WebAuthnError> {
    let alg = alg as i64;
    match alg {
        -65535 => Ok(Hash::Sha1),
        -7 | -37 | -257 => Ok(Hash::Sha256),
        -35 | -38 | -258 => Ok(Hash::Sha384),
        -36 | -39 | -259 | -8 => Ok(Hash::Sha512),
        _ => Err(err(format!(
            "Could not map COSE alg value of {alg} to a WebCrypto alg"
        ))),
    }
}

/// `toHash(data, alg)` (SHA-256 by default).
pub fn to_hash(data: &[u8], alg: f64) -> Result<Vec<u8>, WebAuthnError> {
    Ok(hash_for(alg)?.digest(data))
}

/// The RSA scheme `mapCoseAlgToWebCryptoKeyAlgName(alg)` names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyAlgorithm {
    Ed25519,
    Ecdsa,
    Pkcs1,
    Pss,
}

fn key_algorithm(alg: f64) -> Result<KeyAlgorithm, WebAuthnError> {
    match alg as i64 {
        -8 => Ok(KeyAlgorithm::Ed25519),
        -7 | -35 | -36 | -47 => Ok(KeyAlgorithm::Ecdsa),
        -257 | -258 | -259 | -65535 => Ok(KeyAlgorithm::Pkcs1),
        -39..=-37 => Ok(KeyAlgorithm::Pss),
        other => Err(err(format!(
            "Could not map COSE alg value of {other} to a WebCrypto key alg name"
        ))),
    }
}

/// `decodeCredentialPublicKey(bytes)`.
pub fn decode_public_key(bytes: &[u8]) -> Result<Cbor, WebAuthnError> {
    decode_first(bytes).map_err(|error| err(error.0))
}

/// Minimal BER reader for the `ECDSA-Sig-Value` (`SEQUENCE { r INTEGER, s INTEGER }`) of an EC2 signature.
fn read_tlv(data: &[u8], index: usize) -> Option<(u8, usize, usize)> {
    let tag = *data.get(index)?;
    let first = *data.get(index + 1)?;
    let (length, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let mut length = 0usize;
        for offset in 0..count {
            length = (length << 8) | usize::from(*data.get(index + 2 + offset)?);
        }
        (length, 2 + count)
    };
    if index + header + length > data.len() {
        return None;
    }
    Some((tag, index + header, length))
}

/// `unwrapEC2Signature(signature, crv)`: the raw `r || s` WebCrypto expects.
pub fn unwrap_ec2_signature(signature: &[u8], crv: f64) -> Result<Vec<u8>, WebAuthnError> {
    let invalid = || err("Invalid ECDSA signature encoding");
    let (tag, body, length) = read_tlv(signature, 0).ok_or_else(invalid)?;
    if tag != 0x30 {
        return Err(invalid());
    }
    let (r_tag, r_start, r_length) = read_tlv(signature, body).ok_or_else(invalid)?;
    let (s_tag, s_start, s_length) = read_tlv(signature, r_start + r_length).ok_or_else(invalid)?;
    if r_tag != 0x02 || s_tag != 0x02 || s_start + s_length > body + length {
        return Err(invalid());
    }
    let component = match crv as i64 {
        1 => 32,
        2 => 48,
        3 => 66,
        other => return Err(err(format!("Unexpected COSE crv value of {other} (EC2)"))),
    };
    let normalize = |bytes: &[u8]| -> Result<Vec<u8>, WebAuthnError> {
        if bytes.len() < component {
            let mut out = vec![0u8; component - bytes.len()];
            out.extend_from_slice(bytes);
            Ok(out)
        } else if bytes.len() == component {
            Ok(bytes.to_vec())
        } else if bytes.len() == component + 1 && bytes[0] == 0 && bytes[1] & 0x80 == 0x80 {
            Ok(bytes[1..].to_vec())
        } else {
            Err(err(format!(
                "Invalid signature component length {}, expected {component}",
                bytes.len()
            )))
        }
    };
    let mut out = normalize(&signature[r_start..r_start + r_length])?;
    out.extend(normalize(&signature[s_start..s_start + s_length])?);
    Ok(out)
}

/// The prehash ECDSA verification uses: hashes shorter than the field are left-padded (their value is used as is,
/// as WebCrypto does), longer ones are truncated by the ECDSA implementation.
fn prehash_for(digest: Vec<u8>, field_bytes: usize) -> Vec<u8> {
    if digest.len() >= field_bytes {
        return digest;
    }
    let mut padded = vec![0u8; field_bytes - digest.len()];
    padded.extend(digest);
    padded
}

fn verify_ec2(
    key: &Cbor,
    signature: &[u8],
    data: &[u8],
    hash_override: Option<f64>,
) -> Result<bool, WebAuthnError> {
    let alg = key.get_int(ALG).filter(|alg| alg.truthy());
    let crv = key.get_int(CRV).filter(|crv| crv.truthy());
    let x = key.get_int(X).filter(|x| x.truthy());
    let y = key.get_int(Y).filter(|y| y.truthy());
    let alg = alg.ok_or_else(|| err("Public key was missing alg (EC2)"))?;
    let crv = crv.ok_or_else(|| err("Public key was missing crv (EC2)"))?;
    let x = x
        .and_then(Cbor::as_bytes)
        .ok_or_else(|| err("Public key was missing x (EC2)"))?;
    let y = y
        .and_then(Cbor::as_bytes)
        .ok_or_else(|| err("Public key was missing y (EC2)"))?;
    let mut hash = hash_for(alg.as_number().unwrap_or(f64::NAN))?;
    if let Some(override_alg) = hash_override.filter(|value| *value != 0.0 && !value.is_nan()) {
        hash = hash_for(override_alg)?;
    }
    let digest = hash.digest(data);
    let mut point = vec![0x04];
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    let bad_key = || err("Invalid EC public key");
    match crv.as_number().map(|crv| crv as i64) {
        Some(1) => {
            use p256::ecdsa::signature::hazmat::PrehashVerifier;
            let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(|_| bad_key())?;
            let Ok(signature) = p256::ecdsa::Signature::from_slice(signature) else {
                return Ok(false);
            };
            Ok(key
                .verify_prehash(&prehash_for(digest, 32), &signature)
                .is_ok())
        }
        Some(2) => {
            use p384::ecdsa::signature::hazmat::PrehashVerifier;
            let key = p384::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(|_| bad_key())?;
            let Ok(signature) = p384::ecdsa::Signature::from_slice(signature) else {
                return Ok(false);
            };
            Ok(key
                .verify_prehash(&prehash_for(digest, 48), &signature)
                .is_ok())
        }
        Some(3) => {
            use p521::ecdsa::signature::hazmat::PrehashVerifier;
            let key = p521::ecdsa::VerifyingKey::from_sec1_bytes(&point).map_err(|_| bad_key())?;
            let Ok(signature) = p521::ecdsa::Signature::from_slice(signature) else {
                return Ok(false);
            };
            Ok(key
                .verify_prehash(&prehash_for(digest, 66), &signature)
                .is_ok())
        }
        _ => Err(err("Unexpected COSE crv value (EC2)")),
    }
}

/// RSA verification of `signature` over `data` with the scheme and hash named.
pub(crate) fn verify_rsa_raw(
    n: &[u8],
    e: &[u8],
    pss: bool,
    hash: Hash,
    salt_length: usize,
    signature: &[u8],
    data: &[u8],
) -> Result<bool, WebAuthnError> {
    let key = RsaPublicKey::new_with_max_size(
        BigUint::from_bytes_be(n),
        BigUint::from_bytes_be(e),
        16_384,
    )
    .map_err(|_| err("Invalid RSA public key"))?;
    let digest = hash.digest(data);
    let outcome = if pss {
        let scheme = match hash {
            Hash::Sha1 => rsa::Pss::new_with_salt::<sha1::Sha1>(salt_length),
            Hash::Sha256 => rsa::Pss::new_with_salt::<Sha256>(salt_length),
            Hash::Sha384 => rsa::Pss::new_with_salt::<Sha384>(salt_length),
            Hash::Sha512 => rsa::Pss::new_with_salt::<Sha512>(salt_length),
        };
        key.verify(scheme, &digest, signature)
    } else {
        let scheme = match hash {
            Hash::Sha1 => rsa::Pkcs1v15Sign::new::<sha1::Sha1>(),
            Hash::Sha256 => rsa::Pkcs1v15Sign::new::<Sha256>(),
            Hash::Sha384 => rsa::Pkcs1v15Sign::new::<Sha384>(),
            Hash::Sha512 => rsa::Pkcs1v15Sign::new::<Sha512>(),
        };
        key.verify(scheme, &digest, signature)
    };
    Ok(outcome.is_ok())
}

fn verify_rsa(
    key: &Cbor,
    signature: &[u8],
    data: &[u8],
    hash_override: Option<f64>,
) -> Result<bool, WebAuthnError> {
    let alg = key
        .get_int(ALG)
        .filter(|alg| alg.truthy())
        .ok_or_else(|| err("Public key was missing alg (RSA)"))?;
    if !is_cose_alg(Some(alg)) {
        return Err(err("Public key had invalid alg (RSA)"));
    }
    let n = key
        .get_int(N)
        .filter(|n| n.truthy())
        .and_then(Cbor::as_bytes)
        .ok_or_else(|| err("Public key was missing n (RSA)"))?;
    let e = key
        .get_int(E)
        .filter(|e| e.truthy())
        .and_then(Cbor::as_bytes)
        .ok_or_else(|| err("Public key was missing e (RSA)"))?;
    let alg = alg.as_number().unwrap_or(f64::NAN);
    let name = key_algorithm(alg)?;
    let mut hash = hash_for(alg)?;
    if let Some(override_alg) = hash_override.filter(|value| *value != 0.0 && !value.is_nan()) {
        hash = hash_for(override_alg)?;
    }
    match name {
        KeyAlgorithm::Pkcs1 => verify_rsa_raw(n, e, false, hash, 0, signature, data),
        KeyAlgorithm::Pss => {
            let salt = match hash {
                Hash::Sha256 => 32,
                Hash::Sha384 => 48,
                Hash::Sha512 => 64,
                Hash::Sha1 => 0,
            };
            verify_rsa_raw(n, e, true, hash, salt, signature, data)
        }
        _ => Err(err("Unexpected RSA key algorithm")),
    }
}

fn verify_okp(key: &Cbor, signature: &[u8], data: &[u8]) -> Result<bool, WebAuthnError> {
    let alg = key
        .get_int(ALG)
        .filter(|alg| alg.truthy())
        .ok_or_else(|| err("Public key was missing alg (OKP)"))?;
    if !is_cose_alg(Some(alg)) {
        return Err(err("Public key had invalid alg (OKP)"));
    }
    let crv = key
        .get_int(CRV)
        .filter(|crv| crv.truthy())
        .ok_or_else(|| err("Public key was missing crv (OKP)"))?;
    let x = key
        .get_int(X)
        .filter(|x| x.truthy())
        .and_then(Cbor::as_bytes)
        .ok_or_else(|| err("Public key was missing x (OKP)"))?;
    if crv.as_number() != Some(6.0) {
        return Err(err("Unexpected COSE crv value (OKP)"));
    }
    let bytes: [u8; 32] = x
        .try_into()
        .map_err(|_| err("Invalid Ed25519 public key"))?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
        .map_err(|_| err("Invalid Ed25519 public key"))?;
    let Ok(signature) = ed25519_dalek::Signature::from_slice(signature) else {
        return Ok(false);
    };
    use ed25519_dalek::Verifier;
    Ok(key.verify(data, &signature).is_ok())
}

/// `isoCrypto.verify({ cosePublicKey, signature, data, shaHashOverride })`.
pub fn verify(
    key: &Cbor,
    signature: &[u8],
    data: &[u8],
    hash_override: Option<f64>,
) -> Result<bool, WebAuthnError> {
    let kty = key.get_int(KTY).and_then(Cbor::as_number);
    match kty {
        Some(KTY_EC2) => {
            let crv = key.get_int(CRV).and_then(Cbor::as_number);
            let crv = crv
                .filter(|crv| COSE_CRVS.iter().any(|known| *known as f64 == *crv))
                .ok_or_else(|| err("unknown COSE curve"))?;
            let unwrapped = unwrap_ec2_signature(signature, crv)?;
            verify_ec2(key, &unwrapped, data, hash_override)
        }
        Some(KTY_RSA) => verify_rsa(key, signature, data, hash_override),
        Some(KTY_OKP) => verify_okp(key, signature, data),
        _ => Err(err(
            "Signature verification with public key of this kty is not supported",
        )),
    }
}

/// `convertCOSEtoPKCS(cosePublicKey)`: `0x04 || x || y` (or `0x04 || x` without `y`).
pub fn cose_to_pkcs(public_key: &[u8]) -> Result<Vec<u8>, WebAuthnError> {
    let key = decode_public_key(public_key)?;
    let x = key
        .get_int(X)
        .filter(|x| x.truthy())
        .ok_or_else(|| err("COSE public key was missing x"))?;
    let mut out = vec![0x04];
    out.extend_from_slice(
        x.as_bytes()
            .ok_or_else(|| err("COSE public key was missing x"))?,
    );
    if let Some(y) = key.get_int(Y).filter(|y| y.truthy()) {
        out.extend_from_slice(
            y.as_bytes()
                .ok_or_else(|| err("COSE public key had an invalid y"))?,
        );
    }
    Ok(out)
}

/// The length of a digest (used by attestation checks).
pub fn hash_length(hash: Hash) -> usize {
    hash.length()
}
