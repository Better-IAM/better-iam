//! The JOSE subset the package uses through `jose` and `oidc-provider`: base64url, JSON Web Keys (RSA, EC P-256 /
//! P-384 / P-521, OKP Ed25519), JWS compact signing and verification for the asymmetric algorithms, RFC 7638
//! thumbprints, local key sets (`createLocalJWKSet` key selection) and JWT claim validation (`jwtVerify`).

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use better_iam_core::js;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256, Sha384, Sha512};

/// The asymmetric JOSE algorithms (`RS*`, `PS*`, `ES*`, `EdDSA`, `Ed25519`).
pub const ASYMMETRIC: [&str; 11] = [
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA",
    "Ed25519",
];

/// `base64url` without padding.
pub fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decodes base64url (padding tolerated, as Node's `Buffer.from(value, 'base64url')`).
pub fn b64url_decode(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(value.trim_end_matches('=')).ok()
}

/// Standard base64 with padding.
pub fn b64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}

/// Lenient standard base64 decoding (Node's `Buffer.from(value, 'base64')` skips characters outside the alphabet and
/// accepts the URL-safe alphabet too).
pub fn b64_decode_lenient(value: &str) -> Vec<u8> {
    let cleaned: String = value
        .chars()
        .filter_map(|c| match c {
            '-' => Some('+'),
            '_' => Some('/'),
            c if c.is_ascii_alphanumeric() || c == '+' || c == '/' => Some(c),
            _ => None,
        })
        .collect();
    let mut cleaned = cleaned;
    // Node stops at a lone trailing character that cannot form a byte.
    if cleaned.len() % 4 == 1 {
        cleaned.pop();
    }
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(cleaned.as_bytes())
        .unwrap_or_default()
}

/// SHA-256 of a string, base64url (`crypto.hash('sha256', value, 'base64url')`).
pub fn sha256_b64url(value: &str) -> String {
    b64url(&Sha256::digest(value.as_bytes()))
}

/// A JOSE failure. The variants mirror the jose error classes the callers distinguish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoseError {
    /// Malformed token, header, or key.
    Invalid(String),
    /// Signature verification failed.
    SignatureFailed,
    /// A claim check failed (`JWTClaimValidationFailed` / `JWTExpired`).
    Claim(String),
    /// No key of the set matches the header.
    NoMatchingKey,
    /// More than one key matches and none verifies.
    MultipleMatchingKeys,
    /// The algorithm is not allowed or not supported.
    AlgorithmNotAllowed,
}

impl std::fmt::Display for JoseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JoseError::Invalid(message) => write!(f, "{message}"),
            JoseError::SignatureFailed => write!(f, "signature verification failed"),
            JoseError::Claim(message) => write!(f, "{message}"),
            JoseError::NoMatchingKey => {
                write!(f, "no applicable key found in the JSON Web Key Set")
            }
            JoseError::MultipleMatchingKeys => {
                write!(f, "multiple matching keys found in the JSON Web Key Set")
            }
            JoseError::AlgorithmNotAllowed => {
                write!(f, "\"alg\" (Algorithm) Header Parameter value not allowed")
            }
        }
    }
}

impl std::error::Error for JoseError {}

fn invalid(message: &str) -> JoseError {
    JoseError::Invalid(message.to_owned())
}

/// A key usable for signing (private) or verifying (public).
#[derive(Clone)]
pub enum Key {
    RsaPrivate(Box<rsa::RsaPrivateKey>),
    RsaPublic(Box<rsa::RsaPublicKey>),
    P256Private(p256::ecdsa::SigningKey),
    P256Public(p256::ecdsa::VerifyingKey),
    P384Private(p384::ecdsa::SigningKey),
    P384Public(p384::ecdsa::VerifyingKey),
    P521Private(Box<p521::ecdsa::SigningKey>),
    P521Public(Box<p521::ecdsa::VerifyingKey>),
    Ed25519Private(Box<ed25519_dalek::SigningKey>),
    Ed25519Public(ed25519_dalek::VerifyingKey),
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key")
    }
}

fn str_member<'a>(jwk: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    jwk.get(name).and_then(Value::as_str)
}

fn component(jwk: &Map<String, Value>, name: &str) -> Result<Vec<u8>, JoseError> {
    str_member(jwk, name)
        .and_then(b64url_decode)
        .ok_or_else(|| invalid(&format!("Invalid JWK \"{name}\"")))
}

/// Imports a JWK (public or private) as `importJWK` does.
pub fn import_jwk(jwk: &Map<String, Value>) -> Result<Key, JoseError> {
    let private = jwk.get("d").is_some_and(Value::is_string);
    match str_member(jwk, "kty") {
        Some("RSA") => {
            let n = rsa::BigUint::from_bytes_be(&component(jwk, "n")?);
            let e = rsa::BigUint::from_bytes_be(&component(jwk, "e")?);
            if private {
                let d = rsa::BigUint::from_bytes_be(&component(jwk, "d")?);
                let mut primes = Vec::new();
                if let (Ok(p), Ok(q)) = (component(jwk, "p"), component(jwk, "q")) {
                    primes.push(rsa::BigUint::from_bytes_be(&p));
                    primes.push(rsa::BigUint::from_bytes_be(&q));
                }
                let key = rsa::RsaPrivateKey::from_components(n, e, d, primes)
                    .map_err(|_| invalid("Invalid RSA private key"))?;
                Ok(Key::RsaPrivate(Box::new(key)))
            } else {
                let key = rsa::RsaPublicKey::new_with_max_size(n, e, 16384)
                    .map_err(|_| invalid("Invalid RSA public key"))?;
                Ok(Key::RsaPublic(Box::new(key)))
            }
        }
        Some("EC") => {
            let crv = str_member(jwk, "crv");
            let x = component(jwk, "x")?;
            let y = component(jwk, "y")?;
            macro_rules! ec {
                ($curve:ident, $len:expr, $private:ident, $public:ident, $boxed:expr) => {{
                    if x.len() != $len || y.len() != $len {
                        return Err(invalid("Invalid EC key"));
                    }
                    if private {
                        let d = component(jwk, "d")?;
                        if d.len() != $len {
                            return Err(invalid("Invalid EC key"));
                        }
                        let key = $curve::ecdsa::SigningKey::from_slice(&d)
                            .map_err(|_| invalid("Invalid EC key"))?;
                        Ok($boxed(Key::$private, key))
                    } else {
                        let point = $curve::EncodedPoint::from_affine_coordinates(
                            x.as_slice().into(),
                            y.as_slice().into(),
                            false,
                        );
                        let key = $curve::ecdsa::VerifyingKey::from_encoded_point(&point)
                            .map_err(|_| invalid("Invalid EC key"))?;
                        Ok($boxed(Key::$public, key))
                    }
                }};
            }
            fn plain<K, T>(make: fn(K) -> T, key: K) -> T {
                make(key)
            }
            match crv {
                Some("P-256") => ec!(p256, 32, P256Private, P256Public, plain),
                Some("P-384") => ec!(p384, 48, P384Private, P384Public, plain),
                Some("P-521") => {
                    if x.len() != 66 || y.len() != 66 {
                        return Err(invalid("Invalid EC key"));
                    }
                    if private {
                        let d = component(jwk, "d")?;
                        let key = p521::ecdsa::SigningKey::from_slice(&d)
                            .map_err(|_| invalid("Invalid EC key"))?;
                        Ok(Key::P521Private(Box::new(key)))
                    } else {
                        let point = p521::EncodedPoint::from_affine_coordinates(
                            x.as_slice().into(),
                            y.as_slice().into(),
                            false,
                        );
                        let key = p521::ecdsa::VerifyingKey::from_encoded_point(&point)
                            .map_err(|_| invalid("Invalid EC key"))?;
                        Ok(Key::P521Public(Box::new(key)))
                    }
                }
                _ => Err(invalid("Unsupported JWK \"crv\"")),
            }
        }
        Some("OKP") => {
            if str_member(jwk, "crv") != Some("Ed25519") {
                return Err(invalid("Unsupported JWK \"crv\""));
            }
            if private {
                let d: [u8; 32] = component(jwk, "d")?
                    .try_into()
                    .map_err(|_| invalid("Invalid OKP key"))?;
                Ok(Key::Ed25519Private(Box::new(
                    ed25519_dalek::SigningKey::from_bytes(&d),
                )))
            } else {
                let x: [u8; 32] = component(jwk, "x")?
                    .try_into()
                    .map_err(|_| invalid("Invalid OKP key"))?;
                let key = ed25519_dalek::VerifyingKey::from_bytes(&x)
                    .map_err(|_| invalid("Invalid OKP key"))?;
                Ok(Key::Ed25519Public(key))
            }
        }
        _ => Err(invalid("Unsupported JWK \"kty\"")),
    }
}

/// The public members of a JWK (private parameters removed), keeping the order of the rest.
pub fn public_jwk(jwk: &Map<String, Value>) -> Map<String, Value> {
    jwk.iter()
        .filter(|(key, _)| {
            !["d", "p", "q", "dp", "dq", "qi", "k", "oth", "priv"].contains(&key.as_str())
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

/// RFC 7638 JWK SHA-256 thumbprint (`calculateJwkThumbprint(jwk, 'sha256')`).
pub fn jwk_thumbprint(jwk: &Map<String, Value>) -> Result<String, JoseError> {
    let get = |name: &str| {
        str_member(jwk, name)
            .map(str::to_owned)
            .ok_or_else(|| invalid(&format!("\"{name}\" (JWK member) is missing")))
    };
    let members = match str_member(jwk, "kty") {
        Some("EC") => json!({"crv": get("crv")?, "kty": "EC", "x": get("x")?, "y": get("y")?}),
        Some("OKP") => json!({"crv": get("crv")?, "kty": "OKP", "x": get("x")?}),
        Some("RSA") => json!({"e": get("e")?, "kty": "RSA", "n": get("n")?}),
        Some("oct") => json!({"k": get("k")?, "kty": "oct"}),
        _ => {
            return Err(invalid(
                "\"kty\" (Key Type) Parameter missing or unsupported",
            ));
        }
    };
    Ok(sha256_b64url(&js::stringify(&members)))
}

/// The algorithms a JWK can be used with (its `alg` when set).
pub fn key_algorithms(jwk: &Map<String, Value>) -> Vec<&'static str> {
    let available: Vec<&'static str> = match (str_member(jwk, "kty"), str_member(jwk, "crv")) {
        (Some("RSA"), _) => vec!["PS256", "PS384", "PS512", "RS256", "RS384", "RS512"],
        (Some("EC"), Some("P-256")) => vec!["ES256"],
        (Some("EC"), Some("P-384")) => vec!["ES384"],
        (Some("EC"), Some("P-521")) => vec!["ES512"],
        (Some("OKP"), Some("Ed25519")) => vec!["EdDSA", "Ed25519"],
        _ => Vec::new(),
    };
    match str_member(jwk, "alg") {
        Some(alg) => available
            .into_iter()
            .filter(|candidate| *candidate == alg)
            .collect(),
        None => available,
    }
}

fn rng() -> rand::rngs::OsRng {
    rand::rngs::OsRng
}

/// Signs `data` with `alg`.
pub fn sign_bytes(key: &Key, alg: &str, data: &[u8]) -> Result<Vec<u8>, JoseError> {
    use p256::ecdsa::signature::{RandomizedSigner, Signer};
    macro_rules! rsa_pkcs1 {
        ($digest:ty, $key:expr) => {
            rsa::pkcs1v15::SigningKey::<$digest>::new((**$key).clone())
                .try_sign(data)
                .map(|signature| rsa::signature::SignatureEncoding::to_vec(&signature))
                .map_err(|_| invalid("RSA signing failed"))
        };
    }
    macro_rules! rsa_pss {
        ($digest:ty, $key:expr) => {
            rsa::pss::BlindedSigningKey::<$digest>::new((**$key).clone())
                .try_sign_with_rng(&mut rng(), data)
                .map(|signature| rsa::signature::SignatureEncoding::to_vec(&signature))
                .map_err(|_| invalid("RSA signing failed"))
        };
    }
    match (key, alg) {
        (Key::RsaPrivate(key), "RS256") => rsa_pkcs1!(Sha256, key),
        (Key::RsaPrivate(key), "RS384") => rsa_pkcs1!(Sha384, key),
        (Key::RsaPrivate(key), "RS512") => rsa_pkcs1!(Sha512, key),
        (Key::RsaPrivate(key), "PS256") => rsa_pss!(Sha256, key),
        (Key::RsaPrivate(key), "PS384") => rsa_pss!(Sha384, key),
        (Key::RsaPrivate(key), "PS512") => rsa_pss!(Sha512, key),
        (Key::P256Private(key), "ES256") => {
            let signature: p256::ecdsa::Signature = key.sign(data);
            Ok(signature.to_bytes().to_vec())
        }
        (Key::P384Private(key), "ES384") => {
            let signature: p384::ecdsa::Signature = key.sign(data);
            Ok(signature.to_bytes().to_vec())
        }
        (Key::P521Private(key), "ES512") => {
            let signature: p521::ecdsa::Signature =
                p521::ecdsa::signature::RandomizedSigner::sign_with_rng(&**key, &mut rng(), data);
            Ok(signature.to_bytes().to_vec())
        }
        (Key::Ed25519Private(key), "EdDSA" | "Ed25519") => {
            use ed25519_dalek::Signer as _;
            Ok(key.sign(data).to_bytes().to_vec())
        }
        _ => Err(JoseError::AlgorithmNotAllowed),
    }
}

/// Verifies a signature; false when it does not verify or does not fit the key.
pub fn verify_bytes(key: &Key, alg: &str, data: &[u8], signature: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier;
    macro_rules! rsa_verify {
        ($scheme:ident, $digest:ty, $key:expr) => {
            rsa::$scheme::Signature::try_from(signature).is_ok_and(|signature| {
                rsa::$scheme::VerifyingKey::<$digest>::new($key)
                    .verify(data, &signature)
                    .is_ok()
            })
        };
    }
    let rsa_public = match key {
        Key::RsaPublic(key) => Some((**key).clone()),
        Key::RsaPrivate(key) => Some(key.to_public_key()),
        _ => None,
    };
    if let Some(public) = rsa_public {
        use rsa::traits::PublicKeyParts;
        if public.n().bits() < 2048 {
            return false;
        }
        return match alg {
            "RS256" => rsa_verify!(pkcs1v15, Sha256, public),
            "RS384" => rsa_verify!(pkcs1v15, Sha384, public),
            "RS512" => rsa_verify!(pkcs1v15, Sha512, public),
            "PS256" => rsa_verify!(pss, Sha256, public),
            "PS384" => rsa_verify!(pss, Sha384, public),
            "PS512" => rsa_verify!(pss, Sha512, public),
            _ => false,
        };
    }
    match (key, alg) {
        (Key::P256Public(key), "ES256") => p256::ecdsa::Signature::from_slice(signature)
            .is_ok_and(|signature| key.verify(data, &signature).is_ok()),
        (Key::P256Private(key), "ES256") => p256::ecdsa::Signature::from_slice(signature)
            .is_ok_and(|signature| key.verifying_key().verify(data, &signature).is_ok()),
        (Key::P384Public(key), "ES384") => p384::ecdsa::Signature::from_slice(signature)
            .is_ok_and(|signature| key.verify(data, &signature).is_ok()),
        (Key::P384Private(key), "ES384") => p384::ecdsa::Signature::from_slice(signature)
            .is_ok_and(|signature| key.verifying_key().verify(data, &signature).is_ok()),
        (Key::P521Public(key), "ES512") => p521::ecdsa::Signature::from_slice(signature)
            .is_ok_and(|signature| key.verify(data, &signature).is_ok()),
        (Key::P521Private(key), "ES512") => {
            let verifying = p521::ecdsa::VerifyingKey::from(&**key);
            p521::ecdsa::Signature::from_slice(signature)
                .is_ok_and(|signature| verifying.verify(data, &signature).is_ok())
        }
        (Key::Ed25519Public(key), "EdDSA" | "Ed25519") => {
            ed25519_dalek::Signature::from_slice(signature)
                .is_ok_and(|signature| key.verify(data, &signature).is_ok())
        }
        (Key::Ed25519Private(key), "EdDSA" | "Ed25519") => {
            ed25519_dalek::Signature::from_slice(signature)
                .is_ok_and(|signature| key.verifying_key().verify(data, &signature).is_ok())
        }
        _ => false,
    }
}

/// Signs a JWS compact serialization with `header` (whose `alg` is set here) over the JSON `payload`.
pub fn sign_jwt(
    key: &Key,
    alg: &str,
    header: Map<String, Value>,
    payload: &Value,
) -> Result<String, JoseError> {
    let mut protected = Map::new();
    protected.insert("alg".into(), Value::String(alg.to_owned()));
    for (name, value) in header {
        if name != "alg" && !value.is_null() {
            protected.insert(name, value);
        }
    }
    let signing_input = format!(
        "{}.{}",
        b64url(js::stringify_object(&protected).as_bytes()),
        b64url(js::stringify(payload).as_bytes())
    );
    let signature = sign_bytes(key, alg, signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{}", b64url(&signature)))
}

/// The parts of a compact JWS.
#[derive(Debug, Clone)]
pub struct Decoded {
    pub header: Map<String, Value>,
    pub payload: Map<String, Value>,
    pub signing_input: String,
    pub signature: Vec<u8>,
}

/// Decodes a compact JWS without verifying it (`decodeProtectedHeader` + `decodeJwt`).
pub fn decode(token: &str) -> Result<Decoded, JoseError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(invalid("Invalid Compact JWS"));
    }
    let header = b64url_decode(parts[0])
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value.as_object().cloned())
        .ok_or_else(|| invalid("Invalid JWS Protected Header"))?;
    let payload = b64url_decode(parts[1])
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value.as_object().cloned())
        .ok_or_else(|| invalid("JWT Claims Set must be a top-level JSON object"))?;
    let signature = b64url_decode(parts[2]).ok_or_else(|| invalid("Invalid JWS signature"))?;
    Ok(Decoded {
        header,
        payload,
        signing_input: format!("{}.{}", parts[0], parts[1]),
        signature,
    })
}

/// `decodeProtectedHeader(token)`: the header of a compact JWS (any number of parts with a JSON first segment).
pub fn decode_protected_header(token: &str) -> Option<Map<String, Value>> {
    let first = token.split('.').next()?;
    if token.split('.').count() < 3 {
        return None;
    }
    b64url_decode(first)
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value.as_object().cloned())
}

/// A local JSON Web Key Set (`createLocalJWKSet`).
#[derive(Debug, Clone, Default)]
pub struct KeySet {
    pub keys: Vec<Map<String, Value>>,
}

fn kty_for_alg(alg: &str) -> Option<(&'static str, Option<&'static str>)> {
    match alg {
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" => Some(("RSA", None)),
        "ES256" => Some(("EC", Some("P-256"))),
        "ES384" => Some(("EC", Some("P-384"))),
        "ES512" => Some(("EC", Some("P-521"))),
        "EdDSA" | "Ed25519" => Some(("OKP", Some("Ed25519"))),
        _ => None,
    }
}

impl KeySet {
    pub fn new(keys: Vec<Map<String, Value>>) -> Self {
        Self { keys }
    }

    /// A key set from `{ keys: [...] }`.
    pub fn from_value(value: &Value) -> Result<Self, JoseError> {
        let keys = value
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("JSON Web Key Set malformed"))?;
        Ok(Self {
            keys: keys
                .iter()
                .filter_map(|key| key.as_object().cloned())
                .collect(),
        })
    }

    /// The candidate keys for a header, as jose's `LocalJWKSet` selects them.
    pub fn candidates(&self, header: &Map<String, Value>) -> Vec<&Map<String, Value>> {
        let alg = str_member(header, "alg").unwrap_or_default();
        let kid = str_member(header, "kid");
        let Some((kty, crv)) = kty_for_alg(alg) else {
            return Vec::new();
        };
        self.keys
            .iter()
            .filter(|jwk| {
                let mut ok = str_member(jwk, "kty") == Some(kty);
                if ok && let Some(kid) = kid {
                    ok = str_member(jwk, "kid") == Some(kid);
                }
                if ok && let Some(key_alg) = str_member(jwk, "alg") {
                    ok = key_alg == alg
                        || (alg == "Ed25519" && key_alg == "EdDSA")
                        || (alg == "EdDSA" && key_alg == "Ed25519");
                }
                if ok && let Some(key_use) = str_member(jwk, "use") {
                    ok = key_use == "sig";
                }
                if ok && let Some(ops) = jwk.get("key_ops").and_then(Value::as_array) {
                    ok = ops.iter().any(|op| op.as_str() == Some("verify"));
                }
                if ok && let Some(crv) = crv {
                    ok = str_member(jwk, "crv") == Some(crv);
                }
                ok
            })
            .collect()
    }

    /// Verifies the signature of a decoded JWS against the matching key(s).
    pub fn verify(&self, decoded: &Decoded) -> Result<(), JoseError> {
        let alg = str_member(&decoded.header, "alg").unwrap_or_default();
        let candidates = self.candidates(&decoded.header);
        if candidates.is_empty() {
            return Err(JoseError::NoMatchingKey);
        }
        let mut any_imported = false;
        for jwk in &candidates {
            let Ok(key) = import_jwk(&public_jwk(jwk)) else {
                continue;
            };
            any_imported = true;
            if verify_bytes(
                &key,
                alg,
                decoded.signing_input.as_bytes(),
                &decoded.signature,
            ) {
                return Ok(());
            }
        }
        if !any_imported {
            return Err(JoseError::Invalid(
                "Invalid key in the JSON Web Key Set".into(),
            ));
        }
        if candidates.len() > 1 {
            Err(JoseError::MultipleMatchingKeys)
        } else {
            Err(JoseError::SignatureFailed)
        }
    }
}

/// Options of [`verify_jwt`] (`jwtVerify` options).
#[derive(Debug, Clone, Default)]
pub struct VerifyOptions {
    pub issuer: Option<Vec<String>>,
    pub audience: Option<Vec<String>>,
    pub typ: Option<String>,
    pub algorithms: Option<Vec<String>>,
    pub clock_tolerance: f64,
    pub max_token_age: Option<f64>,
    pub required_claims: Vec<String>,
    pub subject: Option<String>,
    /// Current time in seconds; defaults to `Date.now() / 1000`.
    pub current_date: Option<f64>,
}

fn normalize_typ(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    match lower.strip_prefix("application/") {
        Some(rest) => rest.to_owned(),
        None => lower,
    }
}

/// The key a JWS is verified with.
pub enum VerifyKey<'a> {
    Set(&'a KeySet),
    /// `EmbeddedJWK`: the header's `jwk` (public) member.
    Embedded,
    Single(&'a Key),
}

/// `jwtVerify(token, key, options)`: signature, then the JWT claim set checks.
pub fn verify_jwt(
    token: &str,
    key: VerifyKey<'_>,
    options: &VerifyOptions,
) -> Result<Decoded, JoseError> {
    let decoded = decode(token)?;
    let alg = str_member(&decoded.header, "alg")
        .ok_or_else(|| invalid("JWS \"alg\" (Algorithm) Header Parameter missing or invalid"))?
        .to_owned();
    if decoded.header.get("crit").is_some() {
        return Err(invalid(
            "Extension Header Parameter \"crit\" is not recognized",
        ));
    }
    if decoded.header.get("b64").is_some() {
        return Err(invalid("Unsupported \"b64\" Header Parameter"));
    }
    let allowed = options
        .algorithms
        .clone()
        .unwrap_or_else(|| ASYMMETRIC.iter().map(|alg| (*alg).to_owned()).collect());
    if !allowed.contains(&alg) {
        return Err(JoseError::AlgorithmNotAllowed);
    }
    match key {
        VerifyKey::Set(set) => set.verify(&decoded)?,
        VerifyKey::Embedded => {
            let jwk = decoded
                .header
                .get("jwk")
                .and_then(Value::as_object)
                .ok_or_else(|| {
                    invalid("\"jwk\" (JSON Web Key) Header Parameter must be a JSON object")
                })?;
            if jwk.get("d").is_some() {
                return Err(invalid(
                    "\"jwk\" (JSON Web Key) Header Parameter must be a public key",
                ));
            }
            let imported = import_jwk(jwk)?;
            if !verify_bytes(
                &imported,
                &alg,
                decoded.signing_input.as_bytes(),
                &decoded.signature,
            ) {
                return Err(JoseError::SignatureFailed);
            }
        }
        VerifyKey::Single(key) => {
            if !verify_bytes(
                key,
                &alg,
                decoded.signing_input.as_bytes(),
                &decoded.signature,
            ) {
                return Err(JoseError::SignatureFailed);
            }
        }
    }
    check_claims(&decoded, options)?;
    Ok(decoded)
}

/// The claim checks of `jwtVerify` (`validateClaimsSet`).
pub fn check_claims(decoded: &Decoded, options: &VerifyOptions) -> Result<(), JoseError> {
    let payload = &decoded.payload;
    if let Some(typ) = &options.typ {
        let actual = str_member(&decoded.header, "typ").unwrap_or_default();
        if normalize_typ(actual) != normalize_typ(typ) {
            return Err(JoseError::Claim(
                "unexpected \"typ\" JWT header value".into(),
            ));
        }
    }
    let mut required: Vec<String> = options.required_claims.clone();
    if options.issuer.is_some() {
        required.push("iss".into());
    }
    if options.audience.is_some() {
        required.push("aud".into());
    }
    if options.subject.is_some() {
        required.push("sub".into());
    }
    if options.max_token_age.is_some() {
        required.push("iat".into());
    }
    for claim in &required {
        if !payload.contains_key(claim) {
            return Err(JoseError::Claim(format!(
                "missing required \"{claim}\" claim"
            )));
        }
    }
    if let Some(issuers) = &options.issuer
        && !str_member(payload, "iss").is_some_and(|iss| issuers.iter().any(|value| value == iss))
    {
        return Err(JoseError::Claim("unexpected \"iss\" claim value".into()));
    }
    if let Some(subject) = &options.subject
        && str_member(payload, "sub") != Some(subject.as_str())
    {
        return Err(JoseError::Claim("unexpected \"sub\" claim value".into()));
    }
    if let Some(audiences) = &options.audience {
        let matches = match payload.get("aud") {
            Some(Value::String(aud)) => audiences.contains(aud),
            Some(Value::Array(values)) => values
                .iter()
                .filter_map(Value::as_str)
                .any(|aud| audiences.iter().any(|wanted| wanted == aud)),
            _ => false,
        };
        if !matches {
            return Err(JoseError::Claim("unexpected \"aud\" claim value".into()));
        }
    }
    let now = options
        .current_date
        .unwrap_or_else(|| (js::now_ms() / 1000.0).floor());
    let tolerance = options.clock_tolerance;
    let number = |name: &str| -> Result<Option<f64>, JoseError> {
        match payload.get(name) {
            None => Ok(None),
            Some(Value::Number(value)) => Ok(value.as_f64()),
            Some(_) => Err(JoseError::Claim(format!(
                "\"{name}\" claim must be a number"
            ))),
        }
    };
    let iat = number("iat")?;
    if let Some(max_age) = options.max_token_age {
        let iat = iat.unwrap_or_default();
        let age = now - iat;
        if age - tolerance > max_age {
            return Err(JoseError::Claim(
                "\"iat\" claim timestamp check failed (too far in the past)".into(),
            ));
        }
        if age < -tolerance {
            return Err(JoseError::Claim(
                "\"iat\" claim timestamp check failed (it should be in the past)".into(),
            ));
        }
    }
    if let Some(nbf) = number("nbf")?
        && nbf > now + tolerance
    {
        return Err(JoseError::Claim(
            "\"nbf\" claim timestamp check failed".into(),
        ));
    }
    if let Some(exp) = number("exp")?
        && exp <= now - tolerance
    {
        return Err(JoseError::Claim(
            "\"exp\" claim timestamp check failed".into(),
        ));
    }
    Ok(())
}

/// A signing key of a provider key set: the JWK, its kid and the algorithms it serves.
#[derive(Debug, Clone)]
pub struct SigningKey {
    pub jwk: Map<String, Value>,
    pub kid: Option<String>,
    pub algorithms: Vec<&'static str>,
    pub key: Key,
}

/// The `kid` oidc-provider derives for a key without one (SHA-256 over its public components, base64url).
pub fn calculate_kid(jwk: &Map<String, Value>) -> Option<String> {
    let members = match str_member(jwk, "kty") {
        Some("RSA") => json!({"e": jwk.get("e"), "kty": "RSA", "n": jwk.get("n")}),
        Some("EC") => {
            json!({"crv": jwk.get("crv"), "kty": "EC", "x": jwk.get("x"), "y": jwk.get("y")})
        }
        Some("OKP") => json!({"crv": jwk.get("crv"), "kty": "OKP", "x": jwk.get("x")}),
        _ => return None,
    };
    Some(sha256_b64url(&js::stringify(&members)))
}

/// Constant-time string comparison (`constantEquals`).
pub fn constant_equals(left: &str, right: &str) -> bool {
    use subtle::ConstantTimeEq;
    left.len() == right.len() && bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}
