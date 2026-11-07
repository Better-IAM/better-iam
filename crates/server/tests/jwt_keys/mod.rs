//! Test-only JWT helpers (port of `tests/support/jwt-keys.ts`), built on the RustCrypto primitives directly, so tests
//! can play an external identity provider or forge IAM session JWTs without depending on the code under test.

#![allow(dead_code)]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use serde_json::{Map, Value, json};

/// A test signing key.
#[derive(Clone)]
pub struct TestKey {
    pub kid: String,
    pub alg: String,
    /// The private JWK, with `kid` and `alg`.
    pub private_jwk: Map<String, Value>,
    /// The public JWK, with `kid`, `alg` and `use: 'sig'`.
    pub public_jwk: Map<String, Value>,
    secret: Secret,
}

#[derive(Clone)]
enum Secret {
    Ed25519(Box<ed25519_dalek::SigningKey>),
    P256(Box<p256::ecdsa::SigningKey>),
    P384(Box<p384::ecdsa::SigningKey>),
    Rsa(Box<rsa::RsaPrivateKey>),
}

pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn jwk(members: Value) -> Map<String, Value> {
    members.as_object().cloned().unwrap_or_default()
}

/// Generates a fresh signing key pair for an algorithm (`EdDSA`, `ES256`, `ES384`, `RS256`, `PS256`; RSA keys are 2048
/// bits).
pub fn generate_test_key(alg: &str, kid: &str) -> TestKey {
    let mut rng = rand::thread_rng();
    let (private_jwk, public_jwk, secret) = match alg {
        "EdDSA" => {
            let mut seed = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rng, &mut seed);
            let key = ed25519_dalek::SigningKey::from_bytes(&seed);
            let x = b64(key.verifying_key().as_bytes());
            (
                jwk(json!({ "crv": "Ed25519", "d": b64(&key.to_bytes()), "x": x, "kty": "OKP" })),
                jwk(json!({ "crv": "Ed25519", "x": x, "kty": "OKP" })),
                Secret::Ed25519(Box::new(key)),
            )
        }
        "ES256" => {
            let key = p256::ecdsa::SigningKey::random(&mut rng);
            let point = key.verifying_key().to_encoded_point(false);
            let (x, y) = (b64(point.x().unwrap()), b64(point.y().unwrap()));
            (
                jwk(
                    json!({ "kty": "EC", "x": x, "y": y, "crv": "P-256", "d": b64(&key.to_bytes()) }),
                ),
                jwk(json!({ "kty": "EC", "x": x, "y": y, "crv": "P-256" })),
                Secret::P256(Box::new(key)),
            )
        }
        "ES384" => {
            let key = p384::ecdsa::SigningKey::random(&mut rng);
            let point = key.verifying_key().to_encoded_point(false);
            let (x, y) = (b64(point.x().unwrap()), b64(point.y().unwrap()));
            (
                jwk(
                    json!({ "kty": "EC", "x": x, "y": y, "crv": "P-384", "d": b64(&key.to_bytes()) }),
                ),
                jwk(json!({ "kty": "EC", "x": x, "y": y, "crv": "P-384" })),
                Secret::P384(Box::new(key)),
            )
        }
        _ => {
            return rsa_test_key(rsa_key(2048), alg, kid);
        }
    };
    finish(private_jwk, public_jwk, secret, alg, kid)
}

/// A test key around an RSA private key (any size).
pub fn rsa_test_key(key: rsa::RsaPrivateKey, alg: &str, kid: &str) -> TestKey {
    let n = b64(&key.n().to_bytes_be());
    let e = b64(&key.e().to_bytes_be());
    let primes = key.primes();
    let private_jwk = jwk(json!({
        "kty": "RSA", "n": n, "e": e, "d": b64(&key.d().to_bytes_be()),
        "p": b64(&primes[0].to_bytes_be()), "q": b64(&primes[1].to_bytes_be()),
    }));
    let public_jwk = jwk(json!({ "kty": "RSA", "n": n, "e": e }));
    finish(
        private_jwk,
        public_jwk,
        Secret::Rsa(Box::new(key)),
        alg,
        kid,
    )
}

fn finish(
    mut private_jwk: Map<String, Value>,
    mut public_jwk: Map<String, Value>,
    secret: Secret,
    alg: &str,
    kid: &str,
) -> TestKey {
    for map in [&mut private_jwk, &mut public_jwk] {
        map.insert("kid".into(), Value::from(kid));
        map.insert("alg".into(), Value::from(alg));
    }
    public_jwk.insert("use".into(), Value::from("sig"));
    TestKey {
        kid: kid.to_owned(),
        alg: alg.to_owned(),
        private_jwk,
        public_jwk,
        secret,
    }
}

/// An RSA private key of `bits` bits.
pub fn rsa_key(bits: usize) -> rsa::RsaPrivateKey {
    rsa::RsaPrivateKey::new(&mut rand::thread_rng(), bits).expect("rsa key")
}

/// What signs a test token.
pub enum Signer<'a> {
    Key(&'a TestKey),
    Hs256(&'a [u8]),
    None,
}

fn encode(value: &Value) -> String {
    b64(better_iam_core::js::stringify(value).as_bytes())
}

fn signature(signer: &Signer<'_>, data: &[u8]) -> String {
    use p256::ecdsa::signature::{RandomizedSigner, Signer as _};
    match signer {
        Signer::None => String::new(),
        Signer::Hs256(secret) => {
            use hmac::Mac;
            let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(secret).expect("hmac");
            mac.update(data);
            b64(&mac.finalize().into_bytes())
        }
        Signer::Key(key) => match (&key.secret, key.alg.as_str()) {
            (Secret::Ed25519(secret), _) => b64(&secret.sign(data).to_bytes()),
            (Secret::P256(secret), _) => {
                let signature: p256::ecdsa::Signature = secret.sign(data);
                b64(&signature.to_bytes())
            }
            (Secret::P384(secret), _) => {
                let signature: p384::ecdsa::Signature = secret.sign(data);
                b64(&signature.to_bytes())
            }
            (Secret::Rsa(secret), "PS256") => {
                let signing = rsa::pss::BlindedSigningKey::<sha2::Sha256>::new(*secret.clone());
                let signature = signing.sign_with_rng(&mut rand::thread_rng(), data);
                b64(&rsa::signature::SignatureEncoding::to_vec(&signature))
            }
            (Secret::Rsa(secret), _) => {
                let signing = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(*secret.clone());
                let signature = signing.sign(data);
                b64(&rsa::signature::SignatureEncoding::to_vec(&signature))
            }
        },
    }
}

fn signer_alg(signer: &Signer<'_>) -> &'static str {
    match signer {
        Signer::None => "none",
        Signer::Hs256(_) => "HS256",
        Signer::Key(key) => match key.alg.as_str() {
            "EdDSA" => "EdDSA",
            "ES256" => "ES256",
            "ES384" => "ES384",
            "PS256" => "PS256",
            _ => "RS256",
        },
    }
}

/// Signs a compact JWT. The header defaults to `{ alg, typ: 'JWT', kid }` for the key; `header` entries override it
/// (a `null` entry removes the member), and the signature always uses the key's real algorithm.
pub fn sign_test_jwt(signer: Signer<'_>, payload: &Value, header: Value) -> String {
    let mut merged = Map::new();
    merged.insert("alg".into(), Value::from(signer_alg(&signer)));
    merged.insert("typ".into(), Value::from("JWT"));
    if let Signer::Key(key) = &signer {
        merged.insert("kid".into(), Value::from(key.kid.clone()));
    }
    if let Value::Object(header) = header {
        for (name, value) in header {
            if value.is_null() {
                merged.shift_remove(&name);
            } else {
                merged.insert(name, value);
            }
        }
    }
    let input = format!("{}.{}", encode(&Value::Object(merged)), encode(payload));
    let signature = signature(&signer, input.as_bytes());
    format!("{input}.{signature}")
}

/// Decodes a compact JWT without verifying it: `(header, payload)`.
pub fn decode_test_jwt(token: &str) -> (Value, Value) {
    let parts: Vec<&str> = token.split('.').collect();
    let decode = |part: &str| {
        let bytes = URL_SAFE_NO_PAD.decode(part).expect("base64url");
        better_iam_core::js::parse(&String::from_utf8(bytes).expect("utf8")).expect("json")
    };
    (decode(parts[0]), decode(parts[1]))
}

/// Rewrites the payload (merging `patch`) while keeping the original header and signature.
pub fn tamper_payload(token: &str, patch: Value) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    let (_, mut payload) = decode_test_jwt(token);
    if let (Value::Object(payload), Value::Object(patch)) = (&mut payload, patch) {
        for (name, value) in patch {
            payload.insert(name, value);
        }
    }
    format!(
        "{}.{}.{}",
        parts[0],
        encode(&payload),
        parts.get(2).unwrap_or(&"")
    )
}
