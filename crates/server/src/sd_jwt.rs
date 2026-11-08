//! Port of `packages/server/src/sd-jwt.ts`.
//!
//! Selective Disclosure JWTs (RFC 9901) as SD-JWT VCs (IETF SD-JWT-based Verifiable Credentials), the Token Status
//! List (IETF OAuth Status List) that revokes them, and OpenID4VCI holder proofs. Pure functions over the JOSE
//! operations of `session_tokens::jose` (jose's check order): issuing, presenting with key binding, and verifying.
//! Storage and policy live in vc.rs.
//!
//! TypeScript's `SdJwtError` is not an `IamError`: callers catch it (`error instanceof SdJwtError`) and read its
//! `reason`. Here the functions that can throw both fail with [`VerifyFailure`], which keeps the two apart; an
//! `SdJwtError` that escapes to the HTTP layer or the conformance server is answered as TypeScript answers any
//! exception that is not an `IamError` (INTERNAL_ERROR 500).

use std::future::Future;
use std::pin::Pin;

use better_iam_core::js::{number_value, strict_equal, utf16_len};
use better_iam_core::{IamError, IamResult};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::js::{ThrownError, number, truthy};
use crate::session_tokens::jose::{
    self, JoseError, VerifyKey, decode_base64url, decode_protected_header, encode_base64url,
};

/// The `typ` of an SD-JWT VC (`vc+sd-jwt`, the earlier name, is accepted when verifying).
pub const SD_JWT_VC_TYPE: &str = "dc+sd-jwt";
pub const KB_JWT_TYPE: &str = "kb+jwt";
pub const STATUS_LIST_JWT_TYPE: &str = "statuslist+jwt";
pub const HOLDER_PROOF_TYPE: &str = "openid4vci-proof+jwt";
/// Signature algorithms accepted from holders and issuers.
pub const SD_JWT_ALGORITHMS: &[&str] = &["ES256", "ES384", "EdDSA"];

/// Status values of the Token Status List.
pub const STATUS_VALID: f64 = 0.0;
pub const STATUS_INVALID: f64 = 1.0;
pub const STATUS_SUSPENDED: f64 = 2.0;

/// Claims that are never selectively disclosable and never come from a disclosure.
/// A `Set` in TypeScript.
pub const RESERVED_VC_CLAIMS: &[&str] = &[
    "iss",
    "sub",
    "iat",
    "nbf",
    "exp",
    "cnf",
    "vct",
    "vct#integrity",
    "status",
    "jti",
    "aud",
    "_sd",
    "_sd_alg",
    "...",
    // Never object keys that change an object's prototype.
    "__proto__",
    "constructor",
    "prototype",
];

fn reserved(name: &str) -> bool {
    RESERVED_VC_CLAIMS.contains(&name)
}

/// A presentation or credential that did not verify, with the reason (`SdJwtFailure`: `malformed`,
/// `unsupported-type`, `unknown-issuer`, `bad-signature`, `expired`, `not-yet-valid`, `bad-disclosure`,
/// `key-binding-required`, `bad-key-binding`, `wrong-audience`, `wrong-nonce`, `stale-key-binding`, `revoked`,
/// `suspended`, `status-unavailable`).
#[derive(Debug, Clone, PartialEq)]
pub struct SdJwtError {
    pub reason: String,
    pub message: String,
}

impl SdJwtError {
    /// `new SdJwtError(reason, message)`.
    pub fn new(reason: &str, message: impl Into<String>) -> Self {
        Self {
            reason: reason.to_owned(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for SdJwtError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SdJwtError {}

/// Not an `IamError` in TypeScript: where one escapes, the server answers INTERNAL_ERROR.
impl From<SdJwtError> for IamError {
    fn from(_: SdJwtError) -> Self {
        crate::js::internal_error()
    }
}

/// What a function that can throw both an `SdJwtError` and anything else fails with.
#[derive(Debug, Clone, PartialEq)]
pub enum VerifyFailure {
    /// `error instanceof SdJwtError`.
    SdJwt(SdJwtError),
    /// Any other exception (an `IamError`, or a JavaScript error answered as INTERNAL_ERROR).
    Other(IamError),
}

impl VerifyFailure {
    /// The `SdJwtError`, when it is one.
    pub fn sd_jwt(&self) -> Option<&SdJwtError> {
        match self {
            Self::SdJwt(error) => Some(error),
            Self::Other(_) => None,
        }
    }
}

impl From<SdJwtError> for VerifyFailure {
    fn from(error: SdJwtError) -> Self {
        Self::SdJwt(error)
    }
}

impl From<IamError> for VerifyFailure {
    fn from(error: IamError) -> Self {
        Self::Other(error)
    }
}

impl From<VerifyFailure> for IamError {
    fn from(failure: VerifyFailure) -> Self {
        match failure {
            VerifyFailure::SdJwt(error) => error.into(),
            VerifyFailure::Other(error) => error,
        }
    }
}

/// `value.slice(0, length)` in UTF-16 code units (a pair cut in half is dropped).
pub(crate) fn slice_utf16(value: &str, length: usize) -> String {
    let mut out = String::new();
    let mut units = 0;
    for c in value.chars() {
        units += c.len_utf16();
        if units > length {
            break;
        }
        out.push(c);
    }
    out
}

/// `Buffer.from(text, 'ascii')`: one byte per UTF-16 code unit (its low byte).
fn ascii_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16().map(|unit| unit as u8).collect()
}

/// `createHash('sha256').update(encoded, 'ascii').digest('base64url')`.
fn digest_of(encoded: &str) -> String {
    encode_base64url(&Sha256::digest(ascii_bytes(encoded)))
}

/// `randomBytes(n)`.
pub(crate) fn random_bytes(length: usize) -> Vec<u8> {
    better_iam_auth::crypto::random_bytes(length)
}

/// `crypto.randomInt(max)`: a uniform integer in `[0, max)` (rejection sampling over 48 random bits, as Node).
pub(crate) fn random_int(max: u64) -> u64 {
    if max <= 1 {
        return 0;
    }
    const RANGE: u64 = 1 << 48;
    let limit = RANGE - (RANGE % max);
    loop {
        let bytes = random_bytes(6);
        let mut value = 0u64;
        for byte in bytes {
            value = (value << 8) | u64::from(byte);
        }
        if value < limit {
            return value % max;
        }
    }
}

/// `ToInt32(value)`.
fn to_int32(value: f64) -> i32 {
    if !value.is_finite() {
        return 0;
    }
    let truncated = value.trunc();
    let modulo = truncated.rem_euclid(4_294_967_296.0);
    let unsigned = modulo as u64 as u32;
    unsigned as i32
}

/// The shift count of `a << b` / `a >> b` (`ToUint32(b) & 31`).
fn shift_count(value: f64) -> u32 {
    (to_int32(value) as u32) & 31
}

/// A JavaScript number as a JSON value.
fn num(value: f64) -> Value {
    number(value)
}

/// The private key an issuer or a holder signs with (`KeyObject | CryptoKey`).
#[derive(Clone)]
pub enum SigningKey {
    /// ES256.
    P256(p256::ecdsa::SigningKey),
    /// ES384.
    P384(p384::ecdsa::SigningKey),
    /// EdDSA.
    Ed25519(ed25519_dalek::SigningKey),
}

/// A public key handed to a verifier as a key object rather than a JWK.
#[derive(Clone)]
pub enum PublicKey {
    P256(p256::ecdsa::VerifyingKey),
    P384(p384::ecdsa::VerifyingKey),
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl PublicKey {
    fn verify_key(&self) -> VerifyKey {
        match self {
            Self::P256(key) => VerifyKey::P256(*key),
            Self::P384(key) => VerifyKey::P384(*key),
            Self::Ed25519(key) => VerifyKey::Ed25519(Some(*key)),
        }
    }
}

/// What resolves a verification key: a key object, or a JWK (`'kty' in found`).
#[derive(Clone)]
pub enum VerificationKey {
    Key(PublicKey),
    Jwk(Map<String, Value>),
}

/// `new SignJWT(payload).setProtectedHeader(header).sign(key)`: the compact JWS. A key that does not fit the header's
/// `alg` is jose's TypeError.
pub fn sign_jwt(
    header: &Map<String, Value>,
    payload: &Map<String, Value>,
    key: &SigningKey,
) -> IamResult<String> {
    use p256::ecdsa::signature::Signer;
    let alg = header.get("alg").and_then(Value::as_str).unwrap_or("");
    let fits = matches!(
        (alg, key),
        ("ES256", SigningKey::P256(_))
            | ("ES384", SigningKey::P384(_))
            | ("EdDSA", SigningKey::Ed25519(_))
    );
    if !fits {
        return Err(
            ThrownError::type_error("Key for the algorithm must be of a matching type").into(),
        );
    }
    let mut input = encode_base64url(better_iam_core::js::stringify_object(header).as_bytes());
    input.push('.');
    input.push_str(&encode_base64url(
        better_iam_core::js::stringify_object(payload).as_bytes(),
    ));
    let signature: Vec<u8> = match key {
        SigningKey::P256(key) => {
            let signature: p256::ecdsa::Signature = key.sign(input.as_bytes());
            signature.to_bytes().to_vec()
        }
        SigningKey::P384(key) => {
            let signature: p384::ecdsa::Signature = key.sign(input.as_bytes());
            signature.to_bytes().to_vec()
        }
        SigningKey::Ed25519(key) => key.sign(input.as_bytes()).to_bytes().to_vec(),
    };
    input.push('.');
    input.push_str(&encode_base64url(&signature));
    Ok(input)
}

/// `importJWK(jwk, alg)` for the signature algorithms of SD-JWT VCs, then the usage checks `jwtVerify` makes on the
/// imported key: Err when the import fails, Ok(None) for a key that imports but cannot verify (a private key, or
/// `key_ops` without `verify`), Ok(Some) for a usable public key.
fn import_jwk(jwk: &Map<String, Value>, alg: &str) -> Result<Option<VerifyKey>, ()> {
    // normalizeJwk.
    if !matches!(jwk.get("ext"), None | Some(Value::Bool(_))) {
        return Err(());
    }
    let mut key_ops: Option<Vec<&str>> = None;
    if let Some(ops) = jwk.get("key_ops") {
        let Value::Array(ops) = ops else {
            return Err(());
        };
        let mut seen: Vec<&str> = Vec::new();
        for op in ops {
            let Some(op) = op.as_str() else {
                return Err(());
            };
            if seen.contains(&op) {
                return Err(());
            }
            seen.push(op);
        }
        key_ops = Some(seen);
    }
    let kty = jwk.get("kty").and_then(Value::as_str);
    if kty == Some("oct") {
        // A secret: imported as bytes, which no asymmetric algorithm verifies with.
        return match jwk.get("k") {
            Some(Value::String(_)) => Ok(None),
            _ => Err(()),
        };
    }
    let (wanted_kty, crv) = match alg {
        "ES256" => ("EC", "P-256"),
        "ES384" => ("EC", "P-384"),
        "EdDSA" => ("OKP", "Ed25519"),
        _ => return Err(()),
    };
    if kty != Some(wanted_kty) {
        return Err(());
    }
    let private = truthy(jwk.get("d")) || truthy(jwk.get("priv"));
    // WebCrypto: a public key may only be used to verify.
    if !private
        && let Some(ops) = &key_ops
        && ops.iter().any(|op| *op != "verify")
    {
        return Err(());
    }
    if jwk.get("crv").and_then(Value::as_str) != Some(crv) {
        return Err(());
    }
    let bytes = |name: &str| -> Result<Vec<u8>, ()> {
        jwk.get(name)
            .and_then(Value::as_str)
            .and_then(decode_base64url)
            .ok_or(())
    };
    let key = match crv {
        "P-256" => {
            let (x, y) = (bytes("x")?, bytes("y")?);
            if x.len() != 32 || y.len() != 32 {
                return Err(());
            }
            let point = p256::EncodedPoint::from_affine_coordinates(
                x.as_slice().into(),
                y.as_slice().into(),
                false,
            );
            VerifyKey::P256(p256::ecdsa::VerifyingKey::from_encoded_point(&point).map_err(|_| ())?)
        }
        "P-384" => {
            let (x, y) = (bytes("x")?, bytes("y")?);
            if x.len() != 48 || y.len() != 48 {
                return Err(());
            }
            let point = p384::EncodedPoint::from_affine_coordinates(
                x.as_slice().into(),
                y.as_slice().into(),
                false,
            );
            VerifyKey::P384(p384::ecdsa::VerifyingKey::from_encoded_point(&point).map_err(|_| ())?)
        }
        _ => {
            let x: [u8; 32] = bytes("x")?.try_into().map_err(|_| ())?;
            // Imported (as OpenSSL does) even when the bytes are no curve point; such a key never verifies.
            VerifyKey::Ed25519(ed25519_dalek::VerifyingKey::from_bytes(&x).ok())
        }
    };
    if private {
        // Imported as a private key, which `jwtVerify` refuses to verify with.
        return Ok(None);
    }
    if key_ops.as_ref().is_some_and(|ops| !ops.contains(&"verify")) {
        return Ok(None);
    }
    Ok(Some(key))
}

/// `jwtVerify(token, key, { algorithms, audience?, currentDate, clockTolerance })`.
async fn verify_with(
    token: &str,
    key: Option<VerifyKey>,
    algorithms: &[String],
    audience: Option<&[String]>,
    now: f64,
    tolerance: f64,
) -> Result<Map<String, Value>, JoseError> {
    let tolerance = num(tolerance);
    let options = jose::VerifyOptions {
        algorithms,
        issuer: None,
        audience,
        typ: None,
        required_claims: &[],
        clock_tolerance: Some(&tolerance),
        current_ms: now,
        max_token_age: None,
    };
    jose::jwt_verify(
        token,
        move |_| async move { key.ok_or(JoseError::TypeError) },
        &options,
    )
    .await
}

/// `decodeJwt(jwt)`: the claims of a compact JWS, unverified.
fn decode_jwt(jwt: &str) -> Option<Map<String, Value>> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 || parts[1].is_empty() {
        return None;
    }
    let bytes = decode_base64url(parts[1])?;
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&bytes);
    let text = std::str::from_utf8(bytes).ok()?;
    match better_iam_core::js::parse(text).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

fn str_member<'a>(map: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    map.get(name).and_then(Value::as_str)
}

fn number_member(map: &Map<String, Value>, name: &str) -> Option<f64> {
    match map.get(name) {
        Some(Value::Number(value)) => Some(number_value(value)),
        _ => None,
    }
}

fn algorithm_allowed(alg: Option<&Value>) -> bool {
    matches!(alg, Some(Value::String(alg)) if SD_JWT_ALGORITHMS.contains(&alg.as_str()))
}

/// One disclosure: `[salt, name, value]`, base64url-encoded JSON, and its SHA-256 digest.
#[derive(Debug, Clone, PartialEq)]
pub struct SdJwtDisclosure {
    pub encoded: String,
    pub digest: String,
    pub name: String,
    pub value: Value,
}

/// `createDisclosure(name, value)`.
pub fn create_disclosure(name: &str, value: &Value) -> SdJwtDisclosure {
    let salt = encode_base64url(&random_bytes(16));
    let text = better_iam_core::js::stringify(&json!([salt, name, value]));
    let encoded = encode_base64url(text.as_bytes());
    SdJwtDisclosure {
        digest: digest_of(&encoded),
        encoded,
        name: name.to_owned(),
        value: value.clone(),
    }
}

/// The input of [`issue_sd_jwt`].
pub struct IssueSdJwtInput<'a> {
    pub alg: &'a str,
    pub kid: &'a str,
    pub key: &'a SigningKey,
    pub typ: Option<&'a str>,
    pub plain: &'a Map<String, Value>,
    pub disclosable: &'a Map<String, Value>,
    pub decoys: Option<usize>,
}

/// What [`issue_sd_jwt`] returns.
#[derive(Debug, Clone, PartialEq)]
pub struct IssuedSdJwt {
    pub sd_jwt: String,
    pub jwt: String,
    pub disclosures: Vec<SdJwtDisclosure>,
}

/// Issues an SD-JWT: `plain` claims are visible to anyone holding the credential; each `disclosable` claim becomes
/// a disclosure the holder decides to reveal or keep. Random decoy digests hide how many claims exist. Returns the
/// issued form `<jwt>~<disclosure>~...~` and its parts.
pub fn issue_sd_jwt(input: &IssueSdJwtInput<'_>) -> Result<IssuedSdJwt, VerifyFailure> {
    // What a verifier refuses to accept from a disclosure is never issued as one.
    for name in input.disclosable.keys() {
        if reserved(name) || input.plain.contains_key(name) {
            return Err(SdJwtError::new(
                "bad-disclosure",
                format!(
                    "{} cannot be selectively disclosable",
                    slice_utf16(name, 64)
                ),
            )
            .into());
        }
    }
    let disclosures: Vec<SdJwtDisclosure> = input
        .disclosable
        .iter()
        .map(|(name, value)| create_disclosure(name, value))
        .collect();
    let decoys: Vec<String> = (0..input.decoys.unwrap_or(0))
        .map(|_| digest_of(&encode_base64url(&random_bytes(32))))
        .collect();
    let mut payload = input.plain.clone();
    if !disclosures.is_empty() || !decoys.is_empty() {
        let mut digests: Vec<String> = disclosures.iter().map(|item| item.digest.clone()).collect();
        digests.extend(decoys);
        crate::js::sort_strings(&mut digests);
        payload.insert(
            "_sd".into(),
            Value::Array(digests.into_iter().map(Value::String).collect()),
        );
        payload.insert("_sd_alg".into(), Value::String("sha-256".into()));
    }
    let mut header = Map::new();
    header.insert("alg".into(), Value::String(input.alg.to_owned()));
    header.insert("kid".into(), Value::String(input.kid.to_owned()));
    header.insert(
        "typ".into(),
        Value::String(input.typ.unwrap_or(SD_JWT_VC_TYPE).to_owned()),
    );
    let jwt = sign_jwt(&header, &payload, input.key)?;
    let mut sd_jwt = format!("{jwt}~");
    for item in &disclosures {
        sd_jwt.push_str(&item.encoded);
        sd_jwt.push('~');
    }
    Ok(IssuedSdJwt {
        sd_jwt,
        jwt,
        disclosures,
    })
}

/// The parts of `<jwt>~<d1>~...~<dn>~[<kb-jwt>]`.
#[derive(Debug, Clone, PartialEq)]
pub struct SplitSdJwt {
    pub jwt: String,
    pub disclosures: Vec<String>,
    pub key_binding: Option<String>,
}

/// Splits `<jwt>~<d1>~...~<dn>~[<kb-jwt>]`.
pub fn split_sd_jwt(value: &str) -> Result<SplitSdJwt, SdJwtError> {
    if utf16_len(value) > 65536 || !value.contains('~') {
        return Err(SdJwtError::new("malformed", "Not an SD-JWT"));
    }
    let parts: Vec<&str> = value.split('~').collect();
    let jwt = parts[0];
    let last = parts[parts.len() - 1];
    let disclosures = &parts[1..parts.len() - 1];
    if jwt.is_empty() || disclosures.iter().any(|item| item.is_empty()) {
        return Err(SdJwtError::new("malformed", "Not an SD-JWT"));
    }
    Ok(SplitSdJwt {
        jwt: jwt.to_owned(),
        disclosures: disclosures.iter().map(|item| (*item).to_owned()).collect(),
        key_binding: (!last.is_empty()).then(|| last.to_owned()),
    })
}

/// Decodes a disclosure without trusting it (for wallets choosing what to reveal): its name and value.
pub fn read_disclosure(encoded: &str) -> Result<(String, Value), SdJwtError> {
    let bytes = better_iam_auth::util::node_base64_decode(encoded);
    let text = String::from_utf8_lossy(&bytes);
    let Ok(decoded) = better_iam_core::js::parse(&text) else {
        return Err(SdJwtError::new(
            "bad-disclosure",
            "A disclosure is not base64url JSON",
        ));
    };
    match decoded {
        Value::Array(items) if items.len() == 3 && items[0].is_string() && items[1].is_string() => {
            let name = items[1].as_str().unwrap_or_default().to_owned();
            Ok((name, items[2].clone()))
        }
        _ => Err(SdJwtError::new(
            "bad-disclosure",
            "A disclosure is not [salt, name, value]",
        )),
    }
}

/// Which disclosures a presentation keeps (`string[] | 'all'`).
#[derive(Debug, Clone, PartialEq)]
pub enum Disclose {
    All,
    Names(Vec<String>),
}

/// The options of [`present_sd_jwt`].
pub struct PresentOptions<'a> {
    pub disclose: Disclose,
    pub holder_key: &'a SigningKey,
    pub alg: &'a str,
    pub audience: &'a str,
    pub nonce: &'a str,
    /// Milliseconds (default `Date.now()`).
    pub issued_at: Option<f64>,
}

/// The holder's presentation: the credential with only the named claims disclosed, and a key-binding JWT signed with
/// the holder key over `aud`, `nonce`, `iat` and the hash of everything before it.
pub fn present_sd_jwt(
    credential: &str,
    options: &PresentOptions<'_>,
) -> Result<String, VerifyFailure> {
    let split = split_sd_jwt(credential)?;
    let mut kept: Vec<&String> = Vec::new();
    for encoded in &split.disclosures {
        let keep = match &options.disclose {
            Disclose::All => true,
            Disclose::Names(names) => names.contains(&read_disclosure(encoded)?.0),
        };
        if keep {
            kept.push(encoded);
        }
    }
    let mut presented = format!("{}~", split.jwt);
    for item in kept {
        presented.push_str(item);
        presented.push('~');
    }
    let issued_at = options.issued_at.unwrap_or_else(crate::utils::date_now);
    let mut payload = Map::new();
    payload.insert("aud".into(), Value::String(options.audience.to_owned()));
    payload.insert("nonce".into(), Value::String(options.nonce.to_owned()));
    payload.insert("iat".into(), num((issued_at / 1000.0).floor()));
    payload.insert("sd_hash".into(), Value::String(digest_of(&presented)));
    let mut header = Map::new();
    header.insert("alg".into(), Value::String(options.alg.to_owned()));
    header.insert("typ".into(), Value::String(KB_JWT_TYPE.to_owned()));
    let key_binding = sign_jwt(&header, &payload, options.holder_key)?;
    Ok(presented + &key_binding)
}

/// A verified credential: the issuer's claims plus the disclosed ones.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifiedSdJwt {
    #[serde(rename = "issuer")]
    pub issuer: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "vct", default, skip_serializing_if = "Option::is_none")]
    pub vct: Option<String>,
    /// Every claim: signed plain claims and the disclosures presented (never `_sd`/`_sd_alg`).
    #[serde(rename = "claims")]
    pub claims: Map<String, Value>,
    /// Names of the claims that came from disclosures.
    #[serde(rename = "disclosed")]
    pub disclosed: Vec<String>,
    #[serde(rename = "holderKey", default, skip_serializing_if = "Option::is_none")]
    pub holder_key: Option<Value>,
    /// `{ index, uri }` of the credential's status list entry.
    #[serde(rename = "status", default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Value>,
    #[serde(rename = "issuedAt", default, skip_serializing_if = "Option::is_none")]
    pub issued_at: Option<f64>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(rename = "keyBound")]
    pub key_bound: bool,
    /// The key-binding JWT's audience, nonce and time, for verifiers that check them themselves.
    #[serde(
        rename = "keyBinding",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub key_binding: Option<Value>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl VerifiedSdJwt {
    /// The object TypeScript returns, in its member order (numbers as JavaScript writes them).
    pub fn to_json(&self) -> Map<String, Value> {
        let mut out = Map::new();
        out.insert("issuer".into(), Value::String(self.issuer.clone()));
        out.insert("keyId".into(), Value::String(self.key_id.clone()));
        if let Some(vct) = &self.vct {
            out.insert("vct".into(), Value::String(vct.clone()));
        }
        out.insert("claims".into(), Value::Object(self.claims.clone()));
        out.insert(
            "disclosed".into(),
            Value::Array(self.disclosed.iter().cloned().map(Value::String).collect()),
        );
        if let Some(holder_key) = &self.holder_key {
            out.insert("holderKey".into(), holder_key.clone());
        }
        if let Some(status) = &self.status {
            out.insert("status".into(), status.clone());
        }
        if let Some(issued_at) = self.issued_at {
            out.insert("issuedAt".into(), num(issued_at));
        }
        if let Some(expires_at) = self.expires_at {
            out.insert("expiresAt".into(), num(expires_at));
        }
        out.insert("keyBound".into(), Value::Bool(self.key_bound));
        if let Some(key_binding) = &self.key_binding {
            out.insert("keyBinding".into(), key_binding.clone());
        }
        out
    }

    /// `status.index` and `status.uri`, when the credential names its status list entry.
    pub fn status_reference(&self) -> Option<(f64, String)> {
        let status = self.status.as_ref()?.as_object()?;
        Some((
            number_member(status, "index")?,
            str_member(status, "uri")?.to_owned(),
        ))
    }
}

/// `publicJwk(value)`: the holder key named by a credential or a proof, refused when it is not a public JWK.
fn public_jwk(value: Option<&Value>) -> Result<Map<String, Value>, SdJwtError> {
    let Some(Value::Object(jwk)) = value else {
        return Err(SdJwtError::new(
            "bad-key-binding",
            "The credential has no holder key",
        ));
    };
    if jwk.contains_key("d") || jwk.contains_key("k") {
        return Err(SdJwtError::new(
            "bad-key-binding",
            "The holder key must be public",
        ));
    }
    Ok(jwk.clone())
}

/// The future an issuer key resolver returns.
pub type IssuerKeyFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<VerificationKey>, VerifyFailure>> + Send + 'a>>;

/// `issuerKey(kid, issuer)`: the key that verifies the issuer's signature, None for an untrusted issuer or key.
pub type IssuerKeyFn<'a> = Box<dyn FnOnce(String, String) -> IssuerKeyFuture<'a> + Send + 'a>;

/// The options of [`verify_sd_jwt`].
pub struct VerifySdJwtOptions<'a> {
    pub issuer_key: IssuerKeyFn<'a>,
    /// Require a key-binding JWT (a presentation); default true.
    pub require_key_binding: Option<bool>,
    /// Compared with the key-binding JWT's `aud` by identity (`kb.aud !== audience`).
    pub audience: Option<Value>,
    /// Compared with the key-binding JWT's `nonce` by identity.
    pub nonce: Option<Value>,
    /// Milliseconds (default `Date.now()`).
    pub now: Option<f64>,
    /// Oldest acceptable key-binding `iat`, in seconds (default 300).
    pub max_key_binding_age_seconds: Option<f64>,
    pub clock_tolerance_seconds: Option<f64>,
}

impl<'a> VerifySdJwtOptions<'a> {
    /// Options with every default and the given key resolver.
    pub fn new(issuer_key: IssuerKeyFn<'a>) -> Self {
        Self {
            issuer_key,
            require_key_binding: None,
            audience: None,
            nonce: None,
            now: None,
            max_key_binding_age_seconds: None,
            clock_tolerance_seconds: None,
        }
    }
}

/// Verifies an SD-JWT VC or presentation: the issuer's signature (`issuerKey` resolves `kid`/`iss`), validity
/// times, every disclosure against the signed digests, and, for presentations, the key-binding JWT (`audience`,
/// `nonce`, freshness, `sd_hash`) with the holder key in `cnf.jwk`. Fails with `SdJwtError` and the reason.
pub async fn verify_sd_jwt(
    value: &str,
    options: VerifySdJwtOptions<'_>,
) -> Result<VerifiedSdJwt, VerifyFailure> {
    let SplitSdJwt {
        jwt,
        disclosures,
        key_binding,
    } = split_sd_jwt(value)?;
    let (Ok(header), Some(unverified)) = (decode_protected_header(&jwt), decode_jwt(&jwt)) else {
        return Err(SdJwtError::new("malformed", "The issuer JWT cannot be decoded").into());
    };
    let typ = str_member(&header, "typ");
    if typ != Some(SD_JWT_VC_TYPE) && typ != Some("vc+sd-jwt") {
        return Err(SdJwtError::new("unsupported-type", "Not an SD-JWT VC").into());
    }
    let kid = match header.get("kid") {
        Some(Value::String(kid)) if algorithm_allowed(header.get("alg")) => kid.clone(),
        _ => {
            return Err(SdJwtError::new("unsupported-type", "Unsupported issuer algorithm").into());
        }
    };
    let alg = str_member(&header, "alg").unwrap_or_default().to_owned();
    let Some(issuer) = str_member(&unverified, "iss").map(str::to_owned) else {
        return Err(SdJwtError::new("malformed", "The credential names no issuer").into());
    };
    let Some(found) = (options.issuer_key)(kid.clone(), issuer).await? else {
        return Err(
            SdJwtError::new("unknown-issuer", "The issuer or its key is not trusted").into(),
        );
    };
    let key = match found {
        VerificationKey::Key(key) => Some(key.verify_key()),
        VerificationKey::Jwk(jwk) => match import_jwk(&jwk, &alg) {
            Ok(key) => key,
            // The header names an algorithm the issuer's key does not have.
            Err(()) => {
                return Err(SdJwtError::new(
                    "unsupported-type",
                    "The issuer key does not match the credential algorithm",
                )
                .into());
            }
        },
    };
    let now = options.now.unwrap_or_else(crate::utils::date_now);
    let tolerance = options.clock_tolerance_seconds.unwrap_or(5.0);
    let payload = match verify_with(&jwt, key, std::slice::from_ref(&alg), None, now, tolerance)
        .await
    {
        Ok(payload) => payload,
        Err(JoseError::Expired { .. }) => {
            return Err(SdJwtError::new("expired", "The credential has expired").into());
        }
        Err(JoseError::ClaimValidation { .. }) => {
            return Err(SdJwtError::new("not-yet-valid", "The credential is not valid yet").into());
        }
        Err(_) => {
            return Err(
                SdJwtError::new("bad-signature", "The issuer signature does not verify").into(),
            );
        }
    };
    if let Some(sd_alg) = payload.get("_sd_alg")
        && sd_alg.as_str() != Some("sha-256")
    {
        return Err(SdJwtError::new("unsupported-type", "Unsupported disclosure digest").into());
    }
    let signed_digests: Vec<&str> = match payload.get("_sd") {
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    let mut digests: Vec<&str> = Vec::new();
    for digest in &signed_digests {
        if !digests.contains(digest) {
            digests.push(digest);
        }
    }
    if digests.len() != signed_digests.len() {
        return Err(SdJwtError::new("bad-disclosure", "The credential repeats a digest").into());
    }
    // No prototype: a claim named like an Object property stays data.
    let mut claims = payload.clone();
    claims.shift_remove("_sd");
    claims.shift_remove("_sd_alg");
    let mut used: Vec<String> = Vec::new();
    let mut disclosed: Vec<String> = Vec::new();
    for encoded in &disclosures {
        let digest = digest_of(encoded);
        if !digests.contains(&digest.as_str()) || used.contains(&digest) {
            return Err(SdJwtError::new(
                "bad-disclosure",
                "A disclosure was not signed by the issuer",
            )
            .into());
        }
        used.push(digest);
        let (name, claim) = read_disclosure(encoded)?;
        if reserved(&name) || claims.contains_key(&name) {
            return Err(SdJwtError::new(
                "bad-disclosure",
                format!(
                    "The disclosure of {} is not allowed",
                    slice_utf16(&name, 64)
                ),
            )
            .into());
        }
        claims.insert(name.clone(), claim);
        disclosed.push(name);
    }
    let cnf_jwk = match payload.get("cnf") {
        Some(Value::Object(cnf)) => cnf.get("jwk"),
        _ => None,
    };
    let holder_key = match cnf_jwk {
        Some(jwk) => Some(public_jwk(Some(jwk))?),
        None => None,
    };
    let mut key_binding_claims: Option<Value> = None;
    if let Some(key_binding) = &key_binding {
        let Some(holder_key) = &holder_key else {
            return Err(
                SdJwtError::new("bad-key-binding", "The credential has no holder key").into(),
            );
        };
        let Ok(kb_header) = decode_protected_header(key_binding) else {
            return Err(SdJwtError::new(
                "bad-key-binding",
                "The key-binding JWT cannot be decoded",
            )
            .into());
        };
        if str_member(&kb_header, "typ") != Some(KB_JWT_TYPE)
            || !algorithm_allowed(kb_header.get("alg"))
        {
            return Err(SdJwtError::new("bad-key-binding", "Not a key-binding JWT").into());
        }
        let kb_alg = str_member(&kb_header, "alg").unwrap_or_default().to_owned();
        let verified = match import_jwk(holder_key, &kb_alg) {
            Ok(key) => verify_with(
                key_binding,
                key,
                std::slice::from_ref(&kb_alg),
                None,
                now,
                tolerance,
            )
            .await
            .ok(),
            Err(()) => None,
        };
        let Some(kb) = verified else {
            return Err(SdJwtError::new(
                "bad-key-binding",
                "The key-binding signature does not verify",
            )
            .into());
        };
        let covered = &value[..value.len() - key_binding.len()];
        if str_member(&kb, "sd_hash") != Some(digest_of(covered).as_str()) {
            return Err(SdJwtError::new(
                "bad-key-binding",
                "The key-binding JWT covers another presentation",
            )
            .into());
        }
        if let Some(audience) = &options.audience
            && !kb.get("aud").is_some_and(|aud| strict_equal(aud, audience))
        {
            return Err(SdJwtError::new(
                "wrong-audience",
                "The presentation is for another verifier",
            )
            .into());
        }
        if let Some(nonce) = &options.nonce
            && !kb
                .get("nonce")
                .is_some_and(|value| strict_equal(value, nonce))
        {
            return Err(
                SdJwtError::new("wrong-nonce", "The presentation answers another request").into(),
            );
        }
        let iat = number_member(&kb, "iat");
        let age = now / 1000.0 - iat.unwrap_or(0.0);
        let max_age = options.max_key_binding_age_seconds.unwrap_or(300.0);
        let Some(iat) = iat.filter(|_| !(age > max_age || age < -tolerance)) else {
            return Err(SdJwtError::new("stale-key-binding", "The presentation is too old").into());
        };
        let mut claims = Map::new();
        if let Some(Value::String(aud)) = kb.get("aud") {
            claims.insert("audience".into(), Value::String(aud.clone()));
        }
        if let Some(Value::String(nonce)) = kb.get("nonce") {
            claims.insert("nonce".into(), Value::String(nonce.clone()));
        }
        claims.insert("issuedAt".into(), num(iat * 1000.0));
        key_binding_claims = Some(Value::Object(claims));
    } else if options.require_key_binding != Some(false) {
        return Err(SdJwtError::new(
            "key-binding-required",
            "A presentation needs a key-binding JWT",
        )
        .into());
    }
    let reference = match payload.get("status") {
        Some(Value::Object(status)) => status.get("status_list"),
        _ => None,
    };
    let status = match reference {
        Some(Value::Object(reference)) => match (reference.get("idx"), reference.get("uri")) {
            (Some(Value::Number(index)), Some(Value::String(uri))) => Some(json!({
                "index": num(number_value(index)),
                "uri": uri,
            })),
            _ => None,
        },
        _ => None,
    };
    Ok(VerifiedSdJwt {
        issuer: str_member(&payload, "iss").unwrap_or_default().to_owned(),
        key_id: kid,
        vct: str_member(&payload, "vct").map(str::to_owned),
        // A plain copy: spreading defines own properties, so no key can reach a prototype.
        claims,
        disclosed,
        holder_key: holder_key.map(Value::Object),
        status,
        issued_at: number_member(&payload, "iat").map(|iat| iat * 1000.0),
        expires_at: number_member(&payload, "exp").map(|exp| exp * 1000.0),
        key_bound: key_binding.is_some(),
        key_binding: key_binding_claims,
        extra: Map::new(),
    })
}

/// Reads the status of `index` from a raw list of `bits`-bit entries (index 0 is the low bits of byte 0).
pub fn status_at(bytes: &[u8], index: f64, bits: f64) -> Result<f64, SdJwtError> {
    let per_byte = 8.0 / bits;
    let position = (index / per_byte).floor();
    let byte = if position >= 0.0 && position < bytes.len() as f64 {
        Some(bytes[position as usize])
    } else {
        None
    };
    let Some(byte) = byte else {
        return Err(SdJwtError::new(
            "status-unavailable",
            "The status index is outside the list",
        ));
    };
    let shifted = i32::from(byte) >> shift_count((index % per_byte) * bits);
    let mask = (1i32 << shift_count(bits)).wrapping_sub(1);
    Ok(f64::from(shifted & mask))
}

/// Writes the status of `index` into a raw list. `RangeError` (INTERNAL_ERROR) for a position or value out of range.
pub fn set_status_at(bytes: &mut [u8], index: f64, bits: f64, value: f64) -> IamResult<()> {
    let per_byte = 8.0 / bits;
    let position = (index / per_byte).floor();
    let limit = f64::from(1i32 << shift_count(bits));
    if position >= bytes.len() as f64 || value < 0.0 || value >= limit {
        return Err(ThrownError::new("RangeError", "Status out of range").into());
    }
    let shift = shift_count((index % per_byte) * bits);
    let mask = (1i32 << shift_count(bits))
        .wrapping_sub(1)
        .wrapping_shl(shift);
    // A negative or NaN position is no index of the buffer: the write does nothing.
    if position.is_nan() || position < 0.0 {
        return Ok(());
    }
    let slot = &mut bytes[position as usize];
    let written = (i32::from(*slot) & !mask) | to_int32(value).wrapping_shl(shift);
    *slot = written as u8;
    Ok(())
}

/// The input of [`sign_status_list`].
pub struct SignStatusListInput<'a> {
    pub uri: &'a str,
    pub bytes: &'a [u8],
    pub bits: f64,
    pub alg: &'a str,
    pub kid: &'a str,
    pub key: &'a SigningKey,
    pub issued_at: f64,
    pub expires_at: f64,
    pub ttl_seconds: f64,
}

/// `deflateSync(bytes)`: zlib format, default compression.
fn deflate(bytes: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(bytes, 6)
}

/// A Status List Token (JWT, `typ: statuslist+jwt`) for a raw list.
pub fn sign_status_list(input: &SignStatusListInput<'_>) -> IamResult<String> {
    let mut payload = Map::new();
    payload.insert("sub".into(), Value::String(input.uri.to_owned()));
    payload.insert("iat".into(), num((input.issued_at / 1000.0).floor()));
    payload.insert("exp".into(), num((input.expires_at / 1000.0).floor()));
    payload.insert("ttl".into(), num(input.ttl_seconds));
    payload.insert(
        "status_list".into(),
        json!({ "bits": num(input.bits), "lst": encode_base64url(&deflate(input.bytes)) }),
    );
    let mut header = Map::new();
    header.insert("alg".into(), Value::String(input.alg.to_owned()));
    header.insert("kid".into(), Value::String(input.kid.to_owned()));
    header.insert("typ".into(), Value::String(STATUS_LIST_JWT_TYPE.to_owned()));
    sign_jwt(&header, &payload, input.key)
}

/// A raw status list read from a Status List Token.
#[derive(Debug, Clone, PartialEq)]
pub struct StatusList {
    pub bits: f64,
    pub bytes: Vec<u8>,
}

/// Verifies a Status List Token for `uri` and returns its raw list.
pub async fn read_status_list(
    token: &str,
    key: &VerificationKey,
    uri: &str,
    now: Option<f64>,
) -> Result<StatusList, SdJwtError> {
    let unavailable = || SdJwtError::new("status-unavailable", "The status list does not verify");
    let header = decode_protected_header(token).map_err(|_| unavailable())?;
    if str_member(&header, "typ") != Some(STATUS_LIST_JWT_TYPE) {
        return Err(unavailable());
    }
    let verifying = match key {
        VerificationKey::Key(key) => Some(key.verify_key()),
        VerificationKey::Jwk(jwk) => {
            let alg = str_member(&header, "alg").ok_or_else(unavailable)?;
            import_jwk(jwk, alg).map_err(|_| unavailable())?
        }
    };
    let algorithms: Vec<String> = SD_JWT_ALGORITHMS
        .iter()
        .map(|alg| (*alg).to_owned())
        .collect();
    let tolerance = num(5.0);
    let options = jose::VerifyOptions {
        algorithms: &algorithms,
        issuer: None,
        audience: None,
        typ: None,
        required_claims: &["iat"],
        clock_tolerance: Some(&tolerance),
        current_ms: now.unwrap_or_else(crate::utils::date_now),
        max_token_age: None,
    };
    let payload = jose::jwt_verify(
        token,
        move |_| async move { verifying.ok_or(JoseError::TypeError) },
        &options,
    )
    .await
    .map_err(|_| unavailable())?;
    if str_member(&payload, "sub") != Some(uri) {
        return Err(unavailable());
    }
    let Some(Value::Object(list)) = payload.get("status_list") else {
        return Err(unavailable());
    };
    let bits = number_member(list, "bits").filter(|bits| [1.0, 2.0, 4.0, 8.0].contains(bits));
    let (Some(bits), Some(lst)) = (bits, str_member(list, "lst")) else {
        return Err(unavailable());
    };
    let compressed = better_iam_auth::util::node_base64_decode(lst);
    let bytes =
        miniz_oxide::inflate::decompress_to_vec_zlib_with_limit(&compressed, 16 * 1024 * 1024)
            .map_err(|_| unavailable())?;
    Ok(StatusList { bits, bytes })
}

/// The options of [`verify_holder_proof`].
pub struct HolderProofOptions<'a> {
    pub audience: &'a str,
    /// Milliseconds (default `Date.now()`).
    pub now: Option<f64>,
    pub max_age_seconds: Option<f64>,
}

/// A verified holder proof: the holder's public key (only its key members), its RFC 7638 thumbprint, and the nonce.
#[derive(Debug, Clone, PartialEq)]
pub struct HolderProof {
    pub jwk: Map<String, Value>,
    pub thumbprint: String,
    pub nonce: Option<String>,
}

/// `calculateJwkThumbprint(jwk)` (SHA-256): the required members in lexicographic order.
pub fn jwk_thumbprint(jwk: &Map<String, Value>) -> IamResult<String> {
    let member = |name: &str| -> IamResult<Value> {
        match jwk.get(name) {
            Some(Value::String(value)) if !value.is_empty() => Ok(Value::String(value.clone())),
            _ => Err(ThrownError::new(
                "JWKInvalid",
                format!("\"{name}\" (Parameter) missing or invalid"),
            )
            .into()),
        }
    };
    let mut components = Map::new();
    match jwk.get("kty").and_then(Value::as_str) {
        Some("EC") => {
            components.insert("crv".into(), member("crv")?);
            components.insert("kty".into(), member("kty")?);
            components.insert("x".into(), member("x")?);
            components.insert("y".into(), member("y")?);
        }
        Some("OKP") => {
            components.insert("crv".into(), member("crv")?);
            components.insert("kty".into(), member("kty")?);
            components.insert("x".into(), member("x")?);
        }
        Some("RSA") => {
            components.insert("e".into(), member("e")?);
            components.insert("kty".into(), member("kty")?);
            components.insert("n".into(), member("n")?);
        }
        Some("oct") => {
            components.insert("k".into(), member("k")?);
            components.insert("kty".into(), member("kty")?);
        }
        _ => {
            return Err(ThrownError::new(
                "JOSENotSupported",
                "\"kty\" (Key Type) Parameter missing or unsupported",
            )
            .into());
        }
    }
    let serialized = better_iam_core::js::stringify_object(&components);
    Ok(encode_base64url(&Sha256::digest(serialized.as_bytes())))
}

/// `EmbeddedJWK`: the public key a token's `jwk` header names, for the header's `alg`.
fn embedded_jwk(header: &Map<String, Value>) -> Option<VerifyKey> {
    let Some(Value::Object(jwk)) = header.get("jwk") else {
        return None;
    };
    let alg = str_member(header, "alg")?;
    if jwk
        .get("use")
        .is_some_and(|use_| use_.as_str() != Some("sig"))
    {
        return None;
    }
    if jwk.get("alg").is_some_and(|own| own.as_str() != Some(alg)) {
        return None;
    }
    if truthy(jwk.get("d")) || truthy(jwk.get("priv")) {
        return None;
    }
    import_jwk(jwk, alg).ok().flatten()
}

/// Verifies an OpenID4VCI holder proof (`typ: openid4vci-proof+jwt`, the holder's public key in the `jwk` header):
/// signature, `aud` (the credential issuer), freshness, and the nonce the issuer handed out. Returns the holder key
/// and its RFC 7638 thumbprint.
pub async fn verify_holder_proof(
    proof: Option<&Value>,
    options: &HolderProofOptions<'_>,
) -> Result<HolderProof, VerifyFailure> {
    let proof = match proof {
        Some(Value::String(proof)) if utf16_len(proof) <= 8192 => proof.as_str(),
        _ => return Err(SdJwtError::new("malformed", "Invalid proof").into()),
    };
    let Ok(header) = decode_protected_header(proof) else {
        return Err(SdJwtError::new("malformed", "Invalid proof").into());
    };
    if str_member(&header, "typ") != Some(HOLDER_PROOF_TYPE)
        || !algorithm_allowed(header.get("alg"))
        || !truthy(header.get("jwk"))
    {
        return Err(SdJwtError::new(
            "malformed",
            "The proof must be an openid4vci-proof+jwt with a jwk header",
        )
        .into());
    }
    // OpenID4VCI: exactly one way to name the key.
    if header.contains_key("kid") || header.contains_key("x5c") {
        return Err(SdJwtError::new(
            "malformed",
            "A proof names its key with jwk only (no kid or x5c)",
        )
        .into());
    }
    let jwk = public_jwk(header.get("jwk"))?;
    let now = options.now.unwrap_or_else(crate::utils::date_now);
    let alg = str_member(&header, "alg").unwrap_or_default().to_owned();
    let audience = [options.audience.to_owned()];
    let key = embedded_jwk(&header);
    let payload = match verify_with(proof, key, &[alg], Some(&audience), now, 5.0).await {
        Ok(payload) => payload,
        Err(_) => {
            return Err(SdJwtError::new(
                "bad-key-binding",
                "The proof does not verify for this issuer",
            )
            .into());
        }
    };
    let iat = number_member(&payload, "iat");
    let age = now / 1000.0 - iat.unwrap_or(0.0);
    if iat.is_none() || age > options.max_age_seconds.unwrap_or(300.0) || age < -5.0 {
        return Err(SdJwtError::new("stale-key-binding", "The proof is too old").into());
    }
    let mut clean = Map::new();
    for name in ["kty", "crv", "x", "y", "n", "e"] {
        if let Some(value) = jwk.get(name) {
            clean.insert(name.to_owned(), value.clone());
        }
    }
    let thumbprint = jwk_thumbprint(&clean)?;
    Ok(HolderProof {
        jwk: clean,
        thumbprint,
        nonce: str_member(&payload, "nonce").map(str::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_entries_pack_like_the_status_list_draft() {
        let mut bytes = vec![0u8; 16];
        set_status_at(&mut bytes, 0.0, 2.0, STATUS_INVALID).unwrap();
        set_status_at(&mut bytes, 5.0, 2.0, STATUS_SUSPENDED).unwrap();
        assert_eq!(bytes[0], 0b01);
        assert_eq!(bytes[1], 0b1000);
        assert_eq!(status_at(&bytes, 5.0, 2.0).unwrap(), STATUS_SUSPENDED);
        assert_eq!(status_at(&bytes, 6.0, 2.0).unwrap(), STATUS_VALID);
        assert_eq!(
            status_at(&bytes, 64.0, 2.0).unwrap_err().reason,
            "status-unavailable"
        );
        assert!(set_status_at(&mut bytes, 64.0, 2.0, 1.0).is_err());
        assert!(set_status_at(&mut bytes, 1.0, 2.0, 4.0).is_err());
    }

    #[test]
    fn random_ints_stay_in_range() {
        for _ in 0..200 {
            assert!(random_int(4) < 4);
        }
        assert_eq!(random_int(1), 0);
    }
}
