//! Port of `packages/server/src/token-signing.ts`: signs IAM session JWTs with the deployment's `sts.jwt` keys and
//! verifies them with the same checks downstream verifiers apply. Verification here proves only the signature and
//! claims; IAM additionally requires the stored session row (principals.rs), so revocation inside IAM is immediate.

use std::sync::{Arc, LazyLock, Mutex};

use async_trait::async_trait;
use better_iam_core::{IamError, IamResult};
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde_json::{Map, Value, json};

use crate::session_tokens::jose::{self, SigningKey};
use crate::session_tokens::{
    KID_PATTERN, PublicSessionJwk, SESSION_TOKEN_TYPE, SessionTokenClaims, SessionTokenError,
    SessionTokenVerifier, create_session_token_verifier_with,
};

/// The signer contract (`SessionTokenSigner` of token-signing.ts).
pub use crate::contracts::SessionTokenSigner;

static AUDIENCE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$").expect("valid regex"));
const PRIVATE_MEMBERS: [&str; 7] = ["d", "p", "q", "dp", "dq", "qi", "k"];
const MAX_CACHED_VERIFIERS: usize = 32;

fn invalid(field: &str, detail: &str) -> IamError {
    IamError::new("INVALID_CONFIG", format!("sts.jwt.{field} {detail}"))
}

/// One configured key, checked: its key material (a signing key's private half), kid, algorithm and public members.
struct CheckedKey {
    signing: Option<SigningKey>,
    kid: String,
    alg: &'static str,
    public_jwk: PublicSessionJwk,
}

/// `Buffer.from(value, 'base64url')` of a JWK member.
fn key_bytes(value: Option<&Value>) -> Vec<u8> {
    better_iam_auth::util::node_base64_decode(value.and_then(Value::as_str).unwrap_or_default())
}

/// Parses the key material the way `createPrivateKey` / `createPublicKey` import a JWK: a signing key's public
/// coordinates must be the ones its private key derives; a verification key must be a valid public key.
fn parse_key(jwk: &Map<String, Value>, pair: &str, signing: bool) -> Option<Option<SigningKey>> {
    let encode = |bytes: &[u8]| jose::encode_base64url(bytes);
    let member = |name: &str| jwk.get(name).and_then(Value::as_str).unwrap_or_default();
    if signing {
        let d = key_bytes(jwk.get("d"));
        if pair == "EdDSA" {
            let secret: [u8; 32] = d.try_into().ok()?;
            let key = ed25519_dalek::SigningKey::from_bytes(&secret);
            if encode(key.verifying_key().as_bytes()) != member("x") {
                return None;
            }
            return Some(Some(SigningKey::Ed25519(Box::new(key))));
        }
        let key = p256::ecdsa::SigningKey::from_slice(&d).ok()?;
        let point = key.verifying_key().to_encoded_point(false);
        let (x, y) = (point.x()?, point.y()?);
        if encode(x) != member("x") || encode(y) != member("y") {
            return None;
        }
        return Some(Some(SigningKey::P256(Box::new(key))));
    }
    if pair == "EdDSA" {
        let _: [u8; 32] = key_bytes(jwk.get("x")).try_into().ok()?;
        return Some(None);
    }
    let (x, y) = (key_bytes(jwk.get("x")), key_bytes(jwk.get("y")));
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    let point = p256::EncodedPoint::from_affine_coordinates(
        x.as_slice().into(),
        y.as_slice().into(),
        false,
    );
    p256::ecdsa::VerifyingKey::from_encoded_point(&point).ok()?;
    Some(None)
}

/// `checkKey(value, field, signing)`: validates one configured JWK and derives its public projection; `signing`
/// keys must be private.
fn check_key(jwk: &Map<String, Value>, field: &str, signing: bool) -> IamResult<CheckedKey> {
    let is = |name: &str, wanted: &str| jwk.get(name).and_then(Value::as_str) == Some(wanted);
    let pair: &'static str = if is("kty", "OKP") && is("crv", "Ed25519") && is("alg", "EdDSA") {
        "EdDSA"
    } else if is("kty", "EC") && is("crv", "P-256") && is("alg", "ES256") {
        "ES256"
    } else {
        return Err(invalid(
            field,
            "keys must be kty OKP/crv Ed25519/alg EdDSA or kty EC/crv P-256/alg ES256",
        ));
    };
    let kid = match jwk.get("kid") {
        Some(Value::String(kid)) if KID_PATTERN.is_match(kid) => kid.clone(),
        _ => {
            return Err(invalid(
                field,
                "keys need a kid matching /^[A-Za-z0-9._-]{1,64}$/",
            ));
        }
    };
    if jwk.get("use").is_some() && !is("use", "sig") {
        return Err(invalid(field, "keys must have use 'sig'"));
    }
    let operation = if signing { "sign" } else { "verify" };
    if let Some(ops) = jwk.get("key_ops") {
        let listed = matches!(ops, Value::Array(items)
            if items.iter().any(|item| item.as_str() == Some(operation)));
        if !listed {
            return Err(invalid(
                field,
                &format!("key_ops must include '{operation}'"),
            ));
        }
    }
    if !jwk.get("x").is_some_and(Value::is_string)
        || (pair == "ES256" && !jwk.get("y").is_some_and(Value::is_string))
    {
        return Err(invalid(field, "keys need their public coordinates"));
    }
    if signing {
        if !jwk.get("d").is_some_and(Value::is_string) {
            return Err(invalid(field, "keys must be private keys"));
        }
    } else if PRIVATE_MEMBERS
        .iter()
        .any(|member| jwk.get(*member).is_some())
    {
        return Err(invalid(field, "must contain public keys only"));
    }
    // Parse the key material now, so a broken key fails at construction rather than at the first issuance.
    let Some(signing_key) = parse_key(jwk, pair, signing) else {
        return Err(invalid(
            field,
            &format!("key {kid} is not a valid {pair} key"),
        ));
    };
    let text = |name: &str| {
        jwk.get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    Ok(CheckedKey {
        signing: signing_key,
        kid: kid.clone(),
        alg: pair,
        public_jwk: PublicSessionJwk {
            kty: text("kty"),
            crv: text("crv"),
            x: text("x"),
            y: (pair == "ES256").then(|| text("y")),
            kid,
            alg: pair.to_owned(),
            r#use: "sig".to_owned(),
            extra: Map::new(),
        },
    })
}

/// `checkIssuer(value)`: an absolute http(s) URL without credentials, query or fragment.
fn check_issuer(value: &str) -> IamResult<String> {
    let refused = || {
        invalid(
            "issuer",
            "must be an absolute http(s) URL without credentials, query or fragment",
        )
    };
    let url = url::Url::parse(value).map_err(|_| refused())?;
    if (url.scheme() != "https" && url.scheme() != "http")
        || !url.username().is_empty()
        || url.password().is_some_and(|password| !password.is_empty())
        || url.query().is_some_and(|query| !query.is_empty())
        || url.fragment().is_some_and(|fragment| !fragment.is_empty())
        || !AUDIENCE_PATTERN.is_match(value)
    {
        return Err(refused());
    }
    Ok(value.to_owned())
}

/// The deployment's session token signer (`createSessionTokenSigner`'s result).
pub struct SessionTokenSigning {
    issuer: String,
    audiences: Vec<String>,
    max_lifetime_seconds: f64,
    active_kid: String,
    active_alg: &'static str,
    active_key: SigningKey,
    jwks: Vec<PublicSessionJwk>,
    now: crate::context::NowFn,
    verifiers: Mutex<IndexMap<String, Arc<SessionTokenVerifier>>>,
}

/// `createSessionTokenSigner(options, { issuer, now })` as its concrete type: None when `sts.jwt` is not configured.
/// Every option is validated (INVALID_CONFIG).
pub fn session_token_signer(
    options: Option<&crate::options::SessionTokenSigningOptions>,
    issuer: &str,
    now: crate::context::NowFn,
) -> IamResult<Option<SessionTokenSigning>> {
    let Some(options) = options else {
        return Ok(None);
    };
    if options.signing_keys.is_empty() || options.signing_keys.len() > 10 {
        return Err(invalid("signingKeys", "must contain 1 to 10 keys"));
    }
    let verification_keys: &[crate::options::Jwk] =
        options.verification_keys.as_deref().unwrap_or(&[]);
    if verification_keys.len() > 10 {
        return Err(invalid("verificationKeys", "must contain at most 10 keys"));
    }
    let signing = options
        .signing_keys
        .iter()
        .map(|key| check_key(key, "signingKeys", true))
        .collect::<IamResult<Vec<_>>>()?;
    let retired = verification_keys
        .iter()
        .map(|key| check_key(key, "verificationKeys", false))
        .collect::<IamResult<Vec<_>>>()?;
    let mut kids: IndexSet<String> = IndexSet::new();
    for key in signing.iter().chain(&retired) {
        if kids.contains(&key.kid) {
            return Err(invalid(
                "signingKeys",
                &format!("kid {} is used more than once", key.kid),
            ));
        }
        kids.insert(key.kid.clone());
    }
    let active_key_id = options
        .active_key_id
        .clone()
        .unwrap_or_else(|| signing[0].kid.clone());
    let Some(active) = signing.iter().find(|key| key.kid == active_key_id) else {
        return Err(invalid("activeKeyId", "must name one of the signing keys"));
    };
    let issuer = check_issuer(options.issuer.as_deref().unwrap_or(issuer))?;
    let configured: &[String] = options.audiences.as_deref().unwrap_or(&[]);
    if configured.len() > 50 {
        return Err(invalid(
            "audiences",
            "must be an array of at most 50 audiences",
        ));
    }
    for audience in configured {
        if !AUDIENCE_PATTERN.is_match(audience) {
            return Err(invalid(
                "audiences",
                "entries must match /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/",
            ));
        }
    }
    let audiences: Vec<String> = std::iter::once(issuer.clone())
        .chain(configured.iter().cloned())
        .collect::<IndexSet<String>>()
        .into_iter()
        .collect();
    let max_lifetime_seconds = options.max_lifetime_seconds.unwrap_or(3600.0);
    if !crate::js::is_safe_integer(max_lifetime_seconds)
        || !(300.0..=43200.0).contains(&max_lifetime_seconds)
    {
        return Err(invalid(
            "maxLifetimeSeconds",
            "must be an integer from 300 to 43200",
        ));
    }
    let jwks = signing
        .iter()
        .chain(&retired)
        .map(|key| key.public_jwk.clone())
        .collect();
    let Some(active_key) = active.signing.clone() else {
        return Err(invalid("signingKeys", "keys must be private keys"));
    };
    Ok(Some(SessionTokenSigning {
        issuer,
        audiences,
        max_lifetime_seconds,
        active_kid: active.kid.clone(),
        active_alg: active.alg,
        active_key,
        jwks,
        now,
        verifiers: Mutex::new(IndexMap::new()),
    }))
}

/// `createSessionTokenSigner(options, { issuer, now })`: the deployment's session token signer, or None when `sts.jwt`
/// is not configured. Every option is validated synchronously (INVALID_CONFIG).
pub fn create_session_token_signer(
    options: Option<&crate::options::SessionTokenSigningOptions>,
    issuer: &str,
    now: crate::context::NowFn,
) -> IamResult<Option<Arc<dyn SessionTokenSigner>>> {
    Ok(session_token_signer(options, issuer, now)?
        .map(|signer| Arc::new(signer) as Arc<dyn SessionTokenSigner>))
}

impl SessionTokenSigning {
    /// The verifier for an audience (created on first use; at most 32 are kept). None when the audience cannot make a
    /// verifier.
    fn verifier(&self, audience: &str) -> Option<Arc<SessionTokenVerifier>> {
        let mut verifiers = self
            .verifiers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(found) = verifiers.get(audience) {
            return Some(found.clone());
        }
        let found = Arc::new(
            create_session_token_verifier_with(
                &json!({
                    "issuer": self.issuer,
                    "audience": audience,
                    "jwks": { "keys": self.jwks },
                    "clockToleranceSeconds": 5,
                    "maxLifetimeSeconds": crate::js::number(self.max_lifetime_seconds),
                }),
                Some(self.now.clone()),
            )
            .ok()?,
        );
        if verifiers.len() >= MAX_CACHED_VERIFIERS {
            verifiers.clear();
        }
        verifiers.insert(audience.to_owned(), found.clone());
        Some(found)
    }

    /// Signs a claims object as given (members in order) with the active key; the header is
    /// `{ alg, kid, typ: 'biam-session+jwt' }`.
    pub fn sign_json(&self, claims: &Map<String, Value>) -> String {
        let header =
            json!({ "alg": self.active_alg, "kid": self.active_kid, "typ": SESSION_TOKEN_TYPE });
        jose::sign_compact(&header, &Value::Object(claims.clone()), &self.active_key)
    }

    /// Verifies a token for `audience` (default: the issuer) with a 5 second clock tolerance, keeping the failure
    /// reason.
    pub async fn verify_detailed(
        &self,
        token: &str,
        audience: Option<&str>,
    ) -> Result<SessionTokenClaims, SessionTokenError> {
        let checker = self
            .verifier(audience.unwrap_or(&self.issuer))
            .ok_or_else(|| SessionTokenError::new("audience", None))?;
        checker.verify_detailed(token).await
    }

    /// The public members of the signing and verification keys (copies).
    pub fn public_keys(&self) -> Vec<PublicSessionJwk> {
        self.jwks.clone()
    }
}

#[async_trait]
impl SessionTokenSigner for SessionTokenSigning {
    fn issuer(&self) -> &str {
        &self.issuer
    }

    fn audiences(&self) -> &[String] {
        &self.audiences
    }

    fn max_lifetime_seconds(&self) -> f64 {
        self.max_lifetime_seconds
    }

    async fn sign(&self, claims: &SessionTokenClaims) -> IamResult<String> {
        Ok(self.sign_json(&claims.to_json()))
    }

    async fn verify(&self, token: &str, audience: Option<&str>) -> IamResult<SessionTokenClaims> {
        self.verify_detailed(token, audience)
            .await
            .map_err(IamError::from)
    }

    fn public_jwks(&self) -> Vec<PublicSessionJwk> {
        self.public_keys()
    }
}
