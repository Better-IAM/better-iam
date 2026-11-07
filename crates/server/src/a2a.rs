//! Port of `packages/server/src/a2a.ts`.
//!
//! IAM-attested A2A agent cards. An agent's A2A server builds its agent card (the Agent2Agent protocol's
//! `/.well-known/agent-card.json`) and asks Better IAM to sign it (`agents.signCard`). IAM checks that the card's
//! endpoints belong to the agent's registered `url`, sets the card's `provider.organization` to the tenant, adds an
//! attestation extension (who the agent is, which organization runs it, that a person sponsors it, when the
//! attestation expires), and signs the canonical card (RFC 8785) as a detached JWS, the A2A card signature format.
//! Anyone holding the deployment's card keys (`iam.a2a.jwks()`, published at `a2a.jwksUrl`) can then check that a
//! remote agent is a registered agent in good standing of a given organization (`verifyAgentCard` in
//! `@better-iam/a2a`).
//!
//! The TypeScript module signs with `jose`; this port signs with the same key types (Ed25519 and P-256), the same
//! protected headers (serialized with `JSON.stringify` member order) and the same compact/flattened layouts.

use std::sync::{Arc, Mutex, Weak};

use better_iam_core::{
    DELEGATION_TOKEN_TYPE, DelegationTokenExpectations, DelegationTokenRead,
    DelegationTokenSummary, IamError, IamResult, IamStoreExt, canonicalize_json, js as core_js,
    read_delegation_token_claims,
};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::ServerContext;
use crate::js::{ThrownError, number, utf16_len};
use crate::options::HttpResponse;
use crate::session_tokens::jose::{self, SigningKey};

/// The URI of the attestation extension IAM adds to `capabilities.extensions` of every card it signs.
pub const AGENT_ATTESTATION_URI: &str = "urn:better-iam:a2a:attestation:v1";

/// A card IAM signed: the input card with IAM's provider, attestation extension and one JWS signature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedAgentCard {
    #[serde(rename = "card")]
    pub card: Value,
    #[serde(rename = "attestation")]
    pub attestation: Value,
    /// Epoch milliseconds; re-sign before then.
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl SignedAgentCard {
    /// The JSON the TypeScript function returns: `{ card, attestation, expiresAt }`.
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("card".into(), self.card.clone());
        out.insert("attestation".into(), self.attestation.clone());
        out.insert("expiresAt".into(), number(self.expires_at));
        Value::Object(out)
    }
}

/// One configured card key: its private half (signing keys only), kid, algorithm and public projection.
struct CardKey {
    signing: Option<SigningKey>,
    kid: String,
    alg: &'static str,
    /// The public JWK as published: `kty`, `crv`, `x`, `y` (P-256), `kid`, `alg`, `use`.
    public_jwk: Map<String, Value>,
}

/// The deployment's card signer (`CardSigner`): the issuer, lifetime and keys of the `a2a` option.
pub struct CardSigner {
    /// The attestation's `issuer`.
    pub issuer: String,
    /// Where the deployment publishes the keys; carried as `jku` in every signature.
    pub jwks_url: Option<String>,
    /// How long an attestation is valid, in seconds.
    pub lifetime_seconds: f64,
    active: usize,
    /// Signing keys, then retired verification keys.
    keys: Vec<CardKey>,
}

impl std::fmt::Debug for CardSigner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CardSigner")
            .field("issuer", &self.issuer)
            .field("jwks_url", &self.jwks_url)
            .field("lifetime_seconds", &self.lifetime_seconds)
            .finish_non_exhaustive()
    }
}

/// `{ protected, signature }` of a detached card signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardSignature {
    pub protected: String,
    pub signature: String,
}

impl CardSigner {
    /// `jwks`: the public card keys (signing and retired), copies.
    pub fn jwks(&self) -> Value {
        json!({
            "keys": self
                .keys
                .iter()
                .map(|key| Value::Object(key.public_jwk.clone()))
                .collect::<Vec<_>>()
        })
    }

    fn active_key(&self) -> &CardKey {
        &self.keys[self.active]
    }

    /// The protected header `{ alg, kid, typ, jku? }`.
    fn header(&self, typ: &str) -> Value {
        let active = self.active_key();
        let mut header = Map::new();
        header.insert("alg".into(), Value::String(active.alg.to_owned()));
        header.insert("kid".into(), Value::String(active.kid.clone()));
        header.insert("typ".into(), Value::String(typ.to_owned()));
        if let Some(jwks_url) = &self.jwks_url {
            header.insert("jku".into(), Value::String(jwks_url.clone()));
        }
        Value::Object(header)
    }

    /// Signs `input` (the JWS signing input) with the active key.
    fn signature_of(&self, input: &[u8]) -> Vec<u8> {
        use p256::ecdsa::signature::Signer;
        match self
            .active_key()
            .signing
            .as_ref()
            .expect("the active key is a signing key")
        {
            SigningKey::Ed25519(key) => key.sign(input).to_bytes().to_vec(),
            SigningKey::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(input);
                signature.to_bytes().to_vec()
            }
        }
    }

    /// `sign(payload)`: a flattened JWS of `payload` with the header `{ alg, kid, typ: 'JOSE', jku? }`, as
    /// `{ protected, signature }` (the payload is detached).
    pub fn sign(&self, payload: &[u8]) -> CardSignature {
        let protected = jose::encode_base64url(core_js::stringify(&self.header("JOSE")).as_bytes());
        let input = format!("{protected}.{}", jose::encode_base64url(payload));
        CardSignature {
            protected,
            signature: jose::encode_base64url(&self.signature_of(input.as_bytes())),
        }
    }

    /// `signJwt(claims, typ)`: signs `claims` as a compact JWT with the active key and an explicit `typ` (never
    /// `JOSE`, the card type).
    pub fn sign_jwt(&self, claims: &Map<String, Value>, typ: &str) -> String {
        let protected = jose::encode_base64url(core_js::stringify(&self.header(typ)).as_bytes());
        let payload =
            jose::encode_base64url(core_js::stringify(&Value::Object(claims.clone())).as_bytes());
        let input = format!("{protected}.{payload}");
        let signature = jose::encode_base64url(&self.signature_of(input.as_bytes()));
        format!("{input}.{signature}")
    }

    /// `verifyJwt(token, typ)`: verifies a compact JWT of type `typ` with the published keys; the payload, or None
    /// when it does not verify.
    pub fn verify_jwt(&self, token: &str, typ: &str) -> Option<Map<String, Value>> {
        let header = jose::decode_protected_header(token).ok()?;
        let found = self.keys.iter().find(|item| {
            header.get("kid").and_then(Value::as_str) == Some(item.kid.as_str())
                && header.get("alg").and_then(Value::as_str) == Some(item.alg)
        })?;
        if header.get("typ").and_then(Value::as_str) != Some(typ) || header.get("crit").is_some() {
            return None;
        }
        compact_verify(token, found)
    }
}

/// `compactVerify(token, publicKey, { algorithms: [found.alg] })` followed by `JSON.parse` of the payload (a plain
/// object, or None).
fn compact_verify(token: &str, key: &CardKey) -> Option<Map<String, Value>> {
    let parts: Vec<&str> = token.split('.').collect();
    let [protected, payload, signature] = parts.as_slice() else {
        return None;
    };
    let header_bytes = jose::decode_base64url(protected)?;
    let Ok(Value::Object(header)) = serde_json::from_slice::<Value>(&header_bytes) else {
        return None;
    };
    if header.get("alg").and_then(Value::as_str) != Some(key.alg) {
        return None;
    }
    if header
        .get("b64")
        .is_some_and(|b64| b64 != &Value::Bool(true))
    {
        return None;
    }
    let signature = jose::decode_base64url(signature)?;
    let input = format!("{protected}.{payload}");
    if !verify_signature(key, input.as_bytes(), &signature) {
        return None;
    }
    let payload = jose::decode_base64url(payload)?;
    let text = String::from_utf8_lossy(&payload);
    match core_js::parse(&text) {
        Ok(Value::Object(claims)) => Some(claims),
        _ => None,
    }
}

/// Verifies a signature with a key's public half.
fn verify_signature(key: &CardKey, data: &[u8], signature: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier;
    let member = |name: &str| {
        key.public_jwk
            .get(name)
            .and_then(Value::as_str)
            .and_then(jose::decode_base64url)
    };
    match key.alg {
        "EdDSA" => {
            let Some(x) = member("x").and_then(|x| <[u8; 32]>::try_from(x).ok()) else {
                return false;
            };
            let Ok(verifying) = ed25519_dalek::VerifyingKey::from_bytes(&x) else {
                return false;
            };
            ed25519_dalek::Signature::from_slice(signature)
                .is_ok_and(|signature| verifying.verify(data, &signature).is_ok())
        }
        _ => {
            let (Some(x), Some(y)) = (member("x"), member("y")) else {
                return false;
            };
            if x.len() != 32 || y.len() != 32 {
                return false;
            }
            let point = p256::EncodedPoint::from_affine_coordinates(
                x.as_slice().into(),
                y.as_slice().into(),
                false,
            );
            let Ok(verifying) = p256::ecdsa::VerifyingKey::from_encoded_point(&point) else {
                return false;
            };
            p256::ecdsa::Signature::from_slice(signature)
                .is_ok_and(|signature| verifying.verify(data, &signature).is_ok())
        }
    }
}

const PRIVATE_MEMBERS: [&str; 7] = ["d", "p", "q", "dp", "dq", "qi", "k"];
const MAX_CARD_BYTES: usize = 64 * 1024;

/// `invalid(detail)`: INVALID_CONFIG `a2a.{detail}`.
fn invalid(detail: &str) -> IamError {
    IamError::new("INVALID_CONFIG", format!("a2a.{detail}"))
}

/// `Buffer.from(value, 'base64url')` of a JWK member.
fn key_bytes(value: Option<&Value>) -> Vec<u8> {
    better_iam_auth::util::node_base64_decode(value.and_then(Value::as_str).unwrap_or_default())
}

/// Imports the key material the way `createPrivateKey` / `createPublicKey` import a JWK: a signing key's public
/// coordinates must be the ones its private key derives; a verification key must be a valid public key. None when it
/// is not a valid key; `Some(None)` for a valid public key.
fn parse_key(jwk: &Map<String, Value>, alg: &str, signing: bool) -> Option<Option<SigningKey>> {
    let member = |name: &str| jwk.get(name).and_then(Value::as_str).unwrap_or_default();
    if signing {
        let d = key_bytes(jwk.get("d"));
        if alg == "EdDSA" {
            let secret: [u8; 32] = d.try_into().ok()?;
            let key = ed25519_dalek::SigningKey::from_bytes(&secret);
            if jose::encode_base64url(key.verifying_key().as_bytes()) != member("x") {
                return None;
            }
            return Some(Some(SigningKey::Ed25519(Box::new(key))));
        }
        let key = p256::ecdsa::SigningKey::from_slice(&d).ok()?;
        let point = key.verifying_key().to_encoded_point(false);
        let (x, y) = (point.x()?, point.y()?);
        if jose::encode_base64url(x) != member("x") || jose::encode_base64url(y) != member("y") {
            return None;
        }
        return Some(Some(SigningKey::P256(Box::new(key))));
    }
    if alg == "EdDSA" {
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

/// `cardKey(value, field, signing)`: validates one configured JWK.
fn card_key(value: &Map<String, Value>, field: &str, signing: bool) -> IamResult<CardKey> {
    let jwk = value;
    let is = |name: &str, wanted: &str| jwk.get(name).and_then(Value::as_str) == Some(wanted);
    let alg: &'static str = if is("kty", "OKP") && is("crv", "Ed25519") && is("alg", "EdDSA") {
        "EdDSA"
    } else if is("kty", "EC") && is("crv", "P-256") && is("alg", "ES256") {
        "ES256"
    } else {
        return Err(invalid(&format!(
            "{field} keys must be kty OKP/crv Ed25519/alg EdDSA or kty EC/crv P-256/alg ES256"
        )));
    };
    let kid = match jwk.get("kid") {
        Some(Value::String(kid)) if crate::session_tokens::KID_PATTERN.is_match(kid) => kid.clone(),
        _ => {
            return Err(invalid(&format!(
                "{field} keys need a kid matching /^[A-Za-z0-9._-]{{1,64}}$/"
            )));
        }
    };
    if jwk.get("use").is_some() && !is("use", "sig") {
        return Err(invalid(&format!("{field} keys must have use 'sig'")));
    }
    if !jwk.get("x").is_some_and(Value::is_string)
        || (alg == "ES256" && !jwk.get("y").is_some_and(Value::is_string))
    {
        return Err(invalid(&format!(
            "{field} keys need their public coordinates"
        )));
    }
    if signing {
        if !jwk.get("d").is_some_and(Value::is_string) {
            return Err(invalid(&format!("{field} must contain private keys")));
        }
    } else if PRIVATE_MEMBERS
        .iter()
        .any(|member| jwk.get(*member).is_some())
    {
        return Err(invalid(&format!("{field} must contain public keys only")));
    }
    let Some(signing_key) = parse_key(jwk, alg, signing) else {
        return Err(invalid(&format!(
            "{field} key {kid} is not a valid {alg} key"
        )));
    };
    let text = |name: &str| {
        Value::String(
            jwk.get(name)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        )
    };
    let mut public_jwk = Map::new();
    public_jwk.insert("kty".into(), text("kty"));
    public_jwk.insert("crv".into(), text("crv"));
    public_jwk.insert("x".into(), text("x"));
    if alg == "ES256" {
        public_jwk.insert("y".into(), text("y"));
    }
    public_jwk.insert("kid".into(), Value::String(kid.clone()));
    public_jwk.insert("alg".into(), Value::String(alg.to_owned()));
    public_jwk.insert("use".into(), Value::String("sig".into()));
    Ok(CardKey {
        signing: signing_key,
        kid,
        alg,
        public_jwk,
    })
}

/// `httpUrl(value, field)`: an absolute http(s) URL without credentials.
fn http_url(value: &str, field: &str) -> IamResult<String> {
    let valid = url::Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none_or(str::is_empty)
    });
    if !valid {
        return Err(invalid(&format!(
            "{field} must be an absolute http(s) URL without credentials"
        )));
    }
    Ok(value.to_owned())
}

/// `createCardSigner(ctx)`: None without the `a2a` option; INVALID_CONFIG for an invalid one.
fn create_card_signer(ctx: &ServerContext) -> IamResult<Option<CardSigner>> {
    let Some(options) = ctx.options.a2a.as_ref() else {
        return Ok(None);
    };
    if options.signing_keys.is_empty() || options.signing_keys.len() > 10 {
        return Err(invalid("signingKeys must contain 1 to 10 keys"));
    }
    let verification_keys: &[crate::options::Jwk] =
        options.verification_keys.as_deref().unwrap_or(&[]);
    if verification_keys.len() > 10 {
        return Err(invalid("verificationKeys must contain at most 10 keys"));
    }
    let mut keys = options
        .signing_keys
        .iter()
        .map(|key| card_key(key, "signingKeys", true))
        .collect::<IamResult<Vec<_>>>()?;
    let signing_count = keys.len();
    for key in verification_keys {
        keys.push(card_key(key, "verificationKeys", false)?);
    }
    let mut kids = indexmap::IndexSet::new();
    for key in &keys {
        if !kids.insert(key.kid.clone()) {
            return Err(invalid(&format!("kid {} is used more than once", key.kid)));
        }
    }
    let wanted = options
        .active_key_id
        .clone()
        .unwrap_or_else(|| keys[0].kid.clone());
    let Some(active) = keys[..signing_count]
        .iter()
        .position(|key| key.kid == wanted)
    else {
        return Err(invalid("activeKeyId must name one of the signing keys"));
    };
    let lifetime_seconds = options.card_lifetime_seconds.unwrap_or(3600.0);
    if !core_js::is_safe_integer(lifetime_seconds)
        || !(300.0..=604_800.0).contains(&lifetime_seconds)
    {
        return Err(invalid(
            "cardLifetimeSeconds must be an integer from 300 to 604800",
        ));
    }
    let issuer = match &options.issuer {
        Some(issuer) => http_url(issuer, "issuer")?,
        None => format!("{}{}", ctx.config.origin(), ctx.config.base_path),
    };
    let jwks_url = match &options.jwks_url {
        Some(url) => Some(http_url(url, "jwksUrl")?),
        None => None,
    };
    Ok(Some(CardSigner {
        issuer,
        jwks_url,
        lifetime_seconds,
        active,
        keys,
    }))
}

/// Signers already validated, per context (the TypeScript WeakMap): an entry ends with its context.
type SignerEntry = (Weak<ServerContext>, Option<Arc<CardSigner>>);
static SIGNERS: Mutex<Vec<SignerEntry>> = Mutex::new(Vec::new());

/// The deployment's card signer, validated once per context; None without the `a2a` option.
pub fn card_signer(ctx: &Arc<ServerContext>) -> IamResult<Option<Arc<CardSigner>>> {
    {
        let mut entries = SIGNERS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|(weak, _)| weak.strong_count() > 0);
        if let Some((_, signer)) = entries
            .iter()
            .find(|(weak, _)| weak.upgrade().is_some_and(|live| Arc::ptr_eq(&live, ctx)))
        {
            return Ok(signer.clone());
        }
    }
    let signer = create_card_signer(ctx)?.map(Arc::new);
    SIGNERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push((Arc::downgrade(ctx), signer.clone()));
    Ok(signer)
}

/// `refuse(message)`: INVALID_INPUT.
fn refuse(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

/// `new URL(value)` of a string, for http(s) URLs only.
fn http_url_of(value: Option<&Value>) -> Option<url::Url> {
    let url = url::Url::parse(value?.as_str()?).ok()?;
    matches!(url.scheme(), "http" | "https").then_some(url)
}

/// The origin of a card endpoint, refusing anything but an http(s) URL on the agent's registered origin.
fn endpoint_on(value: Option<&Value>, field: &str, origin: &str) -> IamResult<String> {
    let Some(url) = http_url_of(value) else {
        return Err(refuse(format!("{field} must be an http(s) URL")));
    };
    if crate::hosts::url_origin(&url) != origin {
        return Err(refuse(format!(
            "{field} must be on the agent's registered origin {origin} (set the agent's url)"
        )));
    }
    Ok(value.and_then(Value::as_str).unwrap_or_default().to_owned())
}

/// `new Date(ms).toISOString()`.
fn iso(ms: f64) -> IamResult<String> {
    core_js::iso_string(ms)
        .ok_or_else(|| ThrownError::new("RangeError", "Invalid time value").into_iam())
}

/// Signs `input` for `agent`: an A2A agent card whose `url` (and every `additionalInterfaces[].url`) is on the
/// origin of the agent's registered `url`. The caller has already been authorized; the agent must be in good
/// standing.
pub async fn sign_agent_card(
    ctx: &Arc<ServerContext>,
    tenant: &better_iam_core::Tenant,
    agent: &better_iam_core::Identity,
    input: Option<&Value>,
) -> IamResult<crate::a2a::SignedAgentCard> {
    let Some(signer) = card_signer(ctx)? else {
        return Err(IamError::with_status(
            "FEATURE_DISABLED",
            "Agent card signing is not enabled (a2a option)",
            403,
        ));
    };
    let Some(profile) = agent
        .agent
        .as_ref()
        .filter(|profile| profile.url.as_deref().is_some_and(|url| !url.is_empty()))
    else {
        return Err(refuse(
            "Register the agent\u{2019}s url before signing its card",
        ));
    };
    let Some(Value::Object(input)) = input else {
        return Err(refuse("card must be an A2A agent card object"));
    };
    let registered = profile.url.as_deref().unwrap_or_default();
    let origin = url::Url::parse(registered)
        .map(|url| crate::hosts::url_origin(&url))
        .map_err(|_| ThrownError::type_error("Invalid URL").into_iam())?;
    let mut card = input.clone();
    card.shift_remove("signatures");
    match card.get("name") {
        Some(Value::String(name)) if !core_js::trim(name).is_empty() && utf16_len(name) <= 256 => {}
        _ => return Err(refuse("card.name must be 1-256 characters")),
    }
    endpoint_on(card.get("url"), "card.url", &origin)?;
    // Every endpoint the card offers (A2A 0.3 `additionalInterfaces`, 1.0 `supportedInterfaces`) is pinned the same
    // way.
    for field in ["additionalInterfaces", "supportedInterfaces"] {
        let Some(interfaces) = card.get(field) else {
            continue;
        };
        let Some(interfaces) = interfaces.as_array().filter(|items| items.len() <= 16) else {
            return Err(refuse(format!(
                "card.{field} must list at most 16 interfaces"
            )));
        };
        for (index, item) in interfaces.iter().enumerate() {
            let Value::Object(item) = item else {
                return Err(refuse(format!("card.{field}[{index}] must be an object")));
            };
            endpoint_on(
                item.get("url"),
                &format!("card.{field}[{index}].url"),
                &origin,
            )?;
        }
    }
    let capabilities = match card.get("capabilities") {
        None => Map::new(),
        Some(Value::Object(capabilities)) => capabilities.clone(),
        Some(_) => return Err(refuse("card.capabilities must be an object")),
    };
    let extensions = match capabilities.get("extensions") {
        None => Vec::new(),
        Some(Value::Array(extensions)) => extensions.clone(),
        Some(_) => return Err(refuse("card.capabilities.extensions must be an array")),
    };
    let now = ctx.now();
    let expires_at = now + signer.lifetime_seconds * 1000.0;
    let mut attestation = Map::new();
    attestation.insert("issuer".into(), Value::String(signer.issuer.clone()));
    attestation.insert("tenantId".into(), Value::String(tenant.id.clone()));
    attestation.insert("organization".into(), Value::String(tenant.name.clone()));
    attestation.insert("agentId".into(), Value::String(agent.id.clone()));
    attestation.insert("agentName".into(), Value::String(agent.name.clone()));
    attestation.insert("sponsored".into(), Value::Bool(true));
    attestation.insert(
        "delegable".into(),
        Value::Bool(profile.delegable != Some(false)),
    );
    if let Some(model) = &profile.model {
        attestation.insert("model".into(), Value::String(model.clone()));
    }
    if let Some(provider) = &profile.provider {
        attestation.insert("provider".into(), Value::String(provider.clone()));
    }
    if let Some(protocols) = profile.protocols.as_ref().filter(|list| !list.is_empty()) {
        attestation.insert(
            "protocols".into(),
            Value::Array(protocols.iter().cloned().map(Value::String).collect()),
        );
    }
    attestation.insert("issuedAt".into(), Value::String(iso(now)?));
    attestation.insert("expiresAt".into(), Value::String(iso(expires_at)?));
    let attestation = Value::Object(attestation);

    let mut unsigned = card;
    // The provider is the organization, reached at the agent's registered origin (never a URL the card chose).
    unsigned.insert(
        "provider".into(),
        json!({ "organization": tenant.name, "url": origin }),
    );
    let mut next_capabilities = capabilities;
    // Any attestation already in the card is dropped: only IAM's own, signed below, may stand.
    let mut next_extensions: Vec<Value> = extensions
        .into_iter()
        .filter(|item| {
            !item.as_object().is_some_and(|item| {
                item.get("uri") == Some(&Value::String(AGENT_ATTESTATION_URI.into()))
            })
        })
        .collect();
    next_extensions.push(json!({
        "uri": AGENT_ATTESTATION_URI,
        "description": "This agent is registered with, and attested by, Better IAM.",
        "required": false,
        "params": attestation,
    }));
    next_capabilities.insert("extensions".into(), Value::Array(next_extensions));
    unsigned.insert("capabilities".into(), Value::Object(next_capabilities));
    let canonical = canonicalize_json(&Value::Object(unsigned));
    if canonical.len() > MAX_CARD_BYTES {
        return Err(refuse("card must be at most 64 KiB"));
    }
    let signature = signer.sign(canonical.as_bytes());
    // A copy of exactly what was signed, sharing nothing with the input.
    let Ok(Value::Object(mut signed)) = core_js::parse(&canonical) else {
        return Err(refuse("card must be plain JSON"));
    };
    signed.insert(
        "signatures".into(),
        json!([{ "protected": signature.protected, "signature": signature.signature }]),
    );
    Ok(SignedAgentCard {
        card: Value::Object(signed),
        attestation,
        expires_at,
        extra: Map::new(),
    })
}

/// Records a verified token id until it expires; answers false when it was seen before (the replay is refused).
pub type ReplayCheck =
    Arc<dyn Fn(String, f64) -> BoxFuture<'static, IamResult<bool>> + Send + Sync>;

/// `VerifyIssuedDelegationTokenOptions`.
#[derive(Clone, Default)]
pub struct VerifyIssuedDelegationTokenOptions {
    /// The audience the service answers to: the token's `aud` must be exactly this.
    pub audience: String,
    /// Accept only tokens of this organization.
    pub tenant_id: Option<String>,
    /// Also re-check in storage everything the token stands on: the delegation chain, the person, the agents and
    /// the agent's key in good standing, the audience still allowed, and the scopes still allowed by every limit.
    pub live: bool,
    /// Records a verified token id until it expires; return false when it was seen before to refuse the replay.
    pub replay: Option<ReplayCheck>,
    /// Allowed clock difference in seconds (default 30).
    pub clock_tolerance_seconds: Option<f64>,
}

impl VerifyIssuedDelegationTokenOptions {
    /// The options from their JSON form (`replay` cannot travel as JSON and is left out).
    pub fn from_value(value: Option<&Value>) -> Self {
        let member = |key: &str| value.and_then(|value| value.get(key));
        Self {
            audience: member("audience")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            tenant_id: member("tenantId")
                .and_then(Value::as_str)
                .map(str::to_owned),
            live: crate::js::truthy(member("live")),
            replay: None,
            clock_tolerance_seconds: member("clockToleranceSeconds").and_then(core_js::as_number),
        }
    }
}

/// Validates the `a2a` option at construction (INVALID_CONFIG) and exposes the public keys.
pub struct A2aRuntime {
    ctx: Arc<ServerContext>,
    signer: Option<Arc<CardSigner>>,
}

/// `createA2aRuntime(ctx)`: validates the `a2a` option (INVALID_CONFIG).
pub fn create_a2a_runtime(ctx: &Arc<ServerContext>) -> IamResult<A2aRuntime> {
    Ok(A2aRuntime {
        ctx: ctx.clone(),
        signer: card_signer(ctx)?,
    })
}

fn invalid_token(message: impl Into<String>) -> IamError {
    IamError::with_status("DELEGATION_TOKEN_INVALID", message, 401)
}

impl A2aRuntime {
    /// Whether cards can be signed (the `a2a` option is set).
    pub fn enabled(&self) -> bool {
        self.signer.is_some()
    }

    /// The public card keys (signing and retired), for verifiers. Empty without the `a2a` option.
    pub fn jwks(&self) -> Value {
        match &self.signer {
            Some(signer) => signer.jwks(),
            None => json!({ "keys": [] }),
        }
    }

    /// A GET response publishing `jwks()`, cacheable for five minutes: serve it at `a2a.jwksUrl`.
    pub fn jwks_response(&self) -> HttpResponse {
        http::Response::builder()
            .status(200)
            .header("content-type", "application/jwk-set+json")
            .header("cache-control", "public, max-age=300")
            .header("access-control-allow-origin", "*")
            .body(bytes::Bytes::from(core_js::stringify(&self.jwks())))
            .expect("valid response")
    }

    /// Verifies a delegation token (`delegations.issueToken`) this deployment issued, for a service running next to
    /// it: the signature with the deployment's keys, the type, the issuer, `audience`, `tenantId` when given, and the
    /// times. With `live`, also that everything it stands on is still in place (the delegation chain, the person, the
    /// agents and the agent's key, the audience and the scopes), so a revocation takes effect before the token
    /// expires. Throws DELEGATION_TOKEN_INVALID (401).
    pub async fn verify_delegation_token(
        &self,
        token: &str,
        options: &VerifyIssuedDelegationTokenOptions,
    ) -> IamResult<better_iam_core::DelegationTokenSummary> {
        let Some(signer) = &self.signer else {
            return Err(IamError::with_status(
                "FEATURE_DISABLED",
                "Delegation tokens need the a2a option",
                403,
            ));
        };
        if utf16_len(token) > 16_384 {
            return Err(invalid_token("Not a delegation token"));
        }
        let Some(claims) = signer.verify_jwt(token, DELEGATION_TOKEN_TYPE) else {
            return Err(invalid_token("The delegation token does not verify"));
        };
        let read = read_delegation_token_claims(
            &Value::Object(claims),
            &DelegationTokenExpectations {
                issuer: vec![signer.issuer.clone()],
                audience: options.audience.clone(),
                tenant_id: options.tenant_id.clone(),
                now: self.ctx.now(),
                clock_tolerance_seconds: options.clock_tolerance_seconds,
            },
        )
        .map_err(|error| ThrownError::type_error(error.0).into_iam())?;
        let verified: DelegationTokenSummary = match read {
            DelegationTokenRead::Rejected { message, .. } => return Err(invalid_token(message)),
            DelegationTokenRead::Token(token) => *token,
        };
        if options.live {
            let ctx = self.ctx.clone();
            let verified = &verified;
            self.ctx
                .store
                .transaction(|tx| async move {
                    // The record kept at issue time: the token's own key, audience, scopes and session limits.
                    let stands = match tx.get("delegationTokens", &verified.token_id).await? {
                        Some(raw) => {
                            let text = |key: &str| raw.get(key).and_then(Value::as_str);
                            let scopes = raw.get("scopes").and_then(Value::as_array).map(|items| {
                                items
                                    .iter()
                                    .map(|item| crate::js::js_string(Some(item)))
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            });
                            if text("tenantId") == Some(verified.tenant_id.as_str())
                                && text("delegationId") == Some(verified.delegation_id.as_str())
                                && text("personId") == Some(verified.person_id.as_str())
                                && text("agentId") == Some(verified.agent_id.as_str())
                                && text("audience") == Some(verified.audience.as_str())
                                && scopes.as_deref() == Some(verified.scopes.join(" ").as_str())
                            {
                                let record: crate::delegation_tokens::DelegationTokenRecord =
                                    crate::port::decode(raw)?;
                                crate::delegation_tokens::token_still_stands(
                                    &ctx,
                                    &tx,
                                    &record,
                                    ctx.now(),
                                )
                                .await?
                            } else {
                                false
                            }
                        }
                        None => false,
                    };
                    if !stands {
                        return Err(invalid_token(
                            "What the delegation token stands on is no longer in place",
                        ));
                    }
                    Ok(())
                })
                .await?;
        }
        if let Some(replay) = &options.replay
            && !replay(verified.token_id.clone(), verified.expires_at).await?
        {
            return Err(invalid_token("The delegation token was used before"));
        }
        Ok(verified)
    }

    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        match method {
            "jwks" => Some(Ok(self.jwks())),
            // A Response travels as its tagged class name (FORMAT.md).
            "jwksResponse" => {
                let _ = self.jwks_response();
                Some(Ok(json!({ "$object": "Response" })))
            }
            "verifyDelegationToken" => {
                let options = VerifyIssuedDelegationTokenOptions::from_value(args.get(1));
                let result = match args.first() {
                    Some(Value::String(token)) => {
                        self.verify_delegation_token(token, &options).await
                    }
                    _ if self.signer.is_none() => Err(IamError::with_status(
                        "FEATURE_DISABLED",
                        "Delegation tokens need the a2a option",
                        403,
                    )),
                    _ => Err(invalid_token("Not a delegation token")),
                };
                Some(result.map(|summary| delegation_token_summary_json(&summary)))
            }
            _ => None,
        }
    }
}

/// A `DelegationTokenSummary` as the TypeScript object (numbers in JavaScript form).
fn delegation_token_summary_json(summary: &DelegationTokenSummary) -> Value {
    let strings =
        |items: &[String]| Value::Array(items.iter().cloned().map(Value::String).collect());
    let mut out = Map::new();
    out.insert("issuer".into(), Value::String(summary.issuer.clone()));
    out.insert("personId".into(), Value::String(summary.person_id.clone()));
    out.insert("tenantId".into(), Value::String(summary.tenant_id.clone()));
    out.insert(
        "delegationId".into(),
        Value::String(summary.delegation_id.clone()),
    );
    out.insert("agentId".into(), Value::String(summary.agent_id.clone()));
    out.insert("chain".into(), strings(&summary.chain));
    out.insert("scopes".into(), strings(&summary.scopes));
    out.insert("audience".into(), Value::String(summary.audience.clone()));
    out.insert("tokenId".into(), Value::String(summary.token_id.clone()));
    out.insert("issuedAt".into(), number(summary.issued_at));
    out.insert("expiresAt".into(), number(summary.expires_at));
    out.insert("claims".into(), Value::Object(summary.claims.clone()));
    Value::Object(out)
}
