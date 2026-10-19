//! Port of `packages/server/src/assertions.ts`: stateless assertions, short-lived HS256 JSON Web Tokens that
//! describe the caller for another service, signed with a key derived from the deployment secret.
//!
//! A downstream service holding only the derived key (`iam.assertionKey()`) verifies them with [`verify_assertion`]
//! without a database round trip. They grant nothing inside IAM itself.

use std::sync::{Arc, LazyLock};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use better_iam_auth::util::node_base64_decode;
use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, IamError, IamResult, SessionKind, js as core_js,
};
use hmac::{Hmac, Mac};
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::context::ServerContext;
use crate::contracts::{MutationContext, OperationDenied, OperationFailure, OperationResult};
use crate::js::{self, invalid_input, utf16_len};
use crate::utils::{date_now, id};
use crate::validation::{integer, object, text};

static HEADER: LazyLock<String> =
    LazyLock::new(|| encode(&json!({ "alg": "HS256", "typ": "JWT" })));
static AUDIENCE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$").expect("regex"));
static HEX_KEY: LazyLock<Regex> = LazyLock::new(|| Regex::new("^[0-9a-f]{64}$").expect("regex"));

/// Names `name in claims` finds on a plain object besides its own members (`Object.prototype`).
const OBJECT_PROTOTYPE: [&str; 12] = [
    "constructor",
    "__defineGetter__",
    "__defineSetter__",
    "hasOwnProperty",
    "__lookupGetter__",
    "__lookupSetter__",
    "isPrototypeOf",
    "propertyIsEnumerable",
    "toString",
    "valueOf",
    "__proto__",
    "toLocaleString",
];

/// `base64url(JSON.stringify(value))`.
fn encode(value: &Value) -> String {
    URL_SAFE_NO_PAD.encode(core_js::stringify(value))
}

/// `assertionKey(secret)`: the verification key for a deployment secret, SHA-256 of a purpose-bound derivation, as
/// hex.
pub fn assertion_key(secret: &str) -> String {
    hex::encode(Sha256::digest(
        format!("better-iam:assertion:{secret}").as_bytes(),
    ))
}

fn sign(key: &str, signing_input: &str) -> Vec<u8> {
    let key = hex::decode(key).unwrap_or_default();
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC accepts any key length");
    mac.update(signing_input.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// The options of [`verify_assertion`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VerifyAssertionOptions {
    /// One key, or several (`iam.assertionKeys()`) while a deployment secret rotates.
    pub key: Vec<String>,
    pub audience: String,
    pub issuer: Option<String>,
    pub now: Option<f64>,
    pub tolerance_seconds: Option<f64>,
}

fn invalid(message: &str) -> IamError {
    IamError::with_status("INVALID_ASSERTION", message, 401)
}

/// `verifyAssertion(token, options)`: verifies an assertion against the derived key, audience, optional issuer, and
/// time, and returns its claims.
pub fn verify_assertion(
    token: &str,
    options: &VerifyAssertionOptions,
) -> IamResult<Map<String, Value>> {
    if utf16_len(token) > 16384 {
        return Err(invalid("Malformed assertion"));
    }
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 || parts[0] != HEADER.as_str() {
        return Err(invalid("Malformed assertion"));
    }
    if options.key.is_empty() || options.key.iter().any(|key| !HEX_KEY.is_match(key)) {
        return Err(invalid("Invalid verification key"));
    }
    let provided = node_base64_decode(parts[2]);
    // Base64url decoding is lenient, so only the canonical spelling of a signature is accepted.
    if URL_SAFE_NO_PAD.encode(&provided) != parts[2] {
        return Err(invalid("Malformed assertion"));
    }
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    if !options.key.iter().any(|key| {
        let expected = sign(key, &signing_input);
        provided.len() == expected.len() && bool::from(provided.ct_eq(&expected))
    }) {
        return Err(invalid("Invalid signature"));
    }
    let payload = String::from_utf8_lossy(&node_base64_decode(parts[1])).into_owned();
    let claims = core_js::parse(&payload).map_err(|_| invalid("Malformed assertion"))?;
    let now = (options.now.unwrap_or_else(date_now) / 1000.0).floor();
    let tolerance = options.tolerance_seconds.unwrap_or(30.0);
    let Value::Object(claims) = claims else {
        return Err(invalid("Malformed assertion"));
    };
    let (
        Some(Value::String(_)),
        Some(Value::String(_)),
        Some(Value::Number(exp)),
        Some(Value::Number(iat)),
    ) = (
        claims.get("sub"),
        claims.get("tid"),
        claims.get("exp"),
        claims.get("iat"),
    )
    else {
        return Err(invalid("Malformed assertion"));
    };
    let (exp, iat) = (core_js::number_value(exp), core_js::number_value(iat));
    if claims.get("aud") != Some(&Value::String(options.audience.clone())) {
        return Err(invalid("Audience mismatch"));
    }
    if let Some(issuer) = &options.issuer
        && claims.get("iss") != Some(&Value::String(issuer.clone()))
    {
        return Err(invalid("Issuer mismatch"));
    }
    if exp + tolerance <= now {
        return Err(invalid("Assertion expired"));
    }
    if iat - tolerance > now {
        return Err(invalid("Assertion not yet valid"));
    }
    Ok(claims)
}

/// Who an assertion describes: the parts of the principal `issue` reads.
#[derive(Debug, Clone, PartialEq)]
pub struct AssertionSubject {
    pub identity_id: String,
    pub name: String,
    pub email: Option<String>,
    /// The session kind (`user`, `api-key`, `role`, `session-token`, `delegated`).
    pub kind: String,
    pub mfa: bool,
    pub method: Option<String>,
    pub impersonator_id: Option<String>,
    pub role_id: Option<String>,
    /// The session carries a policy or a source policy (a scoped credential).
    pub scoped: bool,
}

impl AssertionSubject {
    /// The subject of an authenticated principal.
    pub fn of(principal: &AuthenticatedPrincipal) -> Self {
        let session = &principal.session;
        Self {
            identity_id: principal.identity.id.clone(),
            name: principal.identity.name.clone(),
            email: principal.identity.email.clone(),
            kind: session.kind.as_str().to_owned(),
            mfa: session.mfa,
            method: session.method.map(|method| method.as_str().to_owned()),
            impersonator_id: session.impersonator_id.clone(),
            role_id: session.role_id.clone(),
            scoped: session.policy.is_some() || session.source_policy.is_some(),
        }
    }
}

/// What `issue` returns: the token, its expiry (epoch milliseconds) and its claims.
#[derive(Debug, Clone, PartialEq)]
pub struct IssuedAssertion {
    pub token: String,
    pub expires_at: f64,
    pub claims: Map<String, Value>,
}

impl IssuedAssertion {
    /// `{ token, expiresAt, claims }`.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("token".into(), Value::String(self.token.clone()));
        map.insert("expiresAt".into(), js::number(self.expires_at));
        map.insert("claims".into(), Value::Object(self.claims.clone()));
        Value::Object(map)
    }
}

/// The refusals `issue` checks before reading anything (scoped and delegated credentials).
pub fn refuse_scoped(subject: &AssertionSubject) -> OperationResult<()> {
    // The roles claim lists the identity's roles (or the assumed role), which would escape any scope-down.
    if subject.scoped {
        return Err(OperationDenied::new(Some(
            if subject.kind == "session-token" {
                "Scoped session tokens cannot obtain assertions"
            } else {
                "Scoped credentials cannot obtain assertions"
            },
        )));
    }
    // Likewise a delegated agent session, which is always bounded by its delegation's scope.
    if subject.kind == "delegated" {
        return Err(OperationDenied::new(Some(
            "Delegated agent sessions cannot obtain assertions",
        )));
    }
    Ok(())
}

/// The `audience` of `issue`: a URL-safe identifier of at most 256 characters (checked before the envelope runs).
pub fn assertion_audience(value: Option<&Value>) -> IamResult<String> {
    let audience = text(value, "audience", 256)?;
    if !AUDIENCE_PATTERN.is_match(&audience) {
        return Err(invalid_input("audience must be a URL-safe identifier"));
    }
    Ok(audience)
}

/// `ttlSeconds` (10 seconds to one hour, default five minutes).
pub fn assertion_ttl(input: &Value) -> IamResult<f64> {
    let ttl = js::defined(input.get("ttlSeconds"))
        .cloned()
        .unwrap_or_else(|| Value::from(300));
    integer(Some(&ttl), "ttlSeconds", 10.0, 3600.0)
}

/// Signs the claims of an assertion (the part of `issue` after the grant sources were read).
#[allow(clippy::too_many_arguments)]
pub fn sign_assertion(
    key: &str,
    issuer: &str,
    audience: &str,
    tenant_id: &str,
    subject: &AssertionSubject,
    now: f64,
    ttl: f64,
    group_ids: &[String],
    binding_role_ids: &[String],
    ext: Option<&Value>,
    jti: String,
) -> IamResult<IssuedAssertion> {
    let issued_at = (now / 1000.0).floor();
    // Role sessions assert the assumed role (`[principal.session.roleId!]`, null when a session lacks one) and no
    // groups; everyone else their bindings' roles and their groups, deduplicated and sorted.
    let (roles, groups): (Vec<Value>, Vec<String>) = if subject.kind == "role" {
        (
            vec![
                subject
                    .role_id
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            ],
            Vec::new(),
        )
    } else {
        let mut roles = js::unique(binding_role_ids.iter().cloned());
        js::sort_strings(&mut roles);
        let mut groups = js::unique(group_ids.iter().cloned());
        js::sort_strings(&mut groups);
        (roles.into_iter().map(Value::String).collect(), groups)
    };
    let mut claims = Map::new();
    claims.insert("iss".into(), Value::String(issuer.to_owned()));
    claims.insert("sub".into(), Value::String(subject.identity_id.clone()));
    claims.insert("aud".into(), Value::String(audience.to_owned()));
    claims.insert("iat".into(), js::number(issued_at));
    claims.insert("exp".into(), js::number(issued_at + ttl));
    claims.insert("jti".into(), Value::String(jti));
    claims.insert("tid".into(), Value::String(tenant_id.to_owned()));
    claims.insert("kind".into(), Value::String(subject.kind.clone()));
    claims.insert("mfa".into(), Value::Bool(subject.mfa));
    claims.insert("name".into(), Value::String(subject.name.clone()));
    claims.insert("roles".into(), Value::Array(roles));
    claims.insert(
        "groups".into(),
        Value::Array(groups.into_iter().map(Value::String).collect()),
    );
    if let Some(method) = subject.method.as_ref().filter(|method| !method.is_empty()) {
        claims.insert("method".into(), Value::String(method.clone()));
    }
    if let Some(impersonator) = subject.impersonator_id.as_ref().filter(|id| !id.is_empty()) {
        claims.insert("impersonatorId".into(), Value::String(impersonator.clone()));
    }
    if let Some(email) = subject.email.as_ref().filter(|email| !email.is_empty()) {
        claims.insert("email".into(), Value::String(email.clone()));
    }
    if let Some(ext) = ext {
        let ext = object(Some(ext))?;
        let serialized = core_js::stringify(&Value::Object(ext.clone()));
        if utf16_len(&serialized) > 4096 {
            return Err(invalid_input("claims must serialize to at most 4 KiB"));
        }
        for name in js::keys(ext) {
            if claims.contains_key(name.as_str()) || OBJECT_PROTOTYPE.contains(&name.as_str()) {
                return Err(invalid_input(format!("claims cannot redefine {name}")));
            }
        }
        claims.insert("ext".into(), Value::Object(ext.clone()));
    }
    let signing_input = format!("{}.{}", *HEADER, encode(&Value::Object(claims.clone())));
    let signature = URL_SAFE_NO_PAD.encode(sign(key, &signing_input));
    Ok(IssuedAssertion {
        token: format!("{signing_input}.{signature}"),
        expires_at: (issued_at + ttl) * 1000.0,
        claims,
    })
}

/// `createAssertionsApi(ctx)`.
pub struct AssertionsApi {
    ctx: Arc<ServerContext>,
    key: String,
}

/// `createAssertionsApi(ctx)`.
pub fn create_assertions_api(ctx: Arc<ServerContext>) -> AssertionsApi {
    let key = assertion_key(&ctx.options.secret);
    AssertionsApi { ctx, key }
}

impl AssertionsApi {
    /// `issue(credential, { tenantId, audience, ttlSeconds?, claims? })`: an assertion about the caller for
    /// `audience`, authorized as `iam:assertions:create` on `iam/{audience}`. Scoped and delegated credentials are
    /// refused (ACCESS_DENIED, audited).
    pub async fn issue(&self, credential: &CredentialInput, input: &Value) -> IamResult<Value> {
        let audience = assertion_audience(input.get("audience"))?;
        let ctx = self.ctx.clone();
        let key = self.key.clone();
        let tenant_id = input.get("tenantId").cloned();
        let input = input.clone();
        let audience_for = audience.clone();
        let mutation = Box::new(move |call: MutationContext| {
            Box::pin(async move {
                let MutationContext {
                    tx,
                    principal,
                    tenant,
                } = call;
                let subject = AssertionSubject::of(&principal);
                refuse_scoped(&subject)?;
                let ttl = assertion_ttl(&input)?;
                let now = ctx.now();
                let (group_ids, role_ids) = if principal.session.kind == SessionKind::Role {
                    (Vec::new(), Vec::new())
                } else {
                    let sources = ctx
                        .decisions()?
                        .grant_sources(&tx, &principal.identity.id, &tenant.id)
                        .await?;
                    (
                        sources.group_ids.into_iter().collect::<Vec<_>>(),
                        sources
                            .bindings
                            .iter()
                            .map(|binding| binding.role_id.clone())
                            .collect::<Vec<_>>(),
                    )
                };
                let issued = sign_assertion(
                    &key,
                    &ctx.config.origin(),
                    &audience_for,
                    &tenant.id,
                    &subject,
                    now,
                    ttl,
                    &group_ids,
                    &role_ids,
                    input.get("claims"),
                    id(),
                )
                .map_err(OperationFailure::from)?;
                Ok(issued.to_value())
            }) as futures::future::BoxFuture<'static, OperationResult<Value>>
        });
        self.ctx
            .operations()?
            .operation(
                credential,
                tenant_id.as_ref(),
                "iam:assertions:create",
                &audience,
                mutation,
                false,
            )
            .await
    }
}
