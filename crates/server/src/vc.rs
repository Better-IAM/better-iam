//! Port of `packages/server/src/vc.ts`.
//!
//! Verifiable credentials: each tenant is an issuer of SD-JWT VCs (IETF SD-JWT-based Verifiable Credentials) that
//! wallets hold and present, with selective disclosure, holder key binding, and revocation through a Token Status
//! List. Credential types map identity data (email, name, attributes, teams, department, static values) to claims.
//! People get credentials for themselves when policies allow `vc:request` on `credential-type/{name}`, through the
//! API or a wallet (OpenID4VCI pre-authorized code flow, served by the protocol mount of
//! api/verifiable_credentials.rs); administrators issue them for others (`iam:vc:issue`). Verifiers check
//! presentations offline with the issuer's keys and status list, or through `iam.verifiableCredentials.verify`.
//!
//! Records are read and written as raw JSON records, so member order and members this port does not know survive a
//! round trip (a mixed fleet shares the database with TypeScript). The typed structs below document the shapes.

use std::cmp::Ordering;
use std::sync::{Arc, LazyLock, Mutex, Weak};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use better_iam_auth::crypto::{decrypt_secret, encrypt_secret};
use better_iam_auth::util::node_base64_decode;
use better_iam_core::js::{cmp_utf16, is_safe_integer, number_to_string, utf16_len};
use better_iam_core::{
    AttributeType, AuditOutcome, AuthenticatedPrincipal, Filter, FindOptions, IamError, IamPlugin,
    IamResult, IamStoreExt, Identity, IdentityStatus, Record, ResourceTypeDefinition, Tenant,
    TenantStatus,
};
use hmac::{Hmac, Mac};
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::context::{ServerContext, Store};
use crate::contracts::{PreparedDecision, decide_on, is_root_override};
use crate::js::{number, truthy};
use crate::options::ResolvedResource;
use crate::sd_jwt::{
    HolderProofOptions, IssueSdJwtInput, IssuerKeyFn, SD_JWT_VC_TYPE, STATUS_INVALID,
    STATUS_SUSPENDED, STATUS_VALID, SdJwtError, SignStatusListInput, SigningKey, VerificationKey,
    VerifiedSdJwt, VerifyFailure, VerifySdJwtOptions, issue_sd_jwt, jwk_thumbprint, random_bytes,
    random_int, set_status_at, sign_status_list, status_at, verify_holder_proof, verify_sd_jwt,
};
use crate::session_tokens::jose::encode_base64url;
use crate::utils::{hash, id, same_hash};

const MINUTE: f64 = 60_000.0;
const DAY: f64 = 86_400_000.0;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedVcOptions {
    #[serde(rename = "maxLifetimeMs")]
    pub max_lifetime_ms: f64,
    #[serde(rename = "statusListSize")]
    pub status_list_size: f64,
    #[serde(rename = "offerLifetimeMs")]
    pub offer_lifetime_ms: f64,
    #[serde(rename = "statusListLifetimeMs")]
    pub status_list_lifetime_ms: f64,
    #[serde(rename = "statusListTtlSeconds")]
    pub status_list_ttl_seconds: f64,
    #[serde(rename = "recordRetentionMs")]
    pub record_retention_ms: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `'valid' | 'suspended' | 'revoked'`.
pub type VcCredentialStatus = Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VcCredentialType {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    /// The credential type identifier (`vct`); by default `{issuer}/types/{name}`.
    #[serde(rename = "vct")]
    pub vct: String,
    #[serde(rename = "claims")]
    pub claims: Vec<Value>,
    #[serde(rename = "lifetimeMs")]
    pub lifetime_ms: f64,
    /// People need an MFA session to get one for themselves.
    #[serde(rename = "requireMfa")]
    pub require_mfa: bool,
    #[serde(rename = "enabled")]
    pub enabled: bool,
    /// Wallet card colors (`#rrggbb`).
    #[serde(
        rename = "backgroundColor",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub background_color: Option<String>,
    #[serde(rename = "textColor", default, skip_serializing_if = "Option::is_none")]
    pub text_color: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VcIssuedCredential {
    #[serde(rename = "typeId")]
    pub type_id: String,
    #[serde(rename = "typeName")]
    pub type_name: String,
    #[serde(rename = "vct")]
    pub vct: String,
    #[serde(rename = "identityId")]
    pub identity_id: String,
    /// RFC 7638 thumbprint of the holder key the credential is bound to.
    #[serde(rename = "holderThumbprint")]
    pub holder_thumbprint: String,
    /// The `kid` of the issuer key that signed it.
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "statusListId")]
    pub status_list_id: String,
    #[serde(rename = "statusIndex")]
    pub status_index: f64,
    #[serde(rename = "status")]
    pub status: crate::vc::VcCredentialStatus,
    #[serde(rename = "claimNames")]
    pub claim_names: Vec<String>,
    #[serde(rename = "via")]
    pub via: String,
    /// Who is answerable: the holder for self-service, the administrator who offered it otherwise.
    #[serde(rename = "issuedBy")]
    pub issued_by: String,
    /// Requested by the holder for themselves (re-decided by the sweep), with the MFA state of that session.
    #[serde(rename = "selfService")]
    pub self_service: bool,
    #[serde(rename = "mfa")]
    pub mfa: bool,
    /// The wallet offer it was issued through.
    #[serde(rename = "offerId", default, skip_serializing_if = "Option::is_none")]
    pub offer_id: Option<String>,
    #[serde(rename = "issuedAt")]
    pub issued_at: f64,
    #[serde(rename = "validUntil")]
    pub valid_until: f64,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<f64>,
    #[serde(rename = "revokedBy", default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
    #[serde(rename = "reason", default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// When the record itself is swept: `validUntil` plus the record retention.
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VcIssuerKey {
    #[serde(rename = "kid")]
    pub kid: String,
    #[serde(rename = "status")]
    pub status: String,
    #[serde(rename = "alg")]
    pub alg: String,
    #[serde(rename = "publicJwk")]
    pub public_jwk: Value,
    #[serde(rename = "keySealed")]
    pub key_sealed: String,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "rotatedAt", default, skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<f64>,
    #[serde(rename = "retiredAt", default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<f64>,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A pre-authorized OpenID4VCI offer: one credential of one type for one identity.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VcOffer {
    #[serde(rename = "typeId")]
    pub type_id: String,
    #[serde(rename = "identityId")]
    pub identity_id: String,
    #[serde(rename = "codeHash")]
    pub code_hash: String,
    #[serde(
        rename = "txCodeHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub tx_code_hash: Option<String>,
    #[serde(rename = "txCodeAttempts")]
    pub tx_code_attempts: f64,
    /// For offers people make for themselves: whether the session had MFA (re-checked with policy at redemption).
    #[serde(rename = "selfService")]
    pub self_service: bool,
    #[serde(rename = "mfa")]
    pub mfa: bool,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(
        rename = "redeemedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub redeemed_at: Option<f64>,
    #[serde(
        rename = "accessTokenHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub access_token_hash: Option<String>,
    #[serde(
        rename = "accessExpiresAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub access_expires_at: Option<f64>,
    #[serde(
        rename = "credentialId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub credential_id: Option<String>,
    /// The offer's own end; after redemption, the access token's.
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VcStatusList {
    #[serde(rename = "size")]
    pub size: f64,
    #[serde(rename = "bits")]
    pub bits: f64,
    /// Raw status entries, base64.
    #[serde(rename = "bytes")]
    pub bytes: String,
    /// One bit per index handed out, base64 (indexes are never reused).
    #[serde(rename = "allocatedBits")]
    pub allocated_bits: String,
    #[serde(rename = "allocated")]
    pub allocated: f64,
    #[serde(rename = "version")]
    pub version: f64,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VcSweepResult {
    #[serde(rename = "examined")]
    pub examined: f64,
    #[serde(rename = "revoked")]
    pub revoked: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl VcSweepResult {
    /// `{ examined, revoked }`.
    pub fn to_json(&self) -> Value {
        json!({ "examined": number(self.examined), "revoked": number(self.revoked) })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifiedCredential {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// The credential type, when the issuer is a tenant of this deployment and still has it.
    #[serde(rename = "type", default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(rename = "status")]
    pub status: Value,
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

impl VerifiedCredential {
    /// `{ ...verified, tenantId, status: reference, type }` in TypeScript's member order.
    pub fn to_json(&self) -> Map<String, Value> {
        let verified = VerifiedSdJwt {
            issuer: self.issuer.clone(),
            key_id: self.key_id.clone(),
            vct: self.vct.clone(),
            claims: self.claims.clone(),
            disclosed: self.disclosed.clone(),
            holder_key: self.holder_key.clone(),
            status: Some(self.status.clone()),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            key_bound: self.key_bound,
            key_binding: self.key_binding.clone(),
            extra: Map::new(),
        };
        let mut out = verified.to_json();
        out.insert("tenantId".into(), Value::String(self.tenant_id.clone()));
        out.insert("status".into(), self.status.clone());
        match &self.r#type {
            Some(name) => out.insert("type".into(), Value::String(name.clone())),
            None => out.insert("type".into(), Value::Null),
        };
        if self.r#type.is_none() {
            out.shift_remove("type");
        }
        out
    }
}

// --- record helpers ----------------------------------------------------------------------------------------------

fn str_of<'a>(record: &'a Record, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// A numeric member (`NaN` when it is not a number, as arithmetic on `undefined` gives).
fn num_of(record: &Record, key: &str) -> f64 {
    record
        .get(key)
        .and_then(better_iam_core::js::as_number)
        .unwrap_or(f64::NAN)
}

/// `Math.min(a, b)`: NaN when either is NaN.
fn js_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.min(b)
    }
}

/// `(a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1)`.
fn by_created(a: &Record, b: &Record) -> Ordering {
    let difference = num_of(a, "createdAt") - num_of(b, "createdAt");
    if difference < 0.0 {
        Ordering::Less
    } else if difference > 0.0 {
        Ordering::Greater
    } else if cmp_utf16(str_of(a, "id"), str_of(b, "id")) == Ordering::Less {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

async fn find(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

fn origin(ctx: &ServerContext) -> String {
    ctx.config.base_url.origin().ascii_serialization()
}

/// A JavaScript exception that is not an `IamError`, as the server answers it.
fn thrown() -> IamError {
    crate::js::internal_error()
}

// --- options -----------------------------------------------------------------------------------------------------

fn bounded(value: Option<&Value>, fallback: f64, min: f64, max: f64, name: &str) -> IamResult<f64> {
    let resolved = match value {
        None | Some(Value::Null) => Some(fallback),
        Some(Value::Number(number)) => Some(better_iam_core::js::number_value(number)),
        Some(_) => None,
    };
    match resolved {
        Some(resolved) if is_safe_integer(resolved) && resolved >= min && resolved <= max => {
            Ok(resolved)
        }
        _ => Err(IamError::new(
            "INVALID_CONFIG",
            format!(
                "verifiableCredentials.{name} must be an integer between {} and {}",
                number_to_string(min),
                number_to_string(max)
            ),
        )),
    }
}

/// `resolveVcOptions(value)`: None when the module is off; INVALID_CONFIG for a malformed option.
pub fn resolve_vc_options(value: Option<&Value>) -> IamResult<Option<ResolvedVcOptions>> {
    let options = match value {
        None | Some(Value::Bool(false)) => return Ok(None),
        Some(Value::Bool(true)) => Map::new(),
        Some(Value::Object(options)) => options.clone(),
        Some(_) => {
            return Err(IamError::new(
                "INVALID_CONFIG",
                "verifiableCredentials must be true or an options object",
            ));
        }
    };
    let size = bounded(
        options.get("statusListSize"),
        65536.0,
        1024.0,
        1_048_576.0,
        "statusListSize",
    )?;
    if size % 1024.0 != 0.0 {
        return Err(IamError::new(
            "INVALID_CONFIG",
            "verifiableCredentials.statusListSize must be a multiple of 1024",
        ));
    }
    Ok(Some(ResolvedVcOptions {
        max_lifetime_ms: bounded(
            options.get("maxLifetimeMs"),
            365.0 * DAY,
            5.0 * MINUTE,
            5.0 * 365.0 * DAY,
            "maxLifetimeMs",
        )?,
        status_list_size: size,
        offer_lifetime_ms: bounded(
            options.get("offerLifetimeMs"),
            10.0 * MINUTE,
            MINUTE,
            DAY,
            "offerLifetimeMs",
        )?,
        status_list_lifetime_ms: bounded(
            options.get("statusListLifetimeMs"),
            DAY,
            10.0 * MINUTE,
            30.0 * DAY,
            "statusListLifetimeMs",
        )?,
        status_list_ttl_seconds: bounded(
            options.get("statusListTtlSeconds"),
            300.0,
            10.0,
            86_400.0,
            "statusListTtlSeconds",
        )?,
        record_retention_ms: bounded(
            options.get("recordRetentionDays"),
            30.0,
            1.0,
            3650.0,
            "recordRetentionDays",
        )? * DAY,
        extra: Map::new(),
    }))
}

/// `options.verifiableCredentials` as the TypeScript validators see it.
fn option_value(options: &crate::options::BetterIamOptions) -> Option<Value> {
    if let Some(model) = &options.model {
        return model.get("verifiableCredentials").cloned();
    }
    options
        .verifiable_credentials
        .as_ref()
        .map(|toggle| serde_json::to_value(toggle).unwrap_or(Value::Null))
}

type OptionsCache = Vec<(
    Weak<crate::options::BetterIamOptions>,
    Option<ResolvedVcOptions>,
)>;
static RESOLVED: LazyLock<Mutex<OptionsCache>> = LazyLock::new(|| Mutex::new(Vec::new()));

/// `vcOptions(ctx)`: the resolved options (resolved once per options object), None when the module is off.
pub fn vc_options(ctx: &ServerContext) -> IamResult<Option<ResolvedVcOptions>> {
    {
        let entries = RESOLVED
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((_, resolved)) = entries.iter().find(|(weak, _)| {
            weak.upgrade()
                .is_some_and(|live| Arc::ptr_eq(&live, &ctx.options))
        }) {
            return Ok(resolved.clone());
        }
    }
    let resolved = resolve_vc_options(option_value(&ctx.options).as_ref())?;
    let mut entries = RESOLVED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    entries.retain(|(weak, _)| weak.strong_count() > 0);
    entries.push((Arc::downgrade(&ctx.options), resolved.clone()));
    Ok(resolved)
}

/// `assertVc(ctx)`: FEATURE_DISABLED (403) unless the module is on.
pub fn assert_vc(ctx: &ServerContext) -> IamResult<ResolvedVcOptions> {
    vc_options(ctx)?.ok_or_else(|| {
        IamError::with_status(
            "FEATURE_DISABLED",
            "Verifiable credentials are not enabled on this deployment",
            403,
        )
    })
}

pub const CREDENTIAL_TYPE_RESOURCE: &str = "credential-type";
pub const VC_REQUEST_ACTION: &str = "vc:request";

/// The plugin that contributes `credential-type` and `vc:request` to the catalog.
struct VcPlugin;

#[async_trait::async_trait]
impl IamPlugin for VcPlugin {
    fn id(&self) -> &str {
        "better-iam:verifiable-credentials"
    }

    fn resource_types(&self) -> IndexMap<String, ResourceTypeDefinition> {
        let mut attributes = IndexMap::new();
        attributes.insert("name".to_owned(), AttributeType::String);
        attributes.insert("vct".to_owned(), AttributeType::String);
        attributes.insert("requireMfa".to_owned(), AttributeType::Boolean);
        let mut types = IndexMap::new();
        types.insert(
            CREDENTIAL_TYPE_RESOURCE.to_owned(),
            ResourceTypeDefinition {
                description: Some(
                    "A kind of verifiable credential the organization issues: credential-type/{name}"
                        .to_owned(),
                ),
                actions: Some(vec![VC_REQUEST_ACTION.to_owned()]),
                attributes: Some(attributes),
                ..ResourceTypeDefinition::default()
            },
        );
        types
    }
}

/// The catalog entries the module contributes when enabled: `credential-type` and `vc:request`.
pub fn vc_plugins(
    options: &crate::options::BetterIamOptions,
) -> IamResult<Vec<Arc<dyn better_iam_core::IamPlugin>>> {
    if resolve_vc_options(option_value(options).as_ref())?.is_none() {
        return Ok(Vec::new());
    }
    Ok(vec![Arc::new(VcPlugin)])
}

pub const VC_COLLECTIONS: &[&str] = &[
    "vcIssuerKeys",
    "vcCredentialTypes",
    "vcIssued",
    "vcStatusLists",
    "vcOffers",
    "vcNonces",
];

/// The issuer identifier (and base URL of its endpoints) of a tenant.
pub fn issuer_url(ctx: &ServerContext, tenant_id: &str) -> String {
    format!("{}{}/vc/{tenant_id}", origin(ctx), ctx.config.base_path)
}

/// The sealing context of an issuer key.
fn key_context(record_id: &str) -> String {
    format!("vc-issuer-key:{record_id}")
}

/// The tenant's issuer keys, oldest first.
pub async fn issuer_keys(tx: &Store, tenant_id: &str) -> IamResult<Vec<Record>> {
    let mut keys = find(
        tx,
        "vcIssuerKeys",
        Filter::new().eq("tenantId", tenant_id.to_owned()),
    )
    .await?;
    keys.sort_by(by_created);
    Ok(keys)
}

/// A new active ES256 signing key (P-256), its private half sealed with the deployment secret.
pub async fn create_issuer_key(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
    actor_id: &str,
) -> IamResult<Record> {
    use p256::pkcs8::EncodePrivateKey;
    let secret = loop {
        if let Ok(secret) = p256::SecretKey::from_slice(&random_bytes(32)) {
            break secret;
        }
    };
    let point =
        p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&secret.public_key(), false);
    let (Some(x), Some(y)) = (point.x(), point.y()) else {
        return Err(thrown());
    };
    let mut jwk = Map::new();
    jwk.insert("kty".into(), Value::String("EC".into()));
    jwk.insert("crv".into(), Value::String("P-256".into()));
    jwk.insert("x".into(), Value::String(encode_base64url(x)));
    jwk.insert("y".into(), Value::String(encode_base64url(y)));
    let kid = jwk_thumbprint(&jwk)?;
    let mut public_jwk = jwk.clone();
    public_jwk.insert("kid".into(), Value::String(kid.clone()));
    public_jwk.insert("alg".into(), Value::String("ES256".into()));
    public_jwk.insert("use".into(), Value::String("sig".into()));
    let record_id = id();
    let der = secret.to_pkcs8_der().map_err(|_| thrown())?;
    let mut record = Record::new();
    record.insert("id".into(), Value::String(record_id.clone()));
    record.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    record.insert("uniqueKey".into(), Value::String(kid.clone()));
    record.insert("kid".into(), Value::String(kid));
    record.insert("status".into(), Value::String("active".into()));
    record.insert("alg".into(), Value::String("ES256".into()));
    record.insert("publicJwk".into(), Value::Object(public_jwk));
    record.insert(
        "keySealed".into(),
        Value::String(encrypt_secret(
            &STANDARD.encode(der.as_bytes()),
            &ctx.options.secret,
            &key_context(&record_id),
        )),
    );
    record.insert("createdAt".into(), number(ctx.now()));
    record.insert("createdBy".into(), Value::String(actor_id.to_owned()));
    tx.insert("vcIssuerKeys", &record).await
}

/// The active signing key, created on first use.
pub async fn active_issuer_key(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
    actor_id: &str,
) -> IamResult<Record> {
    let active = issuer_keys(tx, tenant_id)
        .await?
        .into_iter()
        .find(|key| str_of(key, "status") == "active");
    match active {
        Some(key) => Ok(key),
        None => create_issuer_key(ctx, tx, tenant_id, actor_id).await,
    }
}

/// `openIssuerKey(ctx, key)`: the private key, opened with the current or a previous deployment secret.
pub fn open_issuer_key(ctx: &ServerContext, key: &Record) -> IamResult<SigningKey> {
    use p256::pkcs8::DecodePrivateKey;
    let mut secrets = vec![ctx.options.secret.clone()];
    secrets.extend(ctx.options.previous_secrets.clone().unwrap_or_default());
    let opened = decrypt_secret(
        str_of(key, "keySealed"),
        &secrets,
        &key_context(str_of(key, "id")),
    )?;
    let der = node_base64_decode(&opened);
    let secret = p256::SecretKey::from_pkcs8_der(&der).map_err(|_| thrown())?;
    Ok(SigningKey::P256(p256::ecdsa::SigningKey::from(secret)))
}

/// The public keys verifiers accept: active and previous (retired keys verify nothing).
pub async fn issuer_jwks(tx: &Store, tenant_id: &str) -> IamResult<Value> {
    let keys: Vec<Value> = issuer_keys(tx, tenant_id)
        .await?
        .into_iter()
        .filter(|key| str_of(key, "status") != "retired")
        .map(|key| key.get("publicJwk").cloned().unwrap_or(Value::Null))
        .collect();
    Ok(json!({ "keys": keys }))
}

/// The tenant's credential type named `name`.
pub async fn type_by_name(tx: &Store, tenant_id: &str, name: &str) -> IamResult<Option<Record>> {
    Ok(find(
        tx,
        "vcCredentialTypes",
        Filter::new()
            .eq("tenantId", tenant_id.to_owned())
            .eq("uniqueKey", name.to_owned()),
    )
    .await?
    .into_iter()
    .next())
}

/// `typeResource(type)`: `credential-type/{name}` with its attributes.
pub fn type_resource(record: &Record) -> ResolvedResource {
    let mut attributes = Map::new();
    attributes.insert(
        "name".into(),
        record.get("name").cloned().unwrap_or(Value::Null),
    );
    attributes.insert(
        "vct".into(),
        record.get("vct").cloned().unwrap_or(Value::Null),
    );
    attributes.insert(
        "requireMfa".into(),
        record.get("requireMfa").cloned().unwrap_or(Value::Null),
    );
    ResolvedResource {
        tenant_id: str_of(record, "tenantId").to_owned(),
        kind: CREDENTIAL_TYPE_RESOURCE.to_owned(),
        id: str_of(record, "name").to_owned(),
        attributes: Some(attributes),
        classification: None,
    }
}

/// Resolves `credential-type/{name}` for the decision engine; undefined for other types.
pub async fn resolve_credential_type_resource(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    reference: &better_iam_core::ResourceRef,
) -> IamResult<Option<crate::options::ResolvedResource>> {
    if reference.kind != CREDENTIAL_TYPE_RESOURCE || vc_options(ctx)?.is_none() {
        return Ok(None);
    }
    match type_by_name(tx, &reference.tenant_id, &reference.id).await? {
        Some(record) => Ok(Some(type_resource(&record))),
        None => Err(IamError::with_status(
            "NOT_FOUND",
            "Unknown credential type",
            404,
        )),
    }
}

/// Whether a principal may request a type for themselves (`vc:request`), outside a root override from elsewhere.
pub async fn may_request(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant: &Tenant,
    record: &Record,
) -> IamResult<bool> {
    let prepared = ctx
        .decisions()?
        .prepare_decision(tx, principal, tenant, VC_REQUEST_ACTION)
        .await?;
    if is_root_override(&prepared) && principal.identity.tenant_id != tenant.id {
        return Ok(false);
    }
    if let PreparedDecision::Fixed(decision) = &prepared {
        return Ok(decision.allowed);
    }
    // With security clearances, the type carries its classification label, as `resolve` attaches it.
    let resource = type_resource(record);
    let labeled = crate::decisions::module_resource_labels(
        ctx,
        tx,
        &tenant.id,
        std::slice::from_ref(&resource),
    )
    .await?;
    Ok(decide_on(
        &prepared,
        &labeled.apply(&resource),
        Some(VC_REQUEST_ACTION),
    )?
    .allowed)
}

/// Whether a person (an agent with its sponsor) is cleared for the classification label of credential type
/// `typeName` (security clearances), whatever roles and policies say: what an administrator offers or issues still
/// needs the holder to dominate the type's label, at the offer, at redemption, and in the sweep. Self-service
/// credentials are decided through `mayRequest`, which applies the label itself. True without clearances.
pub async fn holder_cleared(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant: &Tenant,
    identity: &Identity,
    type_name: &str,
    mfa: Option<bool>,
) -> IamResult<bool> {
    let principal = ctx
        .decisions()?
        .simulated_principal(identity, mfa.unwrap_or(false));
    crate::clearances::cleared_for(
        ctx,
        tx,
        &principal,
        tenant,
        &ResolvedResource {
            tenant_id: tenant.id.clone(),
            kind: CREDENTIAL_TYPE_RESOURCE.to_owned(),
            id: type_name.to_owned(),
            attributes: None,
            classification: None,
        },
        VC_REQUEST_ACTION,
    )
    .await
}

static CLAIM_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z_][a-zA-Z0-9_]{0,63}$").expect("valid regex"));
static STRUCTURE_KEYS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""(?:_sd|_sd_alg|\.\.\.)"\s*:"#).expect("valid regex"));
const SOURCES: &[&str] = &[
    "email",
    "emailVerified",
    "name",
    "identityId",
    "kind",
    "tenantId",
    "tenantName",
    "teams",
    "department",
    "static",
];

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

/// Validates a type's claim list (1 to 32 claims, unique names, known sources). `attributes` are the catalog's
/// identity attributes (`attribute:{name}` sources).
pub fn vc_claims<V>(
    value: Option<&Value>,
    attributes: &IndexMap<String, V>,
) -> IamResult<Vec<Value>> {
    let items = match value {
        Some(Value::Array(items)) if !items.is_empty() && items.len() <= 32 => items,
        _ => return Err(invalid("claims must list 1 to 32 claims")),
    };
    let mut seen: Vec<String> = Vec::new();
    let mut claims = Vec::with_capacity(items.len());
    for raw in items {
        let Value::Object(item) = raw else {
            return Err(invalid("Each claim is an object"));
        };
        let name = match item.get("name") {
            Some(Value::String(name))
                if CLAIM_NAME.is_match(name)
                    && !crate::sd_jwt::RESERVED_VC_CLAIMS.contains(&name.as_str())
                    && !seen.contains(name) =>
            {
                name.clone()
            }
            other => {
                return Err(invalid(format!(
                    "Invalid, reserved or repeated claim name {}",
                    crate::sd_jwt::slice_utf16(&crate::js::js_string(other), 64)
                )));
            }
        };
        seen.push(name.clone());
        let source = match item.get("source") {
            Some(Value::String(source)) => {
                let attribute = source.strip_prefix("attribute:");
                let known = SOURCES.contains(&source.as_str())
                    || attribute.is_some_and(|attribute| {
                        !attribute.is_empty() && attributes.contains_key(attribute)
                    });
                known.then(|| source.clone())
            }
            _ => None,
        };
        let Some(source) = source else {
            return Err(invalid(format!("Claim {name} has an unknown source")));
        };
        let mut claim = Map::new();
        claim.insert("name".into(), Value::String(name.clone()));
        claim.insert("source".into(), Value::String(source.clone()));
        if source == "static" {
            let serialized = item.get("value").map(better_iam_core::js::stringify);
            let Some(serialized) = serialized.filter(|text| utf16_len(text) <= 2048) else {
                return Err(invalid(format!(
                    "Static claim {name} needs a value of at most 2 KiB"
                )));
            };
            if STRUCTURE_KEYS.is_match(&serialized) {
                return Err(invalid(format!(
                    "Static claim {name} may not contain _sd, _sd_alg or ... keys"
                )));
            }
            claim.insert(
                "value".into(),
                item.get("value").cloned().unwrap_or(Value::Null),
            );
        }
        if let Some(selective) = item.get("selective") {
            let Value::Bool(selective) = selective else {
                return Err(invalid("selective must be a boolean"));
            };
            claim.insert("selective".into(), Value::Bool(*selective));
        }
        if let Some(required) = item.get("required") {
            let Value::Bool(required) = required else {
                return Err(invalid("required must be a boolean"));
            };
            claim.insert("required".into(), Value::Bool(*required));
        }
        if let Some(label) = item.get("label") {
            match label {
                Value::String(label)
                    if !better_iam_core::js::trim(label).is_empty() && utf16_len(label) <= 64 =>
                {
                    claim.insert("label".into(), Value::String(label.clone()));
                }
                _ => return Err(invalid("label must be 1-64 characters")),
            }
        }
        claims.push(Value::Object(claim));
    }
    Ok(claims)
}

/// `value === undefined || value === null || value === ''`.
fn missing(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(text)) => text.is_empty(),
        _ => false,
    }
}

/// The value of each claim for an identity; missing values are left out (required ones refuse).
async fn claim_values(
    tx: &Store,
    tenant: &Tenant,
    identity: &Identity,
    record: &Record,
    at: f64,
) -> IamResult<(Map<String, Value>, Map<String, Value>)> {
    let mut plain = Map::new();
    let mut disclosable = Map::new();
    let claims = match record.get("claims") {
        Some(Value::Array(claims)) => claims.clone(),
        _ => Vec::new(),
    };
    for claim in &claims {
        let Value::Object(claim) = claim else {
            return Err(thrown());
        };
        let source = claim
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let value: Option<Value> = match source {
            "email" => identity.email.clone().map(Value::String),
            "emailVerified" => {
                let has_email = identity
                    .email
                    .as_ref()
                    .is_some_and(|email| !email.is_empty());
                has_email.then_some(Value::Bool(identity.email_verified))
            }
            "name" => Some(Value::String(identity.name.clone())),
            "identityId" => Some(Value::String(identity.id.clone())),
            "kind" => serde_json::to_value(identity.kind).ok(),
            "tenantId" => Some(Value::String(tenant.id.clone())),
            "tenantName" => Some(Value::String(tenant.name.clone())),
            "teams" => {
                let mut names: Vec<String> = Vec::new();
                for team_id in
                    crate::teams::teams_of_at(tx, &tenant.id, &identity.id, Some(at), false).await?
                {
                    if let Some(team) = tx.get("teams", &team_id).await?
                        && str_of(&team, "tenantId") == tenant.id
                        && let Some(Value::String(name)) = team.get("name")
                    {
                        names.push(name.clone());
                    }
                }
                if names.is_empty() {
                    None
                } else {
                    crate::js::sort_strings(&mut names);
                    Some(Value::Array(names.into_iter().map(Value::String).collect()))
                }
            }
            "department" => {
                let department =
                    match crate::departments::department_of(tx, &tenant.id, &identity.id).await? {
                        Some(department_id) if !department_id.is_empty() => {
                            tx.get("departments", &department_id).await?
                        }
                        _ => None,
                    };
                department
                    .filter(|department| str_of(department, "tenantId") == tenant.id)
                    .and_then(|department| department.get("name").cloned())
            }
            "static" => claim.get("value").cloned(),
            _ => {
                let attribute = source.strip_prefix("attribute:").unwrap_or(source);
                identity
                    .attributes
                    .as_ref()
                    .and_then(|attributes| attributes.get(attribute).cloned())
            }
        };
        let name = claim
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if missing(value.as_ref()) {
            if truthy(claim.get("required")) {
                return Err(IamError::with_status(
                    "CLAIM_UNAVAILABLE",
                    format!("This person has no value for the claim {name}"),
                    409,
                ));
            }
            continue;
        }
        let value = value.unwrap_or(Value::Null);
        if claim.get("selective") == Some(&Value::Bool(false)) {
            plain.insert(name.to_owned(), value);
        } else {
            disclosable.insert(name.to_owned(), value);
        }
    }
    Ok((plain, disclosable))
}

/// Hands out a fresh status index (random, never reused), opening a new list when the current one is half full.
async fn allocate_status(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
    options: &ResolvedVcOptions,
) -> IamResult<(Record, f64)> {
    let mut lists = find(
        tx,
        "vcStatusLists",
        Filter::new().eq("tenantId", tenant_id.to_owned()),
    )
    .await?;
    lists.sort_by(by_created);
    let found = lists
        .into_iter()
        .find(|item| num_of(item, "allocated") < num_of(item, "size") / 2.0);
    let list = match found {
        Some(list) => list,
        None => {
            let now = ctx.now();
            let size = options.status_list_size;
            let mut record = Record::new();
            record.insert("id".into(), Value::String(id()));
            record.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
            record.insert("size".into(), number(size));
            record.insert("bits".into(), number(2.0));
            record.insert(
                "bytes".into(),
                Value::String(STANDARD.encode(vec![0u8; (size / 4.0) as usize])),
            );
            record.insert(
                "allocatedBits".into(),
                Value::String(STANDARD.encode(vec![0u8; (size / 8.0) as usize])),
            );
            record.insert("allocated".into(), number(0.0));
            record.insert("version".into(), number(0.0));
            record.insert("createdAt".into(), number(now));
            record.insert("updatedAt".into(), number(now));
            tx.insert("vcStatusLists", &record).await?
        }
    };
    let mut taken = node_base64_decode(str_of(&list, "allocatedBits"));
    let size = num_of(&list, "size");
    if !is_safe_integer(size) || size <= 0.0 {
        // `randomInt(max)` refuses a max that is not a positive safe integer (a RangeError).
        return Err(thrown());
    }
    loop {
        // Random indexes keep a credential's position from revealing when it was issued.
        let index = random_int(size as u64) as usize;
        let byte = index >> 3;
        let bit = 1u8 << (index & 7);
        let current = taken.get(byte).copied().unwrap_or(0);
        if current & bit != 0 {
            continue;
        }
        if let Some(slot) = taken.get_mut(byte) {
            *slot = current | bit;
        }
        let mut saved = list.clone();
        saved.insert(
            "allocatedBits".into(),
            Value::String(STANDARD.encode(&taken)),
        );
        saved.insert("allocated".into(), number(num_of(&list, "allocated") + 1.0));
        saved.insert("updatedAt".into(), number(ctx.now()));
        let saved = tx.put("vcStatusLists", &saved).await?;
        return Ok((saved, index as f64));
    }
}

/// Writes a credential's status (`valid`, `suspended` or `revoked`) into its list.
pub async fn write_status(
    ctx: &ServerContext,
    tx: &Store,
    record: &Record,
    status: &str,
) -> IamResult<()> {
    let list = tx
        .get("vcStatusLists", str_of(record, "statusListId"))
        .await?;
    let Some(list) = list.filter(|list| str_of(list, "tenantId") == str_of(record, "tenantId"))
    else {
        return Err(IamError::with_status(
            "NOT_FOUND",
            "Status list not found",
            404,
        ));
    };
    let mut bytes = node_base64_decode(str_of(&list, "bytes"));
    let value = match status {
        "revoked" => STATUS_INVALID,
        "suspended" => STATUS_SUSPENDED,
        _ => STATUS_VALID,
    };
    set_status_at(&mut bytes, num_of(record, "statusIndex"), 2.0, value)?;
    let mut saved = list.clone();
    saved.insert("bytes".into(), Value::String(STANDARD.encode(&bytes)));
    saved.insert("version".into(), number(num_of(&list, "version") + 1.0));
    saved.insert("updatedAt".into(), number(ctx.now()));
    tx.put("vcStatusLists", &saved).await?;
    Ok(())
}

/// Who issues a credential: a principal, or the system on someone's behalf (`{ actorId }`).
pub enum IssueActor<'a> {
    Principal(&'a AuthenticatedPrincipal),
    System(String),
}

/// The input of [`issue_credential`].
pub struct IssueCredentialInput<'a> {
    pub tenant: &'a Tenant,
    pub credential_type: &'a Record,
    pub identity: &'a Identity,
    pub holder_jwk: &'a Map<String, Value>,
    pub holder_thumbprint: &'a str,
    /// `request`, `offer` or `admin`.
    pub via: &'a str,
    pub actor: IssueActor<'a>,
    /// Who is answerable for it: the person for self-service, the administrator who made an offer for someone.
    pub issued_by: &'a str,
    pub self_service: bool,
    pub mfa: bool,
    pub offer_id: Option<&'a str>,
    pub deadline: Option<f64>,
}

/// Issues one SD-JWT VC of `type` for `identity`, bound to `holderJwk`, and records it (status index allocated,
/// audit event `vc:credential:issue`). The lifetime never outlives the account's scheduled expiry nor `deadline`
/// (the end of the grant or session that allowed a self-service request). Returns the credential and its record.
pub async fn issue_credential(
    ctx: &ServerContext,
    tx: &Store,
    input: IssueCredentialInput<'_>,
) -> IamResult<(String, Record)> {
    let options = assert_vc(ctx)?;
    let IssueCredentialInput {
        tenant,
        credential_type,
        identity,
        ..
    } = input;
    if !truthy(credential_type.get("enabled")) {
        return Err(IamError::with_status(
            "TYPE_DISABLED",
            "This credential type is disabled",
            409,
        ));
    }
    if identity.status != IdentityStatus::Active
        || ctx.identity_expired(identity)
        || identity.tenant_id != tenant.id
    {
        return Err(IamError::with_status(
            "IDENTITY_INACTIVE",
            "Credentials are issued to active members only",
            409,
        ));
    }
    let actor_id = match &input.actor {
        IssueActor::System(actor_id) => actor_id.clone(),
        IssueActor::Principal(principal) => principal.identity.id.clone(),
    };
    let key = active_issuer_key(ctx, tx, &tenant.id, &actor_id).await?;
    let now = ctx.now();
    let (plain, disclosable) = claim_values(tx, tenant, identity, credential_type, now).await?;
    let mut valid_until = now
        + js_min(
            num_of(credential_type, "lifetimeMs"),
            options.max_lifetime_ms,
        );
    if let Some(expires_at) = identity.expires_at {
        valid_until = js_min(valid_until, expires_at);
    }
    if let Some(deadline) = input.deadline {
        valid_until = js_min(valid_until, deadline);
    }
    if valid_until < now + MINUTE {
        return Err(IamError::with_status(
            "ACCESS_EXPIRING",
            "The access that allows this credential ends within a minute",
            409,
        ));
    }
    let (list, index) = allocate_status(ctx, tx, &tenant.id, &options).await?;
    let issuer = issuer_url(ctx, &tenant.id);
    let list_id = str_of(&list, "id").to_owned();
    let mut signed = plain.clone();
    signed.insert("iss".into(), Value::String(issuer.clone()));
    signed.insert("iat".into(), number((now / 1000.0).floor()));
    signed.insert("exp".into(), number((valid_until / 1000.0).floor()));
    signed.insert(
        "vct".into(),
        credential_type.get("vct").cloned().unwrap_or(Value::Null),
    );
    signed.insert("cnf".into(), json!({ "jwk": input.holder_jwk }));
    signed.insert(
        "status".into(),
        json!({ "status_list": { "idx": number(index), "uri": format!("{issuer}/status/{list_id}") } }),
    );
    let signing_key = open_issuer_key(ctx, &key)?;
    let issued = issue_sd_jwt(&IssueSdJwtInput {
        alg: "ES256",
        kid: str_of(&key, "kid"),
        key: &signing_key,
        typ: Some(SD_JWT_VC_TYPE),
        plain: &signed,
        disclosable: &disclosable,
        decoys: Some(random_int(4) as usize),
    })
    .map_err(IamError::from)?;
    let mut claim_names: Vec<String> = plain.keys().chain(disclosable.keys()).cloned().collect();
    crate::js::sort_strings(&mut claim_names);
    let claim_names: Vec<Value> = claim_names.into_iter().map(Value::String).collect();
    let mut record = Record::new();
    record.insert("id".into(), Value::String(id()));
    record.insert("tenantId".into(), Value::String(tenant.id.clone()));
    record.insert(
        "uniqueKey".into(),
        Value::String(format!("{list_id}:{}", number_to_string(index))),
    );
    record.insert(
        "typeId".into(),
        credential_type.get("id").cloned().unwrap_or(Value::Null),
    );
    record.insert(
        "typeName".into(),
        credential_type.get("name").cloned().unwrap_or(Value::Null),
    );
    record.insert(
        "vct".into(),
        credential_type.get("vct").cloned().unwrap_or(Value::Null),
    );
    record.insert("identityId".into(), Value::String(identity.id.clone()));
    record.insert(
        "holderThumbprint".into(),
        Value::String(input.holder_thumbprint.to_owned()),
    );
    record.insert(
        "keyId".into(),
        key.get("kid").cloned().unwrap_or(Value::Null),
    );
    record.insert("statusListId".into(), Value::String(list_id.clone()));
    record.insert("statusIndex".into(), number(index));
    record.insert("status".into(), Value::String("valid".into()));
    record.insert("claimNames".into(), Value::Array(claim_names.clone()));
    record.insert("via".into(), Value::String(input.via.to_owned()));
    record.insert("issuedBy".into(), Value::String(input.issued_by.to_owned()));
    record.insert("selfService".into(), Value::Bool(input.self_service));
    record.insert("mfa".into(), Value::Bool(input.mfa));
    if let Some(offer_id) = input.offer_id.filter(|offer_id| !offer_id.is_empty()) {
        record.insert("offerId".into(), Value::String(offer_id.to_owned()));
    }
    record.insert("issuedAt".into(), number(now));
    record.insert("validUntil".into(), number(valid_until));
    record.insert(
        "expiresAt".into(),
        number(valid_until + options.record_retention_ms),
    );
    let record = tx.insert("vcIssued", &record).await?;
    let record_id = str_of(&record, "id").to_owned();
    let mut metadata = Map::new();
    metadata.insert(
        "type".into(),
        credential_type.get("name").cloned().unwrap_or(Value::Null),
    );
    metadata.insert("credentialId".into(), Value::String(record_id.clone()));
    metadata.insert("identityId".into(), Value::String(identity.id.clone()));
    metadata.insert("issuedBy".into(), Value::String(input.issued_by.to_owned()));
    metadata.insert(
        "holder".into(),
        Value::String(input.holder_thumbprint.to_owned()),
    );
    metadata.insert("via".into(), Value::String(input.via.to_owned()));
    metadata.insert(
        "claims".into(),
        record
            .get("claimNames")
            .cloned()
            .unwrap_or(Value::Array(claim_names)),
    );
    metadata.insert("validUntil".into(), number(valid_until));
    if let Some(offer_id) = input.offer_id.filter(|offer_id| !offer_id.is_empty()) {
        metadata.insert("offerId".into(), Value::String(offer_id.to_owned()));
    }
    let resource_id = format!("vc/credentials/{record_id}");
    match &input.actor {
        IssueActor::System(actor_id) => {
            let mut event = Record::new();
            event.insert("id".into(), Value::String(id()));
            event.insert("tenantId".into(), Value::String(tenant.id.clone()));
            event.insert("actorId".into(), Value::String(actor_id.clone()));
            event.insert("action".into(), Value::String("vc:credential:issue".into()));
            event.insert("resourceId".into(), Value::String(resource_id));
            event.insert("outcome".into(), Value::String("allow".into()));
            event.insert("timestamp".into(), number(now));
            event.insert("metadata".into(), Value::Object(metadata));
            ctx.events()?.record_audit(tx, &event).await?;
        }
        IssueActor::Principal(principal) => {
            ctx.events()?
                .audit(
                    tx,
                    principal,
                    "vc:credential:issue",
                    &tenant.id,
                    &resource_id,
                    AuditOutcome::Allow,
                    false,
                    Some(metadata),
                )
                .await?;
        }
    }
    Ok((issued.sd_jwt, record))
}

const NONCE_MS: f64 = 5.0 * MINUTE;

/// `createHash('sha256').update('better-iam:vc-nonce:' + secret).digest()`.
fn nonce_key(ctx: &ServerContext) -> Vec<u8> {
    Sha256::digest(format!("better-iam:vc-nonce:{}", ctx.options.secret).as_bytes()).to_vec()
}

fn nonce_mac(ctx: &ServerContext, tenant_id: &str, issued: &str, random: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&nonce_key(ctx)).expect("HMAC accepts any key length");
    mac.update(format!("{tenant_id}.{issued}.{random}").as_bytes());
    encode_base64url(&mac.finalize().into_bytes())
}

/// `Number.prototype.toString(radix)` (V8's `DoubleToRadixCString`).
fn to_radix_string(value: f64, radix: u32) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.to_owned();
    }
    if value == 0.0 {
        return "0".to_owned();
    }
    const CHARS: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    let radix_f = f64::from(radix);
    let negative = value < 0.0;
    let value = value.abs();
    let mut integer = value.floor();
    let mut fraction = value - integer;
    let next = f64::from_bits(value.to_bits() + 1);
    let mut delta = (0.5 * (next - value)).max(f64::from_bits(1));
    let mut fraction_digits: Vec<u8> = Vec::new();
    if fraction >= delta {
        loop {
            fraction *= radix_f;
            delta *= radix_f;
            let digit = fraction as usize;
            fraction_digits.push(CHARS[digit]);
            fraction -= digit as f64;
            if (fraction > 0.5 || (fraction == 0.5 && (digit & 1) == 1)) && fraction + delta > 1.0 {
                // Round up, propagating carries.
                loop {
                    let Some(last) = fraction_digits.pop() else {
                        integer += 1.0;
                        break;
                    };
                    let digit = if last > b'9' {
                        usize::from(last - b'a') + 10
                    } else {
                        usize::from(last - b'0')
                    };
                    if digit + 1 < radix as usize {
                        fraction_digits.push(CHARS[digit + 1]);
                        break;
                    }
                }
                break;
            }
            if fraction < delta {
                break;
            }
        }
    }
    let mut integer_digits: Vec<u8> = Vec::new();
    while integer / radix_f >= 9_007_199_254_740_992.0 {
        integer /= radix_f;
        integer_digits.push(b'0');
    }
    loop {
        let remainder = integer % radix_f;
        integer_digits.push(CHARS[remainder as usize]);
        integer = (integer - remainder) / radix_f;
        if integer <= 0.0 {
            break;
        }
    }
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    out.extend(integer_digits.iter().rev().map(|byte| *byte as char));
    if !fraction_digits.is_empty() {
        out.push('.');
        out.extend(fraction_digits.iter().map(|byte| *byte as char));
    }
    out
}

/// `Number.parseInt(text, 36)`.
fn parse_int_36(text: &str) -> f64 {
    let trimmed = better_iam_core::js::trim(text);
    let (negative, digits) = match trimmed.as_bytes().first() {
        Some(b'-') => (true, &trimmed[1..]),
        Some(b'+') => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    let mut value = 0.0f64;
    let mut any = false;
    for c in digits.chars() {
        let Some(digit) = c.to_digit(36) else {
            break;
        };
        value = value * 36.0 + f64::from(digit);
        any = true;
    }
    if !any {
        return f64::NAN;
    }
    if negative { -value } else { value }
}

/// A proof nonce (`c_nonce`) for one tenant, valid five minutes: stateless (`{time}.{random}.{mac}`), so handing
/// them out writes nothing; only using one records it, once.
pub fn create_nonce(ctx: &ServerContext, tenant_id: &str) -> String {
    let issued = to_radix_string(ctx.now(), 36);
    let random = encode_base64url(&random_bytes(16));
    let mac = nonce_mac(ctx, tenant_id, &issued, &random);
    format!("{issued}.{random}.{mac}")
}

/// Consumes a nonce; false when forged, expired, another tenant's, or used before.
pub async fn consume_nonce(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
    value: Option<&str>,
) -> IamResult<bool> {
    let Some(value) = value.filter(|value| utf16_len(value) <= 128) else {
        return Ok(false);
    };
    let parts: Vec<&str> = value.split('.').collect();
    let [issued, random, mac] = parts.as_slice() else {
        return Ok(false);
    };
    let expected = nonce_mac(ctx, tenant_id, issued, random);
    if expected.len() != mac.len()
        || !bool::from(subtle::ConstantTimeEq::ct_eq(
            expected.as_bytes(),
            mac.as_bytes(),
        ))
    {
        return Ok(false);
    }
    let at = parse_int_36(issued);
    let now = ctx.now();
    if !is_safe_integer(at) || at > now + MINUTE || now - at > NONCE_MS {
        return Ok(false);
    }
    let record_id = hash(&format!("vc-nonce:{value}"));
    if tx.get("vcNonces", &record_id).await?.is_some() {
        return Ok(false);
    }
    let mut record = Record::new();
    record.insert("id".into(), Value::String(record_id));
    record.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    record.insert("expiresAt".into(), number(at + NONCE_MS));
    record.insert("usedAt".into(), number(now));
    tx.insert("vcNonces", &record).await?;
    Ok(true)
}

/// The holder key of a checked proof: the public JWK and its thumbprint.
#[derive(Debug, Clone, PartialEq)]
pub struct HolderKey {
    pub jwk: Map<String, Value>,
    pub thumbprint: String,
}

/// Checks an OpenID4VCI proof for the tenant's issuer and consumes its nonce; returns the holder key.
pub async fn holder_from_proof(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
    proof: Option<&Value>,
) -> IamResult<HolderKey> {
    let audience = issuer_url(ctx, tenant_id);
    let checked = match verify_holder_proof(
        proof,
        &HolderProofOptions {
            audience: &audience,
            now: Some(ctx.now()),
            max_age_seconds: None,
        },
    )
    .await
    {
        Ok(checked) => checked,
        Err(failure) => {
            let message = match failure {
                VerifyFailure::SdJwt(error) => error.message,
                VerifyFailure::Other(error) => error.message,
            };
            return Err(IamError::with_status("INVALID_PROOF", message, 400));
        }
    };
    if !consume_nonce(ctx, tx, tenant_id, checked.nonce.as_deref()).await? {
        return Err(IamError::with_status(
            "INVALID_NONCE",
            "The proof needs a fresh nonce from verifiableCredentials.nonce",
            400,
        ));
    }
    Ok(HolderKey {
        jwk: checked.jwk,
        thumbprint: checked.thumbprint,
    })
}

/// Signed Status List Tokens, cached per list version and signing key until half their cache time passed.
type TokenCache = Vec<(
    Weak<crate::options::BetterIamOptions>,
    IndexMap<String, (String, f64)>,
)>;
static STATUS_TOKENS: LazyLock<Mutex<TokenCache>> = LazyLock::new(|| Mutex::new(Vec::new()));

pub async fn status_list_token(
    ctx: &ServerContext,
    reader: &Store,
    list: &Record,
) -> IamResult<String> {
    let options = assert_vc(ctx)?;
    // A list exists only after a credential was issued, and with it the key: reads never create one.
    let key = issuer_keys(reader, str_of(list, "tenantId"))
        .await?
        .into_iter()
        .find(|item| str_of(item, "status") == "active");
    let Some(key) = key else {
        return Err(IamError::with_status("NOT_FOUND", "No issuer key", 404));
    };
    let cache_key = format!(
        "{}:{}:{}",
        str_of(list, "id"),
        crate::js::js_string(list.get("version")),
        str_of(&key, "kid")
    );
    let now = ctx.now();
    {
        let entries = STATUS_TOKENS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let hit = entries
            .iter()
            .find(|(weak, _)| {
                weak.upgrade()
                    .is_some_and(|live| Arc::ptr_eq(&live, &ctx.options))
            })
            .and_then(|(_, cache)| cache.get(&cache_key).cloned());
        if let Some((token, at)) = hit
            && now - at < (options.status_list_ttl_seconds * 1000.0) / 2.0
            && now >= at
        {
            return Ok(token);
        }
    }
    let bytes = node_base64_decode(str_of(list, "bytes"));
    let signing_key = open_issuer_key(ctx, &key)?;
    let signed = sign_status_list(&SignStatusListInput {
        uri: &format!(
            "{}/status/{}",
            issuer_url(ctx, str_of(list, "tenantId")),
            str_of(list, "id")
        ),
        bytes: &bytes,
        bits: 2.0,
        alg: "ES256",
        kid: str_of(&key, "kid"),
        key: &signing_key,
        issued_at: now,
        expires_at: now + options.status_list_lifetime_ms,
        ttl_seconds: options.status_list_ttl_seconds,
    })?;
    let mut entries = STATUS_TOKENS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    entries.retain(|(weak, _)| weak.strong_count() > 0);
    let position = entries.iter().position(|(weak, _)| {
        weak.upgrade()
            .is_some_and(|live| Arc::ptr_eq(&live, &ctx.options))
    });
    let cache = match position {
        Some(position) => &mut entries[position].1,
        None => {
            entries.push((Arc::downgrade(&ctx.options), IndexMap::new()));
            let last = entries.len() - 1;
            &mut entries[last].1
        }
    };
    if cache.len() > 1000 {
        cache.clear();
    }
    cache.insert(cache_key, (signed.clone(), now));
    Ok(signed)
}

/// The options of [`verify_local_presentation`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LocalVerifyOptions {
    /// The verifier's audience, compared with the key-binding JWT's `aud` by identity.
    pub audience: Option<Value>,
    /// The nonce the verifier issued, compared with the key-binding JWT's `nonce` by identity.
    pub nonce: Option<Value>,
    /// False accepts a credential without key binding (`requireKeyBinding: false`).
    pub require_key_binding: Option<bool>,
    /// Only credentials of this tenant (when truthy).
    pub tenant_id: Option<Value>,
}

/// Verifies a presentation of a credential this deployment issued: the tenant's keys, disclosures, key binding (for
/// `audience` and `nonce`, both required unless `requireKeyBinding: false`) and the credential's current standing:
/// revoked and suspended credentials fail, and so do those of holders who are no longer active members or of an
/// organization that is suspended (even before the sweep revokes them). Reads only, outside any transaction.
pub async fn verify_local_presentation(
    ctx: &ServerContext,
    presentation: &str,
    options: &LocalVerifyOptions,
) -> Result<VerifiedCredential, VerifyFailure> {
    assert_vc(ctx)?;
    if options.require_key_binding != Some(false)
        && (options.audience.is_none() || options.nonce.is_none())
    {
        return Err(invalid(
            "Verify a presentation for your audience and the nonce you issued; without them it could be a replay",
        )
        .into());
    }
    let reader = ctx.store.clone();
    let prefix = format!("{}{}/vc/", origin(ctx), ctx.config.base_path);
    let lookup_reader = reader.clone();
    let lookup_prefix = prefix.clone();
    let wanted_tenant = options.tenant_id.clone();
    let issuer_key: IssuerKeyFn<'_> = Box::new(move |kid: String, issuer: String| {
        Box::pin(async move {
            let Some(tenant_id) = issuer.strip_prefix(&lookup_prefix) else {
                return Ok(None);
            };
            if tenant_id.is_empty()
                || tenant_id.contains('/')
                || (truthy(wanted_tenant.as_ref())
                    && wanted_tenant.as_ref().and_then(Value::as_str) != Some(tenant_id))
            {
                return Ok(None);
            }
            let key = issuer_keys(&lookup_reader, tenant_id)
                .await?
                .into_iter()
                .find(|item| str_of(item, "kid") == kid && str_of(item, "status") != "retired");
            Ok(key.and_then(|key| match key.get("publicJwk") {
                Some(Value::Object(jwk)) => Some(VerificationKey::Jwk(jwk.clone())),
                _ => None,
            }))
        })
    });
    let mut verify_options = VerifySdJwtOptions::new(issuer_key);
    verify_options.now = Some(ctx.now());
    verify_options.require_key_binding = options.require_key_binding;
    verify_options.audience = options.audience.clone();
    verify_options.nonce = options.nonce.clone();
    let verified = verify_sd_jwt(presentation, verify_options).await?;
    let tenant_id = verified
        .issuer
        .strip_prefix(&prefix)
        .unwrap_or_default()
        .to_owned();
    let reference = verified.status_reference();
    let status_prefix = format!("{}/status/", issuer_url(ctx, &tenant_id));
    let list_id = reference
        .as_ref()
        .and_then(|(_, uri)| uri.strip_prefix(&status_prefix))
        .filter(|list_id| !list_id.is_empty());
    let list = match list_id {
        Some(list_id) => reader.get("vcStatusLists", list_id).await?,
        None => None,
    };
    let (Some((index, _)), Some(list)) = (reference.clone(), list) else {
        return Err(SdJwtError::new(
            "status-unavailable",
            "The credential has no status this issuer knows",
        )
        .into());
    };
    if str_of(&list, "tenantId") != tenant_id {
        return Err(SdJwtError::new(
            "status-unavailable",
            "The credential has no status this issuer knows",
        )
        .into());
    }
    let status = status_at(&node_base64_decode(str_of(&list, "bytes")), index, 2.0)?;
    if status == STATUS_INVALID {
        return Err(SdJwtError::new("revoked", "The credential was revoked").into());
    }
    if status == STATUS_SUSPENDED {
        return Err(SdJwtError::new("suspended", "The credential is suspended").into());
    }
    if status != STATUS_VALID {
        return Err(
            SdJwtError::new("status-unavailable", "The credential status is unknown").into(),
        );
    }
    let record = find(
        &reader,
        "vcIssued",
        Filter::new().eq("tenantId", tenant_id.clone()).eq(
            "uniqueKey",
            format!("{}:{}", str_of(&list, "id"), number_to_string(index)),
        ),
    )
    .await?
    .into_iter()
    .next();
    let Some(record) = record else {
        return Err(SdJwtError::new(
            "status-unavailable",
            "The credential is unknown to this issuer",
        )
        .into());
    };
    let identity: Option<Identity> = match reader
        .get("identities", str_of(&record, "identityId"))
        .await?
    {
        Some(identity) => Some(crate::port::decode(identity)?),
        None => None,
    };
    if !identity.is_some_and(|identity| {
        identity.status == IdentityStatus::Active && !ctx.identity_expired(&identity)
    }) {
        return Err(SdJwtError::new("revoked", "The holder is no longer a member").into());
    }
    let tenant: Option<Tenant> = match reader.get("tenants", &tenant_id).await? {
        Some(tenant) => Some(crate::port::decode(tenant)?),
        None => None,
    };
    let suspended = match &tenant {
        None => true,
        Some(tenant) => ctx
            .ancestry(&reader, tenant)
            .await?
            .iter()
            .any(|item| item.status != TenantStatus::Active),
    };
    if suspended {
        return Err(SdJwtError::new("suspended", "The issuing organization is suspended").into());
    }
    let status_value = verified.status.clone().unwrap_or(Value::Null);
    Ok(VerifiedCredential {
        tenant_id,
        r#type: record
            .get("typeName")
            .and_then(Value::as_str)
            .map(str::to_owned),
        status: status_value,
        issuer: verified.issuer,
        key_id: verified.key_id,
        vct: verified.vct,
        claims: verified.claims,
        disclosed: verified.disclosed,
        holder_key: verified.holder_key,
        issued_at: verified.issued_at,
        expires_at: verified.expires_at,
        key_bound: verified.key_bound,
        key_binding: verified.key_binding,
        extra: Map::new(),
    })
}

/// Revokes valid credentials whose holder is no longer an active member, self-service ones whose holder may no
/// longer request them (`vc:request` decided again, with the MFA state of the issuing session), and, with security
/// clearances, any other whose holder no longer dominates the type's classification label (`holderCleared`). A
/// scheduler job; each tenant in its own transaction. `input` is `{ tenantId? }`.
pub async fn sweep_credentials(
    ctx: &Arc<ServerContext>,
    input: Option<&Value>,
) -> IamResult<crate::vc::VcSweepResult> {
    assert_vc(ctx)?;
    let requested = match input {
        None => None,
        // Reading `tenantId` of `null` is a TypeError.
        Some(Value::Null) => return Err(thrown()),
        Some(Value::Object(input)) => input.get("tenantId").filter(|value| truthy(Some(value))),
        // A primitive has no `tenantId`.
        Some(_) => None,
    };
    let now = ctx.now();
    let tenant_ids: Vec<String> = match requested {
        Some(tenant_id) => vec![crate::js::js_string(Some(tenant_id))],
        None => {
            let valid = find(&ctx.store, "vcIssued", Filter::new().eq("status", "valid")).await?;
            crate::js::unique(
                valid
                    .iter()
                    .filter(|record| num_of(record, "validUntil") > now)
                    .map(|record| str_of(record, "tenantId").to_owned()),
            )
        }
    };
    let mut examined = 0.0;
    let mut revoked = 0.0;
    for tenant_id in tenant_ids {
        let ctx = ctx.clone();
        let (seen, swept) = ctx
            .store
            .clone()
            .transaction(move |tx| async move { sweep_tenant(&ctx, &tx, &tenant_id, now).await })
            .await?;
        examined += seen;
        revoked += swept;
    }
    Ok(VcSweepResult {
        examined,
        revoked,
        extra: Map::new(),
    })
}

/// One tenant of [`sweep_credentials`]: how many credentials were examined and how many revoked.
async fn sweep_tenant(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    now: f64,
) -> IamResult<(f64, f64)> {
    let (mut examined, mut revoked) = (0.0, 0.0);
    let Some(tenant) = tx.get("tenants", tenant_id).await? else {
        return Ok((examined, revoked));
    };
    let tenant: Tenant = crate::port::decode(tenant)?;
    let records: Vec<Record> = find(
        tx,
        "vcIssued",
        Filter::new()
            .eq("tenantId", tenant_id.to_owned())
            .eq("status", "valid"),
    )
    .await?
    .into_iter()
    .filter(|record| num_of(record, "validUntil") > now)
    .collect();
    let mut types: IndexMap<String, Option<Record>> = IndexMap::new();
    for record in records {
        examined += 1.0;
        let identity: Option<Identity> =
            match tx.get("identities", str_of(&record, "identityId")).await? {
                Some(identity) => Some(crate::port::decode(identity)?),
                None => None,
            };
        let mfa = record.get("mfa") == Some(&Value::Bool(true));
        let mut reason: Option<&str> = None;
        match &identity {
            Some(identity)
                if identity.status == IdentityStatus::Active && !ctx.identity_expired(identity) =>
            {
                if truthy(record.get("selfService")) {
                    let type_id = str_of(&record, "typeId").to_owned();
                    if !types.contains_key(&type_id) {
                        let found = tx.get("vcCredentialTypes", &type_id).await?;
                        types.insert(type_id.clone(), found);
                    }
                    let credential_type = types.get(&type_id).cloned().flatten();
                    let principal = ctx.decisions()?.simulated_principal(identity, mfa);
                    // Only a clear refusal revokes: a suspended organization's credentials already fail verification.
                    let allowed = match &credential_type {
                        Some(credential_type)
                            if !truthy(credential_type.get("requireMfa")) || mfa =>
                        {
                            may_request(ctx, tx, &principal, &tenant, credential_type).await?
                        }
                        _ => false,
                    };
                    let suspended = ctx
                        .ancestry(tx, &tenant)
                        .await?
                        .iter()
                        .any(|item| item.status != TenantStatus::Active);
                    if !allowed && !suspended {
                        reason = Some("access-changed");
                    }
                } else if !holder_cleared(
                    ctx,
                    tx,
                    &tenant,
                    identity,
                    str_of(&record, "typeName"),
                    Some(mfa),
                )
                .await?
                {
                    // An administrator's credential needs no `vc:request`, but its holder must still be cleared for
                    // the type's classification label (security clearances).
                    let suspended = ctx
                        .ancestry(tx, &tenant)
                        .await?
                        .iter()
                        .any(|item| item.status != TenantStatus::Active);
                    if !suspended {
                        reason = Some("access-changed");
                    }
                }
            }
            _ => reason = Some("identity-inactive"),
        }
        let Some(reason) = reason else {
            continue;
        };
        write_status(ctx, tx, &record, "revoked").await?;
        let mut changed = record.clone();
        changed.insert("status".into(), Value::String("revoked".into()));
        changed.insert("revokedAt".into(), number(now));
        changed.insert(
            "revokedBy".into(),
            Value::String("deployment-operator".into()),
        );
        changed.insert("reason".into(), Value::String(reason.to_owned()));
        tx.put("vcIssued", &changed).await?;
        let mut event = Record::new();
        event.insert("id".into(), Value::String(id()));
        event.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
        event.insert(
            "actorId".into(),
            Value::String("deployment-operator".into()),
        );
        event.insert(
            "action".into(),
            Value::String("vc:credential:revoke".into()),
        );
        event.insert(
            "resourceId".into(),
            Value::String(format!("vc/credentials/{}", str_of(&record, "id"))),
        );
        event.insert("outcome".into(), Value::String("allow".into()));
        event.insert("timestamp".into(), number(now));
        event.insert(
            "metadata".into(),
            json!({ "reason": reason, "identityId": record.get("identityId").cloned().unwrap_or(Value::Null) }),
        );
        ctx.events()?.record_audit(tx, &event).await?;
        revoked += 1.0;
    }
    Ok((examined, revoked))
}

/// Pre-authorized codes and access tokens name their offer: `biam_vco.{offerId}.{secret}` / `biam_vcat.…`.
pub fn offer_token(prefix: &str, offer_id: &str) -> String {
    format!(
        "{prefix}.{offer_id}.{}",
        encode_base64url(&random_bytes(32))
    )
}

/// The offer a pre-authorized code or access token names, when it has the shape.
pub fn offer_id_of(value: Option<&Value>, prefix: &str) -> Option<String> {
    let value = match value {
        Some(Value::String(value)) if utf16_len(value) <= 256 => value,
        _ => return None,
    };
    let parts: Vec<&str> = value.split('.').collect();
    match parts.as_slice() {
        [head, offer_id, secret]
            if *head == prefix && !offer_id.is_empty() && !secret.is_empty() =>
        {
            Some((*offer_id).to_owned())
        }
        _ => None,
    }
}

/// `typeof stored === 'string' && sameHash(stored, hash(value))`.
pub fn matches_hash(stored: Option<&Value>, value: &str) -> bool {
    match stored {
        Some(Value::String(stored)) => same_hash(stored, &hash(value)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn radix_strings_match_javascript() {
        assert_eq!(to_radix_string(1_700_000_000_000.0, 36), "loyw3v28");
        assert_eq!(to_radix_string(35.0, 36), "z");
        assert_eq!(to_radix_string(0.5, 2), "0.1");
        assert_eq!(parse_int_36("loyw3v28"), 1_700_000_000_000.0);
        assert!(parse_int_36("!").is_nan());
    }

    #[test]
    fn options_resolve_with_their_bounds() {
        let resolved = resolve_vc_options(Some(&Value::Bool(true)))
            .unwrap()
            .unwrap();
        assert_eq!(resolved.status_list_size, 65536.0);
        assert_eq!(resolved.record_retention_ms, 30.0 * DAY);
        assert!(
            resolve_vc_options(Some(&Value::Bool(false)))
                .unwrap()
                .is_none()
        );
        let error = resolve_vc_options(Some(&json!({ "statusListSize": 1500 }))).unwrap_err();
        assert_eq!(error.code, "INVALID_CONFIG");
        assert_eq!(
            error.message,
            "verifiableCredentials.statusListSize must be a multiple of 1024"
        );
        let error = resolve_vc_options(Some(&json!("yes"))).unwrap_err();
        assert_eq!(
            error.message,
            "verifiableCredentials must be true or an options object"
        );
        let error = resolve_vc_options(Some(&json!({ "offerLifetimeMs": 1 }))).unwrap_err();
        assert_eq!(
            error.message,
            "verifiableCredentials.offerLifetimeMs must be an integer between 60000 and 86400000"
        );
    }

    #[test]
    fn offer_tokens_name_their_offer() {
        let token = offer_token("biam_vco", "offer1");
        assert_eq!(
            offer_id_of(Some(&Value::String(token.clone())), "biam_vco"),
            Some("offer1".to_owned())
        );
        assert_eq!(
            offer_id_of(Some(&Value::String(token.clone())), "biam_vcat"),
            None
        );
        assert_eq!(offer_id_of(Some(&json!("biam_vco..x")), "biam_vco"), None);
        assert!(matches_hash(Some(&Value::String(hash(&token))), &token));
        assert!(!matches_hash(None, &token));
    }
}
