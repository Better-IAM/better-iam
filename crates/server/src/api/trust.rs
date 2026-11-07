//! Port of `packages/server/src/api/trust.ts`: the `trust`, `links` and `root` API groups.
//!
//! Trust records are read and written as raw JSON records, so member order and members this port does not know
//! survive a round trip (a mixed fleet shares the database with TypeScript), and malformed stored values are judged
//! exactly as TypeScript judges them.

use std::cmp::Ordering;
use std::sync::Arc;

use better_iam_core::js::{
    cmp_utf16, is_safe_integer, number_to_string, number_value, strict_equal, to_number,
};
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, IamError, IamResult, IamStoreExt, Record,
};
use better_iam_core::{Filter, FindOptions};
use better_iam_types::api::{links, root, trust};
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply};
use crate::context::{ServerContext, Store};
use crate::context_keys::is_tag_key;
use crate::contracts::{Mutation, MutationContext, OperationDenied, OperationResult};
use crate::js::{js_string, truthy, utf16_len};
use crate::models::IdentityLink;
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::session_kinds::next_watermark;
use crate::temporary_credentials::{allowed_tag_keys_value, delete_temporary_sessions};
use crate::utils::{all_value, hash, id};
use crate::validation::{text, text256};
use crate::web_identity::{web_identity_claim_name, web_identity_conditions};
use crate::web_identity_exchange::{WebIdentityEvaluation, evaluate_web_identity};

const SOURCE_IDENTITY_MODES: [&str; 3] = ["forbidden", "optional", "required"];
const IDENTITY_ONLY_FIELDS: [&str; 3] = ["requireMfa", "allowedTagKeys", "sourceIdentityMode"];
const WEB_ONLY_FIELDS: [&str; 3] = ["conditions", "tagClaims", "sourceIdentityClaim"];
/// Fields `trust.create` accepts only for identity trusts, and only for web-identity trusts.
const IDENTITY_CREATE_FIELDS: [&str; 6] = [
    "sourceTenantId",
    "sourceIdentityId",
    "requireMfa",
    "externalId",
    "allowedTagKeys",
    "sourceIdentityMode",
];
const WEB_CREATE_FIELDS: [&str; 5] = [
    "providerId",
    "serviceAccountId",
    "conditions",
    "tagClaims",
    "sourceIdentityClaim",
];
const MAX_TAG_CLAIMS: usize = 10;
/// The duration cap of a trust without `maxSessionSeconds`.
const DEFAULT_MAX_SESSION_SECONDS: f64 = 3600.0;

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

fn web_identity_disabled() -> IamError {
    IamError::with_status(
        "FEATURE_DISABLED",
        "Web identity federation is not enabled",
        403,
    )
}

/// `{ ...value }` for a JSON value: an object's own members, an array's or a string's indexes, nothing otherwise.
fn spread(value: &Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map.clone(),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(index, item)| (index.to_string(), item.clone()))
            .collect(),
        Value::String(text) => text
            .encode_utf16()
            .enumerate()
            .map(|(index, unit)| {
                (
                    index.to_string(),
                    Value::String(String::from_utf16_lossy(&[unit])),
                )
            })
            .collect(),
        _ => Map::new(),
    }
}

/// A trust as the API returns it: an allowlist projection that never carries the external ID hash, reports whether an
/// external ID is required, and reads legacy records (no kind) as identity trusts.
pub fn public_trust(trust: &Record) -> Record {
    let mut result = Record::new();
    let copy = |result: &mut Record, key: &str| {
        if let Some(value) = trust.get(key) {
            result.insert(key.to_owned(), value.clone());
        }
    };
    copy(&mut result, "id");
    copy(&mut result, "tenantId");
    let kind = if trust.get("kind").and_then(Value::as_str) == Some("web-identity") {
        "web-identity"
    } else {
        "identity"
    };
    result.insert("kind".into(), Value::String(kind.into()));
    copy(&mut result, "sourceTenantId");
    copy(&mut result, "sourceIdentityId");
    copy(&mut result, "roleId");
    copy(&mut result, "requireMfa");
    result.insert(
        "requiresExternalId".into(),
        Value::Bool(matches!(
            trust.get("externalIdHash"),
            Some(Value::String(_))
        )),
    );
    copy(&mut result, "revoked");
    copy(&mut result, "ceiling");
    copy(&mut result, "maxSessionSeconds");
    copy(&mut result, "passSourceAttributes");
    // A malformed stored value (not a list) is left out rather than failing the whole projection.
    if let Some(Value::Array(keys)) = trust.get("allowedTagKeys") {
        result.insert("allowedTagKeys".into(), Value::Array(keys.clone()));
    }
    copy(&mut result, "sourceIdentityMode");
    copy(&mut result, "sessionsRevokedBefore");
    copy(&mut result, "providerId");
    copy(&mut result, "conditions");
    if let Some(claims) = trust.get("tagClaims") {
        result.insert("tagClaims".into(), Value::Object(spread(claims)));
    }
    copy(&mut result, "sourceIdentityClaim");
    copy(&mut result, "authorityId");
    copy(&mut result, "description");
    copy(&mut result, "createdAt");
    copy(&mut result, "createdBy");
    copy(&mut result, "updatedAt");
    result
}

/// Longest role session a trust issues: 60 up to the deployment's `sts.maxRoleSessionSeconds`.
fn max_session_seconds_value(ctx: &ServerContext, value: &Value) -> IamResult<f64> {
    let ceiling = ctx.config.sts.max_role_session_seconds;
    if let Value::Number(number) = value {
        let value = number_value(number);
        if is_safe_integer(value) && value >= 60.0 && value <= ceiling {
            return Ok(value);
        }
    }
    Err(invalid(format!(
        "maxSessionSeconds must be an integer from 60 to {}",
        number_to_string(ceiling)
    )))
}

fn boolean_value(value: &Value, name: &str) -> IamResult<bool> {
    match value {
        Value::Bool(flag) => Ok(*flag),
        _ => Err(invalid(format!("{name} must be a boolean"))),
    }
}

fn source_identity_mode_value(value: &Value) -> IamResult<String> {
    match value {
        Value::String(mode) if SOURCE_IDENTITY_MODES.contains(&mode.as_str()) => Ok(mode.clone()),
        _ => Err(invalid(
            "sourceIdentityMode must be 'forbidden', 'optional' or 'required'",
        )),
    }
}

/// A web-identity trust's claim-to-tag mapping: at most 10 entries, each a session tag key (unique case-insensitively)
/// mapped to a flattened claim name (`token.<claim>`).
pub fn web_trust_tag_claims(value: Option<&Value>) -> IamResult<IndexMap<String, String>> {
    let Some(Value::Object(map)) = value else {
        return Err(invalid(
            "tagClaims must map session tag keys to token.<claim> names",
        ));
    };
    let entries = better_iam_core::js::entries(map);
    if entries.len() > MAX_TAG_CLAIMS {
        return Err(invalid(format!(
            "tagClaims may contain at most {MAX_TAG_CLAIMS} entries"
        )));
    }
    let mut seen = IndexSet::new();
    let mut mapping = IndexMap::new();
    for (key, claim) in entries {
        if !is_tag_key(key) {
            return Err(invalid(
                "Tag keys must start with a letter and use at most 64 letters, digits or underscores",
            ));
        }
        let folded = better_iam_core::js::to_lower(key);
        if seen.contains(&folded) {
            return Err(invalid(format!(
                "Tag key {key} is repeated (tag keys are case-insensitive)"
            )));
        }
        seen.insert(folded);
        mapping.insert(key.clone(), web_identity_claim_name(Some(claim))?);
    }
    Ok(mapping)
}

fn tag_claims_value(mapping: &IndexMap<String, String>) -> Value {
    Value::Object(
        mapping
            .iter()
            .map(|(key, claim)| (key.clone(), Value::String(claim.clone())))
            .collect(),
    )
}

/// Objects with their members sorted (`a < b`), recursively, as the replacer of `canonical` returns them.
fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            members.sort_by(|(a, _), (b, _)| cmp_utf16(a, b));
            Value::Object(
                members
                    .into_iter()
                    .map(|(key, item)| (key.clone(), sorted(item)))
                    .collect(),
            )
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

/// JSON with object keys sorted, so equal values compare equal whatever their key order.
fn canonical(value: &Value) -> String {
    better_iam_core::js::stringify(&sorted(value))
}

/// `value ?? fallback`.
fn or_else<'a>(value: Option<&'a Value>, fallback: &'a Value) -> &'a Value {
    match value {
        None | Some(Value::Null) => fallback,
        Some(value) => value,
    }
}

/// Tag key lists compare as sets. A stored value that is not a list (malformed) reads as no keys.
fn same_tag_keys(a: Option<&Value>, b: Option<&Value>) -> bool {
    let keys = |value: Option<&Value>| -> Value {
        match value {
            Some(Value::Array(items)) => {
                let mut items = items.clone();
                // `Array.prototype.sort()` without a comparator: by the strings of the items, stable.
                items.sort_by(|x, y| cmp_utf16(&js_string(Some(x)), &js_string(Some(y))));
                Value::Array(items)
            }
            _ => Value::Array(Vec::new()),
        }
    };
    canonical(&keys(a)) == canonical(&keys(b))
}

/// `ToPrimitive(value)` for a JSON value (objects and arrays become their strings).
fn to_primitive(value: &Value) -> Value {
    match value {
        Value::Array(_) | Value::Object(_) => Value::String(js_string(Some(value))),
        other => other.clone(),
    }
}

/// JavaScript `a < b` between two JSON values.
fn js_less(a: &Value, b: &Value) -> bool {
    let (a, b) = (to_primitive(a), to_primitive(b));
    match (&a, &b) {
        (Value::String(x), Value::String(y)) => cmp_utf16(x, y) == Ordering::Less,
        _ => to_number(&a) < to_number(&b),
    }
}

/// A stored watermark as `Math.max` reads it (`current ?? 0` happens in `next_watermark`).
fn watermark_of(value: Option<&Value>) -> Option<f64> {
    match value {
        None | Some(Value::Null) => None,
        Some(value) => Some(to_number(value)),
    }
}

/// The JSON `===` of two members that may be absent (`undefined === undefined`).
fn same_member(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => strict_equal(a, b),
        _ => false,
    }
}

/// A string member of a record ("" when absent or not a string).
fn record_text(record: &Record, key: &str) -> String {
    record
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Who may manage a trust: identity trusts (a named source identity, possibly in another tenant) stay
/// platform-controlled and need a root principal; web-identity trusts are tenant-managed and editable by their
/// creator's authority (`canEditGrantResource`). Refusals are audited denials.
async fn assert_trust_manager(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    trust: &Record,
) -> OperationResult<()> {
    if trust.get("kind").and_then(Value::as_str) == Some("web-identity") {
        ctx.can_edit_grant_resource(tx, principal, trust).await?;
        return Ok(());
    }
    if !ctx.root_principal(tx, principal).await? {
        return Err(OperationDenied::new(Some(
            "Only a root administrator can manage identity trusts",
        )));
    }
    Ok(())
}

/// A web-identity trust hands its workloads the service account it names, so creating or changing one needs authority
/// over that account: iam:identities:update on it, the permission `serviceAccounts.update` and `setStatus` manage
/// service accounts with. Otherwise a trust administrator could act as any service account of the tenant. The refusal
/// is an audited denial (ACCESS_DENIED).
async fn assert_service_account_control(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    account_id: &str,
) -> OperationResult<()> {
    let decision = ctx
        .decisions()?
        .decide(
            tx,
            principal,
            &AuthorizationRequest {
                credential: CredentialInput::default(),
                tenant_id: tenant_id.to_owned(),
                action: "iam:identities:update".into(),
                resource: ResourceTarget {
                    kind: "iam".into(),
                    id: account_id.to_owned(),
                },
            },
            true,
        )
        .await?;
    if !decision.allowed {
        return Err(OperationDenied::new(Some(
            "Binding a service account to a web-identity trust requires iam:identities:update on it",
        )));
    }
    Ok(())
}

/// The `trust` API group (`createTrustApi(ctx)`): one method per route `trust/{method}`.
pub struct TrustApi {
    ctx: Arc<ServerContext>,
}

/// `createTrustApi(ctx)`.
pub fn create_trust_api(ctx: &Arc<ServerContext>) -> IamResult<TrustApi> {
    Ok(TrustApi { ctx: ctx.clone() })
}

impl TrustApi {
    /// `trust.create` for web-identity trusts: tenant-managed (iam:trust:create on the role, not root-only), recent
    /// authentication, the feature gate first. The role must not be protected, the provider must belong to the tenant,
    /// and the service account must be active and unexpired, with the caller holding iam:identities:update on it
    /// (ACCESS_DENIED otherwise). The trust records the creator's grant authority, which bounds its sessions
    /// (`credentialAuthorityId`) and is the only authority that may edit it besides root.
    async fn create_web_trust(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
    ) -> IamResult<Value> {
        let ctx = &self.ctx;
        if !ctx.config.sts.web_identity.enabled {
            return Err(web_identity_disabled());
        }
        for field in IDENTITY_CREATE_FIELDS {
            if input.get(field).is_some() {
                return Err(invalid(format!("{field} applies only to identity trusts")));
            }
        }
        let provider_id = text256(input.get("providerId"), "providerId")?;
        let service_account_id = text256(input.get("serviceAccountId"), "serviceAccountId")?;
        let conditions = web_identity_conditions(input.get("conditions"))?;
        let tag_claims = match input.get("tagClaims") {
            None => None,
            Some(value) => Some(web_trust_tag_claims(Some(value))?),
        };
        let source_identity_claim = match input.get("sourceIdentityClaim") {
            None => None,
            Some(value) => Some(web_identity_claim_name(Some(value))?),
        };
        let max_session_seconds = match input.get("maxSessionSeconds") {
            None => None,
            Some(value) => Some(max_session_seconds_value(ctx, value)?),
        };
        let pass_source_attributes = match input.get("passSourceAttributes") {
            None => true,
            Some(value) => boolean_value(value, "passSourceAttributes")?,
        };
        let description = match input.get("description") {
            None => None,
            Some(value) => Some(text(Some(value), "description", 512)?),
        };
        let provider_id = &provider_id;
        let service_account_id = &service_account_id;
        let conditions = &conditions;
        let tag_claims = &tag_claims;
        let source_identity_claim = &source_identity_claim;
        let description = &description;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let role = ctx
                        .scoped(&tx, "roles", input.get("roleId"), &tenant.id)
                        .await?;
                    if truthy(role.get("protected")) {
                        return Err(IamError::new(
                            "PROTECTED_RESOURCE",
                            "Cannot assume protected owner roles",
                        )
                        .into());
                    }
                    ctx.scoped(
                        &tx,
                        "oidcProviders",
                        Some(&Value::String(provider_id.clone())),
                        &tenant.id,
                    )
                    .await?;
                    let account = ctx
                        .scoped(
                            &tx,
                            "identities",
                            Some(&Value::String(service_account_id.clone())),
                            &tenant.id,
                        )
                        .await?;
                    let account: better_iam_core::Identity = crate::port::decode(account)?;
                    if account.kind != better_iam_core::IdentityKind::Service
                        || account.status != better_iam_core::IdentityStatus::Active
                        || ctx.identity_expired(&account)
                    {
                        return Err(IamError::new(
                            "INVALID_IDENTITY",
                            "Web-identity trusts require an active service account",
                        )
                        .into());
                    }
                    assert_service_account_control(ctx, &tx, &principal, &tenant.id, &account.id)
                        .await?;
                    let ceiling = input.get("ceiling");
                    if truthy(ceiling) {
                        ctx.catalog
                            .validate(tx.as_ref(), &tenant.id, ceiling.unwrap_or(&Value::Null))
                            .await?;
                    }
                    let authority = ctx
                        .granting_authority(&tx, &principal, &tenant.id, None)
                        .await?;
                    let now = crate::js::number(ctx.now());
                    let mut record = Record::new();
                    record.insert("id".into(), Value::String(id()));
                    record.insert("tenantId".into(), Value::String(tenant.id.clone()));
                    record.insert("kind".into(), Value::String("web-identity".into()));
                    record.insert("sourceTenantId".into(), Value::String(tenant.id.clone()));
                    record.insert("sourceIdentityId".into(), Value::String(account.id.clone()));
                    record.insert("roleId".into(), Value::String(record_text(&role, "id")));
                    record.insert("requireMfa".into(), Value::Bool(false));
                    record.insert("ceiling".into(), or_else(ceiling, &all_value()).clone());
                    record.insert("revoked".into(), Value::Bool(false));
                    record.insert(
                        "passSourceAttributes".into(),
                        Value::Bool(pass_source_attributes),
                    );
                    record.insert("providerId".into(), Value::String(provider_id.clone()));
                    record.insert("conditions".into(), conditions.clone());
                    record.insert("authorityId".into(), Value::String(authority.id.clone()));
                    record.insert("createdAt".into(), now.clone());
                    record.insert(
                        "createdBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    record.insert("updatedAt".into(), now);
                    if let Some(tag_claims) = tag_claims {
                        record.insert("tagClaims".into(), tag_claims_value(tag_claims));
                    }
                    if let Some(claim) = source_identity_claim {
                        record.insert("sourceIdentityClaim".into(), Value::String(claim.clone()));
                    }
                    if let Some(seconds) = max_session_seconds {
                        record.insert("maxSessionSeconds".into(), crate::js::number(seconds));
                    }
                    if let Some(description) = description {
                        record.insert("description".into(), Value::String(description.clone()));
                    }
                    let stored = tx.insert("trusts", &record).await?;
                    Ok(Value::Object(public_trust(&stored)))
                })
            },
        );
        ctx.operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:trust:create",
                &crate::api::string_member(input, "roleId"),
                mutation,
                false,
            )
            .await
    }

    /// `trust/create`: creates a trust. Identity trusts are platform-controlled: they establish exact source-identity
    /// to target-role trust for temporary role assumption (root only, recent authentication). Defaults: MFA required, no
    /// ceiling beyond the role, a 3600 s session cap, no session tags, source identity forbidden, and source attributes
    /// passed only for same-tenant trusts. Web-identity trusts (`kind: 'web-identity'`) admit the tokens of an OIDC
    /// provider that satisfy their claim conditions.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<trust::CreateInput>,
    ) -> IamResult<Reply<trust::CreateOutput>> {
        let ctx = &self.ctx;
        let input: &Map<String, Value> = &input;
        let kind = input.get("kind");
        if kind.and_then(Value::as_str) == Some("web-identity") {
            return Ok(Reply::json(self.create_web_trust(credential, input).await?));
        }
        if kind.is_some_and(|kind| kind.as_str() != Some("identity")) {
            return Err(invalid("kind must be 'identity' or 'web-identity'"));
        }
        for field in WEB_CREATE_FIELDS {
            if input.get(field).is_some() {
                return Err(invalid(format!(
                    "{field} applies only to web-identity trusts"
                )));
            }
        }
        if let Some(value) = input.get("requireMfa") {
            boolean_value(value, "requireMfa")?;
        }
        if input
            .get("externalId")
            .is_some_and(|value| !value.is_string())
        {
            return Err(invalid("externalId must be a string"));
        }
        let max_session_seconds = match input.get("maxSessionSeconds") {
            None => None,
            Some(value) => Some(max_session_seconds_value(ctx, value)?),
        };
        let pass_source_attributes = match input.get("passSourceAttributes") {
            None => same_member(input.get("sourceTenantId"), input.get("tenantId")),
            Some(value) => boolean_value(value, "passSourceAttributes")?,
        };
        let allowed_tag_keys = match input.get("allowedTagKeys") {
            None => Vec::new(),
            Some(value) => allowed_tag_keys_value(Some(value))?,
        };
        let source_identity_mode = match input.get("sourceIdentityMode") {
            None => "forbidden".to_owned(),
            Some(value) => source_identity_mode_value(value)?,
        };
        let description = match input.get("description") {
            None => None,
            Some(value) => Some(text(Some(value), "description", 512)?),
        };
        let allowed_tag_keys = &allowed_tag_keys;
        let source_identity_mode = &source_identity_mode;
        let description = &description;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let role = ctx
                        .scoped(&tx, "roles", input.get("roleId"), &tenant.id)
                        .await?;
                    if truthy(role.get("protected")) {
                        return Err(IamError::new(
                            "PROTECTED_RESOURCE",
                            "Cannot assume protected owner roles",
                        )
                        .into());
                    }
                    ctx.scoped(
                        &tx,
                        "identities",
                        input.get("sourceIdentityId"),
                        &crate::api::string_member(input, "sourceTenantId"),
                    )
                    .await?;
                    let ceiling = input.get("ceiling");
                    if truthy(ceiling) {
                        ctx.catalog
                            .validate(tx.as_ref(), &tenant.id, ceiling.unwrap_or(&Value::Null))
                            .await?;
                    }
                    let now = crate::js::number(ctx.now());
                    let mut record = Record::new();
                    record.insert("id".into(), Value::String(id()));
                    record.insert("tenantId".into(), Value::String(tenant.id.clone()));
                    record.insert("kind".into(), Value::String("identity".into()));
                    record.insert(
                        "sourceTenantId".into(),
                        input.get("sourceTenantId").cloned().unwrap_or(Value::Null),
                    );
                    record.insert(
                        "sourceIdentityId".into(),
                        input
                            .get("sourceIdentityId")
                            .cloned()
                            .unwrap_or(Value::Null),
                    );
                    record.insert(
                        "roleId".into(),
                        input.get("roleId").cloned().unwrap_or(Value::Null),
                    );
                    record.insert(
                        "requireMfa".into(),
                        or_else(input.get("requireMfa"), &Value::Bool(true)).clone(),
                    );
                    record.insert("ceiling".into(), or_else(ceiling, &all_value()).clone());
                    record.insert("revoked".into(), Value::Bool(false));
                    record.insert(
                        "passSourceAttributes".into(),
                        Value::Bool(pass_source_attributes),
                    );
                    record.insert(
                        "allowedTagKeys".into(),
                        Value::Array(
                            allowed_tag_keys
                                .iter()
                                .map(|key| Value::String(key.clone()))
                                .collect(),
                        ),
                    );
                    record.insert(
                        "sourceIdentityMode".into(),
                        Value::String(source_identity_mode.clone()),
                    );
                    record.insert("createdAt".into(), now.clone());
                    record.insert(
                        "createdBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    record.insert("updatedAt".into(), now);
                    if let Some(Value::String(external_id)) = input.get("externalId")
                        && !external_id.is_empty()
                    {
                        record.insert("externalIdHash".into(), Value::String(hash(external_id)));
                    }
                    if let Some(seconds) = max_session_seconds {
                        record.insert("maxSessionSeconds".into(), crate::js::number(seconds));
                    }
                    if let Some(description) = description {
                        record.insert("description".into(), Value::String(description.clone()));
                    }
                    let stored = tx.insert("trusts", &record).await?;
                    Ok(Value::Object(public_trust(&stored)))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:trust:create",
                &crate::api::string_member(input, "roleId"),
                mutation,
                true,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `trust/evaluateWebIdentity`: dry run of AssumeRoleWithWebIdentity for administrators (iam:trust:read on the
    /// trust, web identity enabled): verifies a token against the trust's provider, evaluates the claim conditions
    /// (listing each unmet entry) and the claim mappings, and reports why the exchange would refuse it, stored-state
    /// causes included. Nothing is issued and no replay record is written, so the token stays redeemable. Web-identity
    /// trusts only (INVALID_INPUT otherwise).
    pub async fn evaluate_web_identity(
        &self,
        credential: &CredentialInput,
        input: Body<trust::EvaluateWebIdentityInput>,
    ) -> IamResult<Reply<trust::EvaluateWebIdentityOutput>> {
        let ctx = &self.ctx;
        if !ctx.config.sts.web_identity.enabled {
            return Err(web_identity_disabled());
        }
        let trust_id = text256(input.get("trustId"), "trustId")?;
        // The same size bound as the public exchange, before anything is parsed or verified.
        let token = match input.get("webIdentityToken") {
            Some(Value::String(token)) if utf16_len(token) <= 8192 => token.clone(),
            _ => {
                return Err(invalid(
                    "webIdentityToken must be a compact JWT of at most 8192 characters",
                ));
            }
        };
        let well_formed = compact_jws(&token);
        let trust_id_ref = &trust_id;
        // Authorized on the trust before it is read, so the answer reveals nothing to callers without the permission.
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let trust = ctx
                    .scoped(
                        &tx,
                        "trusts",
                        Some(&Value::String(trust_id_ref.clone())),
                        &tenant.id,
                    )
                    .await?;
                let provider_id = match (trust.get("kind"), trust.get("providerId")) {
                    (Some(Value::String(kind)), Some(Value::String(provider_id)))
                        if kind == "web-identity" =>
                    {
                        provider_id.clone()
                    }
                    _ => {
                        return Err(invalid(
                            "Only web-identity trusts evaluate web identity tokens",
                        )
                        .into());
                    }
                };
                let provider = ctx
                    .scoped(
                        &tx,
                        "oidcProviders",
                        Some(&Value::String(provider_id)),
                        &tenant.id,
                    )
                    .await?;
                Ok(json!({ "trust": trust, "provider": provider }))
            })
        });
        let loaded = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:trust:read",
                &trust_id,
                mutation,
                false,
            )
            .await?;
        // A value that is not a compact JWS never reaches the verifier.
        if !well_formed {
            return Ok(Reply::json(
                json!({ "verified": false, "reason": "malformed" }),
            ));
        }
        // Outside the transaction: verification may fetch the provider's keys.
        let mut request = Map::new();
        request.insert(
            "trust".into(),
            loaded.get("trust").cloned().unwrap_or(Value::Null),
        );
        request.insert(
            "provider".into(),
            loaded.get("provider").cloned().unwrap_or(Value::Null),
        );
        request.insert("token".into(), Value::String(token));
        let evaluation: WebIdentityEvaluation =
            evaluate_web_identity(ctx, &Value::Object(request)).await?;
        Ok(Reply::json(
            serde_json::to_value(evaluation).unwrap_or(Value::Null),
        ))
    }

    /// `trust/list`: trust relationships targeting this tenant's roles, as PublicTrust (external ID hashes are never
    /// returned).
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<trust::ListInput>,
    ) -> IamResult<Reply<trust::ListOutput>> {
        let include_revoked = input.get("includeRevoked") == Some(&Value::Bool(true));
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let trusts = tx
                    .find(
                        "trusts",
                        &Filter::new().eq("tenantId", tenant.id.clone()),
                        &FindOptions::default(),
                    )
                    .await?;
                Ok(Value::Array(
                    trusts
                        .iter()
                        .filter(|trust| include_revoked || !truthy(trust.get("revoked")))
                        .map(|trust| Value::Object(public_trust(trust)))
                        .collect(),
                ))
            })
        });
        let result = self
            .ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:trust:read",
                &crate::api::string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `trust/revoke`: permanently revokes a trust and deletes its live role sessions (recent authentication; identity
    /// trusts need a root principal, web-identity trusts their creator's authority). Revoking only removes access, so it
    /// works for web-identity trusts while `sts.webIdentity.enabled` is off (their provider can then be deleted).
    pub async fn revoke(
        &self,
        credential: &CredentialInput,
        input: Body<trust::RevokeInput>,
    ) -> IamResult<Reply<trust::RevokeOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let mut trust = ctx
                        .scoped(&tx, "trusts", body.get("trustId"), &tenant.id)
                        .await?;
                    assert_trust_manager(ctx, &tx, &principal, &trust).await?;
                    // `createdBefore: Number.POSITIVE_INFINITY` (JSON has no infinity; no timestamp reaches f64::MAX).
                    delete_temporary_sessions(
                        &tx,
                        &json!({
                            "tenantId": trust.get("tenantId").cloned().unwrap_or(Value::Null),
                            "roleId": trust.get("roleId").cloned().unwrap_or(Value::Null),
                            "trustId": trust.get("id").cloned().unwrap_or(Value::Null),
                            "createdBefore": f64::MAX,
                        }),
                    )
                    .await?;
                    trust.insert("revoked".into(), Value::Bool(true));
                    trust.insert("updatedAt".into(), crate::js::number(ctx.now()));
                    let stored = tx.put("trusts", &trust).await?;
                    Ok(Value::Object(public_trust(&stored)))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:trust:revoke",
                &crate::api::string_member(&input, "trustId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `trust/revokeSessions`: revokes the trust's role sessions issued before `before` (default: every session so
    /// far): moves the trust's `sessionsRevokedBefore` watermark forward and deletes the matching rows. Delegated like
    /// `roles.revokeSessions` (iam:roles:revoke-sessions on the trust's role, recent authentication), so a target
    /// tenant's administrators can end sessions under platform-controlled trusts. Audited as `role:sessions-revoked`.
    pub async fn revoke_sessions(
        &self,
        credential: &CredentialInput,
        input: Body<trust::RevokeSessionsInput>,
    ) -> IamResult<Reply<trust::RevokeSessionsOutput>> {
        let ctx = &self.ctx;
        // The action targets the trust's role, so the trust is pre-read with ctx.scoped, as roles.assume does (after
        // the credential is verified, so anonymous callers cannot probe trust ids): a missing or foreign trust is
        // NOT_FOUND (spec F2).
        ctx.principals()?.authenticate(credential).await?;
        let trust_id = text256(input.get("trustId"), "trustId")?;
        let requested = ctx
            .scoped(
                &ctx.store,
                "trusts",
                Some(&Value::String(trust_id.clone())),
                &crate::api::string_member(&input, "tenantId"),
            )
            .await?;
        let resource_id = requested.get("roleId").cloned();
        let resource_text = resource_id
            .as_ref()
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let body = &input;
        let trust_id_ref = &trust_id;
        let resource_ref = &resource_id;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let mut trust = ctx
                        .scoped(
                            &tx,
                            "trusts",
                            Some(&Value::String(trust_id_ref.clone())),
                            &tenant.id,
                        )
                        .await?;
                    // Authorized for another resource than this trust's role (it changed since the pre-read).
                    if !same_member(trust.get("roleId"), resource_ref.as_ref()) {
                        return Err(
                            IamError::with_status("NOT_FOUND", "Resource not found", 404).into(),
                        );
                    }
                    let sessions_revoked_before = next_watermark(
                        watermark_of(trust.get("sessionsRevokedBefore")),
                        body.get("before"),
                        ctx.now(),
                    )?;
                    let watermark = crate::js::number(sessions_revoked_before);
                    trust.insert("sessionsRevokedBefore".into(), watermark.clone());
                    tx.put("trusts", &trust).await?;
                    let revoked = delete_temporary_sessions(
                        &tx,
                        &json!({
                            "tenantId": trust.get("tenantId").cloned().unwrap_or(Value::Null),
                            "roleId": trust.get("roleId").cloned().unwrap_or(Value::Null),
                            "trustId": trust.get("id").cloned().unwrap_or(Value::Null),
                            "createdBefore": watermark.clone(),
                        }),
                    )
                    .await?;
                    let revoked = crate::js::number(revoked);
                    let trust_id = trust.get("id").cloned().unwrap_or(Value::Null);
                    let mut metadata = Map::new();
                    metadata.insert("sessionsRevokedBefore".into(), watermark.clone());
                    metadata.insert("revoked".into(), revoked.clone());
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "role:sessions-revoked",
                            &tenant.id,
                            trust_id.as_str().unwrap_or_default(),
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    let mut result = Map::new();
                    result.insert("trustId".into(), trust_id);
                    result.insert("sessionsRevokedBefore".into(), watermark);
                    result.insert("revoked".into(), revoked);
                    Ok(Value::Object(result))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:roles:revoke-sessions",
                &resource_text,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `trust/update`: changes a trust's knobs (recent authentication; identity trusts need a root principal,
    /// web-identity trusts their creator's authority and iam:identities:update on their service account). Tightening
    /// what a trust admits (tag keys, source identity mode, claim conditions or mappings, or a lower session cap) also
    /// revokes the sessions issued under the old rules, through the trust's `sessionsRevokedBefore` watermark. A
    /// revoked trust is CONFLICT; an update that changes nothing is INVALID_INPUT.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<trust::UpdateInput>,
    ) -> IamResult<Reply<trust::UpdateOutput>> {
        let ctx = &self.ctx;
        let body: &Map<String, Value> = &input;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let trust = ctx
                        .scoped(&tx, "trusts", body.get("trustId"), &tenant.id)
                        .await?;
                    let web = trust.get("kind").and_then(Value::as_str) == Some("web-identity");
                    if web && !ctx.config.sts.web_identity.enabled {
                        return Err(web_identity_disabled().into());
                    }
                    assert_trust_manager(ctx, &tx, &principal, &trust).await?;
                    if truthy(trust.get("revoked")) {
                        return Err(
                            IamError::with_status("CONFLICT", "The trust is revoked", 409).into(),
                        );
                    }
                    // Changing what a web-identity trust admits changes who acts as its service account.
                    if web {
                        assert_service_account_control(
                            ctx,
                            &tx,
                            &principal,
                            &tenant.id,
                            &record_text(&trust, "sourceIdentityId"),
                        )
                        .await?;
                    }
                    let fields = if web {
                        IDENTITY_ONLY_FIELDS
                    } else {
                        WEB_ONLY_FIELDS
                    };
                    for field in fields {
                        if body.get(field).is_some() {
                            return Err(invalid(format!(
                                "{field} applies only to {} trusts",
                                if web { "identity" } else { "web-identity" }
                            ))
                            .into());
                        }
                    }
                    let mut next = trust.clone();
                    if let Some(value) = body.get("requireMfa") {
                        next.insert(
                            "requireMfa".into(),
                            Value::Bool(boolean_value(value, "requireMfa")?),
                        );
                    }
                    match body.get("ceiling") {
                        Some(Value::Null) => {
                            next.insert("ceiling".into(), all_value());
                        }
                        Some(ceiling) => {
                            ctx.catalog
                                .validate(tx.as_ref(), &tenant.id, ceiling)
                                .await?;
                            next.insert("ceiling".into(), ceiling.clone());
                        }
                        None => {}
                    }
                    match body.get("maxSessionSeconds") {
                        Some(Value::Null) => {
                            next.shift_remove("maxSessionSeconds");
                        }
                        Some(value) => {
                            next.insert(
                                "maxSessionSeconds".into(),
                                crate::js::number(max_session_seconds_value(ctx, value)?),
                            );
                        }
                        None => {}
                    }
                    if let Some(value) = body.get("passSourceAttributes") {
                        next.insert(
                            "passSourceAttributes".into(),
                            Value::Bool(boolean_value(value, "passSourceAttributes")?),
                        );
                    }
                    match body.get("allowedTagKeys") {
                        Some(Value::Null) => {
                            next.insert("allowedTagKeys".into(), Value::Array(Vec::new()));
                        }
                        Some(value) => {
                            let keys = allowed_tag_keys_value(Some(value))?;
                            next.insert(
                                "allowedTagKeys".into(),
                                Value::Array(keys.into_iter().map(Value::String).collect()),
                            );
                        }
                        None => {}
                    }
                    if let Some(value) = body.get("sourceIdentityMode") {
                        next.insert(
                            "sourceIdentityMode".into(),
                            Value::String(source_identity_mode_value(value)?),
                        );
                    }
                    match body.get("description") {
                        Some(Value::Null) => {
                            next.shift_remove("description");
                        }
                        Some(value) => {
                            next.insert(
                                "description".into(),
                                Value::String(text(Some(value), "description", 512)?),
                            );
                        }
                        None => {}
                    }
                    if let Some(value) = body.get("conditions") {
                        next.insert("conditions".into(), web_identity_conditions(Some(value))?);
                    }
                    match body.get("tagClaims") {
                        Some(Value::Null) => {
                            next.shift_remove("tagClaims");
                        }
                        Some(value) => {
                            next.insert(
                                "tagClaims".into(),
                                tag_claims_value(&web_trust_tag_claims(Some(value))?),
                            );
                        }
                        None => {}
                    }
                    match body.get("sourceIdentityClaim") {
                        Some(Value::Null) => {
                            next.shift_remove("sourceIdentityClaim");
                        }
                        Some(value) => {
                            next.insert(
                                "sourceIdentityClaim".into(),
                                Value::String(web_identity_claim_name(Some(value))?),
                            );
                        }
                        None => {}
                    }
                    if canonical(&Value::Object(next.clone()))
                        == canonical(&Value::Object(trust.clone()))
                    {
                        return Err(invalid("The update changes nothing").into());
                    }
                    // Sessions issued under looser rules would keep what the trust no longer admits, so they end.
                    let forbidden = Value::String("forbidden".into());
                    let default_seconds = crate::js::number(DEFAULT_MAX_SESSION_SECONDS);
                    let tightened =
                        !same_tag_keys(trust.get("allowedTagKeys"), next.get("allowedTagKeys"))
                            || !strict_equal(
                                or_else(trust.get("sourceIdentityMode"), &forbidden),
                                or_else(next.get("sourceIdentityMode"), &forbidden),
                            )
                            || canonical(or_else(trust.get("conditions"), &Value::Null))
                                != canonical(or_else(next.get("conditions"), &Value::Null))
                            || canonical(or_else(trust.get("tagClaims"), &Value::Null))
                                != canonical(or_else(next.get("tagClaims"), &Value::Null))
                            || !strict_equal(
                                or_else(trust.get("sourceIdentityClaim"), &Value::Null),
                                or_else(next.get("sourceIdentityClaim"), &Value::Null),
                            )
                            || js_less(
                                or_else(next.get("maxSessionSeconds"), &default_seconds),
                                or_else(trust.get("maxSessionSeconds"), &default_seconds),
                            );
                    let now = ctx.now();
                    if tightened {
                        let watermark = next_watermark(
                            watermark_of(trust.get("sessionsRevokedBefore")),
                            None,
                            now,
                        )?;
                        next.insert("sessionsRevokedBefore".into(), crate::js::number(watermark));
                    }
                    next.insert("updatedAt".into(), crate::js::number(now));
                    let stored = tx.put("trusts", &next).await?;
                    Ok(Value::Object(public_trust(&stored)))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:trust:update",
                &crate::api::string_member(&input, "trustId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// `/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/`: a compact JWS.
fn compact_jws(token: &str) -> bool {
    let segment = |part: &str| {
        part.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    };
    let parts: Vec<&str> = token.split('.').collect();
    parts.len() == 3
        && !parts[0].is_empty()
        && !parts[1].is_empty()
        && parts.iter().all(|part| segment(part))
}

/// The `links` API group (`createLinksApi(ctx)`): one method per route `links/{method}`.
pub struct LinksApi {
    ctx: Arc<ServerContext>,
}

/// `createLinksApi(ctx)`.
pub fn create_links_api(ctx: &Arc<ServerContext>) -> IamResult<LinksApi> {
    Ok(LinksApi { ctx: ctx.clone() })
}

impl LinksApi {
    /// `links/create`: links the caller's identity with the identity of `targetCredential` (flows.ts).
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<links::CreateInput>,
    ) -> IamResult<Reply<links::CreateOutput>> {
        let target = crate::api::credential_from_json(input.get("targetCredential"));
        Ok(Reply::json(
            self.ctx
                .flows()?
                .link_identities(credential, &target)
                .await?,
        ))
    }

    /// `links/list`: linked accounts of the current identity, for account-switcher UIs. Switching still requires a
    /// target credential.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        _input: Body<links::ListInput>,
    ) -> IamResult<Reply<links::ListOutput>> {
        let ctx = &self.ctx;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let result = ctx
            .store
            .transaction(|tx| {
                let authenticated = &authenticated;
                async move {
                    let current = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    let own = current.identity.id.clone();
                    let mut links = Vec::new();
                    for side in ["leftId", "rightId"] {
                        links.extend(
                            tx.find(
                                "identityLinks",
                                &Filter::new().eq(side, own.clone()).eq("revoked", false),
                                &FindOptions::default(),
                            )
                            .await?,
                        );
                    }
                    let mut result = Vec::new();
                    for link in links {
                        let link: IdentityLink = crate::port::decode(link)?;
                        let other_id = if link.left_id == own {
                            &link.right_id
                        } else {
                            &link.left_id
                        };
                        let Some(other) = tx.get("identities", other_id).await? else {
                            continue;
                        };
                        let other: better_iam_core::Identity = crate::port::decode(other)?;
                        let Some(realm) = tx.get("tenants", &other.tenant_id).await? else {
                            continue;
                        };
                        let realm: better_iam_core::Tenant = crate::port::decode(realm)?;
                        let mut account = Map::new();
                        account.insert("id".into(), Value::String(link.id.clone()));
                        account.insert("identityId".into(), Value::String(other.id.clone()));
                        if let Some(email) = &other.email {
                            account.insert("email".into(), Value::String(email.clone()));
                        }
                        account.insert("name".into(), Value::String(other.name.clone()));
                        account.insert(
                            "status".into(),
                            serde_json::to_value(other.status).unwrap_or(Value::Null),
                        );
                        account.insert("tenantId".into(), Value::String(realm.id.clone()));
                        account.insert("tenantName".into(), Value::String(realm.name.clone()));
                        if let Some(slug) = &realm.slug {
                            account.insert("tenantSlug".into(), Value::String(slug.clone()));
                        }
                        account.insert(
                            "tenantStatus".into(),
                            serde_json::to_value(realm.status).unwrap_or(Value::Null),
                        );
                        result.push(Value::Object(account));
                    }
                    Ok(Value::Array(result))
                }
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `links/revoke`: ends a link the caller is part of (`identity:unlink`).
    pub async fn revoke(
        &self,
        credential: &CredentialInput,
        input: Body<links::RevokeInput>,
    ) -> IamResult<Reply<links::RevokeOutput>> {
        let ctx = &self.ctx;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        ctx.auth.require_recent(&authenticated)?;
        let body = &input;
        let result = ctx
            .store
            .transaction(|tx| {
                let authenticated = &authenticated;
                async move {
                    ctx.principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    let link_id = crate::api::string_member(body, "linkId");
                    let link = if link_id.is_empty() {
                        None
                    } else {
                        tx.get("identityLinks", &link_id).await?
                    };
                    let own = &authenticated.identity.id;
                    let Some(mut link) = link.filter(|link| {
                        link.get("leftId").and_then(Value::as_str) == Some(own.as_str())
                            || link.get("rightId").and_then(Value::as_str) == Some(own.as_str())
                    }) else {
                        return Err(IamError::with_status("NOT_FOUND", "Link not found", 404));
                    };
                    link.insert("revoked".into(), Value::Bool(true));
                    tx.put("identityLinks", &link).await?;
                    let resource = link
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    ctx.events()?
                        .audit(
                            &tx,
                            authenticated,
                            "identity:unlink",
                            &authenticated.identity.tenant_id,
                            &resource,
                            better_iam_core::AuditOutcome::Allow,
                            false,
                            None,
                        )
                        .await?;
                    Ok(json!({ "revoked": true }))
                }
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `links/switch`: switches to a linked account with that account's credential (flows.ts).
    pub async fn switch(
        &self,
        credential: &CredentialInput,
        input: Body<links::SwitchInput>,
    ) -> IamResult<Reply<links::SwitchOutput>> {
        let target = crate::api::credential_from_json(input.get("targetCredential"));
        Ok(Reply::json(
            self.ctx
                .flows()?
                .switch_identity(credential, input.get("linkId"), &target)
                .await?,
        ))
    }
}

/// The `root` API group (`createRootApi(ctx)`): one method per route `root/{method}`.
pub struct RootApi {
    ctx: Arc<ServerContext>,
}

/// `createRootApi(ctx)`.
pub fn create_root_api(ctx: &Arc<ServerContext>) -> IamResult<RootApi> {
    Ok(RootApi { ctx: ctx.clone() })
}

impl RootApi {
    /// `root/listAdministrators`: the root tenant's root administrators (root only).
    pub async fn list_administrators(
        &self,
        credential: &CredentialInput,
        input: Body<root::ListAdministratorsInput>,
    ) -> IamResult<Reply<root::ListAdministratorsOutput>> {
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx, tenant: realm, ..
             }| {
                Box::pin(async move {
                    if realm.parent_id.is_some() {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "Root administrators belong to the root tenant",
                        )
                        .into());
                    }
                    let identities = tx
                        .find(
                            "identities",
                            &Filter::new()
                                .eq("tenantId", realm.id.clone())
                                .eq("rootAdmin", true),
                            &FindOptions::default(),
                        )
                        .await?;
                    Ok(Value::Array(
                        identities
                            .iter()
                            .map(|identity| {
                                Value::Object(crate::utils::public_identity_record(identity))
                            })
                            .collect(),
                    ))
                })
            },
        );
        let result = self
            .ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:identities:read",
                &crate::api::string_member(&input, "tenantId"),
                mutation,
                true,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `root/setAdministrator`: grants or removes the protected root capability; only root administrators may call it.
    pub async fn set_administrator(
        &self,
        credential: &CredentialInput,
        input: Body<root::SetAdministratorInput>,
    ) -> IamResult<Reply<root::SetAdministratorOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant: realm,
             }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let enabled = match body.get("enabled") {
                        Some(Value::Bool(enabled)) if realm.parent_id.is_none() => *enabled,
                        _ => {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                "Root administrator must belong to root",
                            )
                            .into());
                        }
                    };
                    let mut record = ctx
                        .scoped(&tx, "identities", body.get("identityId"), &realm.id)
                        .await?;
                    let identity: better_iam_core::Identity = crate::port::decode(record.clone())?;
                    if identity.kind != better_iam_core::IdentityKind::User {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "Root administrators must be users",
                        )
                        .into());
                    }
                    if !enabled {
                        ctx.protect_last_owner(&tx, &identity).await?;
                    }
                    ctx.revoke_all(&tx, &identity.id).await?;
                    record.insert("rootAdmin".into(), Value::Bool(enabled));
                    let stored = tx.put("identities", &record).await?;
                    Ok(Value::Object(crate::utils::public_identity_record(&stored)))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:root:grant",
                &crate::api::string_member(&input, "identityId"),
                mutation,
                true,
            )
            .await?;
        Ok(Reply::json(result))
    }
}
