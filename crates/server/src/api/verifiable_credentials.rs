//! Port of `packages/server/src/api/verifiable-credentials.ts`.
//!
//! The `verifiableCredentials` API group: credential types (`iam:vc:manage`), issued credentials and their status
//! (`iam:vc:read`, `iam:vc:revoke`), wallet offers for others (`iam:vc:issue`), and, for members, credentials and
//! offers for themselves where policies allow `vc:request` on `credential-type/{name}`. `nonce`, `verify` and
//! `issuerMetadata` are public. Also the wallet-facing protocol mount (OpenID4VCI metadata, pre-authorized code
//! token endpoint, nonce and credential endpoints, JWKS, type metadata and Token Status Lists) and the
//! `iam.verifiableCredentials` runtime.
//!
//! Records are read and written as raw JSON records, so member order and members this port does not know survive a
//! round trip (a mixed fleet shares the database with TypeScript).

use std::sync::{Arc, LazyLock, Weak};

use better_iam_core::js::{cmp_utf16, has_js_whitespace, number_to_string, strict_equal};
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, IamStoreExt, Identity, IdentityKind, IdentityStatus, Record, SessionKind, Tenant,
    TenantStatus,
};
use better_iam_types::api::verifiable_credentials;
use bytes::Bytes;
use futures::future::BoxFuture;
use regex::Regex;
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext, OperationDenied};
use crate::grant_deadline::grant_deadline;
use crate::js::{number, truthy};
use crate::options::{HttpRequest, HttpResponse};
use crate::sd_jwt::{VerifyFailure, random_int};
use crate::utils::{hash, id};
use crate::validation::{integer, text};
use crate::vc::{
    HolderKey, IssueActor, IssueCredentialInput, LocalVerifyOptions, ResolvedVcOptions,
    VerifiedCredential, active_issuer_key, assert_vc, create_issuer_key, create_nonce,
    holder_cleared, holder_from_proof, issue_credential, issuer_jwks, issuer_keys, issuer_url,
    matches_hash, may_request, offer_id_of, offer_token, status_list_token, sweep_credentials,
    type_by_name, vc_claims, vc_options, verify_local_presentation, write_status,
};

const PRE_AUTHORIZED: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

static TYPE_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9_-]{0,63}$").expect("valid regex"));
static COLOR: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^#[0-9a-fA-F]{6}$").expect("valid regex"));
static TENANT_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,128}$").expect("valid regex"));

fn str_of<'a>(record: &'a Record, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// A numeric member (`NaN` when it is not a number).
fn num_of(record: &Record, key: &str) -> f64 {
    record
        .get(key)
        .and_then(better_iam_core::js::as_number)
        .unwrap_or(f64::NAN)
}

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

/// A JavaScript exception that is not an `IamError` travels as INTERNAL_ERROR 500 (`crate::js::internal_error`).
fn is_thrown(error: &IamError) -> bool {
    error.code == "INTERNAL_ERROR" && error.status == 500
}

/// `!(end <= now)`: true for an end still ahead, and for NaN (a comparison with NaN is false).
fn not_reached(end: f64, now: f64) -> bool {
    end.partial_cmp(&now) != Some(std::cmp::Ordering::Less)
        && end.partial_cmp(&now) != Some(std::cmp::Ordering::Equal)
}

async fn find(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

/// `(a, b) => (a.name < b.name ? -1 : 1)`.
fn by_name(a: &Record, b: &Record) -> std::cmp::Ordering {
    if cmp_utf16(str_of(a, "name"), str_of(b, "name")) == std::cmp::Ordering::Less {
        std::cmp::Ordering::Less
    } else {
        std::cmp::Ordering::Greater
    }
}

/// `(a, b) => b.issuedAt - a.issuedAt || (a.id < b.id ? -1 : 1)`.
fn by_newest_issued(a: &Record, b: &Record) -> std::cmp::Ordering {
    let difference = num_of(b, "issuedAt") - num_of(a, "issuedAt");
    if difference < 0.0 {
        std::cmp::Ordering::Less
    } else if difference > 0.0 {
        std::cmp::Ordering::Greater
    } else if cmp_utf16(str_of(a, "id"), str_of(b, "id")) == std::cmp::Ordering::Less {
        std::cmp::Ordering::Less
    } else {
        std::cmp::Ordering::Greater
    }
}

/// `typeView(type)`: the stored type without its unique key.
fn type_view(record: &Record) -> Value {
    let mut view = record.clone();
    view.shift_remove("uniqueKey");
    Value::Object(view)
}

/// `issuedView(record, now)`: an issued credential without its unique key and record expiry, with its state.
fn issued_view(record: &Record, now: f64) -> Value {
    let mut view = record.clone();
    view.shift_remove("uniqueKey");
    view.shift_remove("expiresAt");
    let state = if num_of(record, "validUntil") <= now {
        Value::String("expired".into())
    } else {
        record.get("status").cloned().unwrap_or(Value::Null)
    };
    view.insert("state".into(), state);
    Value::Object(view)
}

/// `keyView(key)`: an issuer key without its sealed private half.
fn key_view(key: &Record) -> Value {
    let mut view = Map::new();
    for member in ["id", "kid", "status", "alg", "publicJwk", "createdAt"] {
        view.insert(
            member.to_owned(),
            key.get(member).cloned().unwrap_or(Value::Null),
        );
    }
    for member in ["rotatedAt", "retiredAt"] {
        if let Some(value) = key.get(member) {
            view.insert(member.to_owned(), value.clone());
        }
    }
    Value::Object(view)
}

/// `typeName(value)`.
fn type_name(value: Option<&Value>) -> IamResult<String> {
    match value {
        Some(Value::String(name)) if TYPE_NAME.is_match(name) => Ok(name.clone()),
        _ => Err(invalid(
            "Type names use 1-64 lowercase letters, digits, \"_\" or \"-\"",
        )),
    }
}

/// `color(value, name)`.
fn color(value: Option<&Value>, name: &str) -> IamResult<String> {
    match value {
        Some(Value::String(color)) if COLOR.is_match(color) => Ok(color.clone()),
        _ => Err(invalid(format!("{name} must be a #rrggbb color"))),
    }
}

/// `tenantOf(value)`.
fn tenant_of(value: Option<&Value>) -> IamResult<String> {
    text(value, "tenantId", 256)
}

/// `activeTenantOf(ctx, tx, tenantId)`: TENANT_INACTIVE unless the tenant and every ancestor are active.
async fn active_tenant_of(ctx: &ServerContext, tx: &Store, tenant_id: &str) -> IamResult<Tenant> {
    let tenant = ctx.tenant(tx, tenant_id).await?;
    if ctx
        .ancestry(tx, &tenant)
        .await?
        .iter()
        .any(|item| item.status != TenantStatus::Active)
    {
        return Err(IamError::with_status(
            "TENANT_INACTIVE",
            "This organization is not active",
            403,
        ));
    }
    Ok(tenant)
}

/// The tenant's credential type `name` (validated), NOT_FOUND otherwise.
async fn scoped_type(tx: &Store, tenant_id: &str, name: Option<&Value>) -> IamResult<Record> {
    let name = type_name(name)?;
    type_by_name(tx, tenant_id, &name)
        .await?
        .ok_or_else(|| IamError::with_status("NOT_FOUND", "Unknown credential type", 404))
}

/// Checks for people getting a credential for themselves: not "view as", MFA when the type asks, then policy.
async fn self_service_refusal(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant: &Tenant,
    record: &Record,
) -> IamResult<Option<IamError>> {
    if principal
        .session
        .impersonator_id
        .as_deref()
        .is_some_and(|id| !id.is_empty())
    {
        return Ok(Some(IamError::with_status(
            "IMPERSONATION_RESTRICTED",
            "Credentials cannot be issued while viewing as someone",
            403,
        )));
    }
    // An agent acting for a person never binds that person's credential to a key of its own choosing.
    if principal.session.kind == SessionKind::Delegated {
        return Ok(Some(IamError::with_status(
            "ACCESS_DENIED",
            "Agents acting for people cannot obtain credentials for them",
            403,
        )));
    }
    if principal.identity.tenant_id != tenant.id {
        return Ok(Some(IamError::with_status(
            "ACCESS_DENIED",
            "Credentials are issued to members of this organization",
            403,
        )));
    }
    if truthy(record.get("requireMfa"))
        && principal.identity.kind == IdentityKind::User
        && !principal.session.mfa
    {
        return Ok(Some(IamError::with_status(
            "MFA_REQUIRED",
            "Sign in with multi-factor authentication to get this credential",
            403,
        )));
    }
    if !truthy(record.get("enabled")) {
        return Ok(Some(IamError::with_status(
            "TYPE_DISABLED",
            "This credential type is disabled",
            409,
        )));
    }
    if !may_request(ctx, tx, principal, tenant, record).await? {
        return Ok(Some(IamError::with_status(
            "ACCESS_DENIED",
            "Access denied",
            403,
        )));
    }
    Ok(None)
}

/// The latest a self-service credential may stay valid: assumed roles and temporary credentials end with their
/// session; standing sign-ins with the time-limited grants (just-in-time, expiring bindings or memberships, access
/// windows) that allow `vc:request`.
async fn request_deadline(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
) -> IamResult<f64> {
    let kind = principal.session.kind;
    if kind != SessionKind::User && kind != SessionKind::ApiKey {
        return Ok(principal.session.expires_at);
    }
    grant_deadline(ctx, tx, principal, tenant_id, f64::INFINITY, "vc:request").await
}

/// What a self-service call runs once the caller passed the checks: the transaction, the caller, the tenant and the
/// credential type.
type SelfServiceRun<'a> = Box<
    dyn FnOnce(Store, AuthenticatedPrincipal, Tenant, Record) -> BoxFuture<'a, IamResult<Value>>
        + Send
        + 'a,
>;

/// The input of `makeOffer`.
struct OfferInput<'a> {
    tenant: &'a Tenant,
    credential_type: &'a Record,
    identity: &'a Identity,
    principal: &'a AuthenticatedPrincipal,
    options: &'a ResolvedVcOptions,
    self_service: bool,
    with_tx_code: bool,
}

/// `makeOffer(...)`: a pre-authorized OpenID4VCI offer and what a wallet scans.
async fn make_offer(ctx: &ServerContext, tx: &Store, input: OfferInput<'_>) -> IamResult<Value> {
    let offer_id = id();
    let code = offer_token("biam_vco", &offer_id);
    let tx_code = input
        .with_tx_code
        .then(|| format!("{:06}", random_int(1_000_000)));
    let now = ctx.now();
    let mut record = Record::new();
    record.insert("id".into(), Value::String(offer_id.clone()));
    record.insert("tenantId".into(), Value::String(input.tenant.id.clone()));
    record.insert(
        "typeId".into(),
        input
            .credential_type
            .get("id")
            .cloned()
            .unwrap_or(Value::Null),
    );
    record.insert(
        "identityId".into(),
        Value::String(input.identity.id.clone()),
    );
    record.insert("codeHash".into(), Value::String(hash(&code)));
    if let Some(tx_code) = &tx_code {
        record.insert(
            "txCodeHash".into(),
            Value::String(hash(&format!("{offer_id}:{tx_code}"))),
        );
    }
    record.insert("txCodeAttempts".into(), number(0.0));
    record.insert("selfService".into(), Value::Bool(input.self_service));
    record.insert("mfa".into(), Value::Bool(input.principal.session.mfa));
    record.insert("createdAt".into(), number(now));
    record.insert(
        "createdBy".into(),
        Value::String(input.principal.identity.id.clone()),
    );
    record.insert(
        "expiresAt".into(),
        number(now + input.options.offer_lifetime_ms),
    );
    let offer = tx.insert("vcOffers", &record).await?;
    let mut metadata = Map::new();
    metadata.insert(
        "type".into(),
        input
            .credential_type
            .get("name")
            .cloned()
            .unwrap_or(Value::Null),
    );
    metadata.insert(
        "identityId".into(),
        Value::String(input.identity.id.clone()),
    );
    metadata.insert("txCode".into(), Value::Bool(tx_code.is_some()));
    ctx.events()?
        .audit(
            tx,
            input.principal,
            "vc:offer:create",
            &input.tenant.id,
            &format!("vc/offers/{}", str_of(&offer, "id")),
            AuditOutcome::Allow,
            false,
            Some(metadata),
        )
        .await?;
    let mut grant = Map::new();
    grant.insert("pre-authorized_code".into(), Value::String(code));
    if tx_code.is_some() {
        grant.insert(
            "tx_code".into(),
            json!({ "length": 6, "input_mode": "numeric", "description": "The PIN shown with the offer" }),
        );
    }
    let mut grants = Map::new();
    grants.insert(PRE_AUTHORIZED.to_owned(), Value::Object(grant));
    let mut credential_offer = Map::new();
    credential_offer.insert(
        "credential_issuer".into(),
        Value::String(issuer_url(ctx, &input.tenant.id)),
    );
    credential_offer.insert(
        "credential_configuration_ids".into(),
        Value::Array(vec![
            input
                .credential_type
                .get("name")
                .cloned()
                .unwrap_or(Value::Null),
        ]),
    );
    credential_offer.insert("grants".into(), Value::Object(grants));
    let credential_offer = Value::Object(credential_offer);
    let mut result = Map::new();
    result.insert(
        "offerId".into(),
        offer.get("id").cloned().unwrap_or(Value::Null),
    );
    result.insert("credentialOffer".into(), credential_offer.clone());
    result.insert(
        "offerUri".into(),
        Value::String(format!(
            "openid-credential-offer://?credential_offer={}",
            better_iam_auth::util::encode_uri_component(&better_iam_core::js::stringify(
                &credential_offer
            ))
        )),
    );
    if let Some(tx_code) = tx_code {
        result.insert("txCode".into(), Value::String(tx_code));
    }
    result.insert(
        "expiresAt".into(),
        offer.get("expiresAt").cloned().unwrap_or(Value::Null),
    );
    Ok(Value::Object(result))
}

/// `changeStatus(tx, record, next, actorId, reason?)`: a status transition written to the record and its list.
async fn change_status(
    ctx: &ServerContext,
    tx: &Store,
    record: &Record,
    next: &str,
    actor_id: &str,
    reason: Option<&Value>,
) -> IamResult<Record> {
    let current = record.get("status").and_then(Value::as_str);
    let allowed = (next == "revoked" && current != Some("revoked"))
        || (next == "suspended" && current == Some("valid"))
        || (next == "valid" && current == Some("suspended"));
    if !allowed {
        return Err(IamError::with_status(
            "INVALID_TRANSITION",
            format!(
                "A {} credential cannot become {next}",
                crate::js::js_string(record.get("status"))
            ),
            409,
        ));
    }
    write_status(ctx, tx, record, next).await?;
    let now = ctx.now();
    let mut changed = record.clone();
    changed.insert("status".into(), Value::String(next.to_owned()));
    if next == "revoked" {
        changed.insert("revokedAt".into(), number(now));
        changed.insert("revokedBy".into(), Value::String(actor_id.to_owned()));
    }
    if let Some(reason) = reason {
        changed.insert(
            "reason".into(),
            Value::String(text(Some(reason), "reason", 512)?),
        );
    }
    tx.put("vcIssued", &changed).await
}

/// The `verifiableCredentials` API group (`createVerifiableCredentialsApi(ctx)`): one method per route `verifiableCredentials/{method}`.
pub struct VerifiableCredentialsApi {
    ctx: Arc<ServerContext>,
}

/// `createVerifiableCredentialsApi(ctx)`.
pub fn create_verifiable_credentials_api(
    ctx: &Arc<ServerContext>,
) -> IamResult<VerifiableCredentialsApi> {
    Ok(VerifiableCredentialsApi { ctx: ctx.clone() })
}

impl VerifiableCredentialsApi {
    /// A self-service call in its own transaction; a refusal is audited (committed) before it is thrown.
    async fn self_service(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        name: Option<&Value>,
        run: SelfServiceRun<'_>,
    ) -> IamResult<Value> {
        let ctx = &self.ctx;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let tenant_id = tenant_id.to_owned();
        let name = name.cloned();
        let outcome: Result<Value, IamError> = ctx
            .store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                let tenant = ctx.tenant(&tx, &tenant_id).await?;
                let record = scoped_type(&tx, &tenant_id, name.as_ref()).await?;
                if let Some(refusal) =
                    self_service_refusal(ctx, &tx, &principal, &tenant, &record).await?
                {
                    let mut metadata = Map::new();
                    metadata.insert("reason".into(), Value::String(refusal.code.clone()));
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "vc:request",
                            &tenant_id,
                            &format!("credential-type/{}", str_of(&record, "name")),
                            AuditOutcome::Deny,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    return Ok(Err(refusal));
                }
                Ok(Ok(run(tx.clone(), principal, tenant, record).await?))
            })
            .await?;
        outcome
    }

    /// `verifiableCredentials/available`: the credential types the caller may request for themselves. No permission.
    pub async fn available(
        &self,
        credential: &CredentialInput,
        input: Body<verifiable_credentials::AvailableInput>,
    ) -> IamResult<Reply<verifiable_credentials::AvailableOutput>> {
        let ctx = &self.ctx;
        assert_vc(ctx)?;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let result = ctx
            .store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                let tenant = ctx.tenant(&tx, &tenant_id).await?;
                let mut result: Vec<Record> = Vec::new();
                let types = find(
                    &tx,
                    "vcCredentialTypes",
                    Filter::new()
                        .eq("tenantId", tenant_id.clone())
                        .eq("enabled", true),
                )
                .await?;
                for record in types {
                    if self_service_refusal(ctx, &tx, &principal, &tenant, &record)
                        .await?
                        .is_none()
                    {
                        result.push(record);
                    }
                }
                result.sort_by(by_name);
                Ok(Value::Array(result.iter().map(type_view).collect()))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `verifiableCredentials/createOffer`: an OpenID4VCI credential offer (pre-authorized code) a wallet redeems:
    /// for the caller (`vc:request`) or, with `identityId`, for someone else (`iam:vc:issue`). `txCode: true` adds a
    /// 6-digit PIN the wallet asks for.
    pub async fn create_offer(
        &self,
        credential: &CredentialInput,
        input: Body<verifiable_credentials::CreateOfferInput>,
    ) -> IamResult<Reply<verifiable_credentials::CreateOfferOutput>> {
        let ctx = &self.ctx;
        let options = assert_vc(ctx)?;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let with_tx_code = input.get("txCode") == Some(&Value::Bool(true));
        let own = match input.get("identityId") {
            None => true,
            Some(identity_id) => strict_equal(
                identity_id,
                &Value::String(authenticated.identity.id.clone()),
            ),
        };
        if own {
            let options = options.clone();
            let run: SelfServiceRun<'_> = Box::new(move |tx, principal, tenant, record| {
                Box::pin(async move {
                    make_offer(
                        ctx,
                        &tx,
                        OfferInput {
                            tenant: &tenant,
                            credential_type: &record,
                            identity: &principal.identity,
                            principal: &principal,
                            options: &options,
                            self_service: true,
                            with_tx_code,
                        },
                    )
                    .await
                })
            });
            let result = self
                .self_service(credential, &tenant_id, input.get("type"), run)
                .await?;
            return Ok(Reply::json(result));
        }
        let name = type_name(input.get("type"))?;
        let body = &input;
        let options = &options;
        let type_name_ref = &name;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    let record =
                        scoped_type(&tx, &tenant.id, Some(&Value::String(type_name_ref.clone())))
                            .await?;
                    if !truthy(record.get("enabled")) {
                        return Err(IamError::with_status(
                            "TYPE_DISABLED",
                            "This credential type is disabled",
                            409,
                        )
                        .into());
                    }
                    let identity_id = text(body.get("identityId"), "identityId", 256)?;
                    let identity = ctx.active_identity(&tx, &identity_id, &tenant.id).await?;
                    if identity.status != IdentityStatus::Active || ctx.identity_expired(&identity)
                    {
                        return Err(IamError::with_status(
                            "IDENTITY_INACTIVE",
                            "Credentials are issued to active members only",
                            409,
                        )
                        .into());
                    }
                    // Security clearances: whoever offers it, the holder must be cleared for the type's classification
                    // label.
                    if !holder_cleared(
                        ctx,
                        &tx,
                        &tenant,
                        &identity,
                        str_of(&record, "name"),
                        Some(principal.session.mfa),
                    )
                    .await?
                    {
                        return Err(OperationDenied::new(Some(
                            "The holder is not cleared for this credential type",
                        )));
                    }
                    Ok(make_offer(
                        ctx,
                        &tx,
                        OfferInput {
                            tenant: &tenant,
                            credential_type: &record,
                            identity: &identity,
                            principal: &principal,
                            options,
                            self_service: false,
                            with_tx_code,
                        },
                    )
                    .await?)
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id.clone())),
                "iam:vc:issue",
                &format!("vc/types/{name}"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `verifiableCredentials/createType`: defines a credential type: its claims, lifetime and wallet display.
    /// Requires iam:vc:manage.
    pub async fn create_type(
        &self,
        credential: &CredentialInput,
        input: Body<verifiable_credentials::CreateTypeInput>,
    ) -> IamResult<Reply<verifiable_credentials::CreateTypeOutput>> {
        let ctx = &self.ctx;
        let name = type_name(input.get("name"))?;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let body = &input;
        let name_ref = &name;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    let options = assert_vc(ctx)?;
                    let name = name_ref.clone();
                    if type_by_name(&tx, &tenant.id, &name).await?.is_some() {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "A credential type with this name exists",
                            409,
                        )
                        .into());
                    }
                    let own = issuer_url(ctx, &tenant.id);
                    let vct = match body.get("vct") {
                        None => format!("{own}/types/{name}"),
                        Some(vct) => text(Some(vct), "vct", 256)?,
                    };
                    if has_js_whitespace(&vct) {
                        return Err(invalid("vct cannot contain whitespace").into());
                    }
                    // Type identifiers under this deployment's issuers belong to the issuer they name.
                    let deployment = format!(
                        "{}{}/vc/",
                        ctx.config.base_url.origin().ascii_serialization(),
                        ctx.config.base_path
                    );
                    if vct.starts_with(&deployment) && !vct.starts_with(&format!("{own}/")) {
                        return Err(invalid("vct names another organization's issuer").into());
                    }
                    let now = ctx.now();
                    let mut record = Record::new();
                    record.insert("id".into(), Value::String(id()));
                    record.insert("tenantId".into(), Value::String(tenant.id.clone()));
                    record.insert("uniqueKey".into(), Value::String(name.clone()));
                    record.insert("name".into(), Value::String(name.clone()));
                    record.insert(
                        "displayName".into(),
                        Value::String(text(body.get("displayName"), "displayName", 128)?),
                    );
                    if let Some(description) = body.get("description") {
                        record.insert(
                            "description".into(),
                            Value::String(text(Some(description), "description", 512)?),
                        );
                    }
                    record.insert("vct".into(), Value::String(vct));
                    record.insert(
                        "claims".into(),
                        Value::Array(vc_claims(
                            body.get("claims"),
                            &ctx.catalog.identity_attributes,
                        )?),
                    );
                    let lifetime = match body.get("lifetimeMs") {
                        None => (30.0 * 86_400_000.0f64).min(options.max_lifetime_ms),
                        Some(lifetime) => integer(
                            Some(lifetime),
                            "lifetimeMs",
                            5.0 * 60_000.0,
                            options.max_lifetime_ms,
                        )?,
                    };
                    record.insert("lifetimeMs".into(), number(lifetime));
                    record.insert(
                        "requireMfa".into(),
                        Value::Bool(body.get("requireMfa") == Some(&Value::Bool(true))),
                    );
                    record.insert(
                        "enabled".into(),
                        Value::Bool(body.get("enabled") != Some(&Value::Bool(false))),
                    );
                    if let Some(background) = body.get("backgroundColor") {
                        record.insert(
                            "backgroundColor".into(),
                            Value::String(color(Some(background), "backgroundColor")?),
                        );
                    }
                    if let Some(text_color) = body.get("textColor") {
                        record.insert(
                            "textColor".into(),
                            Value::String(color(Some(text_color), "textColor")?),
                        );
                    }
                    record.insert("createdAt".into(), number(now));
                    record.insert(
                        "createdBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    record.insert("updatedAt".into(), number(now));
                    let record = tx.insert("vcCredentialTypes", &record).await?;
                    // The first type also creates the tenant's issuer key.
                    active_issuer_key(ctx, &tx, &tenant.id, &principal.identity.id).await?;
                    Ok(type_view(&record))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id)),
                "iam:vc:manage",
                &format!("vc/types/{name}"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `verifiableCredentials/deleteType`: deletes a type; refused while valid credentials of it exist (disable it,
    /// or revoke them first). Requires iam:vc:manage.
    pub async fn delete_type(
        &self,
        credential: &CredentialInput,
        input: Body<verifiable_credentials::DeleteTypeInput>,
    ) -> IamResult<Reply<verifiable_credentials::DeleteTypeOutput>> {
        let ctx = &self.ctx;
        let name = type_name(input.get("name"))?;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let name_ref = &name;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                assert_vc(ctx)?;
                let record =
                    scoped_type(&tx, &tenant.id, Some(&Value::String(name_ref.clone()))).await?;
                let now = ctx.now();
                let live = find(
                    &tx,
                    "vcIssued",
                    Filter::new()
                        .eq("tenantId", tenant.id.clone())
                        .eq("typeId", record.get("id").cloned().unwrap_or(Value::Null)),
                )
                .await?
                .into_iter()
                .filter(|issued| {
                    str_of(issued, "status") != "revoked" && num_of(issued, "validUntil") > now
                })
                .count();
                if live > 0 {
                    return Err(IamError::with_status(
                        "RESOURCE_IN_USE",
                        format!("{live} credentials of this type are still valid"),
                        409,
                    )
                    .into());
                }
                let offers = find(
                    &tx,
                    "vcOffers",
                    Filter::new()
                        .eq("tenantId", tenant.id.clone())
                        .eq("typeId", record.get("id").cloned().unwrap_or(Value::Null)),
                )
                .await?;
                for offer in offers {
                    tx.delete("vcOffers", str_of(&offer, "id")).await?;
                }
                tx.delete("vcCredentialTypes", str_of(&record, "id"))
                    .await?;
                Ok(json!({ "deleted": true }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id)),
                "iam:vc:manage",
                &format!("vc/types/{name}"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `verifiableCredentials/getType`: one credential type. Requires iam:vc:read.
    pub async fn get_type(
        &self,
        credential: &CredentialInput,
        input: Body<verifiable_credentials::GetTypeInput>,
    ) -> IamResult<Reply<verifiable_credentials::GetTypeOutput>> {
        let ctx = &self.ctx;
        let name = type_name(input.get("name"))?;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let name_ref = &name;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                assert_vc(ctx)?;
                let record =
                    scoped_type(&tx, &tenant.id, Some(&Value::String(name_ref.clone()))).await?;
                Ok(type_view(&record))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id)),
                "iam:vc:read",
                &format!("vc/types/{name}"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `verifiableCredentials/issuerMetadata` (public: no credential): the tenant's OpenID4VCI credential issuer
    /// metadata (also at /.well-known/openid-credential-issuer).
    pub async fn issuer_metadata(
        &self,
        input: Body<verifiable_credentials::IssuerMetadataInput>,
    ) -> IamResult<Reply<verifiable_credentials::IssuerMetadataOutput>> {
        let ctx = &self.ctx;
        assert_vc(ctx)?;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let tenant = active_tenant_of(ctx, &ctx.store, &tenant_id).await?;
        Ok(Reply::json(
            issuer_metadata(ctx, &ctx.store, &tenant).await?,
        ))
    }

    /// `verifiableCredentials/listIssued`: issued credentials, newest first, by type, identity or state. Requires
    /// iam:vc:read.
    pub async fn list_issued(
        &self,
        credential: &CredentialInput,
        input: Body<verifiable_credentials::ListIssuedInput>,
    ) -> IamResult<Reply<verifiable_credentials::ListIssuedOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                assert_vc(ctx)?;
                let given = |name: &str| body.get(name).filter(|value| !value.is_null());
                let limit = match given("limit") {
                    Some(limit) => integer(Some(limit), "limit", 1.0, 500.0)?,
                    None => 100.0,
                };
                let offset = match given("offset") {
                    Some(offset) => integer(Some(offset), "offset", 0.0, 1_000_000.0)?,
                    None => 0.0,
                };
                let mut filter = Filter::new().eq("tenantId", tenant.id.clone());
                if let Some(name) = body.get("type") {
                    filter = filter.eq("typeName", type_name(Some(name))?);
                }
                if let Some(identity_id) = body.get("identityId") {
                    filter = filter.eq("identityId", text(Some(identity_id), "identityId", 256)?);
                }
                let now = ctx.now();
                let state = body.get("state");
                let mut records: Vec<Record> = find(&tx, "vcIssued", filter)
                    .await?
                    .into_iter()
                    .filter(|record| match state {
                        None => true,
                        Some(state) => issued_view(record, now)
                            .get("state")
                            .is_some_and(|own| strict_equal(own, state)),
                    })
                    .collect();
                records.sort_by(by_newest_issued);
                let total = records.len();
                let page: Vec<Value> = records
                    .iter()
                    .skip(offset as usize)
                    .take(limit as usize)
                    .map(|record| issued_view(record, now))
                    .collect();
                Ok(json!({ "credentials": page, "total": number(total as f64) }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id)),
                "iam:vc:read",
                "vc/credentials",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `verifiableCredentials/listKeys`: issuer keys, oldest first (retired ones included). Requires iam:vc:read.
    pub async fn list_keys(
        &self,
        credential: &CredentialInput,
        input: Body<verifiable_credentials::ListKeysInput>,
    ) -> IamResult<Reply<verifiable_credentials::ListKeysOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                assert_vc(ctx)?;
                let keys = issuer_keys(&tx, &tenant.id).await?;
                Ok(Value::Array(keys.iter().map(key_view).collect()))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id)),
                "iam:vc:read",
                "vc/keys",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `verifiableCredentials/listTypes`: every credential type of the tenant, by name. Requires iam:vc:read.
    pub async fn list_types(
        &self,
        credential: &CredentialInput,
        input: Body<verifiable_credentials::ListTypesInput>,
    ) -> IamResult<Reply<verifiable_credentials::ListTypesOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                assert_vc(ctx)?;
                let mut types = find(
                    &tx,
                    "vcCredentialTypes",
                    Filter::new().eq("tenantId", tenant.id.clone()),
                )
                .await?;
                types.sort_by(by_name);
                Ok(Value::Array(types.iter().map(type_view).collect()))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id)),
                "iam:vc:read",
                "vc/types",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `verifiableCredentials/mine`: the caller's own credentials in the tenant, newest first.
    pub async fn mine(
        &self,
        credential: &CredentialInput,
        input: Body<verifiable_credentials::MineInput>,
    ) -> IamResult<Reply<verifiable_credentials::MineOutput>> {
        let ctx = &self.ctx;
        assert_vc(ctx)?;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let result = ctx
            .store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                if principal.session.kind == SessionKind::Delegated {
                    return Err(IamError::with_status("ACCESS_DENIED", "Access denied", 403));
                }
                let now = ctx.now();
                let mut records = find(
                    &tx,
                    "vcIssued",
                    Filter::new()
                        .eq("tenantId", tenant_id.clone())
                        .eq("identityId", principal.identity.id.clone()),
                )
                .await?;
                records.sort_by(by_newest_issued);
                Ok(Value::Array(
                    records
                        .iter()
                        .take(100)
                        .map(|record| issued_view(record, now))
                        .collect(),
                ))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `verifiableCredentials/nonce` (public: no credential): a single-use nonce (`c_nonce`) for a holder proof,
    /// valid five minutes.
    pub async fn nonce(
        &self,
        input: Body<verifiable_credentials::NonceInput>,
    ) -> IamResult<Reply<verifiable_credentials::NonceOutput>> {
        let ctx = &self.ctx;
        assert_vc(ctx)?;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        ctx.tenant(&ctx.store, &tenant_id).await?;
        // Stateless (signed, checked and spent at use): handing nonces out writes nothing.
        Ok(Reply::json(
            json!({ "nonce": create_nonce(ctx, &tenant_id), "expiresIn": 300 }),
        ))
    }

    /// `verifiableCredentials/reinstate`: lifts a suspension. Requires iam:vc:revoke.
    pub async fn reinstate(
        &self,
        credential: &CredentialInput,
        input: Body<verifiable_credentials::ReinstateInput>,
    ) -> IamResult<Reply<verifiable_credentials::ReinstateOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let credential_id = text(input.get("credentialId"), "credentialId", 256)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      tenant,
                      principal,
                  }| {
                Box::pin(async move {
                    assert_vc(ctx)?;
                    let record = ctx
                        .scoped(&tx, "vcIssued", body.get("credentialId"), &tenant.id)
                        .await?;
                    let changed =
                        change_status(ctx, &tx, &record, "valid", &principal.identity.id, None)
                            .await?;
                    Ok(issued_view(&changed, ctx.now()))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id)),
                "iam:vc:revoke",
                &format!("vc/credentials/{credential_id}"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `verifiableCredentials/request`: issues a credential of `type` for the caller, bound to the key in `proof`
    /// (an OpenID4VCI proof JWT over a nonce from `nonce`). Needs `vc:request` on `credential-type/{type}` (and MFA
    /// when the type asks). Audited as `vc:credential:issue`; a refusal as a denied `vc:request`.
    pub async fn request(
        &self,
        credential: &CredentialInput,
        input: Body<verifiable_credentials::RequestInput>,
    ) -> IamResult<Reply<verifiable_credentials::RequestOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let proof = input.get("proof").cloned();
        let run: SelfServiceRun<'_> = Box::new(move |tx, principal, tenant, record| {
            Box::pin(async move {
                let holder: HolderKey =
                    holder_from_proof(ctx, &tx, &tenant.id, proof.as_ref()).await?;
                let deadline = request_deadline(ctx, &tx, &principal, &tenant.id).await?;
                let (issued, issued_record) = issue_credential(
                    ctx,
                    &tx,
                    IssueCredentialInput {
                        tenant: &tenant,
                        credential_type: &record,
                        identity: &principal.identity,
                        holder_jwk: &holder.jwk,
                        holder_thumbprint: &holder.thumbprint,
                        via: "request",
                        actor: IssueActor::Principal(&principal),
                        issued_by: &principal.identity.id,
                        self_service: true,
                        mfa: principal.session.mfa,
                        offer_id: None,
                        deadline: Some(deadline),
                    },
                )
                .await?;
                Ok(
                    json!({ "credential": issued, "record": issued_view(&issued_record, ctx.now()) }),
                )
            })
        });
        let result = self
            .self_service(credential, &tenant_id, input.get("type"), run)
            .await?;
        Ok(Reply::json(result))
    }

    /// `verifiableCredentials/retireKey`: stops publishing a previous key: credentials it signed stop verifying.
    /// Refused while valid ones exist, unless `force` (which revokes them). Requires iam:vc:manage.
    pub async fn retire_key(
        &self,
        credential: &CredentialInput,
        input: Body<verifiable_credentials::RetireKeyInput>,
    ) -> IamResult<Reply<verifiable_credentials::RetireKeyOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      tenant,
                      principal,
                  }| {
                Box::pin(async move {
                    assert_vc(ctx)?;
                    let wanted = body.get("kid");
                    let key = issuer_keys(&tx, &tenant.id)
                        .await?
                        .into_iter()
                        .find(|item| match (item.get("kid"), wanted) {
                            (Some(kid), Some(wanted)) => strict_equal(kid, wanted),
                            (None, None) => true,
                            _ => false,
                        });
                    let Some(key) = key else {
                        return Err(
                            IamError::with_status("NOT_FOUND", "Unknown issuer key", 404).into(),
                        );
                    };
                    if str_of(&key, "status") != "previous" {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "Only a previous key can be retired",
                            409,
                        )
                        .into());
                    }
                    let now = ctx.now();
                    let live: Vec<Record> = find(
                        &tx,
                        "vcIssued",
                        Filter::new()
                            .eq("tenantId", tenant.id.clone())
                            .eq("keyId", key.get("kid").cloned().unwrap_or(Value::Null)),
                    )
                    .await?
                    .into_iter()
                    .filter(|record| {
                        str_of(record, "status") != "revoked" && num_of(record, "validUntil") > now
                    })
                    .collect();
                    if !live.is_empty() && body.get("force") != Some(&Value::Bool(true)) {
                        return Err(IamError::with_status(
                            "RESOURCE_IN_USE",
                            format!(
                                "{} credentials signed by this key are still valid",
                                live.len()
                            ),
                            409,
                        )
                        .into());
                    }
                    let reason = Value::String("key-retired".into());
                    for record in &live {
                        change_status(
                            ctx,
                            &tx,
                            record,
                            "revoked",
                            &principal.identity.id,
                            Some(&reason),
                        )
                        .await?;
                    }
                    let mut retired = key.clone();
                    retired.insert("status".into(), Value::String("retired".into()));
                    retired.insert("retiredAt".into(), number(now));
                    let retired = tx.put("vcIssuerKeys", &retired).await?;
                    Ok(key_view(&retired))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id)),
                "iam:vc:manage",
                "vc/keys",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `verifiableCredentials/revoke`: revokes a credential for good (verifiers see it in the status list): the
    /// holder's own without permission, anyone's with iam:vc:revoke.
    pub async fn revoke(
        &self,
        credential: &CredentialInput,
        input: Body<verifiable_credentials::RevokeInput>,
    ) -> IamResult<Reply<verifiable_credentials::RevokeOutput>> {
        let ctx = &self.ctx;
        assert_vc(ctx)?;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let credential_id = text(input.get("credentialId"), "credentialId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let found = ctx
            .scoped(
                &ctx.store,
                "vcIssued",
                Some(&Value::String(credential_id.clone())),
                &tenant_id,
            )
            .await?;
        let reason = input.get("reason").cloned();
        // The holder's own path skips the permission, so only a session acting in its own unrestricted right takes
        // it: not "view as", not an agent acting for them, not a key or token narrowed by a session policy.
        let session = &authenticated.session;
        if str_of(&found, "identityId") == authenticated.identity.id
            && found.get("identityId").is_some_and(Value::is_string)
            && session.impersonator_id.as_deref().is_none_or(str::is_empty)
            && session.kind != SessionKind::Delegated
            && session.policy.is_none()
            && session.source_policy.is_none()
        {
            let (tenant_id, credential_id) = (tenant_id.clone(), credential_id.clone());
            let result = ctx
                .store
                .transaction(move |tx| async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, &authenticated)
                        .await?;
                    let record = ctx
                        .scoped(
                            &tx,
                            "vcIssued",
                            Some(&Value::String(credential_id.clone())),
                            &tenant_id,
                        )
                        .await?;
                    let changed = change_status(
                        ctx,
                        &tx,
                        &record,
                        "revoked",
                        &principal.identity.id,
                        reason.as_ref(),
                    )
                    .await?;
                    let mut metadata = Map::new();
                    metadata.insert("own".into(), Value::Bool(true));
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "vc:credential:revoke",
                            &tenant_id,
                            &format!("vc/credentials/{credential_id}"),
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(issued_view(&changed, ctx.now()))
                })
                .await?;
            return Ok(Reply::json(result));
        }
        let (scope_tenant, scope_id) = (tenant_id.clone(), credential_id.clone());
        let reason_ref = &reason;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let record = ctx
                    .scoped(
                        &tx,
                        "vcIssued",
                        Some(&Value::String(scope_id)),
                        &scope_tenant,
                    )
                    .await?;
                let changed = change_status(
                    ctx,
                    &tx,
                    &record,
                    "revoked",
                    &principal.identity.id,
                    reason_ref.as_ref(),
                )
                .await?;
                Ok(issued_view(&changed, ctx.now()))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id)),
                "iam:vc:revoke",
                &format!("vc/credentials/{credential_id}"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `verifiableCredentials/rotateKey`: a new signing key; the current one stays published as `previous`, so
    /// credentials it signed keep verifying. Requires iam:vc:manage.
    pub async fn rotate_key(
        &self,
        credential: &CredentialInput,
        input: Body<verifiable_credentials::RotateKeyInput>,
    ) -> IamResult<Reply<verifiable_credentials::RotateKeyOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      tenant,
                      principal,
                  }| {
                Box::pin(async move {
                    assert_vc(ctx)?;
                    let now = ctx.now();
                    for key in issuer_keys(&tx, &tenant.id).await? {
                        if str_of(&key, "status") == "active" {
                            let mut previous = key.clone();
                            previous.insert("status".into(), Value::String("previous".into()));
                            previous.insert("rotatedAt".into(), number(now));
                            tx.put("vcIssuerKeys", &previous).await?;
                        }
                    }
                    let key =
                        create_issuer_key(ctx, &tx, &tenant.id, &principal.identity.id).await?;
                    Ok(key_view(&key))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id)),
                "iam:vc:manage",
                "vc/keys",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `verifiableCredentials/status`: issuer keys, credential types, issued credentials by state, and status lists.
    /// Requires iam:vc:read.
    pub async fn status(
        &self,
        credential: &CredentialInput,
        input: Body<verifiable_credentials::StatusInput>,
    ) -> IamResult<Reply<verifiable_credentials::StatusOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                assert_vc(ctx)?;
                let now = ctx.now();
                let issued = find(
                    &tx,
                    "vcIssued",
                    Filter::new().eq("tenantId", tenant.id.clone()),
                )
                .await?;
                let live: Vec<&Record> = issued
                    .iter()
                    .filter(|record| num_of(record, "validUntil") > now)
                    .collect();
                let count = |status: &str| {
                    live.iter()
                        .filter(|record| str_of(record, "status") == status)
                        .count() as f64
                };
                let keys: Vec<Value> = issuer_keys(&tx, &tenant.id)
                    .await?
                    .iter()
                    .filter(|key| str_of(key, "status") != "retired")
                    .map(key_view)
                    .collect();
                let types = find(
                    &tx,
                    "vcCredentialTypes",
                    Filter::new().eq("tenantId", tenant.id.clone()),
                )
                .await?
                .len();
                let (valid, suspended, revoked) =
                    (count("valid"), count("suspended"), count("revoked"));
                let expired = (issued.len() - live.len()) as f64;
                let lists = find(
                    &tx,
                    "vcStatusLists",
                    Filter::new().eq("tenantId", tenant.id.clone()),
                )
                .await?
                .len();
                Ok(json!({
                    "issuer": issuer_url(ctx, &tenant.id),
                    "metadataUrl": format!(
                        "{}/.well-known/openid-credential-issuer{}/vc/{}",
                        ctx.config.base_url.origin().ascii_serialization(),
                        ctx.config.base_path,
                        tenant.id
                    ),
                    "keys": keys,
                    "types": number(types as f64),
                    "credentials": {
                        "valid": number(valid),
                        "suspended": number(suspended),
                        "revoked": number(revoked),
                        "expired": number(expired),
                    },
                    "statusLists": number(lists as f64),
                }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id)),
                "iam:vc:read",
                "vc/issuer",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `verifiableCredentials/suspend`: suspends a valid credential (reversible with `reinstate`). Requires
    /// iam:vc:revoke.
    pub async fn suspend(
        &self,
        credential: &CredentialInput,
        input: Body<verifiable_credentials::SuspendInput>,
    ) -> IamResult<Reply<verifiable_credentials::SuspendOutput>> {
        let ctx = &self.ctx;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let credential_id = text(input.get("credentialId"), "credentialId", 256)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      tenant,
                      principal,
                  }| {
                Box::pin(async move {
                    assert_vc(ctx)?;
                    let record = ctx
                        .scoped(&tx, "vcIssued", body.get("credentialId"), &tenant.id)
                        .await?;
                    let changed = change_status(
                        ctx,
                        &tx,
                        &record,
                        "suspended",
                        &principal.identity.id,
                        body.get("reason"),
                    )
                    .await?;
                    Ok(issued_view(&changed, ctx.now()))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id)),
                "iam:vc:revoke",
                &format!("vc/credentials/{credential_id}"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `verifiableCredentials/updateType`: changes a type's display, claims, lifetime or switches; its name and vct
    /// stay. Requires iam:vc:manage.
    pub async fn update_type(
        &self,
        credential: &CredentialInput,
        input: Body<verifiable_credentials::UpdateTypeInput>,
    ) -> IamResult<Reply<verifiable_credentials::UpdateTypeOutput>> {
        let ctx = &self.ctx;
        let name = type_name(input.get("name"))?;
        let tenant_id = tenant_of(input.get("tenantId"))?;
        let body = &input;
        let name_ref = &name;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let options = assert_vc(ctx)?;
                let record =
                    scoped_type(&tx, &tenant.id, Some(&Value::String(name_ref.clone()))).await?;
                let mut next = record.clone();
                next.insert("updatedAt".into(), number(ctx.now()));
                if let Some(display_name) = body.get("displayName") {
                    next.insert(
                        "displayName".into(),
                        Value::String(text(Some(display_name), "displayName", 128)?),
                    );
                }
                match body.get("description") {
                    Some(Value::Null) => {
                        next.shift_remove("description");
                    }
                    Some(description) => {
                        next.insert(
                            "description".into(),
                            Value::String(text(Some(description), "description", 512)?),
                        );
                    }
                    None => {}
                }
                if let Some(claims) = body.get("claims") {
                    next.insert(
                        "claims".into(),
                        Value::Array(vc_claims(Some(claims), &ctx.catalog.identity_attributes)?),
                    );
                }
                if let Some(lifetime) = body.get("lifetimeMs") {
                    next.insert(
                        "lifetimeMs".into(),
                        number(integer(
                            Some(lifetime),
                            "lifetimeMs",
                            5.0 * 60_000.0,
                            options.max_lifetime_ms,
                        )?),
                    );
                }
                for key in ["requireMfa", "enabled"] {
                    if let Some(value) = body.get(key) {
                        let Value::Bool(flag) = value else {
                            return Err(invalid(format!("{key} must be a boolean")).into());
                        };
                        next.insert(key.to_owned(), Value::Bool(*flag));
                    }
                }
                for key in ["backgroundColor", "textColor"] {
                    match body.get(key) {
                        Some(Value::Null) => {
                            next.shift_remove(key);
                        }
                        Some(value) => {
                            next.insert(key.to_owned(), Value::String(color(Some(value), key)?));
                        }
                        None => {}
                    }
                }
                let saved = tx.put("vcCredentialTypes", &next).await?;
                Ok(type_view(&saved))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id)),
                "iam:vc:manage",
                &format!("vc/types/{name}"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `verifiableCredentials/verify` (public: no credential): verifies a presentation of a credential this
    /// deployment issued (signature, disclosures, key binding for `audience` and `nonce`, current status). Answers
    /// `{ valid: false, reason, message }` instead of failing.
    pub async fn verify(
        &self,
        input: Body<verifiable_credentials::VerifyInput>,
    ) -> IamResult<Reply<verifiable_credentials::VerifyOutput>> {
        let ctx = &self.ctx;
        assert_vc(ctx)?;
        let presentation = text(input.get("presentation"), "presentation", 65536)?;
        let mut options = LocalVerifyOptions::default();
        if let Some(audience) = input.get("audience") {
            options.audience = Some(Value::String(text(Some(audience), "audience", 512)?));
        }
        if let Some(nonce) = input.get("nonce") {
            options.nonce = Some(Value::String(text(Some(nonce), "nonce", 256)?));
        }
        if let Some(tenant_id) = input.get("tenantId") {
            options.tenant_id = Some(Value::String(tenant_of(Some(tenant_id))?));
        }
        match verify_local_presentation(ctx, &presentation, &options).await {
            Ok(verified) => {
                let mut out = Map::new();
                out.insert("valid".into(), Value::Bool(true));
                out.extend(verified.to_json());
                Ok(Reply::json(Value::Object(out)))
            }
            Err(VerifyFailure::SdJwt(error)) => Ok(Reply::json(json!({
                "valid": false,
                "reason": error.reason,
                "message": error.message,
            }))),
            Err(VerifyFailure::Other(error)) => Err(error),
        }
    }
}

/// OpenID4VCI 1.0 credential issuer metadata for a tenant's enabled types.
async fn issuer_metadata(ctx: &ServerContext, tx: &Store, tenant: &Tenant) -> IamResult<Value> {
    let issuer = issuer_url(ctx, &tenant.id);
    let mut types = find(
        tx,
        "vcCredentialTypes",
        Filter::new()
            .eq("tenantId", tenant.id.clone())
            .eq("enabled", true),
    )
    .await?;
    types.sort_by(by_name);
    let mut configurations = Map::new();
    for record in &types {
        let mut display = Map::new();
        display.insert(
            "name".into(),
            record.get("displayName").cloned().unwrap_or(Value::Null),
        );
        display.insert("locale".into(), Value::String("en".into()));
        for (member, key) in [
            ("description", "description"),
            ("backgroundColor", "background_color"),
            ("textColor", "text_color"),
        ] {
            if truthy(record.get(member)) {
                display.insert(
                    key.to_owned(),
                    record.get(member).cloned().unwrap_or(Value::Null),
                );
            }
        }
        let claims: Vec<Value> = claims_of(record)
            .iter()
            .map(|claim| {
                let mut out = Map::new();
                out.insert(
                    "path".into(),
                    Value::Array(vec![claim.get("name").cloned().unwrap_or(Value::Null)]),
                );
                if truthy(claim.get("label")) {
                    out.insert(
                        "display".into(),
                        json!([{ "name": claim.get("label").cloned().unwrap_or(Value::Null), "locale": "en" }]),
                    );
                }
                Value::Object(out)
            })
            .collect();
        configurations.insert(
            str_of(record, "name").to_owned(),
            json!({
                "format": "dc+sd-jwt",
                "vct": record.get("vct").cloned().unwrap_or(Value::Null),
                "scope": record.get("name").cloned().unwrap_or(Value::Null),
                "cryptographic_binding_methods_supported": ["jwk"],
                "credential_signing_alg_values_supported": ["ES256"],
                "proof_types_supported": { "jwt": { "proof_signing_alg_values_supported": ["ES256", "ES384", "EdDSA"] } },
                "credential_metadata": {
                    "display": [Value::Object(display)],
                    "claims": claims,
                },
            }),
        );
    }
    Ok(json!({
        "credential_issuer": issuer,
        "credential_endpoint": format!("{issuer}/credential"),
        "nonce_endpoint": format!("{issuer}/nonce"),
        "display": [{ "name": tenant.name, "locale": "en" }],
        "credential_configurations_supported": Value::Object(configurations),
    }))
}

/// A type's claim objects.
fn claims_of(record: &Record) -> Vec<Map<String, Value>> {
    match record.get("claims") {
        Some(Value::Array(claims)) => claims
            .iter()
            .filter_map(|claim| claim.as_object().cloned())
            .collect(),
        _ => Vec::new(),
    }
}

/// SD-JWT VC type metadata for `{issuer}/types/{name}`.
fn type_metadata(record: &Record) -> Value {
    let mut out = Map::new();
    out.insert(
        "vct".into(),
        record.get("vct").cloned().unwrap_or(Value::Null),
    );
    out.insert(
        "name".into(),
        record.get("displayName").cloned().unwrap_or(Value::Null),
    );
    if truthy(record.get("description")) {
        out.insert(
            "description".into(),
            record.get("description").cloned().unwrap_or(Value::Null),
        );
    }
    let mut display = Map::new();
    display.insert("locale".into(), Value::String("en".into()));
    display.insert(
        "name".into(),
        record.get("displayName").cloned().unwrap_or(Value::Null),
    );
    if truthy(record.get("description")) {
        display.insert(
            "description".into(),
            record.get("description").cloned().unwrap_or(Value::Null),
        );
    }
    if truthy(record.get("backgroundColor")) || truthy(record.get("textColor")) {
        let mut simple = Map::new();
        if truthy(record.get("backgroundColor")) {
            simple.insert(
                "background_color".into(),
                record
                    .get("backgroundColor")
                    .cloned()
                    .unwrap_or(Value::Null),
            );
        }
        if truthy(record.get("textColor")) {
            simple.insert(
                "text_color".into(),
                record.get("textColor").cloned().unwrap_or(Value::Null),
            );
        }
        display.insert(
            "rendering".into(),
            json!({ "simple": Value::Object(simple) }),
        );
    }
    out.insert("display".into(), Value::Array(vec![Value::Object(display)]));
    let claims: Vec<Value> = claims_of(record)
        .iter()
        .map(|claim| {
            let mut item = Map::new();
            item.insert(
                "path".into(),
                Value::Array(vec![claim.get("name").cloned().unwrap_or(Value::Null)]),
            );
            let never = claim.get("selective") == Some(&Value::Bool(false));
            item.insert(
                "sd".into(),
                Value::String(if never { "never" } else { "always" }.into()),
            );
            if truthy(claim.get("label")) {
                item.insert(
                    "display".into(),
                    json!([{ "locale": "en", "label": claim.get("label").cloned().unwrap_or(Value::Null) }]),
                );
            }
            Value::Object(item)
        })
        .collect();
    out.insert("claims".into(), Value::Array(claims));
    Value::Object(out)
}

const CORS: [(&str, &str); 4] = [
    ("access-control-allow-origin", "*"),
    ("access-control-allow-methods", "GET, POST, OPTIONS"),
    (
        "access-control-allow-headers",
        "authorization, content-type, dpop",
    ),
    ("cache-control", "no-store"),
];

/// `json(status, body, headers)`: `Response.json` with the CORS headers (later headers override).
fn json_reply(status: u16, body: &Value, headers: &[(&str, &str)]) -> HttpResponse {
    let mut merged: Vec<(&str, &str)> = CORS.to_vec();
    for (name, value) in headers {
        if let Some(existing) = merged.iter_mut().find(|(own, _)| own == name) {
            existing.1 = value;
        } else {
            merged.push((name, value));
        }
    }
    crate::http::json_response(status, body, &merged)
}

/// `oauthError(status, error, description, headers)`.
fn oauth_error(
    status: u16,
    error: &str,
    description: &str,
    headers: &[(&str, &str)],
) -> HttpResponse {
    json_reply(
        status,
        &json!({ "error": error, "error_description": description }),
        headers,
    )
}

fn header_value(request: &HttpRequest, name: &str) -> Option<String> {
    let values: Vec<String> = request
        .headers()
        .get_all(name)
        .iter()
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

/// Reads at most `limit` bytes of a body, refusing (PAYLOAD_TOO_LARGE) as soon as more arrive.
fn body_text(request: &HttpRequest, limit: usize) -> IamResult<String> {
    let declared = header_value(request, "content-length")
        .map(|length| better_iam_core::js::string_to_number(&length))
        .unwrap_or(0.0);
    if declared > limit as f64 || request.body().len() > limit {
        return Err(IamError::with_status(
            "PAYLOAD_TOO_LARGE",
            "Request body too large",
            413,
        ));
    }
    Ok(String::from_utf8_lossy(request.body()).into_owned())
}

/// The well-known metadata documents served for each issuer.
const WELL_KNOWN: [&str; 3] = [
    "openid-credential-issuer",
    "jwt-vc-issuer",
    "oauth-authorization-server",
];

/// The wallet-facing endpoints of every tenant's issuer, mounted beside the HTTP API (`{issuer}` is
/// `{origin}{basePath}/vc/{tenantId}`): `/.well-known/openid-credential-issuer{path}`,
/// `/.well-known/jwt-vc-issuer{path}` and `/.well-known/oauth-authorization-server{path}` metadata,
/// `{issuer}/token` (pre-authorized code), `{issuer}/nonce`, `{issuer}/credential`, `{issuer}/jwks.json`,
/// `{issuer}/types/{name}` and `{issuer}/status/{listId}` (Token Status List).
pub fn create_vc_protocol(
    ctx: &Arc<ServerContext>,
) -> IamResult<Arc<dyn crate::options::ProtocolMount>> {
    Ok(Arc::new(VcProtocol {
        ctx: Arc::downgrade(ctx),
        prefix: format!("{}/vc/", ctx.config.base_path),
    }))
}

/// The protocol mount (it holds its context weakly: the context keeps its mounts).
struct VcProtocol {
    ctx: Weak<ServerContext>,
    prefix: String,
}

#[async_trait::async_trait]
impl crate::options::ProtocolMount for VcProtocol {
    async fn handle(&self, request: &HttpRequest) -> IamResult<Option<HttpResponse>> {
        let Some(ctx) = self.ctx.upgrade() else {
            return Ok(None);
        };
        if vc_options(&ctx)?.is_none() {
            return Ok(None);
        }
        let Some(url) = crate::http::request_url(request, &ctx.config.base_url) else {
            return Ok(None);
        };
        let pathname = url.path();
        let mut tenant_id: Option<String> = None;
        let mut rest = String::new();
        let mut metadata: Option<&str> = None;
        for name in WELL_KNOWN {
            let start = format!("/.well-known/{name}{}", self.prefix);
            if let Some(tail) = pathname.strip_prefix(&start) {
                metadata = Some(name);
                tenant_id = Some(tail.to_owned());
            }
        }
        if metadata.is_none() {
            let Some(path) = pathname.strip_prefix(&self.prefix) else {
                return Ok(None);
            };
            match path.find('/') {
                None => tenant_id = Some(path.to_owned()),
                Some(slash) => {
                    tenant_id = Some(path[..slash].to_owned());
                    rest = path[slash + 1..].to_owned();
                }
            }
        }
        let tenant_id = match tenant_id {
            Some(tenant_id) if TENANT_PATTERN.is_match(&tenant_id) => tenant_id,
            _ => return Ok(Some(json_reply(404, &json!({ "error": "not_found" }), &[]))),
        };
        if request.method() == http::Method::OPTIONS {
            let mut response = http::Response::new(Bytes::new());
            *response.status_mut() = http::StatusCode::NO_CONTENT;
            for (name, value) in CORS {
                if let Ok(value) = http::HeaderValue::from_str(value) {
                    response.headers_mut().insert(name, value);
                }
            }
            return Ok(Some(response));
        }
        let answered = async {
            if request.method() == http::Method::GET {
                return read(&ctx, &tenant_id, metadata, &rest).await;
            }
            if request.method() == http::Method::POST {
                if rest == "token" {
                    return token_endpoint(&ctx, request, &tenant_id).await;
                }
                if rest == "nonce" {
                    active_tenant_of(&ctx, &ctx.store, &tenant_id).await?;
                    return Ok(json_reply(
                        200,
                        &json!({ "c_nonce": create_nonce(&ctx, &tenant_id) }),
                        &[],
                    ));
                }
                if rest == "credential" {
                    return credential_endpoint(&ctx, request, &tenant_id).await;
                }
            }
            Ok(json_reply(404, &json!({ "error": "not_found" }), &[]))
        }
        .await;
        Ok(Some(match answered {
            Ok(response) => response,
            Err(error) if is_thrown(&error) => {
                json_reply(500, &json!({ "error": "server_error" }), &[])
            }
            Err(error) => json_reply(
                error.status,
                &json!({
                    "error": if error.status == 404 { "not_found" } else { "invalid_request" },
                    "error_description": error.message,
                }),
                &[],
            ),
        }))
    }
}

/// The public reads: metadata, JWKS, type metadata and status list tokens.
async fn read(
    ctx: &Arc<ServerContext>,
    tenant_id: &str,
    metadata: Option<&str>,
    rest: &str,
) -> IamResult<HttpResponse> {
    // Public reads stay off the write lock: nothing here creates or changes a row.
    let reader = ctx.store.clone();
    let tenant = active_tenant_of(ctx, &reader, tenant_id).await?;
    let issuer = issuer_url(ctx, tenant_id);
    match metadata {
        Some("openid-credential-issuer") => {
            return Ok(json_reply(
                200,
                &issuer_metadata(ctx, &reader, &tenant).await?,
                &[],
            ));
        }
        Some("jwt-vc-issuer") => {
            return Ok(json_reply(
                200,
                &json!({ "issuer": issuer, "jwks": issuer_jwks(&reader, tenant_id).await? }),
                &[],
            ));
        }
        Some("oauth-authorization-server") => {
            return Ok(json_reply(
                200,
                &json!({
                    "issuer": issuer,
                    "token_endpoint": format!("{issuer}/token"),
                    "grant_types_supported": [PRE_AUTHORIZED],
                    "pre-authorized_grant_anonymous_access_supported": true,
                }),
                &[],
            ));
        }
        _ => {}
    }
    if rest == "jwks.json" {
        return Ok(json_reply(
            200,
            &issuer_jwks(&reader, tenant_id).await?,
            &[],
        ));
    }
    if let Some(name) = rest.strip_prefix("types/") {
        return Ok(match type_by_name(&reader, tenant_id, name).await? {
            Some(record) => json_reply(200, &type_metadata(&record), &[]),
            None => json_reply(404, &json!({ "error": "not_found" }), &[]),
        });
    }
    if let Some(list_id) = rest.strip_prefix("status/") {
        let list = reader.get("vcStatusLists", list_id).await?;
        let Some(list) = list.filter(|list| str_of(list, "tenantId") == tenant_id) else {
            return Ok(json_reply(404, &json!({ "error": "not_found" }), &[]));
        };
        let token = status_list_token(ctx, &reader, &list).await?;
        let ttl = number_to_string(assert_vc(ctx)?.status_list_ttl_seconds);
        let mut response = http::Response::new(Bytes::from(token));
        let cache_control = format!("public, max-age={ttl}");
        // `{ ...cors, 'content-type': ..., 'cache-control': ... }`: the later cache-control wins.
        let headers: [(&str, &str); 5] = [
            CORS[0],
            CORS[1],
            CORS[2],
            ("content-type", "application/statuslist+jwt"),
            ("cache-control", cache_control.as_str()),
        ];
        for (name, value) in headers {
            if let Ok(value) = http::HeaderValue::from_str(value) {
                response.headers_mut().insert(name, value);
            }
        }
        return Ok(response);
    }
    Ok(json_reply(404, &json!({ "error": "not_found" }), &[]))
}

/// Pre-authorized code grant: one offer, one access token, the PIN checked at most five times.
async fn token_endpoint(
    ctx: &Arc<ServerContext>,
    request: &HttpRequest,
    tenant_id: &str,
) -> IamResult<HttpResponse> {
    let form_encoded = header_value(request, "content-type").is_some_and(|kind| {
        better_iam_core::js::to_lower(&kind).starts_with("application/x-www-form-urlencoded")
    });
    if !form_encoded {
        return Ok(oauth_error(
            400,
            "invalid_request",
            "Send a form-encoded token request",
            &[],
        ));
    }
    let text = body_text(request, 8192)?;
    let form: Vec<(String, String)> = url::form_urlencoded::parse(text.as_bytes())
        .into_owned()
        .collect();
    let param = |name: &str| {
        form.iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    };
    if param("grant_type").as_deref() != Some(PRE_AUTHORIZED) {
        return Ok(oauth_error(
            400,
            "unsupported_grant_type",
            "Only the pre-authorized code grant is supported",
            &[],
        ));
    }
    let code = param("pre-authorized_code").unwrap_or_default();
    let offer_id = offer_id_of(Some(&Value::String(code.clone())), "biam_vco");
    let tx_code = param("tx_code");
    let tenant_id = tenant_id.to_owned();
    let ctx = ctx.clone();
    ctx.store
        .clone()
        .transaction(move |tx| async move {
            active_tenant_of(&ctx, &tx, &tenant_id).await?;
            let offer = match &offer_id {
                Some(offer_id) => tx.get("vcOffers", offer_id).await?,
                None => None,
            };
            let now = ctx.now();
            let usable = offer.as_ref().filter(|offer| {
                str_of(offer, "tenantId") == tenant_id
                    && offer.get("tenantId").is_some_and(Value::is_string)
                    && matches_hash(offer.get("codeHash"), &code)
                    && !offer.contains_key("redeemedAt")
                    && not_reached(num_of(offer, "expiresAt"), now)
            });
            let Some(offer) = usable.cloned() else {
                return Ok(oauth_error(
                    400,
                    "invalid_grant",
                    "The offer is unknown, used or expired",
                    &[],
                ));
            };
            let offer_id = str_of(&offer, "id").to_owned();
            if truthy(offer.get("txCodeHash")) {
                // A wallet that did not ask for the PIN yet has not guessed wrong.
                let Some(tx_code) = tx_code.filter(|tx_code| !tx_code.is_empty()) else {
                    return Ok(oauth_error(
                        400,
                        "invalid_request",
                        "This offer needs its PIN (tx_code)",
                        &[],
                    ));
                };
                if !matches_hash(offer.get("txCodeHash"), &format!("{offer_id}:{tx_code}")) {
                    let attempts = num_of(&offer, "txCodeAttempts") + 1.0;
                    // Five wrong PINs end the offer.
                    let mut changed = offer.clone();
                    changed.insert("txCodeAttempts".into(), number(attempts));
                    if attempts >= 5.0 {
                        changed.insert("expiresAt".into(), number(now));
                    }
                    tx.put("vcOffers", &changed).await?;
                    let locked = attempts >= 5.0;
                    let mut event = Record::new();
                    event.insert("id".into(), Value::String(id()));
                    event.insert("tenantId".into(), Value::String(tenant_id.clone()));
                    event.insert(
                        "actorId".into(),
                        offer.get("identityId").cloned().unwrap_or(Value::Null),
                    );
                    event.insert("action".into(), Value::String("vc:offer:redeem".into()));
                    event.insert(
                        "resourceId".into(),
                        Value::String(format!("vc/offers/{offer_id}")),
                    );
                    event.insert("outcome".into(), Value::String("deny".into()));
                    event.insert("timestamp".into(), number(now));
                    event.insert(
                        "metadata".into(),
                        json!({
                            "reason": if locked { "pin-locked" } else { "wrong-pin" },
                            "attempts": number(attempts),
                        }),
                    );
                    ctx.events()?.record_audit(&tx, &event).await?;
                    return Ok(oauth_error(
                        400,
                        "invalid_grant",
                        if locked {
                            "Too many wrong PINs; the offer ended"
                        } else {
                            "The PIN is wrong"
                        },
                        &[],
                    ));
                }
            }
            let access_token = offer_token("biam_vcat", &offer_id);
            let access_expires_at = now + 5.0 * 60_000.0;
            let mut redeemed = offer.clone();
            redeemed.insert("redeemedAt".into(), number(now));
            redeemed.insert("accessTokenHash".into(), Value::String(hash(&access_token)));
            redeemed.insert("accessExpiresAt".into(), number(access_expires_at));
            redeemed.insert("expiresAt".into(), number(access_expires_at));
            tx.put("vcOffers", &redeemed).await?;
            Ok(json_reply(
                200,
                &json!({ "access_token": access_token, "token_type": "Bearer", "expires_in": 300 }),
                &[],
            ))
        })
        .await
}

/// Issues the offered credential to the wallet that holds the access token, bound to the key its proof names.
async fn credential_endpoint(
    ctx: &Arc<ServerContext>,
    request: &HttpRequest,
    tenant_id: &str,
) -> IamResult<HttpResponse> {
    let authorization = header_value(request, "authorization").unwrap_or_default();
    let access_token = match authorization.strip_prefix("Bearer ") {
        Some(token) => better_iam_core::js::trim(token).to_owned(),
        None => String::new(),
    };
    let offer_id = offer_id_of(Some(&Value::String(access_token.clone())), "biam_vcat");
    let challenge: [(&str, &str); 1] = [("www-authenticate", "Bearer error=\"invalid_token\"")];
    let Some(offer_id) = offer_id else {
        return Ok(oauth_error(
            401,
            "invalid_token",
            "A bearer access token is required",
            &challenge,
        ));
    };
    let parsed = body_text(request, 16384)
        .ok()
        .and_then(|text| better_iam_core::js::parse(&text).ok());
    let Some(Value::Object(body)) = parsed else {
        return Ok(oauth_error(
            400,
            "invalid_credential_request",
            "Send a JSON credential request",
            &[],
        ));
    };
    let tenant_id = tenant_id.to_owned();
    let ctx = ctx.clone();
    ctx.store
        .clone()
        .transaction(move |tx| async move {
            let tenant = active_tenant_of(&ctx, &tx, &tenant_id).await?;
            let offer = tx.get("vcOffers", &offer_id).await?;
            let now = ctx.now();
            let accepted = offer.as_ref().filter(|offer| {
                let access_expires = match offer.get("accessExpiresAt") {
                    None | Some(Value::Null) => 0.0,
                    Some(value) => better_iam_core::js::as_number(value).unwrap_or(f64::NAN),
                };
                str_of(offer, "tenantId") == tenant_id
                    && offer.get("tenantId").is_some_and(Value::is_string)
                    && matches_hash(offer.get("accessTokenHash"), &access_token)
                    && not_reached(access_expires, now)
                    && !offer.contains_key("credentialId")
            });
            let Some(offer) = accepted.cloned() else {
                return Ok(oauth_error(
                    401,
                    "invalid_token",
                    "The access token is unknown, used or expired",
                    &challenge,
                ));
            };
            let credential_type = tx.get("vcCredentialTypes", str_of(&offer, "typeId")).await?;
            let Some(credential_type) =
                credential_type.filter(|record| str_of(record, "tenantId") == tenant_id)
            else {
                return Ok(oauth_error(
                    400,
                    "unknown_credential_configuration",
                    "The offered credential type no longer exists",
                    &[],
                ));
            };
            let offer_ref = &offer;
            let type_ref = &credential_type;
            let tenant_ref = &tenant_id;
            let ctx_ref = &ctx;
            let tx_ref = &tx;
            // A refused redemption is answered, and audited: the transaction commits either way.
            let refuse = |status: u16, error: &'static str, description: String, reason: String| async move {
                let mut event = Record::new();
                event.insert("id".into(), Value::String(id()));
                event.insert("tenantId".into(), Value::String(tenant_ref.clone()));
                event.insert(
                    "actorId".into(),
                    offer_ref.get("identityId").cloned().unwrap_or(Value::Null),
                );
                event.insert("action".into(), Value::String("vc:offer:redeem".into()));
                event.insert(
                    "resourceId".into(),
                    Value::String(format!("vc/offers/{}", str_of(offer_ref, "id"))),
                );
                event.insert("outcome".into(), Value::String("deny".into()));
                event.insert("timestamp".into(), number(now));
                event.insert(
                    "metadata".into(),
                    json!({ "reason": reason, "type": type_ref.get("name").cloned().unwrap_or(Value::Null) }),
                );
                ctx_ref.events()?.record_audit(tx_ref, &event).await?;
                Ok::<HttpResponse, IamError>(oauth_error(status, error, &description, &[]))
            };
            let requested = match body.get("credential_configuration_id") {
                Some(value) if !value.is_null() => Some(value.clone()),
                _ => {
                    let same_vct = match (body.get("vct"), credential_type.get("vct")) {
                        (Some(a), Some(b)) => strict_equal(a, b),
                        (None, None) => true,
                        _ => false,
                    };
                    if same_vct {
                        credential_type.get("name").cloned()
                    } else {
                        None
                    }
                }
            };
            let same_type = match (&requested, credential_type.get("name")) {
                (Some(requested), Some(name)) => strict_equal(requested, name),
                (None, None) => true,
                _ => false,
            };
            if !same_type {
                return Ok(oauth_error(
                    400,
                    "unknown_credential_configuration",
                    "This token is for another credential",
                    &[],
                ));
            }
            let proofs_jwt = match body.get("proofs") {
                Some(Value::Object(proofs)) => proofs.get("jwt"),
                _ => None,
            };
            let proof: Option<Value> = match proofs_jwt {
                Some(Value::Array(items)) if items.len() == 1 => Some(items[0].clone()),
                _ => match body.get("proof") {
                    Some(Value::Object(proof))
                        if proof.get("proof_type") == Some(&Value::String("jwt".into())) =>
                    {
                        proof.get("jwt").cloned()
                    }
                    _ => None,
                },
            };
            let Some(proof) = proof else {
                return Ok(oauth_error(400, "invalid_proof", "Send one jwt proof", &[]));
            };
            let identity: Option<Identity> =
                match tx.get("identities", str_of(&offer, "identityId")).await? {
                    Some(record) => Some(crate::port::decode(record)?),
                    None => None,
                };
            let Some(identity) = identity.filter(|identity| {
                identity.tenant_id == tenant_id
                    && identity.status == IdentityStatus::Active
                    && !ctx.identity_expired(identity)
            }) else {
                return refuse(
                    400,
                    "invalid_credential_request",
                    "The holder is no longer a member".into(),
                    "identity-inactive".into(),
                )
                .await;
            };
            // Self-service offers are re-decided now: access or MFA may have changed since the offer was made, and
            // the credential ends with the time-limited grants that allow it.
            let offer_mfa = truthy(offer.get("mfa"));
            let mut deadline: Option<f64> = None;
            if truthy(offer.get("selfService")) {
                let principal = ctx.decisions()?.simulated_principal(&identity, offer_mfa);
                let refused = (truthy(credential_type.get("requireMfa"))
                    && identity.kind == IdentityKind::User
                    && !offer_mfa)
                    || !may_request(&ctx, &tx, &principal, &tenant, &credential_type).await?;
                if refused {
                    return refuse(
                        403,
                        "access_denied",
                        "The holder may no longer receive this credential".into(),
                        "access-changed".into(),
                    )
                    .await;
                }
                deadline = Some(
                    grant_deadline(&ctx, &tx, &principal, &tenant_id, f64::INFINITY, "vc:request")
                        .await?,
                );
            } else if !holder_cleared(
                &ctx,
                &tx,
                &tenant,
                &identity,
                str_of(&credential_type, "name"),
                Some(offer_mfa),
            )
            .await?
            {
                // An administrator's offer needs no `vc:request`, but the holder must still be cleared for the
                // type's classification label now (security clearances).
                return refuse(
                    403,
                    "access_denied",
                    "The holder may no longer receive this credential".into(),
                    "access-changed".into(),
                )
                .await;
            }
            let holder = match holder_from_proof(&ctx, &tx, &tenant_id, Some(&proof)).await {
                Ok(holder) => holder,
                Err(error) => {
                    let code = if error.code == "INVALID_NONCE" {
                        "invalid_nonce"
                    } else {
                        "invalid_proof"
                    };
                    return Ok(oauth_error(400, code, &error.message, &[]));
                }
            };
            let offer_id = str_of(&offer, "id").to_owned();
            // An administrator's offer is theirs to answer for; a self-service one is the person's.
            let issued_by = if truthy(offer.get("selfService")) {
                identity.id.clone()
            } else {
                str_of(&offer, "createdBy").to_owned()
            };
            let issued = issue_credential(
                &ctx,
                &tx,
                IssueCredentialInput {
                    tenant: &tenant,
                    credential_type: &credential_type,
                    identity: &identity,
                    holder_jwk: &holder.jwk,
                    holder_thumbprint: &holder.thumbprint,
                    via: "offer",
                    actor: IssueActor::System(identity.id.clone()),
                    issued_by: &issued_by,
                    self_service: truthy(offer.get("selfService")),
                    mfa: offer_mfa,
                    offer_id: Some(&offer_id),
                    deadline,
                },
            )
            .await;
            let (credential, issued_record) = match issued {
                Ok(issued) => issued,
                Err(error) if !is_thrown(&error) => {
                    return refuse(
                        400,
                        "invalid_credential_request",
                        error.message.clone(),
                        better_iam_core::js::to_lower(&error.code),
                    )
                    .await;
                }
                Err(error) => return Err(error),
            };
            let mut redeemed = offer.clone();
            redeemed.shift_remove("accessTokenHash");
            redeemed.insert(
                "credentialId".into(),
                issued_record.get("id").cloned().unwrap_or(Value::Null),
            );
            tx.put("vcOffers", &redeemed).await?;
            // OpenID4VCI 1.0 answers `credentials`; `credential` keeps wallets on the earlier drafts working.
            Ok(json_reply(
                200,
                &json!({ "credentials": [{ "credential": credential }], "credential": credential }),
                &[],
            ))
        })
        .await
}

/// `iam.verifiableCredentials`: server-side verification and the scheduler job, no credential.
pub struct VcRuntime {
    ctx: Arc<ServerContext>,
}

/// `createVcRuntime(ctx)`.
pub fn create_vc_runtime(ctx: &Arc<ServerContext>) -> IamResult<VcRuntime> {
    Ok(VcRuntime { ctx: ctx.clone() })
}

/// The runtime `verify` options as TypeScript reads them (`{ audience?, nonce?, tenantId?, requireKeyBinding? }`).
fn local_options(options: Option<&Value>) -> IamResult<LocalVerifyOptions> {
    let options = match options {
        None => return Ok(LocalVerifyOptions::default()),
        // Reading a member of `null` is a TypeError.
        Some(Value::Null) => return Err(crate::js::internal_error()),
        Some(Value::Object(options)) => options.clone(),
        Some(_) => Map::new(),
    };
    Ok(LocalVerifyOptions {
        audience: options.get("audience").cloned(),
        nonce: options.get("nonce").cloned(),
        require_key_binding: (options.get("requireKeyBinding") == Some(&Value::Bool(false)))
            .then_some(false),
        tenant_id: options.get("tenantId").cloned(),
    })
}

impl VcRuntime {
    /// Whether the `verifiableCredentials` option is on.
    pub fn enabled(&self) -> IamResult<bool> {
        Ok(vc_options(&self.ctx)?.is_some())
    }

    /// Verifies a presentation of a credential this deployment issued; fails with `SdJwtError` and the reason
    /// ([`VerifyFailure::SdJwt`]). `options` is `{ audience?, nonce?, tenantId?, requireKeyBinding? }`.
    pub async fn verify(
        &self,
        presentation: &str,
        options: Option<&Value>,
    ) -> Result<VerifiedCredential, VerifyFailure> {
        let options = local_options(options)?;
        verify_local_presentation(&self.ctx, presentation, &options).await
    }

    /// Revokes credentials of people who are no longer active members (run hourly).
    pub async fn sweep(&self, input: Option<&Value>) -> IamResult<crate::vc::VcSweepResult> {
        sweep_credentials(&self.ctx, input).await
    }

    /// A holder-proof nonce for a tenant, for applications embedding their own wallet flow.
    pub fn nonce(&self, tenant_id: &str) -> IamResult<String> {
        Ok(create_nonce(&self.ctx, tenant_id))
    }

    /// The tenant's issuer identifier.
    pub fn issuer(&self, tenant_id: &str) -> IamResult<String> {
        Ok(issuer_url(&self.ctx, tenant_id))
    }

    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        let arg = |index: usize| args.get(index).filter(|value| !is_undefined(value));
        match method {
            "verify" => Some(
                async {
                    let options = local_options(arg(1))?;
                    // A presentation that is not a string fails like one without `~` (`malformed`).
                    let presentation = match arg(0) {
                        Some(Value::String(presentation)) => presentation.clone(),
                        _ => String::new(),
                    };
                    verify_local_presentation(&self.ctx, &presentation, &options)
                        .await
                        .map(|verified| Value::Object(verified.to_json()))
                        .map_err(IamError::from)
                }
                .await,
            ),
            "sweep" => Some(self.sweep(arg(0)).await.map(|result| result.to_json())),
            "nonce" => Some(self.nonce(&crate::js::js_string(arg(0))).map(Value::String)),
            "issuer" => Some(
                self.issuer(&crate::js::js_string(arg(0)))
                    .map(Value::String),
            ),
            _ => None,
        }
    }
}

/// The tagged `undefined` of the conformance encoding.
fn is_undefined(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|map| map.len() == 1 && map.contains_key("$undefined"))
}
