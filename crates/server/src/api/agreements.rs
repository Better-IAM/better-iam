//! Port of `packages/server/src/api/agreements.ts`: terms of use, versioned agreements a tenant asks its members to
//! accept. Policies see `principal.agreements` (names accepted in their current version) and
//! `principal.pendingAgreements` (required ones still owed), so a deny statement can hold back access until people
//! accept. Managing needs `iam:agreements:manage`, reporting `iam:agreements:read`; members list and accept their own
//! without a permission.

use std::sync::Arc;

use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, IamStoreExt, IdentityKind, Record, js as core_js,
};
use better_iam_types::api::agreements;
use indexmap::IndexMap;
use serde_json::{Map, Value, json};

use crate::agreements::{Agreement, AgreementAcceptance, acceptance_current};
use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::js::{defined, truthy, utf16_len};
use crate::metrics::locale_compare;
use crate::port::decode;
use crate::session_kinds::acts_in_own_right;
use crate::utils::id;
use crate::validation::{integer, text};

const MAX_AGREEMENTS: usize = 50;

/// Agreement text: up to 50 000 characters over several lines (tabs and line breaks allowed, other controls not).
fn body(value: Option<&Value>) -> IamResult<String> {
    match value {
        Some(Value::String(text))
            if !core_js::trim(text).is_empty()
                && utf16_len(text) <= 50_000
                && !text.chars().any(
                    |c| matches!(c as u32, 0x00..=0x08 | 0x0b | 0x0c | 0x0e..=0x1f | 0x7f),
                ) =>
        {
            Ok(text.clone())
        }
        _ => Err(IamError::new("INVALID_INPUT", "Invalid content")),
    }
}

/// `principal.session.impersonatorId` is set (truthy).
fn impersonating(principal: &AuthenticatedPrincipal) -> bool {
    principal
        .session
        .impersonator_id
        .as_deref()
        .is_some_and(|id| !id.is_empty())
}

/// Agreements are the caller's own business: refused for role sessions, session tokens and unknown kinds.
fn self_session(principal: &AuthenticatedPrincipal, tenant_id: &str) -> IamResult<()> {
    if !acts_in_own_right(principal.session.kind)
        || principal.session.tenant_id != tenant_id
        || principal.identity.tenant_id != tenant_id
    {
        return Err(IamError::with_status(
            "ACCESS_DENIED",
            "Agreements are accepted from an ordinary session of their tenant",
            403,
        ));
    }
    Ok(())
}

fn str_of<'a>(record: &'a Record, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

fn number_of(record: &Record, key: &str) -> f64 {
    record
        .get(key)
        .and_then(core_js::as_number)
        .unwrap_or(f64::NAN)
}

/// `fields(input, previous)`: the validated members of an agreement, in the order TypeScript builds them.
fn fields(input: &Map<String, Value>, previous: Option<&Record>) -> IamResult<Map<String, Value>> {
    let previous_member = |key: &str| previous.and_then(|record| record.get(key));
    let name_value = defined(input.get("name")).or_else(|| previous_member("name"));
    let name = core_js::trim(&text(name_value, "name", 100)?).to_owned();
    if name.is_empty() {
        return Err(IamError::new("INVALID_INPUT", "name is required"));
    }
    let content = body(defined(input.get("content")).or_else(|| previous_member("content")))?;
    let url: Option<Value> = match input.get("url") {
        None => previous_member("url").cloned(),
        Some(value) if truthy(Some(value)) => Some(Value::String(text(Some(value), "url", 2048)?)),
        Some(_) => None,
    };
    if let Some(url) = &url {
        // `/^https?:\/\//.test(url)`: a stored non-string value never matches.
        let valid = url
            .as_str()
            .is_some_and(|url| url.starts_with("http://") || url.starts_with("https://"));
        if !valid {
            return Err(IamError::new("INVALID_INPUT", "url must be an http(s) URL"));
        }
    }
    let required = defined(input.get("required"))
        .or_else(|| defined(previous_member("required")))
        .cloned()
        .unwrap_or(Value::Bool(true));
    if !required.is_boolean() {
        return Err(IamError::new("INVALID_INPUT", "required must be a boolean"));
    }
    let reaccept: Option<Value> = match input.get("reacceptAfterDays") {
        None => previous_member("reacceptAfterDays").cloned(),
        Some(Value::Null) => None,
        Some(value) => Some(crate::js::number(integer(
            Some(value),
            "reacceptAfterDays",
            1.0,
            3650.0,
        )?)),
    };
    let mut values = Map::new();
    values.insert(
        "uniqueKey".into(),
        Value::String(format!("name:{}", core_js::to_lower(&name))),
    );
    values.insert("name".into(), Value::String(name));
    values.insert("content".into(), Value::String(content));
    if let Some(url) = url.filter(|url| truthy(Some(url))) {
        values.insert("url".into(), url);
    }
    values.insert("required".into(), required);
    if let Some(reaccept) = reaccept {
        values.insert("reacceptAfterDays".into(), reaccept);
    }
    Ok(values)
}

/// [`save_agreement`] over raw records, so a record written by another implementation keeps its members.
async fn save_agreement_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    input: &Map<String, Value>,
    previous: Option<&Record>,
    new_version: bool,
) -> IamResult<Record> {
    let values = fields(input, previous)?;
    let previous_id = previous.and_then(|record| str_of(record, "id"));
    let others: Vec<Record> = tx
        .find(
            "agreements",
            &Filter::new().eq("tenantId", tenant_id),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .filter(|agreement| str_of(agreement, "id") != previous_id)
        .collect();
    if others
        .iter()
        .any(|agreement| agreement.get("uniqueKey") == values.get("uniqueKey"))
    {
        return Err(IamError::with_status(
            "CONFLICT",
            "An agreement with this name exists",
            409,
        ));
    }
    let now = ctx.now();
    if let Some(previous) = previous {
        let mut record = previous.clone();
        record.shift_remove("url");
        record.shift_remove("reacceptAfterDays");
        let version = number_of(previous, "version") + if new_version { 1.0 } else { 0.0 };
        for (key, value) in values {
            record.insert(key, value);
        }
        record.insert("version".into(), crate::js::number(version));
        record.insert("updatedAt".into(), crate::js::number(now));
        return tx.put("agreements", &record).await;
    }
    if others.len() >= MAX_AGREEMENTS {
        return Err(IamError::with_status(
            "LIMIT_EXCEEDED",
            format!("At most {MAX_AGREEMENTS} agreements"),
            409,
        ));
    }
    let mut record = values;
    record.insert("id".into(), Value::String(id()));
    record.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    record.insert("version".into(), crate::js::number(1.0));
    record.insert("createdAt".into(), crate::js::number(now));
    record.insert("updatedAt".into(), crate::js::number(now));
    tx.insert("agreements", &record).await
}

/// [`delete_agreement`] for the raw record.
async fn delete_agreement_record(tx: &Store, agreement: &Record) -> IamResult<()> {
    let tenant_id = str_of(agreement, "tenantId").unwrap_or("").to_owned();
    let agreement_id = str_of(agreement, "id").unwrap_or("").to_owned();
    for acceptance in tx
        .find(
            "agreementAcceptances",
            &Filter::new()
                .eq("tenantId", tenant_id)
                .eq("agreementId", agreement_id.clone()),
            &FindOptions::default(),
        )
        .await?
    {
        tx.delete(
            "agreementAcceptances",
            str_of(&acceptance, "id").unwrap_or(""),
        )
        .await?;
    }
    tx.delete("agreements", &agreement_id).await
}

/// The `agreements` API group (`createAgreementsApi(ctx)`): one method per route `agreements/{method}`.
pub struct AgreementsApi {
    ctx: Arc<ServerContext>,
}

/// `createAgreementsApi(ctx)`.
pub fn create_agreements_api(ctx: &Arc<ServerContext>) -> IamResult<AgreementsApi> {
    Ok(AgreementsApi { ctx: ctx.clone() })
}

impl AgreementsApi {
    /// `agreements/accept`: records that the caller accepts `version` of an agreement (which must be the current
    /// one, so nobody accepts text they were not shown). Impersonating administrators cannot accept on someone's
    /// behalf. Audited as `agreement:accept`.
    pub async fn accept(
        &self,
        credential: &CredentialInput,
        input: Body<agreements::AcceptInput>,
    ) -> IamResult<Reply<agreements::AcceptOutput>> {
        let ctx = self.ctx.clone();
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let agreement_id = text(input.get("agreementId"), "agreementId", 256)?;
        let version = integer(input.get("version"), "version", 1.0, 1_000_000.0)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let store = ctx.store.clone();
        let result = store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                self_session(&principal, &tenant_id)?;
                if impersonating(&principal) {
                    return Err(IamError::with_status(
                        "IMPERSONATION_RESTRICTED",
                        "Agreements cannot be accepted while impersonating",
                        403,
                    ));
                }
                if principal.identity.kind != IdentityKind::User {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "Only people accept agreements",
                    ));
                }
                let agreement: Agreement = ctx
                    .scoped_as(&tx, "agreements", &agreement_id, &tenant_id)
                    .await?;
                if agreement.version != version {
                    return Err(IamError::with_status(
                        "VERSION_CONFLICT",
                        "The agreement changed; review the current version before accepting",
                        409,
                    ));
                }
                let accepted_at = ctx.now();
                let acceptance_id = format!("{}:{}", agreement.id, principal.identity.id);
                let mut acceptance = Map::new();
                acceptance.insert("id".into(), Value::String(acceptance_id.clone()));
                acceptance.insert("tenantId".into(), Value::String(tenant_id.clone()));
                acceptance.insert("agreementId".into(), Value::String(agreement.id.clone()));
                acceptance.insert(
                    "identityId".into(),
                    Value::String(principal.identity.id.clone()),
                );
                acceptance.insert("version".into(), crate::js::number(version));
                acceptance.insert("acceptedAt".into(), crate::js::number(accepted_at));
                if tx
                    .get("agreementAcceptances", &acceptance_id)
                    .await?
                    .is_some()
                {
                    tx.put("agreementAcceptances", &acceptance).await?;
                } else {
                    tx.insert("agreementAcceptances", &acceptance).await?;
                }
                let mut metadata = Map::new();
                metadata.insert("name".into(), Value::String(agreement.name.clone()));
                metadata.insert("version".into(), crate::js::number(version));
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "agreement:accept",
                        &tenant_id,
                        &agreement.id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                Ok(json!({
                    "accepted": true,
                    "version": crate::js::number(version),
                    "acceptedAt": crate::js::number(accepted_at),
                }))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `agreements/create`: publishes a new agreement at version 1 (required by default).
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<agreements::CreateInput>,
    ) -> IamResult<Reply<agreements::CreateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let saved = save_agreement_record(ctx, &tx, &tenant.id, body, None, false).await?;
                Ok(Value::Object(saved))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:agreements:manage",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `agreements/delete`: deletes an agreement and its acceptances.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<agreements::DeleteInput>,
    ) -> IamResult<Reply<agreements::DeleteOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("agreementId"), "agreementId", 256)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let agreement = ctx
                    .scoped(&tx, "agreements", body.get("agreementId"), &tenant.id)
                    .await?;
                delete_agreement_record(&tx, &agreement).await?;
                Ok(json!({ "deleted": true }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:agreements:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `agreements/list`: the tenant's agreements by name.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<agreements::ListInput>,
    ) -> IamResult<Reply<agreements::ListOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let mut list = tx
                    .find(
                        "agreements",
                        &Filter::new().eq("tenantId", tenant.id.clone()),
                        &FindOptions::default(),
                    )
                    .await?;
                list.sort_by(|a, b| {
                    locale_compare(
                        str_of(a, "name").unwrap_or(""),
                        str_of(b, "name").unwrap_or(""),
                    )
                });
                Ok(Value::Array(list.into_iter().map(Value::Object).collect()))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:agreements:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `agreements/listMine`: the caller's agreements with their acceptance state; needs only an ordinary session of
    /// the tenant.
    pub async fn list_mine(
        &self,
        credential: &CredentialInput,
        input: Body<agreements::ListMineInput>,
    ) -> IamResult<Reply<agreements::ListMineOutput>> {
        let ctx = self.ctx.clone();
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let store = ctx.store.clone();
        let result = store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                self_session(&principal, &tenant_id)?;
                let mut acceptances: IndexMap<String, AgreementAcceptance> = IndexMap::new();
                for record in tx
                    .find(
                        "agreementAcceptances",
                        &Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("identityId", principal.identity.id.clone()),
                        &FindOptions::default(),
                    )
                    .await?
                {
                    let acceptance: AgreementAcceptance = decode(record)?;
                    acceptances.insert(acceptance.agreement_id.clone(), acceptance);
                }
                let now = ctx.now();
                let mut mine: Vec<(bool, bool, String, Value)> = Vec::new();
                for record in tx
                    .find(
                        "agreements",
                        &Filter::new().eq("tenantId", tenant_id.clone()),
                        &FindOptions::default(),
                    )
                    .await?
                {
                    let agreement: Agreement = decode(record)?;
                    let acceptance = acceptances.get(&agreement.id);
                    let accepted = acceptance_current(&agreement, acceptance, now);
                    let mut entry = Map::new();
                    entry.insert("id".into(), Value::String(agreement.id.clone()));
                    entry.insert("name".into(), Value::String(agreement.name.clone()));
                    entry.insert("content".into(), Value::String(agreement.content.clone()));
                    if let Some(url) = agreement.url.as_ref().filter(|url| !url.is_empty()) {
                        entry.insert("url".into(), Value::String(url.clone()));
                    }
                    entry.insert("version".into(), crate::js::number(agreement.version));
                    entry.insert("required".into(), Value::Bool(agreement.required));
                    entry.insert("accepted".into(), Value::Bool(accepted));
                    if let Some(acceptance) = acceptance {
                        entry.insert(
                            "acceptedAt".into(),
                            crate::js::number(acceptance.accepted_at),
                        );
                        entry.insert(
                            "acceptedVersion".into(),
                            crate::js::number(acceptance.version),
                        );
                    }
                    mine.push((
                        accepted,
                        agreement.required,
                        agreement.name.clone(),
                        Value::Object(entry),
                    ));
                }
                // Unaccepted first, then required before optional, then by name.
                mine.sort_by(|a, b| {
                    a.0.cmp(&b.0)
                        .then_with(|| b.1.cmp(&a.1))
                        .then_with(|| locale_compare(&a.2, &b.2))
                });
                Ok(Value::Array(
                    mine.into_iter().map(|(_, _, _, entry)| entry).collect(),
                ))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `agreements/status`: who accepted the current version and which active people still owe it.
    pub async fn status(
        &self,
        credential: &CredentialInput,
        input: Body<agreements::StatusInput>,
    ) -> IamResult<Reply<agreements::StatusOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("agreementId"), "agreementId", 256)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let agreement: Agreement = decode(
                    ctx.scoped(&tx, "agreements", body.get("agreementId"), &tenant.id)
                        .await?,
                )?;
                let mut acceptances: IndexMap<String, AgreementAcceptance> = IndexMap::new();
                for record in tx
                    .find(
                        "agreementAcceptances",
                        &Filter::new()
                            .eq("tenantId", tenant.id.clone())
                            .eq("agreementId", agreement.id.clone()),
                        &FindOptions::default(),
                    )
                    .await?
                {
                    let acceptance: AgreementAcceptance = decode(record)?;
                    acceptances.insert(acceptance.identity_id.clone(), acceptance);
                }
                let now = ctx.now();
                let mut accepted: Vec<Value> = Vec::new();
                let mut pending: Vec<Value> = Vec::new();
                // `identity.email ?? identity.name`.
                let display = |identity: &Record| -> String {
                    match identity.get("email") {
                        Some(Value::String(email)) => email.clone(),
                        _ => str_of(identity, "name").unwrap_or("").to_owned(),
                    }
                };
                let mut people: Vec<Record> = tx
                    .find(
                        "identities",
                        &Filter::new().eq("tenantId", tenant.id.clone()),
                        &FindOptions::default(),
                    )
                    .await?
                    .into_iter()
                    .filter(|identity| {
                        str_of(identity, "kind") == Some("user")
                            && str_of(identity, "status") == Some("active")
                    })
                    .collect();
                people.sort_by(|a, b| locale_compare(&display(a), &display(b)));
                for identity in &people {
                    let identity_id = str_of(identity, "id").unwrap_or("").to_owned();
                    let reference = json!({ "id": identity_id, "name": display(identity) });
                    match acceptances.get(&identity_id) {
                        Some(acceptance)
                            if acceptance_current(&agreement, Some(acceptance), now) =>
                        {
                            accepted.push(json!({
                                "identity": reference,
                                "version": crate::js::number(acceptance.version),
                                "acceptedAt": crate::js::number(acceptance.accepted_at),
                            }));
                        }
                        acceptance => {
                            let mut entry = Map::new();
                            entry.insert("identity".into(), reference);
                            if let Some(acceptance) = acceptance {
                                entry.insert(
                                    "acceptedVersion".into(),
                                    crate::js::number(acceptance.version),
                                );
                            }
                            pending.push(Value::Object(entry));
                        }
                    }
                }
                Ok(json!({
                    "agreement": {
                        "id": agreement.id,
                        "name": agreement.name,
                        "version": crate::js::number(agreement.version),
                        "required": agreement.required,
                    },
                    "accepted": accepted,
                    "pending": pending,
                }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:agreements:read",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `agreements/update`: edits an agreement. `newVersion: true` publishes the change as the next version, so
    /// everyone must accept again; without it the edit (a typo fix, a new link) keeps existing acceptances valid.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<agreements::UpdateInput>,
    ) -> IamResult<Reply<agreements::UpdateOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("agreementId"), "agreementId", 256)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let previous = ctx
                    .scoped(&tx, "agreements", body.get("agreementId"), &tenant.id)
                    .await?;
                let new_version = body.get("newVersion") == Some(&Value::Bool(true));
                let saved =
                    save_agreement_record(ctx, &tx, &tenant.id, body, Some(&previous), new_version)
                        .await?;
                Ok(Value::Object(saved))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:agreements:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// Deletes an agreement with every acceptance of it.
pub async fn delete_agreement(
    tx: &Store,
    agreement: &crate::agreements::Agreement,
) -> IamResult<()> {
    delete_agreement_record(tx, &crate::port::encode(agreement)).await
}

/// Publishes (without `previous`) or edits an agreement after validating it; `newVersion` asks everyone to accept
/// again. Shared by the `agreements` API and configuration apply. `input` is the `AgreementInput` object (other
/// members are ignored; `reacceptAfterDays: null` removes the re-acceptance period).
pub async fn save_agreement(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    input: &Value,
    previous: Option<&crate::agreements::Agreement>,
    new_version: Option<bool>,
) -> IamResult<crate::agreements::Agreement> {
    let empty = Map::new();
    let input = match input {
        Value::Object(map) => map,
        _ => &empty,
    };
    let previous = previous.map(crate::port::encode);
    let saved = save_agreement_record(
        ctx,
        tx,
        tenant_id,
        input,
        previous.as_ref(),
        new_version.unwrap_or(false),
    )
    .await?;
    decode(saved)
}
