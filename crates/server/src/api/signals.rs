//! Port of `packages/server/src/api/signals.ts`: the `signals` group, the tenant's Shared Signals sources (upstream
//! identity providers that send CAEP and RISC security events about its people) and the events they sent. Reading
//! needs `iam:signals:read`, everything else `iam:signals:manage` on `iam/signals/sources[/{id}]` or
//! `iam/signals/events[/{id}]`; changes need recent authentication. Events arrive through the push endpoint or
//! `iam.signals.poll()`, never through this group.

use std::sync::Arc;

use better_iam_core::{
    AuditOutcome, CredentialInput, Direction, Filter, FindOptions, IamError, IamResult,
    OrderOptions, Record, find_ordered, js as core_js, parse_subject_identifier, record_id,
    signal_event_uris,
};
use better_iam_types::api::signals;
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::hosts::url_origin;
use crate::js::number;
use crate::safe_fetch::{SafeFetchAddressOptions, SafeFetchFailureReason, check_fetch_url};
use crate::signal_receiver::{
    DEFAULT_SIGNAL_ALGORITHMS, EVENTS_COLLECTION, MAX_SIGNAL_SOURCES_PER_TENANT,
    SOURCES_COLLECTION, SignalInput, apply_signal, record_signal_received, seal_poll_token,
    signal_receiver_of,
};
use crate::utils::{hash, id, token};
use crate::validation::{integer, text};
use crate::web_identity::{
    IssuerRules, web_identity_algorithms, web_identity_audiences, web_identity_issuer,
    web_identity_keys,
};

fn source_resource(source_id: &str) -> String {
    format!("signals/sources/{source_id}")
}

fn event_resource(event_id: &str) -> String {
    format!("signals/events/{event_id}")
}

const STATUSES: [&str; 5] = ["applied", "recorded", "unmatched", "ignored", "failed"];
const SOURCE_STATUSES: [&str; 2] = ["active", "disabled"];
const ACTION_VALUES: [&str; 2] = ["record", "revoke-sessions"];
const UPDATABLE_FIELDS: [&str; 12] = [
    "name",
    "issuerAliases",
    "audiences",
    "jwksUri",
    "jwks",
    "algorithms",
    "poll",
    "subjects",
    "actions",
    "requireTyp",
    "tenantClaim",
    "status",
];

fn known_event_type(value: &str) -> bool {
    value == "unknown" || signal_event_uris().iter().any(|(name, _)| *name == value)
}

fn actionable_event(value: &str) -> bool {
    value != "verification"
        && value != "stream-updated"
        && signal_event_uris().iter().any(|(name, _)| *name == value)
}

/// Printable ASCII without spaces: what a bearer token may contain.
fn bearer_token(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| (b'!'..=b'~').contains(&b))
}

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

fn boolean_value(value: &Value, name: &str) -> IamResult<bool> {
    value
        .as_bool()
        .ok_or_else(|| invalid(format!("{name} must be a boolean")))
}

/// The source's natural key within its tenant, `issuer:{issuer}`; an issuer too long for the 512-byte key limit is
/// keyed by its SHA-256 instead.
fn issuer_key(issuer: &str) -> String {
    let key = format!("issuer:{issuer}");
    if key.len() <= 512 {
        key
    } else {
        format!("issuer#sha256:{}", hash(issuer))
    }
}

fn identifier_list(value: &Value, name: &str) -> IamResult<Vec<String>> {
    let Value::Array(items) = value else {
        return Err(invalid(format!("{name} must list at most 10 ids")));
    };
    if items.len() > 10 {
        return Err(invalid(format!("{name} must list at most 10 ids")));
    }
    let mut trimmed = Vec::with_capacity(items.len());
    for entry in items {
        trimmed.push(core_js::trim(&text(Some(entry), name, 128)?).to_owned());
    }
    Ok(crate::js::unique(trimmed))
}

fn string_list(value: Option<&Value>) -> Vec<Value> {
    match value {
        Some(Value::Array(items)) => items.clone(),
        _ => Vec::new(),
    }
}

fn subjects_value(value: Option<&Value>, current: Option<&Value>) -> IamResult<Value> {
    let mut connection_ids: Vec<Value> = Vec::new();
    let mut match_email = Value::Bool(false);
    let mut scim_connection_ids: Vec<Value> = Vec::new();
    if let Some(current) = current {
        connection_ids = string_list(current.get("connectionIds"));
        match_email = current.get("matchEmail").cloned().unwrap_or(Value::Null);
        scim_connection_ids = string_list(current.get("scimConnectionIds"));
    }
    let base = |connection_ids: Vec<Value>, match_email: Value, scim: Vec<Value>| {
        json!({
            "connectionIds": connection_ids,
            "matchEmail": match_email,
            "scimConnectionIds": scim,
        })
    };
    let Some(value) = value else {
        return Ok(base(connection_ids, match_email, scim_connection_ids));
    };
    let Value::Object(input) = value else {
        return Err(invalid("subjects must be an object"));
    };
    for key in core_js::keys(input) {
        if !["connectionIds", "matchEmail", "scimConnectionIds"].contains(&key.as_str()) {
            return Err(invalid(format!("Unknown subjects member {key}")));
        }
    }
    if let Some(value) = input.get("connectionIds") {
        connection_ids = identifier_list(value, "subjects.connectionIds")?
            .into_iter()
            .map(Value::String)
            .collect();
    }
    if let Some(value) = input.get("scimConnectionIds") {
        scim_connection_ids = identifier_list(value, "subjects.scimConnectionIds")?
            .into_iter()
            .map(Value::String)
            .collect();
    }
    if let Some(value) = input.get("matchEmail") {
        match_email = Value::Bool(boolean_value(value, "subjects.matchEmail")?);
    }
    Ok(base(connection_ids, match_email, scim_connection_ids))
}

fn actions_value(value: &Value) -> IamResult<Value> {
    let Value::Object(input) = value else {
        return Err(invalid(
            "actions must map event types to record or revoke-sessions",
        ));
    };
    let mut result = Map::new();
    for (kind, action) in core_js::entries(input) {
        if !actionable_event(kind) {
            return Err(invalid(format!(
                "actions names an unsupported event type: {kind}"
            )));
        }
        if !action
            .as_str()
            .is_some_and(|action| ACTION_VALUES.contains(&action))
        {
            return Err(invalid(format!(
                "The action for {kind} must be record or revoke-sessions"
            )));
        }
        result.insert(kind.clone(), action.clone());
    }
    Ok(Value::Object(result))
}

/// The `signals` view of a source: an explicit allowlist without the token hash and the sealed poll token.
fn public_signal_source(ctx: &ServerContext, source: &Record) -> Value {
    let member = |key: &str| source.get(key).cloned().unwrap_or(Value::Null);
    let subjects = source.get("subjects");
    let subject_member = |key: &str| {
        subjects
            .and_then(|subjects| subjects.get(key))
            .cloned()
            .unwrap_or(Value::Null)
    };
    let mut view = Map::new();
    for key in [
        "id",
        "tenantId",
        "name",
        "issuer",
        "issuerAliases",
        "audiences",
        "algorithms",
        "delivery",
    ] {
        view.insert(key.into(), member(key));
    }
    view.insert(
        "hasPushToken".into(),
        Value::Bool(source.contains_key("pushTokenHash")),
    );
    view.insert(
        "subjects".into(),
        json!({
            "connectionIds": subject_member("connectionIds"),
            "matchEmail": subject_member("matchEmail") == Value::Bool(true),
            "scimConnectionIds": subject_member("scimConnectionIds"),
        }),
    );
    view.insert(
        "actions".into(),
        match source.get("actions") {
            Some(Value::Object(actions)) => Value::Object(actions.clone()),
            _ => json!({}),
        },
    );
    view.insert(
        "requireTyp".into(),
        Value::Bool(source.get("requireTyp") != Some(&Value::Bool(false))),
    );
    for key in ["status", "createdAt", "createdBy", "updatedAt", "updatedBy"] {
        view.insert(key.into(), member(key));
    }
    if source.get("delivery").and_then(Value::as_str) == Some("push") {
        view.insert(
            "pushUrl".into(),
            Value::String(format!(
                "{}{}/{}",
                url_origin(&ctx.config.base_url),
                ctx.config.signals.push_path,
                record_id(source)
            )),
        );
    }
    for key in ["jwksUri", "jwks", "tenantClaim"] {
        if let Some(value) = source.get(key) {
            view.insert(key.into(), value.clone());
        }
    }
    if let Some(poll) = source
        .get("poll")
        .filter(|poll| crate::js::truthy(Some(poll)))
    {
        let mut state = Map::new();
        state.insert(
            "endpoint".into(),
            poll.get("endpoint").cloned().unwrap_or(Value::Null),
        );
        state.insert(
            "maxEvents".into(),
            poll.get("maxEvents").cloned().unwrap_or(Value::Null),
        );
        state.insert(
            "pendingAcks".into(),
            number(match poll.get("pendingAcks") {
                Some(Value::Array(acks)) => acks.len() as f64,
                _ => 0.0,
            }),
        );
        if let Some(last) = poll.get("lastPolledAt") {
            state.insert("lastPolledAt".into(), last.clone());
        }
        view.insert("poll".into(), Value::Object(state));
    }
    for key in ["lastEventAt", "lastError", "lastVerifiedAt"] {
        if let Some(value) = source.get(key) {
            view.insert(key.into(), value.clone());
        }
    }
    Value::Object(view)
}

fn public_signal_event(record: &Record) -> Value {
    let mut view = Map::new();
    for key in [
        "id",
        "tenantId",
        "sourceId",
        "jti",
        "eventType",
        "eventUri",
        "issuedAt",
        "status",
        "claims",
        "receivedAt",
        "expiresAt",
    ] {
        view.insert(key.into(), record.get(key).cloned().unwrap_or(Value::Null));
    }
    for key in [
        "eventTimestamp",
        "txn",
        "subject",
        "identityId",
        "reason",
        "reprocessedAt",
        "reprocessedBy",
    ] {
        if let Some(value) = record.get(key) {
            view.insert(key.into(), value.clone());
        }
    }
    Value::Object(view)
}

/// The `signals` API group (`createSignalsApi(ctx)`): one method per route `signals/{method}`.
pub struct SignalsApi {
    ctx: Arc<ServerContext>,
}

/// `createSignalsApi(ctx)`.
pub fn create_signals_api(ctx: &Arc<ServerContext>) -> IamResult<SignalsApi> {
    Ok(SignalsApi { ctx: ctx.clone() })
}

impl SignalsApi {
    fn address_rules(&self) -> SafeFetchAddressOptions {
        let settings = &self.ctx.config.signals;
        SafeFetchAddressOptions {
            any_port: true,
            allow_private_networks: settings.allow_private_networks,
            allow_insecure_localhost: settings.allow_insecure_localhost,
        }
    }

    /// An issuer: https (loopback http in development), no credentials, query or fragment; trailing slashes dropped.
    fn issuer_value(&self, value: Option<&Value>) -> IamResult<String> {
        let issuer = web_identity_issuer(
            value,
            &IssuerRules {
                allow_insecure_localhost: self.ctx.config.signals.allow_insecure_localhost,
                ..IssuerRules::default()
            },
        )?;
        Ok(issuer.trim_end_matches('/').to_owned())
    }

    fn aliases_value(&self, value: &Value, issuer: &str) -> IamResult<Vec<String>> {
        let items = match value {
            Value::Array(items) if items.len() <= 5 => items,
            _ => return Err(invalid("issuerAliases must list at most 5 issuers")),
        };
        let mut aliases = Vec::with_capacity(items.len());
        for alias in items {
            match self.issuer_value(Some(alias)) {
                Ok(alias) => aliases.push(alias),
                Err(error) => return Err(invalid(format!("issuerAliases: {}", error.message))),
            }
        }
        Ok(crate::js::unique(aliases)
            .into_iter()
            .filter(|alias| alias != issuer)
            .collect())
    }

    /// A URL the receiver fetches: https on any port (loopback http in development) and a public address.
    fn url_value(&self, value: Option<&Value>, name: &str) -> IamResult<String> {
        let raw = text(value, name, 2048)?;
        if let Err(error) = check_fetch_url(&raw, &self.address_rules()) {
            if error.reason == SafeFetchFailureReason::Address {
                return Err(invalid(format!(
                    "{name} must not point at a private address"
                )));
            }
            return Err(invalid(format!(
                "{name} must be an https URL without credentials or a fragment"
            )));
        }
        Ok(raw)
    }

    fn poll_token_value(value: Option<&Value>) -> IamResult<String> {
        match value {
            Some(Value::String(token))
                if !token.is_empty()
                    && core_js::utf16_len(token) <= 4096
                    && bearer_token(token) =>
            {
                Ok(token.clone())
            }
            _ => Err(invalid(
                "poll.token must be 1 to 4096 printable characters without spaces",
            )),
        }
    }

    fn max_events_value(value: &Value) -> IamResult<f64> {
        integer(Some(value), "poll.maxEvents", 1.0, 100.0)
    }

    fn poll_object(value: &Value) -> IamResult<&Map<String, Value>> {
        let Value::Object(map) = value else {
            return Err(invalid(
                "poll must be an object with endpoint, token and maxEvents",
            ));
        };
        for key in core_js::keys(map) {
            if !["endpoint", "token", "maxEvents"].contains(&key.as_str()) {
                return Err(invalid(format!("Unknown poll member {key}")));
            }
        }
        Ok(map)
    }

    /// A source of this tenant, else NOT_FOUND.
    async fn scoped_source(
        &self,
        tx: &Store,
        tenant_id: &str,
        source_id: &str,
    ) -> IamResult<Record> {
        self.ctx
            .scoped(
                tx,
                SOURCES_COLLECTION,
                Some(&Value::String(source_id.to_owned())),
                tenant_id,
            )
            .await
    }

    fn forget(&self, source_id: &str) -> IamResult<()> {
        signal_receiver_of(&self.ctx)?.forget(source_id);
        Ok(())
    }

    /// `signals/createSource`: registers a transmitter (iam:signals:manage on iam/signals/sources, recent
    /// authentication), at most 20 per tenant and one per issuer (CONFLICT). Push sources get a push URL and, unless
    /// `pushToken: false`, a bearer token returned only here; poll sources store their poll token sealed. Static keys
    /// must be public signature keys; URLs must be https and public (see the `signals` deployment option). Nothing is
    /// fetched now. Audited as `signal:source-create`.
    pub async fn create_source(
        &self,
        credential: &CredentialInput,
        input: Body<signals::CreateSourceInput>,
    ) -> IamResult<Reply<signals::CreateSourceOutput>> {
        let ctx = &self.ctx;
        let name = core_js::trim(&text(input.get("name"), "name", 128)?).to_owned();
        let issuer = self.issuer_value(input.get("issuer"))?;
        let issuer_aliases = match input.get("issuerAliases") {
            None => Vec::new(),
            Some(value) => self.aliases_value(value, &issuer)?,
        };
        let audiences = web_identity_audiences(input.get("audiences"))?;
        let jwks_uri = match input.get("jwksUri") {
            None => None,
            Some(value) => Some(self.url_value(Some(value), "jwksUri")?),
        };
        let jwks = match input.get("jwks") {
            None => None,
            Some(value) => Some(web_identity_keys(Some(value))?),
        };
        if jwks_uri.is_some() && jwks.is_some() {
            return Err(invalid("Give jwks or jwksUri, not both"));
        }
        let algorithms = match input.get("algorithms") {
            None => DEFAULT_SIGNAL_ALGORITHMS
                .iter()
                .map(|alg| (*alg).to_owned())
                .collect(),
            Some(value) => web_identity_algorithms(Some(value))?,
        };
        let delivery = match input.get("delivery").and_then(Value::as_str) {
            Some(delivery @ ("push" | "poll")) => delivery.to_owned(),
            _ => return Err(invalid("delivery must be push or poll")),
        };
        let wants_push_token = match input.get("pushToken") {
            None => delivery == "push",
            Some(value) => boolean_value(value, "pushToken")?,
        };
        if delivery == "poll" && wants_push_token {
            return Err(invalid(
                "Poll sources receive no pushes, so they take no push token",
            ));
        }
        let mut poll: Option<(String, String, f64)> = None;
        if delivery == "poll" {
            let Some(given) = input.get("poll") else {
                return Err(invalid("Poll sources need poll.endpoint and poll.token"));
            };
            let given = Self::poll_object(given)?;
            let endpoint = self.url_value(given.get("endpoint"), "poll.endpoint")?;
            let token = Self::poll_token_value(given.get("token"))?;
            let max_events = match given.get("maxEvents") {
                None => 25.0,
                Some(value) => Self::max_events_value(value)?,
            };
            poll = Some((endpoint, token, max_events));
        } else if input.get("poll").is_some() {
            return Err(invalid("Only poll sources take poll settings"));
        }
        let subjects = subjects_value(input.get("subjects"), None)?;
        let actions = match input.get("actions") {
            None => json!({}),
            Some(value) => actions_value(value)?,
        };
        let require_typ = match input.get("requireTyp") {
            None => true,
            Some(value) => boolean_value(value, "requireTyp")?,
        };
        let tenant_claim = match input.get("tenantClaim") {
            None => None,
            Some(value) => Some(core_js::trim(&text(Some(value), "tenantClaim", 256)?).to_owned()),
        };
        let tenant_id = string_member(&input, "tenantId");
        let tenant_ref = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let existing = tx
                    .find(
                        SOURCES_COLLECTION,
                        &Filter::new().eq("tenantId", tenant_ref.clone()),
                        &FindOptions::default(),
                    )
                    .await?;
                if existing.len() as f64 >= MAX_SIGNAL_SOURCES_PER_TENANT {
                    return Err(IamError::with_status(
                        "LIMIT_EXCEEDED",
                        format!(
                            "A tenant may register at most {} signal sources",
                            core_js::number_to_string(MAX_SIGNAL_SOURCES_PER_TENANT)
                        ),
                        409,
                    )
                    .into());
                }
                let unique_key = issuer_key(&issuer);
                if existing.iter().any(|source| {
                    source.get("uniqueKey").and_then(Value::as_str) == Some(&unique_key)
                }) {
                    return Err(IamError::with_status(
                        "CONFLICT",
                        "A signal source for this issuer already exists",
                        409,
                    )
                    .into());
                }
                let now = ctx.now();
                let source_id = id();
                let push_token = wants_push_token.then(token);
                let mut source = Record::new();
                source.insert("id".into(), Value::String(source_id.clone()));
                source.insert("tenantId".into(), Value::String(tenant_ref.clone()));
                source.insert("uniqueKey".into(), Value::String(unique_key));
                source.insert("name".into(), Value::String(name.clone()));
                source.insert("issuer".into(), Value::String(issuer.clone()));
                source.insert("issuerAliases".into(), json!(issuer_aliases));
                source.insert("audiences".into(), json!(audiences));
                if let Some(jwks_uri) = &jwks_uri {
                    source.insert("jwksUri".into(), Value::String(jwks_uri.clone()));
                }
                if let Some(jwks) = &jwks {
                    source.insert("jwks".into(), jwks.clone());
                }
                source.insert("algorithms".into(), json!(algorithms));
                source.insert("delivery".into(), Value::String(delivery.clone()));
                if let Some(push_token) = &push_token {
                    source.insert("pushTokenHash".into(), Value::String(hash(push_token)));
                }
                if let Some((endpoint, poll_token, max_events)) = &poll {
                    source.insert(
                        "poll".into(),
                        json!({
                            "endpoint": endpoint,
                            "tokenSealed": seal_poll_token(ctx, &source_id, poll_token)?,
                            "maxEvents": number(*max_events),
                            "pendingAcks": [],
                        }),
                    );
                }
                source.insert("subjects".into(), subjects.clone());
                source.insert("actions".into(), actions.clone());
                source.insert("requireTyp".into(), Value::Bool(require_typ));
                if let Some(tenant_claim) = &tenant_claim {
                    source.insert("tenantClaim".into(), Value::String(tenant_claim.clone()));
                }
                source.insert("status".into(), Value::String("active".into()));
                source.insert("createdAt".into(), number(now));
                source.insert(
                    "createdBy".into(),
                    Value::String(principal.identity.id.clone()),
                );
                source.insert("updatedAt".into(), number(now));
                source.insert(
                    "updatedBy".into(),
                    Value::String(principal.identity.id.clone()),
                );
                tx.insert(SOURCES_COLLECTION, &source).await?;
                let mut metadata = Map::new();
                metadata.insert("name".into(), Value::String(name.clone()));
                metadata.insert("issuer".into(), Value::String(issuer.clone()));
                metadata.insert("delivery".into(), Value::String(delivery.clone()));
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "signal:source-create",
                        tenant_ref,
                        &source_resource(&source_id),
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                let view = public_signal_source(ctx, &source);
                let mut result = Map::new();
                let push_url = view.get("pushUrl").cloned();
                result.insert("source".into(), view);
                if let Some(push_url) = push_url {
                    result.insert("pushUrl".into(), push_url);
                }
                if let Some(push_token) = push_token {
                    result.insert("pushToken".into(), Value::String(push_token));
                }
                Ok(Value::Object(result))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:signals:manage",
                "signals/sources",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `signals/deleteSource`: deletes a source (iam:signals:manage on iam/signals/sources/{id}, recent
    /// authentication). Its pushes answer 404 from now on; the events it sent stay until the retention sweep removes
    /// them. Audited as `signal:source-delete`.
    pub async fn delete_source(
        &self,
        credential: &CredentialInput,
        input: Body<signals::DeleteSourceInput>,
    ) -> IamResult<Reply<signals::DeleteSourceOutput>> {
        let ctx = &self.ctx;
        let source_id = text(input.get("sourceId"), "sourceId", 256)?;
        let tenant_id = string_member(&input, "tenantId");
        let (source_ref, tenant_ref) = (&source_id, &tenant_id);
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let source = self.scoped_source(&tx, tenant_ref, source_ref).await?;
                tx.delete(SOURCES_COLLECTION, record_id(&source)).await?;
                let mut metadata = Map::new();
                metadata.insert(
                    "name".into(),
                    source.get("name").cloned().unwrap_or(Value::Null),
                );
                metadata.insert(
                    "issuer".into(),
                    source.get("issuer").cloned().unwrap_or(Value::Null),
                );
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "signal:source-delete",
                        tenant_ref,
                        &source_resource(record_id(&source)),
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                Ok(json!({ "deleted": true }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:signals:manage",
                &source_resource(&source_id),
                mutation,
                false,
            )
            .await?;
        self.forget(&source_id)?;
        Ok(Reply::json(result))
    }

    /// `signals/getEvent`: one received event (iam:signals:read on iam/signals/events/{id}).
    pub async fn get_event(
        &self,
        credential: &CredentialInput,
        input: Body<signals::GetEventInput>,
    ) -> IamResult<Reply<signals::GetEventOutput>> {
        let ctx = &self.ctx;
        let event_id = text(input.get("eventId"), "eventId", 256)?;
        let tenant_id = string_member(&input, "tenantId");
        let (event_ref, tenant_ref) = (&event_id, &tenant_id);
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let record = ctx
                    .scoped(
                        &tx,
                        EVENTS_COLLECTION,
                        Some(&Value::String(event_ref.clone())),
                        tenant_ref,
                    )
                    .await?;
                Ok(public_signal_event(&record))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:signals:read",
                &event_resource(&event_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `signals/getSource`: one signal source (iam:signals:read on iam/signals/sources/{id}).
    pub async fn get_source(
        &self,
        credential: &CredentialInput,
        input: Body<signals::GetSourceInput>,
    ) -> IamResult<Reply<signals::GetSourceOutput>> {
        let ctx = &self.ctx;
        let source_id = text(input.get("sourceId"), "sourceId", 256)?;
        let tenant_id = string_member(&input, "tenantId");
        let (source_ref, tenant_ref) = (&source_id, &tenant_id);
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let source = self.scoped_source(&tx, tenant_ref, source_ref).await?;
                Ok(public_signal_source(ctx, &source))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:signals:read",
                &source_resource(&source_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `signals/listEvents`: received events, newest first, optionally of one source, status, identity or event type
    /// (iam:signals:read on iam/signals/events). `limit` 1..1000 (default 100), `offset` from 0.
    pub async fn list_events(
        &self,
        credential: &CredentialInput,
        input: Body<signals::ListEventsInput>,
    ) -> IamResult<Reply<signals::ListEventsOutput>> {
        let ctx = &self.ctx;
        let defaulted = |key: &str, fallback: f64| match input.get(key) {
            None | Some(Value::Null) => number(fallback),
            Some(value) => value.clone(),
        };
        let limit = integer(Some(&defaulted("limit", 100.0)), "limit", 1.0, 1000.0)?;
        let offset = integer(Some(&defaulted("offset", 0.0)), "offset", 0.0, 1_000_000.0)?;
        let source_id = match input.get("sourceId") {
            None => None,
            Some(value) => Some(text(Some(value), "sourceId", 256)?),
        };
        let identity_id = match input.get("identityId") {
            None => None,
            Some(value) => Some(text(Some(value), "identityId", 256)?),
        };
        let status = input.get("status").cloned();
        if let Some(status) = &status
            && !status
                .as_str()
                .is_some_and(|status| STATUSES.contains(&status))
        {
            return Err(invalid(
                "status must be applied, recorded, unmatched, ignored or failed",
            ));
        }
        let event_type = input.get("eventType").cloned();
        if let Some(event_type) = &event_type
            && !event_type.as_str().is_some_and(known_event_type)
        {
            return Err(invalid("Unknown eventType"));
        }
        let tenant_id = string_member(&input, "tenantId");
        let tenant_ref = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let mut filter = Filter::new().eq("tenantId", tenant_ref.clone());
                if let Some(source_id) = &source_id {
                    filter = filter.eq("streamId", source_id.clone());
                }
                if let Some(status) = &status {
                    filter = filter.eq("status", status.clone());
                }
                if let Some(identity_id) = &identity_id {
                    filter = filter.eq("identityId", identity_id.clone());
                }
                if let Some(event_type) = &event_type {
                    filter = filter.eq("eventType", event_type.clone());
                }
                let events = find_ordered(
                    tx.as_ref(),
                    EVENTS_COLLECTION,
                    &filter,
                    &OrderOptions {
                        direction: Direction::Desc,
                        ..OrderOptions::by("timestamp")
                    },
                    None,
                )
                .await?;
                let total = events.len();
                let page: Vec<Value> = events
                    .iter()
                    .skip(offset as usize)
                    .take(limit as usize)
                    .map(public_signal_event)
                    .collect();
                Ok(json!({ "events": page, "total": number(total as f64) }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:signals:read",
                "signals/events",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `signals/listSources`: the tenant's signal sources, oldest first (iam:signals:read on iam/signals/sources).
    pub async fn list_sources(
        &self,
        credential: &CredentialInput,
        input: Body<signals::ListSourcesInput>,
    ) -> IamResult<Reply<signals::ListSourcesOutput>> {
        let ctx = &self.ctx;
        let tenant_id = string_member(&input, "tenantId");
        let tenant_ref = &tenant_id;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let mut sources = tx
                    .find(
                        SOURCES_COLLECTION,
                        &Filter::new().eq("tenantId", tenant_ref.clone()),
                        &FindOptions::default(),
                    )
                    .await?;
                let created = |source: &Record| {
                    source
                        .get("createdAt")
                        .map(core_js::to_number)
                        .unwrap_or(f64::NAN)
                };
                sources.sort_by(|a, b| {
                    let delta = created(a) - created(b);
                    if delta != 0.0 && !delta.is_nan() {
                        return delta.partial_cmp(&0.0).unwrap_or(std::cmp::Ordering::Equal);
                    }
                    core_js::cmp_utf16(record_id(a), record_id(b))
                });
                Ok(Value::Array(
                    sources
                        .iter()
                        .map(|source| public_signal_source(ctx, source))
                        .collect(),
                ))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:signals:read",
                "signals/sources",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `signals/poll`: polls one poll source now (iam:signals:manage on iam/signals/sources/{id}), as the scheduled
    /// `iam.signals.poll()` does: the permission and the source are checked first, then the transmitter is called
    /// outside any transaction. INVALID_INPUT for a push source, INVALID_TRANSITION for a disabled one.
    pub async fn poll(
        &self,
        credential: &CredentialInput,
        input: Body<signals::PollInput>,
    ) -> IamResult<Reply<signals::PollOutput>> {
        let ctx = &self.ctx;
        let source_id = text(input.get("sourceId"), "sourceId", 256)?;
        let tenant_id = string_member(&input, "tenantId");
        let (source_ref, tenant_ref) = (&source_id, &tenant_id);
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let source = self.scoped_source(&tx, tenant_ref, source_ref).await?;
                if source.get("delivery").and_then(Value::as_str) != Some("poll") {
                    return Err(invalid("This source receives its events by push").into());
                }
                if source.get("status").and_then(Value::as_str) != Some("active") {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "The source is disabled",
                        409,
                    )
                    .into());
                }
                Ok(Value::Null)
            })
        });
        ctx.operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:signals:manage",
                &source_resource(&source_id),
                mutation,
                false,
            )
            .await?;
        let result = signal_receiver_of(ctx)?
            .poll(ctx, Some(&Value::String(source_id.clone())))
            .await?;
        Ok(Reply::json(result.to_value()))
    }

    /// `signals/reprocess`: maps and applies an `unmatched` or `failed` event again, after the source's mapping or
    /// the directory changed (iam:signals:manage on iam/signals/events/{id}, recent authentication;
    /// INVALID_TRANSITION for other statuses or a disabled source, NOT_FOUND when the source is gone). The configured
    /// action runs as on receipt; an event that now matches someone is audited as `signal:received` again for threat
    /// detection. Audited as `signal:reprocess`.
    pub async fn reprocess(
        &self,
        credential: &CredentialInput,
        input: Body<signals::ReprocessInput>,
    ) -> IamResult<Reply<signals::ReprocessOutput>> {
        let ctx = &self.ctx;
        let event_id = text(input.get("eventId"), "eventId", 256)?;
        let tenant_id = string_member(&input, "tenantId");
        let (event_ref, tenant_ref) = (&event_id, &tenant_id);
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let record = ctx
                    .scoped(
                        &tx,
                        EVENTS_COLLECTION,
                        Some(&Value::String(event_ref.clone())),
                        tenant_ref,
                    )
                    .await?;
                let previous_status = record.get("status").cloned().unwrap_or(Value::Null);
                if !matches!(previous_status.as_str(), Some("unmatched" | "failed")) {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "Only unmatched and failed events can be reprocessed",
                        409,
                    )
                    .into());
                }
                let source = match record.get("sourceId").and_then(Value::as_str) {
                    Some(source_id) => tx.get(SOURCES_COLLECTION, source_id).await?,
                    None => None,
                };
                let Some(source) = source.filter(|source| {
                    source.get("tenantId").and_then(Value::as_str) == Some(tenant_ref.as_str())
                }) else {
                    return Err(IamError::with_status(
                        "NOT_FOUND",
                        "The source of this event no longer exists",
                        404,
                    )
                    .into());
                };
                if source.get("status").and_then(Value::as_str) != Some("active") {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "The source of this event is disabled",
                        409,
                    )
                    .into());
                }
                let subject = record
                    .get("subject")
                    .filter(|subject| crate::js::truthy(Some(subject)))
                    .and_then(parse_subject_identifier);
                let claims = match record.get("claims") {
                    Some(Value::Object(claims)) => claims.clone(),
                    _ => Map::new(),
                };
                let jti = record
                    .get("jti")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let outcome = apply_signal(
                    ctx,
                    &tx,
                    &source,
                    &SignalInput {
                        event_type: record
                            .get("eventType")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                        subject,
                        event: claims.clone(),
                        jti,
                    },
                )
                .await?;
                let mut next = record.clone();
                next.shift_remove("identityId");
                next.shift_remove("reason");
                next.insert("status".into(), Value::String(outcome.status.to_owned()));
                if let Some(identity_id) = outcome
                    .identity_id
                    .as_ref()
                    .filter(|identity_id| !identity_id.is_empty())
                {
                    next.insert("identityId".into(), Value::String(identity_id.clone()));
                }
                if let Some(reason) = outcome.reason {
                    next.insert("reason".into(), Value::String(reason.to_owned()));
                }
                next.insert("reprocessedAt".into(), number(ctx.now()));
                next.insert(
                    "reprocessedBy".into(),
                    Value::String(principal.identity.id.clone()),
                );
                let stored = tx.put(EVENTS_COLLECTION, &next).await?;
                if outcome.source_changed {
                    tx.put(SOURCES_COLLECTION, &outcome.source).await?;
                }
                let stored_identity = stored
                    .get("identityId")
                    .and_then(Value::as_str)
                    .filter(|identity_id| !identity_id.is_empty())
                    .map(str::to_owned);
                if stored_identity.is_some() {
                    record_signal_received(ctx, &tx, &source, &stored, &claims).await?;
                }
                let mut metadata = Map::new();
                metadata.insert(
                    "sourceId".into(),
                    Value::String(record_id(&source).to_owned()),
                );
                metadata.insert(
                    "eventType".into(),
                    record.get("eventType").cloned().unwrap_or(Value::Null),
                );
                metadata.insert(
                    "jti".into(),
                    record.get("jti").cloned().unwrap_or(Value::Null),
                );
                metadata.insert("previousStatus".into(), previous_status);
                metadata.insert(
                    "status".into(),
                    stored.get("status").cloned().unwrap_or(Value::Null),
                );
                if let Some(identity_id) = stored_identity {
                    metadata.insert("identityId".into(), Value::String(identity_id));
                }
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "signal:reprocess",
                        tenant_ref,
                        &event_resource(record_id(&record)),
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                Ok(public_signal_event(&stored))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:signals:manage",
                &event_resource(&event_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `signals/rotatePushToken`: replaces a push source's bearer token (iam:signals:manage on
    /// iam/signals/sources/{id}, recent authentication) and returns the new one, shown only here; the old one stops
    /// working at once. Also gives a push source created without a token one. Audited as `signal:source-rotate`.
    pub async fn rotate_push_token(
        &self,
        credential: &CredentialInput,
        input: Body<signals::RotatePushTokenInput>,
    ) -> IamResult<Reply<signals::RotatePushTokenOutput>> {
        let ctx = &self.ctx;
        let source_id = text(input.get("sourceId"), "sourceId", 256)?;
        let tenant_id = string_member(&input, "tenantId");
        let (source_ref, tenant_ref) = (&source_id, &tenant_id);
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let source = self.scoped_source(&tx, tenant_ref, source_ref).await?;
                if source.get("delivery").and_then(Value::as_str) != Some("push") {
                    return Err(invalid("Only push sources have a push token").into());
                }
                let push_token = token();
                let mut next = source.clone();
                next.insert("pushTokenHash".into(), Value::String(hash(&push_token)));
                next.insert("updatedAt".into(), number(ctx.now()));
                next.insert(
                    "updatedBy".into(),
                    Value::String(principal.identity.id.clone()),
                );
                tx.put(SOURCES_COLLECTION, &next).await?;
                let mut metadata = Map::new();
                metadata.insert(
                    "replaced".into(),
                    Value::Bool(source.contains_key("pushTokenHash")),
                );
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "signal:source-rotate",
                        tenant_ref,
                        &source_resource(record_id(&source)),
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                Ok(json!({ "pushToken": push_token }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:signals:manage",
                &source_resource(&source_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `signals/updateSource`: changes a source (iam:signals:manage on iam/signals/sources/{id}, recent
    /// authentication): names, aliases, audiences, keys (`null` clears `jwksUri` or `jwks`; without either, keys are
    /// discovered), algorithms, poll settings (a new endpoint needs its token again and starts with no pending
    /// acknowledgements), subject mapping, actions, `requireTyp` and `status` (a disabled source's pushes answer 404
    /// and it is not polled). The issuer and delivery cannot change. Cached keys are dropped. An update that changes
    /// nothing is INVALID_INPUT. Audited as `signal:source-update` with the changed fields.
    pub async fn update_source(
        &self,
        credential: &CredentialInput,
        input: Body<signals::UpdateSourceInput>,
    ) -> IamResult<Reply<signals::UpdateSourceOutput>> {
        let ctx = &self.ctx;
        if input.get("issuer").is_some() {
            return Err(invalid("The issuer of a source cannot change"));
        }
        if input.get("delivery").is_some() {
            return Err(invalid("The delivery of a source cannot change"));
        }
        if input.get("pushToken").is_some() {
            return Err(invalid("Use rotatePushToken to change the push token"));
        }
        let source_id = text(input.get("sourceId"), "sourceId", 256)?;
        if !UPDATABLE_FIELDS
            .iter()
            .any(|field| input.get(*field).is_some())
        {
            return Err(invalid("The update changes nothing"));
        }
        if let Some(status) = input.get("status")
            && !status
                .as_str()
                .is_some_and(|status| SOURCE_STATUSES.contains(&status))
        {
            return Err(invalid("status must be active or disabled"));
        }
        let tenant_id = string_member(&input, "tenantId");
        let (source_ref, tenant_ref) = (&source_id, &tenant_id);
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let source = self.scoped_source(&tx, tenant_ref, source_ref).await?;
                let mut next = source.clone();
                if let Some(name) = body.get("name") {
                    next.insert(
                        "name".into(),
                        Value::String(core_js::trim(&text(Some(name), "name", 128)?).to_owned()),
                    );
                }
                if let Some(aliases) = body.get("issuerAliases") {
                    let issuer = source
                        .get("issuer")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    next.insert(
                        "issuerAliases".into(),
                        json!(self.aliases_value(aliases, issuer)?),
                    );
                }
                if let Some(audiences) = body.get("audiences") {
                    next.insert(
                        "audiences".into(),
                        json!(web_identity_audiences(Some(audiences))?),
                    );
                }
                match body.get("jwksUri") {
                    Some(Value::Null) => {
                        next.shift_remove("jwksUri");
                    }
                    Some(value) => {
                        next.insert(
                            "jwksUri".into(),
                            Value::String(self.url_value(Some(value), "jwksUri")?),
                        );
                    }
                    None => {}
                }
                match body.get("jwks") {
                    Some(Value::Null) => {
                        next.shift_remove("jwks");
                    }
                    Some(value) => {
                        next.insert("jwks".into(), web_identity_keys(Some(value))?);
                    }
                    None => {}
                }
                if next.contains_key("jwksUri") && next.contains_key("jwks") {
                    return Err(invalid("Give jwks or jwksUri, not both").into());
                }
                if let Some(algorithms) = body.get("algorithms") {
                    next.insert(
                        "algorithms".into(),
                        json!(web_identity_algorithms(Some(algorithms))?),
                    );
                }
                if let Some(poll) = body.get("poll") {
                    let current = source
                        .get("poll")
                        .filter(|poll| crate::js::truthy(Some(poll)));
                    let current = match (source.get("delivery").and_then(Value::as_str), current) {
                        (Some("poll"), Some(Value::Object(current))) => current,
                        _ => return Err(invalid("Only poll sources take poll settings").into()),
                    };
                    let poll = Self::poll_object(poll)?;
                    let mut state = current.clone();
                    state.insert(
                        "pendingAcks".into(),
                        current.get("pendingAcks").cloned().unwrap_or(Value::Null),
                    );
                    if let Some(endpoint) = poll.get("endpoint") {
                        let endpoint = self.url_value(Some(endpoint), "poll.endpoint")?;
                        if current.get("endpoint").and_then(Value::as_str) != Some(&endpoint) {
                            // The stored token was given for the old endpoint only; the new one's queue starts fresh.
                            if !poll.contains_key("token") {
                                return Err(
                                    invalid("A new poll endpoint needs its token again").into()
                                );
                            }
                            state.insert("endpoint".into(), Value::String(endpoint));
                            state.insert("pendingAcks".into(), json!([]));
                            state.shift_remove("pendingErrors");
                        }
                    }
                    if let Some(poll_token) = poll.get("token") {
                        let poll_token = Self::poll_token_value(Some(poll_token))?;
                        state.insert(
                            "tokenSealed".into(),
                            Value::String(seal_poll_token(ctx, record_id(&source), &poll_token)?),
                        );
                    }
                    if let Some(max_events) = poll.get("maxEvents") {
                        state.insert(
                            "maxEvents".into(),
                            number(Self::max_events_value(max_events)?),
                        );
                    }
                    next.insert("poll".into(), Value::Object(state));
                }
                if let Some(subjects) = body.get("subjects") {
                    next.insert(
                        "subjects".into(),
                        subjects_value(Some(subjects), source.get("subjects"))?,
                    );
                }
                if let Some(actions) = body.get("actions") {
                    next.insert("actions".into(), actions_value(actions)?);
                }
                if let Some(require_typ) = body.get("requireTyp") {
                    next.insert(
                        "requireTyp".into(),
                        Value::Bool(boolean_value(require_typ, "requireTyp")?),
                    );
                }
                match body.get("tenantClaim") {
                    Some(Value::Null) => {
                        next.shift_remove("tenantClaim");
                    }
                    Some(value) => {
                        next.insert(
                            "tenantClaim".into(),
                            Value::String(
                                core_js::trim(&text(Some(value), "tenantClaim", 256)?).to_owned(),
                            ),
                        );
                    }
                    None => {}
                }
                if let Some(status) = body.get("status") {
                    next.insert("status".into(), status.clone());
                }
                let stringified = |record: &Record, field: &str| {
                    core_js::stringify(record.get(field).unwrap_or(&Value::Null))
                };
                let changed: Vec<Value> = UPDATABLE_FIELDS
                    .iter()
                    .filter(|field| stringified(&source, field) != stringified(&next, field))
                    .map(|field| Value::String((*field).to_owned()))
                    .collect();
                if changed.is_empty() {
                    return Err(invalid("The update changes nothing").into());
                }
                next.insert("updatedAt".into(), number(ctx.now()));
                next.insert(
                    "updatedBy".into(),
                    Value::String(principal.identity.id.clone()),
                );
                let stored = tx.put(SOURCES_COLLECTION, &next).await?;
                let mut metadata = Map::new();
                metadata.insert("changed".into(), Value::Array(changed));
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "signal:source-update",
                        tenant_ref,
                        &source_resource(record_id(&source)),
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                Ok(public_signal_source(ctx, &stored))
            })
        });
        let updated = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:signals:manage",
                &source_resource(&source_id),
                mutation,
                false,
            )
            .await?;
        if let Some(updated_id) = updated.get("id").and_then(Value::as_str) {
            self.forget(updated_id)?;
        }
        Ok(Reply::json(updated))
    }
}
