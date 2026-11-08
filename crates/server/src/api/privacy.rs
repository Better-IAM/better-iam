//! Port of `packages/server/src/api/privacy.ts`: privacy and consent management. Processing purposes with their
//! lawful basis, each person's consent (recorded by the person, by an administrator, or by the application for its
//! own customers), signed consent receipts and an append-only history, data-subject requests (access, portability,
//! erasure, rectification, restriction, objection, opt-out) with statutory deadlines and automated fulfilment, legal
//! holds, and restriction of processing. Policies see `principal.consents`. Managing purposes and settings needs
//! `iam:privacy:manage`; reading consents, requests and reports `iam:privacy:read`; recording consents for
//! application subjects `iam:privacy:record`; checking them `iam:privacy:check`; handling requests
//! `iam:privacy:handle`. People manage their own choices without a permission.

use std::cmp::Ordering;
use std::sync::Arc;

use better_iam_auth::outbox::EnqueueInput;
use better_iam_auth::service::LimitAttemptOptions;
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, IamStoreExt, Identity, IdentityKind, OutboxKind, Record, SessionClientInfo,
    SessionKind, Tenant, TenantStatus, canonical_json, js as core_js,
};
use better_iam_types::api::privacy;
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};

use crate::api::identities::delete_identity;
use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{BindingVia, Mutation, MutationContext, OperationDenied, OperationResult};
use crate::js::{defined, internal_error, invalid_input, js_string, number, truthy};
use crate::metrics::locale_compare;
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::port::{decode, encode};
use crate::privacy::{
    ConsentReceipt, DAY_MS, LEGAL_BASES, PrivacyConsent, PrivacyConsentEvent, PrivacyPurpose,
    PrivacySettings, REGULATION_DEADLINES, REJECTION_REASONS, ResolvedSubject,
    SUBJECT_REQUEST_TYPES, SubjectRequest, active_hold, consent_state, consents_of, days,
    decidable, email_subject, external_subject_id, identity_subject, one_of, privacy_settings,
    prose, purpose_key, receipt_from_event, receipt_signature_valid, regulations, request_number,
    request_overdue, resolve_subject, response_window, restriction_of, restriction_state,
};
use crate::session_kinds::acts_in_own_right;
use crate::utils::{hash, id, public_identity_record, same_hash, token};
use crate::validation::{email, integer, object, strings, text};

const MAX_PURPOSES: usize = 200;
const MAX_EVENTS: usize = 100;
const VERIFICATION_LIFETIME_MS: f64 = 7.0 * DAY_MS;

// ── Small helpers ────────────────────────────────────────────────────────────────────────────────────────────────

fn str_of<'a>(record: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

fn s<'a>(record: &'a Map<String, Value>, key: &str) -> &'a str {
    str_of(record, key).unwrap_or("")
}

fn num_of(record: &Map<String, Value>, key: &str) -> Option<f64> {
    record.get(key).and_then(core_js::as_number)
}

/// `record.key` as a number, NaN when it is not one (arithmetic on `undefined` in JavaScript).
fn nan_of(record: &Map<String, Value>, key: &str) -> f64 {
    num_of(record, key).unwrap_or(f64::NAN)
}

fn copy_member(out: &mut Map<String, Value>, from: &Map<String, Value>, key: &str) {
    if let Some(value) = from.get(key) {
        out.insert(key.to_owned(), value.clone());
    }
}

fn str_values(values: &[&str]) -> Vec<Value> {
    values
        .iter()
        .map(|value| Value::String((*value).to_owned()))
        .collect()
}

fn string(value: impl Into<String>) -> Value {
    Value::String(value.into())
}

/// `new Date(ms).toISOString()`; a date outside the JavaScript range throws (a RangeError, not an IamError).
fn iso(ms: f64) -> IamResult<String> {
    core_js::iso_string(ms).ok_or_else(internal_error)
}

/// The sign of a numeric comparator result; NaN counts as equal (`NaN || next` falls through in JavaScript).
fn order(diff: f64) -> Ordering {
    if diff < 0.0 {
        Ordering::Less
    } else if diff > 0.0 {
        Ordering::Greater
    } else {
        Ordering::Equal
    }
}

/// `a.id < b.id ? -1 : 1` for distinct IDs.
fn by_id(a: &Map<String, Value>, b: &Map<String, Value>) -> Ordering {
    core_js::cmp_utf16(s(a, "id"), s(b, "id"))
}

/// `items.slice(offset, offset + limit)` for validated integers.
fn page<T: Clone>(items: &[T], offset: f64, limit: f64) -> Vec<T> {
    let start = (offset as usize).min(items.len());
    let end = ((offset + limit) as usize).min(items.len());
    items[start..end.max(start)].to_vec()
}

/// `value.slice(0, max)` in UTF-16 code units.
fn utf16_prefix(value: &str, max: usize) -> String {
    if core_js::utf16_len(value) <= max {
        return value.to_owned();
    }
    let units: Vec<u16> = value.encode_utf16().take(max).collect();
    String::from_utf16_lossy(&units)
}

async fn find(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

fn decode_all<T: serde::de::DeserializeOwned>(records: Vec<Record>) -> IamResult<Vec<T>> {
    records.into_iter().map(decode).collect()
}

fn decidable_purpose(purpose: &PrivacyPurpose) -> IamResult<bool> {
    decidable(&Value::Object(encode(purpose)))
}

fn state_of(
    purpose: &PrivacyPurpose,
    consent: Option<&PrivacyConsent>,
    restricted: &Value,
    now: f64,
) -> IamResult<Map<String, Value>> {
    Ok(encode(&consent_state(purpose, consent, restricted, now)?))
}

fn audit_metadata(entries: Vec<(&str, Value)>) -> Option<Map<String, Value>> {
    Some(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
}

// ── Validation helpers ───────────────────────────────────────────────────────────────────────────────────────────

/// `value === undefined || value === null || value === ''`.
fn blank(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => true,
        Some(Value::String(text)) => text.is_empty(),
        _ => false,
    }
}

/// Methods and evidence recorded with a decision: short labels and free text.
fn method_label(value: Option<&Value>) -> IamResult<Option<String>> {
    if blank(value) {
        return Ok(None);
    }
    let result = text(value, "method", 64)?;
    // `/^[\w .:/-]+$/`
    if result.is_empty()
        || !result
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | ' ' | '.' | ':' | '/' | '-'))
    {
        return Err(invalid_input("Invalid method"));
    }
    Ok(Some(result))
}

fn evidence(value: Option<&Value>) -> IamResult<Option<String>> {
    if blank(value) {
        return Ok(None);
    }
    Ok(Some(prose(value, "evidence", 2000.0)?))
}

fn categories(value: Option<&Value>) -> IamResult<Vec<String>> {
    if value.is_none() {
        return Ok(Vec::new());
    }
    let mut list = crate::js::unique(strings(value, "dataCategories")?);
    let valid = |item: &String| {
        let mut chars = item.chars();
        let first = chars.next();
        first.is_some_and(|c| c.is_ascii_lowercase())
            && core_js::utf16_len(item) <= 64
            && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
    };
    if list.len() > 32 || list.iter().any(|item| !valid(item)) {
        return Err(invalid_input(
            "dataCategories must hold at most 32 lowercase identifiers such as contact or usage",
        ));
    }
    crate::js::sort_strings(&mut list);
    Ok(list)
}

/// Privacy self-service is the person's own business: refused for role sessions, delegated agents and other tenants.
fn self_session(principal: &AuthenticatedPrincipal, tenant_id: &str) -> IamResult<()> {
    if !acts_in_own_right(principal.session.kind)
        || principal.session.kind != SessionKind::User
        || principal.session.tenant_id != tenant_id
        || principal.identity.tenant_id != tenant_id
        || principal.identity.kind != IdentityKind::User
    {
        return Err(IamError::with_status(
            "ACCESS_DENIED",
            "Privacy choices are made by the person, from a signed-in session of their organization",
            403,
        ));
    }
    if impersonating(principal) {
        return Err(IamError::with_status(
            "IMPERSONATION_RESTRICTED",
            "Privacy choices cannot be made while impersonating",
            403,
        ));
    }
    Ok(())
}

/// `principal.session.impersonatorId` is set (truthy).
fn impersonating(principal: &AuthenticatedPrincipal) -> bool {
    principal
        .session
        .impersonator_id
        .as_deref()
        .is_some_and(|id| !id.is_empty())
}

/// `purposeFields(input, previous)`: the validated members of a purpose, in the order TypeScript builds them.
fn purpose_fields(input: &Map<String, Value>, previous: Option<&Record>) -> IamResult<Record> {
    let prev = |key: &str| previous.and_then(|record| record.get(key));
    let key = match previous {
        Some(record) => js_string(record.get("key")),
        None => purpose_key(input.get("key"))?,
    };
    if let (Some(previous), Some(given)) = (previous, input.get("key"))
        && Some(given) != previous.get("key")
    {
        return Err(invalid_input(
            "A purpose key cannot change; create a new purpose",
        ));
    }
    let name = core_js::trim(&text(
        defined(input.get("name")).or_else(|| prev("name")),
        "name",
        120,
    )?)
    .to_owned();
    let description = prose(
        defined(input.get("description")).or_else(|| prev("description")),
        "description",
        5000.0,
    )?;
    let legal_basis = one_of(
        defined(input.get("legalBasis")).or_else(|| prev("legalBasis")),
        &str_values(LEGAL_BASES),
        "legalBasis",
    )?;
    let opt_in = string("opt-in");
    let mode = one_of(
        Some(
            defined(input.get("mode"))
                .or_else(|| defined(prev("mode")))
                .unwrap_or(&opt_in),
        ),
        &str_values(&["opt-in", "opt-out"]),
        "mode",
    )?;
    let consent_basis = legal_basis.as_str() == Some("consent");
    if mode.as_str() == Some("opt-out") && !consent_basis {
        return Err(invalid_input("Only consent purposes can be opt-out"));
    }
    let retention: Option<Value> = match input.get("retentionDays") {
        None => prev("retentionDays").cloned(),
        Some(Value::Null) => None,
        Some(value) => Some(number(days(Some(value), "retentionDays", Some(36500.0))?)),
    };
    let lifetime: Option<Value> = match input.get("consentLifetimeDays") {
        None => prev("consentLifetimeDays").cloned(),
        Some(Value::Null) => None,
        Some(value) => Some(number(days(Some(value), "consentLifetimeDays", None)?)),
    };
    if lifetime.is_some() && !consent_basis {
        return Err(invalid_input(
            "consentLifetimeDays applies to consent purposes only",
        ));
    }
    let reconsent = defined(input.get("reconsentOnVersion"))
        .or_else(|| defined(prev("reconsentOnVersion")))
        .cloned()
        .unwrap_or(Value::Bool(true));
    if !reconsent.is_boolean() {
        return Err(invalid_input("reconsentOnVersion must be a boolean"));
    }
    let data_categories = match input.get("dataCategories") {
        None => defined(prev("dataCategories"))
            .cloned()
            .unwrap_or_else(|| json!([])),
        Some(value) => Value::Array(
            categories(Some(value))?
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    };
    let mut values = Record::new();
    values.insert("uniqueKey".into(), string(format!("key:{key}")));
    values.insert("key".into(), string(key));
    values.insert("name".into(), string(name));
    values.insert("description".into(), string(description));
    values.insert("legalBasis".into(), legal_basis);
    values.insert("mode".into(), mode);
    values.insert("dataCategories".into(), data_categories);
    if let Some(retention) = retention {
        values.insert("retentionDays".into(), retention);
    }
    if let Some(lifetime) = lifetime {
        values.insert("consentLifetimeDays".into(), lifetime);
    }
    values.insert("reconsentOnVersion".into(), reconsent);
    Ok(values)
}

async fn purpose_record_by_key(
    tx: &Store,
    tenant_id: &str,
    key: Option<&Value>,
) -> IamResult<Record> {
    let unique_key = format!("key:{}", purpose_key(key)?);
    find(
        tx,
        "privacyPurposes",
        Filter::new()
            .eq("tenantId", tenant_id.to_owned())
            .eq("uniqueKey", unique_key),
    )
    .await?
    .into_iter()
    .next()
    .ok_or_else(|| IamError::with_status("NOT_FOUND", "Purpose not found", 404))
}

async fn purpose_by_key(
    tx: &Store,
    tenant_id: &str,
    key: Option<&Value>,
) -> IamResult<PrivacyPurpose> {
    decode(purpose_record_by_key(tx, tenant_id, key).await?)
}

/// The current decision of a subject on a purpose (uniqueKey `{purposeId}:{subject}`).
async fn consent_for(
    tx: &Store,
    tenant_id: &str,
    unique_key: String,
) -> IamResult<Option<PrivacyConsent>> {
    find(
        tx,
        "privacyConsents",
        Filter::new()
            .eq("tenantId", tenant_id.to_owned())
            .eq("uniqueKey", unique_key),
    )
    .await?
    .into_iter()
    .next()
    .map(decode)
    .transpose()
}

fn consent_summary(consent: &PrivacyConsent) -> Value {
    let mut out = Map::new();
    out.insert("granted".into(), Value::Bool(consent.granted));
    out.insert("purposeVersion".into(), number(consent.purpose_version));
    out.insert("recordedAt".into(), number(consent.recorded_at));
    if let Some(expires_at) = consent.expires_at {
        out.insert("expiresAt".into(), number(expires_at));
    }
    out.insert("receiptId".into(), string(consent.receipt_id.clone()));
    Value::Object(out)
}

fn consent_view(
    consent: &PrivacyConsent,
    purpose: &PrivacyPurpose,
    restricted: bool,
    now: f64,
) -> IamResult<Value> {
    let mut out = Map::new();
    out.insert("id".into(), string(consent.id.clone()));
    out.insert("purposeKey".into(), string(consent.purpose_key.clone()));
    out.insert("subject".into(), string(consent.subject.clone()));
    if let Some(identity_id) = consent.identity_id.as_ref().filter(|id| !id.is_empty()) {
        out.insert("identityId".into(), string(identity_id.clone()));
    }
    if let Some(external_id) = &consent.external_id {
        out.insert("externalId".into(), string(external_id.clone()));
    }
    out.insert("granted".into(), Value::Bool(consent.granted));
    out.insert("purposeVersion".into(), number(consent.purpose_version));
    out.insert("source".into(), consent.source.clone());
    if let Some(method) = consent.method.as_ref().filter(|method| !method.is_empty()) {
        out.insert("method".into(), string(method.clone()));
    }
    out.insert("recordedAt".into(), number(consent.recorded_at));
    out.insert("recordedBy".into(), string(consent.recorded_by.clone()));
    if let Some(expires_at) = consent.expires_at {
        out.insert("expiresAt".into(), number(expires_at));
    }
    out.insert("receiptId".into(), string(consent.receipt_id.clone()));
    out.insert(
        "state".into(),
        Value::Object(state_of(
            purpose,
            Some(consent),
            &Value::Bool(restricted),
            now,
        )?),
    );
    Ok(Value::Object(out))
}

fn non_empty(value: &Option<String>) -> Option<&String> {
    value.as_ref().filter(|value| !value.is_empty())
}

fn history_entry(event: &PrivacyConsentEvent) -> Value {
    let mut out = Map::new();
    out.insert("receiptId".into(), string(event.receipt_id.clone()));
    out.insert("purposeKey".into(), string(event.purpose_key.clone()));
    out.insert("purposeVersion".into(), number(event.purpose_version));
    out.insert("subject".into(), string(event.subject.clone()));
    out.insert("granted".into(), Value::Bool(event.granted));
    out.insert("source".into(), event.source.clone());
    if let Some(method) = non_empty(&event.method) {
        out.insert("method".into(), string(method.clone()));
    }
    if let Some(evidence) = non_empty(&event.evidence) {
        out.insert("evidence".into(), string(evidence.clone()));
    }
    if let Some(ip) = non_empty(&event.ip) {
        out.insert("ip".into(), string(ip.clone()));
    }
    if let Some(user_agent) = non_empty(&event.user_agent) {
        out.insert("userAgent".into(), string(user_agent.clone()));
    }
    out.insert("recordedAt".into(), number(event.recorded_at));
    out.insert("recordedBy".into(), string(event.recorded_by.clone()));
    if event.redacted == Some(true) {
        out.insert("redacted".into(), Value::Bool(true));
    }
    Value::Object(out)
}

/// The history of events newest first (`b.recordedAt - a.recordedAt || (a.id < b.id ? -1 : 1)`), at most `max`.
fn newest_events(mut events: Vec<PrivacyConsentEvent>, key: Option<&str>, max: usize) -> Value {
    events.retain(|event| key.is_none_or(|key| event.purpose_key == key));
    events.sort_by(|a, b| {
        order(b.recorded_at - a.recorded_at).then_with(|| core_js::cmp_utf16(&a.id, &b.id))
    });
    Value::Array(events.iter().take(max).map(history_entry).collect())
}

fn request_view(
    request: &Record,
    now: f64,
    subject_name: Option<&str>,
) -> IamResult<Map<String, Value>> {
    let typed: SubjectRequest = decode(request.clone())?;
    let mut out = Map::new();
    for key in [
        "id",
        "tenantId",
        "number",
        "type",
        "regulation",
        "status",
        "subject",
    ] {
        copy_member(&mut out, request, key);
    }
    if truthy(request.get("identityId")) {
        copy_member(&mut out, request, "identityId");
    }
    copy_member(&mut out, request, "externalId");
    if let Some(name) = subject_name.filter(|name| !name.is_empty()) {
        out.insert("subjectName".into(), string(name));
    }
    for key in ["requesterEmail", "requesterName", "details"] {
        if truthy(request.get(key)) {
            copy_member(&mut out, request, key);
        }
    }
    if request
        .get("purposeKeys")
        .and_then(Value::as_array)
        .is_some_and(|keys| !keys.is_empty())
    {
        copy_member(&mut out, request, "purposeKeys");
    }
    for key in ["channel", "verification", "submittedAt"] {
        copy_member(&mut out, request, key);
    }
    for key in ["receivedAt", "dueAt", "extendedAt"] {
        copy_member(&mut out, request, key);
    }
    for key in ["extensionReason", "assigneeId"] {
        if truthy(request.get(key)) {
            copy_member(&mut out, request, key);
        }
    }
    copy_member(&mut out, request, "closedAt");
    for key in ["closedBy", "rejectionReason"] {
        if truthy(request.get(key)) {
            copy_member(&mut out, request, key);
        }
    }
    if request
        .get("actions")
        .and_then(Value::as_array)
        .is_some_and(|actions| !actions.is_empty())
    {
        copy_member(&mut out, request, "actions");
    }
    if truthy(request.get("exportId")) {
        copy_member(&mut out, request, "exportId");
    }
    if truthy(request.get("redacted")) {
        out.insert("redacted".into(), Value::Bool(true));
    }
    out.insert("overdue".into(), Value::Bool(request_overdue(&typed, now)?));
    copy_member(&mut out, request, "events");
    Ok(out)
}

/// The subject's own view: staff notes and assignment stay internal.
fn mine_view(request: &Record, now: f64) -> IamResult<Value> {
    let mut view = request_view(request, now, None)?;
    view.shift_remove("assigneeId");
    view.shift_remove("closedBy");
    let events: Vec<Value> = view
        .get("events")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|event| {
            let what = crate::js::member(Some(event), "what");
            what != Some(&string("note")) && what != Some(&string("assigned"))
        })
        .map(|event| {
            let Value::Object(mut event) = event else {
                return event;
            };
            let note = event.shift_remove("note");
            event.shift_remove("by");
            let what = s(&event, "what").to_owned();
            event.insert("by".into(), string("organization"));
            if matches!(what.as_str(), "rejected" | "extended" | "completed")
                && truthy(note.as_ref())
            {
                event.insert("note".into(), note.unwrap_or(Value::Null));
            }
            Value::Object(event)
        })
        .collect();
    if view.contains_key("events") {
        view.insert("events".into(), Value::Array(events));
    }
    Ok(Value::Object(view))
}

/// `[...request.events, event].slice(-maxEvents)`.
fn push_event(request: &Record, event: Map<String, Value>) -> Value {
    let mut events = request
        .get("events")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    events.push(Value::Object(event));
    let skip = events.len().saturating_sub(MAX_EVENTS);
    Value::Array(events.into_iter().skip(skip).collect())
}

fn event_of(at: f64, by: &str, what: &str, note: Option<String>) -> Map<String, Value> {
    let mut event = Map::new();
    event.insert("at".into(), number(at));
    event.insert("by".into(), string(by));
    event.insert("what".into(), string(what));
    if let Some(note) = note {
        event.insert("note".into(), string(note));
    }
    event
}

/// Whether an email delivery callback exists; privacy emails are optional niceties otherwise.
fn can_email(ctx: &ServerContext) -> bool {
    ctx.options
        .authentication
        .as_ref()
        .is_some_and(|authentication| authentication.send_email.is_some())
}

async fn enqueue_email(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
    to: String,
    template: &str,
    payload: Map<String, Value>,
) -> IamResult<()> {
    ctx.auth
        .enqueue_delivery(
            tx,
            EnqueueInput {
                tenant_id: tenant_id.to_owned(),
                kind: OutboxKind::Email,
                to,
                template: template.to_owned(),
                payload,
                reference: None,
            },
        )
        .await?;
    Ok(())
}

/// Tells the privacy contact about a request that now needs handling.
async fn notify_contact(
    ctx: &ServerContext,
    tx: &Store,
    tenant: &Tenant,
    request: &Record,
) -> IamResult<()> {
    let settings = privacy_settings(tx, &tenant.id).await?;
    let Some(contact) = settings.contact_email.filter(|email| !email.is_empty()) else {
        return Ok(());
    };
    if !can_email(ctx) {
        return Ok(());
    }
    let mut payload = Map::new();
    payload.insert("tenantId".into(), string(tenant.id.clone()));
    payload.insert("tenantName".into(), string(tenant.name.clone()));
    copy_as(&mut payload, "requestId", request, "id");
    copy_member(&mut payload, request, "number");
    copy_member(&mut payload, request, "type");
    copy_member(&mut payload, request, "regulation");
    if request.get("dueAt").is_some() {
        payload.insert("dueAt".into(), string(js_string(request.get("dueAt"))));
    }
    copy_member(&mut payload, request, "channel");
    enqueue_email(
        ctx,
        tx,
        &tenant.id,
        contact,
        "privacy-request-received",
        payload,
    )
    .await
}

fn copy_as(out: &mut Map<String, Value>, key: &str, from: &Map<String, Value>, source: &str) {
    if let Some(value) = from.get(source) {
        out.insert(key.to_owned(), value.clone());
    }
}

/// Where the subject hears back: their account's address, or the requester's.
async fn subject_address(tx: &Store, request: &Record) -> IamResult<Option<String>> {
    if truthy(request.get("identityId"))
        && let Some(identity) = tx.get("identities", s(request, "identityId")).await?
        && truthy(identity.get("email"))
        && s(&identity, "status") != "deleted"
    {
        return Ok(str_of(&identity, "email").map(str::to_owned));
    }
    Ok(str_of(request, "requesterEmail").map(str::to_owned))
}

async fn notify_subject(
    ctx: &ServerContext,
    tx: &Store,
    tenant: &Tenant,
    request: &Record,
    event: &str,
    to: Option<String>,
) -> IamResult<()> {
    let address = match to {
        Some(to) => Some(to),
        None => subject_address(tx, request).await?,
    };
    let Some(address) = address.filter(|address| !address.is_empty()) else {
        return Ok(());
    };
    if !can_email(ctx) {
        return Ok(());
    }
    let mut payload = Map::new();
    payload.insert("tenantId".into(), string(tenant.id.clone()));
    payload.insert("tenantName".into(), string(tenant.name.clone()));
    copy_as(&mut payload, "requestId", request, "id");
    copy_member(&mut payload, request, "number");
    copy_member(&mut payload, request, "type");
    payload.insert("event".into(), string(event));
    if request.get("dueAt").is_some() {
        payload.insert("dueAt".into(), string(js_string(request.get("dueAt"))));
    }
    if event == "rejected" && truthy(request.get("rejectionReason")) {
        copy_as(&mut payload, "reason", request, "rejectionReason");
    }
    if event == "completed" && truthy(request.get("exportId")) {
        payload.insert("exportReady".into(), string("true"));
    }
    if truthy(request.get("identityId")) && event == "completed" && s(request, "type") != "erasure"
    {
        payload.insert("account".into(), string("true"));
    }
    enqueue_email(
        ctx,
        tx,
        &tenant.id,
        address,
        "privacy-request-update",
        payload,
    )
    .await
}

/// `SessionClientInfo` as `writeConsent` reads it.
#[derive(Default)]
struct ClientInfo {
    ip: Option<String>,
    user_agent: Option<String>,
}

impl From<SessionClientInfo> for ClientInfo {
    fn from(client: SessionClientInfo) -> Self {
        Self {
            ip: client.ip,
            user_agent: client.user_agent,
        }
    }
}

/// The input of [`write_consent`].
struct ConsentWrite<'a> {
    tenant_id: &'a str,
    purpose: &'a PrivacyPurpose,
    subject: &'a ResolvedSubject,
    granted: bool,
    source: &'a str,
    method: Option<String>,
    evidence: Option<String>,
    recorded_by: &'a str,
    at: f64,
    version: Option<&'a Value>,
    client: Option<ClientInfo>,
}

/// Records one decision: the current state (unless a newer decision is already recorded, as imports can be older) and
/// an entry in the consent history. Returns the signed receipt and whether the decision is now the current one.
async fn write_consent(
    ctx: &ServerContext,
    tx: &Store,
    input: ConsentWrite<'_>,
) -> IamResult<(ConsentReceipt, bool)> {
    let purpose = input.purpose;
    let subject = input.subject;
    if !decidable_purpose(purpose)? {
        return Err(invalid_input(format!(
            "Purpose {} relies on {}, not on consent",
            purpose.key,
            js_string(Some(&purpose.legal_basis))
        )));
    }
    if purpose.archived && input.granted {
        return Err(IamError::with_status(
            "CONFLICT",
            format!("Purpose {} is archived", purpose.key),
            409,
        ));
    }
    let purpose_version = match input.version {
        None => purpose.version,
        Some(version) => integer(Some(version), "version", 1.0, purpose.version)?,
    };
    let receipt_id = id();
    let expires_at = match purpose.consent_lifetime_days {
        Some(lifetime) if input.granted => Some(input.at + lifetime * DAY_MS),
        _ => None,
    };
    let unique_key = format!("{}:{}", purpose.id, subject.key);
    let existing = find(
        tx,
        "privacyConsents",
        Filter::new()
            .eq("tenantId", input.tenant_id.to_owned())
            .eq("uniqueKey", unique_key.clone()),
    )
    .await?
    .into_iter()
    .next();
    let identity_id = subject.identity_id.as_ref().filter(|id| !id.is_empty());
    let method = input.method.filter(|method| !method.is_empty());
    let mut event = Record::new();
    event.insert("id".into(), string(receipt_id.clone()));
    event.insert("tenantId".into(), string(input.tenant_id));
    event.insert("receiptId".into(), string(receipt_id.clone()));
    event.insert("purposeId".into(), string(purpose.id.clone()));
    event.insert("purposeKey".into(), string(purpose.key.clone()));
    event.insert("purposeName".into(), string(purpose.name.clone()));
    event.insert("legalBasis".into(), purpose.legal_basis.clone());
    event.insert("purposeVersion".into(), number(purpose_version));
    event.insert("subject".into(), string(subject.key.clone()));
    if let Some(identity_id) = identity_id {
        event.insert("identityId".into(), string(identity_id.clone()));
    }
    if let Some(external_id) = &subject.external_id {
        event.insert("externalId".into(), string(external_id.clone()));
    }
    event.insert("granted".into(), Value::Bool(input.granted));
    event.insert("source".into(), string(input.source));
    if let Some(method) = &method {
        event.insert("method".into(), string(method.clone()));
    }
    if let Some(evidence) = input
        .evidence
        .as_ref()
        .filter(|evidence| !evidence.is_empty())
    {
        event.insert("evidence".into(), string(evidence.clone()));
    }
    if let Some(client) = &input.client {
        if let Some(ip) = client.ip.as_ref().filter(|ip| !ip.is_empty()) {
            event.insert("ip".into(), string(ip.clone()));
        }
        if let Some(agent) = client.user_agent.as_ref().filter(|agent| !agent.is_empty()) {
            event.insert("userAgent".into(), string(utf16_prefix(agent, 512)));
        }
    }
    event.insert("recordedAt".into(), number(input.at));
    event.insert("recordedBy".into(), string(input.recorded_by));
    let current = match &existing {
        None => true,
        Some(existing) => num_of(existing, "recordedAt").is_some_and(|at| at <= input.at),
    };
    if current {
        let mut record = Record::new();
        record.insert(
            "id".into(),
            existing
                .as_ref()
                .and_then(|existing| defined(existing.get("id")).cloned())
                .unwrap_or_else(|| string(id())),
        );
        record.insert("tenantId".into(), string(input.tenant_id));
        record.insert("uniqueKey".into(), string(unique_key));
        record.insert("purposeId".into(), string(purpose.id.clone()));
        record.insert("purposeKey".into(), string(purpose.key.clone()));
        record.insert("subject".into(), string(subject.key.clone()));
        if let Some(identity_id) = identity_id {
            record.insert("identityId".into(), string(identity_id.clone()));
        }
        if let Some(external_id) = &subject.external_id {
            record.insert("externalId".into(), string(external_id.clone()));
        }
        record.insert("granted".into(), Value::Bool(input.granted));
        record.insert("purposeVersion".into(), number(purpose_version));
        record.insert("source".into(), string(input.source));
        if let Some(method) = &method {
            record.insert("method".into(), string(method.clone()));
        }
        record.insert("recordedAt".into(), number(input.at));
        record.insert("recordedBy".into(), string(input.recorded_by));
        if let Some(expires_at) = expires_at {
            record.insert("expiresAt".into(), number(expires_at));
        }
        record.insert("receiptId".into(), string(receipt_id));
        if existing.is_some() {
            tx.put("privacyConsents", &record).await?;
        } else {
            tx.insert("privacyConsents", &record).await?;
        }
    }
    let event = tx.insert("privacyConsentEvents", &event).await?;
    let event: PrivacyConsentEvent = decode(event)?;
    Ok((receipt_from_event(&ctx.options.secret, &event)?, current))
}

/// `{ ...record, without }`: the record minus the named members.
fn without(record: &Record, keys: &[&str]) -> Record {
    let mut out = record.clone();
    for key in keys {
        out.shift_remove(*key);
    }
    out
}

/// Builds the `subject` member of an export.
fn export_subject(request: &Record) -> Value {
    if truthy(request.get("identityId")) {
        json!({ "kind": "account", "id": request.get("identityId") })
    } else if let Some(external_id) = request.get("externalId") {
        json!({ "kind": "external", "id": external_id })
    } else {
        json!({
            "kind": "requester",
            "email": defined(request.get("requesterEmail")).cloned().unwrap_or_else(|| string("")),
        })
    }
}

/// Everything the tenant holds about a subject, as JSON: the answer to an access or portability request.
async fn build_export(
    ctx: &ServerContext,
    tx: &Store,
    tenant: &Tenant,
    request: &Record,
    scope: &str,
    include_activity: bool,
) -> IamResult<Value> {
    let tenant_id = tenant.id.as_str();
    let subject = s(request, "subject").to_owned();
    let now = ctx.now();
    let mut purposes: IndexMap<String, PrivacyPurpose> = IndexMap::new();
    for purpose in decode_all::<PrivacyPurpose>(
        find(
            tx,
            "privacyPurposes",
            Filter::new().eq("tenantId", tenant_id.to_owned()),
        )
        .await?,
    )? {
        purposes.insert(purpose.id.clone(), purpose);
    }
    let restricted = restriction_state(restriction_of(tx, tenant_id, &subject).await?.as_ref())?;
    let mut consents = Vec::new();
    for consent in consents_of(tx, tenant_id, &subject).await?.values() {
        let purpose = purposes.get(&consent.purpose_id);
        let mut entry = Map::new();
        entry.insert("purpose".into(), string(consent.purpose_key.clone()));
        entry.insert(
            "purposeName".into(),
            string(
                purpose
                    .map(|purpose| purpose.name.clone())
                    .unwrap_or_else(|| consent.purpose_key.clone()),
            ),
        );
        entry.insert("granted".into(), Value::Bool(consent.granted));
        entry.insert("purposeVersion".into(), number(consent.purpose_version));
        entry.insert("recordedAt".into(), string(iso(consent.recorded_at)?));
        if let Some(expires_at) = consent.expires_at {
            entry.insert("expiresAt".into(), string(iso(expires_at)?));
        }
        entry.insert("source".into(), consent.source.clone());
        if let Some(purpose) = purpose {
            entry.insert(
                "state".into(),
                string(consent_state(purpose, Some(consent), &restricted, now)?.reason),
            );
        }
        consents.push(Value::Object(entry));
    }
    let mut events: Vec<PrivacyConsentEvent> = decode_all(
        find(
            tx,
            "privacyConsentEvents",
            Filter::new()
                .eq("tenantId", tenant_id.to_owned())
                .eq("subject", subject.clone()),
        )
        .await?,
    )?;
    events.sort_by(|a, b| order(a.recorded_at - b.recorded_at));
    let mut history = Vec::new();
    for event in &events {
        let mut entry = Map::new();
        entry.insert("purpose".into(), string(event.purpose_key.clone()));
        entry.insert("granted".into(), Value::Bool(event.granted));
        entry.insert("purposeVersion".into(), number(event.purpose_version));
        entry.insert("recordedAt".into(), string(iso(event.recorded_at)?));
        entry.insert("source".into(), event.source.clone());
        if let Some(method) = non_empty(&event.method) {
            entry.insert("method".into(), string(method.clone()));
        }
        if let Some(evidence) = non_empty(&event.evidence) {
            entry.insert("evidence".into(), string(evidence.clone()));
        }
        if let Some(ip) = non_empty(&event.ip) {
            entry.insert("ip".into(), string(ip.clone()));
        }
        entry.insert("receiptId".into(), string(event.receipt_id.clone()));
        history.push(Value::Object(entry));
    }
    let processing: Vec<Value> = purposes
        .values()
        .filter(|purpose| !purpose.archived)
        .map(|purpose| {
            let mut entry = Map::new();
            entry.insert("purpose".into(), string(purpose.key.clone()));
            entry.insert("name".into(), string(purpose.name.clone()));
            entry.insert("description".into(), string(purpose.description.clone()));
            entry.insert("legalBasis".into(), purpose.legal_basis.clone());
            entry.insert(
                "dataCategories".into(),
                Value::Array(
                    purpose
                        .data_categories
                        .iter()
                        .map(|item| string(item.clone()))
                        .collect(),
                ),
            );
            if let Some(retention) = purpose.retention_days {
                entry.insert("retentionDays".into(), number(retention));
            }
            Value::Object(entry)
        })
        .collect();
    let mut requests = Vec::new();
    for item in find(
        tx,
        "privacyRequests",
        Filter::new()
            .eq("tenantId", tenant_id.to_owned())
            .eq("subject", subject.clone()),
    )
    .await?
    {
        let mut entry = Map::new();
        copy_member(&mut entry, &item, "number");
        copy_member(&mut entry, &item, "type");
        copy_member(&mut entry, &item, "status");
        entry.insert(
            "submittedAt".into(),
            string(iso(nan_of(&item, "submittedAt"))?),
        );
        if item.get("closedAt").is_some() {
            entry.insert("closedAt".into(), string(iso(nan_of(&item, "closedAt"))?));
        }
        requests.push(Value::Object(entry));
    }
    let mut base = Map::new();
    base.insert("format".into(), string("better-iam.privacy-export"));
    base.insert("version".into(), number(1.0));
    base.insert("scope".into(), string(scope));
    base.insert("generatedAt".into(), string(iso(now)?));
    base.insert(
        "organization".into(),
        json!({ "id": tenant.id, "name": tenant.name }),
    );
    let mut request_summary = Map::new();
    copy_member(&mut request_summary, request, "number");
    copy_member(&mut request_summary, request, "type");
    copy_member(&mut request_summary, request, "regulation");
    base.insert("request".into(), Value::Object(request_summary));
    base.insert("subject".into(), export_subject(request));
    base.insert("consents".into(), Value::Array(consents));
    base.insert("consentHistory".into(), Value::Array(history));
    let identity = if truthy(request.get("identityId")) {
        tx.get("identities", s(request, "identityId")).await?
    } else {
        None
    };
    let identity = match identity {
        Some(identity) if s(&identity, "status") != "deleted" => identity,
        _ => {
            let mut out = base;
            if scope == "full" {
                out.insert("processing".into(), Value::Array(processing));
                out.insert("requests".into(), Value::Array(requests));
            }
            return Ok(Value::Object(out));
        }
    };
    let identity_id = s(&identity, "id").to_owned();
    let profile = public_identity_record(&identity);
    let onboarding: Vec<Value> = find(
        tx,
        "onboardingProgress",
        Filter::new()
            .eq("tenantId", tenant_id.to_owned())
            .eq("subjectId", identity_id.clone()),
    )
    .await?
    .into_iter()
    .map(|row| Value::Object(without(&row, &["id", "tenantId", "uniqueKey"])))
    .collect();
    let mut agreements = Vec::new();
    for acceptance in find(
        tx,
        "agreementAcceptances",
        Filter::new()
            .eq("tenantId", tenant_id.to_owned())
            .eq("identityId", identity_id.clone()),
    )
    .await?
    {
        let agreement = tx
            .get("agreements", &js_string(acceptance.get("agreementId")))
            .await?;
        let mut entry = Map::new();
        let name = agreement
            .as_ref()
            .and_then(|agreement| defined(agreement.get("name")).cloned())
            .or_else(|| acceptance.get("agreementId").cloned());
        if let Some(name) = name {
            entry.insert("agreement".into(), name);
        }
        copy_member(&mut entry, &acceptance, "version");
        entry.insert(
            "acceptedAt".into(),
            string(iso(nan_of(&acceptance, "acceptedAt"))?),
        );
        agreements.push(Value::Object(entry));
    }
    if scope == "provided" {
        let mut provided = Map::new();
        copy_member(&mut provided, &profile, "name");
        for key in ["email", "phone", "attributes"] {
            if truthy(profile.get(key)) {
                copy_member(&mut provided, &profile, key);
            }
        }
        let mut out = base;
        out.insert("profile".into(), Value::Object(provided));
        out.insert("onboarding".into(), Value::Array(onboarding));
        out.insert("agreements".into(), Value::Array(agreements));
        return Ok(Value::Object(out));
    }
    let mut groups = Vec::new();
    for membership in find(
        tx,
        "groupMembers",
        Filter::new()
            .eq("tenantId", tenant_id.to_owned())
            .eq("identityId", identity_id.clone()),
    )
    .await?
    {
        let Some(group) = tx.get("groups", s(&membership, "groupId")).await? else {
            continue;
        };
        if s(&group, "tenantId") != tenant_id {
            continue;
        }
        let mut entry = Map::new();
        copy_member(&mut entry, &group, "id");
        copy_member(&mut entry, &group, "name");
        if membership.get("expiresAt").is_some() {
            entry.insert(
                "until".into(),
                string(iso(nan_of(&membership, "expiresAt"))?),
            );
        }
        groups.push(Value::Object(entry));
    }
    let sign_ins = tx.get("authSignIns", &identity_id).await?;
    let activity = if include_activity {
        let mut events = find(
            tx,
            "audit",
            Filter::new()
                .eq("tenantId", tenant_id.to_owned())
                .eq("actorId", identity_id.clone()),
        )
        .await?;
        events.sort_by(|a, b| {
            order(nan_of(b, "timestamp") - nan_of(a, "timestamp")).then_with(|| by_id(a, b))
        });
        let mut activity = Vec::new();
        for event in events.iter().take(5000) {
            let mut entry = Map::new();
            entry.insert("at".into(), string(iso(nan_of(event, "timestamp"))?));
            copy_member(&mut entry, event, "action");
            copy_as(&mut entry, "resource", event, "resourceId");
            copy_member(&mut entry, event, "outcome");
            activity.push(Value::Object(entry));
        }
        Some(activity)
    } else {
        None
    };
    let mut access = Vec::new();
    for binding in ctx
        .decisions()?
        .effective_bindings(tx, tenant_id, &identity_id)
        .await?
    {
        let mut entry = Map::new();
        entry.insert(
            "role".into(),
            string(
                binding
                    .role
                    .as_ref()
                    .map(|role| role.name.clone())
                    .unwrap_or_else(|| binding.binding.role_id.clone()),
            ),
        );
        entry.insert(
            "via".into(),
            string(if binding.via == BindingVia::Identity {
                "direct"
            } else {
                "group"
            }),
        );
        if let Some(expires_at) = binding.binding.expires_at {
            entry.insert("until".into(), string(iso(expires_at)?));
        }
        access.push(Value::Object(entry));
    }
    let mut sessions = Vec::new();
    for session in find(
        tx,
        "sessions",
        Filter::new()
            .eq("tenantId", tenant_id.to_owned())
            .eq("identityId", identity_id.clone()),
    )
    .await?
    {
        let mut entry = Map::new();
        copy_member(&mut entry, &session, "kind");
        for key in ["createdAt", "lastSeenAt", "expiresAt"] {
            entry.insert(key.into(), string(iso(nan_of(&session, key))?));
        }
        if truthy(session.get("client")) {
            copy_member(&mut entry, &session, "client");
        }
        sessions.push(Value::Object(entry));
    }
    let mfa = tx.get("authMfa", &identity_id).await?;
    let mut passkeys = Vec::new();
    for key in find(
        tx,
        "authPasskeys",
        Filter::new()
            .eq("tenantId", tenant_id.to_owned())
            .eq("identityId", identity_id.clone()),
    )
    .await?
    {
        let mut entry = Map::new();
        if truthy(key.get("name")) {
            copy_member(&mut entry, &key, "name");
        }
        for member in ["createdAt", "lastUsedAt"] {
            if let Some(Value::Number(at)) = key.get(member) {
                entry.insert(member.into(), string(iso(core_js::number_value(at))?));
            }
        }
        passkeys.push(Value::Object(entry));
    }
    let linked: Vec<Value> = find(
        tx,
        "externalIdentities",
        Filter::new()
            .eq("tenantId", tenant_id.to_owned())
            .eq("identityId", identity_id.clone()),
    )
    .await?
    .into_iter()
    .map(|mapping| {
        let mut entry = Map::new();
        copy_member(&mut entry, &mapping, "issuer");
        copy_member(&mut entry, &mapping, "subject");
        Value::Object(entry)
    })
    .collect();
    // The app launcher's history (applications.ts): which apps, how often, first and last time.
    let mut launches = Vec::new();
    for launch in find(
        tx,
        "appLaunches",
        Filter::new()
            .eq("tenantId", tenant_id.to_owned())
            .eq("identityId", identity_id.clone()),
    )
    .await?
    {
        let app_id = js_string(launch.get("appId"));
        let application = tx.get("applications", &app_id).await?;
        let name = application
            .as_ref()
            .and_then(|application| defined(application.get("name")).cloned())
            .or_else(|| launch.get("appId").cloned());
        let mut entry = Map::new();
        entry.insert("app".into(), string(js_string(name.as_ref())));
        entry.insert(
            "count".into(),
            number(launch.get("count").map_or(f64::NAN, core_js::to_number)),
        );
        for key in ["firstAt", "lastAt"] {
            let at = launch.get(key).map_or(f64::NAN, core_js::to_number);
            entry.insert(key.into(), string(iso(at)?));
        }
        launches.push(Value::Object(entry));
    }
    let mut access_requests = Vec::new();
    for item in find(
        tx,
        "accessRequests",
        Filter::new()
            .eq("tenantId", tenant_id.to_owned())
            .eq("requesterId", identity_id.clone()),
    )
    .await?
    {
        let mut entry = Map::new();
        entry.insert("kind".into(), string("access"));
        copy_member(&mut entry, &item, "status");
        if let Some(Value::Number(at)) = item.get("createdAt") {
            entry.insert("at".into(), string(iso(core_js::number_value(at))?));
        }
        access_requests.push(Value::Object(entry));
    }
    for item in find(
        tx,
        "packageRequests",
        Filter::new()
            .eq("tenantId", tenant_id.to_owned())
            .eq("identityId", identity_id.clone()),
    )
    .await?
    {
        let mut entry = Map::new();
        entry.insert("kind".into(), string("package"));
        copy_member(&mut entry, &item, "status");
        if let Some(Value::Number(at)) = item.get("requestedAt") {
            entry.insert("at".into(), string(iso(core_js::number_value(at))?));
        }
        access_requests.push(Value::Object(entry));
    }
    let mut out = base;
    out.insert("profile".into(), Value::Object(profile));
    out.insert("groups".into(), Value::Array(groups));
    out.insert("access".into(), Value::Array(access));
    out.insert("sessions".into(), Value::Array(sessions));
    if let Some(sign_ins) = sign_ins {
        let mut entry = Map::new();
        if let Some(Value::Number(at)) = sign_ins.get("lastAt") {
            entry.insert("lastAt".into(), string(iso(core_js::number_value(at))?));
        }
        if truthy(sign_ins.get("lastClient")) {
            copy_member(&mut entry, &sign_ins, "lastClient");
        }
        entry.insert(
            "failedAttempts".into(),
            defined(sign_ins.get("failedAttempts"))
                .cloned()
                .unwrap_or_else(|| number(0.0)),
        );
        out.insert("signIns".into(), Value::Object(entry));
    }
    out.insert(
        "mfa".into(),
        json!({ "enabled": truthy(mfa.as_ref().and_then(|mfa| mfa.get("enabled"))) }),
    );
    out.insert("passkeys".into(), Value::Array(passkeys));
    out.insert("linkedSignIns".into(), Value::Array(linked));
    out.insert("appLaunches".into(), Value::Array(launches));
    out.insert("agreements".into(), Value::Array(agreements));
    out.insert("onboarding".into(), Value::Array(onboarding));
    out.insert("accessRequests".into(), Value::Array(access_requests));
    out.insert("processing".into(), Value::Array(processing));
    out.insert("requests".into(), Value::Array(requests));
    match activity {
        Some(activity) => {
            out.insert("activity".into(), Value::Array(activity));
        }
        None => {
            out.insert("activityOmitted".into(), Value::Bool(true));
        }
    }
    Ok(Value::Object(out))
}

/// Erases what the tenant holds about a subject: the account (through identity deletion, which revokes and removes
/// every credential and grant), then the tombstone's name and remaining details, consent decisions and history,
/// restrictions, exports, sign-in records and queued messages, and the contact details on the subject's requests.
async fn erase_subject(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant: &Tenant,
    request: &Record,
) -> OperationResult<Vec<String>> {
    let tenant_id = tenant.id.as_str();
    let mut actions: Vec<String> = Vec::new();
    if truthy(request.get("identityId"))
        && let Some(record) = tx.get("identities", s(request, "identityId")).await?
        && s(&record, "tenantId") == tenant_id
    {
        let identity: Identity = decode(record.clone())?;
        let address = defined(record.get("email"))
            .or_else(|| defined(record.get("deletedEmail")))
            .and_then(Value::as_str)
            .map(str::to_owned);
        if s(&record, "status") != "deleted" {
            delete_identity(ctx, tx, principal, &identity).await?;
            // Webhooks, outbound SCIM and Shared Signals remove the account downstream on identity:delete; the
            // address stays out of the permanent audit record.
            ctx.events()?
                .audit(
                    tx,
                    principal,
                    "identity:delete",
                    tenant_id,
                    &identity.id,
                    AuditOutcome::Allow,
                    false,
                    audit_metadata(vec![
                        ("kind", record.get("kind").cloned().unwrap_or(Value::Null)),
                        ("erasure", Value::Bool(true)),
                    ]),
                )
                .await?;
            actions.push("account-deleted".into());
        }
        if let Some(tombstone) = tx.get("identities", &identity.id).await? {
            let mut kept = without(
                &tombstone,
                &["deletedEmail", "attributes", "description", "phone"],
            );
            kept.insert("name".into(), string("Erased person"));
            tx.put("identities", &kept).await?;
        }
        if tx.get("authSignIns", &identity.id).await?.is_some() {
            tx.delete("authSignIns", &identity.id).await?;
        }
        for row in find(
            tx,
            "authDevices",
            Filter::new()
                .eq("tenantId", tenant_id.to_owned())
                .eq("identityId", identity.id.clone()),
        )
        .await?
        {
            tx.delete("authDevices", s(&row, "id")).await?;
        }
        for row in find(
            tx,
            "onboardingProgress",
            Filter::new()
                .eq("tenantId", tenant_id.to_owned())
                .eq("subjectId", identity.id.clone()),
        )
        .await?
        {
            tx.delete("onboardingProgress", s(&row, "id")).await?;
        }
        if let Some(address) = address.filter(|address| !address.is_empty()) {
            for row in find(
                tx,
                "outbox",
                Filter::new()
                    .eq("tenantId", tenant_id.to_owned())
                    .eq("to", address),
            )
            .await?
            {
                tx.delete("outbox", s(&row, "id")).await?;
            }
        }
        actions.push("account-details-erased".into());
    }
    let subject = s(request, "subject").to_owned();
    let by_subject = || {
        Filter::new()
            .eq("tenantId", tenant_id.to_owned())
            .eq("subject", subject.clone())
    };
    let mut consents = 0;
    for consent in find(tx, "privacyConsents", by_subject()).await? {
        tx.delete("privacyConsents", s(&consent, "id")).await?;
        consents += 1;
    }
    let mut history = 0;
    for event in find(tx, "privacyConsentEvents", by_subject()).await? {
        if truthy(event.get("redacted")) {
            continue;
        }
        let mut kept = without(&event, &["evidence", "ip", "userAgent"]);
        kept.insert("redacted".into(), Value::Bool(true));
        tx.put("privacyConsentEvents", &kept).await?;
        history += 1;
    }
    for restriction in find(tx, "privacyRestrictions", by_subject()).await? {
        tx.delete("privacyRestrictions", s(&restriction, "id"))
            .await?;
    }
    // An application subject keeps a suppression marker: the application may ask about the same identifier again, and
    // an opt-out or objection the erased records held must not turn back into "allowed".
    if let Some(external_id) = request.get("externalId") {
        let mut marker = Record::new();
        marker.insert("id".into(), string(id()));
        marker.insert("tenantId".into(), string(tenant_id));
        marker.insert("subject".into(), string(subject.clone()));
        marker.insert("externalId".into(), external_id.clone());
        copy_as(&mut marker, "requestId", request, "id");
        marker.insert("erased".into(), Value::Bool(true));
        marker.insert("restrictedAt".into(), number(ctx.now()));
        marker.insert("restrictedBy".into(), string(principal.identity.id.clone()));
        tx.insert("privacyRestrictions", &marker).await?;
    }
    for item in find(tx, "privacyExports", by_subject()).await? {
        tx.delete("privacyExports", s(&item, "id")).await?;
    }
    for other in find(tx, "privacyRequests", by_subject()).await? {
        if s(&other, "id") != s(request, "id") && !truthy(other.get("redacted")) {
            tx.put("privacyRequests", &redact(&other)).await?;
        }
    }
    if consents > 0 {
        actions.push(format!("consents-deleted:{consents}"));
    }
    if history > 0 {
        actions.push(format!("history-redacted:{history}"));
    }
    if actions.is_empty() {
        actions.push("nothing-held".into());
    }
    Ok(actions)
}

fn redact(request: &Record) -> Record {
    let mut kept = without(request, &["requesterEmail", "requesterName", "details"]);
    kept.insert("redacted".into(), Value::Bool(true));
    if let Some(Value::Array(events)) = request.get("events") {
        let events = events
            .iter()
            .map(|event| match event {
                Value::Object(event) => Value::Object(without(event, &["note"])),
                other => other.clone(),
            })
            .collect();
        kept.insert("events".into(), Value::Array(events));
    }
    kept
}

fn regulation_of(value: Option<&Value>, settings: &PrivacySettings) -> IamResult<Value> {
    match value {
        None => Ok(settings.default_regulation.clone()),
        Some(value) => one_of(Some(value), &regulations()?, "regulation"),
    }
}

fn purpose_keys_of(value: Option<&Value>) -> IamResult<Option<Vec<String>>> {
    if value.is_none() {
        return Ok(None);
    }
    let mut keys = Vec::new();
    for key in strings(value, "purposeKeys")? {
        keys.push(purpose_key(Some(&Value::String(key)))?);
    }
    let mut keys = crate::js::unique(keys);
    if keys.len() > 50 {
        return Err(invalid_input("At most 50 purposeKeys"));
    }
    if keys.is_empty() {
        return Ok(None);
    }
    crate::js::sort_strings(&mut keys);
    Ok(Some(keys))
}

/// Opens a verified request: the response window starts now.
fn opened(
    request: &Record,
    settings: &PrivacySettings,
    now: f64,
    verification: Value,
) -> IamResult<Record> {
    let window = response_window(
        request.get("regulation").unwrap_or(&Value::Null),
        &Value::Object(encode(settings)),
    )?;
    let response_days = crate::js::member(Some(&window), "responseDays")
        .and_then(core_js::as_number)
        .unwrap_or(f64::NAN);
    let mut kept = without(request, &["tokenHash", "tokenExpiresAt"]);
    kept.insert("status".into(), string("open"));
    kept.insert("verification".into(), verification);
    kept.insert("receivedAt".into(), number(now));
    kept.insert("dueAt".into(), number(now + response_days * DAY_MS));
    Ok(kept)
}

fn keys_value(keys: &[String]) -> Value {
    Value::Array(keys.iter().map(|key| string(key.clone())).collect())
}

/// Runs a self-service call as the signed-in person of `tenantId` (`asPerson`): the principal re-read inside the
/// transaction, then the person's tenant, which must be active.
async fn as_person(
    ctx: &ServerContext,
    tx: &Store,
    authenticated: &AuthenticatedPrincipal,
    tenant_id: &str,
) -> IamResult<(AuthenticatedPrincipal, Tenant)> {
    let principal = ctx
        .principals()?
        .current_principal(tx, authenticated)
        .await?;
    self_session(&principal, tenant_id)?;
    let tenant = ctx.tenant(tx, tenant_id).await?;
    if tenant.status != TenantStatus::Active {
        return Err(IamError::with_status(
            "TENANT_INACTIVE",
            "Tenant inactive",
            403,
        ));
    }
    Ok((principal, tenant))
}

async fn subject_names(tx: &Store, requests: &[Record]) -> IamResult<IndexMap<String, String>> {
    let mut names: IndexMap<String, String> = IndexMap::new();
    for request in requests {
        if !truthy(request.get("identityId")) {
            continue;
        }
        let identity_id = s(request, "identityId");
        if names.contains_key(identity_id) {
            continue;
        }
        if let Some(identity) = tx.get("identities", identity_id).await? {
            let name = defined(identity.get("email"))
                .or_else(|| identity.get("name"))
                .map(|value| js_string(Some(value)))
                .unwrap_or_else(|| "undefined".into());
            names.insert(s(&identity, "id").to_owned(), name);
        }
    }
    Ok(names)
}

async fn open_request(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
    request_id: Option<&Value>,
) -> IamResult<Record> {
    let request_id = text(request_id, "requestId", 256)?;
    ctx.scoped(
        tx,
        "privacyRequests",
        Some(&Value::String(request_id)),
        tenant_id,
    )
    .await
}

fn iam_request(tenant_id: &str, action: &str, resource_id: &str) -> AuthorizationRequest {
    AuthorizationRequest {
        credential: CredentialInput::default(),
        tenant_id: tenant_id.to_owned(),
        action: action.to_owned(),
        resource: ResourceTarget {
            kind: "iam".into(),
            id: resource_id.to_owned(),
        },
    }
}

/// `ctx.decisions.decide(tx, principal, { tenantId, action, resource: { type: 'iam', id } }, true).allowed`.
async fn may(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    action: &str,
    resource_id: &str,
) -> IamResult<bool> {
    Ok(ctx
        .decisions()?
        .decide(
            tx,
            principal,
            &iam_request(tenant_id, action, resource_id),
            true,
        )
        .await?
        .allowed)
}

/// `{ subject, reason }` lists and the pending deadline job read requests as typed values for `requestOverdue`.
fn overdue(request: &Record, now: f64) -> IamResult<bool> {
    request_overdue(&decode::<SubjectRequest>(request.clone())?, now)
}

fn integer_or(
    value: Option<&Value>,
    fallback: f64,
    name: &str,
    min: f64,
    max: f64,
) -> IamResult<f64> {
    match defined(value) {
        Some(value) => integer(Some(value), name, min, max),
        None => integer(Some(&number(fallback)), name, min, max),
    }
}

fn settings_view(settings: &Map<String, Value>) -> Value {
    let mut out = Map::new();
    for key in ["contactEmail", "contactName"] {
        if truthy(settings.get(key)) {
            copy_member(&mut out, settings, key);
        }
    }
    copy_member(&mut out, settings, "defaultRegulation");
    if truthy(settings.get("responseDays")) {
        copy_member(&mut out, settings, "responseDays");
    }
    copy_member(&mut out, settings, "publicIntake");
    copy_member(&mut out, settings, "exportLifetimeDays");
    out.insert("statutory".into(), REGULATION_DEADLINES.clone());
    Value::Object(out)
}

/// `regulationDeadlines[regulation]`; an unknown regulation is a TypeError in TypeScript.
fn deadline(regulation: &str, member: &str) -> IamResult<f64> {
    REGULATION_DEADLINES
        .get(regulation)
        .and_then(|deadline| deadline.get(member))
        .and_then(core_js::as_number)
        .ok_or_else(internal_error)
}

/// The processing decision for a subject and purpose, shared by the API and the credential-free runtime.
async fn check_subject(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
    subject_input: Option<&Value>,
    key: Option<&Value>,
) -> IamResult<Value> {
    let purpose = purpose_by_key(tx, tenant_id, key).await?;
    let subject = resolve_subject(tx, tenant_id, subject_input, None).await?;
    let consent = consent_for(tx, tenant_id, format!("{}:{}", purpose.id, subject.key)).await?;
    let restricted =
        restriction_state(restriction_of(tx, tenant_id, &subject.key).await?.as_ref())?;
    let state = state_of(&purpose, consent.as_ref(), &restricted, ctx.now())?;
    let mut out = Map::new();
    out.insert("purposeKey".into(), string(purpose.key.clone()));
    out.insert("purposeVersion".into(), number(purpose.version));
    for (key, value) in state {
        out.insert(key, value);
    }
    if let Some(consent) = &consent {
        out.insert("consent".into(), consent_summary(consent));
    }
    Ok(Value::Object(out))
}

// ── The API group ────────────────────────────────────────────────────────────────────────────────────────────────

/// The `privacy` API group (`createPrivacyApi(ctx)`): one method per route `privacy/{method}`.
pub struct PrivacyApi {
    ctx: Arc<ServerContext>,
}

/// `createPrivacyApi(ctx)`.
pub fn create_privacy_api(ctx: &Arc<ServerContext>) -> IamResult<PrivacyApi> {
    Ok(PrivacyApi { ctx: ctx.clone() })
}

impl PrivacyApi {
    /// `operation(credential, input.tenantId, action, resourceId, mutation)`.
    async fn operate(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
        action: &str,
        resource_id: &str,
        mutation: Mutation<'_>,
    ) -> IamResult<Value> {
        self.ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                action,
                resource_id,
                mutation,
                false,
            )
            .await
    }

    // ── Purposes ──────────────────────────────────────────────────────────────────────────────────────────────

    /// `privacy/createPurpose`: adds a processing purpose at version 1. Keys are permanent; names and descriptions
    /// can change.
    pub async fn create_purpose(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::CreatePurposeInput>,
    ) -> IamResult<Reply<privacy::CreatePurposeOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let values = purpose_fields(body, None)?;
                let existing = find(
                    &tx,
                    "privacyPurposes",
                    Filter::new().eq("tenantId", tenant.id.clone()),
                )
                .await?;
                if existing
                    .iter()
                    .any(|purpose| purpose.get("uniqueKey") == values.get("uniqueKey"))
                {
                    return Err(IamError::with_status(
                        "CONFLICT",
                        "A purpose with this key exists",
                        409,
                    )
                    .into());
                }
                if existing.len() >= MAX_PURPOSES {
                    return Err(IamError::with_status(
                        "LIMIT_EXCEEDED",
                        format!("At most {MAX_PURPOSES} purposes"),
                        409,
                    )
                    .into());
                }
                let now = ctx.now();
                let mut record = values;
                record.insert("id".into(), string(id()));
                record.insert("tenantId".into(), string(tenant.id.clone()));
                record.insert("version".into(), number(1.0));
                record.insert("archived".into(), Value::Bool(false));
                record.insert("createdAt".into(), number(now));
                record.insert("updatedAt".into(), number(now));
                Ok(Value::Object(tx.insert("privacyPurposes", &record).await?))
            })
        });
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:manage",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/updatePurpose`: edits a purpose. `newVersion: true` publishes the change as the next version: opt-in
    /// grants given to older versions stop counting (unless `reconsentOnVersion` is false), so people are asked
    /// again. `archived: true` stops all processing for it; decisions are kept.
    pub async fn update_purpose(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::UpdatePurposeInput>,
    ) -> IamResult<Reply<privacy::UpdatePurposeOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("purposeId"), "purposeId", 256)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let previous = ctx
                    .scoped(&tx, "privacyPurposes", body.get("purposeId"), &tenant.id)
                    .await?;
                let values = purpose_fields(body, Some(&previous))?;
                let new_version = body.get("newVersion") == Some(&Value::Bool(true));
                // A new basis or mode changes who may be processed (opt-in to opt-out makes everyone never asked
                // processable), so it is published as a new version people can see.
                if (values.get("legalBasis") != previous.get("legalBasis")
                    || values.get("mode") != previous.get("mode"))
                    && !new_version
                {
                    return Err(invalid_input(
                        "Changing the legal basis or consent mode is a material change: publish it with newVersion",
                    )
                    .into());
                }
                if let Some(archived) = body.get("archived")
                    && !archived.is_boolean()
                {
                    return Err(invalid_input("archived must be a boolean").into());
                }
                let mut record = without(&previous, &["retentionDays", "consentLifetimeDays"]);
                for (key, value) in values {
                    record.insert(key, value);
                }
                record.insert(
                    "version".into(),
                    number(nan_of(&previous, "version") + if new_version { 1.0 } else { 0.0 }),
                );
                record.insert(
                    "archived".into(),
                    body.get("archived")
                        .or_else(|| previous.get("archived"))
                        .cloned()
                        .unwrap_or(Value::Null),
                );
                record.insert("updatedAt".into(), number(ctx.now()));
                Ok(Value::Object(tx.put("privacyPurposes", &record).await?))
            })
        });
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:manage",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/deletePurpose`: deletes a purpose nobody has decided on yet; purposes with recorded decisions are
    /// archived instead.
    pub async fn delete_purpose(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::DeletePurposeInput>,
    ) -> IamResult<Reply<privacy::DeletePurposeOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("purposeId"), "purposeId", 256)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let purpose = ctx
                    .scoped(&tx, "privacyPurposes", body.get("purposeId"), &tenant.id)
                    .await?;
                let purpose_id = s(&purpose, "id").to_owned();
                if !find(
                    &tx,
                    "privacyConsentEvents",
                    Filter::new()
                        .eq("tenantId", tenant.id.clone())
                        .eq("purposeId", purpose_id.clone()),
                )
                .await?
                .is_empty()
                {
                    return Err(IamError::with_status(
                        "RESOURCE_IN_USE",
                        "Decisions are recorded for this purpose; archive it instead so the proof is kept",
                        409,
                    )
                    .into());
                }
                tx.delete("privacyPurposes", &purpose_id).await?;
                Ok(json!({ "deleted": true }))
            })
        });
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:manage",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/listPurposes`.
    pub async fn list_purposes(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::ListPurposesInput>,
    ) -> IamResult<Reply<privacy::ListPurposesOutput>> {
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let include_archived = body.get("includeArchived") == Some(&Value::Bool(true));
                let mut purposes: Vec<Record> = find(
                    &tx,
                    "privacyPurposes",
                    Filter::new().eq("tenantId", tenant.id.clone()),
                )
                .await?
                .into_iter()
                .filter(|purpose| include_archived || !truthy(purpose.get("archived")))
                .collect();
                purposes.sort_by(|a, b| locale_compare(s(a, "name"), s(b, "name")));
                Ok(Value::Array(
                    purposes.into_iter().map(Value::Object).collect(),
                ))
            })
        });
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:read",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    // ── The person's own choices ──────────────────────────────────────────────────────────────────────────────

    /// `privacy/mine`: the caller's privacy page: every purpose with their decision and its effect, whether
    /// processing is restricted, their data-subject requests, and the privacy contact. Needs only a signed-in session
    /// of the organization.
    pub async fn mine(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::MineInput>,
    ) -> IamResult<Reply<privacy::MineOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let tenant_id = &tenant_id;
        let authenticated = &authenticated;
        let result = ctx
            .store
            .transaction(|tx| async move {
                let (principal, _) = as_person(ctx, &tx, authenticated, tenant_id).await?;
                let now = ctx.now();
                let subject = identity_subject(&principal.identity.id)?;
                let consents = consents_of(&tx, tenant_id, &subject).await?;
                let restricted = restriction_of(&tx, tenant_id, &subject).await?.is_some();
                let settings = privacy_settings(&tx, tenant_id).await?;
                let mut listed: Vec<(bool, PrivacyPurpose)> = Vec::new();
                for purpose in decode_all::<PrivacyPurpose>(
                    find(
                        &tx,
                        "privacyPurposes",
                        Filter::new().eq("tenantId", tenant_id.clone()),
                    )
                    .await?,
                )? {
                    if !purpose.archived {
                        listed.push((decidable_purpose(&purpose)?, purpose));
                    }
                }
                listed.sort_by(|(a_decides, a), (b_decides, b)| {
                    b_decides
                        .cmp(a_decides)
                        .then_with(|| locale_compare(&a.name, &b.name))
                });
                let mut purposes = Vec::new();
                for (decides, purpose) in &listed {
                    let consent = consents.get(&purpose.id);
                    let mut entry = Map::new();
                    entry.insert("id".into(), string(purpose.id.clone()));
                    entry.insert("key".into(), string(purpose.key.clone()));
                    entry.insert("name".into(), string(purpose.name.clone()));
                    entry.insert("description".into(), string(purpose.description.clone()));
                    entry.insert("legalBasis".into(), purpose.legal_basis.clone());
                    entry.insert("mode".into(), purpose.mode.clone());
                    entry.insert("version".into(), number(purpose.version));
                    entry.insert(
                        "dataCategories".into(),
                        keys_value(&purpose.data_categories),
                    );
                    if let Some(retention) = purpose.retention_days {
                        entry.insert("retentionDays".into(), number(retention));
                    }
                    entry.insert("decidable".into(), Value::Bool(*decides));
                    entry.insert(
                        "state".into(),
                        Value::Object(state_of(purpose, consent, &Value::Bool(restricted), now)?),
                    );
                    if let Some(consent) = consent {
                        entry.insert("consent".into(), consent_summary(consent));
                    }
                    purposes.push(Value::Object(entry));
                }
                let mut requests = find(
                    &tx,
                    "privacyRequests",
                    Filter::new()
                        .eq("tenantId", tenant_id.clone())
                        .eq("subject", subject.clone()),
                )
                .await?;
                requests.sort_by(|a, b| order(nan_of(b, "submittedAt") - nan_of(a, "submittedAt")));
                let requests = requests
                    .iter()
                    .map(|request| mine_view(request, now))
                    .collect::<IamResult<Vec<_>>>()?;
                let mut out = Map::new();
                out.insert("purposes".into(), Value::Array(purposes));
                out.insert("restricted".into(), Value::Bool(restricted));
                out.insert("requests".into(), Value::Array(requests));
                if let Some(contact) = settings.contact_email.filter(|email| !email.is_empty()) {
                    let mut entry = Map::new();
                    entry.insert("email".into(), string(contact));
                    if let Some(name) = settings.contact_name.filter(|name| !name.is_empty()) {
                        entry.insert("name".into(), string(name));
                    }
                    out.insert("contact".into(), Value::Object(entry));
                }
                Ok(Value::Object(out))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/decide`: records the caller's decision on a purpose: `granted: true` consents (or withdraws an
    /// objection), `false` withdraws consent, opts out, or objects to a legitimate-interest purpose. `version` must be
    /// the purpose's current version, so nobody agrees to text they were not shown. Returns a signed receipt; audited
    /// as `privacy:consent`.
    pub async fn decide(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::DecideInput>,
    ) -> IamResult<Reply<privacy::DecideOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let Some(Value::Bool(granted)) = input.get("granted").cloned() else {
            return Err(invalid_input("granted must be a boolean"));
        };
        let version = integer(input.get("version"), "version", 1.0, 1_000_000.0)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let (tenant_id, authenticated, body) = (&tenant_id, &authenticated, &input);
        let result = ctx
            .store
            .transaction(|tx| async move {
                let (principal, _) = as_person(ctx, &tx, authenticated, tenant_id).await?;
                let purpose = purpose_by_key(&tx, tenant_id, body.get("purposeKey")).await?;
                if purpose.version != version {
                    return Err(IamError::with_status(
                        "VERSION_CONFLICT",
                        "The purpose changed; review the current version before deciding",
                        409,
                    ));
                }
                let subject = resolve_subject(
                    &tx,
                    tenant_id,
                    Some(&json!({ "identityId": principal.identity.id })),
                    None,
                )
                .await?;
                let method =
                    method_label(body.get("method"))?.unwrap_or_else(|| "self-service".into());
                let evidence = evidence(body.get("evidence"))?;
                let (receipt, _) = write_consent(
                    ctx,
                    &tx,
                    ConsentWrite {
                        tenant_id,
                        purpose: &purpose,
                        subject: &subject,
                        granted,
                        source: "self",
                        method: Some(method),
                        evidence,
                        recorded_by: &principal.identity.id,
                        at: ctx.now(),
                        version: None,
                        client: ctx.auth.current_client().map(ClientInfo::from),
                    },
                )
                .await?;
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "privacy:consent",
                        tenant_id,
                        &principal.identity.id,
                        AuditOutcome::Allow,
                        false,
                        audit_metadata(vec![
                            ("purposeKey", string(purpose.key.clone())),
                            ("granted", Value::Bool(granted)),
                            ("purposeVersion", number(version)),
                            ("source", string("self")),
                            ("receiptId", string(receipt.receipt_id.clone())),
                        ]),
                    )
                    .await?;
                Ok(Value::Object(encode(&receipt)))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/myHistory`: the caller's decision history (newest first, at most 500 entries).
    pub async fn my_history(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::MyHistoryInput>,
    ) -> IamResult<Reply<privacy::MyHistoryOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let (tenant_id, authenticated, body) = (&tenant_id, &authenticated, &input);
        let result = ctx
            .store
            .transaction(|tx| async move {
                let (principal, _) = as_person(ctx, &tx, authenticated, tenant_id).await?;
                let key = match body.get("purposeKey") {
                    None => None,
                    Some(value) => Some(purpose_key(Some(value))?),
                };
                let events: Vec<PrivacyConsentEvent> = decode_all(
                    find(
                        &tx,
                        "privacyConsentEvents",
                        Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("subject", identity_subject(&principal.identity.id)?),
                    )
                    .await?,
                )?;
                Ok(newest_events(events, key.as_deref(), 500))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/myReceipt`: a signed receipt for one of the caller's own decisions.
    pub async fn my_receipt(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::MyReceiptInput>,
    ) -> IamResult<Reply<privacy::MyReceiptOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let (tenant_id, authenticated, body) = (&tenant_id, &authenticated, &input);
        let result = ctx
            .store
            .transaction(|tx| async move {
                let (principal, _) = as_person(ctx, &tx, authenticated, tenant_id).await?;
                let receipt_id = text(body.get("receiptId"), "receiptId", 256)?;
                let event = tx.get("privacyConsentEvents", &receipt_id).await?;
                let subject = identity_subject(&principal.identity.id)?;
                let event = match event {
                    Some(event)
                        if s(&event, "tenantId") == tenant_id.as_str()
                            && s(&event, "subject") == subject =>
                    {
                        event
                    }
                    _ => {
                        return Err(IamError::with_status("NOT_FOUND", "Receipt not found", 404));
                    }
                };
                let event: PrivacyConsentEvent = decode(event)?;
                Ok(Value::Object(encode(&receipt_from_event(
                    &ctx.options.secret,
                    &event,
                )?)))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/submitRequest`: files a data-subject request for the caller. Signing in verified who they are, so the
    /// response window starts at once; the privacy contact is emailed. One open request per type at a time. Audited
    /// as `privacy:request:submit`.
    pub async fn submit_request(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::SubmitRequestInput>,
    ) -> IamResult<Reply<privacy::SubmitRequestOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let kind = one_of(
            input.get("type"),
            &str_values(SUBJECT_REQUEST_TYPES),
            "type",
        )?;
        let details = match input.get("details") {
            None => None,
            Some(value) => Some(prose(Some(value), "details", 5000.0)?),
        };
        let purpose_keys = purpose_keys_of(input.get("purposeKeys"))?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let (tenant_id, authenticated, body) = (&tenant_id, &authenticated, &input);
        let (kind, details, purpose_keys) = (&kind, &details, &purpose_keys);
        let result = ctx
            .store
            .transaction(|tx| async move {
                let (principal, tenant) = as_person(ctx, &tx, authenticated, tenant_id).await?;
                let subject = identity_subject(&principal.identity.id)?;
                let settings = privacy_settings(&tx, tenant_id).await?;
                let regulation = regulation_of(body.get("regulation"), &settings)?;
                let open_exists = find(
                    &tx,
                    "privacyRequests",
                    Filter::new()
                        .eq("tenantId", tenant_id.clone())
                        .eq("subject", subject.clone()),
                )
                .await?
                .iter()
                .any(|request| {
                    request.get("type") == Some(kind)
                        && matches!(s(request, "status"), "open" | "pending-verification")
                });
                if open_exists {
                    return Err(IamError::with_status(
                        "CONFLICT",
                        "You already have an open request of this type",
                        409,
                    ));
                }
                if let Some(keys) = purpose_keys {
                    for key in keys {
                        purpose_by_key(&tx, tenant_id, Some(&string(key.clone()))).await?;
                    }
                }
                let now = ctx.now();
                let request_no = request_number()?;
                let mut request = Record::new();
                request.insert("id".into(), string(id()));
                request.insert("tenantId".into(), string(tenant_id.clone()));
                request.insert("uniqueKey".into(), string(format!("number:{request_no}")));
                request.insert("number".into(), string(request_no.clone()));
                request.insert("type".into(), kind.clone());
                request.insert("regulation".into(), regulation.clone());
                request.insert("status".into(), string("pending-verification"));
                request.insert("subject".into(), string(subject.clone()));
                request.insert("identityId".into(), string(principal.identity.id.clone()));
                if let Some(details) = details.as_ref().filter(|details| !details.is_empty()) {
                    request.insert("details".into(), string(details.clone()));
                }
                if let Some(keys) = purpose_keys {
                    request.insert("purposeKeys".into(), keys_value(keys));
                }
                request.insert("channel".into(), string("self-service"));
                request.insert("verification".into(), json!({ "status": "pending" }));
                request.insert("submittedAt".into(), number(now));
                request.insert(
                    "events".into(),
                    Value::Array(vec![Value::Object(event_of(
                        now,
                        &principal.identity.id,
                        "submitted",
                        None,
                    ))]),
                );
                let request = opened(
                    &request,
                    &settings,
                    now,
                    json!({
                        "status": "verified",
                        "method": "authenticated-session",
                        "verifiedAt": number(now),
                    }),
                )?;
                tx.insert("privacyRequests", &request).await?;
                notify_contact(ctx, &tx, &tenant, &request).await?;
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "privacy:request:submit",
                        tenant_id,
                        s(&request, "id"),
                        AuditOutcome::Allow,
                        false,
                        audit_metadata(vec![
                            ("number", string(request_no)),
                            ("type", kind.clone()),
                            ("regulation", regulation),
                            ("channel", string("self-service")),
                        ]),
                    )
                    .await?;
                mine_view(&request, now)
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/cancelMyRequest`: withdraws one of the caller's own requests while it is still being handled.
    pub async fn cancel_my_request(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::CancelMyRequestInput>,
    ) -> IamResult<Reply<privacy::CancelMyRequestOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let (tenant_id, authenticated, body) = (&tenant_id, &authenticated, &input);
        let result = ctx
            .store
            .transaction(|tx| async move {
                let (principal, _) = as_person(ctx, &tx, authenticated, tenant_id).await?;
                let request = open_request(ctx, &tx, tenant_id, body.get("requestId")).await?;
                if s(&request, "subject") != identity_subject(&principal.identity.id)? {
                    return Err(IamError::with_status(
                        "NOT_FOUND",
                        "Resource not found",
                        404,
                    ));
                }
                if !matches!(s(&request, "status"), "open" | "pending-verification") {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "This request is already closed",
                        409,
                    ));
                }
                let now = ctx.now();
                let mut cancelled = request.clone();
                cancelled.insert("status".into(), string("cancelled"));
                cancelled.insert("closedAt".into(), number(now));
                cancelled.insert("closedBy".into(), string(principal.identity.id.clone()));
                cancelled.insert(
                    "events".into(),
                    push_event(
                        &request,
                        event_of(now, &principal.identity.id, "cancelled", None),
                    ),
                );
                tx.put("privacyRequests", &cancelled).await?;
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "privacy:request:cancel",
                        tenant_id,
                        s(&request, "id"),
                        AuditOutcome::Allow,
                        false,
                        audit_metadata(vec![
                            (
                                "number",
                                request.get("number").cloned().unwrap_or(Value::Null),
                            ),
                            ("type", request.get("type").cloned().unwrap_or(Value::Null)),
                        ]),
                    )
                    .await?;
                mine_view(&cancelled, now)
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/downloadExport`: downloads the export an access or portability request produced: by the person it is
    /// about, or by a request handler (`iam:privacy:handle`, recently signed in) who must deliver it another way.
    /// Audited as `privacy:export:download`.
    pub async fn download_export(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::DownloadExportInput>,
    ) -> IamResult<Reply<privacy::DownloadExportOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let request_id = text(input.get("requestId"), "requestId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let (tenant_id, request_id, authenticated) = (&tenant_id, &request_id, &authenticated);
        // A refusal is returned rather than thrown, so the transaction commits its deny audit record.
        let outcome: Option<Value> = ctx
            .store
            .transaction(|tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, authenticated)
                    .await?;
                let request = match tx.get("privacyRequests", request_id).await? {
                    Some(request)
                        if s(&request, "tenantId") == tenant_id.as_str()
                            && truthy(request.get("exportId")) =>
                    {
                        request
                    }
                    _ => {
                        return Err(IamError::with_status("NOT_FOUND", "Export not found", 404));
                    }
                };
                let own = acts_in_own_right(principal.session.kind)
                    && principal.session.kind == SessionKind::User
                    && !impersonating(&principal)
                    && principal.session.tenant_id == *tenant_id
                    && s(&request, "subject") == identity_subject(&principal.identity.id)?;
                if !own {
                    let mut checks = vec![("iam:privacy:handle", s(&request, "id").to_owned())];
                    // A handler reads everything about the person, as identities.export would let them.
                    if truthy(request.get("identityId")) {
                        checks.push(("iam:identities:read", s(&request, "identityId").to_owned()));
                    }
                    for (action, resource_id) in checks {
                        let decision = ctx
                            .operations()?
                            .recorded_decision(
                                &tx,
                                &principal,
                                &iam_request(tenant_id, action, &resource_id),
                            )
                            .await?;
                        if !decision.allowed {
                            return Ok(None);
                        }
                    }
                    ctx.auth.require_recent(&principal)?;
                }
                let item = tx
                    .get("privacyExports", s(&request, "exportId"))
                    .await?
                    .filter(|item| num_of(item, "expiresAt").is_some_and(|at| at > ctx.now()));
                let Some(item) = item else {
                    return Err(IamError::with_status(
                        "NOT_FOUND",
                        "The export has expired; file a new request",
                        404,
                    ));
                };
                let mut updated = item.clone();
                updated.insert("downloads".into(), number(nan_of(&item, "downloads") + 1.0));
                tx.put("privacyExports", &updated).await?;
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "privacy:export:download",
                        tenant_id,
                        s(&request, "id"),
                        AuditOutcome::Allow,
                        false,
                        audit_metadata(vec![
                            (
                                "number",
                                request.get("number").cloned().unwrap_or(Value::Null),
                            ),
                            ("by", string(if own { "subject" } else { "handler" })),
                        ]),
                    )
                    .await?;
                let mut result = Map::new();
                copy_member(&mut result, &request, "number");
                copy_member(&mut result, &item, "createdAt");
                copy_member(&mut result, &item, "expiresAt");
                copy_member(&mut result, &item, "sha256");
                copy_member(&mut result, &item, "data");
                Ok(Some(Value::Object(result)))
            })
            .await?;
        match outcome {
            Some(result) => Ok(Reply::json(result)),
            None => Err(IamError::with_status("ACCESS_DENIED", "Access denied", 403)),
        }
    }

    // ── Consent records kept by the application ───────────────────────────────────────────────────────────────

    /// `privacy/record`: records a decision for a subject: a person here (`{ identityId }`) or one the application
    /// names (`{ externalId }`, such as a customer number or a visitor ID). `source` is `api` (default), `admin` or
    /// `import`; imports may carry an earlier `recordedAt` and `version`, and never overwrite a newer decision.
    /// Returns the receipt.
    pub async fn record(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::RecordInput>,
    ) -> IamResult<Reply<privacy::RecordOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 tenant,
                 principal,
             }| {
                Box::pin(async move {
                    let Some(Value::Bool(granted)) = body.get("granted").cloned() else {
                        return Err(invalid_input("granted must be a boolean").into());
                    };
                    let api = string("api");
                    let source = one_of(
                        Some(defined(body.get("source")).unwrap_or(&api)),
                        &str_values(&["api", "admin", "import"]),
                        "source",
                    )?;
                    let source = source.as_str().unwrap_or("api").to_owned();
                    let now = ctx.now();
                    let at = match body.get("recordedAt") {
                        None => now,
                        Some(value) => integer(Some(value), "recordedAt", 0.0, now)?,
                    };
                    if at != now && source != "import" {
                        return Err(invalid_input("recordedAt is accepted for imports only").into());
                    }
                    // An imported grant counts for the version the person saw, never silently for today's text.
                    if source == "import" && body.get("version").is_none() {
                        return Err(invalid_input(
                            "Imports must state the purpose version decided on",
                        )
                        .into());
                    }
                    let purpose = purpose_by_key(&tx, &tenant.id, body.get("purposeKey")).await?;
                    let subject =
                        resolve_subject(&tx, &tenant.id, body.get("subject"), None).await?;
                    let client = if body.get("ip").is_some() || body.get("userAgent").is_some() {
                        let mut client = ClientInfo::default();
                        if let Some(ip) = body.get("ip") {
                            client.ip = Some(text(Some(ip), "ip", 64)?);
                        }
                        if let Some(agent) = body.get("userAgent") {
                            client.user_agent = Some(text(Some(agent), "userAgent", 512)?);
                        }
                        Some(client)
                    } else {
                        None
                    };
                    let method = method_label(body.get("method"))?;
                    let evidence = evidence(body.get("evidence"))?;
                    let (receipt, current) = write_consent(
                        ctx,
                        &tx,
                        ConsentWrite {
                            tenant_id: &tenant.id,
                            purpose: &purpose,
                            subject: &subject,
                            granted,
                            source: &source,
                            method,
                            evidence,
                            recorded_by: &principal.identity.id,
                            at,
                            version: body.get("version"),
                            client,
                        },
                    )
                    .await?;
                    let mut metadata = vec![
                        ("purposeKey", string(purpose.key.clone())),
                        ("granted", Value::Bool(granted)),
                        (
                            "purposeVersion",
                            crate::js::member(Some(&receipt.purpose), "version")
                                .cloned()
                                .unwrap_or(Value::Null),
                        ),
                        ("source", string(source.clone())),
                        ("receiptId", string(receipt.receipt_id.clone())),
                    ];
                    if let Some(external_id) = &subject.external_id {
                        metadata.push(("externalId", string(external_id.clone())));
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "privacy:consent",
                            &tenant.id,
                            subject.identity_id.as_deref().unwrap_or(&subject.key),
                            AuditOutcome::Allow,
                            false,
                            audit_metadata(metadata),
                        )
                        .await?;
                    let mut out = encode(&receipt);
                    out.insert("current".into(), Value::Bool(current));
                    Ok(Value::Object(out))
                })
            },
        );
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:record",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/importDecisions`: imports up to 500 decisions in one transaction (all or nothing), for moving consent
    /// records from another system. Entries follow `record` with `source: 'import'`; one `privacy:consent-import`
    /// audit event summarizes them.
    pub async fn import_decisions(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::ImportDecisionsInput>,
    ) -> IamResult<Reply<privacy::ImportDecisionsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 tenant,
                 principal,
             }| {
                Box::pin(async move {
                    let decisions = match body.get("decisions") {
                        Some(Value::Array(items)) if !items.is_empty() && items.len() <= 500 => {
                            items
                        }
                        _ => return Err(invalid_input("Provide 1-500 decisions").into()),
                    };
                    let now = ctx.now();
                    let mut purposes: IndexMap<String, PrivacyPurpose> = IndexMap::new();
                    let mut current = 0usize;
                    for raw in decisions {
                        let entry = object(Some(raw))?;
                        let Some(Value::Bool(granted)) = entry.get("granted").cloned() else {
                            return Err(invalid_input("granted must be a boolean").into());
                        };
                        if entry.get("version").is_none() {
                            return Err(invalid_input(
                                "Each imported decision must state its purpose version",
                            )
                            .into());
                        }
                        let key = purpose_key(entry.get("purposeKey"))?;
                        let purpose = match purposes.get(&key) {
                            Some(purpose) => purpose.clone(),
                            None => {
                                purpose_by_key(&tx, &tenant.id, Some(&string(key.clone()))).await?
                            }
                        };
                        purposes.insert(key, purpose.clone());
                        let subject =
                            resolve_subject(&tx, &tenant.id, entry.get("subject"), None).await?;
                        let method = method_label(entry.get("method"))?;
                        let evidence = evidence(entry.get("evidence"))?;
                        let at = integer(entry.get("recordedAt"), "recordedAt", 0.0, now)?;
                        let (_, written) = write_consent(
                            ctx,
                            &tx,
                            ConsentWrite {
                                tenant_id: &tenant.id,
                                purpose: &purpose,
                                subject: &subject,
                                granted,
                                source: "import",
                                method,
                                evidence,
                                recorded_by: &principal.identity.id,
                                at,
                                version: entry.get("version"),
                                client: None,
                            },
                        )
                        .await?;
                        if written {
                            current += 1;
                        }
                    }
                    let mut keys: Vec<String> = purposes.keys().cloned().collect();
                    crate::js::sort_strings(&mut keys);
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "privacy:consent-import",
                            &tenant.id,
                            &tenant.id,
                            AuditOutcome::Allow,
                            false,
                            audit_metadata(vec![
                                ("count", number(decisions.len() as f64)),
                                ("current", number(current as f64)),
                                ("purposes", keys_value(&keys)),
                            ]),
                        )
                        .await?;
                    Ok(json!({
                        "imported": number(decisions.len() as f64),
                        "current": number(current as f64),
                    }))
                })
            },
        );
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:record",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/check`: whether a purpose may be processed for a subject right now, and why (`CONSENT_GIVEN`,
    /// `NO_CONSENT`, `CONSENT_WITHDRAWN`, `CONSENT_EXPIRED`, `CONSENT_OUTDATED`, `OBJECTED`, `RESTRICTED`,
    /// `LEGAL_BASIS`, ...). Server code can call `iam.privacy.check` without a credential.
    pub async fn check(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::CheckInput>,
    ) -> IamResult<Reply<privacy::CheckOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                Ok(check_subject(
                    ctx,
                    &tx,
                    &tenant.id,
                    body.get("subject"),
                    body.get("purposeKey"),
                )
                .await?)
            })
        });
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:check",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/filterSubjects`: splits up to 1 000 subjects into those a purpose may be processed for and those it
    /// may not (with the reason), for batch jobs such as a marketing send.
    pub async fn filter_subjects(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::FilterSubjectsInput>,
    ) -> IamResult<Reply<privacy::FilterSubjectsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let subjects = match body.get("subjects") {
                    Some(Value::Array(items)) if items.len() <= 1000 => items,
                    _ => return Err(invalid_input("Provide at most 1000 subjects").into()),
                };
                let purpose = purpose_by_key(&tx, &tenant.id, body.get("purposeKey")).await?;
                let now = ctx.now();
                let mut allowed = Vec::new();
                let mut refused = Vec::new();
                for raw in subjects {
                    let resolved = match resolve_subject(&tx, &tenant.id, Some(raw), None).await {
                        Ok(resolved) => resolved,
                        Err(error) if error.code == "NOT_FOUND" => {
                            refused.push(json!({ "subject": raw, "reason": "UNKNOWN_SUBJECT" }));
                            continue;
                        }
                        Err(error) => return Err(error.into()),
                    };
                    let consent =
                        consent_for(&tx, &tenant.id, format!("{}:{}", purpose.id, resolved.key))
                            .await?;
                    let restricted = restriction_state(
                        restriction_of(&tx, &tenant.id, &resolved.key)
                            .await?
                            .as_ref(),
                    )?;
                    let state = consent_state(&purpose, consent.as_ref(), &restricted, now)?;
                    if state.allowed {
                        allowed.push(raw.clone());
                    } else {
                        refused.push(json!({ "subject": raw, "reason": state.reason }));
                    }
                }
                Ok(json!({
                    "purposeKey": purpose.key,
                    "allowed": allowed,
                    "refused": refused,
                }))
            })
        });
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:check",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/audience`: the subjects a purpose may currently be processed for: people of the tenant (every active
    /// person for opt-out and legitimate-interest purposes, those who consented for opt-in ones) and application
    /// subjects with a recorded decision. Paged by `offset` (at most 1 000 per page). People's emails and names are
    /// included only when the caller may also read identities (`iam:identities:read`); otherwise they are listed by
    /// ID.
    pub async fn audience(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::AudienceInput>,
    ) -> IamResult<Reply<privacy::AudienceOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 tenant,
                 principal,
             }| {
                Box::pin(async move {
                    let directory = may(
                        ctx,
                        &tx,
                        &principal,
                        &tenant.id,
                        "iam:identities:read",
                        &tenant.id,
                    )
                    .await?;
                    let limit = integer_or(body.get("limit"), 1000.0, "limit", 1.0, 1000.0)?;
                    let offset = integer_or(body.get("offset"), 0.0, "offset", 0.0, 10_000_000.0)?;
                    let purpose = purpose_by_key(&tx, &tenant.id, body.get("purposeKey")).await?;
                    let now = ctx.now();
                    let mut consents: IndexMap<String, PrivacyConsent> = IndexMap::new();
                    for consent in decode_all::<PrivacyConsent>(
                        find(
                            &tx,
                            "privacyConsents",
                            Filter::new()
                                .eq("tenantId", tenant.id.clone())
                                .eq("purposeId", purpose.id.clone()),
                        )
                        .await?,
                    )? {
                        consents.insert(consent.subject.clone(), consent);
                    }
                    let restricted: IndexSet<String> = find(
                        &tx,
                        "privacyRestrictions",
                        Filter::new().eq("tenantId", tenant.id.clone()),
                    )
                    .await?
                    .iter()
                    .map(|restriction| s(restriction, "subject").to_owned())
                    .collect();
                    let mut members: Vec<Value> = Vec::new();
                    let mut people: Vec<Record> = find(
                        &tx,
                        "identities",
                        Filter::new().eq("tenantId", tenant.id.clone()),
                    )
                    .await?
                    .into_iter()
                    .filter(|identity| {
                        s(identity, "kind") == "user" && s(identity, "status") == "active"
                    })
                    .collect();
                    people.sort_by(by_id);
                    for person in &people {
                        let key = identity_subject(s(person, "id"))?;
                        let allowed = consent_state(
                            &purpose,
                            consents.get(&key),
                            &Value::Bool(restricted.contains(&key)),
                            now,
                        )?
                        .allowed;
                        if allowed {
                            let mut member = Map::new();
                            member.insert("subject".into(), string(key));
                            copy_as(&mut member, "identityId", person, "id");
                            if directory && truthy(person.get("email")) {
                                copy_member(&mut member, person, "email");
                            }
                            if directory {
                                copy_member(&mut member, person, "name");
                            }
                            members.push(Value::Object(member));
                        }
                    }
                    let mut external: Vec<&PrivacyConsent> = consents.values().collect();
                    external.sort_by(|a, b| core_js::cmp_utf16(&a.subject, &b.subject));
                    for consent in external {
                        let Some(external_id) = &consent.external_id else {
                            continue;
                        };
                        let allowed = consent_state(
                            &purpose,
                            Some(consent),
                            &Value::Bool(restricted.contains(&consent.subject)),
                            now,
                        )?
                        .allowed;
                        if allowed {
                            members.push(json!({
                                "subject": consent.subject,
                                "externalId": external_id,
                            }));
                        }
                    }
                    Ok(json!({
                        "purposeKey": purpose.key,
                        "total": number(members.len() as f64),
                        "subjects": page(&members, offset, limit),
                    }))
                })
            },
        );
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:read",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/listConsents`: current decisions, filtered by purpose, subject or outcome; newest first.
    pub async fn list_consents(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::ListConsentsInput>,
    ) -> IamResult<Reply<privacy::ListConsentsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let limit = integer_or(body.get("limit"), 100.0, "limit", 1.0, 1000.0)?;
                let offset = integer_or(body.get("offset"), 0.0, "offset", 0.0, 10_000_000.0)?;
                let mut purposes: IndexMap<String, PrivacyPurpose> = IndexMap::new();
                for purpose in decode_all::<PrivacyPurpose>(
                    find(
                        &tx,
                        "privacyPurposes",
                        Filter::new().eq("tenantId", tenant.id.clone()),
                    )
                    .await?,
                )? {
                    purposes.insert(purpose.id.clone(), purpose);
                }
                let mut filter = Filter::new().eq("tenantId", tenant.id.clone());
                if let Some(key) = body.get("purposeKey") {
                    filter = filter.eq(
                        "purposeId",
                        purpose_by_key(&tx, &tenant.id, Some(key)).await?.id,
                    );
                }
                if let Some(subject) = body.get("subject") {
                    filter = filter.eq(
                        "subject",
                        resolve_subject(&tx, &tenant.id, Some(subject), Some(true))
                            .await?
                            .key,
                    );
                }
                if let Some(granted) = body.get("granted") {
                    let Value::Bool(granted) = granted else {
                        return Err(invalid_input("granted must be a boolean").into());
                    };
                    filter = filter.eq("granted", *granted);
                }
                let restricted: IndexSet<String> = find(
                    &tx,
                    "privacyRestrictions",
                    Filter::new().eq("tenantId", tenant.id.clone()),
                )
                .await?
                .iter()
                .map(|restriction| s(restriction, "subject").to_owned())
                .collect();
                let now = ctx.now();
                let mut rows: Vec<PrivacyConsent> =
                    decode_all(find(&tx, "privacyConsents", filter).await?)?;
                rows.sort_by(|a, b| {
                    order(b.recorded_at - a.recorded_at)
                        .then_with(|| core_js::cmp_utf16(&a.id, &b.id))
                });
                let mut consents = Vec::new();
                for consent in page(&rows, offset, limit) {
                    if let Some(purpose) = purposes.get(&consent.purpose_id) {
                        consents.push(consent_view(
                            &consent,
                            purpose,
                            restricted.contains(&consent.subject),
                            now,
                        )?);
                    }
                }
                Ok(json!({ "total": number(rows.len() as f64), "consents": consents }))
            })
        });
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:read",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/history`: a subject's decision history (newest first, at most 1 000 entries).
    pub async fn history(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::HistoryInput>,
    ) -> IamResult<Reply<privacy::HistoryOutput>> {
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let subject =
                    resolve_subject(&tx, &tenant.id, body.get("subject"), Some(true)).await?;
                let key = match body.get("purposeKey") {
                    None => None,
                    Some(value) => Some(purpose_key(Some(value))?),
                };
                let events: Vec<PrivacyConsentEvent> = decode_all(
                    find(
                        &tx,
                        "privacyConsentEvents",
                        Filter::new()
                            .eq("tenantId", tenant.id.clone())
                            .eq("subject", subject.key.clone()),
                    )
                    .await?,
                )?;
                Ok(newest_events(events, key.as_deref(), 1000))
            })
        });
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:read",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/verifyReceipt`: checks a consent receipt someone presents: the signature (current or previous
    /// deployment secret), that the decision is in the history with the same content, and whether it is still the
    /// subject's current decision.
    pub async fn verify_receipt(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::VerifyReceiptInput>,
    ) -> IamResult<Reply<privacy::VerifyReceiptOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let receipt = object(body.get("receipt"))?.clone();
                let mut secrets = vec![ctx.options.secret.clone()];
                secrets.extend(ctx.options.previous_secrets.clone().unwrap_or_default());
                let invalid = json!({ "valid": false, "reason": "SIGNATURE_INVALID" });
                if receipt.get("tenantId") != Some(&string(tenant.id.clone())) {
                    return Ok(invalid);
                }
                // A receipt that does not have the receipt's shape cannot carry a valid signature.
                let Ok(typed) = decode::<ConsentReceipt>(receipt.clone()) else {
                    return Ok(invalid);
                };
                if !receipt_signature_valid(&secrets, &typed)? {
                    return Ok(invalid);
                }
                let event = match receipt.get("receiptId") {
                    Some(Value::String(receipt_id)) => {
                        tx.get("privacyConsentEvents", receipt_id).await?
                    }
                    _ => None,
                };
                let event = match event {
                    Some(event) if s(&event, "tenantId") == tenant.id => event,
                    _ => return Ok(json!({ "valid": false, "reason": "NOT_RECORDED" })),
                };
                let event: PrivacyConsentEvent = decode(event)?;
                // Rebuilt with the secret the receipt verified under, so receipts from before a rotation still match.
                let mut rebuilt = None;
                for secret in &secrets {
                    let candidate = receipt_from_event(secret, &event)?;
                    if rebuilt.is_none()
                        && receipt.get("signature") == Some(&string(candidate.signature.clone()))
                    {
                        rebuilt = Some(candidate);
                    }
                }
                let matches = rebuilt.is_some_and(|rebuilt| {
                    canonical_json(&Value::Object(encode(&rebuilt)))
                        == canonical_json(&Value::Object(receipt.clone()))
                });
                if !matches {
                    return Ok(json!({ "valid": false, "reason": "CONTENT_MISMATCH" }));
                }
                let current = consent_for(
                    &tx,
                    &tenant.id,
                    format!("{}:{}", event.purpose_id, event.subject),
                )
                .await?;
                let mut out = Map::new();
                out.insert("valid".into(), Value::Bool(true));
                out.insert(
                    "current".into(),
                    Value::Bool(
                        current.is_some_and(|current| current.receipt_id == event.receipt_id),
                    ),
                );
                if event.redacted == Some(true) {
                    out.insert("redacted".into(), Value::Bool(true));
                }
                Ok(Value::Object(out))
            })
        });
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:read",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    // ── Data-subject requests ─────────────────────────────────────────────────────────────────────────────────

    /// `privacy/createRequest`: files a request on a subject's behalf (received by phone, mail or a support ticket).
    /// With `verified` (how the handler confirmed who is asking) it opens at once; otherwise it waits for
    /// `verifyRequest`.
    pub async fn create_request(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::CreateRequestInput>,
    ) -> IamResult<Reply<privacy::CreateRequestOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 tenant,
                 principal,
             }| {
                Box::pin(async move {
                    let kind =
                        one_of(body.get("type"), &str_values(SUBJECT_REQUEST_TYPES), "type")?;
                    let settings = privacy_settings(&tx, &tenant.id).await?;
                    let regulation = regulation_of(body.get("regulation"), &settings)?;
                    let requester_email = match body.get("requesterEmail") {
                        None => None,
                        Some(value) => Some(email(Some(value))?),
                    };
                    let requester_name = match body.get("requesterName") {
                        None => None,
                        Some(value) => Some(text(Some(value), "requesterName", 200)?),
                    };
                    let subject = match body.get("subject") {
                        Some(subject) => {
                            Some(resolve_subject(&tx, &tenant.id, Some(subject), None).await?)
                        }
                        None => match requester_email.as_ref().filter(|email| !email.is_empty()) {
                            Some(address) => Some(ResolvedSubject {
                                key: email_subject(&ctx.options.secret, address)?,
                                identity_id: None,
                                external_id: None,
                                identity: None,
                                extra: Map::new(),
                            }),
                            None => None,
                        },
                    };
                    let Some(subject) = subject else {
                        return Err(invalid_input(
                            "Name the subject or the requester\u{2019}s email",
                        )
                        .into());
                    };
                    let purpose_keys = purpose_keys_of(body.get("purposeKeys"))?;
                    if let Some(keys) = &purpose_keys {
                        for key in keys {
                            purpose_by_key(&tx, &tenant.id, Some(&string(key.clone()))).await?;
                        }
                    }
                    let now = ctx.now();
                    let request_no = request_number()?;
                    let mut request = Record::new();
                    request.insert("id".into(), string(id()));
                    request.insert("tenantId".into(), string(tenant.id.clone()));
                    request.insert("uniqueKey".into(), string(format!("number:{request_no}")));
                    request.insert("number".into(), string(request_no.clone()));
                    request.insert("type".into(), kind.clone());
                    request.insert("regulation".into(), regulation.clone());
                    request.insert("status".into(), string("pending-verification"));
                    request.insert("subject".into(), string(subject.key.clone()));
                    if let Some(identity_id) =
                        subject.identity_id.as_ref().filter(|id| !id.is_empty())
                    {
                        request.insert("identityId".into(), string(identity_id.clone()));
                    }
                    if let Some(external_id) = &subject.external_id {
                        request.insert("externalId".into(), string(external_id.clone()));
                    }
                    if let Some(address) = requester_email.filter(|email| !email.is_empty()) {
                        request.insert("requesterEmail".into(), string(address));
                    }
                    if let Some(name) = requester_name.filter(|name| !name.is_empty()) {
                        request.insert("requesterName".into(), string(name));
                    }
                    if let Some(details) = body.get("details") {
                        request.insert(
                            "details".into(),
                            string(prose(Some(details), "details", 5000.0)?),
                        );
                    }
                    if let Some(keys) = &purpose_keys {
                        request.insert("purposeKeys".into(), keys_value(keys));
                    }
                    request.insert("channel".into(), string("staff"));
                    request.insert("verification".into(), json!({ "status": "pending" }));
                    request.insert("submittedAt".into(), number(now));
                    request.insert(
                        "events".into(),
                        Value::Array(vec![Value::Object(event_of(
                            now,
                            &principal.identity.id,
                            "submitted",
                            None,
                        ))]),
                    );
                    if let Some(verified) = body.get("verified") {
                        let verified = object(Some(verified))?;
                        let how = text(verified.get("method"), "verified.method", 120)?;
                        request = opened(
                            &request,
                            &settings,
                            now,
                            json!({
                                "status": "verified",
                                "method": how,
                                "verifiedAt": number(now),
                                "verifiedBy": principal.identity.id,
                            }),
                        )?;
                        let note = match verified.get("note") {
                            None => None,
                            Some(note) => Some(prose(Some(note), "verified.note", 2000.0)?),
                        };
                        let events = push_event(
                            &request,
                            event_of(now, &principal.identity.id, "verified", note),
                        );
                        request.insert("events".into(), events);
                    }
                    tx.insert("privacyRequests", &request).await?;
                    if s(&request, "status") == "open" {
                        notify_contact(ctx, &tx, &tenant, &request).await?;
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "privacy:request:submit",
                            &tenant.id,
                            s(&request, "id"),
                            AuditOutcome::Allow,
                            false,
                            audit_metadata(vec![
                                ("number", string(request_no)),
                                ("type", kind),
                                ("regulation", regulation),
                                ("channel", string("staff")),
                            ]),
                        )
                        .await?;
                    Ok(Value::Object(request_view(&request, now, None)?))
                })
            },
        );
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:handle",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/verifyRequest`: records how the requester's identity was confirmed, which starts the response window.
    pub async fn verify_request(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::VerifyRequestInput>,
    ) -> IamResult<Reply<privacy::VerifyRequestOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("requestId"), "requestId", 256)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 tenant,
                 principal,
             }| {
                Box::pin(async move {
                    let request = open_request(ctx, &tx, &tenant.id, body.get("requestId")).await?;
                    if s(&request, "status") != "pending-verification" {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "Only unverified requests can be verified",
                            409,
                        )
                        .into());
                    }
                    let now = ctx.now();
                    let settings = privacy_settings(&tx, &tenant.id).await?;
                    let method = text(body.get("method"), "method", 120)?;
                    let mut verified = opened(
                        &request,
                        &settings,
                        now,
                        json!({
                            "status": "verified",
                            "method": method,
                            "verifiedAt": number(now),
                            "verifiedBy": principal.identity.id,
                        }),
                    )?;
                    let note = match body.get("note") {
                        None => None,
                        Some(note) => Some(prose(Some(note), "note", 2000.0)?),
                    };
                    verified.insert(
                        "events".into(),
                        push_event(
                            &request,
                            event_of(now, &principal.identity.id, "verified", note),
                        ),
                    );
                    tx.put("privacyRequests", &verified).await?;
                    notify_contact(ctx, &tx, &tenant, &verified).await?;
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "privacy:request:verify",
                            &tenant.id,
                            s(&request, "id"),
                            AuditOutcome::Allow,
                            false,
                            audit_metadata(vec![
                                (
                                    "number",
                                    request.get("number").cloned().unwrap_or(Value::Null),
                                ),
                                ("method", string(method)),
                            ]),
                        )
                        .await?;
                    Ok(Value::Object(request_view(&verified, now, None)?))
                })
            },
        );
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:handle",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/linkRequest`: links a request filed by email (someone the intake could not match to an account) to
    /// the account or application subject it is about, once the handler has established that. Linking to an account
    /// also needs `iam:identities:read` on it. Audited as `privacy:request:link`.
    pub async fn link_request(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::LinkRequestInput>,
    ) -> IamResult<Reply<privacy::LinkRequestOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("requestId"), "requestId", 256)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 tenant,
                 principal,
             }| {
                Box::pin(async move {
                    let request = open_request(ctx, &tx, &tenant.id, body.get("requestId")).await?;
                    if !matches!(s(&request, "status"), "open" | "pending-verification") {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "This request is closed",
                            409,
                        )
                        .into());
                    }
                    if !s(&request, "subject").starts_with("email:") {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "This request is already linked to its subject",
                            409,
                        )
                        .into());
                    }
                    let subject =
                        resolve_subject(&tx, &tenant.id, body.get("subject"), None).await?;
                    let identity_id = subject.identity_id.clone().filter(|id| !id.is_empty());
                    if let Some(identity_id) = &identity_id
                        && !may(
                            ctx,
                            &tx,
                            &principal,
                            &tenant.id,
                            "iam:identities:read",
                            identity_id,
                        )
                        .await?
                    {
                        return Err(OperationDenied::new(Some(
                            "Linking a request to an account also needs iam:identities:read",
                        )));
                    }
                    let now = ctx.now();
                    let note = match body.get("note") {
                        None => None,
                        Some(note) => Some(prose(Some(note), "note", 2000.0)?),
                    };
                    let mut linked = request.clone();
                    linked.insert("subject".into(), string(subject.key.clone()));
                    if let Some(identity_id) = &identity_id {
                        linked.insert("identityId".into(), string(identity_id.clone()));
                    }
                    if let Some(external_id) = &subject.external_id {
                        linked.insert("externalId".into(), string(external_id.clone()));
                    }
                    linked.insert(
                        "events".into(),
                        push_event(
                            &request,
                            event_of(
                                now,
                                &principal.identity.id,
                                "linked",
                                note.filter(|note| !note.is_empty()),
                            ),
                        ),
                    );
                    tx.put("privacyRequests", &linked).await?;
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "privacy:request:link",
                            &tenant.id,
                            s(&request, "id"),
                            AuditOutcome::Allow,
                            false,
                            audit_metadata(vec![
                                (
                                    "number",
                                    request.get("number").cloned().unwrap_or(Value::Null),
                                ),
                                (
                                    "subjectKind",
                                    string(if identity_id.is_some() {
                                        "account"
                                    } else {
                                        "external"
                                    }),
                                ),
                            ]),
                        )
                        .await?;
                    Ok(Value::Object(request_view(&linked, now, None)?))
                })
            },
        );
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:handle",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/assignRequest`: hands a request to a handler (a person of the tenant), or clears the assignment with
    /// `null`.
    pub async fn assign_request(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::AssignRequestInput>,
    ) -> IamResult<Reply<privacy::AssignRequestOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("requestId"), "requestId", 256)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 tenant,
                 principal,
             }| {
                Box::pin(async move {
                    let request = open_request(ctx, &tx, &tenant.id, body.get("requestId")).await?;
                    if !matches!(s(&request, "status"), "open" | "pending-verification") {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "This request is closed",
                            409,
                        )
                        .into());
                    }
                    let now = ctx.now();
                    let assignee = match body.get("assigneeId") {
                        Some(Value::Null) => None,
                        other => {
                            let assignee_id = text(other, "assigneeId", 256)?;
                            let assignee =
                                ctx.active_identity(&tx, &assignee_id, &tenant.id).await?;
                            if assignee.kind != IdentityKind::User
                                || assignee.status != better_iam_core::IdentityStatus::Active
                            {
                                return Err(
                                    invalid_input("Assign requests to an active person").into()
                                );
                            }
                            Some(assignee)
                        }
                    };
                    let mut updated = without(&request, &["assigneeId"]);
                    if let Some(assignee) = &assignee {
                        updated.insert("assigneeId".into(), string(assignee.id.clone()));
                    }
                    let note = match &assignee {
                        Some(assignee) => assignee
                            .email
                            .clone()
                            .unwrap_or_else(|| assignee.name.clone()),
                        None => "unassigned".into(),
                    };
                    updated.insert(
                        "events".into(),
                        push_event(
                            &request,
                            event_of(now, &principal.identity.id, "assigned", Some(note)),
                        ),
                    );
                    tx.put("privacyRequests", &updated).await?;
                    Ok(Value::Object(request_view(&updated, now, None)?))
                })
            },
        );
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:handle",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/extendRequest`: extends the response window once by the regulation's extension (GDPR two months, CCPA
    /// 45 days; LGPD allows none), telling the subject why. Audited as `privacy:request:extend`.
    pub async fn extend_request(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::ExtendRequestInput>,
    ) -> IamResult<Reply<privacy::ExtendRequestOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("requestId"), "requestId", 256)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 tenant,
                 principal,
             }| {
                Box::pin(async move {
                    let request = open_request(ctx, &tx, &tenant.id, body.get("requestId")).await?;
                    if s(&request, "status") != "open" || request.get("dueAt").is_none() {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "Only open requests can be extended",
                            409,
                        )
                        .into());
                    }
                    if request.get("extendedAt").is_some() {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "This request was already extended",
                            409,
                        )
                        .into());
                    }
                    let regulation = js_string(request.get("regulation"));
                    let extension = deadline(&regulation, "extensionDays")?;
                    if extension == 0.0 || extension.is_nan() {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            format!("{regulation} allows no extension"),
                            409,
                        )
                        .into());
                    }
                    let reason = prose(body.get("reason"), "reason", 2000.0)?;
                    let now = ctx.now();
                    let due_at = nan_of(&request, "dueAt") + extension * DAY_MS;
                    let mut extended = request.clone();
                    extended.insert("dueAt".into(), number(due_at));
                    extended.insert("extendedAt".into(), number(now));
                    extended.insert("extensionReason".into(), string(reason.clone()));
                    extended.insert("reminded".into(), json!([]));
                    extended.insert(
                        "events".into(),
                        push_event(
                            &request,
                            event_of(now, &principal.identity.id, "extended", Some(reason)),
                        ),
                    );
                    tx.put("privacyRequests", &extended).await?;
                    notify_subject(ctx, &tx, &tenant, &extended, "extended", None).await?;
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "privacy:request:extend",
                            &tenant.id,
                            s(&request, "id"),
                            AuditOutcome::Allow,
                            false,
                            audit_metadata(vec![
                                (
                                    "number",
                                    request.get("number").cloned().unwrap_or(Value::Null),
                                ),
                                ("dueAt", number(due_at)),
                            ]),
                        )
                        .await?;
                    Ok(Value::Object(request_view(&extended, now, None)?))
                })
            },
        );
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:handle",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/addNote`: adds an internal note to a request's timeline (not shown to the subject).
    pub async fn add_note(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::AddNoteInput>,
    ) -> IamResult<Reply<privacy::AddNoteOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("requestId"), "requestId", 256)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 tenant,
                 principal,
             }| {
                Box::pin(async move {
                    let request = open_request(ctx, &tx, &tenant.id, body.get("requestId")).await?;
                    if truthy(request.get("redacted")) {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "This request was redacted",
                            409,
                        )
                        .into());
                    }
                    let now = ctx.now();
                    let note = prose(body.get("note"), "note", 2000.0)?;
                    let mut updated = request.clone();
                    updated.insert(
                        "events".into(),
                        push_event(
                            &request,
                            event_of(now, &principal.identity.id, "note", Some(note)),
                        ),
                    );
                    tx.put("privacyRequests", &updated).await?;
                    Ok(Value::Object(request_view(&updated, now, None)?))
                })
            },
        );
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:handle",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/fulfilRequest`: fulfils an open request. Access and portability build the export (portability: only
    /// what the person provided); erasure deletes the account (which also needs `iam:identities:delete` on it) and
    /// erases privacy records, refused under a legal hold (`LEGAL_HOLD`); restriction restricts processing; objection
    /// and opt-out withdraw the named purposes (or every purpose the person has a say in, opt-out: every opt-out
    /// purpose); rectification is done by hand and needs a `note`. The subject is emailed; audited as
    /// `privacy:request:complete` (and `privacy:erasure`).
    pub async fn fulfil_request(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::FulfilRequestInput>,
    ) -> IamResult<Reply<privacy::FulfilRequestOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("requestId"), "requestId", 256)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 tenant,
                 principal,
             }| {
                Box::pin(async move {
                    let request = open_request(ctx, &tx, &tenant.id, body.get("requestId")).await?;
                    let status = s(&request, "status");
                    if status != "open" {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            if status == "pending-verification" {
                                "Verify who is asking before fulfilling the request"
                            } else {
                                "This request is closed"
                            },
                            409,
                        )
                        .into());
                    }
                    let note = match body.get("note") {
                        None => None,
                        Some(note) => Some(prose(Some(note), "note", 2000.0)?),
                    };
                    let now = ctx.now();
                    let settings = privacy_settings(&tx, &tenant.id).await?;
                    let mut actions: Vec<String> = Vec::new();
                    let mut export_id: Option<String> = None;
                    let mut notify_to: Option<String> = None;
                    let request_type = s(&request, "type").to_owned();
                    let subject_key = s(&request, "subject").to_owned();
                    let request_identity = str_of(&request, "identityId")
                        .filter(|id| !id.is_empty())
                        .map(str::to_owned);
                    let identity_allowed = |action: &'static str| {
                        let (tx, principal, tenant_id, identity) =
                            (&tx, &principal, &tenant.id, request_identity.clone());
                        async move {
                            match identity {
                                None => Ok::<bool, IamError>(true),
                                Some(identity) => {
                                    may(ctx, tx, principal, tenant_id, action, &identity).await
                                }
                            }
                        }
                    };
                    if matches!(request_type.as_str(), "access" | "portability" | "erasure") {
                        // A request from an address nobody linked would answer "nothing held" while an account may exist.
                        if subject_key.starts_with("email:") {
                            return Err(invalid_input(
                            "Link the request to an account or an application subject (linkRequest), or decline it as no-data",
                        )
                        .into());
                        }
                        // Exporting or erasing everything about someone is as sensitive as identities.export / delete.
                        ctx.auth.require_recent(&principal)?;
                    }
                    match request_type.as_str() {
                        "access" | "portability" => {
                            if !identity_allowed("iam:identities:read").await? {
                                return Err(OperationDenied::new(Some(
                                    "Exporting a person\u{2019}s data also needs iam:identities:read",
                                )));
                            }
                            let scope = if request_type == "access" {
                                "full"
                            } else {
                                "provided"
                            };
                            let audit_allowed = may(
                                ctx,
                                &tx,
                                &principal,
                                &tenant.id,
                                "iam:audit:read",
                                &tenant.id,
                            )
                            .await?;
                            let data =
                                build_export(ctx, &tx, &tenant, &request, scope, audit_allowed)
                                    .await?;
                            let new_id = id();
                            let mut item = Record::new();
                            item.insert("id".into(), string(new_id.clone()));
                            item.insert("tenantId".into(), string(tenant.id.clone()));
                            copy_as(&mut item, "requestId", &request, "id");
                            item.insert("subject".into(), string(subject_key.clone()));
                            if let Some(identity_id) = &request_identity {
                                item.insert("identityId".into(), string(identity_id.clone()));
                            }
                            item.insert("scope".into(), string(scope));
                            item.insert("createdAt".into(), number(now));
                            item.insert(
                                "expiresAt".into(),
                                number(now + settings.export_lifetime_days * DAY_MS),
                            );
                            item.insert("sha256".into(), string(hash(&canonical_json(&data))));
                            item.insert("data".into(), data);
                            item.insert("downloads".into(), number(0.0));
                            tx.insert("privacyExports", &item).await?;
                            export_id = Some(new_id);
                            actions.push(format!("export:{scope}"));
                        }
                        "erasure" => {
                            if active_hold(&tx, &tenant.id, &subject_key, now)
                                .await?
                                .is_some()
                            {
                                return Err(IamError::with_status(
                                "LEGAL_HOLD",
                                "This subject is under a legal hold; release it or reject the request as exempt",
                                409,
                            )
                            .into());
                            }
                            if !identity_allowed("iam:identities:delete").await? {
                                return Err(OperationDenied::new(Some(
                                    "Erasing an account also needs iam:identities:delete",
                                )));
                            }
                            notify_to = subject_address(&tx, &request).await?;
                            actions.extend(
                                erase_subject(ctx, &tx, &principal, &tenant, &request).await?,
                            );
                        }
                        "restriction" => {
                            if subject_key.starts_with("email:") {
                                return Err(invalid_input(
                                "Link the request to an account or an application subject before restricting processing",
                            )
                            .into());
                            }
                            if restriction_of(&tx, &tenant.id, &subject_key)
                                .await?
                                .is_none()
                            {
                                let mut restriction = Record::new();
                                restriction.insert("id".into(), string(id()));
                                restriction.insert("tenantId".into(), string(tenant.id.clone()));
                                restriction.insert("subject".into(), string(subject_key.clone()));
                                if let Some(identity_id) = &request_identity {
                                    restriction
                                        .insert("identityId".into(), string(identity_id.clone()));
                                }
                                copy_member(&mut restriction, &request, "externalId");
                                copy_as(&mut restriction, "requestId", &request, "id");
                                restriction.insert("restrictedAt".into(), number(now));
                                restriction.insert(
                                    "restrictedBy".into(),
                                    string(principal.identity.id.clone()),
                                );
                                tx.insert("privacyRestrictions", &restriction).await?;
                            }
                            actions.push("restricted".into());
                        }
                        "objection" | "opt-out" => {
                            if subject_key.starts_with("email:") {
                                return Err(invalid_input(
                                "Link the request to an account or an application subject before withdrawing consent",
                            )
                            .into());
                            }
                            let all: Vec<PrivacyPurpose> = decode_all(
                                find(
                                    &tx,
                                    "privacyPurposes",
                                    Filter::new().eq("tenantId", tenant.id.clone()),
                                )
                                .await?,
                            )?;
                            let named: Vec<String> = request
                                .get("purposeKeys")
                                .and_then(Value::as_array)
                                .map(|keys| {
                                    keys.iter()
                                        .filter_map(|key| key.as_str().map(str::to_owned))
                                        .collect()
                                })
                                .unwrap_or_default();
                            let has_named = request
                                .get("purposeKeys")
                                .and_then(Value::as_array)
                                .is_some_and(|keys| !keys.is_empty());
                            let mut targets = Vec::new();
                            for purpose in all {
                                let target = if has_named {
                                    named.contains(&purpose.key)
                                } else if request_type == "opt-out" {
                                    purpose.legal_basis.as_str() == Some("consent")
                                        && purpose.mode.as_str() == Some("opt-out")
                                } else {
                                    decidable_purpose(&purpose)?
                                };
                                if target {
                                    targets.push(purpose);
                                }
                            }
                            let subject = ResolvedSubject {
                                key: subject_key.clone(),
                                identity_id: request_identity.clone(),
                                external_id: str_of(&request, "externalId")
                                    .map(str::to_owned)
                                    .or_else(|| {
                                        request
                                            .get("externalId")
                                            .map(|value| js_string(Some(value)))
                                    }),
                                identity: None,
                                extra: Map::new(),
                            };
                            let method = format!("request:{}", js_string(request.get("number")));
                            let mut withdrawn = 0;
                            for purpose in &targets {
                                if !decidable_purpose(purpose)? {
                                    continue;
                                }
                                write_consent(
                                    ctx,
                                    &tx,
                                    ConsentWrite {
                                        tenant_id: &tenant.id,
                                        purpose,
                                        subject: &subject,
                                        granted: false,
                                        source: "request",
                                        method: Some(method.clone()),
                                        evidence: None,
                                        recorded_by: &principal.identity.id,
                                        at: now,
                                        version: None,
                                        client: None,
                                    },
                                )
                                .await?;
                                withdrawn += 1;
                            }
                            actions.push(format!("consents-withdrawn:{withdrawn}"));
                        }
                        "rectification" => {
                            if note.as_ref().is_none_or(|note| note.is_empty()) {
                                return Err(invalid_input(
                                    "Describe what was corrected in the note",
                                )
                                .into());
                            }
                            actions.push("rectified".into());
                        }
                        _ => {}
                    }
                    let base = if request_type == "erasure" {
                        redact(&request)
                    } else {
                        request.clone()
                    };
                    let mut completed = base.clone();
                    completed.insert("status".into(), string("completed"));
                    completed.insert("closedAt".into(), number(now));
                    completed.insert("closedBy".into(), string(principal.identity.id.clone()));
                    completed.insert("actions".into(), keys_value(&actions));
                    if let Some(export_id) = &export_id {
                        completed.insert("exportId".into(), string(export_id.clone()));
                    }
                    let completion_note = note
                        .clone()
                        .filter(|note| !note.is_empty() && request_type != "erasure");
                    completed.insert(
                        "events".into(),
                        push_event(
                            &base,
                            event_of(now, &principal.identity.id, "completed", completion_note),
                        ),
                    );
                    tx.put("privacyRequests", &completed).await?;
                    notify_subject(ctx, &tx, &tenant, &completed, "completed", notify_to).await?;
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "privacy:request:complete",
                            &tenant.id,
                            s(&request, "id"),
                            AuditOutcome::Allow,
                            false,
                            audit_metadata(vec![
                                (
                                    "number",
                                    request.get("number").cloned().unwrap_or(Value::Null),
                                ),
                                ("type", request.get("type").cloned().unwrap_or(Value::Null)),
                                ("actions", keys_value(&actions)),
                            ]),
                        )
                        .await?;
                    if request_type == "erasure" {
                        let mut metadata = vec![
                            (
                                "requestId",
                                request.get("id").cloned().unwrap_or(Value::Null),
                            ),
                            (
                                "subjectKind",
                                string(if request_identity.is_some() {
                                    "account"
                                } else if request.get("externalId").is_some() {
                                    "external"
                                } else {
                                    "requester"
                                }),
                            ),
                        ];
                        if let Some(external_id) = request.get("externalId") {
                            metadata.push(("externalId", external_id.clone()));
                        }
                        let resource_id = defined(request.get("identityId"))
                            .map(|value| js_string(Some(value)))
                            .unwrap_or_else(|| subject_key.clone());
                        ctx.events()?
                            .audit(
                                &tx,
                                &principal,
                                "privacy:erasure",
                                &tenant.id,
                                &resource_id,
                                AuditOutcome::Allow,
                                false,
                                audit_metadata(metadata),
                            )
                            .await?;
                    }
                    Ok(Value::Object(request_view(&completed, now, None)?))
                })
            },
        );
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:handle",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/rejectRequest`: refuses a request (`unverified`, `unfounded`, `excessive`, `exempt`, `duplicate`,
    /// `other`) with a note the subject is told. Audited as `privacy:request:reject`.
    pub async fn reject_request(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::RejectRequestInput>,
    ) -> IamResult<Reply<privacy::RejectRequestOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("requestId"), "requestId", 256)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 tenant,
                 principal,
             }| {
                Box::pin(async move {
                    let request = open_request(ctx, &tx, &tenant.id, body.get("requestId")).await?;
                    if !matches!(s(&request, "status"), "open" | "pending-verification") {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "This request is closed",
                            409,
                        )
                        .into());
                    }
                    let reason =
                        one_of(body.get("reason"), &str_values(REJECTION_REASONS), "reason")?;
                    let now = ctx.now();
                    let note = match body.get("note") {
                        None => None,
                        Some(note) => Some(prose(Some(note), "note", 2000.0)?),
                    };
                    let mut rejected = without(&request, &["tokenHash", "tokenExpiresAt"]);
                    rejected.insert("status".into(), string("rejected"));
                    rejected.insert("rejectionReason".into(), reason.clone());
                    rejected.insert("closedAt".into(), number(now));
                    rejected.insert("closedBy".into(), string(principal.identity.id.clone()));
                    rejected.insert(
                        "events".into(),
                        push_event(
                            &request,
                            event_of(now, &principal.identity.id, "rejected", note),
                        ),
                    );
                    tx.put("privacyRequests", &rejected).await?;
                    notify_subject(ctx, &tx, &tenant, &rejected, "rejected", None).await?;
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "privacy:request:reject",
                            &tenant.id,
                            s(&request, "id"),
                            AuditOutcome::Allow,
                            false,
                            audit_metadata(vec![
                                (
                                    "number",
                                    request.get("number").cloned().unwrap_or(Value::Null),
                                ),
                                ("type", request.get("type").cloned().unwrap_or(Value::Null)),
                                ("reason", reason),
                            ]),
                        )
                        .await?;
                    Ok(Value::Object(request_view(&rejected, now, None)?))
                })
            },
        );
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:handle",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/listRequests`: requests, filtered by status, type, assignee or `overdue`; open ones by deadline, then
    /// newest first.
    pub async fn list_requests(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::ListRequestsInput>,
    ) -> IamResult<Reply<privacy::ListRequestsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let limit = integer_or(body.get("limit"), 100.0, "limit", 1.0, 500.0)?;
                let offset = integer_or(body.get("offset"), 0.0, "offset", 0.0, 10_000_000.0)?;
                let mut filter = Filter::new().eq("tenantId", tenant.id.clone());
                if let Some(status) = body.get("status") {
                    filter = filter.eq(
                        "status",
                        one_of(
                            Some(status),
                            &str_values(&[
                                "pending-verification",
                                "open",
                                "completed",
                                "rejected",
                                "cancelled",
                            ]),
                            "status",
                        )?,
                    );
                }
                if let Some(kind) = body.get("type") {
                    filter = filter.eq(
                        "type",
                        one_of(Some(kind), &str_values(SUBJECT_REQUEST_TYPES), "type")?,
                    );
                }
                if let Some(assignee) = body.get("assigneeId") {
                    filter = filter.eq("assigneeId", text(Some(assignee), "assigneeId", 256)?);
                }
                if let Some(subject) = body.get("subject") {
                    filter = filter.eq(
                        "subject",
                        resolve_subject(&tx, &tenant.id, Some(subject), Some(true))
                            .await?
                            .key,
                    );
                }
                let now = ctx.now();
                let only_overdue = body.get("overdue") == Some(&Value::Bool(true));
                let mut rows = Vec::new();
                for request in find(&tx, "privacyRequests", filter).await? {
                    if !only_overdue || overdue(&request, now)? {
                        rows.push(request);
                    }
                }
                rows.sort_by(|a, b| {
                    let a_open = s(a, "status") == "open";
                    let b_open = s(b, "status") == "open";
                    b_open
                        .cmp(&a_open)
                        .then_with(|| {
                            if a_open && b_open {
                                order(
                                    num_of(a, "dueAt").unwrap_or(0.0)
                                        - num_of(b, "dueAt").unwrap_or(0.0),
                                )
                            } else {
                                order(nan_of(b, "submittedAt") - nan_of(a, "submittedAt"))
                            }
                        })
                        .then_with(|| by_id(a, b))
                });
                let current = page(&rows, offset, limit);
                let names = subject_names(&tx, &current).await?;
                let mut requests = Vec::new();
                for request in &current {
                    let name = if truthy(request.get("identityId")) {
                        names.get(s(request, "identityId")).map(String::as_str)
                    } else {
                        None
                    };
                    requests.push(Value::Object(request_view(request, now, name)?));
                }
                Ok(json!({ "total": number(rows.len() as f64), "requests": requests }))
            })
        });
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:read",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/getRequest`.
    pub async fn get_request(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::GetRequestInput>,
    ) -> IamResult<Reply<privacy::GetRequestOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("requestId"), "requestId", 256)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let request = open_request(ctx, &tx, &tenant.id, body.get("requestId")).await?;
                let names = subject_names(&tx, std::slice::from_ref(&request)).await?;
                let subject = s(&request, "subject").to_owned();
                let hold = active_hold(&tx, &tenant.id, &subject, ctx.now()).await?;
                let name = if truthy(request.get("identityId")) {
                    names.get(s(&request, "identityId")).map(String::as_str)
                } else {
                    None
                };
                let mut view = request_view(&request, ctx.now(), name)?;
                view.insert("legalHold".into(), Value::Bool(hold.is_some()));
                view.insert(
                    "restricted".into(),
                    Value::Bool(restriction_of(&tx, &tenant.id, &subject).await?.is_some()),
                );
                Ok(Value::Object(view))
            })
        });
        let result = self
            .operate(credential, &input, "iam:privacy:read", &resource, mutation)
            .await?;
        Ok(Reply::json(result))
    }

    // ── Public intake ─────────────────────────────────────────────────────────────────────────────────────────

    /// `privacy/submitPublic` (public: no credential): public request form for people without an account (or who
    /// cannot sign in), when the organization turned on `publicIntake`. The requester confirms their email address
    /// through the emailed link (`confirmPublic`) before anyone handles it; unconfirmed requests lapse after seven
    /// days. Rate limited per organization and address.
    pub async fn submit_public(
        &self,
        input: Body<privacy::SubmitPublicInput>,
    ) -> IamResult<Reply<privacy::SubmitPublicOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let address = email(input.get("email"))?;
        let kind = one_of(
            input.get("type"),
            &str_values(SUBJECT_REQUEST_TYPES),
            "type",
        )?;
        let details = match input.get("details") {
            None => None,
            Some(value) => Some(prose(Some(value), "details", 5000.0)?),
        };
        let name = match input.get("name") {
            None => None,
            Some(value) => Some(text(Some(value), "name", 200)?),
        };
        let external_id = match input.get("externalId") {
            None => None,
            Some(value) => Some(external_subject_id(Some(value))?),
        };
        let purpose_keys = purpose_keys_of(input.get("purposeKeys"))?;
        // Counted outside the transaction, so a refusal cannot roll the counters back.
        // The per-address budget is the main control (with the per-IP counter when `rateLimits.ipAttempts` is on); the
        // organization-wide one only caps floods, so it is generous enough that one sender cannot lock others out.
        ctx.auth
            .limit_attempt(
                &tenant_id,
                "privacy-intake",
                LimitAttemptOptions {
                    limit: Some(500.0),
                    ..LimitAttemptOptions::default()
                },
            )
            .await?;
        ctx.auth
            .limit_attempt(
                &tenant_id,
                &format!("privacy-intake:{address}"),
                LimitAttemptOptions {
                    limit: Some(3.0),
                    ..LimitAttemptOptions::default()
                },
            )
            .await?;
        let (tenant_id, address, body) = (&tenant_id, &address, &input);
        let (kind, details, name, external_id, purpose_keys) =
            (&kind, &details, &name, &external_id, &purpose_keys);
        let result = ctx
            .store
            .transaction(|tx| async move {
                let tenant = tx.get("tenants", tenant_id).await?;
                let settings = match &tenant {
                    Some(_) => Some(privacy_settings(&tx, tenant_id).await?),
                    None => None,
                };
                let (tenant, settings) = match (tenant, settings) {
                    (Some(tenant), Some(settings))
                        if s(&tenant, "status") == "active" && settings.public_intake =>
                    {
                        (tenant, settings)
                    }
                    _ => return Err(IamError::with_status("NOT_FOUND", "Not found", 404)),
                };
                if !can_email(ctx) {
                    return Err(IamError::new(
                        "DELIVERY_REQUIRED",
                        "Public requests need an email delivery callback",
                    ));
                }
                if let Some(keys) = purpose_keys {
                    for key in keys {
                        purpose_by_key(&tx, tenant_id, Some(&string(key.clone()))).await?;
                    }
                }
                let now = ctx.now();
                let request_no = request_number()?;
                let secret = token();
                let regulation = regulation_of(body.get("regulation"), &settings)?;
                let mut request = Record::new();
                request.insert("id".into(), string(id()));
                request.insert("tenantId".into(), string(tenant_id.clone()));
                request.insert("uniqueKey".into(), string(format!("number:{request_no}")));
                request.insert("number".into(), string(request_no.clone()));
                request.insert("type".into(), kind.clone());
                request.insert("regulation".into(), regulation.clone());
                request.insert("status".into(), string("pending-verification"));
                request.insert(
                    "subject".into(),
                    string(match external_id {
                        Some(external_id) => format!("external:{external_id}"),
                        None => email_subject(&ctx.options.secret, address)?,
                    }),
                );
                if let Some(external_id) = external_id {
                    request.insert("externalId".into(), string(external_id.clone()));
                }
                request.insert("requesterEmail".into(), string(address.clone()));
                if let Some(name) = name.as_ref().filter(|name| !name.is_empty()) {
                    request.insert("requesterName".into(), string(name.clone()));
                }
                if let Some(details) = details.as_ref().filter(|details| !details.is_empty()) {
                    request.insert("details".into(), string(details.clone()));
                }
                if let Some(keys) = purpose_keys {
                    request.insert("purposeKeys".into(), keys_value(keys));
                }
                request.insert("channel".into(), string("public"));
                request.insert("verification".into(), json!({ "status": "pending" }));
                request.insert("tokenHash".into(), string(hash(&secret)));
                request.insert(
                    "tokenExpiresAt".into(),
                    number(now + VERIFICATION_LIFETIME_MS),
                );
                request.insert("submittedAt".into(), number(now));
                request.insert(
                    "events".into(),
                    json!([
                        event_of(now, "requester", "submitted", None),
                        event_of(now, "requester", "verification-sent", None),
                    ]),
                );
                tx.insert("privacyRequests", &request).await?;
                let mut payload = Map::new();
                payload.insert("tenantId".into(), string(tenant_id.clone()));
                copy_as(&mut payload, "tenantName", &tenant, "name");
                copy_as(&mut payload, "requestId", &request, "id");
                payload.insert("number".into(), string(request_no.clone()));
                payload.insert("type".into(), kind.clone());
                payload.insert("token".into(), string(secret));
                enqueue_email(
                    ctx,
                    &tx,
                    tenant_id,
                    address.clone(),
                    "privacy-request-verify",
                    payload,
                )
                .await?;
                let mut event = Record::new();
                event.insert("id".into(), string(id()));
                event.insert("tenantId".into(), string(tenant_id.clone()));
                event.insert("actorId".into(), string("public-intake"));
                event.insert("action".into(), string("privacy:request:submit"));
                copy_as(&mut event, "resourceId", &request, "id");
                event.insert("timestamp".into(), number(now));
                event.insert("outcome".into(), string("allow"));
                event.insert(
                    "metadata".into(),
                    json!({
                        "number": request_no,
                        "type": kind,
                        "regulation": regulation,
                        "channel": "public",
                    }),
                );
                ctx.events()?.record_audit(&tx, &event).await?;
                Ok(json!({ "number": request_no, "status": "pending-verification" }))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/confirmPublic` (public: no credential): confirms a public request from the emailed link. The response
    /// window starts now; when the address belongs to a person here with a verified email, the request is linked to
    /// their account. A request naming an application identifier (`externalId`) stays unverified: owning the address
    /// does not prove owning the identifier, so a handler checks it (`verifyRequest`) before anything is exported,
    /// withdrawn or erased.
    pub async fn confirm_public(
        &self,
        input: Body<privacy::ConfirmPublicInput>,
    ) -> IamResult<Reply<privacy::ConfirmPublicOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let request_id = text(input.get("requestId"), "requestId", 256)?;
        let presented = text(input.get("token"), "token", 512)?;
        ctx.auth
            .limit_attempt(
                &tenant_id,
                &format!("privacy-confirm:{request_id}"),
                LimitAttemptOptions {
                    limit: Some(10.0),
                    ..LimitAttemptOptions::default()
                },
            )
            .await?;
        let (tenant_id, request_id, presented) = (&tenant_id, &request_id, &presented);
        let result = ctx
            .store
            .transaction(|tx| async move {
                let request = tx.get("privacyRequests", request_id).await?;
                let now = ctx.now();
                let request = match request {
                    Some(request)
                        if s(&request, "tenantId") == tenant_id.as_str()
                            && s(&request, "status") == "pending-verification"
                            && truthy(request.get("tokenHash"))
                            && same_hash(s(&request, "tokenHash"), &hash(presented))
                            && num_of(&request, "tokenExpiresAt").unwrap_or(0.0) > now =>
                    {
                        request
                    }
                    _ => {
                        return Err(IamError::with_status(
                            "CONFIRMATION_INVALID",
                            "This confirmation link is invalid or has expired",
                            400,
                        ));
                    }
                };
                let tenant = ctx.tenant(&tx, tenant_id).await?;
                let settings = privacy_settings(&tx, tenant_id).await?;
                if request.get("externalId").is_some() {
                    let mut confirmed = without(&request, &["tokenHash", "tokenExpiresAt"]);
                    confirmed.insert("emailConfirmedAt".into(), number(now));
                    confirmed.insert(
                        "events".into(),
                        push_event(
                            &request,
                            event_of(
                                now,
                                "requester",
                                "email-confirmed",
                                Some(
                                    "The address is confirmed; a handler must still confirm the identifier"
                                        .into(),
                                ),
                            ),
                        ),
                    );
                    tx.put("privacyRequests", &confirmed).await?;
                    notify_contact(ctx, &tx, &tenant, &confirmed).await?;
                    let mut event = Record::new();
                    event.insert("id".into(), string(id()));
                    event.insert("tenantId".into(), string(tenant_id.clone()));
                    event.insert("actorId".into(), string("public-intake"));
                    event.insert("action".into(), string("privacy:request:email-confirmed"));
                    copy_as(&mut event, "resourceId", &request, "id");
                    event.insert("timestamp".into(), number(now));
                    event.insert("outcome".into(), string("allow"));
                    let mut metadata = Map::new();
                    copy_member(&mut metadata, &request, "number");
                    event.insert("metadata".into(), Value::Object(metadata));
                    ctx.events()?.record_audit(&tx, &event).await?;
                    let mut out = Map::new();
                    copy_member(&mut out, &confirmed, "number");
                    copy_member(&mut out, &confirmed, "status");
                    return Ok(Value::Object(out));
                }
                let mut linked = request.clone();
                if truthy(request.get("requesterEmail")) {
                    let person = find(
                        &tx,
                        "identities",
                        Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("email", s(&request, "requesterEmail").to_owned()),
                    )
                    .await?
                    .into_iter()
                    .find(|identity| {
                        s(identity, "kind") == "user"
                            && s(identity, "status") != "deleted"
                            && truthy(identity.get("emailVerified"))
                    });
                    if let Some(person) = person {
                        linked.insert(
                            "subject".into(),
                            string(identity_subject(s(&person, "id"))?),
                        );
                        copy_as(&mut linked, "identityId", &person, "id");
                    }
                }
                let mut verified = opened(
                    &linked,
                    &settings,
                    now,
                    json!({
                        "status": "verified",
                        "method": "email-link",
                        "verifiedAt": number(now),
                    }),
                )?;
                verified.insert(
                    "events".into(),
                    push_event(&request, event_of(now, "requester", "verified", None)),
                );
                tx.put("privacyRequests", &verified).await?;
                notify_contact(ctx, &tx, &tenant, &verified).await?;
                let mut event = Record::new();
                event.insert("id".into(), string(id()));
                event.insert("tenantId".into(), string(tenant_id.clone()));
                event.insert("actorId".into(), string("public-intake"));
                event.insert("action".into(), string("privacy:request:verify"));
                copy_as(&mut event, "resourceId", &request, "id");
                event.insert("timestamp".into(), number(now));
                event.insert("outcome".into(), string("allow"));
                let mut metadata = Map::new();
                copy_member(&mut metadata, &request, "number");
                metadata.insert("method".into(), string("email-link"));
                metadata.insert(
                    "linked".into(),
                    Value::Bool(truthy(verified.get("identityId"))),
                );
                event.insert("metadata".into(), Value::Object(metadata));
                ctx.events()?.record_audit(&tx, &event).await?;
                let mut out = Map::new();
                copy_member(&mut out, &verified, "number");
                copy_member(&mut out, &verified, "status");
                copy_member(&mut out, &verified, "dueAt");
                Ok(Value::Object(out))
            })
            .await?;
        Ok(Reply::json(result))
    }

    // ── Holds and restriction ─────────────────────────────────────────────────────────────────────────────────

    /// `privacy/placeHold`: places a legal hold: erasure of the subject (and deletion of their account) is refused
    /// until it is released.
    pub async fn place_hold(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::PlaceHoldInput>,
    ) -> IamResult<Reply<privacy::PlaceHoldOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 tenant,
                 principal,
             }| {
                Box::pin(async move {
                    let subject =
                        resolve_subject(&tx, &tenant.id, body.get("subject"), None).await?;
                    let now = ctx.now();
                    let expires_at = match body.get("expiresAt") {
                        None => None,
                        Some(value) => Some(ctx.binding_expiry(Some(value))?),
                    };
                    let mut hold = Record::new();
                    hold.insert("id".into(), string(id()));
                    hold.insert("tenantId".into(), string(tenant.id.clone()));
                    hold.insert("subject".into(), string(subject.key.clone()));
                    if let Some(identity_id) =
                        subject.identity_id.as_ref().filter(|id| !id.is_empty())
                    {
                        hold.insert("identityId".into(), string(identity_id.clone()));
                    }
                    if let Some(external_id) = &subject.external_id {
                        hold.insert("externalId".into(), string(external_id.clone()));
                    }
                    hold.insert(
                        "reason".into(),
                        string(prose(body.get("reason"), "reason", 2000.0)?),
                    );
                    hold.insert("placedBy".into(), string(principal.identity.id.clone()));
                    hold.insert("placedAt".into(), number(now));
                    if let Some(expires_at) = expires_at {
                        hold.insert("expiresAt".into(), number(expires_at));
                    }
                    tx.insert("privacyHolds", &hold).await?;
                    let mut metadata =
                        vec![("holdId", hold.get("id").cloned().unwrap_or(Value::Null))];
                    if let Some(expires_at) = expires_at {
                        metadata.push(("expiresAt", number(expires_at)));
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "privacy:hold:place",
                            &tenant.id,
                            subject.identity_id.as_deref().unwrap_or(&subject.key),
                            AuditOutcome::Allow,
                            false,
                            audit_metadata(metadata),
                        )
                        .await?;
                    Ok(Value::Object(hold))
                })
            },
        );
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:manage",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/releaseHold`.
    pub async fn release_hold(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::ReleaseHoldInput>,
    ) -> IamResult<Reply<privacy::ReleaseHoldOutput>> {
        let ctx = &self.ctx;
        let resource = text(input.get("holdId"), "holdId", 256)?;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 tenant,
                 principal,
             }| {
                Box::pin(async move {
                    let hold = ctx
                        .scoped(&tx, "privacyHolds", body.get("holdId"), &tenant.id)
                        .await?;
                    tx.delete("privacyHolds", s(&hold, "id")).await?;
                    let resource_id = defined(hold.get("identityId"))
                        .or_else(|| hold.get("subject"))
                        .map(|value| js_string(Some(value)))
                        .unwrap_or_default();
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "privacy:hold:release",
                            &tenant.id,
                            &resource_id,
                            AuditOutcome::Allow,
                            false,
                            audit_metadata(vec![(
                                "holdId",
                                hold.get("id").cloned().unwrap_or(Value::Null),
                            )]),
                        )
                        .await?;
                    Ok(json!({ "released": true }))
                })
            },
        );
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:manage",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/listHolds`.
    pub async fn list_holds(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::ListHoldsInput>,
    ) -> IamResult<Reply<privacy::ListHoldsOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let now = ctx.now();
                let mut holds: Vec<Record> = find(
                    &tx,
                    "privacyHolds",
                    Filter::new().eq("tenantId", tenant.id.clone()),
                )
                .await?
                .into_iter()
                .map(|mut hold| {
                    let active = match hold.get("expiresAt") {
                        None => true,
                        Some(value) => core_js::as_number(value).is_some_and(|at| at > now),
                    };
                    hold.insert("active".into(), Value::Bool(active));
                    hold
                })
                .collect();
                holds.sort_by(|a, b| order(nan_of(b, "placedAt") - nan_of(a, "placedAt")));
                Ok(Value::Array(holds.into_iter().map(Value::Object).collect()))
            })
        });
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:read",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/listRestrictions`: subjects whose processing is restricted.
    pub async fn list_restrictions(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::ListRestrictionsInput>,
    ) -> IamResult<Reply<privacy::ListRestrictionsOutput>> {
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let mut restrictions = find(
                    &tx,
                    "privacyRestrictions",
                    Filter::new().eq("tenantId", tenant.id.clone()),
                )
                .await?;
                restrictions
                    .sort_by(|a, b| order(nan_of(b, "restrictedAt") - nan_of(a, "restrictedAt")));
                Ok(Value::Array(
                    restrictions.into_iter().map(Value::Object).collect(),
                ))
            })
        });
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:read",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/liftRestriction`: ends a restriction of processing (the subject should be told before it ends).
    pub async fn lift_restriction(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::LiftRestrictionInput>,
    ) -> IamResult<Reply<privacy::LiftRestrictionOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 tenant,
                 principal,
             }| {
                Box::pin(async move {
                    let subject =
                        resolve_subject(&tx, &tenant.id, body.get("subject"), Some(true)).await?;
                    let Some(restriction) = restriction_of(&tx, &tenant.id, &subject.key).await?
                    else {
                        return Err(IamError::with_status(
                            "NOT_FOUND",
                            "No restriction for this subject",
                            404,
                        )
                        .into());
                    };
                    tx.delete("privacyRestrictions", &restriction.id).await?;
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "privacy:restriction:lift",
                            &tenant.id,
                            subject.identity_id.as_deref().unwrap_or(&subject.key),
                            AuditOutcome::Allow,
                            false,
                            None,
                        )
                        .await?;
                    Ok(json!({ "lifted": true }))
                })
            },
        );
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:handle",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    // ── Settings and reporting ────────────────────────────────────────────────────────────────────────────────

    /// `privacy/getSettings`.
    pub async fn get_settings(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::GetSettingsInput>,
    ) -> IamResult<Reply<privacy::GetSettingsOutput>> {
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let settings = privacy_settings(&tx, &tenant.id).await?;
                Ok(settings_view(&encode(&settings)))
            })
        });
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:read",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/updateSettings`: updates the privacy contact, the default regulation, shorter internal response
    /// windows, public intake and how long exports stay downloadable. `null` clears an optional field.
    pub async fn update_settings(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::UpdateSettingsInput>,
    ) -> IamResult<Reply<privacy::UpdateSettingsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let settings_id = format!("privacy:{}", tenant.id);
                // `privacySettings(tx, tenantId)`: the stored record, or `defaultPrivacySettings(tenantId)`.
                let stored = tx.get("privacySettings", &settings_id).await?;
                let previous = match &stored {
                    Some(record) => record.clone(),
                    None => {
                        let mut record = Record::new();
                        record.insert("id".into(), string(settings_id.clone()));
                        record.insert("tenantId".into(), string(tenant.id.clone()));
                        record.insert("defaultRegulation".into(), string("gdpr"));
                        record.insert("publicIntake".into(), Value::Bool(false));
                        record.insert("exportLifetimeDays".into(), number(14.0));
                        record.insert("updatedAt".into(), number(0.0));
                        record
                    }
                };
                let mut next = previous;
                next.insert("updatedAt".into(), number(ctx.now()));
                match body.get("contactEmail") {
                    Some(Value::Null) => {
                        next.shift_remove("contactEmail");
                    }
                    Some(value) => {
                        next.insert("contactEmail".into(), string(email(Some(value))?));
                    }
                    None => {}
                }
                match body.get("contactName") {
                    Some(Value::Null) => {
                        next.shift_remove("contactName");
                    }
                    Some(value) => {
                        next.insert(
                            "contactName".into(),
                            string(text(Some(value), "contactName", 200)?),
                        );
                    }
                    None => {}
                }
                if let Some(value) = body.get("defaultRegulation") {
                    next.insert(
                        "defaultRegulation".into(),
                        one_of(Some(value), &regulations()?, "defaultRegulation")?,
                    );
                }
                match body.get("responseDays") {
                    Some(Value::Null) => {
                        next.shift_remove("responseDays");
                    }
                    Some(value) => {
                        let entries = object(Some(value))?;
                        let mut result = Map::new();
                        for (key, value) in entries {
                            let regulation = one_of(
                                Some(&string(key.clone())),
                                &regulations()?,
                                "responseDays key",
                            )?;
                            let regulation = js_string(Some(&regulation));
                            let max = deadline(&regulation, "responseDays")?;
                            let days = integer(
                                Some(value),
                                &format!("responseDays.{regulation}"),
                                1.0,
                                max,
                            )?;
                            result.insert(regulation, number(days));
                        }
                        if result.is_empty() {
                            next.shift_remove("responseDays");
                        } else {
                            next.insert("responseDays".into(), Value::Object(result));
                        }
                    }
                    None => {}
                }
                if let Some(value) = body.get("publicIntake") {
                    let Value::Bool(public_intake) = value else {
                        return Err(invalid_input("publicIntake must be a boolean").into());
                    };
                    if *public_intake && !can_email(ctx) {
                        return Err(IamError::new(
                            "DELIVERY_REQUIRED",
                            "Public requests need an email delivery callback to confirm addresses",
                        )
                        .into());
                    }
                    next.insert("publicIntake".into(), Value::Bool(*public_intake));
                }
                if let Some(value) = body.get("exportLifetimeDays") {
                    next.insert(
                        "exportLifetimeDays".into(),
                        number(integer(Some(value), "exportLifetimeDays", 1.0, 90.0)?),
                    );
                }
                if tx.get("privacySettings", s(&next, "id")).await?.is_some() {
                    tx.put("privacySettings", &next).await?;
                } else {
                    tx.insert("privacySettings", &next).await?;
                }
                Ok(settings_view(&next))
            })
        });
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:manage",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `privacy/summary`: consent counts per purpose, the request queue, holds and restrictions at a glance.
    pub async fn summary(
        &self,
        credential: &CredentialInput,
        input: Body<privacy::SummaryInput>,
    ) -> IamResult<Reply<privacy::SummaryOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let now = ctx.now();
                let restricted: IndexSet<String> = find(
                    &tx,
                    "privacyRestrictions",
                    Filter::new().eq("tenantId", tenant.id.clone()),
                )
                .await?
                .iter()
                .map(|restriction| s(restriction, "subject").to_owned())
                .collect();
                let consents: Vec<PrivacyConsent> = decode_all(
                    find(
                        &tx,
                        "privacyConsents",
                        Filter::new().eq("tenantId", tenant.id.clone()),
                    )
                    .await?,
                )?;
                let mut listed: Vec<PrivacyPurpose> = decode_all(
                    find(
                        &tx,
                        "privacyPurposes",
                        Filter::new().eq("tenantId", tenant.id.clone()),
                    )
                    .await?,
                )?;
                listed.sort_by(|a, b| locale_compare(&a.name, &b.name));
                let mut purposes = Vec::new();
                for purpose in &listed {
                    let (mut granted, mut withdrawn, mut expired, mut outdated) = (0, 0, 0, 0);
                    for consent in consents
                        .iter()
                        .filter(|consent| consent.purpose_id == purpose.id)
                    {
                        let state = consent_state(
                            purpose,
                            Some(consent),
                            &Value::Bool(restricted.contains(&consent.subject)),
                            now,
                        )?;
                        if state.allowed {
                            granted += 1;
                        } else if state.reason == "CONSENT_EXPIRED" {
                            expired += 1;
                        } else if state.reason == "CONSENT_OUTDATED" {
                            outdated += 1;
                        } else if state.reason == "CONSENT_WITHDRAWN" || state.reason == "OBJECTED"
                        {
                            withdrawn += 1;
                        }
                    }
                    purposes.push(json!({
                        "id": purpose.id,
                        "key": purpose.key,
                        "name": purpose.name,
                        "legalBasis": purpose.legal_basis,
                        "mode": purpose.mode,
                        "version": number(purpose.version),
                        "archived": purpose.archived,
                        "granted": granted,
                        "withdrawn": withdrawn,
                        "expired": expired,
                        "outdated": outdated,
                    }));
                }
                let requests = find(
                    &tx,
                    "privacyRequests",
                    Filter::new().eq("tenantId", tenant.id.clone()),
                )
                .await?;
                let mut by_type: IndexMap<String, f64> = SUBJECT_REQUEST_TYPES
                    .iter()
                    .map(|kind| ((*kind).to_owned(), 0.0))
                    .collect();
                let mut durations: Vec<f64> = Vec::new();
                let mut completed_last_30_days = 0;
                for request in &requests {
                    let status = s(request, "status");
                    if status == "open" || status == "pending-verification" {
                        let kind = js_string(request.get("type"));
                        let count = by_type.entry(kind).or_insert(f64::NAN);
                        *count += 1.0;
                    }
                    if status == "completed"
                        && num_of(request, "closedAt").unwrap_or(0.0) > now - 30.0 * DAY_MS
                    {
                        completed_last_30_days += 1;
                    }
                    if let (Some(closed_at), Some(received_at)) =
                        (num_of(request, "closedAt"), num_of(request, "receivedAt"))
                        && closed_at > now - 90.0 * DAY_MS
                        && (status == "completed" || status == "rejected")
                    {
                        durations.push((closed_at - received_at) / DAY_MS);
                    }
                }
                durations.sort_by(|a, b| order(a - b));
                let median = if durations.is_empty() {
                    None
                } else if durations.len() % 2 == 1 {
                    Some(durations[(durations.len() - 1) / 2])
                } else {
                    Some(
                        (durations[durations.len() / 2 - 1] + durations[durations.len() / 2]) / 2.0,
                    )
                };
                let mut overdue_count = 0;
                for request in &requests {
                    if overdue(request, now)? {
                        overdue_count += 1;
                    }
                }
                let mut queue = Map::new();
                queue.insert(
                    "pendingVerification".into(),
                    json!(
                        requests
                            .iter()
                            .filter(|r| s(r, "status") == "pending-verification")
                            .count()
                    ),
                );
                queue.insert(
                    "open".into(),
                    json!(requests.iter().filter(|r| s(r, "status") == "open").count()),
                );
                queue.insert("overdue".into(), json!(overdue_count));
                queue.insert(
                    "dueSoon".into(),
                    json!(
                        requests
                            .iter()
                            .filter(|r| {
                                s(r, "status") == "open"
                                    && num_of(r, "dueAt")
                                        .is_some_and(|due| due > now && due <= now + 7.0 * DAY_MS)
                            })
                            .count()
                    ),
                );
                queue.insert("completedLast30Days".into(), json!(completed_last_30_days));
                if let Some(median) = median {
                    // `Math.round(median * 10) / 10`
                    queue.insert(
                        "medianDaysToClose".into(),
                        number((median * 10.0 + 0.5).floor() / 10.0),
                    );
                }
                queue.insert(
                    "byType".into(),
                    Value::Object(
                        by_type
                            .into_iter()
                            .map(|(kind, count)| (kind, number(count)))
                            .collect(),
                    ),
                );
                let holds = find(
                    &tx,
                    "privacyHolds",
                    Filter::new().eq("tenantId", tenant.id.clone()),
                )
                .await?
                .iter()
                .filter(|hold| match hold.get("expiresAt") {
                    None => true,
                    Some(value) => core_js::as_number(value).is_some_and(|at| at > now),
                })
                .count();
                Ok(json!({
                    "purposes": purposes,
                    "requests": queue,
                    "holds": holds,
                    "restrictions": restricted.len(),
                }))
            })
        });
        let result = self
            .operate(
                credential,
                &input,
                "iam:privacy:read",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

// ── The credential-free runtime ──────────────────────────────────────────────────────────────────────────────────

/// Privacy for the deployment's own server code (`iam.privacy`): credential-free consent checks and recording (for
/// an application's own customers), and the deadline job.
pub struct PrivacyRuntime {
    ctx: Arc<ServerContext>,
}

/// `createPrivacyRuntime(ctx)`.
pub fn create_privacy_runtime(ctx: &Arc<ServerContext>) -> IamResult<PrivacyRuntime> {
    Ok(PrivacyRuntime { ctx: ctx.clone() })
}

/// The members of a runtime input object; reading a member of `undefined` or `null` is a TypeError in TypeScript.
fn input_object(input: &Value) -> IamResult<Map<String, Value>> {
    match input {
        Value::Object(map) => Ok(map.clone()),
        Value::Null => Err(internal_error()),
        _ => Ok(Map::new()),
    }
}

impl PrivacyRuntime {
    /// Whether a purpose may be processed for a subject right now; not audited.
    pub async fn check(&self, input: &Value) -> IamResult<Value> {
        let ctx = &self.ctx;
        let input = &input_object(input)?;
        ctx.store
            .transaction(|tx| async move {
                let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
                check_subject(
                    ctx,
                    &tx,
                    &tenant_id,
                    input.get("subject"),
                    input.get("purposeKey"),
                )
                .await
            })
            .await
    }

    /// Records a decision the application captured itself (a cookie banner, a signup form), attributed to
    /// `application`. Audited as `privacy:consent`; returns the receipt.
    pub async fn record(&self, input: &Value) -> IamResult<crate::privacy::ConsentReceipt> {
        let ctx = &self.ctx;
        let input = &input_object(input)?;
        ctx.store
            .transaction(|tx| async move {
                let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
                let Some(Value::Bool(granted)) = input.get("granted").cloned() else {
                    return Err(invalid_input("granted must be a boolean"));
                };
                ctx.tenant(&tx, &tenant_id).await?;
                let purpose = purpose_by_key(&tx, &tenant_id, input.get("purposeKey")).await?;
                let subject = resolve_subject(&tx, &tenant_id, input.get("subject"), None).await?;
                let now = ctx.now();
                let method = method_label(input.get("method"))?;
                let evidence = evidence(input.get("evidence"))?;
                let mut client = ClientInfo::default();
                if let Some(ip) = input.get("ip") {
                    client.ip = Some(text(Some(ip), "ip", 64)?);
                }
                if let Some(agent) = input.get("userAgent") {
                    client.user_agent = Some(text(Some(agent), "userAgent", 512)?);
                }
                let (receipt, _) = write_consent(
                    ctx,
                    &tx,
                    ConsentWrite {
                        tenant_id: &tenant_id,
                        purpose: &purpose,
                        subject: &subject,
                        granted,
                        source: "api",
                        method,
                        evidence,
                        recorded_by: "application",
                        at: now,
                        version: None,
                        client: Some(client),
                    },
                )
                .await?;
                let mut metadata = Map::new();
                metadata.insert("purposeKey".into(), string(purpose.key.clone()));
                metadata.insert("granted".into(), Value::Bool(granted));
                metadata.insert(
                    "purposeVersion".into(),
                    crate::js::member(Some(&receipt.purpose), "version")
                        .cloned()
                        .unwrap_or(Value::Null),
                );
                metadata.insert("source".into(), string("api"));
                metadata.insert("receiptId".into(), string(receipt.receipt_id.clone()));
                if let Some(external_id) = &subject.external_id {
                    metadata.insert("externalId".into(), string(external_id.clone()));
                }
                let mut event = Record::new();
                event.insert("id".into(), string(id()));
                event.insert("tenantId".into(), string(tenant_id.clone()));
                event.insert("actorId".into(), string("application"));
                event.insert("action".into(), string("privacy:consent"));
                event.insert(
                    "resourceId".into(),
                    string(subject.identity_id.clone().unwrap_or(subject.key.clone())),
                );
                event.insert("timestamp".into(), number(now));
                event.insert("outcome".into(), string("allow"));
                event.insert("metadata".into(), Value::Object(metadata));
                ctx.events()?.record_audit(&tx, &event).await?;
                Ok(receipt)
            })
            .await
    }

    /// Deadline job (daily or hourly): emails the assignee (or the privacy contact) once when an open request is due
    /// within `withinDays` (default 7) and once when it becomes overdue, audited as `privacy:request:due-soon` /
    /// `privacy:request:overdue` so webhooks can alert too; cancels public requests nobody confirmed within seven days.
    pub async fn send_deadline_reminders(&self, input: Option<&Value>) -> IamResult<Value> {
        let ctx = &self.ctx;
        let input = match input {
            None => Map::new(),
            Some(value) => input_object(value)?,
        };
        let within_days = integer_or(input.get("withinDays"), 7.0, "withinDays", 1.0, 60.0)?;
        let tenant_filter = match input.get("tenantId") {
            None => None,
            Some(value) => Some(text(Some(value), "tenantId", 256)?),
        };
        let tenant_filter = &tenant_filter;
        ctx.store
            .transaction(|tx| async move {
                let now = ctx.now();
                let mut reminded: Vec<Value> = Vec::new();
                let mut lapsed = 0usize;
                let mut tenants: IndexMap<String, Option<Record>> = IndexMap::new();
                let filter_for = |status: &str| {
                    let filter = match tenant_filter {
                        Some(tenant_id) => Filter::new().eq("tenantId", tenant_id.clone()),
                        None => Filter::new(),
                    };
                    filter.eq("status", status.to_owned())
                };
                for request in find(&tx, "privacyRequests", filter_for("pending-verification")).await? {
                    if s(&request, "channel") == "public"
                        && request.get("tokenHash").is_some()
                        && nan_of(&request, "submittedAt") + VERIFICATION_LIFETIME_MS <= now
                    {
                        let mut cancelled = without(&request, &["tokenHash", "tokenExpiresAt"]);
                        cancelled.insert("status".into(), string("cancelled"));
                        cancelled.insert("closedAt".into(), number(now));
                        cancelled.insert("closedBy".into(), string("deployment-operator"));
                        cancelled.insert(
                            "events".into(),
                            push_event(
                                &request,
                                event_of(
                                    now,
                                    "deployment-operator",
                                    "cancelled",
                                    Some(
                                        "The requester did not confirm their email address within seven days"
                                            .into(),
                                    ),
                                ),
                            ),
                        );
                        tx.put("privacyRequests", &cancelled).await?;
                        lapsed += 1;
                    }
                }
                for request in find(&tx, "privacyRequests", filter_for("open")).await? {
                    let Some(due_at) = request.get("dueAt") else {
                        continue;
                    };
                    let due_at = core_js::as_number(due_at).unwrap_or(f64::NAN);
                    let kind = if due_at <= now {
                        "overdue"
                    } else if due_at <= now + within_days * DAY_MS {
                        "due-soon"
                    } else {
                        continue;
                    };
                    let already = request
                        .get("reminded")
                        .and_then(Value::as_array)
                        .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(kind)));
                    if already {
                        continue;
                    }
                    let request_tenant = s(&request, "tenantId").to_owned();
                    if !tenants.contains_key(&request_tenant) {
                        let tenant = tx.get("tenants", &request_tenant).await?;
                        tenants.insert(request_tenant.clone(), tenant);
                    }
                    let Some(Some(tenant)) = tenants.get(&request_tenant).cloned() else {
                        continue;
                    };
                    if s(&tenant, "status") != "active" {
                        continue;
                    }
                    let tenant_id = s(&tenant, "id").to_owned();
                    let settings = privacy_settings(&tx, &tenant_id).await?;
                    let assignee = if truthy(request.get("assigneeId")) {
                        tx.get("identities", s(&request, "assigneeId")).await?
                    } else {
                        None
                    };
                    let to = match &assignee {
                        Some(assignee)
                            if s(assignee, "status") == "active" && truthy(assignee.get("email")) =>
                        {
                            str_of(assignee, "email").map(str::to_owned)
                        }
                        _ => settings.contact_email.clone(),
                    };
                    if let Some(to) = to.filter(|to| !to.is_empty())
                        && can_email(ctx) {
                            let mut payload = Map::new();
                            payload.insert("tenantId".into(), string(tenant_id.clone()));
                            copy_as(&mut payload, "tenantName", &tenant, "name");
                            copy_as(&mut payload, "requestId", &request, "id");
                            copy_member(&mut payload, &request, "number");
                            copy_member(&mut payload, &request, "type");
                            payload.insert(
                                "dueAt".into(),
                                string(js_string(request.get("dueAt"))),
                            );
                            payload.insert(
                                "overdue".into(),
                                string(if kind == "overdue" { "true" } else { "false" }),
                            );
                            enqueue_email(
                                ctx,
                                &tx,
                                &tenant_id,
                                to,
                                "privacy-request-due",
                                payload,
                            )
                            .await?;
                        }
                    let mut marks = request
                        .get("reminded")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    marks.push(string(kind));
                    let mut updated = request.clone();
                    updated.insert("reminded".into(), Value::Array(marks));
                    updated.insert(
                        "events".into(),
                        push_event(
                            &request,
                            event_of(now, "deployment-operator", "reminded", Some(kind.into())),
                        ),
                    );
                    tx.put("privacyRequests", &updated).await?;
                    let mut event = Record::new();
                    event.insert("id".into(), string(id()));
                    event.insert("tenantId".into(), string(tenant_id.clone()));
                    event.insert("actorId".into(), string("deployment-operator"));
                    event.insert("action".into(), string(format!("privacy:request:{kind}")));
                    copy_as(&mut event, "resourceId", &request, "id");
                    event.insert("timestamp".into(), number(now));
                    event.insert("outcome".into(), string("allow"));
                    let mut metadata = Map::new();
                    copy_member(&mut metadata, &request, "number");
                    copy_member(&mut metadata, &request, "type");
                    copy_member(&mut metadata, &request, "dueAt");
                    event.insert("metadata".into(), Value::Object(metadata));
                    ctx.events()?.record_audit(&tx, &event).await?;
                    reminded.push(json!({
                        "tenantId": tenant_id,
                        "requestId": request.get("id"),
                        "kind": kind,
                    }));
                }
                Ok(json!({ "reminded": reminded, "lapsed": lapsed }))
            })
            .await
    }

    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        let first = args.first().cloned().unwrap_or(Value::Null);
        match method {
            "check" => Some(self.check(&first).await),
            "record" => Some(
                self.record(&first)
                    .await
                    .map(|receipt| Value::Object(encode(&receipt))),
            ),
            "sendDeadlineReminders" => Some(self.send_deadline_reminders(args.first()).await),
            _ => None,
        }
    }
}
