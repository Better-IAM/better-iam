//! Port of `packages/server/src/api/clearances.ts`: security clearances and classification labels (the `clearances`
//! option; FEATURE_DISABLED otherwise).
//!
//! Schemes: `templates` (no permission), `getScheme` (iam:clearances:read), `defineScheme` / `updateScheme`
//! (iam:classifications:manage, recent sign-in) on `iam/classifications/scheme`. Clearances on
//! `iam/clearances/{identityId}`: `grant`, `update`, `readIn`, `reinstate`, `revoke` (iam:clearances:adjudicate, recent
//! sign-in), `debrief` (adjudicate), `suspend` (iam:clearances:suspend, usable in an incident), `get` / `list`
//! (iam:clearances:read), `explain` (adjudicate), and `mine` (no permission). Nobody adjudicates their own clearance,
//! not even an owner or root; under `within-own` adjudication an officer grants only levels and compartments their own
//! clearance holds (an owner or root may bootstrap a level or compartment nobody in the scheme's subtree holds yet).
//! Labels on `iam/classifications/labels/{type}/{id}`: `label` raises (iam:classifications:label), `declassify` lowers
//! or removes (iam:classifications:declassify, recent sign-in, and the caller's own clearance must dominate the current
//! label), `getLabel` / `listLabels` (iam:clearances:read).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use better_iam_auth::outbox::EnqueueInput;
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, ClassificationLabel, ClassificationLevel,
    ClassificationSchemeDefinition, CredentialInput, Filter, FindOptions, IamError, IamResult,
    IamStoreExt, Identity, IdentityStatus, OutboxKind, Record, ResourceRef, SessionKind, Tenant,
    classification_template, dominates, is_valid_classification_label, js as core_js, label_covers,
    validate_label, validate_scheme,
};
use better_iam_types::api::clearances;
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};

use crate::agents::agent_decision_scope;
use crate::agreements::{Agreement, AgreementAcceptance, acceptance_current};
use crate::api::{Body, Reply};
use crate::catalog::{RESERVED_RESOURCE_TYPES, is_resource_type_name};
use crate::clearances::{
    CLEARANCE_COLLECTIONS, CLEARANCE_LIMITS, ClassificationScheme, KnownLabeling, PartyState,
    ResourceLabel, applicable_label, assert_clearances, attach_label, defined_scheme,
    effective_scheme, inherited_label, label_key, notify_clearance_status, parties_fail,
    party_state, read_clearance, scheme_level, session_parties, stored_label, suspend_clearance,
};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext, OperationDenied, OperationResult};
use crate::invariants::narrows_access_only;
use crate::js::{cmp_utf16, defined, js_string, sort_strings, truthy, utf16_len};
use crate::metrics::locale_compare;
use crate::options::ResolvedResource;
use crate::port::{decode, encode};
use crate::session_kinds::acts_in_own_right;
use crate::utils::{hash, id};
use crate::validation::{email, integer, object, text, text256};

// --- validation ------------------------------------------------------------------------------------------------

/// `templateNames`, in declaration order.
const TEMPLATE_NAMES: [(&str, &str); 4] = [
    ("us", "United States"),
    ("uk", "United Kingdom"),
    ("nato", "NATO"),
    ("corporate", "Corporate"),
];
const ADJUDICATION_MODES: [&str; 2] = ["within-own", "unrestricted"];
const CLEARANCE_STATUSES: [&str; 5] = ["interim", "active", "suspended", "revoked", "terminated"];
/// Statuses of a clearance that is in force or can be again (by reinstatement).
const LIVE_STATUSES: [&str; 3] = ["interim", "active", "suspended"];
const YEAR_MS: f64 = 365.0 * 86_400_000.0;
const DAY_MS: f64 = 86_400_000.0;
const SCHEME_RESOURCE: &str = "classifications/scheme";

/// A collection of `clearanceCollections`.
fn collection(key: &str) -> &'static str {
    CLEARANCE_COLLECTIONS
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// A limit of `clearanceLimits`.
fn limit(key: &str) -> f64 {
    CLEARANCE_LIMITS
        .get(key)
        .and_then(Value::as_f64)
        .unwrap_or_default()
}

fn schemes() -> &'static str {
    collection("schemes")
}
fn clearances_collection() -> &'static str {
    collection("clearances")
}
fn labels() -> &'static str {
    collection("labels")
}

fn live_status(status: Option<&Value>) -> bool {
    status
        .and_then(Value::as_str)
        .is_some_and(|status| LIVE_STATUSES.contains(&status))
}

fn str_of<'a>(record: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

/// `typeof value === 'number'`.
fn number_member(record: &Map<String, Value>, key: &str) -> Option<f64> {
    record.get(key).and_then(Value::as_f64)
}

/// `{ key: source.key }` in an object literal: a member that is undefined in the source is left out of the JSON.
fn copy_member(target: &mut Map<String, Value>, source: &Map<String, Value>, key: &str) {
    if let Some(value) = source.get(key) {
        target.insert(key.to_owned(), value.clone());
    }
}

fn num(value: f64) -> Value {
    crate::js::number(value)
}

/// `clearanceResource(identityId)`.
fn clearance_resource(identity_id: Option<&Value>) -> IamResult<(String, String)> {
    let identity_id = text256(identity_id, "identityId")?;
    Ok((format!("clearances/{identity_id}"), identity_id))
}

/// `classifications/labels/{type}/{id}`. Too long to authorize as one resource id, the id becomes `sha256:{hex}` (so
/// per-type policy patterns keep working), and with a very long type the whole name does.
fn label_resource(kind: &str, resource_id: &str) -> String {
    let plain = format!("classifications/labels/{kind}/{resource_id}");
    if utf16_len(&plain) <= 256 {
        return plain;
    }
    let typed = format!("classifications/labels/{kind}/sha256:{}", hash(resource_id));
    if utf16_len(&typed) <= 256 {
        typed
    } else {
        format!(
            "classifications/labels/sha256:{}",
            hash(&format!("{kind}/{resource_id}"))
        )
    }
}

/// `flag(value, name)`: undefined, or a boolean.
fn flag(value: Option<&Value>, name: &str) -> IamResult<Option<bool>> {
    match value {
        None => Ok(None),
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(IamError::new(
            "INVALID_INPUT",
            format!("{name} must be a boolean"),
        )),
    }
}

fn country(value: &str) -> bool {
    value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}

fn citizenship_list(value: Option<&Value>) -> IamResult<Vec<String>> {
    let max = limit("maxCitizenship");
    let items = match value {
        Some(Value::Array(items)) if items.len() as f64 <= max => items,
        _ => {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!(
                    "citizenship must list at most {} countries",
                    core_js::number_to_string(max)
                ),
            ));
        }
    };
    let mut countries: IndexSet<String> = IndexSet::new();
    for item in items {
        match item.as_str() {
            Some(code) if country(code) => {
                countries.insert(code.to_owned());
            }
            _ => {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    "citizenship must hold ISO 3166-1 alpha-3 codes in upper case",
                ));
            }
        }
    }
    let mut list: Vec<String> = countries.into_iter().collect();
    sort_strings(&mut list);
    Ok(list)
}

/// A resource type that can carry a label: a resource type name (lowercase letters, digits and `-`, as every
/// declared, registered and built-in type is) other than the platform's own. Never a `/`, so the `{type}/{id}` key of a
/// label and its `classifications/labels/{type}/{id}` resource name each belong to exactly one resource.
fn label_type(value: Option<&Value>) -> IamResult<String> {
    let kind = text256(value, "type")?;
    if !is_resource_type_name(&kind) {
        return Err(IamError::new(
            "INVALID_INPUT",
            "type must be a resource type name: a lowercase letter, then up to 63 lowercase letters, digits or \"-\"",
        ));
    }
    if RESERVED_RESOURCE_TYPES.contains(&kind.as_str()) {
        return Err(IamError::new(
            "INVALID_INPUT",
            "Platform resource types cannot be labeled",
        ));
    }
    Ok(kind)
}

fn required_types(value: Option<&Value>) -> IamResult<Vec<String>> {
    let max = limit("maxRequiredTypes");
    let items = match value {
        Some(Value::Array(items)) if items.len() as f64 <= max => items,
        _ => {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!(
                    "requireLabels must list at most {} resource types",
                    core_js::number_to_string(max)
                ),
            ));
        }
    };
    let mut types = Vec::with_capacity(items.len());
    for item in items {
        types.push(if item.as_str() == Some("*") {
            "*".to_owned()
        } else {
            label_type(Some(item))?
        });
    }
    let mut types = crate::js::unique(types);
    sort_strings(&mut types);
    Ok(types)
}

fn notify_emails(value: &Value) -> IamResult<Option<Value>> {
    if value.is_null() {
        return Ok(None);
    }
    let input = object(Some(value))?;
    let max = limit("maxNotifyEmails");
    let items = match input.get("emails") {
        Some(Value::Array(items)) if items.len() as f64 <= max => items,
        _ => {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!(
                    "notify.emails must list at most {} addresses",
                    core_js::number_to_string(max)
                ),
            ));
        }
    };
    let mut emails = Vec::with_capacity(items.len());
    for item in items {
        emails.push(email(Some(item))?);
    }
    let mut emails = crate::js::unique(emails);
    sort_strings(&mut emails);
    Ok((!emails.is_empty()).then(|| json!({ "emails": emails })))
}

/// `{ definition }` as `schemeLevel` reads a scheme.
fn definition_holder(definition: &ClassificationSchemeDefinition) -> Value {
    json!({ "definition": definition })
}

/// `schemeLevel(scheme, levelId)`.
fn level_in(
    scheme: &ClassificationScheme,
    level_id: Option<&str>,
) -> IamResult<Option<ClassificationLevel>> {
    scheme_level(&definition_holder(&scheme.definition), level_id)
}

/// The settings of a scheme (`schemeSettings`).
struct SchemeSettings {
    name: String,
    require_labels: Vec<String>,
    default_label: Option<ClassificationLabel>,
    /// A level id or null.
    guest_ceiling: Value,
    interim_allowed: bool,
    adjudication: String,
    notify: Option<Value>,
}

impl SchemeSettings {
    /// The members in the order TypeScript spreads them.
    fn members(&self) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("name".into(), Value::String(self.name.clone()));
        map.insert("requireLabels".into(), json!(self.require_labels));
        if let Some(label) = &self.default_label {
            map.insert("defaultLabel".into(), label.to_value());
        }
        map.insert("guestCeiling".into(), self.guest_ceiling.clone());
        map.insert("interimAllowed".into(), Value::Bool(self.interim_allowed));
        map.insert(
            "adjudication".into(),
            Value::String(self.adjudication.clone()),
        );
        if let Some(notify) = &self.notify {
            map.insert("notify".into(), notify.clone());
        }
        map
    }
}

/// The settings of a scheme over `previous`, checked against `definition`.
fn scheme_settings(
    input: &Map<String, Value>,
    definition: &ClassificationSchemeDefinition,
    previous: Option<&ClassificationScheme>,
) -> IamResult<SchemeSettings> {
    let name = match input.get("name") {
        Some(value) => Some(core_js::trim(&text(Some(value), "name", 100)?).to_owned()),
        None => previous.map(|scheme| scheme.name.clone()),
    };
    let name = match name {
        Some(name) if !name.is_empty() => name,
        _ => return Err(IamError::new("INVALID_INPUT", "name is required")),
    };
    let require_labels = match input.get("requireLabels") {
        Some(value) => required_types(Some(value))?,
        None => previous
            .map(|scheme| scheme.require_labels.clone())
            .unwrap_or_default(),
    };
    let default_label = match input.get("defaultLabel") {
        None => match previous.and_then(|scheme| scheme.default_label.as_ref()) {
            Some(label) => {
                let value = label.to_value();
                if !is_valid_classification_label(&value, definition) {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "The default label is not valid under the new definition; set a new defaultLabel or null",
                    ));
                }
                Some(validate_label(&value, definition)?)
            }
            None => None,
        },
        Some(Value::Null) => None,
        Some(value) => Some(validate_label(value, definition)?),
    };
    let guest_ceiling = match input.get("guestCeiling") {
        None => previous
            .and_then(|scheme| scheme.guest_ceiling.clone())
            .map(Value::String)
            .unwrap_or(Value::Null),
        Some(value) => value.clone(),
    };
    if !guest_ceiling.is_null() {
        let level = match guest_ceiling.as_str() {
            Some(ceiling) => scheme_level(&definition_holder(definition), Some(ceiling))?,
            None => None,
        };
        if level.is_none() {
            return Err(IamError::new(
                "INVALID_INPUT",
                "guestCeiling must be a level id of the scheme, or null",
            ));
        }
    }
    let interim_allowed = match flag(input.get("interimAllowed"), "interimAllowed")? {
        Some(value) => value,
        None => previous.is_some_and(|scheme| scheme.interim_allowed),
    };
    let adjudication = defined(input.get("adjudication"))
        .or_else(|| previous.and_then(|scheme| defined(Some(&scheme.adjudication))))
        .cloned()
        .unwrap_or_else(|| Value::String("within-own".into()));
    let adjudication = match adjudication.as_str() {
        Some(mode) if ADJUDICATION_MODES.contains(&mode) => mode.to_owned(),
        _ => {
            return Err(IamError::new(
                "INVALID_INPUT",
                "adjudication must be within-own or unrestricted",
            ));
        }
    };
    let notify = match input.get("notify") {
        None => previous.and_then(|scheme| scheme.notify.clone()),
        Some(value) => notify_emails(value)?,
    };
    Ok(SchemeSettings {
        name,
        require_labels,
        default_label,
        guest_ceiling,
        interim_allowed,
        adjudication,
        notify,
    })
}

fn scheme_view(scheme: &ClassificationScheme, asking_tenant_id: &str) -> Value {
    let mut view = Map::new();
    view.insert("tenantId".into(), Value::String(scheme.tenant_id.clone()));
    view.insert(
        "inherited".into(),
        Value::Bool(scheme.tenant_id != asking_tenant_id),
    );
    view.insert("name".into(), Value::String(scheme.name.clone()));
    view.insert("definition".into(), json!(scheme.definition));
    view.insert("requireLabels".into(), json!(scheme.require_labels));
    if let Some(label) = &scheme.default_label {
        view.insert("defaultLabel".into(), label.to_value());
    }
    view.insert(
        "guestCeiling".into(),
        scheme
            .guest_ceiling
            .clone()
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    view.insert("interimAllowed".into(), Value::Bool(scheme.interim_allowed));
    view.insert("adjudication".into(), scheme.adjudication.clone());
    if let Some(notify) = scheme.notify.as_ref().filter(|notify| truthy(Some(notify))) {
        let emails = notify.get("emails").cloned().unwrap_or(Value::Null);
        view.insert("notify".into(), json!({ "emails": emails }));
    }
    view.insert("createdAt".into(), num(scheme.created_at));
    view.insert("createdBy".into(), Value::String(scheme.created_by.clone()));
    view.insert("updatedAt".into(), num(scheme.updated_at));
    view.insert("updatedBy".into(), Value::String(scheme.updated_by.clone()));
    view.insert("version".into(), num(scheme.version));
    Value::Object(view)
}

fn label_view(stored: &ResourceLabel, scheme: Option<&ClassificationScheme>) -> IamResult<Value> {
    let level = match scheme {
        Some(scheme) => level_in(scheme, Some(&stored.label.level))?,
        None => None,
    };
    let mut view = Map::new();
    view.insert("type".into(), Value::String(stored.r#type.clone()));
    view.insert("id".into(), Value::String(stored.resource_id.clone()));
    view.insert("label".into(), stored.label.to_value());
    if let Some(level) = level {
        view.insert("levelName".into(), Value::String(level.name));
    }
    view.insert(
        "inheritToChildren".into(),
        Value::Bool(stored.inherit_to_children),
    );
    view.insert("labeledBy".into(), Value::String(stored.labeled_by.clone()));
    view.insert("labeledAt".into(), num(stored.labeled_at));
    view.insert("version".into(), num(stored.version));
    Ok(Value::Object(view))
}

/// Audit metadata for a label: level and compartment ids, never names.
fn label_metadata(label: &ClassificationLabel) -> Map<String, Value> {
    let mut metadata = Map::new();
    metadata.insert("level".into(), Value::String(label.level.clone()));
    if let Some(compartments) = label.compartments.as_ref().filter(|list| !list.is_empty()) {
        metadata.insert("compartments".into(), json!(compartments));
    }
    if label.noforn == Some(true) {
        metadata.insert("noforn".into(), Value::Bool(true));
    }
    if let Some(releasable) = &label.releasable_to {
        metadata.insert("releasableTo".into(), json!(releasable));
    }
    metadata
}

fn sorted(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut list: Vec<String> = items.into_iter().collect();
    sort_strings(&mut list);
    list
}

fn party_view(state: &PartyState) -> Value {
    let mut view = Map::new();
    view.insert(
        "identityId".into(),
        Value::String(state.party.identity_id.clone()),
    );
    view.insert("status".into(), state.status.clone());
    if let Some(level) = state.level.as_ref().filter(|_| state.party.rank >= 0.0) {
        view.insert("level".into(), Value::String(level.id.clone()));
    }
    view.insert("rank".into(), num(state.party.rank));
    view.insert(
        "compartments".into(),
        json!(sorted(state.party.compartments.iter().cloned())),
    );
    view.insert(
        "citizenship".into(),
        json!(sorted(state.party.citizenship.iter().cloned())),
    );
    Value::Object(view)
}

/// `new Date(at).toISOString()`; a date outside the JavaScript range throws (not an IamError).
fn iso(at: f64) -> IamResult<String> {
    core_js::iso_string(at).ok_or_else(crate::js::internal_error)
}

/// `ctx.options.authentication?.sendEmail` is configured.
fn sends_email(ctx: &ServerContext) -> bool {
    ctx.options
        .authentication
        .as_ref()
        .is_some_and(|authentication| authentication.send_email.is_some())
}

fn identity_value(identity: &Identity) -> Value {
    serde_json::to_value(identity).unwrap_or(Value::Null)
}

fn tenant_value(tenant: &Tenant) -> Value {
    serde_json::to_value(tenant).unwrap_or(Value::Null)
}

/// The stored record behind a typed record a helper of clearances.ts returned, so a read-modify-write keeps its member
/// order and the members this implementation does not know.
async fn raw_record<T: serde::Serialize>(
    tx: &Store,
    collection: &str,
    record_id: &str,
    typed: &T,
) -> IamResult<Record> {
    Ok(match tx.get(collection, record_id).await? {
        Some(raw) => raw,
        None => encode(typed),
    })
}

/// `readClearance(tx, identity)`, as the stored record.
async fn clearance_record(tx: &Store, identity: &Identity) -> IamResult<Option<Record>> {
    let Some(typed) = read_clearance(tx, &identity_value(identity)).await? else {
        return Ok(None);
    };
    Ok(Some(
        raw_record(tx, clearances_collection(), &typed.id, &typed).await?,
    ))
}

/// The scheme in force for a tenant (`effectiveScheme(tx, await ctx.ancestry(tx, tenant))`).
async fn scheme_in_force(
    ctx: &ServerContext,
    tx: &Store,
    tenant: &Tenant,
) -> IamResult<Option<ClassificationScheme>> {
    let chain: Vec<Value> = ctx
        .ancestry(tx, tenant)
        .await?
        .iter()
        .map(tenant_value)
        .collect();
    effective_scheme(tx, &chain).await
}

/// The scheme in force for a tenant; NOT_FOUND when none applies.
async fn scheme_in(
    ctx: &ServerContext,
    tx: &Store,
    tenant: &Tenant,
) -> IamResult<ClassificationScheme> {
    scheme_in_force(ctx, tx, tenant).await?.ok_or_else(|| {
        IamError::with_status(
            "NOT_FOUND",
            "No classification scheme applies to this organization",
            404,
        )
    })
}

fn no_impersonation(principal: &AuthenticatedPrincipal) -> IamResult<()> {
    if principal
        .session
        .impersonator_id
        .as_deref()
        .is_some_and(|id| !id.is_empty())
    {
        return Err(IamError::with_status(
            "IMPERSONATION_RESTRICTED",
            "Clearances and labels cannot be changed while impersonating",
            403,
        ));
    }
    Ok(())
}

/// The officer acting and their parties' clearances in the tenant.
struct Acting {
    states: Vec<PartyState>,
    root: bool,
}

/// The officer acting: never while impersonating, never a guest, never on their own clearance (`subject`), whatever
/// their role (owners and root included). Returns their parties' clearances in the tenant, for `within-own`.
async fn officer(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant: &Tenant,
    scheme: &ClassificationScheme,
    subject: Option<&Identity>,
) -> OperationResult<Acting> {
    no_impersonation(principal)?;
    if principal.identity.guest.is_some() && principal.identity.tenant_id == tenant.id {
        return Err(OperationDenied::new(Some(
            "Guests cannot adjudicate clearances",
        )));
    }
    let root = ctx.root_principal(tx, principal).await?;
    let scope = agent_decision_scope(tx, principal, Some(ctx.now())).await?;
    let states = session_parties(
        tx,
        principal,
        &tenant_value(tenant),
        scope.as_ref(),
        scheme,
        ctx.now(),
        root,
    )
    .await?;
    if let Some(subject) = subject {
        let mut own: HashSet<&str> = HashSet::new();
        own.insert(principal.identity.id.as_str());
        for state in &states {
            own.insert(state.party.identity_id.as_str());
        }
        if let Some(agent_id) = &principal.session.agent_id {
            own.insert(agent_id.as_str());
        }
        if let Some(original) = &principal.session.original_identity_id {
            own.insert(original.as_str());
        }
        if own.contains(subject.id.as_str()) {
            return Err(OperationDenied::new(Some(
                "Your own clearance is adjudicated by another officer",
            )));
        }
    }
    Ok(Acting { states, root })
}

/// What an officer grants: a level's rank, or a compartment.
enum Need {
    Rank(f64),
    Compartment(String),
}

/// Whether an active clearance of the scheme's subtree (people of active, unexpired accounts; guests do not count)
/// holds at least `need`'s rank, or is read into its compartment.
async fn held_in_subtree(
    ctx: &ServerContext,
    tx: &Store,
    scheme: &ClassificationScheme,
    need: &Need,
) -> IamResult<bool> {
    let now = ctx.now();
    let records = tx
        .find(
            clearances_collection(),
            &Filter::new()
                .eq("schemeTenantId", scheme.tenant_id.clone())
                .eq("status", "active"),
            &FindOptions::default(),
        )
        .await?;
    for record in records {
        if str_of(&record, "schemeTenantId") != Some(scheme.tenant_id.as_str())
            || str_of(&record, "status") != Some("active")
        {
            continue;
        }
        if number_member(&record, "expiresAt").is_some_and(|at| at <= now) {
            continue;
        }
        match need {
            Need::Rank(rank) => {
                let level = level_in(scheme, str_of(&record, "level"))?;
                if level.is_none_or(|level| level.rank < *rank) {
                    continue;
                }
            }
            Need::Compartment(compartment_id) => {
                let read_in =
                    record
                        .get("readIns")
                        .and_then(Value::as_array)
                        .is_some_and(|items| {
                            items.iter().any(|item| {
                                item.get("compartmentId").and_then(Value::as_str)
                                    == Some(compartment_id.as_str())
                            })
                        });
                if !read_in {
                    continue;
                }
            }
        }
        let holder_id = js_string(record.get("identityId"));
        let Some(holder) = tx.get("identities", &holder_id).await? else {
            continue;
        };
        if holder.get("tenantId") != record.get("tenantId")
            || str_of(&holder, "status") != Some("active")
            || holder.get("guest").is_some()
            || number_member(&holder, "expiresAt").is_some_and(|at| at <= now)
        {
            continue;
        }
        return Ok(true);
    }
    Ok(false)
}

/// `within-own` adjudication: every party of the officer must hold `need`. The bootstrap exception lets an owner of
/// the tenant or root grant it when nobody in the scheme's subtree holds it yet. Returns true for a bootstrap grant
/// (audited as such); refuses (audited denial) otherwise.
async fn within_own(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant: &Tenant,
    scheme: &ClassificationScheme,
    acting: &Acting,
    need: Need,
) -> OperationResult<bool> {
    if scheme.adjudication.as_str() == Some("unrestricted") {
        return Ok(false);
    }
    let covered = !acting.states.is_empty()
        && acting.states.iter().all(|state| match &need {
            Need::Rank(rank) => state.party.rank >= *rank,
            Need::Compartment(compartment_id) => {
                state.party.rank >= 0.0 && state.party.compartments.contains(compartment_id)
            }
        });
    if covered {
        return Ok(false);
    }
    let owner = principal.session.kind == SessionKind::User
        && principal.identity.owner
        && principal.identity.tenant_id == tenant.id
        && principal.session.tenant_id == tenant.id;
    if (owner || acting.root) && !held_in_subtree(ctx, tx, scheme, &need).await? {
        return Ok(true);
    }
    Err(OperationDenied::new(Some(
        "Under within-own adjudication an officer grants only what their own clearance holds",
    )))
}

/// A level of the scheme by id (INVALID_INPUT otherwise).
fn level_of(
    scheme: &ClassificationScheme,
    value: Option<&Value>,
) -> IamResult<ClassificationLevel> {
    let level_id = text(value, "level", 64)?;
    level_in(scheme, Some(&level_id))?
        .ok_or_else(|| IamError::new("INVALID_INPUT", "level must be a level id of the scheme"))
}

/// Guests hold at most the scheme's guest ceiling, and nothing when it sets none.
fn assert_guest_level(
    scheme: &ClassificationScheme,
    identity: &Identity,
    level: &ClassificationLevel,
) -> IamResult<()> {
    if identity.guest.is_none() {
        return Ok(());
    }
    let Some(ceiling) = level_in(scheme, scheme.guest_ceiling.as_deref())? else {
        return Err(IamError::new(
            "INVALID_INPUT",
            "Guests hold no clearance under this scheme",
        ));
    };
    if level.rank > ceiling.rank {
        return Err(IamError::new(
            "INVALID_INPUT",
            "Guests hold at most the scheme\u{2019}s guest ceiling",
        ));
    }
    Ok(())
}

fn investigation_of(ctx: &ServerContext, value: Option<&Value>) -> IamResult<Value> {
    let input = object(value)?;
    let completed_at = integer(
        input.get("completedAt"),
        "investigation.completedAt",
        0.0,
        ctx.now() + DAY_MS,
    )?;
    let kind = core_js::trim(&text(input.get("kind"), "investigation.kind", 64)?).to_owned();
    Ok(json!({ "kind": kind, "completedAt": num(completed_at) }))
}

fn due_of(ctx: &ServerContext, value: Option<&Value>) -> IamResult<f64> {
    let at = integer(value, "reinvestigationDue", 0.0, core_js::MAX_SAFE_INTEGER)?;
    if at > ctx.now() + 20.0 * YEAR_MS {
        return Err(IamError::new(
            "INVALID_INPUT",
            "reinvestigationDue must be within twenty years",
        ));
    }
    Ok(at)
}

fn end_of(ctx: &ServerContext, value: Option<&Value>) -> IamResult<f64> {
    let at = integer(value, "expiresAt", 0.0, core_js::MAX_SAFE_INTEGER)?;
    if at <= ctx.now() {
        return Err(IamError::new(
            "INVALID_INPUT",
            "expiresAt must be in the future",
        ));
    }
    if at > ctx.now() + 20.0 * YEAR_MS {
        return Err(IamError::new(
            "INVALID_INPUT",
            "expiresAt must be within twenty years",
        ));
    }
    Ok(at)
}

/// The record of a live (interim, active or suspended) clearance issued under the scheme in force.
async fn live_record(
    tx: &Store,
    identity: &Identity,
    scheme: &ClassificationScheme,
) -> IamResult<Record> {
    let record = clearance_record(tx, identity).await?;
    let Some(record) = record.filter(|record| live_status(record.get("status"))) else {
        return Err(IamError::with_status(
            "NOT_FOUND",
            "This identity holds no clearance",
            404,
        ));
    };
    if str_of(&record, "schemeTenantId") != Some(scheme.tenant_id.as_str()) {
        return Err(IamError::with_status(
            "CONFLICT",
            "This clearance was issued under another scheme; revoke it and grant a new one",
            409,
        ));
    }
    Ok(record)
}

/// `record.readIns ?? []`.
fn read_ins(record: &Map<String, Value>) -> Vec<Value> {
    record
        .get("readIns")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Whether a read-in counts right now: the compartment exists and any NDA has a current acceptance.
async fn read_in_current(
    tx: &Store,
    owner: &Map<String, Value>,
    compartment_id: Option<&str>,
    agreement_id: Option<&Value>,
    known: &HashMap<String, String>,
    now: f64,
) -> IamResult<bool> {
    if !compartment_id.is_some_and(|id| known.contains_key(id)) {
        return Ok(false);
    }
    let Some(agreement_id) = agreement_id else {
        return Ok(true);
    };
    let agreement_id = js_string(Some(agreement_id));
    let owner_identity = js_string(owner.get("identityId"));
    let agreement = tx.get("agreements", &agreement_id).await?;
    let acceptance = tx
        .get(
            "agreementAcceptances",
            &format!("{agreement_id}:{owner_identity}"),
        )
        .await?;
    let (Some(agreement), Some(acceptance)) = (agreement, acceptance) else {
        return Ok(false);
    };
    if agreement.get("tenantId") != owner.get("tenantId")
        || acceptance.get("tenantId") != owner.get("tenantId")
    {
        return Ok(false);
    }
    let agreement: Agreement = decode(agreement)?;
    let acceptance: AgreementAcceptance = decode(acceptance)?;
    Ok(acceptance_current(&agreement, Some(&acceptance), now))
}

/// A clearance as officers see it (`get`, `list` and the mutations).
async fn clearance_view(
    ctx: &ServerContext,
    tx: &Store,
    record: &Map<String, Value>,
    scheme: Option<&ClassificationScheme>,
    identity: Option<&Identity>,
) -> IamResult<Map<String, Value>> {
    let identity_id = js_string(record.get("identityId"));
    let read: Option<Identity> = match identity {
        Some(_) => None,
        None => match tx.get("identities", &identity_id).await? {
            Some(found) => Some(decode(found)?),
            None => None,
        },
    };
    let person = identity.or(read.as_ref());
    let now = ctx.now();
    let state = match scheme {
        Some(scheme) => Some(
            party_state(
                tx,
                scheme,
                person,
                &identity_id,
                str_of(record, "tenantId"),
                now,
            )
            .await?,
        ),
        None => None,
    };
    let level = match scheme {
        Some(scheme) => level_in(scheme, str_of(record, "level"))?,
        None => None,
    };
    let compartments: HashMap<String, String> = scheme
        .map(|scheme| {
            scheme
                .definition
                .compartments
                .iter()
                .map(|compartment| (compartment.id.clone(), compartment.name.clone()))
                .collect()
        })
        .unwrap_or_default();
    let mut views = Vec::new();
    for read_in in read_ins(record) {
        let Value::Object(read_in) = read_in else {
            continue;
        };
        let compartment_id = str_of(&read_in, "compartmentId");
        let mut view = Map::new();
        copy_member(&mut view, &read_in, "compartmentId");
        if let Some(name) = compartment_id.and_then(|id| compartments.get(id)) {
            view.insert("compartmentName".into(), Value::String(name.clone()));
        }
        copy_member(&mut view, &read_in, "readInAt");
        copy_member(&mut view, &read_in, "readInBy");
        copy_member(&mut view, &read_in, "agreementId");
        copy_member(&mut view, &read_in, "acceptedAt");
        let current = read_in_current(
            tx,
            record,
            compartment_id,
            read_in.get("agreementId"),
            &compartments,
            now,
        )
        .await?;
        view.insert("current".into(), Value::Bool(current));
        views.push(Value::Object(view));
    }
    let mut out = Map::new();
    copy_member(&mut out, record, "identityId");
    let mut who = Map::new();
    copy_member(&mut who, record, "identityId");
    if let Some(value) = who.shift_remove("identityId") {
        who.insert("id".into(), value);
    }
    who.insert(
        "name".into(),
        match person {
            Some(person) => Value::String(person.name.clone()),
            None => record.get("identityId").cloned().unwrap_or(Value::Null),
        },
    );
    if let Some(address) = person
        .and_then(|person| person.email.as_ref())
        .filter(|address| !address.is_empty())
    {
        who.insert("email".into(), Value::String(address.clone()));
    }
    who.insert(
        "kind".into(),
        match person {
            Some(person) => serde_json::to_value(person.kind).unwrap_or(Value::Null),
            None => json!("user"),
        },
    );
    who.insert(
        "status".into(),
        match person {
            Some(person) => serde_json::to_value(person.status).unwrap_or(Value::Null),
            None => json!("deleted"),
        },
    );
    who.insert(
        "guest".into(),
        Value::Bool(person.is_some_and(|person| person.guest.is_some())),
    );
    out.insert("identity".into(), Value::Object(who));
    copy_member(&mut out, record, "schemeTenantId");
    let mut level_view = Map::new();
    copy_member(&mut level_view, record, "level");
    if let Some(value) = level_view.shift_remove("level") {
        level_view.insert("id".into(), value);
    }
    if let Some(level) = &level {
        level_view.insert("name".into(), Value::String(level.name.clone()));
        level_view.insert("rank".into(), num(level.rank));
    }
    out.insert("level".into(), Value::Object(level_view));
    copy_member(&mut out, record, "status");
    out.insert(
        "effectiveStatus".into(),
        state
            .as_ref()
            .and_then(|state| defined(Some(&state.status)).cloned())
            .unwrap_or_else(|| json!("none")),
    );
    if let Some(state) = &state
        && let Some(level) = state.level.as_ref().filter(|_| state.party.rank >= 0.0)
    {
        out.insert("effectiveLevel".into(), Value::String(level.id.clone()));
    }
    out.insert(
        "citizenship".into(),
        record
            .get("citizenship")
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or_else(|| json!([])),
    );
    if let Some(investigation) = record
        .get("investigation")
        .filter(|value| truthy(Some(value)))
    {
        out.insert("investigation".into(), investigation.clone());
    }
    copy_member(&mut out, record, "reinvestigationDue");
    copy_member(&mut out, record, "expiresAt");
    out.insert("readIns".into(), Value::Array(views));
    copy_member(&mut out, record, "grantedAt");
    copy_member(&mut out, record, "grantedBy");
    copy_member(&mut out, record, "updatedAt");
    copy_member(&mut out, record, "updatedBy");
    if let Some(suspended) = record.get("suspended").filter(|value| truthy(Some(value))) {
        let mut view = Map::new();
        if let Value::Object(suspended) = suspended {
            copy_member(&mut view, suspended, "by");
            copy_member(&mut view, suspended, "at");
            copy_member(&mut view, suspended, "reason");
            copy_member(&mut view, suspended, "incidentId");
        }
        out.insert("suspended".into(), Value::Object(view));
    }
    if let Some(revoked) = record.get("revoked").filter(|value| truthy(Some(value))) {
        out.insert("revoked".into(), revoked.clone());
    }
    if let Some(terminated) = record.get("terminated").filter(|value| truthy(Some(value))) {
        out.insert("terminated".into(), terminated.clone());
    }
    Ok(out)
}

/// The labels' scheme (`labelTarget`): the one in force for the tenant (NOT_FOUND when none).
async fn label_target(
    ctx: &ServerContext,
    tx: &Store,
    tenant: &Tenant,
    input: &Map<String, Value>,
) -> IamResult<(ClassificationScheme, String, String)> {
    let kind = label_type(input.get("type"))?;
    let resource_id = text256(input.get("id"), "id")?;
    Ok((scheme_in(ctx, tx, tenant).await?, kind, resource_id))
}

/// Writes a label record (insert or new version).
#[allow(clippy::too_many_arguments)]
async fn write_label(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant: &Tenant,
    scheme: &ClassificationScheme,
    kind: &str,
    resource_id: &str,
    label: &ClassificationLabel,
    inherit_to_children: bool,
    existing: Option<&ResourceLabel>,
) -> IamResult<ResourceLabel> {
    let now = ctx.now();
    let mut record = Map::new();
    record.insert(
        "id".into(),
        Value::String(existing.map(|label| label.id.clone()).unwrap_or_else(id)),
    );
    record.insert("tenantId".into(), Value::String(tenant.id.clone()));
    record.insert(
        "uniqueKey".into(),
        Value::String(label_key(kind, resource_id)?),
    );
    record.insert("type".into(), Value::String(kind.to_owned()));
    record.insert("resourceId".into(), Value::String(resource_id.to_owned()));
    record.insert("label".into(), label.to_value());
    record.insert("inheritToChildren".into(), Value::Bool(inherit_to_children));
    record.insert(
        "schemeTenantId".into(),
        Value::String(scheme.tenant_id.clone()),
    );
    record.insert(
        "labeledBy".into(),
        Value::String(principal.identity.id.clone()),
    );
    record.insert("labeledAt".into(), num(now));
    record.insert(
        "version".into(),
        num(existing.map(|label| label.version).unwrap_or(0.0) + 1.0),
    );
    let saved = if existing.is_some() {
        tx.put(labels(), &record).await?
    } else {
        tx.insert(labels(), &record).await?
    };
    decode(saved)
}

/// A retired level: its id and last rank.
fn retired_entries(scheme: &ClassificationScheme) -> Vec<(String, f64)> {
    scheme
        .retired_levels
        .iter()
        .flatten()
        .map(|level| {
            (
                js_string(level.get("id")),
                level
                    .get("rank")
                    .and_then(Value::as_f64)
                    .unwrap_or(f64::NAN),
            )
        })
        .collect()
}

/// The levels a scheme has ever removed, with their last rank, once `next` replaces its definition (`retiredLevels`):
/// those removed now join the ones removed before, and any that `next` brings back (at that rank) leave. Sorted by id.
fn retired_levels_after(
    scheme: &ClassificationScheme,
    next: &ClassificationSchemeDefinition,
) -> IamResult<Vec<Value>> {
    let mut retired: IndexMap<String, f64> = retired_entries(scheme).into_iter().collect();
    for level in &scheme.definition.levels {
        retired.insert(level.id.clone(), level.rank);
    }
    for level in &next.levels {
        retired.shift_remove(&level.id);
    }
    let max = limit("maxRetiredLevels");
    if retired.len() as f64 > max {
        return Err(IamError::new(
            "INVALID_INPUT",
            format!(
                "A scheme removes at most {} distinct levels over its life",
                core_js::number_to_string(max)
            ),
        ));
    }
    let mut list: Vec<(String, f64)> = retired.into_iter().collect();
    list.sort_by(|a, b| cmp_utf16(&a.0, &b.0));
    Ok(list
        .into_iter()
        .map(|(level_id, rank)| json!({ "id": level_id, "rank": num(rank) }))
        .collect())
}

/// `flatMap(item => item ?? [])` over a member: an array's items, nothing for null or undefined, else the value.
fn flat_items(value: Option<&Value>) -> Vec<Value> {
    match value {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) => items.clone(),
        Some(other) => vec![other.clone()],
    }
}

/// Refuses a definition change that would reinterpret what may be in use: new levels must rank above every level
/// kept; every level keeps its rank, and one removed earlier comes back only at its former rank (IAM cannot see every
/// use: an application's resolver asserts labels by level id, and a default label may name any level); a level a live
/// clearance or a label uses cannot be removed; a compartment in use must stay; every label must remain valid.
async fn assert_definition_change(
    tx: &Store,
    scheme: &ClassificationScheme,
    next: &ClassificationSchemeDefinition,
) -> IamResult<()> {
    let before: HashMap<&str, &ClassificationLevel> = scheme
        .definition
        .levels
        .iter()
        .map(|level| (level.id.as_str(), level))
        .collect();
    let after: HashSet<&str> = next.levels.iter().map(|level| level.id.as_str()).collect();
    let kept_top = next
        .levels
        .iter()
        .filter_map(|level| before.get(level.id.as_str()).map(|kept| kept.rank))
        .fold(None, |top: Option<f64>, rank| {
            Some(top.map_or(rank, |top| top.max(rank)))
        })
        .unwrap_or(-1.0);
    for level in &next.levels {
        if !before.contains_key(level.id.as_str()) && level.rank <= kept_top {
            return Err(IamError::new(
                "INVALID_INPUT",
                "New levels go above every existing level",
            ));
        }
    }
    let retired: HashMap<String, f64> = retired_entries(scheme).into_iter().collect();
    for level in &next.levels {
        let former = before
            .get(level.id.as_str())
            .map(|known| known.rank)
            .or_else(|| retired.get(&level.id).copied());
        if former.is_some_and(|former| former != level.rank) {
            return Err(IamError::with_status(
                "RESOURCE_IN_USE",
                "Levels keep their rank: labels, including those your application asserts, may use any level",
                409,
            ));
        }
    }
    let records: Vec<Record> = tx
        .find(
            clearances_collection(),
            &Filter::new().eq("schemeTenantId", scheme.tenant_id.clone()),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .filter(|record| {
            str_of(record, "schemeTenantId") == Some(scheme.tenant_id.as_str())
                && live_status(record.get("status"))
        })
        .collect();
    let label_records: Vec<Record> = tx
        .find(
            labels(),
            &Filter::new().eq("schemeTenantId", scheme.tenant_id.clone()),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .filter(|item| str_of(item, "schemeTenantId") == Some(scheme.tenant_id.as_str()))
        .collect();
    let levels_used = records.iter().map(|record| record.get("level")).chain(
        label_records
            .iter()
            .map(|item| item.get("label").and_then(|label| label.get("level"))),
    );
    for level_id in levels_used {
        if let Some(level_id) = level_id.and_then(Value::as_str)
            && before.contains_key(level_id)
            && !after.contains(level_id)
        {
            return Err(IamError::with_status(
                "RESOURCE_IN_USE",
                "A level that clearances or labels use cannot be removed",
                409,
            ));
        }
    }
    let compartments: HashSet<&str> = next
        .compartments
        .iter()
        .map(|compartment| compartment.id.as_str())
        .collect();
    let mut used: Vec<Value> = Vec::new();
    for record in &records {
        for item in read_ins(record) {
            used.push(item.get("compartmentId").cloned().unwrap_or(Value::Null));
        }
    }
    for item in &label_records {
        used.extend(flat_items(
            item.get("label")
                .and_then(|label| label.get("compartments")),
        ));
    }
    for compartment_id in &used {
        if !compartment_id
            .as_str()
            .is_some_and(|id| compartments.contains(id))
        {
            return Err(IamError::with_status(
                "RESOURCE_IN_USE",
                "A compartment that clearances or labels use cannot be removed",
                409,
            ));
        }
    }
    for item in &label_records {
        let label = item.get("label").cloned().unwrap_or(Value::Null);
        if is_valid_classification_label(&label, &scheme.definition)
            && !is_valid_classification_label(&label, next)
        {
            return Err(IamError::with_status(
                "RESOURCE_IN_USE",
                "The change would invalidate existing labels",
                409,
            ));
        }
    }
    Ok(())
}

/// The audit metadata members every scheme event names: level and compartment ids.
fn definition_ids(definition: &ClassificationSchemeDefinition) -> (Value, Value) {
    (
        json!(
            definition
                .levels
                .iter()
                .map(|level| level.id.clone())
                .collect::<Vec<_>>()
        ),
        json!(
            definition
                .compartments
                .iter()
                .map(|compartment| compartment.id.clone())
                .collect::<Vec<_>>()
        ),
    )
}

// --- the API ---------------------------------------------------------------------------------------------------

/// The `clearances` API group (`createClearancesApi(ctx)`): one method per route `clearances/{method}`.
pub struct ClearancesApi {
    ctx: Arc<ServerContext>,
}

/// `createClearancesApi(ctx)`.
pub fn create_clearances_api(ctx: &Arc<ServerContext>) -> IamResult<ClearancesApi> {
    Ok(ClearancesApi { ctx: ctx.clone() })
}

impl ClearancesApi {
    /// `operation(credential, input.tenantId, action, resource, mutation)`.
    async fn run(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
        action: &str,
        resource: &str,
        mutation: Mutation<'_>,
    ) -> IamResult<Value> {
        self.ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                action,
                resource,
                mutation,
                false,
            )
            .await
    }

    /// `clearances/debrief`: ends a read-in. Tightening, so it needs no recent sign-in and may be your own. Requires
    /// iam:clearances:adjudicate; audited as `clearance:debrief` with the compartment id.
    pub async fn debrief(
        &self,
        credential: &CredentialInput,
        input: Body<clearances::DebriefInput>,
    ) -> IamResult<Reply<clearances::DebriefOutput>> {
        let ctx = &self.ctx;
        assert_clearances(ctx)?;
        let (resource, identity_id) = clearance_resource(input.get("identityId"))?;
        let body = input.raw();
        let identity_id = &identity_id;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    let scheme = scheme_in(ctx, &tx, &tenant).await?;
                    officer(ctx, &tx, &principal, &tenant, &scheme, None).await?;
                    let identity: Identity = ctx
                        .scoped_as(&tx, "identities", identity_id, &tenant.id)
                        .await?;
                    let compartment_id = text(body.get("compartmentId"), "compartmentId", 64)?;
                    let reason = match body.get("reason") {
                        Some(value) => {
                            Some(core_js::trim(&text(Some(value), "reason", 512)?).to_owned())
                        }
                        None => None,
                    };
                    let record = clearance_record(&tx, &identity).await?;
                    let Some(record) = record.filter(|record| {
                        read_ins(record).iter().any(|item| {
                            item.get("compartmentId").and_then(Value::as_str)
                                == Some(compartment_id.as_str())
                        })
                    }) else {
                        return Err(IamError::with_status(
                            "NOT_FOUND",
                            "Not read into this compartment",
                            404,
                        )
                        .into());
                    };
                    let now = ctx.now();
                    let mut next = record.clone();
                    let remaining: Vec<Value> = read_ins(&record)
                        .into_iter()
                        .filter(|item| {
                            item.get("compartmentId").and_then(Value::as_str)
                                != Some(compartment_id.as_str())
                        })
                        .collect();
                    next.insert("readIns".into(), Value::Array(remaining));
                    next.insert("updatedAt".into(), num(now));
                    next.insert(
                        "updatedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    let saved = tx.put(clearances_collection(), &next).await?;
                    let mut metadata = Map::new();
                    metadata.insert("compartmentId".into(), Value::String(compartment_id));
                    if let Some(reason) = reason.filter(|reason| !reason.is_empty()) {
                        metadata.insert("reason".into(), Value::String(reason));
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "clearance:debrief",
                            &tenant.id,
                            &identity.id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    let view =
                        clearance_view(ctx, &tx, &saved, Some(&scheme), Some(&identity)).await?;
                    // Only narrows: an "expect allow" invariant never blocks a debrief (invariants.ts).
                    narrows_access_only(&tx);
                    Ok(Value::Object(view))
                })
            },
        );
        let result = self
            .run(
                credential,
                body,
                "iam:clearances:adjudicate",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `clearances/declassify`: lowers, changes or (with `label: null`) removes a resource's label. The caller's own
    /// clearance must dominate the current label as the scheme in force reads it (nobody declassifies what they could
    /// not read), also for a label written under another scheme; only a label naming a level, compartment or caveat
    /// the scheme does not define may be repaired without. Requires iam:classifications:declassify and a recent
    /// sign-in; audited as `classification:declassify` with the reason.
    pub async fn declassify(
        &self,
        credential: &CredentialInput,
        input: Body<clearances::DeclassifyInput>,
    ) -> IamResult<Reply<clearances::DeclassifyOutput>> {
        let ctx = &self.ctx;
        assert_clearances(ctx)?;
        let resource = label_resource(
            &label_type(input.get("type"))?,
            &text256(input.get("id"), "id")?,
        );
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let (scheme, kind, resource_id) = label_target(ctx, &tx, &tenant, body).await?;
                    let reason =
                        core_js::trim(&text(body.get("reason"), "reason", 512)?).to_owned();
                    let label = match body.get("label") {
                        None => {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                "label is required (null removes it)",
                            )
                            .into());
                        }
                        Some(Value::Null) => None,
                        Some(value) => Some(validate_label(value, &scheme.definition)?),
                    };
                    let inherit = flag(body.get("inheritToChildren"), "inheritToChildren")?;
                    let Some(existing) = stored_label(&tx, &tenant.id, &kind, &resource_id).await?
                    else {
                        return Err(IamError::with_status(
                            "NOT_FOUND",
                            "This resource has no label",
                            404,
                        )
                        .into());
                    };
                    let acting = officer(ctx, &tx, &principal, &tenant, &scheme, None).await?;
                    // Nobody declassifies what they could not read, as the scheme in force reads the label, even one
                    // written under another scheme (it refuses everyone until replaced, but its level still means what
                    // it says here). Only a label naming what this scheme does not define, which no clearance can
                    // dominate, may be repaired by anyone holding the permission.
                    if is_valid_classification_label(&existing.label.to_value(), &scheme.definition)
                    {
                        let parties: Vec<_> = acting
                            .states
                            .iter()
                            .map(|state| state.party.clone())
                            .collect();
                        if parties_fail(&parties, &existing.label, &scheme.definition)?.is_some() {
                            return Err(OperationDenied::new(Some(
                                "Only someone cleared to read a label may declassify it",
                            )));
                        }
                    }
                    let mut saved: Option<ResourceLabel> = None;
                    match &label {
                        None => tx.delete(labels(), &existing.id).await?,
                        Some(label) => {
                            saved = Some(
                                write_label(
                                    ctx,
                                    &tx,
                                    &principal,
                                    &tenant,
                                    &scheme,
                                    &kind,
                                    &resource_id,
                                    label,
                                    inherit.unwrap_or(existing.inherit_to_children),
                                    Some(&existing),
                                )
                                .await?,
                            );
                        }
                    }
                    let mut metadata = Map::new();
                    metadata.insert("type".into(), Value::String(kind.clone()));
                    metadata.insert(
                        "previous".into(),
                        Value::Object(label_metadata(&existing.label)),
                    );
                    match &label {
                        Some(label) => {
                            metadata.insert("label".into(), Value::Object(label_metadata(label)));
                        }
                        None => {
                            metadata.insert("removed".into(), Value::Bool(true));
                        }
                    }
                    metadata.insert("reason".into(), Value::String(reason));
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "classification:declassify",
                            &tenant.id,
                            &label_key(&kind, &resource_id)?,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(match &saved {
                        Some(saved) => label_view(saved, Some(&scheme))?,
                        None => Value::Null,
                    })
                })
            },
        );
        let result = self
            .run(
                credential,
                body,
                "iam:classifications:declassify",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `clearances/defineScheme`: defines the tenant's classification scheme from a `template` or a `definition`.
    /// CONFLICT when the tenant, an ancestor or a tenant below it already defines one (the scheme closest to the root
    /// is in force for its whole subtree). Requires iam:classifications:manage and a recent sign-in; audited as
    /// `classification:scheme-define`.
    pub async fn define_scheme(
        &self,
        credential: &CredentialInput,
        input: Body<clearances::DefineSchemeInput>,
    ) -> IamResult<Reply<clearances::DefineSchemeOutput>> {
        let ctx = &self.ctx;
        assert_clearances(ctx)?;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let template = body.get("template");
                    let definition_input = body.get("definition");
                    if template.is_none() == definition_input.is_none() {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "Give either a template or a definition",
                        )
                        .into());
                    }
                    let definition = match template {
                        Some(template) => {
                            // `Object.hasOwn(templateNames, input.template)` reads the template as a property key.
                            let name = js_string(Some(template));
                            let Some(found) = TEMPLATE_NAMES
                                .iter()
                                .find(|(key, _)| *key == name)
                                .and_then(|(key, _)| classification_template(key))
                            else {
                                return Err(IamError::new(
                                    "INVALID_INPUT",
                                    "template must be us, uk, nato or corporate",
                                )
                                .into());
                            };
                            validate_scheme(&json!(found))?
                        }
                        None => validate_scheme(definition_input.unwrap_or(&Value::Null))?,
                    };
                    let settings = scheme_settings(body, &definition, None)?;
                    for realm in ctx.ancestry(&tx, &tenant).await? {
                        if defined_scheme(&tx, &realm.id).await?.is_some() {
                            return Err(IamError::with_status(
                                "CONFLICT",
                                if realm.id == tenant.id {
                                    "This tenant already defines a classification scheme"
                                } else {
                                    "An ancestor tenant defines the classification scheme in force here"
                                },
                                409,
                            )
                            .into());
                        }
                    }
                    for other in tx
                        .find(schemes(), &Filter::new(), &FindOptions::default())
                        .await?
                    {
                        let other_tenant = js_string(other.get("tenantId"));
                        if ctx
                            .ancestor_ids(&tx, &other_tenant)
                            .await?
                            .contains(&tenant.id)
                        {
                            return Err(IamError::with_status(
                                "CONFLICT",
                                "A tenant below this one defines its own classification scheme",
                                409,
                            )
                            .into());
                        }
                    }
                    let now = ctx.now();
                    let mut record = Map::new();
                    record.insert("id".into(), Value::String(id()));
                    record.insert("tenantId".into(), Value::String(tenant.id.clone()));
                    record.insert("uniqueKey".into(), json!("scheme"));
                    record.insert("definition".into(), json!(definition));
                    for (key, value) in settings.members() {
                        record.insert(key, value);
                    }
                    record.insert("createdAt".into(), num(now));
                    record.insert(
                        "createdBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    record.insert("updatedAt".into(), num(now));
                    record.insert(
                        "updatedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    record.insert("version".into(), num(1.0));
                    let scheme: ClassificationScheme =
                        decode(tx.insert(schemes(), &record).await?)?;
                    let (levels, compartments) = definition_ids(&definition);
                    let mut metadata = Map::new();
                    if let Some(template) = template {
                        metadata.insert("template".into(), template.clone());
                    }
                    metadata.insert("levels".into(), levels);
                    metadata.insert("compartments".into(), compartments);
                    metadata.insert("requireLabels".into(), json!(settings.require_labels));
                    metadata.insert("guestCeiling".into(), settings.guest_ceiling.clone());
                    metadata.insert(
                        "interimAllowed".into(),
                        Value::Bool(settings.interim_allowed),
                    );
                    metadata.insert(
                        "adjudication".into(),
                        Value::String(settings.adjudication.clone()),
                    );
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "classification:scheme-define",
                            &tenant.id,
                            &scheme.id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(scheme_view(&scheme, &tenant.id))
                })
            },
        );
        let result = self
            .run(
                credential,
                body,
                "iam:classifications:manage",
                SCHEME_RESOURCE,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `clearances/explain`: for investigations, whether a person (their own sessions: an agent with its sponsor) may
    /// read a resource, which dimension the first refused party fails, the label decisions apply and each party's
    /// clearance. Officers only: requires iam:clearances:adjudicate.
    pub async fn explain(
        &self,
        credential: &CredentialInput,
        input: Body<clearances::ExplainInput>,
    ) -> IamResult<Reply<clearances::ExplainOutput>> {
        let ctx = &self.ctx;
        assert_clearances(ctx)?;
        let (resource, identity_id) = clearance_resource(input.get("identityId"))?;
        let body = input.raw();
        let identity_id = &identity_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let kind = text256(body.get("type"), "type")?;
                let resource_id = text256(body.get("id"), "id")?;
                let scheme = scheme_in(ctx, &tx, &tenant).await?;
                let identity = ctx.active_identity(&tx, identity_id, &tenant.id).await?;
                let subject = ctx.decisions()?.simulated_principal(&identity, false);
                let states = session_parties(
                    &tx,
                    &subject,
                    &tenant_value(&tenant),
                    None,
                    &scheme,
                    ctx.now(),
                    false,
                )
                .await?;
                let reference = ResourceRef {
                    tenant_id: tenant.id.clone(),
                    kind,
                    id: resource_id,
                };
                let known = KnownLabeling {
                    scheme: Some(scheme.clone()),
                    named: None,
                };
                let labeled = match ctx
                    .decisions()?
                    .resolve(&tx, &reference, false, None, Some(&known))
                    .await
                {
                    Ok(labeled) => labeled,
                    // An unregistered or unresolvable resource still has its IAM-held label (labels outlive
                    // resources). What TypeScript would not catch (an exception that is not an IamError, or a part
                    // not ported yet) still fails.
                    Err(error)
                        if error.code != "INTERNAL_ERROR" && error.code != "NOT_IMPLEMENTED" =>
                    {
                        attach_label(
                            ctx,
                            &tx,
                            &tenant.id,
                            &ResolvedResource::of(&reference),
                            Some(&known),
                        )
                        .await?
                    }
                    Err(error) => return Err(error.into()),
                };
                let scheme_json = serde_json::to_value(&scheme).unwrap_or(Value::Null);
                let label = applicable_label(&scheme_json, &labeled)?;
                let views: Vec<Value> = states.iter().map(party_view).collect();
                let answer =
                    |allowed: bool, failure: Option<&str>, label: Value, party: Option<&Value>| {
                        let mut out = Map::new();
                        out.insert("allowed".into(), Value::Bool(allowed));
                        if let Some(failure) = failure {
                            out.insert("failure".into(), Value::String(failure.to_owned()));
                        }
                        out.insert("label".into(), label);
                        if let Some(party) = party {
                            out.insert("party".into(), party.clone());
                        }
                        out.insert("parties".into(), Value::Array(views.clone()));
                        Value::Object(out)
                    };
                let label = match label {
                    None => return Ok(answer(true, None, Value::Null, views.first())),
                    Some(Value::Bool(false)) => {
                        return Ok(answer(
                            false,
                            Some("invalid-label"),
                            Value::Null,
                            views.first(),
                        ));
                    }
                    Some(label) => label,
                };
                for (index, state) in states.iter().enumerate() {
                    // `partiesFail([state.party], label, scheme.definition)`: one party's dominance.
                    if let Some(failure) = dominates(&state.party, &label, &scheme.definition) {
                        return Ok(answer(
                            false,
                            Some(failure.as_str()),
                            label.clone(),
                            views.get(index),
                        ));
                    }
                }
                Ok(answer(true, None, label.clone(), views.first()))
            })
        });
        let result = self
            .run(
                credential,
                body,
                "iam:clearances:adjudicate",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `clearances/get`: one identity's clearance (null when it has none). Requires iam:clearances:read.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<clearances::GetInput>,
    ) -> IamResult<Reply<clearances::GetOutput>> {
        let ctx = &self.ctx;
        assert_clearances(ctx)?;
        let (resource, identity_id) = clearance_resource(input.get("identityId"))?;
        let body = input.raw();
        let identity_id = &identity_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let identity: Identity = ctx
                    .scoped_as(&tx, "identities", identity_id, &tenant.id)
                    .await?;
                let Some(record) = clearance_record(&tx, &identity).await? else {
                    return Ok(Value::Null);
                };
                let scheme = scheme_in_force(ctx, &tx, &tenant).await?;
                Ok(Value::Object(
                    clearance_view(ctx, &tx, &record, scheme.as_ref(), Some(&identity)).await?,
                ))
            })
        });
        let result = self
            .run(credential, body, "iam:clearances:read", &resource, mutation)
            .await?;
        Ok(Reply::json(result))
    }

    /// `clearances/getLabel`: a resource's own IAM label and what it inherits from its managed parents. Requires
    /// iam:clearances:read.
    pub async fn get_label(
        &self,
        credential: &CredentialInput,
        input: Body<clearances::GetLabelInput>,
    ) -> IamResult<Reply<clearances::GetLabelOutput>> {
        let ctx = &self.ctx;
        assert_clearances(ctx)?;
        let resource = label_resource(
            &label_type(input.get("type"))?,
            &text256(input.get("id"), "id")?,
        );
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let (scheme, kind, resource_id) = label_target(ctx, &tx, &tenant, body).await?;
                let existing = stored_label(&tx, &tenant.id, &kind, &resource_id).await?;
                let inherited =
                    inherited_label(&tx, &tenant.id, &scheme, &kind, &resource_id).await?;
                let mut out = Map::new();
                out.insert("type".into(), Value::String(kind));
                out.insert("id".into(), Value::String(resource_id));
                out.insert(
                    "label".into(),
                    match &existing {
                        Some(existing) => label_view(existing, Some(&scheme))?,
                        None => Value::Null,
                    },
                );
                out.insert(
                    "inherited".into(),
                    inherited
                        .map(|label| label.to_value())
                        .unwrap_or(Value::Null),
                );
                Ok(Value::Object(out))
            })
        });
        let result = self
            .run(credential, body, "iam:clearances:read", &resource, mutation)
            .await?;
        Ok(Reply::json(result))
    }

    /// `clearances/getScheme`: the scheme in force for the tenant and where it is defined (`inherited` when an
    /// ancestor defines it), or null. Requires iam:clearances:read.
    pub async fn get_scheme(
        &self,
        credential: &CredentialInput,
        input: Body<clearances::GetSchemeInput>,
    ) -> IamResult<Reply<clearances::GetSchemeOutput>> {
        let ctx = &self.ctx;
        assert_clearances(ctx)?;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                Ok(match scheme_in_force(ctx, &tx, &tenant).await? {
                    Some(scheme) => scheme_view(&scheme, &tenant.id),
                    None => Value::Null,
                })
            })
        });
        let result = self
            .run(
                credential,
                body,
                "iam:clearances:read",
                SCHEME_RESOURCE,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `clearances/grant`: grants a clearance under the scheme in force: a level, adjudicated citizenship, optionally
    /// interim, the investigation and its dates. CONFLICT when the identity already holds a live one (use `update`).
    /// Guests are held to the guest ceiling. Never your own; under `within-own` only within the officer's own clearance
    /// (bootstrap aside). Requires iam:clearances:adjudicate and a recent sign-in; audited as `clearance:grant`.
    pub async fn grant(
        &self,
        credential: &CredentialInput,
        input: Body<clearances::GrantInput>,
    ) -> IamResult<Reply<clearances::GrantOutput>> {
        let ctx = &self.ctx;
        assert_clearances(ctx)?;
        let (resource, identity_id) = clearance_resource(input.get("identityId"))?;
        let body = input.raw();
        let identity_id = &identity_id;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let scheme = scheme_in(ctx, &tx, &tenant).await?;
                    let identity = ctx.active_identity(&tx, identity_id, &tenant.id).await?;
                    if identity.status != IdentityStatus::Active {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "Only active identities are granted clearances",
                        )
                        .into());
                    }
                    let acting =
                        officer(ctx, &tx, &principal, &tenant, &scheme, Some(&identity)).await?;
                    let level = level_of(&scheme, body.get("level"))?;
                    assert_guest_level(&scheme, &identity, &level)?;
                    let interim = flag(body.get("interim"), "interim")?.unwrap_or(false);
                    if interim && !scheme.interim_allowed {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "This scheme does not allow interim clearances",
                        )
                        .into());
                    }
                    let citizenship = citizenship_list(body.get("citizenship"))?;
                    let investigation = match body.get("investigation") {
                        Some(value) => Some(investigation_of(ctx, Some(value))?),
                        None => None,
                    };
                    let reinvestigation_due = match body.get("reinvestigationDue") {
                        Some(value) => Some(due_of(ctx, Some(value))?),
                        None => None,
                    };
                    let expires_at = match body.get("expiresAt") {
                        Some(value) => Some(end_of(ctx, Some(value))?),
                        None => None,
                    };
                    let existing = clearance_record(&tx, &identity).await?;
                    if existing
                        .as_ref()
                        .is_some_and(|existing| live_status(existing.get("status")))
                    {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "This identity already holds a clearance; change it with update",
                            409,
                        )
                        .into());
                    }
                    let bootstrap = within_own(
                        ctx,
                        &tx,
                        &principal,
                        &tenant,
                        &scheme,
                        &acting,
                        Need::Rank(level.rank),
                    )
                    .await?;
                    let now = ctx.now();
                    let mut record = Map::new();
                    record.insert("id".into(), Value::String(identity.id.clone()));
                    record.insert("tenantId".into(), Value::String(tenant.id.clone()));
                    record.insert(
                        "uniqueKey".into(),
                        Value::String(format!("identity:{}", identity.id)),
                    );
                    record.insert("identityId".into(), Value::String(identity.id.clone()));
                    record.insert(
                        "schemeTenantId".into(),
                        Value::String(scheme.tenant_id.clone()),
                    );
                    record.insert("level".into(), Value::String(level.id.clone()));
                    record.insert("citizenship".into(), json!(citizenship));
                    record.insert(
                        "status".into(),
                        json!(if interim { "interim" } else { "active" }),
                    );
                    if let Some(investigation) = investigation {
                        record.insert("investigation".into(), investigation);
                    }
                    if let Some(due) = reinvestigation_due {
                        record.insert("reinvestigationDue".into(), num(due));
                    }
                    if let Some(expires_at) = expires_at {
                        record.insert("expiresAt".into(), num(expires_at));
                    }
                    record.insert("readIns".into(), json!([]));
                    record.insert("grantedAt".into(), num(now));
                    record.insert(
                        "grantedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    record.insert("updatedAt".into(), num(now));
                    record.insert(
                        "updatedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    let saved = if existing.is_some() {
                        tx.put(clearances_collection(), &record).await?
                    } else {
                        tx.insert(clearances_collection(), &record).await?
                    };
                    let mut metadata = Map::new();
                    metadata.insert("level".into(), Value::String(level.id.clone()));
                    metadata.insert(
                        "status".into(),
                        saved.get("status").cloned().unwrap_or(Value::Null),
                    );
                    if let Some(expires_at) = expires_at {
                        metadata.insert("expiresAt".into(), num(expires_at));
                    }
                    if bootstrap {
                        metadata.insert("bootstrap".into(), Value::Bool(true));
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "clearance:grant",
                            &tenant.id,
                            &identity.id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(Value::Object(
                        clearance_view(ctx, &tx, &saved, Some(&scheme), Some(&identity)).await?,
                    ))
                })
            },
        );
        let result = self
            .run(
                credential,
                body,
                "iam:clearances:adjudicate",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `clearances/label`: labels a resource (any application or tenant type; it need not exist yet, and the label
    /// outlives it). Only raises: the new label must cover the current one in every dimension, and inheritance once on
    /// stays on; anything else is a declassification. Requires iam:classifications:label; audited as
    /// `classification:label` with level and compartment ids.
    pub async fn label(
        &self,
        credential: &CredentialInput,
        input: Body<clearances::LabelInput>,
    ) -> IamResult<Reply<clearances::LabelOutput>> {
        let ctx = &self.ctx;
        assert_clearances(ctx)?;
        let resource = label_resource(
            &label_type(input.get("type"))?,
            &text256(input.get("id"), "id")?,
        );
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    no_impersonation(&principal)?;
                    let (scheme, kind, resource_id) = label_target(ctx, &tx, &tenant, body).await?;
                    let label = validate_label(
                        body.get("label").unwrap_or(&Value::Null),
                        &scheme.definition,
                    )?;
                    let inherit = flag(body.get("inheritToChildren"), "inheritToChildren")?;
                    let existing = stored_label(&tx, &tenant.id, &kind, &resource_id).await?;
                    let inherit_to_children = inherit
                        .or(existing
                            .as_ref()
                            .map(|existing| existing.inherit_to_children))
                        .unwrap_or(false);
                    // A label written under another scheme refuses everyone, so replacing it is a declassification
                    // too.
                    if let Some(existing) = &existing
                        && (existing.scheme_tenant_id != scheme.tenant_id
                            || !label_covers(
                                &label.to_value(),
                                &existing.label.to_value(),
                                &scheme.definition,
                            )
                            || (existing.inherit_to_children && !inherit_to_children))
                    {
                        return Err(OperationDenied::new(Some(
                            "Lowering or removing any part of a label is a declassification: use declassify",
                        )));
                    }
                    if let Some(existing) = &existing
                        && existing.inherit_to_children == inherit_to_children
                        && serde_json::to_string(&existing.label).ok()
                            == serde_json::to_string(&label).ok()
                    {
                        return Ok(label_view(existing, Some(&scheme))?);
                    }
                    let saved = write_label(
                        ctx,
                        &tx,
                        &principal,
                        &tenant,
                        &scheme,
                        &kind,
                        &resource_id,
                        &label,
                        inherit_to_children,
                        existing.as_ref(),
                    )
                    .await?;
                    let mut metadata = Map::new();
                    metadata.insert("type".into(), Value::String(kind.clone()));
                    for (key, value) in label_metadata(&label) {
                        metadata.insert(key, value);
                    }
                    metadata.insert("inheritToChildren".into(), Value::Bool(inherit_to_children));
                    if let Some(existing) = &existing {
                        metadata.insert(
                            "previousLevel".into(),
                            Value::String(existing.label.level.clone()),
                        );
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "classification:label",
                            &tenant.id,
                            &label_key(&kind, &resource_id)?,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(label_view(&saved, Some(&scheme))?)
                })
            },
        );
        let result = self
            .run(
                credential,
                body,
                "iam:classifications:label",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `clearances/list`: the tenant's clearances, by name: optionally one stored `status`, one `level`, or those
    /// ending within `expiringWithinDays` (ended ones included). Requires iam:clearances:read.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<clearances::ListInput>,
    ) -> IamResult<Reply<clearances::ListOutput>> {
        let ctx = &self.ctx;
        assert_clearances(ctx)?;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let status = body.get("status");
                if let Some(status) = status
                    && !status
                        .as_str()
                        .is_some_and(|status| CLEARANCE_STATUSES.contains(&status))
                {
                    return Err(IamError::new("INVALID_INPUT", "Invalid status").into());
                }
                let level = match body.get("level") {
                    Some(value) => Some(text(Some(value), "level", 64)?),
                    None => None,
                };
                let within = match body.get("expiringWithinDays") {
                    Some(value) => Some(integer(Some(value), "expiringWithinDays", 1.0, 3650.0)?),
                    None => None,
                };
                let default_limit = json!(100);
                let default_offset = json!(0);
                let limit = integer(
                    defined(body.get("limit")).or(Some(&default_limit)),
                    "limit",
                    1.0,
                    500.0,
                )?;
                let offset = integer(
                    defined(body.get("offset")).or(Some(&default_offset)),
                    "offset",
                    0.0,
                    1_000_000.0,
                )?;
                let scheme = scheme_in_force(ctx, &tx, &tenant).await?;
                let horizon = within.map(|within| ctx.now() + within * DAY_MS);
                let mut filter = Filter::new().eq("tenantId", tenant.id.clone());
                if let Some(status) = status {
                    filter = filter.eq("status", status.clone());
                }
                let records: Vec<Record> = tx
                    .find(clearances_collection(), &filter, &FindOptions::default())
                    .await?
                    .into_iter()
                    .filter(|record| {
                        str_of(record, "tenantId") == Some(tenant.id.as_str())
                            && level
                                .as_ref()
                                .is_none_or(|level| str_of(record, "level") == Some(level.as_str()))
                            && horizon.is_none_or(|horizon| {
                                number_member(record, "expiresAt").is_some_and(|at| at <= horizon)
                            })
                    })
                    .collect();
                // Ordered by name first, so only the page's clearances are evaluated in full.
                let mut people: Vec<(Record, Option<Identity>, String)> = Vec::new();
                for record in records {
                    let identity_id = js_string(record.get("identityId"));
                    let identity: Option<Identity> =
                        match tx.get("identities", &identity_id).await? {
                            Some(found) => Some(decode(found)?),
                            None => None,
                        };
                    let name = identity
                        .as_ref()
                        .map(|identity| identity.name.clone())
                        .unwrap_or(identity_id);
                    people.push((record, identity, name));
                }
                people.sort_by(|a, b| {
                    locale_compare(&a.2, &b.2).then_with(|| {
                        cmp_utf16(
                            &js_string(a.0.get("identityId")),
                            &js_string(b.0.get("identityId")),
                        )
                    })
                });
                let total = people.len();
                let mut views = Vec::new();
                for (record, identity, _) in
                    people.iter().skip(offset as usize).take(limit as usize)
                {
                    views.push(Value::Object(
                        clearance_view(ctx, &tx, record, scheme.as_ref(), identity.as_ref())
                            .await?,
                    ));
                }
                Ok(json!({ "clearances": views, "total": total }))
            })
        });
        let result = self
            .run(
                credential,
                body,
                "iam:clearances:read",
                "clearances",
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `clearances/listLabels`: the tenant's IAM labels, optionally of one type or level. Requires
    /// iam:clearances:read.
    pub async fn list_labels(
        &self,
        credential: &CredentialInput,
        input: Body<clearances::ListLabelsInput>,
    ) -> IamResult<Reply<clearances::ListLabelsOutput>> {
        let ctx = &self.ctx;
        assert_clearances(ctx)?;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let kind = match body.get("type") {
                    Some(value) => Some(label_type(Some(value))?),
                    None => None,
                };
                let level = match body.get("level") {
                    Some(value) => Some(text(Some(value), "level", 64)?),
                    None => None,
                };
                let default_limit = json!(100);
                let default_offset = json!(0);
                let limit = integer(
                    defined(body.get("limit")).or(Some(&default_limit)),
                    "limit",
                    1.0,
                    500.0,
                )?;
                let offset = integer(
                    defined(body.get("offset")).or(Some(&default_offset)),
                    "offset",
                    0.0,
                    1_000_000.0,
                )?;
                let scheme = scheme_in_force(ctx, &tx, &tenant).await?;
                let mut filter = Filter::new().eq("tenantId", tenant.id.clone());
                if let Some(kind) = &kind {
                    filter = filter.eq("type", kind.clone());
                }
                let mut items: Vec<ResourceLabel> = Vec::new();
                for record in tx.find(labels(), &filter, &FindOptions::default()).await? {
                    let item: ResourceLabel = decode(record)?;
                    if level
                        .as_ref()
                        .is_none_or(|level| &item.label.level == level)
                    {
                        items.push(item);
                    }
                }
                items.sort_by(|a, b| {
                    cmp_utf16(&a.r#type, &b.r#type)
                        .then_with(|| cmp_utf16(&a.resource_id, &b.resource_id))
                });
                let mut page = Vec::new();
                for item in items.iter().skip(offset as usize).take(limit as usize) {
                    page.push(label_view(item, scheme.as_ref())?);
                }
                Ok(json!({ "labels": page, "total": items.len() }))
            })
        });
        let result = self
            .run(
                credential,
                body,
                "iam:clearances:read",
                "classifications/labels",
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `clearances/mine`: the caller's own clearance under the scheme in force (levels of the scheme, their level,
    /// status, citizenship, dates and the compartments they are read into with whether each NDA is current). Needs only
    /// an ordinary session of the tenant (not while impersonating); no permission.
    pub async fn mine(
        &self,
        credential: &CredentialInput,
        input: Body<clearances::MineInput>,
    ) -> IamResult<Reply<clearances::MineOutput>> {
        let ctx = self.ctx.clone();
        assert_clearances(&ctx)?;
        let tenant_id = text256(input.get("tenantId"), "tenantId")?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let store = ctx.store.clone();
        let result = store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                if !acts_in_own_right(principal.session.kind)
                    || principal.session.tenant_id != tenant_id
                    || principal.identity.tenant_id != tenant_id
                {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "Your clearance is read from an ordinary session of its tenant",
                        403,
                    ));
                }
                if principal
                    .session
                    .impersonator_id
                    .as_deref()
                    .is_some_and(|id| !id.is_empty())
                {
                    return Err(IamError::with_status(
                        "IMPERSONATION_RESTRICTED",
                        "A clearance is not shown while impersonating",
                        403,
                    ));
                }
                let tenant = ctx.tenant(&tx, &tenant_id).await?;
                let Some(scheme) = scheme_in_force(&ctx, &tx, &tenant).await? else {
                    return Ok(json!({ "scheme": null, "clearance": null }));
                };
                let view = match clearance_record(&tx, &principal.identity).await? {
                    Some(record) => Some(
                        clearance_view(
                            &ctx,
                            &tx,
                            &record,
                            Some(&scheme),
                            Some(&principal.identity),
                        )
                        .await?,
                    ),
                    None => None,
                };
                let mut scheme_out = Map::new();
                scheme_out.insert("tenantId".into(), Value::String(scheme.tenant_id.clone()));
                scheme_out.insert("name".into(), Value::String(scheme.name.clone()));
                scheme_out.insert("levels".into(), json!(scheme.definition.levels));
                let clearance = match view {
                    None => Value::Null,
                    Some(view) => {
                        let mut out = Map::new();
                        let mut level = Map::new();
                        if let Some(Value::Object(view_level)) = view.get("level") {
                            copy_member(&mut level, view_level, "id");
                            if let Some(name) =
                                view_level.get("name").filter(|name| truthy(Some(name)))
                            {
                                level.insert("name".into(), name.clone());
                            }
                        }
                        out.insert("level".into(), Value::Object(level));
                        copy_member(&mut out, &view, "status");
                        copy_member(&mut out, &view, "effectiveStatus");
                        if let Some(effective) = view
                            .get("effectiveLevel")
                            .filter(|level| truthy(Some(level)))
                        {
                            out.insert("effectiveLevel".into(), effective.clone());
                        }
                        copy_member(&mut out, &view, "citizenship");
                        copy_member(&mut out, &view, "reinvestigationDue");
                        copy_member(&mut out, &view, "expiresAt");
                        let mut items = Vec::new();
                        for item in view
                            .get("readIns")
                            .and_then(Value::as_array)
                            .into_iter()
                            .flatten()
                        {
                            let Value::Object(item) = item else {
                                continue;
                            };
                            let mut entry = Map::new();
                            copy_member(&mut entry, item, "compartmentId");
                            if let Some(name) = item
                                .get("compartmentName")
                                .filter(|name| truthy(Some(name)))
                            {
                                entry.insert("compartmentName".into(), name.clone());
                            }
                            copy_member(&mut entry, item, "agreementId");
                            copy_member(&mut entry, item, "current");
                            items.push(Value::Object(entry));
                        }
                        out.insert("readIns".into(), Value::Array(items));
                        Value::Object(out)
                    }
                };
                Ok(json!({ "scheme": Value::Object(scheme_out), "clearance": clearance }))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `clearances/readIn`: reads a person into a compartment of the scheme, optionally backed by an NDA
    /// (`agreementId`, an agreement of the person's tenant; the read-in counts only while their acceptance of its
    /// current version is current). The clearance must be active or interim; guests are never read in. Under
    /// `within-own` the officer must be read into the compartment (an owner or root may bootstrap one nobody holds).
    /// Requires iam:clearances:adjudicate and a recent sign-in; audited as `clearance:read-in` with the compartment id.
    pub async fn read_in(
        &self,
        credential: &CredentialInput,
        input: Body<clearances::ReadInInput>,
    ) -> IamResult<Reply<clearances::ReadInOutput>> {
        let ctx = &self.ctx;
        assert_clearances(ctx)?;
        let (resource, identity_id) = clearance_resource(input.get("identityId"))?;
        let body = input.raw();
        let identity_id = &identity_id;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let scheme = scheme_in(ctx, &tx, &tenant).await?;
                    let identity = ctx.active_identity(&tx, identity_id, &tenant.id).await?;
                    let acting =
                        officer(ctx, &tx, &principal, &tenant, &scheme, Some(&identity)).await?;
                    if identity.guest.is_some() {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "Guests are not read into compartments",
                        )
                        .into());
                    }
                    let record = live_record(&tx, &identity, &scheme).await?;
                    if str_of(&record, "status") == Some("suspended") {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "A suspended clearance cannot be read into compartments",
                            409,
                        )
                        .into());
                    }
                    let compartment_id = text(body.get("compartmentId"), "compartmentId", 64)?;
                    if !scheme
                        .definition
                        .compartments
                        .iter()
                        .any(|item| item.id == compartment_id)
                    {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "compartmentId must be a compartment of the scheme",
                        )
                        .into());
                    }
                    if read_ins(&record).iter().any(|item| {
                        item.get("compartmentId").and_then(Value::as_str)
                            == Some(compartment_id.as_str())
                    }) {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "Already read into this compartment",
                            409,
                        )
                        .into());
                    }
                    let mut accepted_at: Option<f64> = None;
                    let mut agreement_id: Option<String> = None;
                    if let Some(value) = body.get("agreementId") {
                        let wanted = text256(Some(value), "agreementId")?;
                        let agreement: Agreement = ctx
                            .scoped_as(&tx, "agreements", &wanted, &identity.tenant_id)
                            .await?;
                        agreement_id = Some(agreement.id.clone());
                        let acceptance = tx
                            .get(
                                "agreementAcceptances",
                                &format!("{}:{}", agreement.id, identity.id),
                            )
                            .await?;
                        if let Some(acceptance) = acceptance
                            && str_of(&acceptance, "tenantId") == Some(identity.tenant_id.as_str())
                        {
                            let acceptance: AgreementAcceptance = decode(acceptance)?;
                            if acceptance_current(&agreement, Some(&acceptance), ctx.now()) {
                                accepted_at = Some(acceptance.accepted_at);
                            }
                        }
                    }
                    let bootstrap = within_own(
                        ctx,
                        &tx,
                        &principal,
                        &tenant,
                        &scheme,
                        &acting,
                        Need::Compartment(compartment_id.clone()),
                    )
                    .await?;
                    let now = ctx.now();
                    let mut entry = Map::new();
                    entry.insert(
                        "compartmentId".into(),
                        Value::String(compartment_id.clone()),
                    );
                    entry.insert("readInAt".into(), num(now));
                    entry.insert(
                        "readInBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    if let Some(agreement_id) = &agreement_id {
                        entry.insert("agreementId".into(), Value::String(agreement_id.clone()));
                    }
                    if let Some(accepted_at) = accepted_at {
                        entry.insert("acceptedAt".into(), num(accepted_at));
                    }
                    let mut items = read_ins(&record);
                    items.push(Value::Object(entry));
                    let mut next = record.clone();
                    next.insert("readIns".into(), Value::Array(items));
                    next.insert("updatedAt".into(), num(now));
                    next.insert(
                        "updatedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    let saved = tx.put(clearances_collection(), &next).await?;
                    let mut metadata = Map::new();
                    metadata.insert("compartmentId".into(), Value::String(compartment_id));
                    metadata.insert(
                        "level".into(),
                        record.get("level").cloned().unwrap_or(Value::Null),
                    );
                    if let Some(agreement_id) = agreement_id {
                        metadata.insert("agreementId".into(), Value::String(agreement_id));
                    }
                    if bootstrap {
                        metadata.insert("bootstrap".into(), Value::Bool(true));
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "clearance:read-in",
                            &tenant.id,
                            &identity.id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(Value::Object(
                        clearance_view(ctx, &tx, &saved, Some(&scheme), Some(&identity)).await?,
                    ))
                })
            },
        );
        let result = self
            .run(
                credential,
                body,
                "iam:clearances:adjudicate",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `clearances/reinstate`: lifts a suspension (back to active or interim). Any officer but the person themselves,
    /// within their own clearance under `within-own`: its level and every compartment it is read into, since
    /// reinstating gives them back. Requires iam:clearances:adjudicate and a recent sign-in; audited as
    /// `clearance:reinstate`.
    pub async fn reinstate(
        &self,
        credential: &CredentialInput,
        input: Body<clearances::ReinstateInput>,
    ) -> IamResult<Reply<clearances::ReinstateOutput>> {
        let ctx = &self.ctx;
        assert_clearances(ctx)?;
        let (resource, identity_id) = clearance_resource(input.get("identityId"))?;
        let body = input.raw();
        let identity_id = &identity_id;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let scheme = scheme_in(ctx, &tx, &tenant).await?;
                    let identity = ctx.active_identity(&tx, identity_id, &tenant.id).await?;
                    let acting =
                        officer(ctx, &tx, &principal, &tenant, &scheme, Some(&identity)).await?;
                    let reason = match body.get("reason") {
                        Some(value) => {
                            Some(core_js::trim(&text(Some(value), "reason", 512)?).to_owned())
                        }
                        None => None,
                    };
                    let record = live_record(&tx, &identity, &scheme).await?;
                    if str_of(&record, "status") != Some("suspended") {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "Only a suspended clearance is reinstated",
                            409,
                        )
                        .into());
                    }
                    let Some(level) = level_in(&scheme, str_of(&record, "level"))? else {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "The clearance\u{2019}s level left the scheme; grant anew",
                        )
                        .into());
                    };
                    let mut bootstrap = within_own(
                        ctx,
                        &tx,
                        &principal,
                        &tenant,
                        &scheme,
                        &acting,
                        Need::Rank(level.rank),
                    )
                    .await?;
                    // The read-ins come back with the clearance: under within-own the officer must hold each
                    // compartment the scheme still defines, as for a read-in (the others never count).
                    for read_in in read_ins(&record) {
                        let compartment_id = read_in.get("compartmentId").and_then(Value::as_str);
                        if let Some(compartment_id) = compartment_id.filter(|id| {
                            scheme
                                .definition
                                .compartments
                                .iter()
                                .any(|item| item.id == *id)
                        }) {
                            bootstrap = within_own(
                                ctx,
                                &tx,
                                &principal,
                                &tenant,
                                &scheme,
                                &acting,
                                Need::Compartment(compartment_id.to_owned()),
                            )
                            .await?
                                || bootstrap;
                        }
                    }
                    let now = ctx.now();
                    let mut next = record.clone();
                    let suspended = next.shift_remove("suspended");
                    let status = suspended
                        .as_ref()
                        .and_then(|suspended| defined(suspended.get("previousStatus")))
                        .cloned()
                        .unwrap_or_else(|| json!("active"));
                    next.insert("status".into(), status);
                    next.insert("updatedAt".into(), num(now));
                    next.insert(
                        "updatedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    let saved = tx.put(clearances_collection(), &next).await?;
                    let mut metadata = Map::new();
                    metadata.insert(
                        "level".into(),
                        saved.get("level").cloned().unwrap_or(Value::Null),
                    );
                    metadata.insert(
                        "status".into(),
                        saved.get("status").cloned().unwrap_or(Value::Null),
                    );
                    if let Some(reason) = reason.filter(|reason| !reason.is_empty()) {
                        metadata.insert("reason".into(), Value::String(reason));
                    }
                    if bootstrap {
                        metadata.insert("bootstrap".into(), Value::Bool(true));
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "clearance:reinstate",
                            &tenant.id,
                            &identity.id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    notify_clearance_status(
                        ctx,
                        &tx,
                        &identity,
                        Some(&scheme),
                        &Value::Object(saved.clone()),
                        "reinstated",
                    )
                    .await?;
                    Ok(Value::Object(
                        clearance_view(ctx, &tx, &saved, Some(&scheme), Some(&identity)).await?,
                    ))
                })
            },
        );
        let result = self
            .run(
                credential,
                body,
                "iam:clearances:adjudicate",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `clearances/revoke`: revokes a clearance for cause and debriefs every compartment; the record stays as history
    /// and a new clearance needs a new grant. The person is emailed (`clearance-status`) unless `notifyPerson` is
    /// false. Requires iam:clearances:adjudicate and a recent sign-in; audited as `clearance:revoke` with the debriefed
    /// compartment ids.
    pub async fn revoke(
        &self,
        credential: &CredentialInput,
        input: Body<clearances::RevokeInput>,
    ) -> IamResult<Reply<clearances::RevokeOutput>> {
        let ctx = &self.ctx;
        assert_clearances(ctx)?;
        let (resource, identity_id) = clearance_resource(input.get("identityId"))?;
        let body = input.raw();
        let identity_id = &identity_id;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let scheme = scheme_in(ctx, &tx, &tenant).await?;
                    officer(ctx, &tx, &principal, &tenant, &scheme, None).await?;
                    let identity: Identity = ctx
                        .scoped_as(&tx, "identities", identity_id, &tenant.id)
                        .await?;
                    let reason =
                        core_js::trim(&text(body.get("reason"), "reason", 512)?).to_owned();
                    let notify_person =
                        flag(body.get("notifyPerson"), "notifyPerson")?.unwrap_or(true);
                    let record = clearance_record(&tx, &identity).await?;
                    let Some(record) = record.filter(|record| live_status(record.get("status")))
                    else {
                        return Err(IamError::with_status(
                            "NOT_FOUND",
                            "This identity holds no clearance to revoke",
                            404,
                        )
                        .into());
                    };
                    let now = ctx.now();
                    let mut next = record.clone();
                    next.shift_remove("suspended");
                    next.insert("status".into(), json!("revoked"));
                    next.insert("readIns".into(), json!([]));
                    next.insert(
                        "revoked".into(),
                        json!({
                            "by": principal.identity.id,
                            "at": num(now),
                            "reason": reason,
                        }),
                    );
                    next.insert("updatedAt".into(), num(now));
                    next.insert(
                        "updatedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    let saved = tx.put(clearances_collection(), &next).await?;
                    let debriefed: Vec<Value> = read_ins(&record)
                        .iter()
                        .map(|item| item.get("compartmentId").cloned().unwrap_or(Value::Null))
                        .collect();
                    let mut metadata = Map::new();
                    metadata.insert(
                        "level".into(),
                        record.get("level").cloned().unwrap_or(Value::Null),
                    );
                    metadata.insert("reason".into(), Value::String(reason));
                    metadata.insert("debriefed".into(), Value::Array(debriefed));
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "clearance:revoke",
                            &tenant.id,
                            &identity.id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    if notify_person {
                        notify_clearance_status(
                            ctx,
                            &tx,
                            &identity,
                            Some(&scheme),
                            &Value::Object(saved.clone()),
                            "revoked",
                        )
                        .await?;
                    }
                    let view =
                        clearance_view(ctx, &tx, &saved, Some(&scheme), Some(&identity)).await?;
                    // Only narrows: an "expect allow" invariant never blocks revoking for cause (invariants.ts).
                    narrows_access_only(&tx);
                    Ok(Value::Object(view))
                })
            },
        );
        let result = self
            .run(
                credential,
                body,
                "iam:clearances:adjudicate",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `clearances/suspend`: suspends an active or interim clearance at once (an incident, an investigation). Needs no
    /// recent sign-in so it works during an incident; lifted only by `reinstate`. The person is emailed
    /// (`clearance-status`) unless `notifyPerson` is false (an investigation that must not tip them off). Requires
    /// iam:clearances:suspend; audited as `clearance:suspend`.
    pub async fn suspend(
        &self,
        credential: &CredentialInput,
        input: Body<clearances::SuspendInput>,
    ) -> IamResult<Reply<clearances::SuspendOutput>> {
        let ctx = &self.ctx;
        assert_clearances(ctx)?;
        let (resource, identity_id) = clearance_resource(input.get("identityId"))?;
        let body = input.raw();
        let identity_id = &identity_id;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    let scheme = scheme_in(ctx, &tx, &tenant).await?;
                    officer(ctx, &tx, &principal, &tenant, &scheme, None).await?;
                    let identity: Identity = ctx
                        .scoped_as(&tx, "identities", identity_id, &tenant.id)
                        .await?;
                    let reason =
                        core_js::trim(&text(body.get("reason"), "reason", 512)?).to_owned();
                    let incident_id = match body.get("incidentId") {
                        Some(value) => Some(text256(Some(value), "incidentId")?),
                        None => None,
                    };
                    let notify_person =
                        flag(body.get("notifyPerson"), "notifyPerson")?.unwrap_or(true);
                    let mut request = Map::new();
                    request.insert("by".into(), Value::String(principal.identity.id.clone()));
                    request.insert("at".into(), num(ctx.now()));
                    request.insert("reason".into(), Value::String(reason.clone()));
                    if let Some(incident_id) = &incident_id {
                        request.insert("incidentId".into(), Value::String(incident_id.clone()));
                    }
                    let result =
                        suspend_clearance(&tx, &identity_value(&identity), &Value::Object(request))
                            .await?;
                    match result.get("outcome").and_then(Value::as_str) {
                        Some("no-clearance") => {
                            return Err(IamError::with_status(
                                "NOT_FOUND",
                                "This identity holds no clearance to suspend",
                                404,
                            )
                            .into());
                        }
                        Some("already-applied") => {
                            return Err(IamError::with_status(
                                "INVALID_TRANSITION",
                                "The clearance is already suspended",
                                409,
                            )
                            .into());
                        }
                        _ => {}
                    }
                    let record = match result.get("record") {
                        Some(Value::Object(record)) => record.clone(),
                        _ => return Err(crate::js::internal_error().into()),
                    };
                    let mut metadata = Map::new();
                    metadata.insert(
                        "level".into(),
                        record.get("level").cloned().unwrap_or(Value::Null),
                    );
                    metadata.insert("reason".into(), Value::String(reason));
                    if let Some(incident_id) = incident_id {
                        metadata.insert("incidentId".into(), Value::String(incident_id));
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "clearance:suspend",
                            &tenant.id,
                            &identity.id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    if notify_person {
                        notify_clearance_status(
                            ctx,
                            &tx,
                            &identity,
                            Some(&scheme),
                            &Value::Object(record.clone()),
                            "suspended",
                        )
                        .await?;
                    }
                    Ok(Value::Object(
                        clearance_view(ctx, &tx, &record, Some(&scheme), Some(&identity)).await?,
                    ))
                })
            },
        );
        let result = self
            .run(
                credential,
                body,
                "iam:clearances:suspend",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `clearances/templates`: the built-in scheme templates (us, uk, nato, corporate); any signed-in caller.
    pub async fn templates(
        &self,
        credential: &CredentialInput,
        input: Body<clearances::TemplatesInput>,
    ) -> IamResult<Reply<clearances::TemplatesOutput>> {
        let _ = &input;
        assert_clearances(&self.ctx)?;
        self.ctx.principals()?.authenticate(credential).await?;
        let mut list = Vec::new();
        for (name, display) in TEMPLATE_NAMES {
            let template = classification_template(name).ok_or_else(crate::js::internal_error)?;
            list.push(json!({
                "id": name,
                "name": display,
                "definition": validate_scheme(&json!(template))?,
            }));
        }
        Ok(Reply::json(Value::Array(list)))
    }

    /// `clearances/update`: changes a live clearance: level, citizenship, interim or final, investigation and dates
    /// (null clears one). The same rules as `grant` apply to the higher of the old and the new level. Requires
    /// iam:clearances:adjudicate and a recent sign-in; audited as `clearance:update`.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<clearances::UpdateInput>,
    ) -> IamResult<Reply<clearances::UpdateOutput>> {
        let ctx = &self.ctx;
        assert_clearances(ctx)?;
        let (resource, identity_id) = clearance_resource(input.get("identityId"))?;
        let body = input.raw();
        let identity_id = &identity_id;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let scheme = scheme_in(ctx, &tx, &tenant).await?;
                    let identity = ctx.active_identity(&tx, identity_id, &tenant.id).await?;
                    let acting =
                        officer(ctx, &tx, &principal, &tenant, &scheme, Some(&identity)).await?;
                    let record = live_record(&tx, &identity, &scheme).await?;
                    let previous = level_in(&scheme, str_of(&record, "level"))?;
                    let level = match body.get("level") {
                        Some(value) => level_of(&scheme, Some(value))?,
                        None => match &previous {
                            Some(previous) => previous.clone(),
                            None => {
                                return Err(IamError::new(
                                    "INVALID_INPUT",
                                    "The clearance\u{2019}s level left the scheme; set a level",
                                )
                                .into());
                            }
                        },
                    };
                    assert_guest_level(&scheme, &identity, &level)?;
                    let mut next = record.clone();
                    next.insert("level".into(), Value::String(level.id.clone()));
                    let mut changed: Vec<&str> = Vec::new();
                    if str_of(&record, "level") != Some(level.id.as_str()) {
                        changed.push("level");
                    }
                    if let Some(value) = body.get("citizenship") {
                        next.insert("citizenship".into(), json!(citizenship_list(Some(value))?));
                        changed.push("citizenship");
                    }
                    if let Some(interim) = flag(body.get("interim"), "interim")? {
                        if interim && !scheme.interim_allowed {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                "This scheme does not allow interim clearances",
                            )
                            .into());
                        }
                        let status = if interim { "interim" } else { "active" };
                        let suspended = record
                            .get("suspended")
                            .filter(|suspended| truthy(Some(suspended)));
                        match suspended {
                            Some(suspended) if str_of(&record, "status") == Some("suspended") => {
                                let mut held = suspended.as_object().cloned().unwrap_or_default();
                                held.insert("previousStatus".into(), json!(status));
                                next.insert("suspended".into(), Value::Object(held));
                            }
                            _ => {
                                next.insert("status".into(), json!(status));
                            }
                        }
                        changed.push("interim");
                    }
                    match body.get("investigation") {
                        None => {}
                        Some(Value::Null) => {
                            next.shift_remove("investigation");
                            changed.push("investigation");
                        }
                        Some(value) => {
                            next.insert(
                                "investigation".into(),
                                investigation_of(ctx, Some(value))?,
                            );
                            changed.push("investigation");
                        }
                    }
                    match body.get("reinvestigationDue") {
                        None => {}
                        Some(Value::Null) => {
                            next.shift_remove("reinvestigationDue");
                            changed.push("reinvestigationDue");
                        }
                        Some(value) => {
                            next.insert(
                                "reinvestigationDue".into(),
                                num(due_of(ctx, Some(value))?),
                            );
                            changed.push("reinvestigationDue");
                        }
                    }
                    match body.get("expiresAt") {
                        None => {}
                        Some(Value::Null) => {
                            next.shift_remove("expiresAt");
                            changed.push("expiresAt");
                        }
                        Some(value) => {
                            next.insert("expiresAt".into(), num(end_of(ctx, Some(value))?));
                            changed.push("expiresAt");
                        }
                    }
                    if changed.is_empty() {
                        return Ok(Value::Object(
                            clearance_view(ctx, &tx, &record, Some(&scheme), Some(&identity))
                                .await?,
                        ));
                    }
                    let rank = level.rank.max(
                        previous
                            .as_ref()
                            .map(|previous| previous.rank)
                            .unwrap_or(level.rank),
                    );
                    let bootstrap = within_own(
                        ctx,
                        &tx,
                        &principal,
                        &tenant,
                        &scheme,
                        &acting,
                        Need::Rank(rank),
                    )
                    .await?;
                    let now = ctx.now();
                    next.insert("updatedAt".into(), num(now));
                    next.insert(
                        "updatedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    let saved = tx.put(clearances_collection(), &next).await?;
                    let mut metadata = Map::new();
                    metadata.insert(
                        "level".into(),
                        saved.get("level").cloned().unwrap_or(Value::Null),
                    );
                    if saved.get("level") != record.get("level") {
                        metadata.insert(
                            "previousLevel".into(),
                            record.get("level").cloned().unwrap_or(Value::Null),
                        );
                    }
                    metadata.insert(
                        "status".into(),
                        saved.get("status").cloned().unwrap_or(Value::Null),
                    );
                    metadata.insert("changed".into(), json!(changed));
                    if bootstrap {
                        metadata.insert("bootstrap".into(), Value::Bool(true));
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "clearance:update",
                            &tenant.id,
                            &identity.id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(Value::Object(
                        clearance_view(ctx, &tx, &saved, Some(&scheme), Some(&identity)).await?,
                    ))
                })
            },
        );
        let result = self
            .run(
                credential,
                body,
                "iam:clearances:adjudicate",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `clearances/updateScheme`: changes the scheme this tenant defines (an inherited one is changed where it is
    /// defined: CONFLICT). New levels go above every remaining level; no level is ever re-ranked (one removed earlier
    /// comes back only at its former rank), a level or compartment that a live clearance or a label uses cannot be
    /// removed, and every label must stay valid (RESOURCE_IN_USE). Settings change freely. `version` (optional) must
    /// match the stored one. Requires iam:classifications:manage and a recent sign-in; audited as
    /// `classification:scheme-update`.
    pub async fn update_scheme(
        &self,
        credential: &CredentialInput,
        input: Body<clearances::UpdateSchemeInput>,
    ) -> IamResult<Reply<clearances::UpdateSchemeOutput>> {
        let ctx = &self.ctx;
        assert_clearances(ctx)?;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    if body.contains_key("template") {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "Templates start a scheme; change it with definition",
                        )
                        .into());
                    }
                    let Some(scheme) = defined_scheme(&tx, &tenant.id).await? else {
                        if scheme_in_force(ctx, &tx, &tenant).await?.is_some() {
                            return Err(IamError::with_status(
                                "CONFLICT",
                                "The scheme in force here is defined by an ancestor tenant; change it there",
                                409,
                            )
                            .into());
                        }
                        return Err(IamError::with_status(
                            "NOT_FOUND",
                            "This tenant defines no classification scheme",
                            404,
                        )
                        .into());
                    };
                    if let Some(version) = body.get("version")
                        && version.as_f64() != Some(scheme.version)
                    {
                        return Err(IamError::with_status(
                            "VERSION_CONFLICT",
                            "The scheme changed; reload it first",
                            409,
                        )
                        .into());
                    }
                    let definition_input = body.get("definition");
                    let definition = match definition_input {
                        Some(value) => validate_scheme(value)?,
                        None => scheme.definition.clone(),
                    };
                    let settings = scheme_settings(body, &definition, Some(&scheme))?;
                    if definition_input.is_some() {
                        assert_definition_change(&tx, &scheme, &definition).await?;
                    }
                    let mut changed: Vec<&str> = Vec::new();
                    if definition_input.is_some() {
                        changed.push("definition");
                    }
                    for field in [
                        "name",
                        "requireLabels",
                        "defaultLabel",
                        "guestCeiling",
                        "interimAllowed",
                        "adjudication",
                        "notify",
                    ] {
                        if body.contains_key(field) {
                            changed.push(field);
                        }
                    }
                    let now = ctx.now();
                    let retired = retired_levels_after(&scheme, &definition)?;
                    let mut next = raw_record(&tx, schemes(), &scheme.id, &scheme).await?;
                    next.shift_remove("defaultLabel");
                    next.shift_remove("notify");
                    next.shift_remove("retiredLevels");
                    next.insert("definition".into(), json!(definition));
                    for (key, value) in settings.members() {
                        next.insert(key, value);
                    }
                    if !retired.is_empty() {
                        next.insert("retiredLevels".into(), Value::Array(retired));
                    }
                    next.insert("updatedAt".into(), num(now));
                    next.insert(
                        "updatedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    next.insert("version".into(), num(scheme.version + 1.0));
                    let saved: ClassificationScheme = decode(tx.put(schemes(), &next).await?)?;
                    let mut metadata = Map::new();
                    metadata.insert("changed".into(), json!(changed));
                    metadata.insert("version".into(), num(saved.version));
                    if definition_input.is_some() {
                        let (levels, compartments) = definition_ids(&definition);
                        metadata.insert("levels".into(), levels);
                        metadata.insert("compartments".into(), compartments);
                        metadata.insert("ownerCountries".into(), json!(definition.owner_countries));
                    }
                    if body.contains_key("guestCeiling") {
                        metadata.insert("guestCeiling".into(), settings.guest_ceiling.clone());
                    }
                    if body.contains_key("adjudication") {
                        metadata.insert(
                            "adjudication".into(),
                            Value::String(settings.adjudication.clone()),
                        );
                    }
                    if body.contains_key("interimAllowed") {
                        metadata.insert(
                            "interimAllowed".into(),
                            Value::Bool(settings.interim_allowed),
                        );
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "classification:scheme-update",
                            &tenant.id,
                            &scheme.id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(scheme_view(&saved, &tenant.id))
                })
            },
        );
        let result = self
            .run(
                credential,
                body,
                "iam:classifications:manage",
                SCHEME_RESOURCE,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

// --- reminders -------------------------------------------------------------------------------------------------

/// What one tenant's reminder run produced.
enum TenantReminders {
    Inactive,
    Ran {
        sent: Vec<Value>,
        no_recipients: f64,
    },
}

/// A date a clearance reminder is about.
struct Due {
    kind: &'static str,
    at: f64,
}

/// Reminds officers of reinvestigations and clearance ends (see [`ClearancesRuntime::send_reminders`]).
async fn send_reminders(ctx: &Arc<ServerContext>, input: &Value) -> IamResult<Value> {
    assert_clearances(ctx)?;
    let default_days = json!(limit("reminderDays"));
    let within_days = integer(
        defined(crate::js::member(Some(input), "withinDays")).or(Some(&default_days)),
        "withinDays",
        1.0,
        365.0,
    )?;
    if !sends_email(ctx) {
        return Err(IamError::new(
            "DELIVERY_REQUIRED",
            "Clearance reminders require an email delivery callback",
        ));
    }
    let live = |record: &Record| matches!(str_of(record, "status"), Some("active" | "interim"));
    let tenant_ids: Vec<String> = match crate::js::member(Some(input), "tenantId") {
        Some(value) => vec![text256(Some(value), "tenantId")?],
        None => {
            let all = ctx
                .store
                .find(
                    clearances_collection(),
                    &Filter::new(),
                    &FindOptions::default(),
                )
                .await?;
            let ids = crate::js::unique(
                all.iter()
                    .filter(|record| live(record))
                    .map(|record| js_string(record.get("tenantId"))),
            );
            sorted(ids)
        }
    };
    let mut sent_all: Vec<Value> = Vec::new();
    let mut inactive = 0.0;
    let mut no_recipients_all = 0.0;
    for tenant_id in tenant_ids {
        let run_ctx = ctx.clone();
        let outcome = ctx
            .store
            .transaction(move |tx| async move {
                let ctx = run_ctx;
                let Some(tenant_record) = tx.get("tenants", &tenant_id).await? else {
                    return Ok(TenantReminders::Inactive);
                };
                if str_of(&tenant_record, "status") != Some("active") {
                    return Ok(TenantReminders::Inactive);
                }
                let tenant: Tenant = decode(tenant_record)?;
                let mut sent: Vec<Value> = Vec::new();
                let mut no_recipients = 0.0;
                let Some(scheme) = scheme_in_force(&ctx, &tx, &tenant).await? else {
                    return Ok(TenantReminders::Ran {
                        sent,
                        no_recipients,
                    });
                };
                let now = ctx.now();
                let horizon = now + within_days * DAY_MS;
                let mut reminded: HashSet<String> = tx
                    .find(
                        "expiryReminderMarks",
                        &Filter::new().eq("tenantId", tenant_id.clone()),
                        &FindOptions::default(),
                    )
                    .await?
                    .iter()
                    .map(|mark| js_string(mark.get("uniqueKey")))
                    .collect();
                let mut recipients: Option<Vec<String>> = None;
                let mut records: Vec<Record> = tx
                    .find(
                        clearances_collection(),
                        &Filter::new().eq("tenantId", tenant_id.clone()),
                        &FindOptions::default(),
                    )
                    .await?
                    .into_iter()
                    .filter(|record| str_of(record, "tenantId") == Some(tenant_id.as_str()))
                    .filter(|record| live(record))
                    .collect();
                records.sort_by(|a, b| cmp_utf16(&js_string(a.get("id")), &js_string(b.get("id"))));
                for record in records {
                    if str_of(&record, "schemeTenantId") != Some(scheme.tenant_id.as_str()) {
                        continue;
                    }
                    let identity_id = js_string(record.get("identityId"));
                    let Some(person) = tx.get("identities", &identity_id).await? else {
                        continue;
                    };
                    if str_of(&person, "tenantId") != Some(tenant_id.as_str())
                        || str_of(&person, "status") != Some("active")
                        || number_member(&person, "expiresAt").is_some_and(|at| at <= now)
                    {
                        continue;
                    }
                    let record_id = js_string(record.get("id"));
                    let mut due: Vec<Due> = Vec::new();
                    if let Some(at) =
                        number_member(&record, "reinvestigationDue").filter(|at| *at <= horizon)
                    {
                        due.push(Due {
                            kind: "reinvestigation",
                            at,
                        });
                    }
                    if let Some(at) =
                        number_member(&record, "expiresAt").filter(|at| *at > now && *at <= horizon)
                    {
                        due.push(Due {
                            kind: if str_of(&record, "status") == Some("interim") {
                                "interim-end"
                            } else {
                                "expiry"
                            },
                            at,
                        });
                    }
                    let mark_key = |at: f64| {
                        format!(
                            "clearance-reminder:{record_id}:{}",
                            core_js::number_to_string(at)
                        )
                    };
                    due.retain(|item| !reminded.contains(&mark_key(item.at)));
                    if due.is_empty() {
                        continue;
                    }
                    if recipients.is_none() {
                        let owners = tx
                            .find(
                                "identities",
                                &Filter::new()
                                    .eq("tenantId", scheme.tenant_id.clone())
                                    .eq("owner", true)
                                    .eq("status", "active"),
                                &FindOptions::default(),
                            )
                            .await?;
                        let mut addresses: Vec<String> = owners
                            .iter()
                            .filter(|owner| {
                                str_of(owner, "kind") == Some("user")
                                    && owner.get("guest").is_none()
                                    && owner.get("email").is_some_and(Value::is_string)
                                    && !number_member(owner, "expiresAt")
                                        .is_some_and(|at| at <= now)
                            })
                            .map(|owner| core_js::to_lower(str_of(owner, "email").unwrap_or("")))
                            .collect();
                        if let Some(emails) = scheme
                            .notify
                            .as_ref()
                            .and_then(|notify| notify.get("emails"))
                            .and_then(Value::as_array)
                        {
                            addresses.extend(emails.iter().map(|address| js_string(Some(address))));
                        }
                        recipients = Some(sorted(crate::js::unique(addresses)));
                    }
                    let to = recipients.clone().unwrap_or_default();
                    if to.is_empty() {
                        no_recipients += 1.0;
                        continue;
                    }
                    let due_at = due.iter().map(|item| item.at).fold(f64::INFINITY, f64::min);
                    let level = level_in(&scheme, str_of(&record, "level"))?;
                    let person_id = js_string(person.get("id"));
                    for address in &to {
                        let mut payload = Map::new();
                        payload.insert("tenantId".into(), Value::String(tenant_id.clone()));
                        payload.insert("tenantName".into(), Value::String(tenant.name.clone()));
                        payload.insert("identityId".into(), Value::String(person_id.clone()));
                        payload.insert(
                            "personName".into(),
                            person.get("name").cloned().unwrap_or(Value::Null),
                        );
                        if let Some(level) = &level {
                            payload.insert("levelName".into(), Value::String(level.name.clone()));
                        }
                        payload.insert(
                            "status".into(),
                            record.get("status").cloned().unwrap_or(Value::Null),
                        );
                        payload.insert("dueAt".into(), Value::String(iso(due_at)?));
                        if let Some(at) = number_member(&record, "reinvestigationDue") {
                            payload.insert("reinvestigationDue".into(), Value::String(iso(at)?));
                        }
                        if let Some(at) = number_member(&record, "expiresAt") {
                            payload.insert("expiresAt".into(), Value::String(iso(at)?));
                        }
                        ctx.auth
                            .enqueue_delivery(
                                &tx,
                                EnqueueInput {
                                    tenant_id: tenant_id.clone(),
                                    kind: OutboxKind::Email,
                                    to: address.clone(),
                                    template: "clearance-reminder".into(),
                                    payload,
                                    reference: None,
                                },
                            )
                            .await?;
                    }
                    for item in &due {
                        let key = mark_key(item.at);
                        reminded.insert(key.clone());
                        let mut mark = Map::new();
                        mark.insert("id".into(), Value::String(id()));
                        mark.insert("tenantId".into(), Value::String(tenant_id.clone()));
                        mark.insert("uniqueKey".into(), Value::String(key));
                        mark.insert("identityId".into(), Value::String(person_id.clone()));
                        // Outlives the date, so the purge cannot let the reminder go out again while it is due.
                        mark.insert(
                            "expiresAt".into(),
                            num(item.at.max(now) + within_days * DAY_MS),
                        );
                        tx.insert("expiryReminderMarks", &mark).await?;
                    }
                    let mut event = Map::new();
                    event.insert("id".into(), Value::String(id()));
                    event.insert("tenantId".into(), Value::String(tenant_id.clone()));
                    event.insert("actorId".into(), json!("deployment-operator"));
                    event.insert("action".into(), json!("clearance:reminder"));
                    event.insert("resourceId".into(), Value::String(person_id.clone()));
                    event.insert("timestamp".into(), num(now));
                    event.insert("outcome".into(), json!("allow"));
                    event.insert(
                        "metadata".into(),
                        json!({
                            "level": record.get("level").cloned().unwrap_or(Value::Null),
                            "dueAt": num(due_at),
                            "kinds": due.iter().map(|item| item.kind).collect::<Vec<_>>(),
                            "recipients": to.len(),
                        }),
                    );
                    ctx.events()?.record_audit(&tx, &event).await?;
                    sent.push(json!({
                        "tenantId": tenant_id,
                        "identityId": person_id,
                        "dueAt": num(due_at),
                        "recipients": to.len(),
                    }));
                }
                Ok(TenantReminders::Ran {
                    sent,
                    no_recipients,
                })
            })
            .await?;
        match outcome {
            TenantReminders::Inactive => inactive += 1.0,
            TenantReminders::Ran {
                sent,
                no_recipients,
            } => {
                sent_all.extend(sent);
                no_recipients_all += no_recipients;
            }
        }
    }
    Ok(json!({
        "sent": sent_all,
        "skipped": { "inactive": num(inactive), "noRecipients": num(no_recipients_all) },
    }))
}

/// Clearances, server side (`createClearancesRuntime(ctx)`, `IamClearances`).
pub struct ClearancesRuntime {
    ctx: Arc<ServerContext>,
}

/// `createClearancesRuntime(ctx)`.
pub fn create_clearances_runtime(ctx: &Arc<ServerContext>) -> IamResult<ClearancesRuntime> {
    Ok(ClearancesRuntime { ctx: ctx.clone() })
}

impl ClearancesRuntime {
    /// Emails the owners of each scheme's defining tenant and the scheme's `notify.emails` (template
    /// `clearance-reminder`, naming the level only, never compartments) about clearances whose periodic reinvestigation
    /// is due or whose end (interim or final) falls within `withinDays` (default 60): each date once. `tenantId` limits
    /// the run to the clearances held in that tenant. Requires an email delivery callback and the `clearances` option.
    pub async fn send_reminders(&self, input: Option<&Value>) -> IamResult<Value> {
        let empty = json!({});
        send_reminders(&self.ctx, input.unwrap_or(&empty)).await
    }

    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        match method {
            "sendReminders" => Some(self.send_reminders(args.first()).await),
            _ => None,
        }
    }
}
