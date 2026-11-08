//! Port of `packages/server/src/clearances.ts`.
//!
//! Security clearances and mandatory access control (the `clearances` option). A tenant (normally an organization)
//! defines a classification scheme: ranked levels, compartments and dissemination controls (core classification.rs).
//! The scheme in force for a tenant is the one defined closest to the root of its ancestry, so a child can neither
//! redefine nor re-rank what its ancestors classify. Officers adjudicate one clearance per identity (level, adjudicated
//! citizenship, read-ins to compartments backed by NDAs) and label resources; the label is IAM-held (`resourceLabels`),
//! inherited down managed parents, and can only be raised by the application's resolver. At decision time every party
//! of the session must dominate the resource's label (Bell-LaPadula simple security property: no read up), whatever
//! roles, policies and relationships say; `iam:*` administration is never subject. Status, expiry, the guest ceiling
//! and NDA acceptance are evaluated at decision time, never by a worker.
//!
//! Labels are handled as JSON (`Value`) inside the module, as the TypeScript functions handle `unknown` labels: a
//! stored or asserted label is read through [`better_iam_core::is_valid_classification_label`] and becomes the
//! invalid label (which refuses every party) when the scheme cannot read it. They become typed
//! [`better_iam_core::ClassificationLabel`]s only where a signature asks for one.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use better_iam_auth::outbox::EnqueueInput;
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, ClassificationLabel, ClassificationLevel,
    ClassificationSchemeDefinition, ClearanceParty, Decision, DominanceFailure, Filter,
    FilterValue, FindOptions, IamError, IamResult, Identity, IdentityKind, IdentityStatus,
    OutboxKind, Record, ResourceFilter, SessionKind, Tenant, dominates,
    is_valid_classification_label, join_labels, label_rank, not_filter, validate_label,
};
use futures::future::BoxFuture;
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::agreements::{Agreement, AgreementAcceptance, acceptance_current};
use crate::catalog::{is_internal_resource_type, managed_resource, resolved_managed};
use crate::context::{ServerContext, Store};
use crate::js::{number, sort_strings};
use crate::models::ResourceRecord;
use crate::options::ResolvedResource;
use crate::port::decode;
use crate::utils::{date_now, hash, id};

/// How officers may adjudicate: `'within-own'` (only within their own clearance) or `'unrestricted'` (any level the
/// scheme defines). Kept as the stored JSON string.
pub type AdjudicationMode = Value;

/// A tenant's classification scheme; `tenantId` is the defining tenant (its whole subtree uses it).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClassificationScheme {
    #[serde(rename = "uniqueKey")]
    pub unique_key: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "definition")]
    pub definition: better_iam_core::ClassificationSchemeDefinition,
    /// Resource types that must carry a label (`*`: every application type); unlabeled ones are refused.
    #[serde(rename = "requireLabels")]
    pub require_labels: Vec<String>,
    /// Applied to unlabeled resources of the required types instead of refusing them.
    #[serde(
        rename = "defaultLabel",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub default_label: Option<better_iam_core::ClassificationLabel>,
    /// The highest level a guest's clearance counts as; null: guests hold no clearance.
    #[serde(
        rename = "guestCeiling",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub guest_ceiling: Option<String>,
    /// Whether interim clearances count at decision time.
    #[serde(rename = "interimAllowed")]
    pub interim_allowed: bool,
    #[serde(rename = "adjudication")]
    pub adjudication: crate::clearances::AdjudicationMode,
    /// Extra recipients of `iam.clearances.sendReminders` besides the defining tenant's owners (`{ emails }`).
    #[serde(rename = "notify", default, skip_serializing_if = "Option::is_none")]
    pub notify: Option<Value>,
    /// Levels removed from the definition, with the rank they had (`{ id, rank }`): one comes back only at that rank,
    /// so labels your application asserts with its id (which IAM cannot see) are never re-ranked by removing and
    /// re-adding it.
    #[serde(
        rename = "retiredLevels",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub retired_levels: Option<Vec<Value>>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(rename = "updatedBy")]
    pub updated_by: String,
    #[serde(rename = "version")]
    pub version: f64,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One identity's adjudicated clearance, in the identity's tenant (the record id is the identity id).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Clearance {
    #[serde(rename = "uniqueKey")]
    pub unique_key: String,
    #[serde(rename = "identityId")]
    pub identity_id: String,
    /// The tenant whose scheme it was issued under; it counts only while that scheme is the one in force.
    #[serde(rename = "schemeTenantId")]
    pub scheme_tenant_id: String,
    #[serde(rename = "level")]
    pub level: String,
    /// Adjudicated citizenship (ISO 3166-1 alpha-3), the only source of NOFORN and REL TO decisions.
    #[serde(rename = "citizenship", default)]
    pub citizenship: Vec<String>,
    #[serde(rename = "status")]
    pub status: crate::clearances::ClearanceStatus,
    /// `{ kind, completedAt }`.
    #[serde(
        rename = "investigation",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub investigation: Option<Value>,
    #[serde(
        rename = "reinvestigationDue",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub reinvestigation_due: Option<f64>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    /// `ClearanceReadIn`s: `{ compartmentId, readInAt, readInBy, agreementId?, acceptedAt? }`; with `agreementId` a
    /// read-in counts only while the person's NDA acceptance is current.
    #[serde(rename = "readIns", default)]
    pub read_ins: Vec<Value>,
    #[serde(rename = "grantedAt")]
    pub granted_at: f64,
    #[serde(rename = "grantedBy")]
    pub granted_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(rename = "updatedBy")]
    pub updated_by: String,
    /// `{ by, at, reason, incidentId?, previousStatus }` (the status a reinstatement returns to).
    #[serde(rename = "suspended", default, skip_serializing_if = "Option::is_none")]
    pub suspended: Option<Value>,
    /// `{ by, at, reason }`.
    #[serde(rename = "revoked", default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<Value>,
    /// `{ by, at, reason }`.
    #[serde(
        rename = "terminated",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub terminated: Option<Value>,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `'interim' | 'active' | 'suspended' | 'revoked' | 'terminated'`, kept as the stored JSON string.
pub type ClearanceStatus = Value;

/// What a clearance counts as at decision time: `active` or `interim` when it applies, otherwise why not (`none`:
/// no record, another scheme, an unknown level, an interim the scheme does not allow, a guest without a ceiling, or
/// an inactive identity; `expired`; or the record's own `suspended` / `revoked` / `terminated`). A JSON string.
pub type EffectiveClearanceStatus = Value;

/// What decisions enforce for one session in one tenant (decisions.ts): the policy keys and the mandatory check.
/// Built once per prepared decision by `clearanceScope`.
#[async_trait::async_trait]
pub trait MandatoryAccess: Send + Sync {
    /// The scheme the check enforces in the tenant (see `schemeForTenant`), so `resolve` attaches labels under it
    /// without reading it again.
    fn scheme(&self) -> &ClassificationScheme;
    /// `principal.clearance*` keys: the lowest rank of the parties, the shared compartments and citizenship.
    fn keys(&self) -> &Map<String, Value>;
    /// The label `check` applies to a resource whose label `resolve` attached, or None when it carries none.
    fn label(
        &self,
        resource: &crate::options::ResolvedResource,
    ) -> Option<better_iam_core::ClassificationLabel>;
    /// The rank of a label's level in the scheme (`resource.classificationRank`); None for an unknown level.
    fn rank(&self, label: &better_iam_core::ClassificationLabel) -> Option<f64>;
    /// `{ allowed: false, reason: 'CLEARANCE_REQUIRED' }` unless every party dominates the resource's label; None
    /// when the check passes. `iam:*` actions are never subject.
    fn check(
        &self,
        resource: &crate::options::ResolvedResource,
        action: &str,
    ) -> Option<better_iam_core::Decision>;
    /// For query planning (`planResources`): the resources of `type` every party may read, by id.
    async fn filter(
        &self,
        kind: &str,
        action: Option<&str>,
    ) -> IamResult<better_iam_core::ResourceFilter>;
}

/// What `resolve` may take as known when it attaches a label (`known` of `attachLabel`, `preparedLabeling` of
/// decisions.ts): the scheme the decision enforces (None: none), and for an `iam/{type}/{id}` alias the named resource
/// as the application resolves it (`Some(None)`: its resolver failed, which refuses every party).
#[derive(Clone, Default)]
pub struct KnownLabeling {
    pub scheme: Option<ClassificationScheme>,
    pub named: Option<Option<crate::options::ResolvedResource>>,
}

/// A party's clearance as it stands at decision time.
#[derive(Debug, Clone)]
pub struct PartyState {
    pub party: better_iam_core::ClearanceParty,
    pub status: crate::clearances::EffectiveClearanceStatus,
    /// The level the party counts at (capped for guests); absent without a clearance.
    pub level: Option<better_iam_core::ClassificationLevel>,
    pub record: Option<crate::clearances::Clearance>,
}

/// An IAM-held classification label of one resource; it outlives the resource, so deleting cannot declassify.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceLabel {
    /// `{type}/{resourceId}`, or `sha256:{hex}` of it when longer than 512 bytes (`labelKey`).
    #[serde(rename = "uniqueKey")]
    pub unique_key: String,
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(rename = "resourceId")]
    pub resource_id: String,
    #[serde(rename = "label")]
    pub label: better_iam_core::ClassificationLabel,
    /// Whether the label also applies to every managed descendant of the resource.
    #[serde(rename = "inheritToChildren")]
    pub inherit_to_children: bool,
    /// The defining tenant of the scheme the label was written under.
    #[serde(rename = "schemeTenantId")]
    pub scheme_tenant_id: String,
    #[serde(rename = "labeledBy")]
    pub labeled_by: String,
    #[serde(rename = "labeledAt")]
    pub labeled_at: f64,
    #[serde(rename = "version")]
    pub version: f64,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The collections of the clearance module (tenant scoped; tenant purge sweeps them).
pub static CLEARANCE_COLLECTIONS: std::sync::LazyLock<Value> = std::sync::LazyLock::new(
    || json!({"schemes":"classificationSchemes","clearances":"clearances","labels":"resourceLabels"}),
);

/// Limits of the clearance module.
pub static CLEARANCE_LIMITS: std::sync::LazyLock<Value> = std::sync::LazyLock::new(
    || json!({"maxRequiredTypes":100,"maxCitizenship":10,"maxNotifyEmails":20,"maxInheritanceDepth":16,"maxRetiredLevels":500,"reminderDays":60}),
);

/// `clearanceCollections.schemes`.
pub const SCHEMES: &str = "classificationSchemes";
/// `clearanceCollections.clearances`.
pub const CLEARANCES: &str = "clearances";
/// `clearanceCollections.labels`.
pub const LABELS: &str = "resourceLabels";

/// `clearanceLimits.maxRequiredTypes`: resource types a scheme may require labels on.
pub const MAX_REQUIRED_TYPES: usize = 100;
/// `clearanceLimits.maxCitizenship`: countries on one clearance record.
pub const MAX_CITIZENSHIP: usize = 10;
/// `clearanceLimits.maxNotifyEmails`: extra addresses `sendReminders` emails besides the scheme tenant's owners.
pub const MAX_NOTIFY_EMAILS: usize = 20;
/// `clearanceLimits.maxInheritanceDepth`: how far up managed parents a label is inherited from.
pub const MAX_INHERITANCE_DEPTH: f64 = 16.0;
/// `clearanceLimits.maxRetiredLevels`: distinct levels a scheme may remove over its life.
pub const MAX_RETIRED_LEVELS: usize = 500;
/// `clearanceLimits.reminderDays`: default window of `sendReminders`, in days.
pub const REMINDER_DAYS: f64 = 60.0;

const SCHEME_KEY: &str = "scheme";

/// Resource types the built-in modules resolve themselves (models and the provider tools they run, SSH logins and
/// hosts, credential types); `requireLabels: ['*']` (all application types) skips them.
const MODULE_RESOURCE_TYPES: [&str; 5] = [
    "model",
    "model-tool",
    "ssh-login",
    "ssh-host",
    "credential-type",
];

/// Resource types one record of which serves a whole subtree: an inference model resolves up the tenant tree, so a
/// project uses its organization's models. A label of such a resource written in any tenant of the deciding tenant's
/// ancestry applies to it as well, joined like any other.
const TREE_RESOURCE_TYPES: [&str; 1] = ["model"];

/// The type of the resource each of these is part of, named by the first segment of their ids (`containerOf`).
fn container_type(kind: &str) -> Option<&'static str> {
    match kind {
        "ssh-login" => Some("ssh-host"),
        _ => None,
    }
}

/// A resource reference (`Reference`).
#[derive(Debug, Clone, PartialEq)]
struct Reference {
    kind: String,
    id: String,
}

/// `refKey(ref)`: `{type}/{id}`.
fn ref_key(reference: &Reference) -> String {
    format!("{}/{}", reference.kind, reference.id)
}

/// The resource another one is part of, whose own label it always carries (whatever its `inheritToChildren`): an SSH
/// login (`ssh-login/{host}/{login}`) is access to its host, so a label on `ssh-host/{host}` applies to every login
/// of the host, those added later included.
fn container_of(kind: &str, resource_id: &str) -> Option<Reference> {
    let container = container_type(kind)?;
    match resource_id.find('/') {
        Some(slash) if slash > 0 => Some(Reference {
            kind: container.to_owned(),
            id: resource_id[..slash].to_owned(),
        }),
        _ => None,
    }
}

/// A label that is valid for no scheme (level ids start with a letter or digit): it refuses every party.
fn invalid_label() -> Value {
    json!({ "level": "!invalid" })
}

/// A label value as the typed label a signature asks for; anything that is not one reads as the invalid label, so
/// it still refuses every party.
fn typed_label(label: &Value) -> ClassificationLabel {
    serde_json::from_value(label.clone()).unwrap_or_else(|_| ClassificationLabel {
        level: "!invalid".into(),
        compartments: None,
        noforn: None,
        releasable_to: None,
    })
}

/// `value.slice(0, max)` in UTF-16 code units (a surrogate pair is never split).
fn slice_utf16(value: &str, max: usize) -> String {
    let mut out = String::new();
    let mut units = 0;
    for ch in value.chars() {
        units += ch.len_utf16();
        if units > max {
            break;
        }
        out.push(ch);
    }
    out
}

/// A string member of a record.
fn str_member<'a>(record: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

/// Refuses with FEATURE_DISABLED (403) unless the deployment enables clearances.
pub fn assert_clearances(ctx: &Arc<ServerContext>) -> IamResult<()> {
    if ctx.options.clearances.is_none() {
        return Err(IamError::with_status(
            "FEATURE_DISABLED",
            "Security clearances are not enabled on this deployment",
            403,
        ));
    }
    Ok(())
}

/// The natural key of a resource's label: `{type}/{id}`, hashed when it would exceed 512 UTF-8 bytes.
pub fn label_key(r#type: &str, resource_id: &str) -> IamResult<String> {
    Ok(label_key_of(r#type, resource_id))
}

fn label_key_of(kind: &str, resource_id: &str) -> String {
    let key = format!("{kind}/{resource_id}");
    if key.len() <= 512 {
        key
    } else {
        format!("sha256:{}", hash(&key))
    }
}

/// The scheme a tenant defines itself, if it does.
pub async fn defined_scheme(
    tx: &Store,
    tenant_id: &str,
) -> IamResult<Option<crate::clearances::ClassificationScheme>> {
    let found = tx
        .find(
            SCHEMES,
            &Filter::new()
                .eq("tenantId", tenant_id)
                .eq("uniqueKey", SCHEME_KEY),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .next();
    match found {
        Some(found) if str_member(&found, "tenantId") == Some(tenant_id) => {
            Ok(Some(decode(found)?))
        }
        _ => Ok(None),
    }
}

/// The scheme in force for a tenant, given its ancestry (`[tenant, parent, ..., root]`): the one defined closest to
/// the root. Undefined when no tenant of the chain defines one.
pub async fn effective_scheme(
    tx: &Store,
    chain: &[Value],
) -> IamResult<Option<crate::clearances::ClassificationScheme>> {
    let ids: Vec<String> = chain
        .iter()
        .map(|realm| {
            realm
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    effective_scheme_of(tx, &ids).await
}

/// `effectiveScheme` over the tenant ids of an ancestry (`[tenant, parent, ..., root]`).
pub async fn effective_scheme_of(
    tx: &Store,
    chain: &[String],
) -> IamResult<Option<ClassificationScheme>> {
    for tenant_id in chain.iter().rev() {
        if let Some(scheme) = defined_scheme(tx, tenant_id).await? {
            return Ok(Some(scheme));
        }
    }
    Ok(None)
}

/// The tenant ids of an ancestry of tenants.
fn chain_ids(chain: &[Tenant]) -> Vec<String> {
    chain.iter().map(|realm| realm.id.clone()).collect()
}

/// A tenant's ancestor ids from itself to the root, read through the store alone; fails closed on a broken chain.
async fn tenant_chain(tx: &Store, tenant_id: &str) -> IamResult<Vec<String>> {
    let mut chain: Vec<String> = Vec::new();
    let mut seen: IndexSet<String> = IndexSet::new();
    let mut current = Some(tenant_id.to_owned());
    while let Some(tenant) = current.filter(|tenant| !tenant.is_empty()) {
        if seen.contains(&tenant) || chain.len() > 100 {
            return Err(IamError::with_status(
                "INVALID_HIERARCHY",
                "Invalid tenant hierarchy",
                500,
            ));
        }
        seen.insert(tenant.clone());
        let Some(realm) = tx.get("tenants", &tenant).await? else {
            return Err(IamError::with_status("NOT_FOUND", "Tenant not found", 404));
        };
        chain.push(str_member(&realm, "id").unwrap_or_default().to_owned());
        current = str_member(&realm, "parentId").map(str::to_owned);
    }
    Ok(chain)
}

/// The defining tenant of the stand-in scheme `enforcedScheme` uses where labels outlived the scheme they were written
/// under: no label or clearance names it, and its definition has no level, so every label it reads is invalid.
const LAPSED_SCHEME_TENANT_ID: &str = "!no-scheme-in-force";

/// The stand-in scheme of a tenant that holds labels while no scheme is in force: every label refuses everyone.
fn lapsed_scheme() -> ClassificationScheme {
    ClassificationScheme {
        id: LAPSED_SCHEME_TENANT_ID.into(),
        tenant_id: LAPSED_SCHEME_TENANT_ID.into(),
        unique_key: SCHEME_KEY.into(),
        name: String::new(),
        definition: ClassificationSchemeDefinition {
            levels: Vec::new(),
            compartments: Vec::new(),
            owner_countries: Vec::new(),
            caveats: Vec::new(),
        },
        require_labels: Vec::new(),
        default_label: None,
        guest_ceiling: None,
        interim_allowed: false,
        adjudication: Value::String("within-own".into()),
        notify: None,
        retired_levels: None,
        created_at: 0.0,
        created_by: String::new(),
        updated_at: 0.0,
        updated_by: String::new(),
        version: 0.0,
        extra: Map::new(),
    }
}

/// The scheme decisions enforce in a tenant, given its ancestry (`[tenant, parent, ..., root]`): the scheme in force
/// (`effectiveScheme`), or, when none is but the tenant still holds labels (written under a scheme that no longer
/// applies to it), a stand-in under which each of those labels refuses every party, root included: a label is never
/// dropped because its scheme went away. Undefined when there is nothing to enforce.
pub async fn enforced_scheme(
    tx: &Store,
    tenant_id: &str,
    chain: &[String],
) -> IamResult<Option<ClassificationScheme>> {
    if let Some(scheme) = effective_scheme_of(tx, chain).await? {
        return Ok(Some(scheme));
    }
    let held = tx
        .find(
            LABELS,
            &Filter::new().eq("tenantId", tenant_id),
            &FindOptions {
                limit: Some(1),
                ..FindOptions::default()
            },
        )
        .await?;
    Ok(held
        .iter()
        .any(|item| str_member(item, "tenantId") == Some(tenant_id))
        .then(lapsed_scheme))
}

/// The scheme decisions enforce in a tenant (`enforcedScheme`), reading its ancestry from the store.
pub async fn scheme_for_tenant(
    tx: &Store,
    tenant_id: &str,
) -> IamResult<Option<crate::clearances::ClassificationScheme>> {
    let chain = tenant_chain(tx, tenant_id).await?;
    enforced_scheme(tx, tenant_id, &chain).await
}

/// A level of the scheme by id.
pub fn scheme_level(
    scheme: &Value,
    level_id: Option<&str>,
) -> IamResult<Option<better_iam_core::ClassificationLevel>> {
    let Some(level_id) = level_id else {
        return Ok(None);
    };
    let levels = scheme
        .get("definition")
        .and_then(|definition| definition.get("levels"))
        .and_then(Value::as_array);
    let found = levels
        .into_iter()
        .flatten()
        .find(|level| level.get("id").and_then(Value::as_str) == Some(level_id));
    match found {
        Some(level) => serde_json::from_value(level.clone())
            .map(Some)
            .map_err(|_| {
                IamError::with_status("STORAGE_CORRUPT", "Record does not match its type", 500)
            }),
        None => Ok(None),
    }
}

/// `schemeLevel` of a typed scheme.
pub fn level_of(
    scheme: &ClassificationScheme,
    level_id: Option<&str>,
) -> Option<ClassificationLevel> {
    let level_id = level_id?;
    scheme
        .definition
        .levels
        .iter()
        .find(|level| level.id == level_id)
        .cloned()
}

/// Whether the scheme requires a label on resources of `type` (`*` covers application types, not built-in ones).
pub fn label_required(scheme: &ClassificationScheme, kind: &str) -> bool {
    label_required_in(&scheme.require_labels, kind)
}

fn label_required_in(require_labels: &[String], kind: &str) -> bool {
    if is_internal_resource_type(kind) {
        return false;
    }
    require_labels.iter().any(|item| item == kind)
        || (require_labels.iter().any(|item| item == "*") && !MODULE_RESOURCE_TYPES.contains(&kind))
}

/// The stored IAM label of a resource, if it has one.
pub async fn stored_label(
    tx: &Store,
    tenant_id: &str,
    r#type: &str,
    resource_id: &str,
) -> IamResult<Option<crate::clearances::ResourceLabel>> {
    stored_label_record(tx, tenant_id, r#type, resource_id)
        .await?
        .map(decode)
        .transpose()
}

/// `storedLabel` as the raw record, so a label the scheme cannot read is seen exactly as stored.
async fn stored_label_record(
    tx: &Store,
    tenant_id: &str,
    kind: &str,
    resource_id: &str,
) -> IamResult<Option<Record>> {
    let found = tx
        .find(
            LABELS,
            &Filter::new()
                .eq("tenantId", tenant_id)
                .eq("uniqueKey", label_key_of(kind, resource_id)),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .next();
    Ok(found.filter(|found| {
        str_member(found, "type") == Some(kind)
            && str_member(found, "resourceId") == Some(resource_id)
    }))
}

/// A stored or asserted label as the scheme reads it: normalized when valid, otherwise the invalid label.
fn scheme_label(label: &Value, definition: &ClassificationSchemeDefinition) -> Value {
    match validate_label(label, definition) {
        Ok(label) => label.to_value(),
        Err(_) => invalid_label(),
    }
}

/// Whether a stored IAM label is valid under the scheme in force: written under that scheme (not one a tenant used
/// before it was moved below an ancestor defining its own) and valid for its definition.
pub fn stored_label_valid(stored: &ResourceLabel, scheme: &ClassificationScheme) -> bool {
    stored.scheme_tenant_id == scheme.tenant_id
        && is_valid_classification_label(&stored.label.to_value(), &scheme.definition)
}

/// `storedLabelValid` of a raw label record.
fn stored_record_valid(stored: &Record, scheme: &ClassificationScheme) -> bool {
    str_member(stored, "schemeTenantId") == Some(scheme.tenant_id.as_str())
        && is_valid_classification_label(
            stored.get("label").unwrap_or(&Value::Null),
            &scheme.definition,
        )
}

/// A stored IAM label as the scheme in force reads it; one `storedLabelValid` rejects refuses every party.
fn stored_scheme_label(stored: &Record, scheme: &ClassificationScheme) -> Value {
    if !stored_record_valid(stored, scheme) {
        return invalid_label();
    }
    scheme_label(
        stored.get("label").unwrap_or(&Value::Null),
        &scheme.definition,
    )
}

/// `joinLabels(a, b, definition)` over optional label values.
fn join(
    a: Option<Value>,
    b: Option<Value>,
    definition: &ClassificationSchemeDefinition,
) -> Option<Value> {
    join_labels(a.as_ref(), b.as_ref(), definition)
}

/// The managed parent of a registered resource, when it has one.
fn parent_of(record: Option<&ResourceRecord>) -> Option<Reference> {
    let record = record?;
    match (&record.parent_type, &record.parent_id) {
        (Some(kind), Some(id)) => Some(Reference {
            kind: kind.clone(),
            id: id.clone(),
        }),
        _ => None,
    }
}

/// Every parent a resource inherits labels from: its registration's managed parent, and the parent its attributes
/// report (`parentType` / `parentId`: an application resolver's, or what `resolvedManaged` presents for a
/// registration). Both count when they differ, since labels only ever rise: a type only a tenant registered answers
/// the application's actions from the application's resolver, so a registration of the tenant's must not stand in for
/// the parent the application reports (that would declassify through registering a record).
fn parents_of(
    record: Option<&ResourceRecord>,
    attributes: Option<&Map<String, Value>>,
) -> Vec<Reference> {
    let mut parents: Vec<Reference> = Vec::new();
    let linked = parent_of(record);
    if let Some(linked) = &linked {
        parents.push(linked.clone());
    }
    if let Some(attributes) = attributes
        && let (Some(kind), Some(id)) = (
            str_member(attributes, "parentType"),
            str_member(attributes, "parentId"),
        )
    {
        let reported = Reference {
            kind: kind.to_owned(),
            id: id.to_owned(),
        };
        if linked
            .as_ref()
            .is_none_or(|linked| ref_key(linked) != ref_key(&reported))
        {
            parents.push(reported);
        }
    }
    parents
}

/// What a managed resource passes down: the join of its and its ancestors' inherited labels, and its chain's height.
#[derive(Debug, Clone)]
struct InheritedChain {
    label: Option<Value>,
    /// The resource and the ancestors above it; infinity for a cyclic or runaway chain.
    height: f64,
}

/// How far a walk up managed parents goes at all before it fails closed (inheritance itself stops at 16).
const MAX_PARENT_WALK: usize = 256;

type Memo = HashMap<String, InheritedChain>;

/// The chain above (and including) one managed resource. Depends only on the resource, never on where a walk started,
/// so `memo` can share it between the resources of one batch. A cycle (which registration never creates) or a runaway
/// chain yields the invalid label.
fn chain_from<'a>(
    tx: &'a Store,
    tenant_id: &'a str,
    scheme: &'a ClassificationScheme,
    node: Reference,
    visiting: &'a mut IndexSet<String>,
    memo: &'a mut Memo,
) -> BoxFuture<'a, IamResult<InheritedChain>> {
    Box::pin(async move {
        let key = ref_key(&node);
        if let Some(known) = memo.get(&key) {
            return Ok(known.clone());
        }
        if visiting.contains(&key) || visiting.len() >= MAX_PARENT_WALK {
            return Ok(InheritedChain {
                label: Some(invalid_label()),
                height: f64::INFINITY,
            });
        }
        visiting.insert(key.clone());
        let stored = stored_label_record(tx, tenant_id, &node.kind, &node.id).await?;
        let above = parent_of(
            managed_resource(tx.as_ref(), tenant_id, &node.kind, &node.id)
                .await?
                .as_ref(),
        );
        let upper = match above {
            Some(above) => {
                chain_from(tx, tenant_id, scheme, above, &mut *visiting, &mut *memo).await?
            }
            None => InheritedChain {
                label: None,
                height: 0.0,
            },
        };
        visiting.shift_remove(&key);
        let here = stored
            .as_ref()
            .filter(|stored| crate::js::truthy(stored.get("inheritToChildren")))
            .map(|stored| stored_scheme_label(stored, scheme));
        let chain = InheritedChain {
            label: join(here, upper.label, &scheme.definition),
            height: upper.height + 1.0,
        };
        memo.insert(key, chain.clone());
        Ok(chain)
    })
}

/// The labels a resource (`self`, a `{type}/{id}` key) inherits from `parent` and the managed ancestors above it: the
/// join of every one of their labels marked `inheritToChildren`. More than `maxInheritanceDepth` ancestors, or a
/// cyclic chain, inherits the invalid label (fail closed). `memo` shares results between the resources of one batch.
async fn inherited_at(
    tx: &Store,
    tenant_id: &str,
    scheme: &ClassificationScheme,
    parent: Reference,
    own: String,
    memo: &mut Memo,
) -> IamResult<Option<Value>> {
    let mut visiting: IndexSet<String> = IndexSet::new();
    visiting.insert(own);
    let chain = chain_from(tx, tenant_id, scheme, parent, &mut visiting, memo).await?;
    Ok(if chain.height > MAX_INHERITANCE_DEPTH {
        Some(invalid_label())
    } else {
        chain.label
    })
}

/// What a resource carries besides its own label and its managed parents' labels: the labels of the same resource in
/// the tenants above the deciding one, for types one record of which serves a subtree (`treeResourceTypes`), and the
/// own label of the resource it is part of (`containerOf`). Undefined when there is none.
async fn carried_label(
    tx: &Store,
    tenant_id: &str,
    scheme: &ClassificationScheme,
    kind: &str,
    resource_id: &str,
) -> IamResult<Option<Value>> {
    let mut label: Option<Value> = None;
    if TREE_RESOURCE_TYPES.contains(&kind) {
        for realm in tenant_chain(tx, tenant_id).await?.iter().skip(1) {
            if let Some(above) = stored_label_record(tx, realm, kind, resource_id).await? {
                label = join(
                    label,
                    Some(stored_scheme_label(&above, scheme)),
                    &scheme.definition,
                );
            }
        }
    }
    if let Some(container) = container_of(kind, resource_id)
        && let Some(held) =
            stored_label_record(tx, tenant_id, &container.kind, &container.id).await?
    {
        label = join(
            label,
            Some(stored_scheme_label(&held, scheme)),
            &scheme.definition,
        );
    }
    Ok(label)
}

/// The effective IAM-held label of one resource under `scheme`: its own label joined with what it carries
/// (`carriedLabel`) and what it inherits from its managed parents and from the parent its attributes report
/// (`attributes.parentType` / `attributes.parentId`, see `parentsOf`), and from the parent `also` reports (what the
/// application resolves for the resource an `iam/{type}/{id}` alias names). Undefined when unlabeled.
async fn iam_label(
    tx: &Store,
    tenant_id: &str,
    scheme: &ClassificationScheme,
    resource: &Reference,
    attributes: Option<&Map<String, Value>>,
    also: Option<&Map<String, Value>>,
) -> IamResult<Option<Value>> {
    let definition = &scheme.definition;
    let own = stored_label_record(tx, tenant_id, &resource.kind, &resource.id).await?;
    let record = managed_resource(tx.as_ref(), tenant_id, &resource.kind, &resource.id).await?;
    let mut memo: Memo = HashMap::new();
    let mut label = own.as_ref().map(|own| stored_scheme_label(own, scheme));
    label = join(
        label,
        carried_label(tx, tenant_id, scheme, &resource.kind, &resource.id).await?,
        definition,
    );
    let mut parents = parents_of(record.as_ref(), attributes);
    if let Some(also) = also {
        for parent in parents_of(record.as_ref(), Some(also)) {
            if !parents
                .iter()
                .any(|known| ref_key(known) == ref_key(&parent))
            {
                parents.push(parent);
            }
        }
    }
    for parent in parents {
        label = join(
            label,
            inherited_at(tx, tenant_id, scheme, parent, ref_key(resource), &mut memo).await?,
            definition,
        );
    }
    Ok(label)
}

/// Attaches a resource's effective classification label as the server-owned `classification` field (never an
/// attribute): its IAM label, joined with the labels inherited from managed parents (at most 16 levels) and with
/// the `classification` the application's resolver returned, which can therefore only raise it. An asserted label
/// that is not valid for the scheme makes the result invalid, so every party is refused. `null` means looked up and
/// unlabeled. Without a scheme to enforce the resource is returned unchanged. Platform-internal resources carry a
/// label only as `iam/{type}/{id}`, labeled as the resource it names. Pass `known.scheme` when the caller already
/// resolved the scheme (`null` for none) to save the ancestry reads, and for an alias `known.named`: the named
/// resource as the application resolves it (`resolve` passes it for application actions), whose own
/// `classification` and reported parent count too, or `null` when its resolver failed, which refuses every party
/// (fail closed).
pub async fn attach_label(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    resource: &crate::options::ResolvedResource,
    known: Option<&KnownLabeling>,
) -> IamResult<crate::options::ResolvedResource> {
    let _ = ctx;
    let scheme = match known {
        Some(known) => known.scheme.clone(),
        None => scheme_for_tenant(tx, tenant_id).await?,
    };
    let Some(scheme) = scheme else {
        return Ok(resource.clone());
    };
    // `iam/{type}/{id}` is labeled as the resource it names, with what was resolved for this name (the parent its
    // attributes report, a resolver's own label) joined in like for the resource itself, so the alias never reads
    // lower.
    let alias = is_internal_resource_type(&resource.kind);
    let labeled = if alias {
        let slash = if resource.kind == "iam" {
            resource.id.find('/')
        } else {
            None
        };
        let Some(slash) = slash.filter(|slash| *slash > 0) else {
            return Ok(resource.clone());
        };
        let labeled = Reference {
            kind: resource.id[..slash].to_owned(),
            id: resource.id[slash + 1..].to_owned(),
        };
        if labeled.id.is_empty() || is_internal_resource_type(&labeled.kind) {
            return Ok(resource.clone());
        }
        labeled
    } else {
        Reference {
            kind: resource.kind.clone(),
            id: resource.id.clone(),
        }
    };
    let named = if alias {
        known.and_then(|known| known.named.as_ref())
    } else {
        None
    };
    let named_attributes = named
        .and_then(Option::as_ref)
        .and_then(|named| named.attributes.as_ref());
    let mut label = iam_label(
        tx,
        tenant_id,
        &scheme,
        &labeled,
        resource.attributes.as_ref(),
        named_attributes,
    )
    .await?;
    if let Some(asserted) = resource
        .classification
        .as_ref()
        .filter(|asserted| !asserted.is_null())
    {
        label = join(
            label,
            Some(scheme_label(asserted, &scheme.definition)),
            &scheme.definition,
        );
    }
    match named {
        Some(None) => label = Some(invalid_label()),
        Some(Some(named)) => {
            if let Some(classification) = named
                .classification
                .as_ref()
                .filter(|classification| !classification.is_null())
            {
                label = join(
                    label,
                    Some(scheme_label(classification, &scheme.definition)),
                    &scheme.definition,
                );
            }
        }
        None => {}
    }
    Ok(ResolvedResource {
        classification: Some(label.unwrap_or(Value::Null)),
        ..resource.clone()
    })
}

/// What a resource inherits under `scheme`, without its own label: the join of the labels marked
/// `inheritToChildren` of its managed ancestors (through the parents `parentsOf` names for its registration) and
/// what it carries (`carriedLabel`: the same model's labels in the tenants above, an SSH login's host label);
/// undefined when it inherits nothing.
pub async fn inherited_label(
    tx: &Store,
    tenant_id: &str,
    scheme: &crate::clearances::ClassificationScheme,
    r#type: &str,
    resource_id: &str,
) -> IamResult<Option<better_iam_core::ClassificationLabel>> {
    Ok(inherited_value(tx, tenant_id, scheme, r#type, resource_id)
        .await?
        .map(|label| typed_label(&label)))
}

/// `inheritedLabel` as JSON.
async fn inherited_value(
    tx: &Store,
    tenant_id: &str,
    scheme: &ClassificationScheme,
    kind: &str,
    resource_id: &str,
) -> IamResult<Option<Value>> {
    let record = managed_resource(tx.as_ref(), tenant_id, kind, resource_id).await?;
    let mut memo: Memo = HashMap::new();
    let mut label = carried_label(tx, tenant_id, scheme, kind, resource_id).await?;
    let attributes = record
        .as_ref()
        .and_then(|record| resolved_managed(record).attributes);
    let own = ref_key(&Reference {
        kind: kind.to_owned(),
        id: resource_id.to_owned(),
    });
    for parent in parents_of(record.as_ref(), attributes.as_ref()) {
        label = join(
            label,
            inherited_at(tx, tenant_id, scheme, parent, own.clone(), &mut memo).await?,
            &scheme.definition,
        );
    }
    Ok(label)
}

/// `labelsForType` under a scheme already known.
async fn type_labels(
    tx: &Store,
    tenant_id: &str,
    scheme: &ClassificationScheme,
    kind: &str,
) -> IamResult<IndexMap<String, Value>> {
    let definition = &scheme.definition;
    let mut result: IndexMap<String, Value> = IndexMap::new();
    for stored in tx
        .find(
            LABELS,
            &Filter::new().eq("tenantId", tenant_id).eq("type", kind),
            &FindOptions::default(),
        )
        .await?
    {
        if str_member(&stored, "tenantId") == Some(tenant_id)
            && str_member(&stored, "type") == Some(kind)
            && let Some(resource_id) = str_member(&stored, "resourceId")
        {
            result.insert(resource_id.to_owned(), stored_scheme_label(&stored, scheme));
        }
    }
    // Types one record of which serves a subtree carry the labels written above too (see `carriedLabel`).
    if TREE_RESOURCE_TYPES.contains(&kind) {
        for realm in tenant_chain(tx, tenant_id).await?.iter().skip(1) {
            for stored in tx
                .find(
                    LABELS,
                    &Filter::new()
                        .eq("tenantId", realm.as_str())
                        .eq("type", kind),
                    &FindOptions::default(),
                )
                .await?
            {
                if str_member(&stored, "tenantId") == Some(realm.as_str())
                    && str_member(&stored, "type") == Some(kind)
                    && let Some(resource_id) = str_member(&stored, "resourceId")
                {
                    let joined = join(
                        result.get(resource_id).cloned(),
                        Some(stored_scheme_label(&stored, scheme)),
                        definition,
                    )
                    .unwrap_or_else(invalid_label);
                    result.insert(resource_id.to_owned(), joined);
                }
            }
        }
    }
    let mut memo: Memo = HashMap::new();
    for record in tx
        .find(
            "resources",
            &Filter::new().eq("tenantId", tenant_id).eq("type", kind),
            &FindOptions::default(),
        )
        .await?
    {
        let record: ResourceRecord = decode(record)?;
        if record.kind != kind {
            continue;
        }
        // The same parents `resolve` follows for the registration (see `parentsOf`).
        let mut joined = result.get(&record.resource_id).cloned();
        let attributes = resolved_managed(&record).attributes;
        let own = ref_key(&Reference {
            kind: kind.to_owned(),
            id: record.resource_id.clone(),
        });
        for parent in parents_of(Some(&record), attributes.as_ref()) {
            joined = join(
                joined,
                inherited_at(tx, tenant_id, scheme, parent, own.clone(), &mut memo).await?,
                definition,
            );
        }
        if let Some(joined) = joined {
            result.insert(record.resource_id.clone(), joined);
        }
    }
    Ok(result)
}

/// The effective IAM-held labels of every labeled resource of one type in a tenant, by resource id, for listings:
/// own labels joined with what registered resources inherit from their managed parents. Labels an application
/// resolver asserts are not included (decisions still apply them). Empty when there is no scheme to enforce; where
/// labels outlived their scheme (`enforcedScheme`), each one is invalid and refuses everyone.
pub async fn labels_for_type(
    tx: &Store,
    tenant_id: &str,
    r#type: &str,
) -> IamResult<IndexMap<String, better_iam_core::ClassificationLabel>> {
    let Some(scheme) = scheme_for_tenant(tx, tenant_id).await? else {
        return Ok(IndexMap::new());
    };
    Ok(type_labels(tx, tenant_id, &scheme, r#type)
        .await?
        .into_iter()
        .map(|(resource_id, label)| (resource_id, typed_label(&label)))
        .collect())
}

// --- parties ---------------------------------------------------------------------------------------

fn uncleared_party(identity_id: &str) -> ClearanceParty {
    ClearanceParty {
        identity_id: identity_id.to_owned(),
        rank: -1.0,
        compartments: BTreeSet::new(),
        citizenship: BTreeSet::new(),
    }
}

/// An identity's clearance record (in the identity's own tenant), if any.
pub async fn read_clearance(
    tx: &Store,
    identity: &Value,
) -> IamResult<Option<crate::clearances::Clearance>> {
    let identity_id = identity
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let tenant_id = identity
        .get("tenantId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    read_clearance_of(tx, identity_id, tenant_id).await
}

/// `readClearance` by the identity's id and tenant.
pub async fn read_clearance_of(
    tx: &Store,
    identity_id: &str,
    tenant_id: &str,
) -> IamResult<Option<Clearance>> {
    clearance_record(tx, identity_id, tenant_id)
        .await?
        .map(decode)
        .transpose()
}

/// `readClearance` as the raw record, for read-modify-write.
async fn clearance_record(
    tx: &Store,
    identity_id: &str,
    tenant_id: &str,
) -> IamResult<Option<Record>> {
    let record = tx.get(CLEARANCES, identity_id).await?;
    Ok(record.filter(|record| {
        str_member(record, "tenantId") == Some(tenant_id)
            && str_member(record, "identityId") == Some(identity_id)
    }))
}

/// The compartments a record's read-ins hold right now: known to the scheme, NDA (when named) currently accepted.
async fn live_compartments(
    tx: &Store,
    scheme: &ClassificationScheme,
    record: &Clearance,
    now: f64,
) -> IamResult<BTreeSet<String>> {
    let mut held: BTreeSet<String> = BTreeSet::new();
    for read_in in &record.read_ins {
        let Some(compartment_id) = read_in.get("compartmentId").and_then(Value::as_str) else {
            continue;
        };
        if !scheme
            .definition
            .compartments
            .iter()
            .any(|compartment| compartment.id == compartment_id)
        {
            continue;
        }
        if let Some(agreement_id) = read_in.get("agreementId") {
            let Some(agreement_id) = agreement_id.as_str() else {
                continue;
            };
            let agreement: Option<Agreement> = tx
                .get("agreements", agreement_id)
                .await?
                .map(decode)
                .transpose()?;
            let acceptance: Option<AgreementAcceptance> = tx
                .get(
                    "agreementAcceptances",
                    &format!("{agreement_id}:{}", record.identity_id),
                )
                .await?
                .map(decode)
                .transpose()?;
            let current = match (&agreement, &acceptance) {
                (Some(agreement), Some(acceptance)) => {
                    agreement.tenant_id == record.tenant_id
                        && acceptance.tenant_id == record.tenant_id
                        && acceptance.identity_id == record.identity_id
                        && acceptance.agreement_id == agreement.id
                        && acceptance_current(agreement, Some(acceptance), now)
                }
                _ => false,
            };
            if !current {
                continue;
            }
        }
        held.insert(compartment_id.to_owned());
    }
    Ok(held)
}

/// One identity's clearance at decision time under `scheme`: the identity must be active and unexpired (and, unless
/// `tenantId` is undefined, of that tenant), the record issued under this scheme, active (or interim where the
/// scheme allows it) and unexpired, its level known; guests count at most at the scheme's guest ceiling and never
/// hold compartments; compartments count only while their NDA acceptance is current. Anything else is no clearance.
pub async fn party_state(
    tx: &Store,
    scheme: &crate::clearances::ClassificationScheme,
    identity: Option<&better_iam_core::Identity>,
    identity_id: &str,
    tenant_id: Option<&str>,
    now: f64,
) -> IamResult<crate::clearances::PartyState> {
    let none = |status: Value, record: Option<Clearance>| PartyState {
        party: uncleared_party(identity_id),
        status,
        level: None,
        record,
    };
    let none_status = || Value::String("none".into());
    let Some(identity) = identity.filter(|identity| {
        identity.id == identity_id && tenant_id.is_none_or(|tenant| identity.tenant_id == tenant)
    }) else {
        return Ok(none(none_status(), None));
    };
    let active = identity.status == IdentityStatus::Active
        && !identity.expires_at.is_some_and(|expires| expires <= now);
    // An inactive account never counts; its record is read only to report a suspended or ended clearance as such.
    let Some(record) = read_clearance_of(tx, &identity.id, &identity.tenant_id).await? else {
        return Ok(none(none_status(), None));
    };
    if record.scheme_tenant_id != scheme.tenant_id {
        return Ok(none(none_status(), Some(record)));
    }
    let status = record.status.as_str().unwrap_or_default().to_owned();
    if status != "active" && status != "interim" {
        let status = record.status.clone();
        return Ok(none(status, Some(record)));
    }
    if !active {
        return Ok(none(none_status(), Some(record)));
    }
    if status == "interim" && !scheme.interim_allowed {
        return Ok(none(none_status(), Some(record)));
    }
    if record.expires_at.is_some_and(|expires| expires <= now) {
        return Ok(none(Value::String("expired".into()), Some(record)));
    }
    let Some(mut level) = level_of(scheme, Some(&record.level)) else {
        return Ok(none(none_status(), Some(record)));
    };
    let mut compartments: BTreeSet<String> = BTreeSet::new();
    if identity.guest.is_some() {
        let Some(ceiling) = level_of(scheme, scheme.guest_ceiling.as_deref()) else {
            return Ok(none(none_status(), Some(record)));
        };
        if level.rank > ceiling.rank {
            level = ceiling;
        }
    } else {
        compartments = live_compartments(tx, scheme, &record, now).await?;
    }
    Ok(PartyState {
        party: ClearanceParty {
            identity_id: identity_id.to_owned(),
            rank: level.rank,
            compartments,
            citizenship: record.citizenship.iter().cloned().collect(),
        },
        status: record.status.clone(),
        level: Some(level),
        record: Some(record),
    })
}

/// The agents of a delegated session: the acting agent and every agent that handed the work on to it.
fn delegated_agents(
    principal: &AuthenticatedPrincipal,
    agent_scope: Option<&crate::agents::AgentDecisionScope>,
) -> Vec<String> {
    let mut ids: Vec<String> = Vec::new();
    let mut add = |value: Option<&str>| {
        if let Some(value) = value
            && !value.is_empty()
            && !ids.iter().any(|known| known == value)
        {
            ids.push(value.to_owned());
        }
    };
    if let Some(scope) = agent_scope {
        for value in &scope.agent_ids {
            add(Some(value));
        }
    }
    add(agent_scope
        .and_then(|scope| scope.keys.get("principal.agentId"))
        .and_then(Value::as_str));
    add(principal.session.agent_id.as_deref());
    ids
}

/// An identity record by id, if any.
async fn load_identity(tx: &Store, identity_id: &str) -> IamResult<Option<Identity>> {
    tx.get("identities", identity_id)
        .await?
        .map(decode)
        .transpose()
}

/// The parties of a session in `target`, each with its clearance: a person in their own tenant (an impersonation
/// session: the member; the administrator is decided separately); a service account's key: the account; an agent's
/// key (or a session token from it): the agent and its sponsor; a session token: its source identity; a delegated
/// session: the person, the acting agent and every agent above it in the hand-off chain; a role session: nobody
/// cleared; root: the root administrator's record when issued under the target's scheme. Unknown session kinds are
/// uncleared.
pub async fn session_parties(
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    target: &Value,
    agent_scope: Option<&crate::agents::AgentDecisionScope>,
    scheme: &crate::clearances::ClassificationScheme,
    now: f64,
    root: bool,
) -> IamResult<Vec<crate::clearances::PartyState>> {
    let target_id = target.get("id").and_then(Value::as_str).unwrap_or_default();
    parties_of(tx, principal, target_id, agent_scope, scheme, now, root).await
}

/// `sessionParties` with the target tenant's id.
pub async fn parties_of(
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    target_id: &str,
    agent_scope: Option<&crate::agents::AgentDecisionScope>,
    scheme: &ClassificationScheme,
    now: f64,
    root: bool,
) -> IamResult<Vec<PartyState>> {
    let identity = &principal.identity;
    let session = &principal.session;
    let uncleared = |identity_id: String| PartyState {
        party: uncleared_party(&identity_id),
        status: Value::String("none".into()),
        level: None,
        record: None,
    };
    if root {
        return Ok(vec![
            party_state(tx, scheme, Some(identity), &identity.id, None, now).await?,
        ]);
    }
    if session.tenant_id != target_id || identity.tenant_id != target_id {
        return Ok(vec![uncleared(identity.id.clone())]);
    }
    let local = |candidate: Option<Identity>, identity_id: String| async move {
        party_state(
            tx,
            scheme,
            candidate.as_ref(),
            &identity_id,
            Some(target_id),
            now,
        )
        .await
    };
    match session.kind {
        SessionKind::User => Ok(vec![
            local(Some(identity.clone()), identity.id.clone()).await?,
        ]),
        SessionKind::ApiKey | SessionKind::SessionToken => {
            let own = local(Some(identity.clone()), identity.id.clone()).await?;
            if identity.kind != IdentityKind::Agent {
                return Ok(vec![own]);
            }
            let sponsor_id = identity
                .agent
                .as_ref()
                .map(|agent| agent.sponsor_id.clone())
                .unwrap_or_default();
            if sponsor_id.is_empty() {
                return Ok(vec![own, uncleared(format!("{}#sponsor", identity.id))]);
            }
            let sponsor = load_identity(tx, &sponsor_id)
                .await?
                .filter(|sponsor| sponsor.kind == IdentityKind::User);
            Ok(vec![own, local(sponsor, sponsor_id).await?])
        }
        SessionKind::Delegated => {
            let mut states = vec![local(Some(identity.clone()), identity.id.clone()).await?];
            let agent_ids = delegated_agents(principal, agent_scope);
            if agent_ids.is_empty() {
                states.push(uncleared(format!("{}#agent", identity.id)));
                return Ok(states);
            }
            for agent_id in agent_ids {
                let agent = load_identity(tx, &agent_id)
                    .await?
                    .filter(|agent| agent.kind == IdentityKind::Agent);
                states.push(local(agent, agent_id).await?);
            }
            Ok(states)
        }
        // Roles and unknown kinds are uncleared (the `default` branch).
        SessionKind::Role | SessionKind::Unknown => Ok(vec![uncleared(identity.id.clone())]),
    }
}

/// Sorted members of every set (the empty list for no sets).
fn intersection(sets: &[&BTreeSet<String>]) -> Vec<String> {
    let Some(first) = sets.first() else {
        return Vec::new();
    };
    let mut shared: Vec<String> = first
        .iter()
        .filter(|value| sets.iter().all(|set| set.contains(*value)))
        .cloned()
        .collect();
    sort_strings(&mut shared);
    shared
}

/// The status the parties hold together: the first that does not count, otherwise interim when any is interim.
fn combined_status(states: &[PartyState]) -> Value {
    let counts = |state: &PartyState| state.status == "active" || state.status == "interim";
    if let Some(lacking) = states.iter().find(|state| !counts(state)) {
        return lacking.status.clone();
    }
    Value::String(
        if states.iter().any(|state| state.status == "interim") {
            "interim"
        } else {
            "active"
        }
        .into(),
    )
}

/// The `principal.clearance*` policy keys of a set of parties.
pub fn clearance_keys(states: &[PartyState]) -> Map<String, Value> {
    let rank = if states.is_empty() {
        -1.0
    } else {
        states
            .iter()
            .map(|state| state.party.rank)
            .fold(f64::INFINITY, f64::min)
    };
    let weakest = states.iter().find(|state| state.party.rank == rank);
    let mut keys = Map::new();
    keys.insert("principal.clearanceRank".into(), number(rank));
    if rank >= 0.0
        && let Some(level) = weakest.and_then(|state| state.level.as_ref())
    {
        keys.insert(
            "principal.clearanceLevel".into(),
            Value::String(level.id.clone()),
        );
    }
    keys.insert(
        "principal.clearanceStatus".into(),
        if states.is_empty() {
            Value::String("none".into())
        } else {
            combined_status(states)
        },
    );
    let compartments: Vec<&BTreeSet<String>> = states
        .iter()
        .map(|state| &state.party.compartments)
        .collect();
    keys.insert(
        "principal.clearanceCompartments".into(),
        json!(intersection(&compartments)),
    );
    let citizenship: Vec<&BTreeSet<String>> = states
        .iter()
        .map(|state| &state.party.citizenship)
        .collect();
    keys.insert(
        "principal.clearanceCitizenship".into(),
        json!(intersection(&citizenship)),
    );
    keys
}

fn refused() -> Decision {
    Decision {
        allowed: false,
        reason: "CLEARANCE_REQUIRED".into(),
        matched: Vec::new(),
    }
}

/// What the scheme applies to a resource (`applicableLabel`).
enum Applicable {
    /// The resource carries no label (`undefined`).
    Unlabeled,
    /// It must be refused whoever asks (`false`).
    Refused,
    /// The label to check.
    Label(Value),
}

fn applicable(
    require_labels: &[String],
    default_label: Option<Value>,
    resource: &ResolvedResource,
) -> Applicable {
    let classification = resource.classification.as_ref();
    let required = |kind: &str| {
        if label_required_in(require_labels, kind) {
            match &default_label {
                Some(label) => Applicable::Label(label.clone()),
                None => Applicable::Refused,
            }
        } else {
            Applicable::Unlabeled
        }
    };
    // Platform-internal resources are not labeled, except `iam/{type}/{id}` naming a labeled resource (or, once its
    // label was looked up, an unlabeled one of a type that requires a label: refused like the resource itself).
    if is_internal_resource_type(&resource.kind) {
        if let Some(classification @ (Value::Object(_) | Value::Array(_))) = classification {
            return Applicable::Label(classification.clone());
        }
        let slash = if resource.kind == "iam" {
            resource.id.find('/')
        } else {
            None
        };
        return match (classification, slash) {
            (Some(Value::Null), Some(slash)) if slash > 0 => required(&resource.id[..slash]),
            _ => Applicable::Unlabeled,
        };
    }
    match classification {
        None => Applicable::Refused,
        Some(Value::Null) => required(&resource.kind),
        Some(label @ Value::Object(_)) => Applicable::Label(label.clone()),
        Some(_) => Applicable::Refused,
    }
}

/// The label the scheme applies to a resource, `undefined` when it carries none, or `false` when it must be refused
/// whoever asks: its label was never looked up, or it lacks the label its type requires and the scheme sets no
/// default.
pub fn applicable_label(
    scheme: &Value,
    resource: &crate::options::ResolvedResource,
) -> IamResult<Option<Value>> {
    let require_labels: Vec<String> = scheme
        .get("requireLabels")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let default_label = scheme
        .get("defaultLabel")
        .filter(|label| !label.is_null())
        .cloned();
    Ok(match applicable(&require_labels, default_label, resource) {
        Applicable::Unlabeled => None,
        Applicable::Refused => Some(Value::Bool(false)),
        Applicable::Label(label) => Some(label),
    })
}

/// `applicableLabel` of a typed scheme.
fn applicable_in(scheme: &ClassificationScheme, resource: &ResolvedResource) -> Applicable {
    applicable(
        &scheme.require_labels,
        scheme
            .default_label
            .as_ref()
            .map(ClassificationLabel::to_value),
        resource,
    )
}

/// The first dimension a party fails (`partiesFail` over a label value).
fn parties_failure(
    parties: &[ClearanceParty],
    label: &Value,
    definition: &ClassificationSchemeDefinition,
) -> Option<DominanceFailure> {
    if parties.is_empty() {
        return Some(DominanceFailure::Level);
    }
    parties
        .iter()
        .find_map(|party| dominates(party, label, definition))
}

/// Whether every party dominates the label; undefined when they do, else the first failure.
pub fn parties_fail(
    parties: &[better_iam_core::ClearanceParty],
    label: &better_iam_core::ClassificationLabel,
    definition: &better_iam_core::ClassificationSchemeDefinition,
) -> IamResult<Option<String>> {
    Ok(parties_failure(parties, &label.to_value(), definition)
        .map(|failure| failure.as_str().to_owned()))
}

/// The mandatory check of one session in one tenant (the object `clearanceScope` returns).
struct Mandatory {
    ctx: Arc<ServerContext>,
    tx: Store,
    target_id: String,
    scheme: ClassificationScheme,
    keys: Map<String, Value>,
    parties: Vec<ClearanceParty>,
}

impl Mandatory {
    fn passes(&self, label: &Value) -> bool {
        parties_failure(&self.parties, label, &self.scheme.definition).is_none()
    }

    async fn any_label(&self, filter: Filter) -> IamResult<bool> {
        Ok(!self
            .tx
            .find(
                LABELS,
                &filter,
                &FindOptions {
                    limit: Some(1),
                    ..FindOptions::default()
                },
            )
            .await?
            .is_empty())
    }
}

fn id_filter(mut values: Vec<String>) -> ResourceFilter {
    sort_strings(&mut values);
    ResourceFilter::Equals {
        field: "id".into(),
        values: values.into_iter().map(FilterValue::String).collect(),
        ignore_case: false,
    }
}

#[async_trait::async_trait]
impl MandatoryAccess for Mandatory {
    fn scheme(&self) -> &ClassificationScheme {
        &self.scheme
    }

    fn keys(&self) -> &Map<String, Value> {
        &self.keys
    }

    fn label(&self, resource: &ResolvedResource) -> Option<ClassificationLabel> {
        match applicable_in(&self.scheme, resource) {
            Applicable::Label(label) => Some(typed_label(&label)),
            Applicable::Unlabeled | Applicable::Refused => None,
        }
    }

    fn rank(&self, label: &ClassificationLabel) -> Option<f64> {
        label_rank(&label.to_value(), &self.scheme.definition)
    }

    fn check(&self, resource: &ResolvedResource, action: &str) -> Option<Decision> {
        if action.starts_with("iam:") {
            return None;
        }
        match applicable_in(&self.scheme, resource) {
            Applicable::Unlabeled => None,
            Applicable::Label(label) if self.passes(&label) => None,
            Applicable::Label(_) | Applicable::Refused => Some(refused()),
        }
    }

    async fn filter(&self, kind: &str, action: Option<&str>) -> IamResult<ResourceFilter> {
        if action.is_some_and(|action| action.starts_with("iam:"))
            || is_internal_resource_type(kind)
        {
            return Ok(ResourceFilter::True);
        }
        let scheme = &self.scheme;
        let required = label_required(scheme, kind);
        let definition_of_type = self
            .ctx
            .catalog
            .resource_type_definition(self.tx.as_ref(), &self.target_id, kind)
            .await?;
        // Registered resources answer for the action unless the type is one only a tenant registered and the action
        // is the application's: `resolve` then asks the application's resolver (decisions.ts shadowsApplicationType,
        // which this module cannot import), so the type is planned as an application type.
        let managed = definition_of_type.as_ref().is_some_and(|definition| {
            definition.managed
                && !(self.ctx.options.resolve_resource.is_some()
                    && definition.source == "tenant"
                    && !action.is_some_and(|action| action.starts_with(&format!("{kind}:"))))
        });
        if required && !managed {
            return Err(IamError::new(
                "UNSUPPORTED_FILTER",
                "Resources of this type must carry a classification label, which a filter cannot check for application resources; check them with authorize",
            ));
        }
        // An application resource also inherits the labels of the parent its resolver reports, which no filter can
        // see: while any label in the tenant passes down to children, application types are not planned (fail
        // closed).
        if !managed
            && self
                .any_label(
                    Filter::new()
                        .eq("tenantId", self.target_id.as_str())
                        .eq("inheritToChildren", true),
                )
                .await?
        {
            return Err(IamError::new(
                "UNSUPPORTED_FILTER",
                "Classification labels pass down to application resources through the parents their resolver reports, which a filter cannot check; check them with authorize",
            ));
        }
        // Resources part of another carry its label (`containerOf`: an SSH host's label on its logins), which a filter
        // by id cannot follow: while any of those is labeled, the type is not planned (fail closed).
        if let Some(container) = container_type(kind)
            && self
                .any_label(
                    Filter::new()
                        .eq("tenantId", self.target_id.as_str())
                        .eq("type", container),
                )
                .await?
        {
            return Err(IamError::new(
                "UNSUPPORTED_FILTER",
                "These resources carry the classification labels of the resources they are part of, which a filter cannot check; check them with authorize",
            ));
        }
        let labels = type_labels(&self.tx, &self.target_id, scheme, kind).await?;
        if required {
            let mut allowed: IndexSet<String> = IndexSet::new();
            for record in self
                .tx
                .find(
                    "resources",
                    &Filter::new()
                        .eq("tenantId", self.target_id.as_str())
                        .eq("type", kind),
                    &FindOptions::default(),
                )
                .await?
            {
                let Some(resource_id) = str_member(&record, "resourceId") else {
                    continue;
                };
                let label = labels.get(resource_id).cloned().or_else(|| {
                    scheme
                        .default_label
                        .as_ref()
                        .map(ClassificationLabel::to_value)
                });
                if let Some(label) = label
                    && self.passes(&label)
                {
                    allowed.insert(resource_id.to_owned());
                }
            }
            return Ok(if allowed.is_empty() {
                ResourceFilter::False
            } else {
                id_filter(allowed.into_iter().collect())
            });
        }
        let denied: Vec<String> = labels
            .iter()
            .filter(|(_, label)| !self.passes(label))
            .map(|(resource_id, _)| resource_id.clone())
            .collect();
        Ok(if denied.is_empty() {
            ResourceFilter::True
        } else {
            not_filter(id_filter(denied))
        })
    }
}

/// The mandatory part of a decision for one session in `target`: undefined when there is no scheme to enforce there
/// (`enforcedScheme`: none in force and no label left over from one) or the principal is a root administrator and
/// `clearances.appliesToRoot` is false. Otherwise the session's parties (see `sessionParties`) with their
/// clearances at `now`, their policy keys, and the check every party must pass on labeled resources. Called by
/// `prepareDecision` after the tenant checks and the agent scope; `chain` is the target's ancestry from itself to
/// the root, and `root` whether the principal is a root administrator when the caller already knows (read
/// otherwise).
#[allow(clippy::too_many_arguments)]
pub async fn clearance_scope(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    target: &better_iam_core::Tenant,
    chain: &[better_iam_core::Tenant],
    agent_scope: Option<&crate::agents::AgentDecisionScope>,
    now: f64,
    root: Option<bool>,
) -> IamResult<Option<Arc<dyn MandatoryAccess>>> {
    let Some(options) = &ctx.options.clearances else {
        return Ok(None);
    };
    let ids = if chain.is_empty() {
        vec![target.id.clone()]
    } else {
        chain_ids(chain)
    };
    let Some(scheme) = enforced_scheme(tx, &target.id, &ids).await? else {
        return Ok(None);
    };
    let is_root = match root {
        Some(root) => root,
        None => ctx.root_principal(tx, principal).await?,
    };
    if is_root && options.applies_to_root == Some(false) {
        return Ok(None);
    }
    let states = parties_of(
        tx,
        principal,
        &target.id,
        agent_scope,
        &scheme,
        now,
        is_root,
    )
    .await?;
    let parties = states.iter().map(|state| state.party.clone()).collect();
    Ok(Some(Arc::new(Mandatory {
        ctx: ctx.clone(),
        tx: tx.clone(),
        target_id: target.id.clone(),
        keys: clearance_keys(&states),
        scheme,
        parties,
    })))
}

/// Whether the mandatory check alone lets `principal` (every party of its session) at `resource` in `tenant` for
/// `action`, whatever roles and policies say: for what is decided on someone's behalf rather than by their own
/// decision, such as an administrator's credential offer to them. The resource is labeled here as `resolve` would
/// label it. True without the option or a scheme to enforce, and for `iam:` actions.
pub async fn cleared_for(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    tenant: &better_iam_core::Tenant,
    resource: &crate::options::ResolvedResource,
    action: &str,
) -> IamResult<bool> {
    if ctx.options.clearances.is_none() {
        return Ok(true);
    }
    let chain = ctx.ancestry(tx, tenant).await?;
    let Some(mandatory) =
        clearance_scope(ctx, tx, principal, tenant, &chain, None, ctx.now(), None).await?
    else {
        return Ok(true);
    };
    let labeled = attach_label(
        ctx,
        tx,
        &tenant.id,
        resource,
        Some(&KnownLabeling {
            scheme: Some(mandatory.scheme().clone()),
            named: None,
        }),
    )
    .await?;
    Ok(mandatory.check(&labeled, action).is_none())
}

// --- lifecycle -------------------------------------------------------------------------------------

/// Whether a clearance already ended: revoked for cause or terminated. Such a record keeps why it ended.
fn ended(record: &Record) -> bool {
    matches!(str_member(record, "status"), Some("terminated" | "revoked"))
}

/// The read-ins of a raw clearance record (none when the member is not a list).
fn read_ins_of(record: &Record) -> Vec<Value> {
    record
        .get("readIns")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Before a registration is deleted (`resources.delete`): what it inherits from its managed parents becomes part of
/// its own label (joined with any it has), because labels outlive resources but the parent link does not, so
/// deleting it and registering it again under another parent cannot declassify it. Audited as
/// `classification:label` with `reason: 'resource-deleted'`. Refuses (RESOURCE_IN_USE) while what it inherits
/// cannot be read under the scheme in force: repair that label first. Does nothing (and reads nothing) without the
/// option, and nothing without a scheme to enforce or a label to inherit.
pub async fn keep_inherited_label(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    record: &crate::models::ResourceRecord,
) -> IamResult<()> {
    if ctx.options.clearances.is_none() {
        return Ok(());
    }
    let tenant_id = record.tenant_id.as_str();
    let kind = record.kind.as_str();
    let resource_id = record.resource_id.as_str();
    let Some(scheme) = scheme_for_tenant(tx, tenant_id).await? else {
        return Ok(());
    };
    let definition = &scheme.definition;
    let Some(inherited) = inherited_value(tx, tenant_id, &scheme, kind, resource_id).await? else {
        return Ok(());
    };
    if !is_valid_classification_label(&inherited, definition) {
        return Err(IamError::with_status(
            "RESOURCE_IN_USE",
            "This resource inherits a classification label the scheme in force cannot read; repair that label before deleting it",
            409,
        ));
    }
    let existing = stored_label_record(tx, tenant_id, kind, resource_id).await?;
    // An own label the scheme cannot read already refuses everyone, and outlives the resource as it is.
    if let Some(existing) = &existing
        && !stored_record_valid(existing, &scheme)
    {
        return Ok(());
    }
    let own = match &existing {
        Some(existing) => Some(
            validate_label(existing.get("label").unwrap_or(&Value::Null), definition)?.to_value(),
        ),
        None => None,
    };
    let label = join(
        own.clone(),
        Some(validate_label(&inherited, definition)?.to_value()),
        definition,
    )
    .unwrap_or_else(invalid_label);
    if let Some(own) = &own
        && crate::js::stringify(own) == crate::js::stringify(&label)
    {
        return Ok(());
    }
    let now = ctx.now();
    let unique_key = label_key_of(kind, resource_id);
    let inherit_to_children = existing
        .as_ref()
        .and_then(|existing| existing.get("inheritToChildren"))
        .filter(|value| !value.is_null())
        .cloned()
        .unwrap_or(Value::Bool(false));
    let version = existing
        .as_ref()
        .and_then(|existing| existing.get("version"))
        .and_then(better_iam_core::js::as_number)
        .unwrap_or(0.0)
        + 1.0;
    let mut next = Record::new();
    next.insert(
        "id".into(),
        existing
            .as_ref()
            .and_then(|existing| existing.get("id"))
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or_else(|| Value::String(id())),
    );
    next.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    next.insert("uniqueKey".into(), Value::String(unique_key.clone()));
    next.insert("type".into(), Value::String(kind.to_owned()));
    next.insert("resourceId".into(), Value::String(resource_id.to_owned()));
    next.insert("label".into(), label.clone());
    next.insert("inheritToChildren".into(), inherit_to_children.clone());
    next.insert(
        "schemeTenantId".into(),
        Value::String(scheme.tenant_id.clone()),
    );
    next.insert(
        "labeledBy".into(),
        Value::String(principal.identity.id.clone()),
    );
    next.insert("labeledAt".into(), number(now));
    next.insert("version".into(), number(version));
    if existing.is_some() {
        tx.put(LABELS, &next).await?;
    } else {
        tx.insert(LABELS, &next).await?;
    }
    let mut metadata = Map::new();
    metadata.insert("type".into(), Value::String(kind.to_owned()));
    if let Some(level) = label.get("level") {
        metadata.insert("level".into(), level.clone());
    }
    if let Some(compartments) = label.get("compartments").filter(|compartments| {
        compartments
            .as_array()
            .is_some_and(|items| !items.is_empty())
    }) {
        metadata.insert("compartments".into(), compartments.clone());
    }
    if label.get("noforn") == Some(&Value::Bool(true)) {
        metadata.insert("noforn".into(), Value::Bool(true));
    }
    if let Some(releasable_to) = label.get("releasableTo") {
        metadata.insert("releasableTo".into(), releasable_to.clone());
    }
    metadata.insert("inheritToChildren".into(), inherit_to_children);
    if let Some(previous) = existing
        .as_ref()
        .and_then(|existing| existing.get("label"))
        .and_then(|label| label.get("level"))
    {
        metadata.insert("previousLevel".into(), previous.clone());
    }
    metadata.insert("reason".into(), Value::String("resource-deleted".into()));
    ctx.events()?
        .audit(
            tx,
            principal,
            "classification:label",
            tenant_id,
            &unique_key,
            AuditOutcome::Allow,
            false,
            Some(metadata),
        )
        .await
}

/// Refuses moving `tenant` below `parent` (`tenants.reparent`) when the move changes the scheme in force for it and
/// `subtree` (the tenant and its descendants) holds classification labels or live (interim, active, or suspended)
/// clearances: they were written under the scheme in force now, and under another one they would stop counting, or
/// with none in force no longer protect anything. Declassify and revoke them first, or keep the tenant under its
/// scheme. Does nothing (and reads nothing) without the option.
pub async fn assert_scheme_kept(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant: &better_iam_core::Tenant,
    parent: &better_iam_core::Tenant,
    subtree: &Value,
) -> IamResult<()> {
    if ctx.options.clearances.is_none() {
        return Ok(());
    }
    // Only the ancestry above the moved tenant changes: a scheme its subtree defines stays in force unless the new
    // ancestry brings one closer to the root.
    let above: Vec<String> = chain_ids(&ctx.ancestry(tx, tenant).await?)
        .into_iter()
        .skip(1)
        .collect();
    let before = effective_scheme_of(tx, &above).await?;
    let after = effective_scheme_of(tx, &chain_ids(&ctx.ancestry(tx, parent).await?)).await?;
    if before.as_ref().map(|scheme| &scheme.tenant_id)
        == after.as_ref().map(|scheme| &scheme.tenant_id)
    {
        return Ok(());
    }
    let members: Vec<&str> = match subtree {
        Value::Array(items) => items.iter().filter_map(Value::as_str).collect(),
        Value::String(single) => vec![single.as_str()],
        _ => Vec::new(),
    };
    for tenant_id in members {
        let labels = tx
            .find(
                LABELS,
                &Filter::new().eq("tenantId", tenant_id),
                &FindOptions {
                    limit: Some(1),
                    ..FindOptions::default()
                },
            )
            .await?;
        let live = tx
            .find(
                CLEARANCES,
                &Filter::new().eq("tenantId", tenant_id),
                &FindOptions::default(),
            )
            .await?
            .iter()
            .any(|record| {
                str_member(record, "tenantId") == Some(tenant_id)
                    && matches!(
                        str_member(record, "status"),
                        Some("active" | "interim" | "suspended")
                    )
            });
        if labels
            .iter()
            .any(|item| str_member(item, "tenantId") == Some(tenant_id))
            || live
        {
            return Err(IamError::with_status(
                "RESOURCE_IN_USE",
                "Moving this tenant changes the classification scheme in force for it while it holds classification labels or clearances; declassify and revoke them first",
                409,
            ));
        }
    }
    Ok(())
}

/// `{ by, at, reason }` of an ended clearance.
fn ending(by: &str, at: f64, reason: &str) -> Value {
    let mut ended = Map::new();
    ended.insert("by".into(), Value::String(by.to_owned()));
    ended.insert("at".into(), number(at));
    ended.insert("reason".into(), Value::String(reason.to_owned()));
    Value::Object(ended)
}

/// Offboarding (`identities.offboard`): ends the leaver's clearance as `terminated`, debriefing every compartment
/// (audited as `clearance:debrief` and `clearance:terminate` with the identity as the resource). The record stays
/// as history; one that already ended (revoked for cause, or terminated) is left as it is, so a revocation is never
/// rewritten as an ordinary departure. Returns 1 when a clearance was terminated, else 0. Lifecycle cleanup inside
/// the offboarding operation, so it needs no clearance permission. Does nothing (and reads nothing) without the
/// `clearances` option.
pub async fn terminate_clearances_of(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    identity: &better_iam_core::Identity,
    reason: &str,
) -> IamResult<f64> {
    if ctx.options.clearances.is_none() {
        return Ok(0.0);
    }
    let Some(mut record) = clearance_record(tx, &identity.id, &identity.tenant_id).await? else {
        return Ok(0.0);
    };
    if ended(&record) {
        return Ok(0.0);
    }
    let now = ctx.now();
    let events = ctx.events()?;
    for read_in in read_ins_of(&record) {
        let mut metadata = Map::new();
        if let Some(compartment_id) = read_in.get("compartmentId") {
            metadata.insert("compartmentId".into(), compartment_id.clone());
        }
        metadata.insert("reason".into(), Value::String("terminated".into()));
        events
            .audit(
                tx,
                principal,
                "clearance:debrief",
                &identity.tenant_id,
                &identity.id,
                AuditOutcome::Allow,
                false,
                Some(metadata),
            )
            .await?;
    }
    let reason = slice_utf16(reason, 512);
    let level = record.get("level").cloned();
    let previous_status = record.get("status").cloned();
    record.shift_remove("suspended");
    record.insert("status".into(), Value::String("terminated".into()));
    record.insert("readIns".into(), Value::Array(Vec::new()));
    record.insert(
        "terminated".into(),
        ending(&principal.identity.id, now, &reason),
    );
    record.insert("updatedAt".into(), number(now));
    record.insert(
        "updatedBy".into(),
        Value::String(principal.identity.id.clone()),
    );
    tx.put(CLEARANCES, &record).await?;
    let mut metadata = Map::new();
    if let Some(level) = level {
        metadata.insert("level".into(), level);
    }
    if let Some(previous_status) = previous_status {
        metadata.insert("previousStatus".into(), previous_status);
    }
    metadata.insert("reason".into(), Value::String(reason));
    events
        .audit(
            tx,
            principal,
            "clearance:terminate",
            &identity.tenant_id,
            &identity.id,
            AuditOutcome::Allow,
            false,
            Some(metadata),
        )
        .await?;
    Ok(1.0)
}

/// Identity deletion (`deleteIdentity`): marks the clearance `terminated` and releases its read-ins, keeping the
/// record as history. One that already ended keeps its status (a revocation for cause stays a revocation) and only
/// loses any read-ins left. Call only with the `clearances` option.
pub async fn release_clearances_of(
    tx: &Store,
    identity: &better_iam_core::Identity,
    now: Option<f64>,
    by: Option<&str>,
) -> IamResult<()> {
    let now = now.unwrap_or_else(date_now);
    let by = by.unwrap_or("identity-deleted");
    let Some(mut record) = clearance_record(tx, &identity.id, &identity.tenant_id).await? else {
        return Ok(());
    };
    let was_ended = ended(&record);
    if was_ended && read_ins_of(&record).is_empty() {
        return Ok(());
    }
    record.shift_remove("suspended");
    if !was_ended {
        record.insert("status".into(), Value::String("terminated".into()));
    }
    record.insert("readIns".into(), Value::Array(Vec::new()));
    if !was_ended {
        record.insert("terminated".into(), ending(by, now, "identity deleted"));
    }
    record.insert("updatedAt".into(), number(now));
    record.insert("updatedBy".into(), Value::String(by.to_owned()));
    tx.put(CLEARANCES, &record).await?;
    Ok(())
}

/// Suspends an identity's active or interim clearance (`suspended` with who, when, why and the incident), for the
/// clearances API and automatic responses. It records nothing in the audit trail and sends nothing: callers do. A
/// suspension is lifted only by `clearances.reinstate`.
///
/// `identity` is `{ id, tenantId }`, `input` is `{ by, at, reason, incidentId? }`; the answer is
/// `{ outcome: 'suspended' | 'no-clearance' | 'already-applied', record? }`.
pub async fn suspend_clearance(tx: &Store, identity: &Value, input: &Value) -> IamResult<Value> {
    let identity_id = identity
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let tenant_id = identity
        .get("tenantId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(mut record) = clearance_record(tx, identity_id, tenant_id).await? else {
        return Ok(json!({ "outcome": "no-clearance" }));
    };
    match str_member(&record, "status") {
        Some("revoked" | "terminated") => return Ok(json!({ "outcome": "no-clearance" })),
        Some("suspended") => {
            return Ok(json!({ "outcome": "already-applied", "record": Value::Object(record) }));
        }
        _ => {}
    }
    let by = input.get("by").cloned().unwrap_or(Value::Null);
    let at = input.get("at").cloned().unwrap_or(Value::Null);
    let reason = slice_utf16(
        input
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        512,
    );
    let mut suspended = Map::new();
    suspended.insert("by".into(), by.clone());
    suspended.insert("at".into(), at.clone());
    suspended.insert("reason".into(), Value::String(reason));
    if let Some(incident_id) = input.get("incidentId") {
        suspended.insert("incidentId".into(), incident_id.clone());
    }
    suspended.insert(
        "previousStatus".into(),
        record.get("status").cloned().unwrap_or(Value::Null),
    );
    record.insert("status".into(), Value::String("suspended".into()));
    record.insert("suspended".into(), Value::Object(suspended));
    record.insert("updatedAt".into(), at);
    record.insert("updatedBy".into(), by);
    let next = tx.put(CLEARANCES, &record).await?;
    Ok(json!({ "outcome": "suspended", "record": Value::Object(next) }))
}

/// Emails the person (template `clearance-status`) that their clearance was suspended, revoked or reinstated,
/// naming the level only. Sent only to people with an address, and only when the deployment delivers email.
pub async fn notify_clearance_status(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    identity: &better_iam_core::Identity,
    scheme: Option<&crate::clearances::ClassificationScheme>,
    record: &Value,
    status: &str,
) -> IamResult<()> {
    let sends_email = ctx
        .options
        .authentication
        .as_ref()
        .is_some_and(|authentication| authentication.send_email.is_some());
    let Some(email) = identity.email.as_deref().filter(|email| !email.is_empty()) else {
        return Ok(());
    };
    if !sends_email || identity.kind != IdentityKind::User {
        return Ok(());
    }
    let tenant = tx.get("tenants", &identity.tenant_id).await?;
    let level =
        scheme.and_then(|scheme| level_of(scheme, record.get("level").and_then(Value::as_str)));
    let mut payload = Map::new();
    payload.insert("tenantId".into(), Value::String(identity.tenant_id.clone()));
    if let Some(tenant) = &tenant {
        payload.insert(
            "tenantName".into(),
            tenant.get("name").cloned().unwrap_or(Value::Null),
        );
    }
    payload.insert("status".into(), Value::String(status.to_owned()));
    if let Some(level) = level {
        payload.insert("levelName".into(), Value::String(level.name));
    }
    ctx.auth
        .enqueue_delivery(
            tx,
            EnqueueInput {
                tenant_id: identity.tenant_id.clone(),
                kind: OutboxKind::Email,
                to: email.to_owned(),
                template: "clearance-status".into(),
                payload,
                reference: None,
            },
        )
        .await?;
    Ok(())
}
