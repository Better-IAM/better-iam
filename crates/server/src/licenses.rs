//! Port of `packages/server/src/licenses.ts`.
//!
//! License management: products (SKUs) defined by the platform (the root tenant, visible to every tenant) or by a
//! tenant for its own subtree, capacity per consuming tenant as pools of seats, assignment to people and groups, and
//! materialized seats. The claimants of a product in a tenant (direct assignees and live members of assigned groups,
//! active and unexpired identities only) are ranked by seniority: the first `capacity` hold an active seat, the rest
//! wait. What a license unlocks is expressed with existing governance: birthright package rules on
//! `identity.licenses` (package-rules.ts, org-rules.ts), policies on `principal.licenses` (decisions.ts), and the
//! feature keys a product lists (`iam.licenses.features`).

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, Weak};

use better_iam_auth::outbox::EnqueueInput;
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, Filter, FindOptions, IamError, IamResult, IamStore,
    IamStoreExt, Identity, IdentityKind, IdentityStatus, OutboxKind, Record, Session,
    js as core_js,
};

use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::{ServerContext, Store};
use crate::js::{number, truthy};
use crate::models::GroupMember;
use crate::port::{Callback, decode};
use crate::utils::id;
use crate::validation::text;

/// A product given to a person or a group (uniqueKey `{productId}:{subjectType}:{subjectId}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LicenseAssignment {
    #[serde(rename = "productId")]
    pub product_id: String,
    #[serde(rename = "subjectType")]
    pub subject_type: crate::licenses::LicenseSubjectType,
    #[serde(rename = "subjectId")]
    pub subject_id: String,
    #[serde(rename = "assignedBy")]
    pub assigned_by: String,
    #[serde(rename = "assignedAt")]
    pub assigned_at: f64,
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

/// Capacity of a product in the consuming tenant (`tenantId`): `quantity` seats from `startsAt` (or its creation)
/// until `endsAt` (or indefinitely). A tenant's capacity for a product is the sum over its live pools.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LicensePool {
    #[serde(rename = "productId")]
    pub product_id: String,
    #[serde(rename = "quantity")]
    pub quantity: f64,
    #[serde(rename = "startsAt", default, skip_serializing_if = "Option::is_none")]
    pub starts_at: Option<f64>,
    #[serde(rename = "endsAt", default, skip_serializing_if = "Option::is_none")]
    pub ends_at: Option<f64>,
    #[serde(rename = "note", default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// `subscription`: the capacity was bought through the billing subscription `subscriptionId` (a reference only).
    #[serde(rename = "source")]
    pub source: crate::licenses::LicensePoolSource,
    #[serde(
        rename = "subscriptionId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub subscription_id: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt", default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<f64>,
    #[serde(rename = "updatedBy", default, skip_serializing_if = "Option::is_none")]
    pub updated_by: Option<String>,
    /// When the record itself is swept (retention.ts): 400 days after `endsAt`; ended pools stay as purchase history.
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
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

/// TODO(port): a union or intersection type in TypeScript; JSON until ported.
pub type LicensePoolSource = Value;

/// A license product (SKU). Defined on the root tenant it is a platform product every tenant sees; defined
/// elsewhere it is visible to that tenant and its subtree. Keys are unique per defining tenant (uniqueKey
/// `key:{key}`), and a tenant may not define a key an enclosing tenant already defines.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LicenseProduct {
    #[serde(rename = "key")]
    pub key: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    /// Feature keys the product unlocks for the people holding an active seat (`iam.licenses.features`).
    #[serde(rename = "featureKeys")]
    pub feature_keys: Vec<String>,
    /// A retired product holds no seats anywhere; its pools and assignments stay, read-only.
    #[serde(rename = "status")]
    pub status: crate::licenses::LicenseProductStatus,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(rename = "updatedBy")]
    pub updated_by: String,
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

/// TODO(port): a union or intersection type in TypeScript; JSON until ported.
pub type LicenseProductStatus = Value;

/// One person's claim on a product in a tenant (uniqueKey `{productId}:{identityId}`), materialized by
/// reconciliation: `active` holds one of the tenant's seats, `waiting` is on the waiting list. Seniority
/// (`assignedAt`, the first time the person claimed a seat) decides who keeps a seat when capacity is short; a seat
/// that loses its last claim goes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LicenseSeat {
    #[serde(rename = "productId")]
    pub product_id: String,
    #[serde(rename = "identityId")]
    pub identity_id: String,
    #[serde(rename = "status")]
    pub status: crate::licenses::LicenseSeatStatus,
    #[serde(rename = "sources")]
    pub sources: Value,
    #[serde(rename = "assignedAt")]
    pub assigned_at: f64,
    /// When the seat last became active.
    #[serde(
        rename = "activatedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub activated_at: Option<f64>,
    /// The holder's latest sign-in or credential use, as the last reclaim pass saw it.
    #[serde(
        rename = "lastActivityAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_activity_at: Option<f64>,
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

/// One seat that reconciliation created, changed, or released.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LicenseSeatChange {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "productId")]
    pub product_id: String,
    #[serde(rename = "productKey")]
    pub product_key: String,
    #[serde(rename = "identityId")]
    pub identity_id: String,
    #[serde(rename = "from")]
    pub from: String,
    #[serde(rename = "to")]
    pub to: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// TODO(port): a union or intersection type in TypeScript; JSON until ported.
pub type LicenseSeatStatus = Value;

/// A tenant's license settings (id = tenant ID).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LicenseSettings {
    /// Direct assignments of people inactive this many days are removed by `iam.licenses.reclaim` (off when absent).
    #[serde(
        rename = "reclaimAfterDays",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub reclaim_after_days: Option<f64>,
    /// Email people when they join a product's waiting list and when a waiting seat becomes active.
    #[serde(rename = "notifyWaiting")]
    pub notify_waiting: bool,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(rename = "updatedBy")]
    pub updated_by: String,
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

/// TODO(port): a union or intersection type in TypeScript; JSON until ported.
pub type LicenseSubjectType = Value;

pub static LICENSE_COLLECTIONS: std::sync::LazyLock<Value> = std::sync::LazyLock::new(
    || json!({"products":"licenseProducts","pools":"licensePools","assignments":"licenseAssignments","seats":"licenseSeats","settings":"licenseSettings"}),
);

/// Products one tenant may define.
pub const MAX_LICENSE_PRODUCTS_PER_TENANT: f64 = 200.0;

/// Feature keys one product may list.
pub const MAX_LICENSE_FEATURE_KEYS: f64 = 50.0;

/// Pools (live or ended) one tenant may hold for one product; ended pools are swept 400 days after their end.
pub const MAX_LICENSE_POOLS_PER_PRODUCT: f64 = 100.0;

/// Seats one pool may carry.
pub const MAX_LICENSE_POOL_QUANTITY: f64 = 1000000.0;

/// Direct and group assignments of one product in one tenant.
pub const MAX_LICENSE_ASSIGNMENTS_PER_PRODUCT: f64 = 10000.0;

/// The range of `reclaimAfterDays`.
pub static LICENSE_RECLAIM_DAYS: std::sync::LazyLock<Value> =
    std::sync::LazyLock::new(|| json!({"min":7,"max":365}));

/// How long an ended pool stays as purchase history before the retention sweep removes it.
pub const LICENSE_POOL_RETENTION_MS: f64 = 34560000000.0;

/// Why a person claims a seat: a direct assignment, and the assigned groups they are a live member of.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct LicenseSeatSources {
    pub direct: bool,
    pub group_ids: Vec<String>,
}

/// Who seat changes are attributed to: the acting person, or a system actor (`deployment-operator`,
/// `directory-sync`, ...).
#[derive(Debug, Clone, PartialEq)]
pub enum LicenseActor {
    System(String),
    Principal(Box<AuthenticatedPrincipal>),
}

impl LicenseActor {
    /// The actor as callers pass it: a system actor's name, or a principal encoded as
    /// `crate::conformance::principal_json` writes it (`{ identity, session, deviceProof? }`).
    pub fn from_value(value: &Value) -> IamResult<LicenseActor> {
        if let Value::String(name) = value {
            return Ok(LicenseActor::System(name.clone()));
        }
        let corrupt = || IamError::with_status("INTERNAL_ERROR", "Internal server error", 500);
        let identity: Identity =
            serde_json::from_value(value.get("identity").cloned().unwrap_or(Value::Null))
                .map_err(|_| corrupt())?;
        let session: Session =
            serde_json::from_value(value.get("session").cloned().unwrap_or(Value::Null))
                .map_err(|_| corrupt())?;
        Ok(LicenseActor::Principal(Box::new(AuthenticatedPrincipal {
            identity,
            session,
            device_proof: value
                .get("deviceProof")
                .and_then(Value::as_str)
                .map(str::to_owned),
        })))
    }

    /// The actor of an acting principal.
    pub fn principal(principal: &AuthenticatedPrincipal) -> LicenseActor {
        LicenseActor::Principal(Box::new(principal.clone()))
    }
}

/// `ReconcileLicenseOptions`.
#[derive(Debug, Clone, Default)]
pub struct ReconcileLicenseOptions {
    /// Who the seat changes are attributed to; `deployment-operator` when left out.
    pub actor: Option<LicenseActor>,
    /// Why the run happened, recorded on every seat event (`assign`, `pool-update`, `group-membership`, ...).
    pub reason: Option<String>,
}

/// An active seat that counts right now, with its product.
#[derive(Debug, Clone)]
pub struct HeldLicense {
    pub product: LicenseProduct,
    pub seat: Record,
}

impl LicenseSeatChange {
    /// The change as the TypeScript object encodes.
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }

    fn new(
        tenant_id: &str,
        product_id: &str,
        product_key: &str,
        identity_id: &str,
        from: &str,
        to: &str,
    ) -> Self {
        LicenseSeatChange {
            tenant_id: tenant_id.to_owned(),
            product_id: product_id.to_owned(),
            product_key: product_key.to_owned(),
            identity_id: identity_id.to_owned(),
            from: from.to_owned(),
            to: to.to_owned(),
            extra: Map::new(),
        }
    }
}

/// The policy key listing the product keys a person holds an active seat for in the decision's tenant.
pub const LICENSE_CONTEXT_KEY: &str = "principal.licenses";

/// `licenseCollections.products`.
pub const PRODUCTS: &str = "licenseProducts";
/// `licenseCollections.pools`.
pub const POOLS: &str = "licensePools";
/// `licenseCollections.assignments`.
pub const ASSIGNMENTS: &str = "licenseAssignments";
/// `licenseCollections.seats`.
pub const SEATS: &str = "licenseSeats";
/// `licenseCollections.settings`.
pub const SETTINGS: &str = "licenseSettings";

static KEY_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9._-]{0,63}$").expect("key pattern"));

/// Every record of a collection matching the filter.
pub(crate) async fn find(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

/// Whether any record of a collection matches (`find(..., { limit: 1 }).length`).
pub(crate) async fn any(tx: &Store, collection: &str, filter: Filter) -> IamResult<bool> {
    Ok(!tx
        .find(
            collection,
            &filter,
            &FindOptions {
                limit: Some(1),
                ..FindOptions::default()
            },
        )
        .await?
        .is_empty())
}

/// A string member of a record (None when absent or not a string).
pub(crate) fn str_of<'a>(record: &'a Record, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

/// A string member of a record, `""` when absent.
pub(crate) fn string_of(record: &Record, key: &str) -> String {
    str_of(record, key).unwrap_or_default().to_owned()
}

/// A number member of a record (None when absent or not a number).
pub(crate) fn num_of(record: &Record, key: &str) -> Option<f64> {
    record.get(key).and_then(core_js::as_number)
}

/// `a < b ? -1 : a > b ? 1 : 0` on strings (UTF-16 code units).
pub(crate) fn by_text(a: &str, b: &str) -> Ordering {
    core_js::cmp_utf16(a, b)
}

/// `a - b` of two numbers as an ordering.
pub(crate) fn by_number(a: f64, b: f64) -> Ordering {
    a.partial_cmp(&b).unwrap_or(Ordering::Equal)
}

/// `[...set].sort()`.
pub(crate) fn sorted(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut items: Vec<String> = items.into_iter().collect();
    crate::js::sort_strings(&mut items);
    items
}

/// A seat's sources as stored (`{ direct?: true, groupIds?: string[] }`).
pub(crate) fn seat_sources(seat: &Record) -> LicenseSeatSources {
    let sources = seat.get("sources");
    LicenseSeatSources {
        direct: sources.and_then(|sources| sources.get("direct")) == Some(&Value::Bool(true)),
        group_ids: sources
            .and_then(|sources| sources.get("groupIds"))
            .and_then(Value::as_array)
            .map(|ids| {
                ids.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// Validates a product key: lowercase letters, digits, dots, underscores or hyphens, starting with a letter or
/// digit.
pub fn license_key(value: Option<&Value>) -> IamResult<String> {
    let key = text(value, "key", 64)?;
    if !KEY_PATTERN.is_match(&key) {
        return Err(IamError::new(
            "INVALID_INPUT",
            "License keys are 1-64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter or digit",
        ));
    }
    Ok(key)
}

/// Whether a pool contributes capacity at `now`.
pub fn live_license_pool(pool: &LicensePool, now: f64) -> bool {
    pool.starts_at.is_none_or(|starts| starts <= now) && pool.ends_at.is_none_or(|ends| ends > now)
}

/// The seats a set of pools provides at `now`.
pub fn license_capacity(pools: &[LicensePool], now: f64) -> f64 {
    pools.iter().fold(0.0, |sum, pool| {
        if live_license_pool(pool, now) {
            sum + pool.quantity
        } else {
            sum
        }
    })
}

/// The tenant and its ancestors, nearest first, tolerant of missing records (readers without a server context).
async fn chain_ids(reader: &Store, tenant_id: &str) -> IamResult<Vec<String>> {
    let mut ids: Vec<String> = Vec::new();
    let mut current = Some(tenant_id.to_owned()).filter(|id| !id.is_empty());
    while let Some(tenant) = current {
        if ids.len() >= 64 || ids.contains(&tenant) {
            break;
        }
        ids.push(tenant.clone());
        current = reader
            .get("tenants", &tenant)
            .await?
            .and_then(|realm| str_of(&realm, "parentId").map(str::to_owned))
            .filter(|parent| !parent.is_empty());
    }
    Ok(ids)
}

/// Every product visible to a tenant: its own and those of its ancestors (the root tenant's are platform products).
pub async fn visible_license_products(
    reader: &Store,
    tenant_id: &str,
) -> IamResult<Vec<LicenseProduct>> {
    let mut products = Vec::new();
    for definer in chain_ids(reader, tenant_id).await? {
        for record in find(reader, PRODUCTS, Filter::new().eq("tenantId", definer)).await? {
            products.push(decode::<LicenseProduct>(record)?);
        }
    }
    Ok(products)
}

/// Of the products visible to a tenant (nearest definer first), those whose seats grant their key there, by ID.
fn granting_of(visible: &[LicenseProduct]) -> IndexMap<String, LicenseProduct> {
    let mut by_key: IndexMap<String, LicenseProduct> = IndexMap::new();
    // The last definition of a key is the one closest to the root: it wins.
    for product in visible {
        by_key.insert(product.key.clone(), product.clone());
    }
    by_key
        .into_values()
        .map(|product| (product.id.clone(), product))
        .collect()
}

/// The products whose seats grant their key in a tenant: those visible to it, except a product whose key a tenant
/// enclosing its definer defines as well (`shadowed`). The definition closest to the root wins, so a tenant can
/// never mint seats that count as a key the platform or an enclosing tenant sells, and a product of a tenant the
/// seat's tenant is no longer below (after `tenants.reparent`) grants nothing there.
pub async fn granting_license_products(
    reader: &Store,
    tenant_id: &str,
) -> IamResult<IndexMap<String, LicenseProduct>> {
    Ok(granting_of(
        &visible_license_products(reader, tenant_id).await?,
    ))
}

/// The valid `identity.licenses` values of a tenant: the keys of every product visible to it, retired ones
/// included.
pub async fn license_rule_keys(reader: &Store, tenant_id: &str) -> IamResult<IndexSet<String>> {
    Ok(visible_license_products(reader, tenant_id)
        .await?
        .into_iter()
        .map(|product| product.key)
        .collect())
}

/// What `identity.licenses` holds for the people of one tenant, read once (org-rules.ts).
#[derive(Clone)]
pub struct TenantLicenseFacts {
    /// The keys of every product visible to the tenant.
    pub keys: IndexSet<String>,
    /// `of(identityId, countedGroupIds)`: the keys of the products a person holds an active seat for. A seat held
    /// only through groups counts while one of them is in `countedGroupIds` (memberships no access package created),
    /// so a rule never feeds on what a package granted.
    #[allow(clippy::type_complexity)]
    pub of: Arc<dyn Fn(&str, &IndexSet<String>) -> Vec<String> + Send + Sync>,
}

pub async fn load_license_facts(reader: &Store, tenant_id: &str) -> IamResult<TenantLicenseFacts> {
    let visible = visible_license_products(reader, tenant_id).await?;
    // Seats of a shadowed product (or of one the tenant no longer sees) never count.
    let products = granting_of(&visible);
    let mut seats: HashMap<String, Vec<Record>> = HashMap::new();
    for seat in find(
        reader,
        SEATS,
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("status", "active"),
    )
    .await?
    {
        seats
            .entry(string_of(&seat, "identityId"))
            .or_default()
            .push(seat);
    }
    let keys = visible.iter().map(|product| product.key.clone()).collect();
    Ok(TenantLicenseFacts {
        keys,
        of: Arc::new(move |identity_id, counted_group_ids| {
            let mut keys: IndexSet<String> = IndexSet::new();
            for seat in seats.get(identity_id).map(Vec::as_slice).unwrap_or(&[]) {
                let Some(product) = products.get(str_of(seat, "productId").unwrap_or_default())
                else {
                    continue;
                };
                if product.status != "active" {
                    continue;
                }
                let sources = seat_sources(seat);
                if !sources.direct
                    && !sources
                        .group_ids
                        .iter()
                        .any(|group_id| counted_group_ids.contains(group_id))
                {
                    continue;
                }
                keys.insert(product.key.clone());
            }
            sorted(keys)
        }),
    })
}

/// The active seats of a person in a tenant that count right now: the product is active and grants its key in the
/// tenant (`grantingLicenseProducts`: not shadowed by an enclosing tenant's product, still visible), and a seat
/// held only through groups still has a live membership behind it (memberships lapse between reconciliations).
pub async fn held_licenses(
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    now: f64,
) -> IamResult<Vec<HeldLicense>> {
    let seats: Vec<Record> = find(
        tx,
        SEATS,
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("identityId", identity_id),
    )
    .await?
    .into_iter()
    .filter(|seat| str_of(seat, "status") == Some("active"))
    .collect();
    if seats.is_empty() {
        return Ok(Vec::new());
    }
    let mut groups: Option<IndexSet<String>> = None;
    let mut granting: Option<IndexMap<String, LicenseProduct>> = None;
    let mut held: Vec<HeldLicense> = Vec::new();
    for seat in seats {
        let sources = seat_sources(&seat);
        if !sources.direct {
            if groups.is_none() {
                groups = Some(
                    find(
                        tx,
                        "groupMembers",
                        Filter::new()
                            .eq("tenantId", tenant_id)
                            .eq("identityId", identity_id),
                    )
                    .await?
                    .iter()
                    .filter(|member| {
                        member
                            .get("expiresAt")
                            .is_none_or(|expires| core_js::to_number(expires) > now)
                    })
                    .map(|member| string_of(member, "groupId"))
                    .collect(),
                );
            }
            let live = groups.as_ref().expect("groups");
            if !sources
                .group_ids
                .iter()
                .any(|group_id| live.contains(group_id))
            {
                continue;
            }
        }
        if granting.is_none() {
            granting = Some(granting_license_products(tx, tenant_id).await?);
        }
        let product = granting
            .as_ref()
            .expect("granting")
            .get(str_of(&seat, "productId").unwrap_or_default());
        if let Some(product) = product
            && product.status == "active"
        {
            held.push(HeldLicense {
                product: product.clone(),
                seat,
            });
        }
    }
    held.sort_by(|a, b| by_text(&a.product.key, &b.product.key));
    Ok(held)
}

/// Whether any document names `principal.licenses` (conditions, `${…}` variables, resource patterns).
pub fn mentions_licenses(documents: &[&better_iam_core::PolicyDocument]) -> bool {
    documents.iter().any(|document| {
        let serialized = better_iam_core::js::stringify(
            &serde_json::to_value(&document.statements).unwrap_or(Value::Null),
        );
        [LICENSE_CONTEXT_KEY]
            .iter()
            .any(|key| serialized.contains(key))
    })
}

/// `principal.licenses` for a person in their own tenant: the keys of the products they hold an active seat for.
pub async fn license_context(
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    now: f64,
) -> IamResult<Map<String, Value>> {
    let keys = sorted(
        held_licenses(tx, tenant_id, identity_id, now)
            .await?
            .into_iter()
            .map(|held| held.product.key)
            .collect::<IndexSet<String>>(),
    );
    let mut context = Map::new();
    context.insert(LICENSE_CONTEXT_KEY.into(), json!(keys));
    Ok(context)
}

/// A person's latest activity: their last sign-in (`authSignIns`, else when the account was created) or the last
/// use of one of their own sessions or API keys ("view as" sessions of administrators excluded).
pub async fn last_activity_of(tx: &Store, identity: &Identity) -> IamResult<f64> {
    let ledger = tx.get("authSignIns", &identity.id).await?;
    let mut last = ledger
        .as_ref()
        .and_then(|ledger| ledger.get("lastAt"))
        .filter(|value| !value.is_null())
        .map(core_js::to_number)
        .unwrap_or(identity.created_at);
    for session in find(
        tx,
        "sessions",
        Filter::new().eq("identityId", identity.id.clone()),
    )
    .await?
    {
        let kind = str_of(&session, "kind");
        if let Some(seen) = num_of(&session, "lastSeenAt")
            && (kind == Some("user") || kind == Some("api-key"))
            && !truthy(session.get("impersonatorId"))
            && seen > last
        {
            last = seen;
        }
    }
    Ok(last)
}

async fn audit_as(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    actor: &LicenseActor,
    action: &str,
    tenant_id: &str,
    resource_id: &str,
    metadata: Map<String, Value>,
) -> IamResult<()> {
    match actor {
        LicenseActor::System(actor) => {
            let mut event = Record::new();
            event.insert("id".into(), Value::String(id()));
            event.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
            event.insert("actorId".into(), Value::String(actor.clone()));
            event.insert("action".into(), Value::String(action.to_owned()));
            event.insert("resourceId".into(), Value::String(resource_id.to_owned()));
            event.insert("timestamp".into(), number(ctx.now()));
            event.insert("outcome".into(), Value::String("allow".into()));
            event.insert("metadata".into(), Value::Object(metadata));
            ctx.events()?.record_audit(tx, &event).await
        }
        LicenseActor::Principal(principal) => {
            ctx.events()?
                .audit(
                    tx,
                    principal,
                    action,
                    tenant_id,
                    resource_id,
                    AuditOutcome::Allow,
                    false,
                    Some(metadata),
                )
                .await
        }
    }
}

struct ProductRun {
    actor: LicenseActor,
    reason: String,
    identities: HashMap<String, Option<Identity>>,
    /// The seat tenant and its ancestors, read once per run.
    chain: Option<(String, IndexSet<String>)>,
}

impl ProductRun {
    fn new(actor: LicenseActor, reason: &str) -> Self {
        ProductRun {
            actor,
            reason: reason.to_owned(),
            identities: HashMap::new(),
            chain: None,
        }
    }
}

#[derive(Default)]
struct Claim {
    direct: bool,
    group_ids: IndexSet<String>,
}

/// The waiting-list emails of one product run (`notify`): settings and the tenant's name are read once.
struct Notifier<'a> {
    ctx: &'a Arc<ServerContext>,
    tx: &'a Store,
    tenant_id: &'a str,
    product: Option<&'a LicenseProduct>,
    settings: Option<Option<Record>>,
    tenant_name: Option<String>,
}

impl Notifier<'_> {
    async fn notify(
        &mut self,
        identities: &HashMap<String, Option<Identity>>,
        identity_id: &str,
        template: &str,
    ) -> IamResult<()> {
        let sends_email = self
            .ctx
            .options
            .authentication
            .as_ref()
            .is_some_and(|authentication| authentication.send_email.is_some());
        let Some(product) = self.product else {
            return Ok(());
        };
        if !sends_email {
            return Ok(());
        }
        if self.settings.is_none() {
            self.settings = Some(self.tx.get(SETTINGS, self.tenant_id).await?);
        }
        let notify_waiting = self
            .settings
            .as_ref()
            .and_then(Option::as_ref)
            .and_then(|settings| settings.get("notifyWaiting"))
            == Some(&Value::Bool(true));
        if !notify_waiting {
            return Ok(());
        }
        let identity = match identities.get(identity_id).cloned().flatten() {
            Some(identity) => Some(identity),
            None => match self.tx.get("identities", identity_id).await? {
                Some(record) => Some(decode::<Identity>(record)?),
                None => None,
            },
        };
        let Some(identity) = identity else {
            return Ok(());
        };
        let Some(email) = identity.email.clone().filter(|email| !email.is_empty()) else {
            return Ok(());
        };
        if identity.kind != IdentityKind::User || identity.status != IdentityStatus::Active {
            return Ok(());
        }
        if self.tenant_name.is_none() {
            self.tenant_name = Some(
                self.tx
                    .get("tenants", self.tenant_id)
                    .await?
                    .and_then(|realm| str_of(&realm, "name").map(str::to_owned))
                    .unwrap_or_default(),
            );
        }
        let mut payload = Map::new();
        payload.insert("tenantId".into(), Value::String(self.tenant_id.to_owned()));
        payload.insert(
            "tenantName".into(),
            Value::String(self.tenant_name.clone().unwrap_or_default()),
        );
        payload.insert("productKey".into(), Value::String(product.key.clone()));
        payload.insert("productName".into(), Value::String(product.name.clone()));
        self.ctx
            .auth
            .enqueue_delivery(
                self.tx,
                EnqueueInput {
                    tenant_id: self.tenant_id.to_owned(),
                    kind: OutboxKind::Email,
                    to: email,
                    template: template.to_owned(),
                    payload,
                    reference: None,
                },
            )
            .await?;
        Ok(())
    }
}

/// The seat changes of one product run (`record`): each is collected, audited, and mailed when asked to.
struct SeatRecorder<'a> {
    notifier: Notifier<'a>,
    product_id: &'a str,
    product_key: String,
    changes: Vec<LicenseSeatChange>,
}

impl SeatRecorder<'_> {
    async fn record(
        &mut self,
        run: &ProductRun,
        identity_id: &str,
        from: &str,
        to: &str,
    ) -> IamResult<()> {
        let tenant_id = self.notifier.tenant_id;
        self.changes.push(LicenseSeatChange::new(
            tenant_id,
            self.product_id,
            &self.product_key,
            identity_id,
            from,
            to,
        ));
        let action = match to {
            "none" => "license:seat-release",
            "active" => "license:seat-activate",
            _ => "license:seat-waiting",
        };
        let mut metadata = Map::new();
        metadata.insert(
            "productId".into(),
            Value::String(self.product_id.to_owned()),
        );
        metadata.insert("productKey".into(), Value::String(self.product_key.clone()));
        metadata.insert("from".into(), Value::String(from.to_owned()));
        metadata.insert("to".into(), Value::String(to.to_owned()));
        metadata.insert("reason".into(), Value::String(run.reason.clone()));
        audit_as(
            self.notifier.ctx,
            self.notifier.tx,
            &run.actor,
            action,
            tenant_id,
            identity_id,
            metadata,
        )
        .await?;
        if to == "waiting" {
            self.notifier
                .notify(&run.identities, identity_id, "license-waiting")
                .await?;
        } else if from == "waiting" && to == "active" {
            self.notifier
                .notify(&run.identities, identity_id, "license-activated")
                .await?;
        }
        Ok(())
    }
}

/// Brings one product's seats in a tenant in line with its claimants and live capacity.
async fn reconcile_product(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    product_id: &str,
    run: &mut ProductRun,
) -> IamResult<Vec<LicenseSeatChange>> {
    let now = ctx.now();
    let product: Option<LicenseProduct> = match tx.get(PRODUCTS, product_id).await? {
        Some(record) => Some(decode(record)?),
        None => None,
    };
    let seats = find(
        tx,
        SEATS,
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("productId", product_id),
    )
    .await?;
    let mut claims: IndexMap<String, Claim> = IndexMap::new();
    let mut capacity = 0.0;
    if product.is_some() && run.chain.as_ref().map(|(id, _)| id.as_str()) != Some(tenant_id) {
        run.chain = Some((
            tenant_id.to_owned(),
            chain_ids(tx, tenant_id).await?.into_iter().collect(),
        ));
    }
    // A retired (or vanished) product has no claimants: every seat goes. So does one the tenant no longer sees
    // because it moved out from under the defining tenant (`tenants.reparent`); its assignments stay and count again
    // if it returns.
    if let Some(product) = &product
        && product.status == "active"
        && run
            .chain
            .as_ref()
            .is_some_and(|(_, ids)| ids.contains(&product.tenant_id))
    {
        for assignment in find(
            tx,
            ASSIGNMENTS,
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("productId", product_id),
        )
        .await?
        {
            let subject_id = string_of(&assignment, "subjectId");
            if str_of(&assignment, "subjectType") == Some("identity") {
                claims.entry(subject_id).or_default().direct = true;
            } else {
                for record in find(
                    tx,
                    "groupMembers",
                    Filter::new()
                        .eq("tenantId", tenant_id)
                        .eq("groupId", subject_id.clone()),
                )
                .await?
                {
                    let member: GroupMember = decode(record)?;
                    if ctx.live_membership(&member) {
                        claims
                            .entry(member.identity_id.clone())
                            .or_default()
                            .group_ids
                            .insert(subject_id.clone());
                    }
                }
            }
        }
        // Only active, unexpired identities of the tenant claim a seat (any kind; guests count like anyone).
        let claimants: Vec<String> = claims.keys().cloned().collect();
        for identity_id in claimants {
            if !run.identities.contains_key(&identity_id) {
                let identity = match tx.get("identities", &identity_id).await? {
                    Some(record) => Some(decode::<Identity>(record)?),
                    None => None,
                };
                run.identities.insert(identity_id.clone(), identity);
            }
            let keeps = run
                .identities
                .get(&identity_id)
                .and_then(Option::as_ref)
                .is_some_and(|identity| {
                    identity.tenant_id == tenant_id
                        && identity.status == IdentityStatus::Active
                        && !ctx.identity_expired(identity)
                });
            if !keeps {
                claims.shift_remove(&identity_id);
            }
        }
        let mut pools = Vec::new();
        for record in find(
            tx,
            POOLS,
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("productId", product_id),
        )
        .await?
        {
            pools.push(decode::<LicensePool>(record)?);
        }
        capacity = license_capacity(&pools, now);
    }
    let product_key = product
        .as_ref()
        .map(|product| product.key.clone())
        .unwrap_or_else(|| product_id.to_owned());
    let mut existing: IndexMap<String, Record> = IndexMap::new();
    for seat in &seats {
        existing.insert(string_of(seat, "identityId"), seat.clone());
    }
    // Seniority decides: the oldest claims keep their seats, new claimants queue behind every existing seat. Claims
    // of the same millisecond rank existing seats before new ones and active before waiting, so a claimant never takes
    // a seat someone already holds and repeated runs never swap two holders.
    let rank = |identity_id: &str| match existing.get(identity_id) {
        Some(seat) if str_of(seat, "status") == Some("active") => 0,
        Some(_) => 1,
        None => 2,
    };
    let mut ranked: Vec<(String, f64, i32)> = claims
        .keys()
        .map(|identity_id| {
            (
                identity_id.clone(),
                existing
                    .get(identity_id)
                    .and_then(|seat| num_of(seat, "assignedAt"))
                    .unwrap_or(now),
                rank(identity_id),
            )
        })
        .collect();
    ranked.sort_by(|a, b| {
        by_number(a.1, b.1)
            .then(a.2.cmp(&b.2))
            .then_with(|| by_text(&a.0, &b.0))
    });
    let mut recorder = SeatRecorder {
        notifier: Notifier {
            ctx,
            tx,
            tenant_id,
            product: product.as_ref(),
            settings: None,
            tenant_name: None,
        },
        product_id,
        product_key,
        changes: Vec::new(),
    };
    for seat in &seats {
        let identity_id = string_of(seat, "identityId");
        if !claims.contains_key(&identity_id) {
            tx.delete(SEATS, &string_of(seat, "id")).await?;
            recorder
                .record(
                    run,
                    &identity_id,
                    str_of(seat, "status").unwrap_or_default(),
                    "none",
                )
                .await?;
        }
    }
    for (index, (identity_id, assigned_at, _)) in ranked.iter().enumerate() {
        let status = if (index as f64) < capacity {
            "active"
        } else {
            "waiting"
        };
        let source = claims.get(identity_id).expect("claim");
        let group_ids = sorted(source.group_ids.iter().cloned());
        let mut sources = Map::new();
        if source.direct {
            sources.insert("direct".into(), Value::Bool(true));
        }
        if !group_ids.is_empty() {
            sources.insert("groupIds".into(), json!(group_ids));
        }
        let Some(seat) = existing.get(identity_id) else {
            let mut created = Record::new();
            created.insert("id".into(), Value::String(id()));
            created.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
            created.insert(
                "uniqueKey".into(),
                Value::String(format!("{product_id}:{identity_id}")),
            );
            created.insert("productId".into(), Value::String(product_id.to_owned()));
            created.insert("identityId".into(), Value::String(identity_id.clone()));
            created.insert("status".into(), Value::String(status.into()));
            created.insert("sources".into(), Value::Object(sources));
            created.insert("assignedAt".into(), number(*assigned_at));
            if status == "active" {
                created.insert("activatedAt".into(), number(now));
            }
            tx.insert(SEATS, &created).await?;
            recorder.record(run, identity_id, "none", status).await?;
            continue;
        };
        let previous = seat_sources(seat);
        let same_sources = previous.direct == source.direct && previous.group_ids == group_ids;
        let seat_status = str_of(seat, "status").unwrap_or_default().to_owned();
        if seat_status == status && same_sources {
            continue;
        }
        let mut next = seat.clone();
        let previous_activation = next
            .shift_remove("activatedAt")
            .filter(|value| !value.is_null());
        next.shift_remove("sources");
        next.insert("status".into(), Value::String(status.into()));
        next.insert("sources".into(), Value::Object(sources));
        if status == "active" {
            next.insert(
                "activatedAt".into(),
                if seat_status == "active" {
                    previous_activation.unwrap_or_else(|| number(now))
                } else {
                    number(now)
                },
            );
        }
        tx.put(SEATS, &next).await?;
        if seat_status != status {
            recorder
                .record(run, identity_id, &seat_status, status)
                .await?;
        }
    }
    Ok(recorder.changes)
}

/// The products with assignments or seats in a tenant.
async fn licensed_product_ids(tx: &Store, tenant_id: &str) -> IamResult<Vec<String>> {
    let mut ids: IndexSet<String> = IndexSet::new();
    for assignment in find(tx, ASSIGNMENTS, Filter::new().eq("tenantId", tenant_id)).await? {
        ids.insert(string_of(&assignment, "productId"));
    }
    for seat in find(tx, SEATS, Filter::new().eq("tenantId", tenant_id)).await? {
        ids.insert(string_of(&seat, "productId"));
    }
    Ok(sorted(ids))
}

/// Brings the seats of one product (or of every product with assignments or seats) in a tenant in line with who
/// claims them and the capacity of the live pools. Idempotent. Seats of claimants who are gone (unassigned, left
/// the group, disabled, expired, deleted) are released; the rest are ranked by seniority, the first `capacity`
/// active and the others waiting, so capacity is never over-allocated and a capacity cut moves the newest active
/// seats to the waiting list. Changes are audited as `license:seat-activate`, `license:seat-waiting` and
/// `license:seat-release` (resource: the identity). Callers run `afterIdentityChange` post-commit for the
/// identities in the result.
pub async fn reconcile_licenses(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    product_id: Option<&str>,
    options: ReconcileLicenseOptions,
) -> IamResult<Vec<LicenseSeatChange>> {
    let mut run = ProductRun::new(
        options
            .actor
            .unwrap_or_else(|| LicenseActor::System("deployment-operator".into())),
        options.reason.as_deref().unwrap_or("reconcile"),
    );
    let products = match product_id {
        Some(product_id) => vec![product_id.to_owned()],
        None => licensed_product_ids(tx, tenant_id).await?,
    };
    let mut changes = Vec::new();
    for each in products {
        changes.extend(reconcile_product(ctx, tx, tenant_id, &each, &mut run).await?);
    }
    Ok(changes)
}

/// The products a batch of membership writes left to reconcile, by `{tenantId}:{productId}`.
type Pending = Arc<Mutex<IndexMap<String, (String, String, LicenseActor)>>>;

/// Per transaction: the products a batch of membership writes left to reconcile (`deferredGroupProducts`, a WeakMap
/// keyed by the transaction).
static DEFERRED_GROUP_PRODUCTS: Mutex<Vec<(Weak<dyn IamStore>, Pending)>> = Mutex::new(Vec::new());

fn deferred() -> std::sync::MutexGuard<'static, Vec<(Weak<dyn IamStore>, Pending)>> {
    let mut entries = DEFERRED_GROUP_PRODUCTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    entries.retain(|(weak, _)| weak.strong_count() > 0);
    entries
}

fn same_tx(weak: &Weak<dyn IamStore>, tx: &Store) -> bool {
    weak.upgrade()
        .is_some_and(|live| std::ptr::addr_eq(Arc::as_ptr(&live), Arc::as_ptr(tx)))
}

fn deferred_get(tx: &Store) -> Option<Pending> {
    deferred()
        .iter()
        .find(|(weak, _)| same_tx(weak, tx))
        .map(|(_, pending)| pending.clone())
}

fn deferred_set(tx: &Store, pending: Pending) {
    deferred().push((Arc::downgrade(tx), pending));
}

fn deferred_delete(tx: &Store) {
    deferred().retain(|(weak, _)| !same_tx(weak, tx));
}

/// Runs a batch of group membership writes (`groups.addMembers`, offboarding, configuration sync) with the seat
/// reconciliation they cause deferred to the end of the batch, where each affected product is reconciled once
/// instead of once per membership: every run rebuilds all of the product's claimants, which made batches quadratic
/// inside the transaction. People who claim a seat in the same batch rank by identity ID among themselves. Nested
/// batches join the outermost one.
pub async fn batch_group_licenses(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    run: &Callback,
) -> IamResult<Value> {
    if deferred_get(tx).is_some() {
        return run(Vec::new()).await;
    }
    let pending: Pending = Arc::default();
    deferred_set(tx, pending.clone());
    let result = run(Vec::new()).await;
    deferred_delete(tx);
    let result = result?;
    let entries = std::mem::take(&mut *pending.lock().unwrap_or_else(|p| p.into_inner()));
    for key in sorted(entries.keys().cloned()) {
        let (tenant_id, product_id, actor) = entries.get(&key).expect("pending").clone();
        reconcile_licenses(
            ctx,
            tx,
            &tenant_id,
            Some(&product_id),
            ReconcileLicenseOptions {
                actor: Some(actor),
                reason: Some("group-membership".into()),
            },
        )
        .await?;
    }
    Ok(result)
}

/// The group IDs of an `Iterable<string>` given as JSON (an array of strings).
fn group_id_list(group_ids: &Value) -> Vec<String> {
    match group_ids {
        Value::String(group_id) => vec![group_id.clone()],
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

/// Whether a product that still holds seats (an active one) is assigned to any of the groups.
pub async fn groups_hold_licenses(
    tx: &Store,
    tenant_id: &str,
    group_ids: &Value,
) -> IamResult<bool> {
    let unique: IndexSet<String> = group_id_list(group_ids).into_iter().collect();
    for group_id in unique {
        for assignment in find(
            tx,
            ASSIGNMENTS,
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("subjectType", "group")
                .eq("subjectId", group_id),
        )
        .await?
        {
            let product = tx
                .get(
                    PRODUCTS,
                    str_of(&assignment, "productId").unwrap_or_default(),
                )
                .await?;
            if product.is_some_and(|product| str_of(&product, "status") == Some("active")) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// The products assigned to some groups, after their membership changed (teams.ts `syncTeamsFromGroups`): each
/// product is reconciled once. Inside `batchGroupLicenses` the products are only noted, for the end of the batch.
pub async fn reconcile_group_licenses(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    group_ids: &Value,
    actor: &Value,
) -> IamResult<Vec<LicenseSeatChange>> {
    let actor = LicenseActor::from_value(actor)?;
    let mut found: IndexSet<String> = IndexSet::new();
    let unique: IndexSet<String> = group_id_list(group_ids).into_iter().collect();
    for group_id in unique {
        for assignment in find(
            tx,
            ASSIGNMENTS,
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("subjectType", "group")
                .eq("subjectId", group_id),
        )
        .await?
        {
            found.insert(string_of(&assignment, "productId"));
        }
    }
    let product_ids = sorted(found);
    if let Some(pending) = deferred_get(tx) {
        let mut pending = pending.lock().unwrap_or_else(|p| p.into_inner());
        for product_id in product_ids {
            let key = format!("{tenant_id}:{product_id}");
            if !pending.contains_key(&key) {
                pending.insert(key, (tenant_id.to_owned(), product_id, actor.clone()));
            }
        }
        return Ok(Vec::new());
    }
    let mut changes = Vec::new();
    for product_id in product_ids {
        changes.extend(
            reconcile_licenses(
                ctx,
                tx,
                tenant_id,
                Some(&product_id),
                ReconcileLicenseOptions {
                    actor: Some(actor.clone()),
                    reason: Some("group-membership".into()),
                },
            )
            .await?,
        );
    }
    Ok(changes)
}

/// When a group is deleted: its license assignments go with it, and the seats they carried follow.
pub async fn release_group_licenses(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    group_id: &str,
    actor: &Value,
) -> IamResult<Vec<LicenseSeatChange>> {
    let actor = LicenseActor::from_value(actor)?;
    let mut product_ids: IndexSet<String> = IndexSet::new();
    for assignment in find(
        tx,
        ASSIGNMENTS,
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("subjectType", "group")
            .eq("subjectId", group_id),
    )
    .await?
    {
        product_ids.insert(string_of(&assignment, "productId"));
        tx.delete(ASSIGNMENTS, &string_of(&assignment, "id"))
            .await?;
    }
    let mut changes = Vec::new();
    for product_id in sorted(product_ids) {
        changes.extend(
            reconcile_licenses(
                ctx,
                tx,
                tenant_id,
                Some(&product_id),
                ReconcileLicenseOptions {
                    actor: Some(actor.clone()),
                    reason: Some("group-deleted".into()),
                },
            )
            .await?,
        );
    }
    Ok(changes)
}

/// When a person is deleted: their direct assignments go and their seats are released (their group memberships are
/// already gone), and waiting people move up.
pub async fn release_licenses_of(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    identity: &Identity,
    actor: &Value,
) -> IamResult<Vec<LicenseSeatChange>> {
    let actor = LicenseActor::from_value(actor)?;
    let tenant_id = identity.tenant_id.as_str();
    let mut product_ids: IndexSet<String> = IndexSet::new();
    for assignment in find(
        tx,
        ASSIGNMENTS,
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("subjectType", "identity")
            .eq("subjectId", identity.id.clone()),
    )
    .await?
    {
        product_ids.insert(string_of(&assignment, "productId"));
        tx.delete(ASSIGNMENTS, &string_of(&assignment, "id"))
            .await?;
    }
    for seat in find(
        tx,
        SEATS,
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("identityId", identity.id.clone()),
    )
    .await?
    {
        product_ids.insert(string_of(&seat, "productId"));
    }
    let mut changes = Vec::new();
    let mut run = ProductRun::new(actor, "identity-deleted");
    // Whatever still ties the person to a product (a membership written after the cleanup) must not keep a seat.
    run.identities.insert(identity.id.clone(), None);
    for product_id in sorted(product_ids) {
        changes.extend(reconcile_product(ctx, tx, tenant_id, &product_id, &mut run).await?);
    }
    Ok(changes)
}

/// Reconciles, inside the caller's transaction, the products that concern some identities of a tenant (their seats,
/// direct assignments, and assignments of their groups), after their status or memberships changed (SCIM
/// provisioning through `protocolHost.identityStatusChanged`, and `reconcileLicensesOf`). Returns the seat changes.
pub async fn reconcile_identity_licenses(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    identity_ids: &[String],
    actor: Option<&Value>,
) -> IamResult<Vec<LicenseSeatChange>> {
    let actor = match actor {
        Some(actor) => LicenseActor::from_value(actor)?,
        None => LicenseActor::System("deployment-operator".into()),
    };
    if identity_ids.is_empty() {
        return Ok(Vec::new());
    }
    // Tenants without licenses pay one indexed lookup.
    if !any(tx, ASSIGNMENTS, Filter::new().eq("tenantId", tenant_id)).await?
        && !any(tx, SEATS, Filter::new().eq("tenantId", tenant_id)).await?
    {
        return Ok(Vec::new());
    }
    let mut product_ids: IndexSet<String> = IndexSet::new();
    let mut groups: IndexMap<String, Vec<String>> = IndexMap::new();
    let unique: IndexSet<&String> = identity_ids.iter().collect();
    for identity_id in unique {
        for seat in find(
            tx,
            SEATS,
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("identityId", identity_id.clone()),
        )
        .await?
        {
            product_ids.insert(string_of(&seat, "productId"));
        }
        for assignment in find(
            tx,
            ASSIGNMENTS,
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("subjectType", "identity")
                .eq("subjectId", identity_id.clone()),
        )
        .await?
        {
            product_ids.insert(string_of(&assignment, "productId"));
        }
        for member in find(
            tx,
            "groupMembers",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("identityId", identity_id.clone()),
        )
        .await?
        {
            let group_id = string_of(&member, "groupId");
            if !groups.contains_key(&group_id) {
                let assigned = find(
                    tx,
                    ASSIGNMENTS,
                    Filter::new()
                        .eq("tenantId", tenant_id)
                        .eq("subjectType", "group")
                        .eq("subjectId", group_id.clone()),
                )
                .await?
                .iter()
                .map(|assignment| string_of(assignment, "productId"))
                .collect();
                groups.insert(group_id.clone(), assigned);
            }
            for product_id in groups.get(&group_id).expect("group") {
                product_ids.insert(product_id.clone());
            }
        }
    }
    let mut run = ProductRun::new(actor, "identity-change");
    let mut changes = Vec::new();
    for product_id in sorted(product_ids) {
        changes.extend(reconcile_product(ctx, tx, tenant_id, &product_id, &mut run).await?);
    }
    Ok(changes)
}

/// Reconciles the products that concern some identities of a tenant (`reconcileIdentityLicenses`) in one
/// transaction, after an administrator changed them (package-automation.ts `afterIdentityChange`). Returns the
/// identities whose seats changed; never throws (the scheduled reconcile catches up).
pub async fn reconcile_licenses_of(
    ctx: &Arc<ServerContext>,
    tenant_id: &str,
    identity_ids: &[String],
    actor: Option<&Value>,
) -> IamResult<Vec<String>> {
    if identity_ids.is_empty() {
        return Ok(Vec::new());
    }
    let context = ctx.clone();
    let tenant = tenant_id.to_owned();
    let ids = identity_ids.to_vec();
    let actor = actor.cloned();
    let outcome = ctx
        .store
        .transaction(|tx| async move {
            let changes =
                reconcile_identity_licenses(&context, &tx, &tenant, &ids, actor.as_ref()).await?;
            let seated: IndexSet<String> = changes
                .into_iter()
                .map(|change| change.identity_id)
                .collect();
            Ok(seated.into_iter().collect::<Vec<String>>())
        })
        .await;
    Ok(outcome.unwrap_or_default())
}

/// A tenant's settings with defaults (reclaim off, no waiting-list email).
pub async fn resolve_license_settings(reader: &Store, tenant_id: &str) -> IamResult<Value> {
    let stored = reader.get(SETTINGS, tenant_id).await?;
    let mut settings = Map::new();
    if let Some(days) = stored
        .as_ref()
        .and_then(|stored| stored.get("reclaimAfterDays"))
    {
        settings.insert("reclaimAfterDays".into(), days.clone());
    }
    settings.insert(
        "notifyWaiting".into(),
        Value::Bool(
            stored
                .as_ref()
                .and_then(|stored| stored.get("notifyWaiting"))
                == Some(&Value::Bool(true)),
        ),
    );
    if let Some(stored) = &stored {
        for key in ["updatedAt", "updatedBy"] {
            if let Some(value) = stored.get(key) {
                settings.insert(key.into(), value.clone());
            }
        }
    }
    Ok(Value::Object(settings))
}
