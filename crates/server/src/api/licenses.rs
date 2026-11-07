//! Port of `packages/server/src/api/licenses.ts`.
//!
//! License management: products (SKUs) the platform or a tenant defines, pools of seats per consuming tenant,
//! assignment to people and groups, seats with a waiting list, and inactive-seat reclaim. What a license unlocks is
//! expressed with birthright package rules on `identity.licenses`, policies on `principal.licenses`, and product
//! feature keys (`iam.licenses.features`). Actions: iam:licenses:read, iam:licenses:manage (products, pools,
//! settings) and iam:licenses:assign, on `iam/licenses/products[/{id}]`, `iam/licenses/pools[/{id}]`,
//! `iam/licenses/assignments`, `iam/licenses/seats` and `iam/licenses/settings`.

use std::collections::HashMap;
use std::sync::Arc;

use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, Filter, IamError, IamResult, IamStoreExt, Identity,
    IdentityStatus, Record, SessionKind, Tenant, TenantStatus, js as core_js,
};
use better_iam_types::api::licenses;
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext, OperationDenied, OperationResult};
use crate::features::feature_key;
use crate::invariants::{InvariantSnapshot, invariant_snapshot, invariant_verify};
use crate::js::{number, sort_strings, unique};
use crate::licenses::{
    ASSIGNMENTS, HeldLicense, LICENSE_POOL_RETENTION_MS, LicenseActor, LicensePool, LicenseProduct,
    LicenseSeatChange, MAX_LICENSE_ASSIGNMENTS_PER_PRODUCT, MAX_LICENSE_FEATURE_KEYS,
    MAX_LICENSE_POOL_QUANTITY, MAX_LICENSE_POOLS_PER_PRODUCT, MAX_LICENSE_PRODUCTS_PER_TENANT,
    POOLS, PRODUCTS, ReconcileLicenseOptions, SEATS, SETTINGS, any, by_number, by_text, find,
    granting_license_products, held_licenses, last_activity_of, license_capacity, license_key,
    live_license_pool, num_of, reconcile_licenses, resolve_license_settings, seat_sources, sorted,
    str_of, string_of, visible_license_products,
};
use crate::port::decode;
use crate::utils::id;
use crate::validation::{integer, strings, text};

const DAY: f64 = 86_400_000.0;
/// `licenseReclaimDays`.
const RECLAIM_DAYS_MIN: f64 = 7.0;
const RECLAIM_DAYS_MAX: f64 = 365.0;

fn product_resource(product_id: &str) -> String {
    format!("licenses/products/{product_id}")
}

fn pool_resource(pool_id: &str) -> String {
    format!("licenses/pools/{pool_id}")
}

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

/// `value ?? fallback` for a request member: undefined and null take the fallback.
fn or_default(value: Option<&Value>, fallback: Value) -> Value {
    value
        .filter(|value| !value.is_null())
        .cloned()
        .unwrap_or(fallback)
}

fn subject_type(value: Option<&Value>) -> IamResult<String> {
    match value.and_then(Value::as_str) {
        Some(kind @ ("identity" | "group")) => Ok(kind.to_owned()),
        _ => Err(invalid("subjectType must be 'identity' or 'group'")),
    }
}

fn feature_keys_of(value: &Value) -> IamResult<Vec<String>> {
    let Some(items) = value
        .as_array()
        .filter(|items| items.len() as f64 <= MAX_LICENSE_FEATURE_KEYS)
    else {
        return Err(invalid(format!(
            "featureKeys must list at most {} feature keys",
            MAX_LICENSE_FEATURE_KEYS
        )));
    };
    let keys = items
        .iter()
        .map(|item| feature_key(Some(item)))
        .collect::<IamResult<Vec<String>>>()?;
    Ok(sorted(unique(keys)))
}

fn trimmed(value: Option<&Value>, name: &str, max: usize) -> IamResult<String> {
    Ok(core_js::trim(&text(value, name, max)?).to_owned())
}

fn optional_text(value: Option<&Value>, name: &str, max: usize) -> IamResult<Option<String>> {
    match value {
        None => Ok(None),
        Some(value) => Ok(Some(trimmed(Some(value), name, max)?)),
    }
}

fn timestamp(value: Option<&Value>, name: &str) -> IamResult<f64> {
    integer(value, name, 0.0, core_js::MAX_SAFE_INTEGER)
}

fn writable(realm: &Tenant) -> IamResult<()> {
    if realm.status == TenantStatus::Deleted {
        return Err(IamError::with_status(
            "INVALID_TRANSITION",
            "Deleted tenants cannot be updated",
            409,
        ));
    }
    Ok(())
}

fn tenant_ids(chain: &[Tenant]) -> IndexSet<String> {
    chain.iter().map(|link| link.id.clone()).collect()
}

/// The views and whether each product's key is also defined further up (chain nearest-first).
fn product_views(products: &[LicenseProduct], chain: &[Tenant], viewer: &str) -> Vec<Value> {
    let depth: HashMap<&str, i64> = chain
        .iter()
        .enumerate()
        .map(|(index, realm)| (realm.id.as_str(), index as i64))
        .collect();
    let root_id = chain.last().map(|realm| realm.id.as_str());
    products
        .iter()
        .map(|product| {
            let own = depth.get(product.tenant_id.as_str()).copied().unwrap_or(-1);
            let mut view = Map::new();
            view.insert("id".into(), Value::String(product.id.clone()));
            view.insert("key".into(), Value::String(product.key.clone()));
            view.insert("name".into(), Value::String(product.name.clone()));
            if let Some(description) = &product.description {
                view.insert("description".into(), Value::String(description.clone()));
            }
            view.insert("featureKeys".into(), json!(product.feature_keys));
            view.insert("status".into(), product.status.clone());
            view.insert(
                "scope".into(),
                Value::String(
                    if Some(product.tenant_id.as_str()) == root_id {
                        "platform"
                    } else {
                        "tenant"
                    }
                    .into(),
                ),
            );
            view.insert("definedBy".into(), Value::String(product.tenant_id.clone()));
            view.insert(
                "definedHere".into(),
                Value::Bool(product.tenant_id == viewer),
            );
            view.insert(
                "shadowed".into(),
                Value::Bool(products.iter().any(|other| {
                    other.id != product.id
                        && other.key == product.key
                        && depth.get(other.tenant_id.as_str()).copied().unwrap_or(-1) > own
                })),
            );
            view.insert("createdAt".into(), number(product.created_at));
            view.insert(
                "createdBy".into(),
                Value::String(product.created_by.clone()),
            );
            view.insert("updatedAt".into(), number(product.updated_at));
            view.insert(
                "updatedBy".into(),
                Value::String(product.updated_by.clone()),
            );
            Value::Object(view)
        })
        .collect()
}

fn product_metadata(product: &LicenseProduct) -> Map<String, Value> {
    let mut metadata = Map::new();
    metadata.insert("productId".into(), Value::String(product.id.clone()));
    metadata.insert("key".into(), Value::String(product.key.clone()));
    metadata.insert("name".into(), Value::String(product.name.clone()));
    metadata.insert(
        "description".into(),
        product
            .description
            .clone()
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    metadata.insert("featureKeys".into(), json!(product.feature_keys));
    metadata.insert("status".into(), product.status.clone());
    metadata
}

fn optional_number(value: Option<f64>) -> Value {
    value.map(number).unwrap_or(Value::Null)
}

fn pool_metadata(pool: &LicensePool, product: &LicenseProduct) -> Map<String, Value> {
    let mut metadata = Map::new();
    metadata.insert("poolId".into(), Value::String(pool.id.clone()));
    metadata.insert("productId".into(), Value::String(product.id.clone()));
    metadata.insert("productKey".into(), Value::String(product.key.clone()));
    metadata.insert("quantity".into(), number(pool.quantity));
    metadata.insert("startsAt".into(), optional_number(pool.starts_at));
    metadata.insert("endsAt".into(), optional_number(pool.ends_at));
    metadata.insert("source".into(), pool.source.clone());
    metadata.insert(
        "subscriptionId".into(),
        pool.subscription_id
            .clone()
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    metadata
}

fn pool_view(pool: &LicensePool, key: &str, name: &str, tenant_name: &str, now: f64) -> Value {
    let mut view = Map::new();
    view.insert("id".into(), Value::String(pool.id.clone()));
    view.insert("tenantId".into(), Value::String(pool.tenant_id.clone()));
    view.insert("tenantName".into(), Value::String(tenant_name.to_owned()));
    view.insert("productId".into(), Value::String(pool.product_id.clone()));
    view.insert("productKey".into(), Value::String(key.to_owned()));
    view.insert("productName".into(), Value::String(name.to_owned()));
    view.insert("quantity".into(), number(pool.quantity));
    if let Some(starts_at) = pool.starts_at {
        view.insert("startsAt".into(), number(starts_at));
    }
    if let Some(ends_at) = pool.ends_at {
        view.insert("endsAt".into(), number(ends_at));
    }
    if let Some(note) = &pool.note {
        view.insert("note".into(), Value::String(note.clone()));
    }
    view.insert("source".into(), pool.source.clone());
    if let Some(subscription_id) = &pool.subscription_id {
        view.insert(
            "subscriptionId".into(),
            Value::String(subscription_id.clone()),
        );
    }
    view.insert("live".into(), Value::Bool(live_license_pool(pool, now)));
    view.insert("createdAt".into(), number(pool.created_at));
    view.insert("createdBy".into(), Value::String(pool.created_by.clone()));
    if let Some(updated_at) = pool.updated_at {
        view.insert("updatedAt".into(), number(updated_at));
    }
    if let Some(updated_by) = &pool.updated_by {
        view.insert("updatedBy".into(), Value::String(updated_by.clone()));
    }
    Value::Object(view)
}

/// Reads products by ID once per call.
#[derive(Default)]
struct ProductCache(HashMap<String, Option<LicenseProduct>>);

impl ProductCache {
    async fn get(&mut self, tx: &Store, product_id: &str) -> IamResult<Option<LicenseProduct>> {
        if !self.0.contains_key(product_id) {
            let product = match tx.get(PRODUCTS, product_id).await? {
                Some(record) => Some(decode::<LicenseProduct>(record)?),
                None => None,
            };
            self.0.insert(product_id.to_owned(), product);
        }
        Ok(self.0.get(product_id).cloned().flatten())
    }

    /// `(product?.key ?? fallback, product?.name ?? fallback)`.
    async fn names(&mut self, tx: &Store, product_id: &str) -> IamResult<(String, String)> {
        Ok(match self.get(tx, product_id).await? {
            Some(product) => (product.key, product.name),
            None => (product_id.to_owned(), product_id.to_owned()),
        })
    }
}

async fn identity_of(tx: &Store, identity_id: &str) -> IamResult<Option<Identity>> {
    match tx.get("identities", identity_id).await? {
        Some(record) => Ok(Some(decode(record)?)),
        None => Ok(None),
    }
}

async fn assignment_view(
    tx: &Store,
    assignment: &Record,
    key: &str,
    name: &str,
) -> IamResult<Value> {
    let subject_id = string_of(assignment, "subjectId");
    let mut subject_name = Value::String(subject_id.clone());
    let mut subject_email: Option<Value> = None;
    if str_of(assignment, "subjectType") == Some("identity") {
        if let Some(identity) = tx.get("identities", &subject_id).await? {
            subject_name = identity.get("name").cloned().unwrap_or(Value::Null);
            subject_email = identity.get("email").cloned();
        }
    } else if let Some(group) = tx.get("groups", &subject_id).await? {
        subject_name = group.get("name").cloned().unwrap_or(Value::Null);
    }
    let member = |key: &str| assignment.get(key).cloned().unwrap_or(Value::Null);
    let mut view = Map::new();
    view.insert("id".into(), member("id"));
    view.insert("tenantId".into(), member("tenantId"));
    view.insert("productId".into(), member("productId"));
    view.insert("productKey".into(), Value::String(key.to_owned()));
    view.insert("productName".into(), Value::String(name.to_owned()));
    view.insert("subjectType".into(), member("subjectType"));
    view.insert("subjectId".into(), member("subjectId"));
    view.insert("subjectName".into(), subject_name);
    if let Some(email) = subject_email {
        view.insert("subjectEmail".into(), email);
    }
    view.insert("assignedBy".into(), member("assignedBy"));
    view.insert("assignedAt".into(), member("assignedAt"));
    Ok(Value::Object(view))
}

/// Waiting-list places per seat ID: per product, by seniority.
fn waiting_positions(seats: &[Record]) -> HashMap<String, usize> {
    let mut queues: IndexMap<String, Vec<&Record>> = IndexMap::new();
    for seat in seats {
        if str_of(seat, "status") == Some("waiting") {
            queues
                .entry(string_of(seat, "productId"))
                .or_default()
                .push(seat);
        }
    }
    let mut positions = HashMap::new();
    for queue in queues.values_mut() {
        queue.sort_by(|a, b| {
            by_number(
                num_of(a, "assignedAt").unwrap_or(f64::NAN),
                num_of(b, "assignedAt").unwrap_or(f64::NAN),
            )
            .then_with(|| {
                by_text(
                    str_of(a, "identityId").unwrap_or_default(),
                    str_of(b, "identityId").unwrap_or_default(),
                )
            })
        });
        for (index, seat) in queue.iter().enumerate() {
            positions.insert(string_of(seat, "id"), index + 1);
        }
    }
    positions
}

fn seats_json(changes: &[LicenseSeatChange]) -> Value {
    Value::Array(changes.iter().map(LicenseSeatChange::to_json).collect())
}

/// Package rules on `identity.licenses` re-evaluate for the people whose seats changed (post-commit, per tenant;
/// never throws).
async fn follow_seats(ctx: &Arc<ServerContext>, result: Value) -> Value {
    let mut by_tenant: IndexMap<String, IndexSet<String>> = IndexMap::new();
    for change in result
        .get("seats")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
    {
        let tenant_id = change
            .get("tenantId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let identity_id = change
            .get("identityId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        by_tenant.entry(tenant_id).or_default().insert(identity_id);
    }
    for (tenant_id, identity_ids) in by_tenant {
        let identity_ids: Vec<String> = identity_ids.into_iter().collect();
        // `afterIdentityChange` never throws (the scheduled reconcile catches up).
        let _ = crate::api::package_automation::after_identity_change(
            ctx,
            &tenant_id,
            &identity_ids,
            &Value::Null,
        )
        .await;
    }
    result
}

fn failure(tenant_id: &str, error: &IamError) -> Value {
    json!({ "tenantId": tenant_id, "code": error.code, "message": error.message })
}

async fn tenants_for(
    ctx: &Arc<ServerContext>,
    tenant_id: Option<&Value>,
) -> IamResult<Vec<Tenant>> {
    match tenant_id {
        Some(tenant_id) => Ok(vec![
            ctx.tenant(&ctx.store, &text(Some(tenant_id), "tenantId", 256)?)
                .await?,
        ]),
        None => {
            let mut tenants: Vec<Tenant> = Vec::new();
            for record in find(&ctx.store, "tenants", Filter::new().eq("status", "active")).await? {
                tenants.push(decode(record)?);
            }
            tenants.sort_by(|a, b| by_text(&a.id, &b.id));
            Ok(tenants)
        }
    }
}

/// `input.tenantId` of a job's optional input (`{ tenantId?: string } = {}`).
fn job_tenant(input: Option<&Value>) -> Option<&Value> {
    input.and_then(|input| input.get("tenantId"))
}

/// The scheduler job behind `iam.licenses.reconcile`: one transaction per tenant with licenses.
pub async fn reconcile_all_licenses(
    ctx: &Arc<ServerContext>,
    input: Option<&Value>,
) -> IamResult<Value> {
    let mut tenants = 0.0;
    let mut activated = 0.0;
    let mut waiting = 0.0;
    let mut released = 0.0;
    let mut failed: Vec<Value> = Vec::new();
    for tenant in tenants_for(ctx, job_tenant(input)).await? {
        if tenant.status != TenantStatus::Active {
            continue;
        }
        let context = ctx.clone();
        let tenant_id = tenant.id.clone();
        let outcome = ctx
            .store
            .transaction(|tx| async move {
                if !any(
                    &tx,
                    ASSIGNMENTS,
                    Filter::new().eq("tenantId", tenant_id.clone()),
                )
                .await?
                    && !any(&tx, SEATS, Filter::new().eq("tenantId", tenant_id.clone())).await?
                {
                    return Ok(None);
                }
                Ok(Some(
                    reconcile_licenses(
                        &context,
                        &tx,
                        &tenant_id,
                        None,
                        ReconcileLicenseOptions {
                            actor: None,
                            reason: Some("schedule".into()),
                        },
                    )
                    .await?,
                ))
            })
            .await;
        match outcome {
            Ok(None) => continue,
            Ok(Some(changes)) => {
                tenants += 1.0;
                for change in &changes {
                    match change.to.as_str() {
                        "active" => activated += 1.0,
                        "waiting" => waiting += 1.0,
                        _ => released += 1.0,
                    }
                }
                follow_seats(ctx, json!({ "seats": seats_json(&changes) })).await;
            }
            Err(error) => failed.push(failure(&tenant.id, &error)),
        }
    }
    Ok(json!({
        "tenants": number(tenants),
        "activated": number(activated),
        "waiting": number(waiting),
        "released": number(released),
        "failedTenants": failed,
    }))
}

/// The scheduler job behind `iam.licenses.reclaim`: one transaction per tenant with reclaim turned on.
pub async fn reclaim_licenses(ctx: &Arc<ServerContext>, input: Option<&Value>) -> IamResult<Value> {
    let mut tenants = 0.0;
    let mut reclaimed_all: Vec<Value> = Vec::new();
    let mut failed: Vec<Value> = Vec::new();
    let tenant_ids: Vec<String> = match job_tenant(input) {
        Some(tenant_id) => vec![text(Some(tenant_id), "tenantId", 256)?],
        None => {
            let mut ids: Vec<String> = find(&ctx.store, SETTINGS, Filter::new())
                .await?
                .iter()
                .filter(|settings| settings.get("reclaimAfterDays").is_some())
                .map(|settings| string_of(settings, "tenantId"))
                .collect();
            ids.sort_by(|a, b| by_text(a, b));
            ids
        }
    };
    for tenant_id in tenant_ids {
        let context = ctx.clone();
        let realm_id = tenant_id.clone();
        let outcome = ctx
            .store
            .transaction(|tx| async move { reclaim_tenant(&context, &tx, &realm_id).await })
            .await;
        match outcome {
            Ok(None) => continue,
            Ok(Some((reclaimed, seats))) => {
                tenants += 1.0;
                reclaimed_all.extend(reclaimed);
                follow_seats(ctx, json!({ "seats": seats_json(&seats) })).await;
            }
            Err(error) => failed.push(failure(&tenant_id, &error)),
        }
    }
    Ok(json!({
        "tenants": number(tenants),
        "reclaimed": reclaimed_all,
        "failedTenants": failed,
    }))
}

/// One tenant's reclaim pass (in its transaction): None when the tenant is inactive or reclaim is off.
async fn reclaim_tenant(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
) -> IamResult<Option<(Vec<Value>, Vec<LicenseSeatChange>)>> {
    let tenant = ctx.tenant(tx, tenant_id).await?;
    let days = resolve_license_settings(tx, &tenant.id)
        .await?
        .get("reclaimAfterDays")
        .cloned();
    let Some(days) = days.filter(|_| tenant.status == TenantStatus::Active) else {
        return Ok(None);
    };
    let days_number = core_js::to_number(&days);
    let now = ctx.now();
    let cutoff = now - days_number * DAY;
    let mut identities: HashMap<String, Option<Identity>> = HashMap::new();
    let mut activity: HashMap<String, f64> = HashMap::new();
    // Seats remember what this pass saw, for the console and exports.
    for seat in find(tx, SEATS, Filter::new().eq("tenantId", tenant.id.clone())).await? {
        let identity_id = string_of(&seat, "identityId");
        if !identities.contains_key(&identity_id) {
            identities.insert(identity_id.clone(), identity_of(tx, &identity_id).await?);
        }
        let Some(holder) = identities.get(&identity_id).cloned().flatten() else {
            continue;
        };
        if !activity.contains_key(&holder.id) {
            activity.insert(holder.id.clone(), last_activity_of(tx, &holder).await?);
        }
        let last = activity[&holder.id];
        if num_of(&seat, "lastActivityAt") != Some(last) {
            let mut next = seat.clone();
            next.insert("lastActivityAt".into(), number(last));
            tx.put(SEATS, &next).await?;
        }
    }
    let mut products: HashMap<String, Option<LicenseProduct>> = HashMap::new();
    // Only a product that holds seats here has a seat to reclaim: the assignments of a retired product stay as
    // read-only history, and so do those of a product the tenant no longer sees (it moved away from the definer).
    let chain = tenant_ids(&ctx.ancestry(tx, &tenant).await?);
    let mut reclaimed: Vec<Value> = Vec::new();
    let mut product_ids: IndexSet<String> = IndexSet::new();
    for assignment in find(
        tx,
        ASSIGNMENTS,
        Filter::new()
            .eq("tenantId", tenant.id.clone())
            .eq("subjectType", "identity"),
    )
    .await?
    {
        let assigned_at = num_of(&assignment, "assignedAt").unwrap_or(f64::NAN);
        // Someone assigned within the window has not had the chance to use it yet.
        if assigned_at > cutoff {
            continue;
        }
        let product_id = string_of(&assignment, "productId");
        if !products.contains_key(&product_id) {
            let product = match tx.get(PRODUCTS, &product_id).await? {
                Some(record) => Some(decode::<LicenseProduct>(record)?),
                None => None,
            };
            products.insert(product_id.clone(), product);
        }
        let Some(owner) = products
            .get(&product_id)
            .cloned()
            .flatten()
            .filter(|owner| owner.status == "active" && chain.contains(&owner.tenant_id))
        else {
            continue;
        };
        let subject_id = string_of(&assignment, "subjectId");
        if !identities.contains_key(&subject_id) {
            identities.insert(subject_id.clone(), identity_of(tx, &subject_id).await?);
        }
        let person = identities.get(&subject_id).cloned().flatten();
        let last = match person.filter(|person| person.status != IdentityStatus::Deleted) {
            Some(person) => {
                if !activity.contains_key(&person.id) {
                    activity.insert(person.id.clone(), last_activity_of(tx, &person).await?);
                }
                activity[&person.id]
            }
            None => 0.0,
        };
        if last > cutoff {
            continue;
        }
        tx.delete(ASSIGNMENTS, &string_of(&assignment, "id"))
            .await?;
        let key = owner.key.clone();
        let mut metadata = Map::new();
        metadata.insert("productId".into(), Value::String(product_id.clone()));
        metadata.insert("productKey".into(), Value::String(key.clone()));
        metadata.insert(
            "assignedAt".into(),
            assignment.get("assignedAt").cloned().unwrap_or(Value::Null),
        );
        metadata.insert("lastActivityAt".into(), number(last));
        metadata.insert("reclaimAfterDays".into(), days.clone());
        let mut event = Record::new();
        event.insert("id".into(), Value::String(id()));
        event.insert("tenantId".into(), Value::String(tenant.id.clone()));
        event.insert(
            "actorId".into(),
            Value::String("deployment-operator".into()),
        );
        event.insert("action".into(), Value::String("license:reclaim".into()));
        event.insert("resourceId".into(), Value::String(subject_id.clone()));
        event.insert("timestamp".into(), number(now));
        event.insert("outcome".into(), Value::String("allow".into()));
        event.insert("metadata".into(), Value::Object(metadata));
        ctx.events()?.record_audit(tx, &event).await?;
        product_ids.insert(product_id.clone());
        reclaimed.push(json!({
            "tenantId": tenant.id,
            "productId": product_id,
            "productKey": key,
            "identityId": subject_id,
            "lastActivityAt": number(last),
        }));
    }
    let mut seats = Vec::new();
    for product_id in sorted(product_ids) {
        seats.extend(
            reconcile_licenses(
                ctx,
                tx,
                &tenant.id,
                Some(&product_id),
                ReconcileLicenseOptions {
                    actor: None,
                    reason: Some("reclaim".into()),
                },
            )
            .await?,
        );
    }
    Ok(Some((reclaimed, seats)))
}

/// The `licenses` API group (`createLicensesApi(ctx)`): one method per route `licenses/{method}`.
pub struct LicensesApi {
    ctx: Arc<ServerContext>,
}

/// `createLicensesApi(ctx)`.
pub fn create_licenses_api(ctx: &Arc<ServerContext>) -> IamResult<LicensesApi> {
    Ok(LicensesApi { ctx: ctx.clone() })
}

/// A product as stored and as its type.
struct FoundProduct {
    record: Record,
    product: LicenseProduct,
    chain: Vec<Tenant>,
}

/// Where a pool change is authorized (`poolAuthority`): the defining tenant, or the caller's tenant.
struct PoolAuthority {
    tenant_id: Option<Value>,
    platform: bool,
}

impl LicensesApi {
    /// Platform products (the root tenant's) are defined and changed by a root administrator only.
    async fn platform_guard(
        &self,
        tx: &Store,
        realm: &Tenant,
        principal: &AuthenticatedPrincipal,
    ) -> OperationResult<()> {
        if realm.parent_id.is_none() && !self.ctx.root_principal(tx, principal).await? {
            return Err(OperationDenied::new(Some(
                "Platform license products are managed by a root administrator",
            )));
        }
        Ok(())
    }

    async fn visible_product(
        &self,
        tx: &Store,
        realm: &Tenant,
        product_id: Option<&Value>,
    ) -> IamResult<FoundProduct> {
        let chain = self.ctx.ancestry(tx, realm).await?;
        let product_id = text(product_id, "productId", 256)?;
        let record = tx.get(PRODUCTS, &product_id).await?;
        let Some(record) = record.filter(|record| {
            chain
                .iter()
                .any(|link| str_of(record, "tenantId") == Some(link.id.as_str()))
        }) else {
            return Err(IamError::with_status(
                "NOT_FOUND",
                "License product not found",
                404,
            ));
        };
        let product: LicenseProduct = decode(record.clone())?;
        Ok(FoundProduct {
            record,
            product,
            chain,
        })
    }

    async fn own_product(
        &self,
        tx: &Store,
        realm: &Tenant,
        product_id: Option<&Value>,
    ) -> IamResult<FoundProduct> {
        let found = self.visible_product(tx, realm, product_id).await?;
        if found.product.tenant_id != realm.id {
            return Err(invalid(
                "An enclosing tenant defines this product; change it there",
            ));
        }
        Ok(found)
    }

    async fn view_of(
        &self,
        tx: &Store,
        realm: &Tenant,
        product: &LicenseProduct,
        chain: &[Tenant],
    ) -> IamResult<Value> {
        let mut products = vec![product.clone()];
        products.extend(
            visible_license_products(tx, &realm.id)
                .await?
                .into_iter()
                .filter(|other| other.key == product.key && other.id != product.id),
        );
        Ok(product_views(&products, chain, &realm.id).remove(0))
    }

    /// Pool changes are authorized in the product's defining tenant: root for platform products (capacity bought
    /// from the platform), the defining tenant's managers for their own products. Read outside the transaction to
    /// pick the tenant; the operation re-reads and refuses when it changed.
    async fn pool_authority(
        &self,
        product_id: Option<&str>,
        fallback: Option<&Value>,
    ) -> IamResult<PoolAuthority> {
        let store = &self.ctx.store;
        let product = match product_id {
            Some(product_id) => store.get(PRODUCTS, product_id).await?,
            None => None,
        };
        let definer = match product {
            Some(product) => {
                store
                    .get("tenants", str_of(&product, "tenantId").unwrap_or_default())
                    .await?
            }
            None => None,
        };
        Ok(match definer {
            Some(definer) => PoolAuthority {
                tenant_id: definer.get("id").cloned(),
                platform: definer.get("parentId") == Some(&Value::Null),
            },
            None => PoolAuthority {
                tenant_id: fallback.cloned(),
                platform: false,
            },
        })
    }

    /// The consuming tenant and product of a pool change, checked against the authorizing (defining) tenant. With
    /// `detached`, a pool of a tenant that has since moved out from under the definer passes too, so the definer can
    /// still remove capacity it granted (`removePool`); nothing else changes such a pool.
    async fn pool_target(
        &self,
        tx: &Store,
        definer: &Tenant,
        consumer_id: Option<&Value>,
        product_id: &str,
        detached: bool,
    ) -> IamResult<(LicenseProduct, Tenant)> {
        let ctx = &self.ctx;
        let consumer = ctx.tenant(tx, &text(consumer_id, "tenantId", 256)?).await?;
        let Some(record) = tx.get(PRODUCTS, product_id).await? else {
            return Err(IamError::with_status(
                "NOT_FOUND",
                "License product not found",
                404,
            ));
        };
        let product: LicenseProduct = decode(record)?;
        if product.tenant_id != definer.id {
            return Err(IamError::with_status(
                "CONFLICT",
                "The product changed; try again",
                409,
            ));
        }
        if !detached
            && !ctx
                .ancestry(tx, &consumer)
                .await?
                .iter()
                .any(|link| link.id == definer.id)
        {
            return Err(invalid(
                "tenantId must be the tenant that defines the product or a tenant below it",
            ));
        }
        writable(&consumer)?;
        if product.status != "active" {
            return Err(IamError::with_status(
                "INVALID_TRANSITION",
                "The product is retired; its pools are read-only",
                409,
            ));
        }
        Ok((product, consumer))
    }

    /// Capacity granted from an enclosing tenant moves seats in the receiving tenant, whose enforced access
    /// invariants the operation envelope (run in the defining tenant) does not check: they are checked around the
    /// change the same way. Call before changing anything; `invariant_verify` with the snapshot afterwards refuses
    /// (rolling back) a change that newly breaks one.
    async fn consumer_invariants(
        &self,
        tx: &Store,
        definer: &Tenant,
        consumer: &Tenant,
    ) -> IamResult<Option<InvariantSnapshot>> {
        if consumer.id != definer.id {
            invariant_snapshot(&self.ctx, tx, &consumer.id, "iam:licenses:manage").await
        } else {
            Ok(None)
        }
    }

    async fn audit(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        action: &str,
        tenant_id: &str,
        resource_id: &str,
        metadata: Map<String, Value>,
    ) -> IamResult<()> {
        self.ctx
            .events()?
            .audit(
                tx,
                principal,
                action,
                tenant_id,
                resource_id,
                better_iam_core::AuditOutcome::Allow,
                false,
                Some(metadata),
            )
            .await
    }

    async fn reconcile_as(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
        product_id: &str,
        reason: &str,
    ) -> IamResult<Vec<LicenseSeatChange>> {
        reconcile_licenses(
            &self.ctx,
            tx,
            tenant_id,
            Some(product_id),
            ReconcileLicenseOptions {
                actor: Some(LicenseActor::principal(principal)),
                reason: Some(reason.into()),
            },
        )
        .await
    }

    /// `operation(credential, tenantId, action, resource, mutation, rootOnly)`.
    async fn run<'m>(
        &self,
        credential: &CredentialInput,
        tenant_id: Option<&Value>,
        action: &str,
        resource_id: &str,
        mutation: Mutation<'m>,
        root_only: bool,
    ) -> IamResult<Value> {
        self.ctx
            .operations()?
            .operation(
                credential,
                tenant_id,
                action,
                resource_id,
                mutation,
                root_only,
            )
            .await
    }

    /// `licenses/addPool`: adds capacity to a tenant (`tenantId`): `quantity` seats of the product from `startsAt`
    /// until `endsAt`, optionally referencing the billing subscription that bought them. Authorized in the product's
    /// defining tenant; audited as `license:pool-add` in the receiving tenant. Waiting people take the new seats.
    pub async fn add_pool(
        &self,
        credential: &CredentialInput,
        input: Body<licenses::AddPoolInput>,
    ) -> IamResult<Reply<licenses::AddPoolOutput>> {
        let product_id = text(input.get("productId"), "productId", 256)?;
        let authority = self
            .pool_authority(Some(&product_id), input.get("tenantId"))
            .await?;
        let ctx = &self.ctx;
        let body = &input;
        let product_id = &product_id;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: definer,
                  }| {
                Box::pin(async move {
                    let (product, consumer) = self
                        .pool_target(&tx, &definer, body.get("tenantId"), product_id, false)
                        .await?;
                    let quantity = integer(
                        body.get("quantity"),
                        "quantity",
                        1.0,
                        MAX_LICENSE_POOL_QUANTITY,
                    )?;
                    let now = ctx.now();
                    let starts_at = match body.get("startsAt") {
                        None => None,
                        Some(value) => Some(timestamp(Some(value), "startsAt")?),
                    };
                    let ends_at = match body.get("endsAt") {
                        None => None,
                        Some(value) => Some(timestamp(Some(value), "endsAt")?),
                    };
                    if let Some(ends_at) = ends_at
                        && (ends_at <= now || starts_at.is_some_and(|starts| ends_at <= starts))
                    {
                        return Err(
                            invalid("endsAt must be in the future and after startsAt").into()
                        );
                    }
                    let note = optional_text(body.get("note"), "note", 512)?;
                    let mut subscription_id: Option<String> = None;
                    if let Some(value) = body.get("subscriptionId") {
                        let wanted = text(Some(value), "subscriptionId", 256)?;
                        let subscription = tx.get("billingSubscriptions", &wanted).await?;
                        let belongs = match &subscription {
                            Some(subscription) => ctx
                                .ancestry(&tx, &consumer)
                                .await?
                                .iter()
                                .any(|link| str_of(subscription, "tenantId") == Some(&link.id)),
                            None => false,
                        };
                        // The subscription belongs to the receiving tenant's billing account: itself or an
                        // enclosing tenant.
                        if !belongs {
                            return Err(IamError::with_status(
                                "NOT_FOUND",
                                "Subscription not found",
                                404,
                            )
                            .into());
                        }
                        subscription_id = Some(wanted);
                    }
                    if find(
                        &tx,
                        POOLS,
                        Filter::new()
                            .eq("tenantId", consumer.id.clone())
                            .eq("productId", product.id.clone()),
                    )
                    .await?
                    .len() as f64
                        >= MAX_LICENSE_POOLS_PER_PRODUCT
                    {
                        return Err(IamError::with_status(
                            "LIMIT_EXCEEDED",
                            format!(
                                "A tenant can hold at most {} pools of one product",
                                MAX_LICENSE_POOLS_PER_PRODUCT
                            ),
                            409,
                        )
                        .into());
                    }
                    let snapshot = self.consumer_invariants(&tx, &definer, &consumer).await?;
                    let mut record = Record::new();
                    record.insert("id".into(), Value::String(id()));
                    record.insert("tenantId".into(), Value::String(consumer.id.clone()));
                    record.insert("productId".into(), Value::String(product.id.clone()));
                    record.insert("quantity".into(), number(quantity));
                    if let Some(starts_at) = starts_at {
                        record.insert("startsAt".into(), number(starts_at));
                    }
                    if let Some(ends_at) = ends_at {
                        record.insert("endsAt".into(), number(ends_at));
                        record.insert(
                            "expiresAt".into(),
                            number(ends_at + LICENSE_POOL_RETENTION_MS),
                        );
                    }
                    if let Some(note) = &note {
                        record.insert("note".into(), Value::String(note.clone()));
                    }
                    record.insert(
                        "source".into(),
                        Value::String(
                            if subscription_id.is_some() {
                                "subscription"
                            } else {
                                "manual"
                            }
                            .into(),
                        ),
                    );
                    if let Some(subscription_id) = &subscription_id {
                        record.insert(
                            "subscriptionId".into(),
                            Value::String(subscription_id.clone()),
                        );
                    }
                    record.insert("createdAt".into(), number(now));
                    record.insert(
                        "createdBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    let pool: LicensePool = decode(tx.insert(POOLS, &record).await?)?;
                    self.audit(
                        &tx,
                        &principal,
                        "license:pool-add",
                        &consumer.id,
                        &pool_resource(&pool.id),
                        pool_metadata(&pool, &product),
                    )
                    .await?;
                    let seats = self
                        .reconcile_as(&tx, &principal, &consumer.id, &product.id, "pool-add")
                        .await?;
                    invariant_verify(ctx, &tx, &consumer.id, snapshot.as_ref()).await?;
                    Ok(json!({
                        "pool": pool_view(&pool, &product.key, &product.name, &consumer.name, now),
                        "seats": seats_json(&seats),
                    }))
                })
            },
        );
        let result = self
            .run(
                credential,
                authority.tenant_id.as_ref(),
                "iam:licenses:manage",
                "licenses/pools",
                mutation,
                authority.platform,
            )
            .await?;
        Ok(Reply::json(follow_seats(ctx, result).await))
    }

    /// `licenses/assign`: gives a product to a person (any kind; guests too) or a group of the tenant. The person, or
    /// each active member of the group, claims a seat. Audited as `license:assign`, with the seat changes it caused.
    pub async fn assign(
        &self,
        credential: &CredentialInput,
        input: Body<licenses::AssignInput>,
    ) -> IamResult<Reply<licenses::AssignOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: realm,
                  }| {
                Box::pin(async move {
                    writable(&realm)?;
                    let found = self
                        .visible_product(&tx, &realm, body.get("productId"))
                        .await?;
                    let product = found.product;
                    if product.status != "active" {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "The product is retired",
                            409,
                        )
                        .into());
                    }
                    let kind = subject_type(body.get("subjectType"))?;
                    let subject_id = text(body.get("subjectId"), "subjectId", 256)?;
                    if kind == "identity" {
                        ctx.active_identity(&tx, &subject_id, &realm.id).await?;
                    } else {
                        ctx.scoped(
                            &tx,
                            "groups",
                            Some(&Value::String(subject_id.clone())),
                            &realm.id,
                        )
                        .await?;
                    }
                    let unique_key = format!("{}:{kind}:{subject_id}", product.id);
                    if any(
                        &tx,
                        ASSIGNMENTS,
                        Filter::new()
                            .eq("tenantId", realm.id.clone())
                            .eq("uniqueKey", unique_key.clone()),
                    )
                    .await?
                    {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "The product is already assigned to this subject",
                            409,
                        )
                        .into());
                    }
                    if find(
                        &tx,
                        ASSIGNMENTS,
                        Filter::new()
                            .eq("tenantId", realm.id.clone())
                            .eq("productId", product.id.clone()),
                    )
                    .await?
                    .len() as f64
                        >= MAX_LICENSE_ASSIGNMENTS_PER_PRODUCT
                    {
                        return Err(assignment_limit().into());
                    }
                    let mut record = Record::new();
                    record.insert("id".into(), Value::String(id()));
                    record.insert("tenantId".into(), Value::String(realm.id.clone()));
                    record.insert("uniqueKey".into(), Value::String(unique_key));
                    record.insert("productId".into(), Value::String(product.id.clone()));
                    record.insert("subjectType".into(), Value::String(kind.clone()));
                    record.insert("subjectId".into(), Value::String(subject_id.clone()));
                    record.insert(
                        "assignedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    record.insert("assignedAt".into(), number(ctx.now()));
                    let assignment = tx.insert(ASSIGNMENTS, &record).await?;
                    self.audit(
                        &tx,
                        &principal,
                        "license:assign",
                        &realm.id,
                        &subject_id,
                        assign_metadata(&assignment, &product, &kind),
                    )
                    .await?;
                    let seats = self
                        .reconcile_as(&tx, &principal, &realm.id, &product.id, "assign")
                        .await?;
                    Ok(json!({
                        "assignment": assignment_view(&tx, &assignment, &product.key, &product.name).await?,
                        "seats": seats_json(&seats),
                    }))
                })
            },
        );
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:licenses:assign",
                "licenses/assignments",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(follow_seats(ctx, result).await))
    }

    /// `licenses/assignMany`: gives a product to up to 100 people at once (one transaction; people who already hold
    /// a direct assignment are skipped). Audited as `license:assign` per person.
    pub async fn assign_many(
        &self,
        credential: &CredentialInput,
        input: Body<licenses::AssignManyInput>,
    ) -> IamResult<Reply<licenses::AssignManyOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: realm,
                  }| {
                Box::pin(async move {
                    writable(&realm)?;
                    let identity_ids = unique(strings(body.get("identityIds"), "identityIds")?);
                    if identity_ids.is_empty() {
                        return Err(invalid("Provide 1-100 identityIds").into());
                    }
                    let found = self
                        .visible_product(&tx, &realm, body.get("productId"))
                        .await?;
                    let product = found.product;
                    if product.status != "active" {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "The product is retired",
                            409,
                        )
                        .into());
                    }
                    let existing = find(
                        &tx,
                        ASSIGNMENTS,
                        Filter::new()
                            .eq("tenantId", realm.id.clone())
                            .eq("productId", product.id.clone()),
                    )
                    .await?;
                    let mut held: IndexSet<Option<String>> = existing
                        .iter()
                        .map(|assignment| str_of(assignment, "uniqueKey").map(str::to_owned))
                        .collect();
                    let mut assigned: Vec<Value> = Vec::new();
                    let mut skipped: Vec<String> = Vec::new();
                    for identity_id in identity_ids {
                        ctx.active_identity(&tx, &identity_id, &realm.id).await?;
                        let unique_key = format!("{}:identity:{identity_id}", product.id);
                        if held.contains(&Some(unique_key.clone())) {
                            skipped.push(identity_id);
                            continue;
                        }
                        if (existing.len() + assigned.len()) as f64
                            >= MAX_LICENSE_ASSIGNMENTS_PER_PRODUCT
                        {
                            return Err(assignment_limit().into());
                        }
                        let mut record = Record::new();
                        record.insert("id".into(), Value::String(id()));
                        record.insert("tenantId".into(), Value::String(realm.id.clone()));
                        record.insert("uniqueKey".into(), Value::String(unique_key.clone()));
                        record.insert("productId".into(), Value::String(product.id.clone()));
                        record.insert("subjectType".into(), Value::String("identity".into()));
                        record.insert("subjectId".into(), Value::String(identity_id.clone()));
                        record.insert(
                            "assignedBy".into(),
                            Value::String(principal.identity.id.clone()),
                        );
                        record.insert("assignedAt".into(), number(ctx.now()));
                        let assignment = tx.insert(ASSIGNMENTS, &record).await?;
                        held.insert(Some(unique_key));
                        self.audit(
                            &tx,
                            &principal,
                            "license:assign",
                            &realm.id,
                            &identity_id,
                            assign_metadata(&assignment, &product, "identity"),
                        )
                        .await?;
                        assigned.push(
                            assignment_view(&tx, &assignment, &product.key, &product.name).await?,
                        );
                    }
                    let seats = if assigned.is_empty() {
                        Vec::new()
                    } else {
                        self.reconcile_as(&tx, &principal, &realm.id, &product.id, "assign")
                            .await?
                    };
                    Ok(json!({
                        "assigned": assigned,
                        "skipped": skipped,
                        "seats": seats_json(&seats),
                    }))
                })
            },
        );
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:licenses:assign",
                "licenses/assignments",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(follow_seats(ctx, result).await))
    }

    /// `licenses/configure`: turns inactive-seat reclaim on (`reclaimAfterDays`, 7-365) or off (`null`), and
    /// waiting-list email on or off (`notifyWaiting`). Audited as `license:settings`.
    pub async fn configure(
        &self,
        credential: &CredentialInput,
        input: Body<licenses::ConfigureInput>,
    ) -> IamResult<Reply<licenses::ConfigureOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: realm,
                  }| {
                Box::pin(async move {
                    writable(&realm)?;
                    let days_input = body.get("reclaimAfterDays");
                    let notify_input = body.get("notifyWaiting");
                    if days_input.is_none() && notify_input.is_none() {
                        return Err(invalid("Nothing to update").into());
                    }
                    if notify_input.is_some_and(|value| !value.is_boolean()) {
                        return Err(invalid("notifyWaiting must be a boolean").into());
                    }
                    let stored = tx.get(SETTINGS, &realm.id).await?;
                    let stored_days = stored
                        .as_ref()
                        .and_then(|stored| stored.get("reclaimAfterDays"))
                        .cloned();
                    let stored_notify = stored
                        .as_ref()
                        .and_then(|stored| stored.get("notifyWaiting"))
                        == Some(&Value::Bool(true));
                    let reclaim_after_days = match days_input {
                        None => stored_days.clone(),
                        Some(Value::Null) => None,
                        Some(value) => Some(number(integer(
                            Some(value),
                            "reclaimAfterDays",
                            RECLAIM_DAYS_MIN,
                            RECLAIM_DAYS_MAX,
                        )?)),
                    };
                    let notify_waiting = match notify_input {
                        Some(Value::Bool(value)) => *value,
                        _ => stored_notify,
                    };
                    let mut next = Record::new();
                    next.insert("id".into(), Value::String(realm.id.clone()));
                    next.insert("tenantId".into(), Value::String(realm.id.clone()));
                    if let Some(days) = &reclaim_after_days {
                        next.insert("reclaimAfterDays".into(), days.clone());
                    }
                    next.insert("notifyWaiting".into(), Value::Bool(notify_waiting));
                    next.insert("updatedAt".into(), number(ctx.now()));
                    next.insert(
                        "updatedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    if stored.is_some() {
                        tx.put(SETTINGS, &next).await?;
                    } else {
                        tx.insert(SETTINGS, &next).await?;
                    }
                    let mut metadata = Map::new();
                    metadata.insert(
                        "reclaimAfterDays".into(),
                        reclaim_after_days.unwrap_or(Value::Null),
                    );
                    metadata.insert("notifyWaiting".into(), Value::Bool(notify_waiting));
                    metadata.insert(
                        "previousReclaimAfterDays".into(),
                        stored_days.unwrap_or(Value::Null),
                    );
                    metadata.insert("previousNotifyWaiting".into(), Value::Bool(stored_notify));
                    self.audit(
                        &tx,
                        &principal,
                        "license:settings",
                        &realm.id,
                        "licenses/settings",
                        metadata,
                    )
                    .await?;
                    Ok(settings_view(&tx, &realm.id).await?)
                })
            },
        );
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:licenses:manage",
                "licenses/settings",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `licenses/createProduct`: defines a product: on the root tenant a platform product (root administrators
    /// only), elsewhere a product for the tenant's subtree. Audited as `license:product-create`.
    pub async fn create_product(
        &self,
        credential: &CredentialInput,
        input: Body<licenses::CreateProductInput>,
    ) -> IamResult<Reply<licenses::CreateProductOutput>> {
        let key = license_key(input.get("key"))?;
        let ctx = &self.ctx;
        let body = &input;
        let key = &key;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: realm,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    writable(&realm)?;
                    self.platform_guard(&tx, &realm, &principal).await?;
                    let name = trimmed(body.get("name"), "name", 100)?;
                    let description = optional_text(body.get("description"), "description", 512)?;
                    let feature_keys =
                        feature_keys_of(&or_default(body.get("featureKeys"), json!([])))?;
                    let chain = ctx.ancestry(&tx, &realm).await?;
                    for ancestor in chain.iter().skip(1) {
                        if !find(
                            &tx,
                            PRODUCTS,
                            Filter::new()
                                .eq("tenantId", ancestor.id.clone())
                                .eq("uniqueKey", format!("key:{key}")),
                        )
                        .await?
                        .is_empty()
                        {
                            return Err(IamError::with_status(
                                "CONFLICT",
                                if ancestor.parent_id.is_none() {
                                    "A platform license product already uses this key"
                                } else {
                                    "An enclosing tenant already defines a license product with this key"
                                },
                                409,
                            )
                            .into());
                        }
                    }
                    let existing = find(
                        &tx,
                        PRODUCTS,
                        Filter::new().eq("tenantId", realm.id.clone()),
                    )
                    .await?;
                    if existing
                        .iter()
                        .any(|product| str_of(product, "key") == Some(key.as_str()))
                    {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "A license product with this key already exists",
                            409,
                        )
                        .into());
                    }
                    if existing.len() as f64 >= MAX_LICENSE_PRODUCTS_PER_TENANT {
                        return Err(IamError::with_status(
                            "LIMIT_EXCEEDED",
                            format!(
                                "A tenant can define at most {} license products",
                                MAX_LICENSE_PRODUCTS_PER_TENANT
                            ),
                            409,
                        )
                        .into());
                    }
                    let now = ctx.now();
                    let mut record = Record::new();
                    record.insert("id".into(), Value::String(id()));
                    record.insert("tenantId".into(), Value::String(realm.id.clone()));
                    record.insert("uniqueKey".into(), Value::String(format!("key:{key}")));
                    record.insert("key".into(), Value::String(key.clone()));
                    record.insert("name".into(), Value::String(name));
                    if let Some(description) = description {
                        record.insert("description".into(), Value::String(description));
                    }
                    record.insert("featureKeys".into(), json!(feature_keys));
                    record.insert("status".into(), Value::String("active".into()));
                    record.insert("createdAt".into(), number(now));
                    record.insert(
                        "createdBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    record.insert("updatedAt".into(), number(now));
                    record.insert(
                        "updatedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    let product: LicenseProduct = decode(tx.insert(PRODUCTS, &record).await?)?;
                    self.audit(
                        &tx,
                        &principal,
                        "license:product-create",
                        &realm.id,
                        &product_resource(&product.id),
                        product_metadata(&product),
                    )
                    .await?;
                    Ok(product_views(&[product], &chain, &realm.id).remove(0))
                })
            },
        );
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:licenses:manage",
                "licenses/products",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `licenses/getProduct`: one product visible to the tenant.
    pub async fn get_product(
        &self,
        credential: &CredentialInput,
        input: Body<licenses::GetProductInput>,
    ) -> IamResult<Reply<licenses::GetProductOutput>> {
        let product_id = text(input.get("productId"), "productId", 256)?;
        let wanted = Value::String(product_id.clone());
        let wanted = &wanted;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx, tenant: realm, ..
                  }| {
                Box::pin(async move {
                    let found = self.visible_product(&tx, &realm, Some(wanted)).await?;
                    Ok(self
                        .view_of(&tx, &realm, &found.product, &found.chain)
                        .await?)
                })
            },
        );
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:licenses:read",
                &product_resource(&product_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `licenses/getSettings`: the tenant's license settings (defaults when never configured).
    pub async fn get_settings(
        &self,
        credential: &CredentialInput,
        input: Body<licenses::GetSettingsInput>,
    ) -> IamResult<Reply<licenses::GetSettingsOutput>> {
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx, tenant: realm, ..
                  }| {
                Box::pin(async move { Ok(settings_view(&tx, &realm.id).await?) })
            },
        );
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:licenses:read",
                "licenses/settings",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `licenses/listAssignments`: the tenant's assignments, newest first, optionally of one product or subject.
    pub async fn list_assignments(
        &self,
        credential: &CredentialInput,
        input: Body<licenses::ListAssignmentsInput>,
    ) -> IamResult<Reply<licenses::ListAssignmentsOutput>> {
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx, tenant: realm, ..
                  }| {
                Box::pin(async move {
                    let limit = integer(
                        Some(&or_default(body.get("limit"), json!(100))),
                        "limit",
                        1.0,
                        1000.0,
                    )?;
                    let offset = integer(
                        Some(&or_default(body.get("offset"), json!(0))),
                        "offset",
                        0.0,
                        1_000_000.0,
                    )?;
                    let mut filter = Filter::new().eq("tenantId", realm.id.clone());
                    if let Some(value) = body.get("productId") {
                        filter = filter.eq("productId", text(Some(value), "productId", 256)?);
                    }
                    if let Some(value) = body.get("subjectType") {
                        filter = filter.eq("subjectType", subject_type(Some(value))?);
                    }
                    if let Some(value) = body.get("subjectId") {
                        filter = filter.eq("subjectId", text(Some(value), "subjectId", 256)?);
                    }
                    let mut rows = find(&tx, ASSIGNMENTS, filter).await?;
                    rows.sort_by(|a, b| {
                        by_number(
                            num_of(b, "assignedAt").unwrap_or(f64::NAN),
                            num_of(a, "assignedAt").unwrap_or(f64::NAN),
                        )
                        .then_with(|| {
                            by_text(
                                str_of(a, "id").unwrap_or_default(),
                                str_of(b, "id").unwrap_or_default(),
                            )
                        })
                    });
                    let mut products = ProductCache::default();
                    let mut assignments = Vec::new();
                    for assignment in page(&rows, offset, limit) {
                        let (key, name) = products
                            .names(&tx, str_of(assignment, "productId").unwrap_or_default())
                            .await?;
                        assignments.push(assignment_view(&tx, assignment, &key, &name).await?);
                    }
                    Ok(json!({ "assignments": assignments, "total": rows.len() }))
                })
            },
        );
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:licenses:read",
                "licenses/assignments",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `licenses/listPools`: pools of the tenant and, for products the tenant defines, the pools it granted to
    /// tenants below it; newest first. Ended pools only with `includeEnded`.
    pub async fn list_pools(
        &self,
        credential: &CredentialInput,
        input: Body<licenses::ListPoolsInput>,
    ) -> IamResult<Reply<licenses::ListPoolsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx, tenant: realm, ..
                  }| {
                Box::pin(async move {
                    let limit = integer(
                        Some(&or_default(body.get("limit"), json!(100))),
                        "limit",
                        1.0,
                        1000.0,
                    )?;
                    let offset = integer(
                        Some(&or_default(body.get("offset"), json!(0))),
                        "offset",
                        0.0,
                        1_000_000.0,
                    )?;
                    let product_id = match body.get("productId") {
                        Some(value) => Some(text(Some(value), "productId", 256)?),
                        None => None,
                    };
                    let include_ended = body.get("includeEnded");
                    if include_ended.is_some_and(|value| !value.is_boolean()) {
                        return Err(invalid("includeEnded must be a boolean").into());
                    }
                    let now = ctx.now();
                    let mut filter = Filter::new().eq("tenantId", realm.id.clone());
                    if let Some(product_id) = &product_id {
                        filter = filter.eq("productId", product_id.clone());
                    }
                    let mut rows: Vec<LicensePool> = Vec::new();
                    for record in find(&tx, POOLS, filter).await? {
                        rows.push(decode(record)?);
                    }
                    for product in find(
                        &tx,
                        PRODUCTS,
                        Filter::new().eq("tenantId", realm.id.clone()),
                    )
                    .await?
                    {
                        let own_id = string_of(&product, "id");
                        if product_id.as_ref().is_none_or(|wanted| *wanted == own_id) {
                            for record in
                                find(&tx, POOLS, Filter::new().eq("productId", own_id.clone()))
                                    .await?
                            {
                                if str_of(&record, "tenantId") != Some(realm.id.as_str()) {
                                    rows.push(decode(record)?);
                                }
                            }
                        }
                    }
                    let include_ended = include_ended == Some(&Value::Bool(true));
                    let mut shown: Vec<LicensePool> = rows
                        .into_iter()
                        .filter(|pool| include_ended || pool.ends_at.is_none_or(|ends| ends > now))
                        .collect();
                    shown.sort_by(|a, b| {
                        by_number(b.created_at, a.created_at).then_with(|| by_text(&a.id, &b.id))
                    });
                    let mut products = ProductCache::default();
                    let mut tenant_names: HashMap<String, Option<String>> = HashMap::new();
                    let mut pools = Vec::new();
                    for pool in page(&shown, offset, limit) {
                        let (key, name) = products.names(&tx, &pool.product_id).await?;
                        if !tenant_names.contains_key(&pool.tenant_id) {
                            let found = tx.get("tenants", &pool.tenant_id).await?;
                            tenant_names.insert(
                                pool.tenant_id.clone(),
                                found.and_then(|realm| str_of(&realm, "name").map(str::to_owned)),
                            );
                        }
                        let tenant_name = tenant_names[&pool.tenant_id]
                            .clone()
                            .unwrap_or_else(|| pool.tenant_id.clone());
                        pools.push(pool_view(pool, &key, &name, &tenant_name, now));
                    }
                    Ok(json!({ "pools": pools, "total": shown.len() }))
                })
            },
        );
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:licenses:read",
                "licenses/pools",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `licenses/listProducts`: the products the tenant can use, sorted by key, optionally one `status`.
    pub async fn list_products(
        &self,
        credential: &CredentialInput,
        input: Body<licenses::ListProductsInput>,
    ) -> IamResult<Reply<licenses::ListProductsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx, tenant: realm, ..
                  }| {
                Box::pin(async move {
                    let status = body.get("status");
                    if let Some(status) = status
                        && !matches!(status.as_str(), Some("active" | "retired"))
                    {
                        return Err(invalid("status must be 'active' or 'retired'").into());
                    }
                    let chain = ctx.ancestry(&tx, &realm).await?;
                    let depth: HashMap<String, i64> = chain
                        .iter()
                        .enumerate()
                        .map(|(index, link)| (link.id.clone(), index as i64))
                        .collect();
                    let products = visible_license_products(&tx, &realm.id).await?;
                    let mut views: Vec<Value> = product_views(&products, &chain, &realm.id)
                        .into_iter()
                        .filter(|view| {
                            status.is_none_or(|status| view.get("status") == Some(status))
                        })
                        .collect();
                    let depth_of = |view: &Value| {
                        view.get("definedBy")
                            .and_then(Value::as_str)
                            .and_then(|tenant| depth.get(tenant).copied())
                            .unwrap_or(0)
                    };
                    let key_of = |view: &Value| {
                        view.get("key")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned()
                    };
                    views.sort_by(|a, b| {
                        by_text(&key_of(a), &key_of(b)).then_with(|| depth_of(b).cmp(&depth_of(a)))
                    });
                    Ok(json!({ "tenantId": realm.id, "products": views }))
                })
            },
        );
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:licenses:read",
                "licenses/products",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `licenses/listSeats`: the tenant's seats, optionally of one product, status or person: by product key, active
    /// before waiting, then by seniority (the waiting list's order, with each waiting seat's `position`).
    pub async fn list_seats(
        &self,
        credential: &CredentialInput,
        input: Body<licenses::ListSeatsInput>,
    ) -> IamResult<Reply<licenses::ListSeatsOutput>> {
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx, tenant: realm, ..
                  }| {
                Box::pin(async move {
                    let limit = integer(
                        Some(&or_default(body.get("limit"), json!(100))),
                        "limit",
                        1.0,
                        1000.0,
                    )?;
                    let offset = integer(
                        Some(&or_default(body.get("offset"), json!(0))),
                        "offset",
                        0.0,
                        1_000_000.0,
                    )?;
                    let status = body.get("status");
                    if let Some(status) = status
                        && !matches!(status.as_str(), Some("active" | "waiting"))
                    {
                        return Err(invalid("status must be 'active' or 'waiting'").into());
                    }
                    let identity_id = match body.get("identityId") {
                        Some(value) => Some(text(Some(value), "identityId", 256)?),
                        None => None,
                    };
                    let mut filter = Filter::new().eq("tenantId", realm.id.clone());
                    if let Some(value) = body.get("productId") {
                        filter = filter.eq("productId", text(Some(value), "productId", 256)?);
                    }
                    let all = find(&tx, SEATS, filter).await?;
                    let positions = waiting_positions(&all);
                    let mut products = ProductCache::default();
                    let mut keys: HashMap<String, String> = HashMap::new();
                    for seat in &all {
                        let product_id = string_of(seat, "productId");
                        if let std::collections::hash_map::Entry::Vacant(entry) =
                            keys.entry(product_id.clone())
                        {
                            entry.insert(products.names(&tx, &product_id).await?.0);
                        }
                    }
                    let mut rows: Vec<&Record> = all
                        .iter()
                        .filter(|seat| {
                            status.is_none_or(|status| seat.get("status") == Some(status))
                                && identity_id
                                    .as_ref()
                                    .is_none_or(|wanted| str_of(seat, "identityId") == Some(wanted))
                        })
                        .collect();
                    let key_of = |seat: &Record| {
                        keys.get(str_of(seat, "productId").unwrap_or_default())
                            .cloned()
                            .unwrap_or_default()
                    };
                    let waiting =
                        |seat: &Record| (str_of(seat, "status") == Some("waiting")) as i32;
                    rows.sort_by(|a, b| {
                        by_text(&key_of(a), &key_of(b))
                            .then_with(|| {
                                by_text(
                                    str_of(a, "productId").unwrap_or_default(),
                                    str_of(b, "productId").unwrap_or_default(),
                                )
                            })
                            .then_with(|| waiting(a).cmp(&waiting(b)))
                            .then_with(|| {
                                by_number(
                                    num_of(a, "assignedAt").unwrap_or(f64::NAN),
                                    num_of(b, "assignedAt").unwrap_or(f64::NAN),
                                )
                            })
                            .then_with(|| {
                                by_text(
                                    str_of(a, "identityId").unwrap_or_default(),
                                    str_of(b, "identityId").unwrap_or_default(),
                                )
                            })
                    });
                    let mut seats = Vec::new();
                    for seat in page(&rows, offset, limit) {
                        let product_id = string_of(seat, "productId");
                        let identity = string_of(seat, "identityId");
                        let (key, name) = products.names(&tx, &product_id).await?;
                        let holder = tx.get("identities", &identity).await?;
                        let position = positions.get(&string_of(seat, "id")).copied();
                        let sources = seat_sources(seat);
                        let member = |key: &str| seat.get(key).cloned().unwrap_or(Value::Null);
                        let mut view = Map::new();
                        view.insert("id".into(), member("id"));
                        view.insert("tenantId".into(), member("tenantId"));
                        view.insert("productId".into(), member("productId"));
                        view.insert("productKey".into(), Value::String(key));
                        view.insert("productName".into(), Value::String(name));
                        view.insert("identityId".into(), member("identityId"));
                        view.insert(
                            "identityName".into(),
                            holder
                                .as_ref()
                                .and_then(|holder| holder.get("name"))
                                .filter(|name| !name.is_null())
                                .cloned()
                                .unwrap_or_else(|| Value::String(identity.clone())),
                        );
                        if let Some(email) = holder.as_ref().and_then(|holder| holder.get("email"))
                        {
                            view.insert("identityEmail".into(), email.clone());
                        }
                        if let Some(kind) = holder.as_ref().and_then(|holder| holder.get("kind")) {
                            view.insert("identityKind".into(), kind.clone());
                        }
                        view.insert("status".into(), member("status"));
                        if let Some(position) = position {
                            view.insert("position".into(), json!(position));
                        }
                        view.insert("direct".into(), Value::Bool(sources.direct));
                        view.insert(
                            "groupIds".into(),
                            seat.get("sources")
                                .and_then(|sources| sources.get("groupIds"))
                                .filter(|ids| !ids.is_null())
                                .cloned()
                                .unwrap_or_else(|| json!([])),
                        );
                        view.insert("assignedAt".into(), member("assignedAt"));
                        for key in ["activatedAt", "lastActivityAt"] {
                            if let Some(value) = seat.get(key) {
                                view.insert(key.into(), value.clone());
                            }
                        }
                        seats.push(Value::Object(view));
                    }
                    Ok(json!({ "seats": seats, "total": rows.len() }))
                })
            },
        );
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:licenses:read",
                "licenses/seats",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `licenses/mine`: the caller's own licenses in the tenant (active seats and waiting-list places) and the
    /// feature keys their active seats unlock. Needs only a session of the tenant; not audited.
    pub async fn mine(
        &self,
        credential: &CredentialInput,
        input: Body<licenses::MineInput>,
    ) -> IamResult<Reply<licenses::MineOutput>> {
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let authenticated = self.ctx.principals()?.authenticate(credential).await?;
        let ctx = self.ctx.clone();
        let result = self
            .ctx
            .store
            .transaction(
                |tx| async move { my_licenses(&ctx, &tx, &authenticated, &tenant_id).await },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `licenses/removePool`: removes a pool; the newest active seats beyond the remaining capacity move to the
    /// waiting list. Audited as `license:pool-remove`.
    pub async fn remove_pool(
        &self,
        credential: &CredentialInput,
        input: Body<licenses::RemovePoolInput>,
    ) -> IamResult<Reply<licenses::RemovePoolOutput>> {
        let pool_id = text(input.get("poolId"), "poolId", 256)?;
        let authority = self
            .pool_authority_of(&pool_id, input.get("tenantId"))
            .await?;
        let ctx = &self.ctx;
        let body = &input;
        let wanted = &pool_id;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: definer,
                  }| {
                Box::pin(async move {
                    let consumer_id = text(body.get("tenantId"), "tenantId", 256)?;
                    let pool: LicensePool = decode(
                        ctx.scoped(
                            &tx,
                            POOLS,
                            Some(&Value::String(wanted.clone())),
                            &consumer_id,
                        )
                        .await?,
                    )?;
                    // A tenant that moved away keeps no hold on capacity the definer granted it.
                    let (product, consumer) = self
                        .pool_target(
                            &tx,
                            &definer,
                            Some(&Value::String(pool.tenant_id.clone())),
                            &pool.product_id,
                            true,
                        )
                        .await?;
                    let snapshot = self.consumer_invariants(&tx, &definer, &consumer).await?;
                    tx.delete(POOLS, &pool.id).await?;
                    self.audit(
                        &tx,
                        &principal,
                        "license:pool-remove",
                        &consumer.id,
                        &pool_resource(&pool.id),
                        pool_metadata(&pool, &product),
                    )
                    .await?;
                    let seats = self
                        .reconcile_as(&tx, &principal, &consumer.id, &product.id, "pool-remove")
                        .await?;
                    invariant_verify(ctx, &tx, &consumer.id, snapshot.as_ref()).await?;
                    Ok(json!({ "removed": true, "seats": seats_json(&seats) }))
                })
            },
        );
        let result = self
            .run(
                credential,
                authority.tenant_id.as_ref(),
                "iam:licenses:manage",
                &pool_resource(&pool_id),
                mutation,
                authority.platform,
            )
            .await?;
        Ok(Reply::json(follow_seats(ctx, result).await))
    }

    /// `poolAuthority(found?.tenantId === input.tenantId ? found.productId : undefined, input.tenantId)`.
    async fn pool_authority_of(
        &self,
        pool_id: &str,
        tenant_id: Option<&Value>,
    ) -> IamResult<PoolAuthority> {
        let found = self.ctx.store.get(POOLS, pool_id).await?;
        let product_id = found
            .as_ref()
            .filter(|found| {
                tenant_id.is_some_and(|tenant_id| found.get("tenantId") == Some(tenant_id))
            })
            .and_then(|found| str_of(found, "productId"))
            .map(str::to_owned);
        self.pool_authority(product_id.as_deref(), tenant_id).await
    }

    /// `licenses/retireProduct`: retires a product for good: every seat of it is released in every tenant, its pools
    /// and assignments stay read-only, and its key stays taken. Audited as `license:product-retire`.
    pub async fn retire_product(
        &self,
        credential: &CredentialInput,
        input: Body<licenses::RetireProductInput>,
    ) -> IamResult<Reply<licenses::RetireProductOutput>> {
        let product_id = text(input.get("productId"), "productId", 256)?;
        let ctx = &self.ctx;
        let wanted = Value::String(product_id.clone());
        let wanted = &wanted;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: realm,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let found = self.own_product(&tx, &realm, Some(wanted)).await?;
                    self.platform_guard(&tx, &realm, &principal).await?;
                    if found.product.status == "retired" {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "The product is already retired",
                            409,
                        )
                        .into());
                    }
                    let mut next = found.record.clone();
                    next.insert("status".into(), Value::String("retired".into()));
                    next.insert("updatedAt".into(), number(ctx.now()));
                    next.insert(
                        "updatedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    let next: LicenseProduct = decode(tx.put(PRODUCTS, &next).await?)?;
                    let tenant_ids = sorted(
                        find(
                            &tx,
                            SEATS,
                            Filter::new().eq("productId", found.product.id.clone()),
                        )
                        .await?
                        .iter()
                        .map(|seat| string_of(seat, "tenantId"))
                        .collect::<IndexSet<String>>(),
                    );
                    let mut seats = Vec::new();
                    for tenant_id in &tenant_ids {
                        seats.extend(
                            reconcile_licenses(
                                ctx,
                                &tx,
                                tenant_id,
                                Some(&found.product.id),
                                ReconcileLicenseOptions {
                                    actor: Some(LicenseActor::principal(&principal)),
                                    reason: Some("product-retired".into()),
                                },
                            )
                            .await?,
                        );
                    }
                    let mut metadata = Map::new();
                    metadata.insert("productId".into(), Value::String(next.id.clone()));
                    metadata.insert("key".into(), Value::String(next.key.clone()));
                    metadata.insert("releasedSeats".into(), json!(seats.len()));
                    metadata.insert("tenants".into(), json!(tenant_ids.len()));
                    self.audit(
                        &tx,
                        &principal,
                        "license:product-retire",
                        &realm.id,
                        &product_resource(&next.id),
                        metadata,
                    )
                    .await?;
                    Ok(json!({
                        "product": self.view_of(&tx, &realm, &next, &found.chain).await?,
                        "seats": seats_json(&seats),
                    }))
                })
            },
        );
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:licenses:manage",
                &product_resource(&product_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(follow_seats(ctx, result).await))
    }

    /// `licenses/unassign`: removes an assignment, by `assignmentId` or by product and subject. Seats it carried are
    /// released (unless another assignment still covers the person). Audited as `license:unassign`.
    pub async fn unassign(
        &self,
        credential: &CredentialInput,
        input: Body<licenses::UnassignInput>,
    ) -> IamResult<Reply<licenses::UnassignOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: realm,
                  }| {
                Box::pin(async move {
                    let assignment = match body.get("assignmentId") {
                        Some(assignment_id) => {
                            ctx.scoped(&tx, ASSIGNMENTS, Some(assignment_id), &realm.id)
                                .await?
                        }
                        None => {
                            let product_id = text(body.get("productId"), "productId", 256)?;
                            let kind = subject_type(body.get("subjectType"))?;
                            let subject_id = text(body.get("subjectId"), "subjectId", 256)?;
                            let unique_key = format!("{product_id}:{kind}:{subject_id}");
                            find(
                                &tx,
                                ASSIGNMENTS,
                                Filter::new()
                                    .eq("tenantId", realm.id.clone())
                                    .eq("uniqueKey", unique_key),
                            )
                            .await?
                            .into_iter()
                            .next()
                            .ok_or_else(|| {
                                IamError::with_status("NOT_FOUND", "Assignment not found", 404)
                            })?
                        }
                    };
                    tx.delete(ASSIGNMENTS, &string_of(&assignment, "id"))
                        .await?;
                    let product_id = string_of(&assignment, "productId");
                    let product = tx.get(PRODUCTS, &product_id).await?;
                    let mut metadata = Map::new();
                    metadata.insert(
                        "assignmentId".into(),
                        assignment.get("id").cloned().unwrap_or(Value::Null),
                    );
                    metadata.insert("productId".into(), Value::String(product_id.clone()));
                    metadata.insert(
                        "productKey".into(),
                        product
                            .as_ref()
                            .and_then(|product| product.get("key"))
                            .filter(|key| !key.is_null())
                            .cloned()
                            .unwrap_or_else(|| Value::String(product_id.clone())),
                    );
                    metadata.insert(
                        "subjectType".into(),
                        assignment
                            .get("subjectType")
                            .cloned()
                            .unwrap_or(Value::Null),
                    );
                    self.audit(
                        &tx,
                        &principal,
                        "license:unassign",
                        &realm.id,
                        &string_of(&assignment, "subjectId"),
                        metadata,
                    )
                    .await?;
                    let seats = self
                        .reconcile_as(&tx, &principal, &realm.id, &product_id, "unassign")
                        .await?;
                    Ok(json!({ "removed": true, "seats": seats_json(&seats) }))
                })
            },
        );
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:licenses:assign",
                "licenses/assignments",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(follow_seats(ctx, result).await))
    }

    /// `licenses/updatePool`: changes a pool's `quantity`, its end (`endsAt`; `null` makes it open-ended, a past time
    /// ends it now) or its note (`null` clears). Audited as `license:pool-update` with the pool before and after.
    pub async fn update_pool(
        &self,
        credential: &CredentialInput,
        input: Body<licenses::UpdatePoolInput>,
    ) -> IamResult<Reply<licenses::UpdatePoolOutput>> {
        let pool_id = text(input.get("poolId"), "poolId", 256)?;
        let authority = self
            .pool_authority_of(&pool_id, input.get("tenantId"))
            .await?;
        let ctx = &self.ctx;
        let body = &input;
        let wanted = &pool_id;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: definer,
                  }| {
                Box::pin(async move {
                    let consumer_id = text(body.get("tenantId"), "tenantId", 256)?;
                    let record = ctx
                        .scoped(
                            &tx,
                            POOLS,
                            Some(&Value::String(wanted.clone())),
                            &consumer_id,
                        )
                        .await?;
                    let pool: LicensePool = decode(record.clone())?;
                    let (product, consumer) = self
                        .pool_target(
                            &tx,
                            &definer,
                            Some(&Value::String(pool.tenant_id.clone())),
                            &pool.product_id,
                            false,
                        )
                        .await?;
                    let quantity_input = body.get("quantity");
                    let ends_input = body.get("endsAt");
                    let note_input = body.get("note");
                    if quantity_input.is_none() && ends_input.is_none() && note_input.is_none() {
                        return Err(invalid("Nothing to update").into());
                    }
                    let mut rest = record;
                    rest.shift_remove("endsAt");
                    rest.shift_remove("expiresAt");
                    rest.shift_remove("note");
                    let ends_at = match ends_input {
                        None => pool.ends_at,
                        Some(Value::Null) => None,
                        Some(value) => Some(timestamp(Some(value), "endsAt")?),
                    };
                    if let (Some(ends_at), Some(starts_at)) = (ends_at, pool.starts_at)
                        && ends_at <= starts_at
                    {
                        return Err(invalid("endsAt must be after startsAt").into());
                    }
                    let note = match note_input {
                        None => pool.note.clone(),
                        Some(Value::Null) => None,
                        Some(value) => Some(trimmed(Some(value), "note", 512)?),
                    };
                    let snapshot = self.consumer_invariants(&tx, &definer, &consumer).await?;
                    let now = ctx.now();
                    let quantity = match quantity_input {
                        None => pool.quantity,
                        Some(value) => {
                            integer(Some(value), "quantity", 1.0, MAX_LICENSE_POOL_QUANTITY)?
                        }
                    };
                    rest.insert("quantity".into(), number(quantity));
                    if let Some(ends_at) = ends_at {
                        rest.insert("endsAt".into(), number(ends_at));
                        rest.insert(
                            "expiresAt".into(),
                            number(ends_at + LICENSE_POOL_RETENTION_MS),
                        );
                    }
                    if let Some(note) = note {
                        rest.insert("note".into(), Value::String(note));
                    }
                    rest.insert("updatedAt".into(), number(now));
                    rest.insert(
                        "updatedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    let next: LicensePool = decode(tx.put(POOLS, &rest).await?)?;
                    let mut metadata = Map::new();
                    metadata.insert(
                        "before".into(),
                        Value::Object(pool_metadata(&pool, &product)),
                    );
                    metadata.insert(
                        "after".into(),
                        Value::Object(pool_metadata(&next, &product)),
                    );
                    self.audit(
                        &tx,
                        &principal,
                        "license:pool-update",
                        &consumer.id,
                        &pool_resource(&pool.id),
                        metadata,
                    )
                    .await?;
                    let seats = self
                        .reconcile_as(&tx, &principal, &consumer.id, &product.id, "pool-update")
                        .await?;
                    invariant_verify(ctx, &tx, &consumer.id, snapshot.as_ref()).await?;
                    Ok(json!({
                        "pool": pool_view(&next, &product.key, &product.name, &consumer.name, now),
                        "seats": seats_json(&seats),
                    }))
                })
            },
        );
        let result = self
            .run(
                credential,
                authority.tenant_id.as_ref(),
                "iam:licenses:manage",
                &pool_resource(&pool_id),
                mutation,
                authority.platform,
            )
            .await?;
        Ok(Reply::json(follow_seats(ctx, result).await))
    }

    /// `licenses/updateProduct`: renames a product, changes (`null` clears) its description, or replaces its feature
    /// keys; the key never changes. Audited as `license:product-update` with the settings before and after.
    pub async fn update_product(
        &self,
        credential: &CredentialInput,
        input: Body<licenses::UpdateProductInput>,
    ) -> IamResult<Reply<licenses::UpdateProductOutput>> {
        let product_id = text(input.get("productId"), "productId", 256)?;
        let ctx = &self.ctx;
        let body = &input;
        let wanted = Value::String(product_id.clone());
        let wanted = &wanted;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: realm,
                  }| {
                Box::pin(async move {
                    writable(&realm)?;
                    let found = self.own_product(&tx, &realm, Some(wanted)).await?;
                    self.platform_guard(&tx, &realm, &principal).await?;
                    let name_input = body.get("name");
                    let description_input = body.get("description");
                    let feature_input = body.get("featureKeys");
                    if name_input.is_none()
                        && description_input.is_none()
                        && feature_input.is_none()
                    {
                        return Err(invalid("Nothing to update").into());
                    }
                    let mut next = found.record.clone();
                    next.shift_remove("description");
                    let description = match description_input {
                        None => found.product.description.clone(),
                        Some(Value::Null) => None,
                        Some(value) => Some(trimmed(Some(value), "description", 512)?),
                    };
                    if let Some(value) = name_input {
                        next.insert(
                            "name".into(),
                            Value::String(trimmed(Some(value), "name", 100)?),
                        );
                    }
                    if let Some(description) = description {
                        next.insert("description".into(), Value::String(description));
                    }
                    if let Some(value) = feature_input {
                        next.insert("featureKeys".into(), json!(feature_keys_of(value)?));
                    }
                    next.insert("updatedAt".into(), number(ctx.now()));
                    next.insert(
                        "updatedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    let next: LicenseProduct = decode(tx.put(PRODUCTS, &next).await?)?;
                    let mut metadata = Map::new();
                    metadata.insert(
                        "before".into(),
                        Value::Object(product_metadata(&found.product)),
                    );
                    metadata.insert("after".into(), Value::Object(product_metadata(&next)));
                    self.audit(
                        &tx,
                        &principal,
                        "license:product-update",
                        &realm.id,
                        &product_resource(&next.id),
                        metadata,
                    )
                    .await?;
                    Ok(self.view_of(&tx, &realm, &next, &found.chain).await?)
                })
            },
        );
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:licenses:manage",
                &product_resource(&product_id),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `licenses/usage`: per product the tenant uses: capacity from the live pools, active and waiting seats, what is
    /// available, and with `reclaimAfterDays` set how many active seats belong to people inactive that long.
    pub async fn usage(
        &self,
        credential: &CredentialInput,
        input: Body<licenses::UsageInput>,
    ) -> IamResult<Reply<licenses::UsageOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx, tenant: realm, ..
                  }| {
                Box::pin(async move { Ok(usage_report(ctx, &tx, &realm).await?) })
            },
        );
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:licenses:read",
                "licenses/seats",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

fn assignment_limit() -> IamError {
    IamError::with_status(
        "LIMIT_EXCEEDED",
        format!(
            "At most {} assignments per product; assign groups instead",
            MAX_LICENSE_ASSIGNMENTS_PER_PRODUCT
        ),
        409,
    )
}

fn assign_metadata(
    assignment: &Record,
    product: &LicenseProduct,
    kind: &str,
) -> Map<String, Value> {
    let mut metadata = Map::new();
    metadata.insert(
        "assignmentId".into(),
        assignment.get("id").cloned().unwrap_or(Value::Null),
    );
    metadata.insert("productId".into(), Value::String(product.id.clone()));
    metadata.insert("productKey".into(), Value::String(product.key.clone()));
    metadata.insert("subjectType".into(), Value::String(kind.to_owned()));
    metadata
}

/// `rows.slice(offset, offset + limit)`.
fn page<T>(rows: &[T], offset: f64, limit: f64) -> &[T] {
    let start = (offset as usize).min(rows.len());
    let end = (offset + limit).min(rows.len() as f64) as usize;
    &rows[start..end.max(start)]
}

/// `{ tenantId, ...resolveLicenseSettings(tx, tenantId) }`.
async fn settings_view(tx: &Store, tenant_id: &str) -> IamResult<Value> {
    let mut view = Map::new();
    view.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    if let Value::Object(settings) = resolve_license_settings(tx, tenant_id).await? {
        view.extend(settings);
    }
    Ok(Value::Object(view))
}

async fn usage_report(ctx: &Arc<ServerContext>, tx: &Store, realm: &Tenant) -> IamResult<Value> {
    let now = ctx.now();
    let chain = ctx.ancestry(tx, realm).await?;
    let root_id = chain.last().map(|link| link.id.clone()).unwrap_or_default();
    let settings = resolve_license_settings(tx, &realm.id).await?;
    let days = settings.get("reclaimAfterDays").cloned();
    let cutoff = days
        .as_ref()
        .map(|days| now - core_js::to_number(days) * DAY);
    let mut pools: Vec<LicensePool> = Vec::new();
    for record in find(tx, POOLS, Filter::new().eq("tenantId", realm.id.clone())).await? {
        pools.push(decode(record)?);
    }
    let seats = find(tx, SEATS, Filter::new().eq("tenantId", realm.id.clone())).await?;
    let assignments = find(
        tx,
        ASSIGNMENTS,
        Filter::new().eq("tenantId", realm.id.clone()),
    )
    .await?;
    let mut used: IndexSet<String> = IndexSet::new();
    used.extend(pools.iter().map(|pool| pool.product_id.clone()));
    used.extend(seats.iter().map(|seat| string_of(seat, "productId")));
    used.extend(
        assignments
            .iter()
            .map(|assignment| string_of(assignment, "productId")),
    );
    let mut activity: HashMap<String, Option<f64>> = HashMap::new();
    let mut products: Vec<Value> = Vec::new();
    for product in visible_license_products(tx, &realm.id).await? {
        if !used.contains(&product.id) && product.tenant_id != realm.id {
            continue;
        }
        let own: Vec<&Record> = seats
            .iter()
            .filter(|seat| str_of(seat, "productId") == Some(product.id.as_str()))
            .collect();
        let live_pools: Vec<LicensePool> = pools
            .iter()
            .filter(|pool| pool.product_id == product.id && live_license_pool(pool, now))
            .cloned()
            .collect();
        let capacity = license_capacity(&live_pools, now);
        let active = own
            .iter()
            .filter(|seat| str_of(seat, "status") == Some("active"))
            .count() as f64;
        let mut reclaimable = 0.0;
        let mut reclaimable_through_groups = 0.0;
        for seat in &own {
            let inactive = match cutoff {
                Some(cutoff)
                    if str_of(seat, "status") == Some("active")
                        && num_of(seat, "assignedAt").is_some_and(|at| at <= cutoff) =>
                {
                    let identity_id = string_of(seat, "identityId");
                    if !activity.contains_key(&identity_id) {
                        let last = match identity_of(tx, &identity_id).await? {
                            Some(holder) => Some(last_activity_of(tx, &holder).await?),
                            None => None,
                        };
                        activity.insert(identity_id.clone(), last);
                    }
                    activity[&identity_id].is_some_and(|last| last <= cutoff)
                }
                _ => false,
            };
            if inactive {
                reclaimable += 1.0;
                if !seat_sources(seat).direct {
                    reclaimable_through_groups += 1.0;
                }
            }
        }
        products.push(json!({
            "productId": product.id,
            "key": product.key,
            "name": product.name,
            "scope": if product.tenant_id == root_id { "platform" } else { "tenant" },
            "status": product.status,
            "capacity": number(capacity),
            "active": number(active),
            "waiting": number(own.len() as f64 - active),
            "available": number((capacity - active).max(0.0)),
            "pools": live_pools.len(),
            "assignments": assignments
                .iter()
                .filter(|assignment| str_of(assignment, "productId") == Some(product.id.as_str()))
                .count(),
            "reclaimable": number(reclaimable),
            "reclaimableThroughGroups": number(reclaimable_through_groups),
        }));
    }
    products.sort_by(|a, b| {
        let text_of = |value: &Value, key: &str| {
            value
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        by_text(&text_of(a, "key"), &text_of(b, "key"))
            .then_with(|| by_text(&text_of(a, "productId"), &text_of(b, "productId")))
    });
    let mut report = Map::new();
    report.insert("tenantId".into(), Value::String(realm.id.clone()));
    if let Some(days) = days {
        report.insert("reclaimAfterDays".into(), days);
    }
    report.insert("products".into(), Value::Array(products));
    Ok(Value::Object(report))
}

async fn my_licenses(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    authenticated: &AuthenticatedPrincipal,
    tenant_id: &str,
) -> IamResult<Value> {
    let principal = ctx
        .principals()?
        .current_principal(tx, authenticated)
        .await?;
    let realm = ctx.tenant(tx, tenant_id).await?;
    if principal.session.tenant_id != realm.id && !ctx.root_principal(tx, &principal).await? {
        return Err(IamError::with_status(
            "ACCESS_DENIED",
            "Licenses are read from a session of their tenant",
            403,
        ));
    }
    let identity = &principal.identity;
    let empty = |licenses: Vec<Value>, feature_keys: Vec<String>, all: Vec<String>| {
        json!({
            "tenantId": realm.id,
            "identityId": identity.id,
            "licenses": licenses,
            "featureKeys": feature_keys,
            "allFeatureKeys": all,
        })
    };
    if principal.session.kind == SessionKind::Role || identity.tenant_id != realm.id {
        return Ok(empty(Vec::new(), Vec::new(), Vec::new()));
    }
    let now = ctx.now();
    let root_id = ctx
        .ancestry(tx, &realm)
        .await?
        .last()
        .map(|link| link.id.clone())
        .unwrap_or_default();
    let counted: IndexSet<String> = held_licenses(tx, &realm.id, &identity.id, now)
        .await?
        .iter()
        .map(|held| string_of(&held.seat, "id"))
        .collect();
    // A shadowed product, or one the tenant no longer sees, grants nothing: neither its seats nor its waiting list.
    let granting = granting_license_products(tx, &realm.id).await?;
    // (key, productId, platform, featureKeys, license)
    let mut licenses: Vec<(String, String, bool, Vec<String>, Value)> = Vec::new();
    for seat in find(
        tx,
        SEATS,
        Filter::new()
            .eq("tenantId", realm.id.clone())
            .eq("identityId", identity.id.clone()),
    )
    .await?
    {
        let Some(product) = granting.get(str_of(&seat, "productId").unwrap_or_default()) else {
            continue;
        };
        if product.status != "active" {
            continue;
        }
        let status = str_of(&seat, "status").unwrap_or_default();
        if status == "active" && !counted.contains(&string_of(&seat, "id")) {
            continue;
        }
        let position = if status == "waiting" {
            waiting_positions(
                &find(
                    tx,
                    SEATS,
                    Filter::new()
                        .eq("tenantId", realm.id.clone())
                        .eq("productId", string_of(&seat, "productId"))
                        .eq("status", "waiting"),
                )
                .await?,
            )
            .get(&string_of(&seat, "id"))
            .copied()
        } else {
            None
        };
        let feature_keys = if status == "active" {
            product.feature_keys.clone()
        } else {
            Vec::new()
        };
        let platform = product.tenant_id == root_id;
        let mut license = Map::new();
        license.insert("productId".into(), Value::String(product.id.clone()));
        license.insert("key".into(), Value::String(product.key.clone()));
        license.insert("name".into(), Value::String(product.name.clone()));
        if let Some(description) = &product.description {
            license.insert("description".into(), Value::String(description.clone()));
        }
        license.insert(
            "status".into(),
            seat.get("status").cloned().unwrap_or(Value::Null),
        );
        if let Some(position) = position {
            license.insert("position".into(), json!(position));
        }
        license.insert("featureKeys".into(), json!(feature_keys));
        license.insert("platform".into(), Value::Bool(platform));
        license.insert("definedBy".into(), Value::String(product.tenant_id.clone()));
        licenses.push((
            product.key.clone(),
            product.id.clone(),
            platform,
            feature_keys,
            Value::Object(license),
        ));
    }
    licenses.sort_by(|a, b| by_text(&a.0, &b.0).then_with(|| by_text(&a.1, &b.1)));
    let union = |platform_only: bool| {
        sorted(
            licenses
                .iter()
                .filter(|license| !platform_only || license.2)
                .flat_map(|license| license.3.iter().cloned())
                .collect::<IndexSet<String>>(),
        )
    };
    // Only the platform's products are paid entitlements no tenant can mint for itself.
    let feature_keys = union(true);
    let all = union(false);
    Ok(empty(
        licenses.into_iter().map(|license| license.4).collect(),
        feature_keys,
        all,
    ))
}

/// Credential-free license helpers and jobs, shared by `iam.licenses` and tests.
pub struct LicensesRuntime {
    ctx: Arc<ServerContext>,
}

/// `createLicensesRuntime(...)`.
pub fn create_licenses_runtime(ctx: &Arc<ServerContext>) -> IamResult<LicensesRuntime> {
    Ok(LicensesRuntime { ctx: ctx.clone() })
}

impl LicensesRuntime {
    /// The seats that count for a person of the tenant (none for inactive, expired, or other tenants' people). With
    /// `trust`, only those of products defined by the trusted tenant or its ancestors: `trustedTenantId`, else the
    /// root tenant alone (platform products).
    async fn held(
        &self,
        identity_id: Option<&Value>,
        tenant_id: Option<&Value>,
        trust: Option<Option<&Value>>,
    ) -> IamResult<Vec<HeldLicense>> {
        let ctx = self.ctx.clone();
        let identity_id = identity_id.cloned();
        let tenant_id = tenant_id.cloned();
        let trust = trust.map(|trusted| trusted.cloned());
        self.ctx
            .store
            .transaction(|tx| async move {
                let realm = ctx.tenant_of(&tx, tenant_id.as_ref()).await?;
                let trusted: Option<IndexSet<String>> = match trust {
                    None => None,
                    Some(Some(trusted)) => {
                        let tenant = ctx
                            .tenant(&tx, &text(Some(&trusted), "trustedTenantId", 256)?)
                            .await?;
                        Some(tenant_ids(&ctx.ancestry(&tx, &tenant).await?))
                    }
                    Some(None) => Some(
                        ctx.ancestry(&tx, &realm)
                            .await?
                            .last()
                            .map(|link| link.id.clone())
                            .into_iter()
                            .collect(),
                    ),
                };
                let wanted = text(identity_id.as_ref(), "identityId", 256)?;
                let identity = identity_of(&tx, &wanted).await?;
                let Some(identity) = identity.filter(|identity| {
                    identity.tenant_id == realm.id
                        && identity.status == IdentityStatus::Active
                        && !ctx.identity_expired(identity)
                }) else {
                    return Ok(Vec::new());
                };
                let seats = held_licenses(&tx, &realm.id, &identity.id, ctx.now()).await?;
                Ok(match trusted {
                    Some(trusted) => seats
                        .into_iter()
                        .filter(|held| trusted.contains(&held.product.tenant_id))
                        .collect(),
                    None => seats,
                })
            })
            .await
    }

    async fn features_value(
        &self,
        identity_id: Option<&Value>,
        tenant_id: Option<&Value>,
        options: Option<&Value>,
    ) -> IamResult<Vec<String>> {
        let trusted_tenant_id = options
            .filter(|options| !options.is_null())
            .and_then(|options| options.get("trustedTenantId"));
        let mut keys: Vec<String> = self
            .held(identity_id, tenant_id, Some(trusted_tenant_id))
            .await?
            .into_iter()
            .flat_map(|held| held.product.feature_keys)
            .collect();
        keys = unique(keys);
        sort_strings(&mut keys);
        Ok(keys)
    }

    async fn products_value(
        &self,
        identity_id: Option<&Value>,
        tenant_id: Option<&Value>,
    ) -> IamResult<Vec<String>> {
        let keys: IndexSet<String> = self
            .held(identity_id, tenant_id, None)
            .await?
            .into_iter()
            .map(|held| held.product.key)
            .collect();
        Ok(sorted(keys))
    }

    /// The feature keys of the products a person holds an active seat for in the tenant (none for inactive people),
    /// from the products the trusted tenant or one of its ancestors defines only. Any tenant can define a product of
    /// its own that lists any feature key, so by default only **platform** products (the root tenant's) count: pass
    /// `trustedTenantId` to count the products a tenant (and the tenants above it) sells too, such as the tenant's own.
    pub async fn features(
        &self,
        identity_id: &str,
        tenant_id: &str,
        options: Option<&Value>,
    ) -> IamResult<Vec<String>> {
        self.features_value(
            Some(&Value::String(identity_id.to_owned())),
            Some(&Value::String(tenant_id.to_owned())),
            options,
        )
        .await
    }

    /// The keys of the products a person holds an active seat for in the tenant: what `principal.licenses` holds.
    pub async fn products(&self, identity_id: &str, tenant_id: &str) -> IamResult<Vec<String>> {
        self.products_value(
            Some(&Value::String(identity_id.to_owned())),
            Some(&Value::String(tenant_id.to_owned())),
        )
        .await
    }

    /// A scheduler job (hourly): brings every tenant's seats in line with assignments, memberships, identity status and
    /// pool terms, and re-evaluates birthright package rules for the people whose seats changed.
    pub async fn reconcile(&self, input: Option<&Value>) -> IamResult<Value> {
        reconcile_all_licenses(&self.ctx, input).await
    }

    /// A scheduler job (daily): in tenants with `reclaimAfterDays`, removes direct assignments of people with no
    /// sign-in or credential use for that long (audited `license:reclaim`), then reconciles.
    pub async fn reclaim(&self, input: Option<&Value>) -> IamResult<Value> {
        reclaim_licenses(&self.ctx, input).await
    }

    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        let arg = |index: usize| args.get(index);
        match method {
            "features" => Some(
                self.features_value(arg(0), arg(1), arg(2))
                    .await
                    .map(|keys| json!(keys)),
            ),
            "products" => Some(
                self.products_value(arg(0), arg(1))
                    .await
                    .map(|keys| json!(keys)),
            ),
            "reconcile" => Some(
                self.reconcile(arg(0).filter(|input| !input.is_null()))
                    .await,
            ),
            "reclaim" => Some(self.reclaim(arg(0).filter(|input| !input.is_null())).await),
            _ => None,
        }
    }
}
