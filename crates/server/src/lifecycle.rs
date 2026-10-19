//! Port of `packages/server/src/lifecycle.ts`: deployment operations (migrations, root bootstrap and recovery, audit
//! pruning, the access digest and expiry reminders, birthright reconciliation, and the retention worker). None are
//! HTTP endpoints.
//!
//! Ported: `initialize`, `bootstrap`, `recoverRoot`, `pruneAudit`. Skeleton (NOT_IMPLEMENTED): `sendAccessDigest`,
//! `sendExpiryReminders`, `reconcilePackages`, `purgeDeleted`.

use std::sync::Arc;

use better_iam_auth::service::base::CreateIdentityRaw;
use better_iam_core::{
    Filter, FindOptions, IamError, IamResult, IamStoreExt, Identity, OrderOptions, Record, Tenant,
    chain_audit_event, find_ordered,
};
use serde_json::{Map, Value, json};

use crate::context::ServerContext;
use crate::models::GrantAuthority;
use crate::port::{decode, not_ported};
use crate::utils::{all_value, date_now, id, public_identity};
use crate::validation::{email, integer, text};

/// Every tenant-scoped collection; purging a tenant sweeps each of them (`tenantCollections`).
pub const TENANT_COLLECTIONS: &[&str] = &[
    "tenants",
    "identities",
    "sessions",
    "grantAuthorities",
    "policies",
    "policyVersions",
    "roles",
    "bindings",
    "groups",
    "groupMembers",
    "accessPackages",
    "packageAssignments",
    "packageRequests",
    "packageRuleIssues",
    "expiryReminderMarks",
    "trusts",
    "ownerInvitations",
    "memberInvitations",
    "principalBoundaries",
    "actions",
    "resourceTypes",
    "resources",
    "tenantAliases",
    "tenantDomains",
    "domainOwners",
    "tenantHostnames",
    "licenseSettings",
    "guestInvitations",
    "guestAccounts",
    "crossTenantAccess",
    "classificationSchemes",
    "clearances",
    "resourceLabels",
];

/// `createLifecycle(ctx)`: deployment operations.
pub struct Lifecycle {
    ctx: Arc<ServerContext>,
}

/// `createLifecycle(ctx)`.
pub fn create_lifecycle(ctx: &Arc<ServerContext>) -> Lifecycle {
    Lifecycle { ctx: ctx.clone() }
}

fn string(value: &Record, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn number(value: &Record, key: &str) -> f64 {
    value
        .get(key)
        .and_then(better_iam_core::js::as_number)
        .unwrap_or(f64::NAN)
}

impl Lifecycle {
    /// `initialize()`: migrations, plugin migrations, the `deletedAt` backfill of deleted tenants, and the one-time
    /// chaining of audit events recorded before the hash chain existed.
    pub async fn initialize(&self) -> IamResult<()> {
        let ctx = &self.ctx;
        let store = &ctx.store;
        store.migrate().await?;
        for plugin in &ctx.plugins {
            store
                .transaction(|tx| async move { plugin.migrate(tx.as_ref()).await })
                .await?;
        }
        // Tenants deleted before deletedAt existed start their retention window now.
        store
            .transaction(|tx| async move {
                for mut realm in tx
                    .find(
                        "tenants",
                        &Filter::new().eq("status", "deleted"),
                        &FindOptions::default(),
                    )
                    .await?
                {
                    if realm.get("deletedAt").and_then(Value::as_f64).is_none() {
                        realm.insert("deletedAt".into(), crate::js::number(date_now()));
                        tx.put("tenants", &realm).await?;
                    }
                }
                Ok(())
            })
            .await?;
        // Audit events recorded before the hash chain existed are chained once, in timestamp order per tenant, and only
        // in a tenant without a chain yet.
        store
            .transaction(|tx| async move {
                let loose: Vec<Record> = tx
                    .find(
                        "audit",
                        &Filter::new().absent("sequence"),
                        &FindOptions::default(),
                    )
                    .await?
                    .into_iter()
                    .filter(|event| event.get("sequence").and_then(Value::as_f64).is_none())
                    .collect();
                let mut chainless: indexmap::IndexSet<String> = indexmap::IndexSet::new();
                let tenants: indexmap::IndexSet<String> = loose
                    .iter()
                    .map(|event| string(event, "tenantId"))
                    .collect();
                for tenant_id in tenants {
                    if tx.get("auditChains", &tenant_id).await?.is_none() {
                        chainless.insert(tenant_id);
                    }
                }
                let mut pending: Vec<Record> = loose
                    .into_iter()
                    .filter(|event| chainless.contains(&string(event, "tenantId")))
                    .collect();
                pending.sort_by(|a, b| {
                    better_iam_core::js::cmp_utf16(&string(a, "tenantId"), &string(b, "tenantId"))
                        .then_with(|| {
                            (number(a, "timestamp") - number(b, "timestamp"))
                                .partial_cmp(&0.0)
                                .unwrap_or(std::cmp::Ordering::Equal)
                        })
                        .then_with(|| {
                            better_iam_core::js::cmp_utf16(&string(a, "id"), &string(b, "id"))
                        })
                });
                for event in pending {
                    let chained = chain_audit_event(tx.as_ref(), &event).await?;
                    tx.put("audit", &chained).await?;
                }
                Ok(())
            })
            .await
    }

    /// `bootstrap({ email, name, password, rootName?, slug? })`: creates the root tenant and its first root
    /// administrator. Fails with ALREADY_INITIALIZED (409) once a root exists.
    pub async fn bootstrap(&self, input: &Value) -> IamResult<Value> {
        let ctx = &self.ctx;
        ctx.store
            .transaction(|tx| async move {
                if !tx
                    .find(
                        "tenants",
                        &Filter::new().eq("parentId", Value::Null),
                        &FindOptions::default(),
                    )
                    .await?
                    .is_empty()
                {
                    return Err(IamError::with_status(
                        "ALREADY_INITIALIZED",
                        "Root already exists",
                        409,
                    ));
                }
                let realm_id = id();
                let mut realm = Map::new();
                realm.insert("id".into(), Value::String(realm_id.clone()));
                realm.insert("tenantId".into(), Value::String(realm_id.clone()));
                realm.insert("uniqueKey".into(), json!("installation-root"));
                realm.insert(
                    "name".into(),
                    input
                        .get("rootName")
                        .filter(|value| !value.is_null())
                        .cloned()
                        .unwrap_or(json!("Platform")),
                );
                realm.insert("type".into(), json!("root"));
                realm.insert("parentId".into(), Value::Null);
                realm.insert("status".into(), json!("active"));
                realm.insert("createdAt".into(), crate::js::number(date_now()));
                if let Some(slug) = input.get("slug") {
                    let claimed = ctx.claim_slug(&tx, &realm_id, Some(slug)).await?;
                    realm.insert("slug".into(), Value::String(claimed));
                }
                tx.insert("tenants", &realm).await?;
                let address = Value::String(email(input.get("email"))?);
                let name = Value::String(text(input.get("name"), "name", 256)?);
                let tenant_id = Value::String(realm_id.clone());
                let identity: Identity = ctx
                    .auth
                    .create_identity_raw(
                        &tx,
                        CreateIdentityRaw {
                            tenant_id: Some(&tenant_id),
                            email: Some(&address),
                            name: Some(&name),
                            password: input.get("password"),
                            owner: true,
                            root_admin: true,
                            email_verified: true,
                        },
                    )
                    .await?;
                let mut authority = Map::new();
                authority.insert("id".into(), Value::String(id()));
                authority.insert("tenantId".into(), Value::String(realm_id.clone()));
                authority.insert("identityId".into(), Value::String(identity.id.clone()));
                authority.insert("ceiling".into(), all_value());
                authority.insert("revoked".into(), Value::Bool(false));
                let authority: GrantAuthority =
                    decode(tx.insert("grantAuthorities", &authority).await?)?;
                let tenant: Tenant = decode(realm.clone())?;
                ctx.owner_setup(&tx, &tenant, &identity, &authority).await?;
                let mut event = Map::new();
                event.insert("id".into(), Value::String(id()));
                event.insert("tenantId".into(), Value::String(realm_id.clone()));
                event.insert("actorId".into(), json!("deployment-operator"));
                event.insert("action".into(), json!("root:bootstrap"));
                event.insert("resourceId".into(), Value::String(identity.id.clone()));
                event.insert("timestamp".into(), crate::js::number(date_now()));
                event.insert("outcome".into(), json!("allow"));
                ctx.events()?.record_audit(&tx, &event).await?;
                Ok(json!({
                    "tenant": Value::Object(realm),
                    "identity": Value::Object(public_identity(&identity)),
                    "mfaEnrollmentRequired": true,
                }))
            })
            .await
    }

    /// `recoverRoot({ email, name, password })`: adds a root administrator to an initialized platform.
    pub async fn recover_root(&self, input: &Value) -> IamResult<Value> {
        let ctx = &self.ctx;
        ctx.store
            .transaction(|tx| async move {
                let realm = tx
                    .find(
                        "tenants",
                        &Filter::new().eq("parentId", Value::Null),
                        &FindOptions::default(),
                    )
                    .await?
                    .into_iter()
                    .next();
                let Some(realm) = realm else {
                    return Err(IamError::new("NOT_INITIALIZED", "Bootstrap first"));
                };
                let realm_id = string(&realm, "id");
                let address = Value::String(email(input.get("email"))?);
                let name = Value::String(text(input.get("name"), "name", 256)?);
                let tenant_id = Value::String(realm_id.clone());
                let identity: Identity = ctx
                    .auth
                    .create_identity_raw(
                        &tx,
                        CreateIdentityRaw {
                            tenant_id: Some(&tenant_id),
                            email: Some(&address),
                            name: Some(&name),
                            password: input.get("password"),
                            owner: false,
                            root_admin: true,
                            email_verified: true,
                        },
                    )
                    .await?;
                let mut event = Map::new();
                event.insert("id".into(), Value::String(id()));
                event.insert("tenantId".into(), Value::String(realm_id.clone()));
                event.insert("actorId".into(), json!("deployment-operator"));
                event.insert("action".into(), json!("root:recover"));
                event.insert("resourceId".into(), Value::String(identity.id.clone()));
                event.insert("timestamp".into(), crate::js::number(date_now()));
                event.insert("outcome".into(), json!("allow"));
                ctx.events()?.record_audit(&tx, &event).await?;
                Ok(json!({
                    "identity": Value::Object(public_identity(&identity)),
                    "tenantId": realm_id,
                    "mfaEnrollmentRequired": true,
                }))
            })
            .await
    }

    /// `pruneAudit({ tenantId, retentionMs })`: deletes a tenant's oldest chained events (the longest prefix older
    /// than the cutoff) and appends an `audit:prune` checkpoint, so the remaining chain still verifies.
    pub async fn prune_audit(&self, input: &Value) -> IamResult<Value> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let retention_ms = integer(
            input.get("retentionMs"),
            "retentionMs",
            0.0,
            100.0 * 365.0 * 86_400_000.0,
        )?;
        let cutoff = date_now() - retention_ms;
        ctx.store
            .transaction(|tx| {
                let tenant_id = &tenant_id;
                async move {
                    let mut last: Option<Record> = None;
                    let mut deleted = 0.0;
                    let mut held = false;
                    // Once a tenant is being archived (a cursor exists), or wherever an archive is configured, only
                    // events the archive already holds may leave the database.
                    let cursor = tx.get("auditArchiveCursors", tenant_id).await?;
                    let archived_through =
                        if cursor.is_some() || ctx.options.audit_archive.is_some() {
                            cursor
                                .as_ref()
                                .and_then(|cursor| cursor.get("sequence"))
                                .and_then(Value::as_f64)
                                .unwrap_or(0.0)
                        } else {
                            f64::INFINITY
                        };
                    let mut from = 1.0;
                    let mut done = false;
                    while !done {
                        let order = OrderOptions {
                            from: Some(from),
                            limit: Some(1000),
                            ..OrderOptions::by("sequence")
                        };
                        let page = find_ordered(
                            tx.as_ref(),
                            "audit",
                            &Filter::new().eq("tenantId", tenant_id.clone()),
                            &order,
                            None,
                        )
                        .await?;
                        for event in &page {
                            if number(event, "timestamp") >= cutoff {
                                done = true;
                                break;
                            }
                            if number(event, "sequence") > archived_through {
                                held = true;
                                done = true;
                                break;
                            }
                            tx.delete("audit", &string(event, "id")).await?;
                            last = Some(event.clone());
                            deleted += 1.0;
                        }
                        if page.len() < 1000 {
                            done = true;
                        } else if let Some(tail) = page.last() {
                            from = number(tail, "sequence") + 1.0;
                        }
                    }
                    let Some(last) = last else {
                        let mut out = Map::new();
                        out.insert("deleted".into(), crate::js::number(0.0));
                        if held {
                            out.insert("heldForArchive".into(), Value::Bool(true));
                        }
                        return Ok(Value::Object(out));
                    };
                    let sequence = last.get("sequence").cloned().unwrap_or(Value::Null);
                    let hash = last.get("hash").cloned().unwrap_or(Value::Null);
                    let mut event = Map::new();
                    event.insert("id".into(), Value::String(id()));
                    event.insert("tenantId".into(), Value::String(tenant_id.clone()));
                    event.insert("actorId".into(), json!("deployment-operator"));
                    event.insert("action".into(), json!("audit:prune"));
                    event.insert("resourceId".into(), Value::String(tenant_id.clone()));
                    event.insert("timestamp".into(), crate::js::number(date_now()));
                    event.insert("outcome".into(), json!("allow"));
                    event.insert(
                        "metadata".into(),
                        json!({
                            "deleted": crate::js::number(deleted),
                            "before": crate::js::number(cutoff),
                            "prunedThroughSequence": sequence,
                            "prunedThroughHash": hash,
                        }),
                    );
                    ctx.events()?.record_audit(&tx, &event).await?;
                    let mut out = Map::new();
                    out.insert("deleted".into(), crate::js::number(deleted));
                    out.insert("prunedThroughSequence".into(), sequence);
                    out.insert("prunedThroughHash".into(), hash);
                    if held {
                        out.insert("heldForArchive".into(), Value::Bool(true));
                    }
                    Ok(Value::Object(out))
                }
            })
            .await
    }

    /// `sendAccessDigest(input?)`: emails each organization's owners its access report when there is something to
    /// report (a scheduler job).
    pub async fn send_access_digest(&self, _input: Option<&Value>) -> IamResult<Value> {
        Err(not_ported("lifecycle.ts sendAccessDigest"))
    }

    /// `sendExpiryReminders(input?)`: emails each person whose access ends soon a reminder listing it, once per item.
    pub async fn send_expiry_reminders(&self, _input: Option<&Value>) -> IamResult<Value> {
        Err(not_ported("lifecycle.ts sendExpiryReminders"))
    }

    /// `reconcilePackages(input?)`: assigns and removes rule-based (birthright) access packages (a scheduler job).
    pub async fn reconcile_packages(&self, _input: Option<&Value>) -> IamResult<Value> {
        Err(not_ported("lifecycle.ts reconcilePackages"))
    }

    /// `purgeDeleted({ retentionMs? })`: the retention worker (deleted tenants past retention, expired bindings,
    /// requests, identities, activations, memberships and assignments).
    pub async fn purge_deleted(&self, _input: Option<&Value>) -> IamResult<Value> {
        Err(not_ported("lifecycle.ts purgeDeleted"))
    }

    /// The conformance server's `call` for the lifecycle members of the instance.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        let first = args.first();
        Some(match method {
            "initialize" => self.initialize().await.map(|()| Value::Null),
            "bootstrap" => self.bootstrap(first.unwrap_or(&Value::Null)).await,
            "recoverRoot" => self.recover_root(first.unwrap_or(&Value::Null)).await,
            "pruneAudit" => self.prune_audit(first.unwrap_or(&Value::Null)).await,
            "sendAccessDigest" => self.send_access_digest(first).await,
            "sendExpiryReminders" => self.send_expiry_reminders(first).await,
            "reconcilePackages" => self.reconcile_packages(first).await,
            "purgeDeleted" => self.purge_deleted(first).await,
            _ => return None,
        })
    }
}
