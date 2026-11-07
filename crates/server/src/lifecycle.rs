//! Port of `packages/server/src/lifecycle.ts`: deployment operations (migrations, root bootstrap and recovery, audit
//! pruning, the access digest and expiry reminders, birthright reconciliation, and the retention worker). None are
//! HTTP endpoints.

use std::sync::Arc;

use better_iam_auth::outbox::EnqueueInput;
use better_iam_auth::service::base::CreateIdentityRaw;
use better_iam_core::{
    Filter, FindOptions, IamError, IamResult, IamStoreExt, Identity, OrderOptions, OutboxKind,
    Record, Tenant, TenantStatus, chain_audit_event, find_ordered,
};
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};

use crate::api::package_automation::reconcile_package_rules;
use crate::api::reports::{build_access_report, report_has_findings, report_windows};
use crate::context::{ServerContext, Store};
use crate::js::{defined, js_string, member, truthy};
use crate::models::{Binding, GrantAuthority, GroupMember, PackageAssignment};
use crate::port::decode;
use crate::utils::{all_value, date_now, id, public_identity};
use crate::validation::{email, integer, text};

const DAY: f64 = 86_400_000.0;

/// Rows deleted per transaction by the authentication bookkeeping sweep, so the write lock is never held for long.
const SWEEP_BATCH: usize = 500;

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
    "hostnameOwners",
    "analysisSuppressions",
    "certificationCampaigns",
    "certificationItems",
    "sodRules",
    "externalIdentities",
    "authMfa",
    "passwordHistory",
    "authChallenges",
    "authPasskeys",
    "authDevices",
    "authSignIns",
    "authBlocks",
    "authRateLimits",
    "outbox",
    "accessRequests",
    "bindingActivations",
    "webhooks",
    "relationships",
    "scimConnections",
    "scimUsers",
    "scimGroups",
    "oauthClients",
    "oauthArtifacts",
    "oauthGrantSessions",
    "oauthLoginStates",
    "oauthRegistrationTokens",
    "samlRequests",
    "samlRelays",
    "samlConnections",
    "samlAssertions",
    "provisioningTargets",
    "provisioningLinks",
    "provisioningGroupLinks",
    "ssfStreams",
    "ssfDeliveries",
    "accessUsage",
    "accessUsageTracking",
    "accessInvariants",
    "agreements",
    "agreementAcceptances",
    // Web identity federation: the tenant's OIDC providers and its redeemed-token replay records.
    "oidcProviders",
    "webIdentityReplays",
    // Feature flags the tenant defines, and the targets and overrides that apply to it.
    "featureFlags",
    "featureTargets",
    // Onboarding flows the tenant defines, its welcome settings, and progress of its people (or its own setup).
    "onboardingFlows",
    "onboardingSettings",
    "onboardingProgress",
    // Delegations people give AI agents (delegations.ts), and the confirmations they answer one action at a time.
    "delegations",
    "delegationConfirmations",
    "delegationTokens",
    // The latest attested A2A card of each agent, for the agent directory (a2a.ts, api/agents.ts).
    "agentCards",
    // Inference access control (inference.ts): providers, models, budgets, their counters, usage and gateway tickets.
    "inferenceProviders",
    "inferenceModels",
    "inferenceBudgets",
    "inferenceCounters",
    "inferenceUsage",
    "inferenceTickets",
    "inferenceResponses",
    // Teams (teams.ts) and departments (departments.ts).
    "teams",
    "teamMembers",
    "teamJoinRequests",
    "teamReviews",
    "teamReviewItems",
    "departments",
    "departmentMembers",
    // Billing (billing.ts): meters and prices, usage and its daily roll-ups, budgets and alerts, credits, the billing
    // profile, statements, and contract terms; invoice items, credit notes, plans (on the root), subscriptions,
    // coupons (on the root) and redeemed discounts.
    "billingMeters",
    "billingPrices",
    "billingUsage",
    "billingRollups",
    "billingBudgets",
    "billingBudgetAlerts",
    "billingCredits",
    "billingProfiles",
    "billingStatements",
    "billingTerms",
    "billingInvoiceItems",
    "billingCreditNotes",
    "billingPlans",
    "billingSubscriptions",
    "billingCoupons",
    "billingDiscounts",
    // Key management (kms.ts): keys, their sealed versions, aliases and grants.
    "kmsKeys",
    "kmsKeyVersions",
    "kmsAliases",
    "kmsGrants",
    // Private certificate authority (pki.ts): authorities and the certificates they issued.
    "pkiAuthorities",
    "pkiCertificates",
    // Data protection (tokenization.ts): tokenization profiles and the tokens they issued.
    "protectionProfiles",
    "protectionTokens",
    // Secrets vault (vault.ts): secrets, their sealed versions, check-outs and leases, access records.
    "vaultSecrets",
    "vaultVersions",
    "vaultLeases",
    "vaultAccess",
    // API usage plans and quotas (quotas.ts): plans, their assignments, and the window counters and throttle buckets.
    "quotaPlans",
    "quotaAssignments",
    "quotaCounters",
    // Privacy and consent (privacy.ts): purposes, current decisions and their history, data-subject requests and their
    // exports, legal holds, restrictions of processing, and the tenant's privacy settings.
    "privacyPurposes",
    "privacyConsents",
    "privacyConsentEvents",
    "privacyRequests",
    "privacyExports",
    "privacyHolds",
    "privacyRestrictions",
    "privacySettings",
    // Lifecycle workflows (workflows.ts): definitions, their runs, and the mover/leaver baselines.
    "workflows",
    "workflowRuns",
    "workflowSubjects",
    // Compliance center (compliance.ts): controls, exceptions, evaluation results and runs.
    "complianceControls",
    "complianceExceptions",
    "complianceResults",
    "complianceRuns",
    "complianceCheckpoints",
    // Application catalog (applications.ts): apps, their assignments, and each person's launches.
    "applications",
    "appAssignments",
    "appLaunches",
    // SSH certificate authority (ssh.ts): settings, authority keys, hosts, and issued certificates.
    "sshSettings",
    "sshAuthorities",
    "sshHosts",
    "sshCertificates",
    // Verifiable credentials (vc.ts): issuer keys, credential types, issued credentials, status lists, wallet offers and
    // proof nonces.
    "vcIssuerKeys",
    "vcCredentialTypes",
    "vcIssued",
    "vcStatusLists",
    "vcOffers",
    "vcNonces",
    // LDAP directory gateway (ldap.ts): the tenant's settings and its entry in the base DN index.
    "ldapSettings",
    "ldapBases",
    // Threat detection and response (threats.ts): detections, incidents and their notes, identity risk, sign-in
    // baselines, the audit-reading cursor, settings, playbooks, and the responses taken.
    "threatDetections",
    "threatIncidents",
    "threatNotes",
    "identityRisk",
    "threatBaselines",
    "threatCursors",
    "threatSettings",
    "threatPlaybooks",
    "threatResponses",
    // Device posture (devices.ts): registered devices, their keys (ids are global thumbprints; rows carry the tenant),
    // enrollment codes, integrations, and the tenant's compliance settings.
    "registeredDevices",
    "deviceKeys",
    "deviceEnrollments",
    "deviceIntegrations",
    "deviceSettings",
    // Shared Signals receiver (signal-receiver.ts): the tenant's transmitters and the security events they sent.
    "signalSources",
    "signalEvents",
    // License management (licenses.ts): the products the tenant defines, the pools it consumes, its assignments and
    // seats, and its settings.
    "licenseProducts",
    "licensePools",
    "licenseAssignments",
    "licenseSeats",
    "licenseSettings",
    // B2B guest collaboration (guests.ts): guest invitations, guest accounts, and the cross-tenant access settings.
    "guestInvitations",
    "guestAccounts",
    "crossTenantAccess",
    // Security clearances (clearances.ts): the classification scheme the tenant defines, its people's clearances, and
    // the classification labels of its resources (which outlive the resources).
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

fn send_email_configured(ctx: &ServerContext) -> bool {
    ctx.options
        .authentication
        .as_ref()
        .is_some_and(|authentication| authentication.send_email.is_some())
}

/// `input.tenantId ? [await ctx.tenant(tx, text(input.tenantId, 'tenantId'))] : active tenants by id`.
async fn selected_tenants(
    ctx: &ServerContext,
    tx: &Store,
    input: &Value,
) -> IamResult<Vec<Tenant>> {
    let requested = member(Some(input), "tenantId");
    if truthy(requested) {
        return Ok(vec![
            ctx.tenant(tx, &text(requested, "tenantId", 256)?).await?,
        ]);
    }
    let mut tenants: Vec<Tenant> = Vec::new();
    for record in tx
        .find(
            "tenants",
            &Filter::new().eq("status", "active"),
            &FindOptions::default(),
        )
        .await?
    {
        tenants.push(decode(record)?);
    }
    tenants.sort_by(|a, b| better_iam_core::js::cmp_utf16(&a.id, &b.id));
    Ok(tenants)
}

/// One item of an expiry reminder: its reminder key (`{kind}:{id}:{expiresAt}`), kind, display name and end.
struct ReminderItem {
    key: String,
    kind: &'static str,
    name: String,
    expires_at: f64,
}

impl ReminderItem {
    fn new(prefix: &str, id: &str, kind: &'static str, name: &str, expires_at: f64) -> Self {
        Self {
            key: format!(
                "{prefix}:{id}:{}",
                better_iam_core::js::number_to_string(expires_at)
            ),
            kind,
            name: name.to_owned(),
            expires_at,
        }
    }
}

/// `new Map(records.map((record) => [record.id, record.name]))`.
fn names(records: Vec<Record>) -> IndexMap<String, String> {
    records
        .iter()
        .map(|record| (string(record, "id"), string(record, "name")))
        .collect()
}

/// `sweepExpiredAuthRecords(ctx)`: authentication bookkeeping nothing else removes (rate-limit counters past their
/// window, challenges past their expiry, lapsed network blocks). Rows are listed once, then deleted in bounded
/// batches of short transactions; each row is re-read first, so a counter or a block renewed meanwhile survives.
async fn sweep_expired_auth_records(ctx: &ServerContext) -> IamResult<()> {
    let now = ctx.now();
    let ended = |row: &Record, field: &str| match row.get(field) {
        Some(Value::Number(value)) => better_iam_core::js::number_value(value) <= now,
        _ => false,
    };
    for (collection, field) in [
        ("authRateLimits", "resetAt"),
        ("authChallenges", "expiresAt"),
        ("authBlocks", "expiresAt"),
    ] {
        let ids: Vec<String> = ctx
            .store
            .find(collection, &Filter::new(), &FindOptions::default())
            .await?
            .iter()
            .filter(|row| ended(row, field))
            .map(|row| string(row, "id"))
            .collect();
        for batch in ids.chunks(SWEEP_BATCH) {
            ctx.store
                .transaction(|tx| async move {
                    for row_id in batch {
                        if let Some(row) = tx.get(collection, row_id).await?
                            && ended(&row, field)
                        {
                            tx.delete(collection, row_id).await?;
                        }
                    }
                    Ok(())
                })
                .await?;
        }
        // Cached block lists may still hold the removed rows; they no longer apply, but need not be kept.
        if collection == "authBlocks" && !ids.is_empty() {
            ctx.auth.invalidate_network_blocks();
        }
    }
    Ok(())
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
    ///
    /// Owners of every active tenant (or one `tenantId`) whose access report has findings get the `access-digest`
    /// template with the counts and the full report as JSON, at most once per `minimumIntervalMs` (20 hours by
    /// default) per tenant, recorded as `tenant:access-digest`. Requires an email delivery callback.
    pub async fn send_access_digest(&self, input: Option<&Value>) -> IamResult<Value> {
        let ctx = &self.ctx;
        let empty = Value::Object(Map::new());
        let input = input.unwrap_or(&empty);
        let windows = report_windows(input)?;
        let minimum_interval_default = crate::js::number(20.0 * 3_600_000.0);
        let minimum_interval_ms = integer(
            Some(
                defined(member(Some(input), "minimumIntervalMs"))
                    .unwrap_or(&minimum_interval_default),
            ),
            "minimumIntervalMs",
            0.0,
            365.0 * DAY,
        )?;
        if !send_email_configured(ctx) {
            return Err(IamError::new(
                "DELIVERY_REQUIRED",
                "The access digest requires an email delivery callback",
            ));
        }
        ctx.store
            .transaction(|tx| {
                let windows = &windows;
                async move {
                    let tenants = selected_tenants(ctx, &tx, input).await?;
                    let mut sent: Vec<Value> = Vec::new();
                    let (mut inactive, mut recent, mut quiet, mut no_owners) = (0.0, 0.0, 0.0, 0.0);
                    for tenant in tenants {
                        if tenant.status != TenantStatus::Active {
                            inactive += 1.0;
                            continue;
                        }
                        let since = ctx.now() - minimum_interval_ms;
                        let digested = tx
                            .find(
                                "audit",
                                &Filter::new()
                                    .eq("tenantId", tenant.id.clone())
                                    .eq("action", "tenant:access-digest"),
                                &FindOptions::default(),
                            )
                            .await?
                            .iter()
                            .any(|event| number(event, "timestamp") > since);
                        if digested {
                            recent += 1.0;
                            continue;
                        }
                        let report = build_access_report(
                            ctx,
                            &tx,
                            &tenant.id,
                            windows,
                            &json!({ "bindings": true, "credentials": true }),
                        )
                        .await?;
                        if !report_has_findings(&report)? {
                            quiet += 1.0;
                            continue;
                        }
                        let owners: Vec<String> = tx
                            .find(
                                "identities",
                                &Filter::new()
                                    .eq("tenantId", tenant.id.clone())
                                    .eq("owner", true)
                                    .eq("status", "active"),
                                &FindOptions::default(),
                            )
                            .await?
                            .iter()
                            .filter(|owner| truthy(owner.get("email")))
                            .map(|owner| string(owner, "email"))
                            .collect();
                        if owners.is_empty() {
                            no_owners += 1.0;
                            continue;
                        }
                        let length = |value: Option<&Value>| {
                            value
                                .and_then(Value::as_array)
                                .map_or(0.0, |items| items.len() as f64)
                        };
                        let bindings = report.get("bindings").filter(|value| !value.is_null());
                        let credentials =
                            report.get("credentials").filter(|value| !value.is_null());
                        let counts: Vec<(&str, f64)> = vec![
                            (
                                "expiringIdentities",
                                length(member(report.get("identities"), "expiring")),
                            ),
                            ("expiringBindings", length(member(bindings, "expiring"))),
                            ("startingBindings", length(member(bindings, "starting"))),
                            (
                                "expiringMemberships",
                                length(member(bindings, "expiringMemberships")),
                            ),
                            ("activations", length(member(bindings, "activations"))),
                            (
                                "pendingRequests",
                                defined(member(bindings, "pendingRequests"))
                                    .and_then(better_iam_core::js::as_number)
                                    .unwrap_or(0.0),
                            ),
                            ("unusedKeys", length(member(credentials, "unused"))),
                            ("expiringKeys", length(member(credentials, "expiring"))),
                        ];
                        let mut payload = Map::new();
                        payload.insert("tenantId".into(), Value::String(tenant.id.clone()));
                        payload.insert("tenantName".into(), Value::String(tenant.name.clone()));
                        payload.insert(
                            "generatedAt".into(),
                            Value::String(js_string(report.get("generatedAt"))),
                        );
                        payload.insert(
                            "withinMs".into(),
                            Value::String(js_string(windows.get("withinMs"))),
                        );
                        payload.insert(
                            "unusedForMs".into(),
                            Value::String(js_string(windows.get("unusedForMs"))),
                        );
                        for (key, value) in &counts {
                            payload.insert(
                                (*key).into(),
                                Value::String(better_iam_core::js::number_to_string(*value)),
                            );
                        }
                        payload.insert(
                            "report".into(),
                            Value::String(better_iam_core::js::stringify(&report)),
                        );
                        for owner in &owners {
                            ctx.auth
                                .enqueue_delivery(
                                    &tx,
                                    EnqueueInput {
                                        tenant_id: tenant.id.clone(),
                                        kind: OutboxKind::Email,
                                        to: owner.clone(),
                                        template: "access-digest".into(),
                                        payload: payload.clone(),
                                        reference: None,
                                    },
                                )
                                .await?;
                        }
                        let mut metadata = Map::new();
                        metadata
                            .insert("recipients".into(), crate::js::number(owners.len() as f64));
                        for (key, value) in &counts {
                            metadata.insert((*key).into(), crate::js::number(*value));
                        }
                        let mut event = Map::new();
                        event.insert("id".into(), Value::String(id()));
                        event.insert("tenantId".into(), Value::String(tenant.id.clone()));
                        event.insert("actorId".into(), json!("deployment-operator"));
                        event.insert("action".into(), json!("tenant:access-digest"));
                        event.insert("resourceId".into(), Value::String(tenant.id.clone()));
                        event.insert("timestamp".into(), crate::js::number(ctx.now()));
                        event.insert("outcome".into(), json!("allow"));
                        event.insert("metadata".into(), Value::Object(metadata.clone()));
                        ctx.events()?.record_audit(&tx, &event).await?;
                        let mut entry = Map::new();
                        entry.insert("tenantId".into(), Value::String(tenant.id.clone()));
                        for (key, value) in metadata {
                            entry.insert(key, value);
                        }
                        sent.push(Value::Object(entry));
                    }
                    Ok(json!({
                        "sent": sent,
                        "skipped": {
                            "inactive": crate::js::number(inactive),
                            "recent": crate::js::number(recent),
                            "quiet": crate::js::number(quiet),
                            "noOwners": crate::js::number(no_owners),
                        },
                    }))
                }
            })
            .await
    }

    /// `sendExpiryReminders(input?)`: emails each person whose access ends soon a reminder listing it, once per item.
    ///
    /// Accounts, direct role bindings, group memberships, and package assignments ending within `withinMs` (seven days
    /// by default) are listed in one `expiry-reminder` message per person, once per item and end date, recorded as
    /// `identity:expiry-reminder`. Requires an email delivery callback.
    pub async fn send_expiry_reminders(&self, input: Option<&Value>) -> IamResult<Value> {
        let ctx = &self.ctx;
        let empty = Value::Object(Map::new());
        let input = input.unwrap_or(&empty);
        let within_default = crate::js::number(7.0 * DAY);
        let within_ms = integer(
            Some(defined(member(Some(input), "withinMs")).unwrap_or(&within_default)),
            "withinMs",
            60_000.0,
            365.0 * DAY,
        )?;
        if !send_email_configured(ctx) {
            return Err(IamError::new(
                "DELIVERY_REQUIRED",
                "Expiry reminders require an email delivery callback",
            ));
        }
        ctx.store
            .transaction(|tx| async move {
                let tenants = selected_tenants(ctx, &tx, input).await?;
                let mut sent: Vec<Value> = Vec::new();
                let (mut inactive, mut quiet) = (0.0, 0.0);
                let all = FindOptions::default;
                for tenant in tenants {
                    if tenant.status != TenantStatus::Active {
                        inactive += 1.0;
                        continue;
                    }
                    let of_tenant = || Filter::new().eq("tenantId", tenant.id.clone());
                    let now = ctx.now();
                    let horizon = now + within_ms;
                    let ending = |expires_at: Option<f64>| -> Option<f64> {
                        expires_at.filter(|at| *at > now && *at <= horizon)
                    };
                    // What was already reminded: marks kept until the item ends (they survive audit pruning), plus
                    // the audit trail of runs made before marks existed.
                    let mut reminded: IndexSet<String> = IndexSet::new();
                    for mark in tx.find("expiryReminderMarks", &of_tenant(), &all()).await? {
                        reminded.insert(string(&mark, "uniqueKey"));
                    }
                    for event in tx
                        .find(
                            "audit",
                            &of_tenant().eq("action", "identity:expiry-reminder"),
                            &all(),
                        )
                        .await?
                    {
                        if let Some(Value::Array(keys)) = member(event.get("metadata"), "items") {
                            for key in keys {
                                if let Value::String(key) = key {
                                    reminded.insert(key.clone());
                                }
                            }
                        }
                    }
                    let mut assignments: Vec<PackageAssignment> = Vec::new();
                    for record in tx.find("packageAssignments", &of_tenant(), &all()).await? {
                        assignments.push(decode(record)?);
                    }
                    // A package's own bindings and memberships are reminded as the package, while it still exists.
                    let assignment_ids: IndexSet<String> =
                        assignments.iter().map(|assignment| assignment.id.clone()).collect();
                    let packaged = |assignment_id: &Option<String>| {
                        assignment_id
                            .as_ref()
                            .is_some_and(|assignment_id| assignment_ids.contains(assignment_id))
                    };
                    let mut items: IndexMap<String, Vec<ReminderItem>> = IndexMap::new();
                    let mut add = |identity_id: &str, item: ReminderItem| {
                        if reminded.contains(&item.key) {
                            return;
                        }
                        items.entry(identity_id.to_owned()).or_default().push(item);
                    };
                    let mut identities: Vec<Identity> = Vec::new();
                    for record in tx
                        .find("identities", &of_tenant().eq("status", "active"), &all())
                        .await?
                    {
                        identities.push(decode(record)?);
                    }
                    for identity in &identities {
                        if let Some(expires_at) = ending(identity.expires_at) {
                            add(
                                &identity.id,
                                ReminderItem::new("identity", &identity.id, "account", &identity.name, expires_at),
                            );
                        }
                    }
                    let roles = names(tx.find("roles", &of_tenant(), &all()).await?);
                    for record in tx
                        .find("bindings", &of_tenant().eq("subjectType", "identity"), &all())
                        .await?
                    {
                        let binding: Binding = decode(record)?;
                        if let Some(expires_at) = ending(binding.expires_at)
                            && ctx.live_binding(&binding)
                            && binding.eligible != Some(true)
                            && !packaged(&binding.package_assignment_id)
                        {
                            let name = roles
                                .get(&binding.role_id)
                                .cloned()
                                .unwrap_or_else(|| binding.role_id.clone());
                            add(
                                &binding.subject_id,
                                ReminderItem::new("binding", &binding.id, "role", &name, expires_at),
                            );
                        }
                    }
                    let groups = names(tx.find("groups", &of_tenant(), &all()).await?);
                    for record in tx.find("groupMembers", &of_tenant(), &all()).await? {
                        let member: GroupMember = decode(record)?;
                        if let Some(expires_at) = ending(member.expires_at)
                            && ctx.live_membership(&member)
                            && !packaged(&member.package_assignment_id)
                        {
                            let name = groups
                                .get(&member.group_id)
                                .cloned()
                                .unwrap_or_else(|| member.group_id.clone());
                            add(
                                &member.identity_id,
                                ReminderItem::new("membership", &member.id, "group", &name, expires_at),
                            );
                        }
                    }
                    let packages = names(tx.find("accessPackages", &of_tenant(), &all()).await?);
                    for assignment in &assignments {
                        if let Some(expires_at) = ending(assignment.expires_at) {
                            let name = packages
                                .get(&assignment.package_id)
                                .cloned()
                                .unwrap_or_else(|| assignment.package_id.clone());
                            add(
                                &assignment.identity_id,
                                ReminderItem::new("package", &assignment.id, "package", &name, expires_at),
                            );
                        }
                    }
                    let mut any = false;
                    let mut people: Vec<(String, Vec<ReminderItem>)> = items.into_iter().collect();
                    people.sort_by(|(a, _), (b, _)| better_iam_core::js::cmp_utf16(a, b));
                    for (identity_id, mut list) in people {
                        let Some(identity) = identities.iter().find(|identity| identity.id == identity_id)
                        else {
                            continue;
                        };
                        let Some(address) = identity.email.clone().filter(|email| !email.is_empty())
                        else {
                            continue;
                        };
                        list.sort_by(|a, b| {
                            a.expires_at
                                .partial_cmp(&b.expires_at)
                                .unwrap_or(std::cmp::Ordering::Equal)
                        });
                        let earliest = list[0].expires_at;
                        let listed: Vec<Value> = list
                            .iter()
                            .map(|item| {
                                json!({
                                    "kind": item.kind,
                                    "name": item.name,
                                    "expiresAt": crate::js::number(item.expires_at),
                                })
                            })
                            .collect();
                        let mut payload = Map::new();
                        payload.insert("tenantId".into(), Value::String(tenant.id.clone()));
                        payload.insert("tenantName".into(), Value::String(tenant.name.clone()));
                        payload.insert("identityName".into(), Value::String(identity.name.clone()));
                        payload.insert(
                            "count".into(),
                            Value::String(better_iam_core::js::number_to_string(list.len() as f64)),
                        );
                        payload.insert(
                            "earliest".into(),
                            Value::String(better_iam_core::js::number_to_string(earliest)),
                        );
                        payload.insert(
                            "items".into(),
                            Value::String(better_iam_core::js::stringify(&Value::Array(listed))),
                        );
                        ctx.auth
                            .enqueue_delivery(
                                &tx,
                                EnqueueInput {
                                    tenant_id: tenant.id.clone(),
                                    kind: OutboxKind::Email,
                                    to: address,
                                    template: "expiry-reminder".into(),
                                    payload,
                                    reference: None,
                                },
                            )
                            .await?;
                        let mut event = Map::new();
                        event.insert("id".into(), Value::String(id()));
                        event.insert("tenantId".into(), Value::String(tenant.id.clone()));
                        event.insert("actorId".into(), json!("deployment-operator"));
                        event.insert("action".into(), json!("identity:expiry-reminder"));
                        event.insert("resourceId".into(), Value::String(identity.id.clone()));
                        event.insert("timestamp".into(), crate::js::number(now));
                        event.insert("outcome".into(), json!("allow"));
                        event.insert(
                            "metadata".into(),
                            json!({
                                "count": crate::js::number(list.len() as f64),
                                "earliest": crate::js::number(earliest),
                                "items": list.iter().map(|item| item.key.clone()).collect::<Vec<_>>(),
                            }),
                        );
                        ctx.events()?.record_audit(&tx, &event).await?;
                        for item in &list {
                            let mut mark = Map::new();
                            mark.insert("id".into(), Value::String(id()));
                            mark.insert("tenantId".into(), Value::String(tenant.id.clone()));
                            mark.insert("uniqueKey".into(), Value::String(item.key.clone()));
                            mark.insert("identityId".into(), Value::String(identity_id.clone()));
                            mark.insert("expiresAt".into(), crate::js::number(item.expires_at));
                            tx.insert("expiryReminderMarks", &mark).await?;
                        }
                        sent.push(json!({
                            "tenantId": tenant.id,
                            "identityId": identity_id,
                            "items": crate::js::number(list.len() as f64),
                        }));
                        any = true;
                    }
                    if !any {
                        quiet += 1.0;
                    }
                }
                Ok(json!({
                    "sent": sent,
                    "skipped": {
                        "inactive": crate::js::number(inactive),
                        "quiet": crate::js::number(quiet),
                    },
                }))
            })
            .await
    }

    /// `reconcilePackages(input?)`: assigns and removes rule-based (birthright) access packages (a scheduler job).
    ///
    /// Applies every access-package rule (or one tenant's, or one package's) under its owner's grant authority. At
    /// most `limit` changes per organization (1000); unusually large changes are held back unless `confirm` (with
    /// `packageId`).
    pub async fn reconcile_packages(&self, input: Option<&Value>) -> IamResult<Value> {
        let tenant_id = match member(input, "tenantId") {
            Some(value) => Some(text(Some(value), "tenantId", 256)?),
            None => None,
        };
        let package_id = match member(input, "packageId") {
            Some(value) => Some(text(Some(value), "packageId", 256)?),
            None => None,
        };
        if package_id.is_some() && tenant_id.is_none() {
            return Err(crate::js::invalid_input("packageId needs tenantId"));
        }
        let confirm = member(input, "confirm");
        if confirm.is_some_and(|confirm| !confirm.is_boolean()) {
            return Err(crate::js::invalid_input("confirm must be boolean"));
        }
        let confirmed = confirm == Some(&Value::Bool(true));
        if confirmed && package_id.is_none() {
            return Err(crate::js::invalid_input("confirm needs packageId"));
        }
        let limit_default = crate::js::number(1000.0);
        let limit = integer(
            Some(defined(member(input, "limit")).unwrap_or(&limit_default)),
            "limit",
            1.0,
            10_000.0,
        )?;
        let mut options = Map::new();
        if let Some(tenant_id) = tenant_id {
            options.insert("tenantId".into(), Value::String(tenant_id));
        }
        if let Some(package_id) = package_id {
            options.insert("packageId".into(), Value::String(package_id));
        }
        options.insert("limit".into(), crate::js::number(limit));
        options.insert("trigger".into(), json!("schedule"));
        if confirmed {
            options.insert("confirmedBy".into(), json!("deployment-operator"));
        }
        let result = reconcile_package_rules(&self.ctx, &Value::Object(options)).await?;
        serde_json::to_value(result).map_err(|_| crate::js::internal_error())
    }

    /// `purgeDeleted({ retentionMs? })`: the retention worker (deleted tenants past retention, expired bindings,
    /// requests, identities, activations, memberships and assignments).
    ///
    /// Audit records are preserved. It also deletes authentication bookkeeping past its end in every tenant: rate-limit
    /// counters past their window, challenges past their expiry, and lapsed network blocks.
    pub async fn purge_deleted(&self, input: Option<&Value>) -> IamResult<Value> {
        let ctx = &self.ctx;
        let retention_default = crate::js::number(2_592_000_000.0);
        let retention_ms = integer(
            Some(defined(member(input, "retentionMs")).unwrap_or(&retention_default)),
            "retentionMs",
            0.0,
            315_360_000_000.0,
        )?;
        let cutoff = date_now() - retention_ms;
        sweep_expired_auth_records(ctx).await?;
        ctx.store
            .transaction(|tx| async move {
                let all = FindOptions::default;
                let mut expired_bindings = 0.0;
                let mut expired_requests = 0.0;
                let mut expired_identities = 0.0;
                let mut expired_activations = 0.0;
                let mut expired_memberships = 0.0;
                let mut expired_assignments = 0.0;
                for record in tx.find("bindings", &Filter::new(), &all()).await? {
                    let binding: Binding = decode(record)?;
                    if ctx.expired_binding(&binding) {
                        // Activations of a binding that is gone could never grant again.
                        for activation in tx
                            .find(
                                "bindingActivations",
                                &Filter::new()
                                    .eq("tenantId", binding.tenant_id.clone())
                                    .eq("bindingId", binding.id.clone()),
                                &all(),
                            )
                            .await?
                        {
                            tx.delete("bindingActivations", &string(&activation, "id"))
                                .await?;
                            expired_activations += 1.0;
                        }
                        tx.delete("bindings", &binding.id).await?;
                        expired_bindings += 1.0;
                    }
                }
                for activation in tx
                    .find("bindingActivations", &Filter::new(), &all())
                    .await?
                {
                    if number(&activation, "expiresAt") <= ctx.now() {
                        tx.delete("bindingActivations", &string(&activation, "id"))
                            .await?;
                        expired_activations += 1.0;
                    }
                }
                // A lapsed membership ends the person's activations of that group's eligible bindings too.
                for record in tx.find("groupMembers", &Filter::new(), &all()).await? {
                    let member: GroupMember = decode(record)?;
                    if !ctx.live_membership(&member) {
                        for binding in tx
                            .find(
                                "bindings",
                                &Filter::new()
                                    .eq("tenantId", member.tenant_id.clone())
                                    .eq("subjectType", "group")
                                    .eq("subjectId", member.group_id.clone()),
                                &all(),
                            )
                            .await?
                        {
                            for activation in tx
                                .find(
                                    "bindingActivations",
                                    &Filter::new()
                                        .eq("tenantId", member.tenant_id.clone())
                                        .eq("bindingId", string(&binding, "id"))
                                        .eq("identityId", member.identity_id.clone()),
                                    &all(),
                                )
                                .await?
                            {
                                tx.delete("bindingActivations", &string(&activation, "id"))
                                    .await?;
                            }
                        }
                        tx.delete("groupMembers", &member.id).await?;
                        expired_memberships += 1.0;
                    }
                }
                for assignment in tx
                    .find("packageAssignments", &Filter::new(), &all())
                    .await?
                {
                    if assignment
                        .get("expiresAt")
                        .and_then(better_iam_core::js::as_number)
                        .is_some_and(|expires_at| expires_at <= ctx.now())
                    {
                        tx.delete("packageAssignments", &string(&assignment, "id"))
                            .await?;
                        expired_assignments += 1.0;
                    }
                }
                for collection in ["accessRequests", "packageRequests"] {
                    for mut request in tx
                        .find(collection, &Filter::new().eq("status", "pending"), &all())
                        .await?
                    {
                        if number(&request, "expiresAt") <= ctx.now() {
                            request.insert("status".into(), json!("expired"));
                            tx.put(collection, &request).await?;
                            expired_requests += 1.0;
                        }
                    }
                }
                // Reminder marks are only needed until the item they remember has ended.
                for mark in tx
                    .find("expiryReminderMarks", &Filter::new(), &all())
                    .await?
                {
                    if number(&mark, "expiresAt") <= ctx.now() {
                        tx.delete("expiryReminderMarks", &string(&mark, "id"))
                            .await?;
                    }
                }
                for record in tx
                    .find("identities", &Filter::new().eq("status", "active"), &all())
                    .await?
                {
                    let identity: Identity = decode(record.clone())?;
                    if ctx.identity_expired(&identity) {
                        let mut disabled = record;
                        disabled.insert("status".into(), json!("disabled"));
                        tx.put("identities", &disabled).await?;
                        ctx.revoke_all(&tx, &identity.id).await?;
                        for activation in tx
                            .find(
                                "bindingActivations",
                                &Filter::new()
                                    .eq("tenantId", identity.tenant_id.clone())
                                    .eq("identityId", identity.id.clone()),
                                &all(),
                            )
                            .await?
                        {
                            tx.delete("bindingActivations", &string(&activation, "id"))
                                .await?;
                            expired_activations += 1.0;
                        }
                        let mut event = Map::new();
                        event.insert("id".into(), Value::String(id()));
                        event.insert("tenantId".into(), Value::String(identity.tenant_id.clone()));
                        event.insert("actorId".into(), json!("deployment-operator"));
                        event.insert("action".into(), json!("identity:expire"));
                        event.insert("resourceId".into(), Value::String(identity.id.clone()));
                        event.insert("timestamp".into(), crate::js::number(date_now()));
                        event.insert("outcome".into(), json!("allow"));
                        event.insert(
                            "metadata".into(),
                            json!({
                                "kind": serde_json::to_value(identity.kind).unwrap_or(Value::Null),
                                "expiresAt": identity.expires_at.map_or(Value::Null, crate::js::number),
                            }),
                        );
                        ctx.events()?.record_audit(&tx, &event).await?;
                        expired_identities += 1.0;
                    }
                }
                let counts = |purged: Vec<String>, deleted_records: f64| {
                    json!({
                        "purgedTenants": purged,
                        "deletedRecords": crate::js::number(deleted_records),
                        "expiredBindings": crate::js::number(expired_bindings),
                        "expiredRequests": crate::js::number(expired_requests),
                        "expiredIdentities": crate::js::number(expired_identities),
                        "expiredActivations": crate::js::number(expired_activations),
                        "expiredMemberships": crate::js::number(expired_memberships),
                        "expiredAssignments": crate::js::number(expired_assignments),
                    })
                };
                let realms = tx.find("tenants", &Filter::new(), &all()).await?;
                let roots: Vec<&Record> = realms
                    .iter()
                    .filter(|realm| {
                        realm.get("status").and_then(Value::as_str) == Some("deleted")
                            && realm
                                .get("deletedAt")
                                .and_then(better_iam_core::js::as_number)
                                .is_some_and(|deleted_at| deleted_at <= cutoff)
                    })
                    .collect();
                if roots.is_empty() {
                    return Ok(counts(Vec::new(), 0.0));
                }
                let subtree = |root: &str| {
                    let mut below: IndexSet<String> = IndexSet::new();
                    below.insert(root.to_owned());
                    let mut depth = 0.0;
                    while depth < ctx.config.max_depth {
                        for realm in &realms {
                            let parent = string(realm, "parentId");
                            if !parent.is_empty() && below.contains(&parent) {
                                below.insert(string(realm, "id"));
                            }
                        }
                        depth += 1.0;
                    }
                    below
                };
                let mut purged: IndexSet<String> =
                    roots.iter().map(|root| string(root, "id")).collect();
                let mut depth = 0.0;
                while depth < ctx.config.max_depth {
                    for realm in &realms {
                        let parent = string(realm, "parentId");
                        if !parent.is_empty() && purged.contains(&parent) {
                            purged.insert(string(realm, "id"));
                        }
                    }
                    depth += 1.0;
                }
                let mut identities: IndexSet<String> = IndexSet::new();
                for tenant_id in &purged {
                    for identity in tx
                        .find("identities", &Filter::new().eq("tenantId", tenant_id.clone()), &all())
                        .await?
                    {
                        identities.insert(string(&identity, "id"));
                    }
                }
                let mut deleted_records = 0.0;
                for tenant_id in &purged {
                    for collection in TENANT_COLLECTIONS {
                        for row in tx
                            .find(collection, &Filter::new().eq("tenantId", tenant_id.clone()), &all())
                            .await?
                        {
                            tx.delete(collection, &string(&row, "id")).await?;
                            deleted_records += 1.0;
                        }
                    }
                }
                // Records in surviving tenants that reference purged tenants or identities become dead references.
                for session in tx.find("sessions", &Filter::new(), &all()).await? {
                    let source = string(&session, "sourceTenantId");
                    if !source.is_empty() && purged.contains(&source) {
                        tx.delete("sessions", &string(&session, "id")).await?;
                        deleted_records += 1.0;
                    }
                }
                for trust in tx.find("trusts", &Filter::new(), &all()).await? {
                    if purged.contains(&string(&trust, "sourceTenantId")) {
                        tx.delete("trusts", &string(&trust, "id")).await?;
                        deleted_records += 1.0;
                    }
                }
                for link in tx.find("identityLinks", &Filter::new(), &all()).await? {
                    if identities.contains(&string(&link, "leftId"))
                        || identities.contains(&string(&link, "rightId"))
                    {
                        tx.delete("identityLinks", &string(&link, "id")).await?;
                        deleted_records += 1.0;
                    }
                }
                for artifact in tx.find("oauthArtifacts", &Filter::new(), &all()).await? {
                    if let Some(Value::String(account)) = artifact.get("accountId")
                        && identities.contains(account)
                    {
                        tx.delete("oauthArtifacts", &string(&artifact, "id")).await?;
                        deleted_records += 1.0;
                    }
                }
                let purged_list: Vec<String> = purged.iter().cloned().collect();
                for plugin in &ctx.plugins {
                    plugin.purge(tx.as_ref(), &purged_list).await?;
                }
                // Audit records survive the purge so the deletion trail remains queryable.
                for root in &roots {
                    let root_id = string(root, "id");
                    let tenant_ids: Vec<String> = subtree(&root_id).into_iter().collect();
                    let mut event = Map::new();
                    event.insert("id".into(), Value::String(id()));
                    event.insert("tenantId".into(), Value::String(root_id.clone()));
                    event.insert("actorId".into(), json!("deployment-operator"));
                    event.insert("action".into(), json!("tenants:purge"));
                    event.insert("resourceId".into(), Value::String(root_id));
                    event.insert("timestamp".into(), crate::js::number(date_now()));
                    event.insert("outcome".into(), json!("allow"));
                    event.insert(
                        "metadata".into(),
                        json!({
                            "tenantIds": tenant_ids,
                            "deletedRecords": crate::js::number(deleted_records),
                        }),
                    );
                    ctx.events()?.record_audit(&tx, &event).await?;
                }
                let mut sorted = purged_list;
                crate::js::sort_strings(&mut sorted);
                Ok(counts(sorted, deleted_records))
            })
            .await
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
