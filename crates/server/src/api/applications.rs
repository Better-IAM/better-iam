//! Port of `packages/server/src/api/applications.ts`: the application catalog and the "My apps" launcher.
//!
//! Administrators register apps (an OAuth client of this deployment, or a link to any tool) and assign them to people
//! and groups (`iam:applications:manage`, `iam:applications:assign`, reading `iam:applications:read`); people see and
//! launch their apps, and request the ones they lack, without a permission. For an OpenID Connect app the OAuth
//! provider enforces the assignment (`iam.protocolHost.clientAllowed`); `check` (and `iam.applications.allowed`)
//! answers the same question for other sign-in pages. People's names and addresses appear only for callers who may
//! read the directory.

use std::cmp::Ordering;
use std::sync::Arc;

use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, IamError, IamResult,
    IamStoreExt, IdentityKind, Record, SessionKind, js as core_js,
};
use better_iam_types::api::applications;
use indexmap::IndexMap;
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply, string_member};
use crate::applications::{
    app_access, app_holders, app_key, app_url, apps_for, find_records, local_deployment,
    member_str, member_string,
};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::js::{js_string, number, truthy};
use crate::metrics::locale_compare;
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::session_kinds::acts_in_own_right;
use crate::utils::id;
use crate::validation::{integer, strings, text};

const MAX_APPS: usize = 500;
const MAX_ASSIGNMENTS_PER_APP: usize = 10_000;
const DAY: f64 = 86_400_000.0;

fn name_text(value: Option<&Value>, name: &str, max: usize) -> IamResult<String> {
    Ok(core_js::trim(&text(value, name, max)?).to_owned())
}

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

/// `value ?? undefined`: None for undefined and null.
fn nullish_free(value: Option<&Value>) -> Option<&Value> {
    value.filter(|value| !value.is_null())
}

/// `value === null || value === ''`.
fn null_or_empty(value: &Value) -> bool {
    value.is_null() || value.as_str() == Some("")
}

fn self_session(principal: &AuthenticatedPrincipal, tenant_id: &str) -> IamResult<()> {
    if !acts_in_own_right(principal.session.kind)
        || principal.session.kind != SessionKind::User
        || principal.session.tenant_id != tenant_id
        || principal.identity.tenant_id != tenant_id
        || principal.identity.kind != IdentityKind::User
    {
        return Err(IamError::with_status(
            "ACCESS_DENIED",
            "The launcher is for people signed in to their organization",
            403,
        ));
    }
    Ok(())
}

/// `optional(value, prior, name, max)` of `appFields`: an optional text member that `null` or `''` clears.
fn optional_text(
    value: Option<&Value>,
    prior: Option<&str>,
    name: &str,
    max: usize,
) -> IamResult<Option<String>> {
    Ok(match value {
        None => prior.map(str::to_owned),
        Some(value) if null_or_empty(value) => None,
        Some(value) => Some(name_text(Some(value), name, max)?),
    })
}

/// The validated members of an app (`appFields`), in the TypeScript member order.
async fn app_fields(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    input: &Map<String, Value>,
    previous: Option<&Record>,
) -> IamResult<Record> {
    let key = match previous {
        Some(previous) => member_string(previous, "key"),
        None => app_key(input.get("key"))?,
    };
    if let Some(previous) = previous
        && input.get("key").is_some()
        && input.get("key") != previous.get("key")
    {
        return Err(invalid("An app key cannot change"));
    }
    let allow_local = local_deployment(Some(&ctx.options.base_url))?;
    let previous_str = |key: &str| previous.and_then(|previous| member_str(previous, key));
    let oauth_client_id = match input.get("oauthClientId") {
        None => previous_str("oauthClientId").map(str::to_owned),
        Some(value) if null_or_empty(value) => None,
        Some(value) => Some(text(Some(value), "oauthClientId", 256)?),
    };
    if let Some(client_id) = &oauth_client_id
        && Some(client_id.as_str()) != previous_str("oauthClientId")
    {
        let client = find_records(
            tx,
            "oauthClients",
            Filter::new()
                .eq("tenantId", tenant_id)
                .eq("clientId", client_id.clone()),
        )
        .await?
        .into_iter()
        .next();
        if client.is_none_or(|client| client.get("revoked") == Some(&Value::Bool(true))) {
            return Err(invalid(
                "oauthClientId must name an OAuth client of this organization",
            ));
        }
        // One app per client: two would make whether someone may sign in depend on which one is found first.
        let previous_id = previous.and_then(|previous| previous.get("id"));
        let other = find_records(tx, "applications", Filter::new().eq("tenantId", tenant_id))
            .await?
            .into_iter()
            .find(|app| {
                member_str(app, "oauthClientId") == Some(client_id.as_str())
                    && app.get("id") != previous_id
            });
        if let Some(other) = other {
            return Err(IamError::with_status(
                "CONFLICT",
                format!(
                    "App {} already governs this OAuth client",
                    js_string(other.get("key"))
                ),
                409,
            ));
        }
    }
    let request_package_id = match input.get("requestPackageId") {
        None => previous_str("requestPackageId").map(str::to_owned),
        Some(value) if null_or_empty(value) => None,
        Some(value) => Some(text(Some(value), "requestPackageId", 256)?),
    };
    if let Some(package_id) = &request_package_id
        && Some(package_id.as_str()) != previous_str("requestPackageId")
    {
        let package = ctx
            .scoped(
                tx,
                "accessPackages",
                Some(&Value::String(package_id.clone())),
                tenant_id,
            )
            .await?;
        if !truthy(package.get("requestable")) {
            return Err(invalid(
                "requestPackageId must name a package members may request",
            ));
        }
    }
    // Owners are checked when they are set; an owner deleted later never blocks editing (or disabling) the app.
    let mut owner_ids = previous
        .and_then(|previous| nullish_free(previous.get("ownerIds")))
        .cloned()
        .unwrap_or_else(|| json!([]));
    if let Some(value) = input.get("ownerIds") {
        let owners = crate::js::unique(strings(Some(value), "ownerIds")?);
        if owners.len() > 20 {
            return Err(invalid("At most 20 owners"));
        }
        for owner_id in &owners {
            ctx.active_identity(tx, owner_id, tenant_id).await?;
        }
        owner_ids = json!(owners);
    }
    let visibility = nullish_free(input.get("visibility"))
        .or_else(|| previous.and_then(|previous| nullish_free(previous.get("visibility"))))
        .cloned()
        .unwrap_or_else(|| json!("assigned"));
    if visibility != json!("everyone") && visibility != json!("assigned") {
        return Err(invalid("visibility must be 'everyone' or 'assigned'"));
    }
    let enabled = nullish_free(input.get("enabled"))
        .or_else(|| previous.and_then(|previous| nullish_free(previous.get("enabled"))))
        .cloned()
        .unwrap_or(Value::Bool(true));
    if !enabled.is_boolean() {
        return Err(invalid("enabled must be a boolean"));
    }
    let description = optional_text(
        input.get("description"),
        previous_str("description"),
        "description",
        1000,
    )?;
    let category = optional_text(
        input.get("category"),
        previous_str("category"),
        "category",
        60,
    )?;
    let logo_url = match input.get("logoUrl") {
        None => previous_str("logoUrl").map(str::to_owned),
        Some(value) if null_or_empty(value) => None,
        Some(value) => Some(app_url(Some(value), "logoUrl", allow_local)?),
    };
    let launch_url = match previous {
        Some(previous) if input.get("launchUrl").is_none() => {
            previous.get("launchUrl").cloned().unwrap_or(Value::Null)
        }
        _ => Value::String(app_url(input.get("launchUrl"), "launchUrl", allow_local)?),
    };
    let name = name_text(
        nullish_free(input.get("name"))
            .or_else(|| previous.and_then(|previous| previous.get("name"))),
        "name",
        120,
    )?;
    let present = |value: &Option<String>| value.clone().filter(|value| !value.is_empty());
    let mut values = Record::new();
    values.insert("uniqueKey".into(), Value::String(format!("key:{key}")));
    values.insert("key".into(), Value::String(key));
    values.insert("name".into(), Value::String(name));
    if let Some(description) = present(&description) {
        values.insert("description".into(), Value::String(description));
    }
    if let Some(category) = present(&category) {
        values.insert("category".into(), Value::String(category));
    }
    values.insert("launchUrl".into(), launch_url);
    if let Some(logo_url) = present(&logo_url) {
        values.insert("logoUrl".into(), Value::String(logo_url));
    }
    let client = present(&oauth_client_id);
    values.insert(
        "kind".into(),
        Value::String(if client.is_some() { "oidc" } else { "link" }.into()),
    );
    if let Some(client) = client {
        values.insert("oauthClientId".into(), Value::String(client));
    }
    values.insert("visibility".into(), visibility);
    values.insert("enabled".into(), enabled);
    if let Some(package_id) = present(&request_package_id) {
        values.insert("requestPackageId".into(), Value::String(package_id));
    }
    values.insert("ownerIds".into(), owner_ids);
    Ok(values)
}

/// What an audit event records about an app's state (`appState`).
fn app_state(app: &Record) -> Map<String, Value> {
    let mut state = Map::new();
    for key in ["name", "launchUrl", "visibility", "enabled"] {
        if let Some(value) = app.get(key) {
            state.insert(key.into(), value.clone());
        }
    }
    for key in ["oauthClientId", "requestPackageId"] {
        if truthy(app.get(key)) {
            state.insert(key.into(), app[key].clone());
        }
    }
    state
}

/// `{ key: app.key, ...appState(app) }`.
fn keyed_state(app: &Record) -> Map<String, Value> {
    let mut metadata = Map::new();
    if let Some(key) = app.get("key") {
        metadata.insert("key".into(), key.clone());
    }
    metadata.extend(app_state(app));
    metadata
}

/// Governing a client stops only on purpose: without the app, everyone of the tenant may sign in to it.
fn assert_released(app: &Record, release_client: Option<&Value>) -> IamResult<()> {
    if truthy(app.get("oauthClientId")) && release_client != Some(&Value::Bool(true)) {
        return Err(IamError::with_status(
            "CONFLICT",
            format!(
                "{} decides who may sign in to OAuth client {}; without it everyone of the organization may. Pass releaseClient: true to confirm.",
                js_string(app.get("name")),
                js_string(app.get("oauthClientId"))
            ),
            409,
        ));
    }
    Ok(())
}

/// `a.name.localeCompare(b.name)` of two records.
fn by_name(a: &Record, b: &Record) -> Ordering {
    locale_compare(&member_string(a, "name"), &member_string(b, "name"))
}

/// `appId:identityId` → `lastAt` of launches (later launches of the same pair win, as `new Map(...)` does).
fn last_launches(launches: &[Record]) -> IndexMap<String, Value> {
    let mut last = IndexMap::new();
    for launch in launches {
        last.insert(
            format!(
                "{}:{}",
                js_string(launch.get("appId")),
                js_string(launch.get("identityId"))
            ),
            launch.get("lastAt").cloned().unwrap_or(Value::Null),
        );
    }
    last
}

/// How many launches of an app happened within the last 30 days.
fn launched_last_30_days(launches: &[Record], app_id: Option<&Value>, now: f64) -> usize {
    launches
        .iter()
        .filter(|launch| {
            launch.get("appId") == app_id
                && launch
                    .get("lastAt")
                    .is_some_and(|last| core_js::to_number(last) > now - 30.0 * DAY)
        })
        .count()
}

/// Direct assignments made at least `days` ago whose person has not launched the app within `days`.
fn unused_assignments(
    assignments: &[Record],
    launches: &[Record],
    now: f64,
    days: f64,
) -> Vec<Record> {
    let cutoff = now - days * DAY;
    let last = last_launches(launches);
    assignments
        .iter()
        .filter(|assignment| {
            let key = format!(
                "{}:{}",
                js_string(assignment.get("appId")),
                js_string(assignment.get("subjectId"))
            );
            member_str(assignment, "subjectType") == Some("identity")
                && assignment
                    .get("assignedAt")
                    .is_some_and(|at| core_js::to_number(at) <= cutoff)
                && last.get(&key).map_or(0.0, core_js::to_number) <= cutoff
        })
        .cloned()
        .collect()
}

/// `checkAccess(ctx, tx, tenant, input)`: exactly one of `appId` or `oauthClientId`.
async fn check_access(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant: &better_iam_core::Tenant,
    input: &Map<String, Value>,
) -> IamResult<Value> {
    if input.get("appId").is_none() == input.get("oauthClientId").is_none() {
        return Err(invalid("Name exactly one of appId or oauthClientId"));
    }
    let identity_id = text(input.get("identityId"), "identityId", 256)?;
    let target = if input.get("appId").is_some() {
        json!({ "appId": text(input.get("appId"), "appId", 256)? })
    } else {
        json!({ "oauthClientId": text(input.get("oauthClientId"), "oauthClientId", 256)? })
    };
    app_access(ctx, tx, tenant, &identity_id, &target).await
}

/// `usageOf(ctx, tx, tenantId, unusedDays, withNames)`.
async fn usage_of(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    unused_days: f64,
    with_names: bool,
) -> IamResult<Value> {
    let now = ctx.now();
    let mut apps =
        find_records(tx, "applications", Filter::new().eq("tenantId", tenant_id)).await?;
    let launches = find_records(tx, "appLaunches", Filter::new().eq("tenantId", tenant_id)).await?;
    let assignments = find_records(
        tx,
        "appAssignments",
        Filter::new().eq("tenantId", tenant_id),
    )
    .await?;
    let holders = app_holders(ctx, tx, tenant_id, now).await?;
    let mut names: IndexMap<String, Value> = IndexMap::new();
    if with_names {
        for identity in
            find_records(tx, "identities", Filter::new().eq("tenantId", tenant_id)).await?
        {
            let name = nullish_free(identity.get("email"))
                .or(identity.get("name"))
                .cloned()
                .unwrap_or(Value::Null);
            names.insert(member_string(&identity, "id"), name);
        }
    }
    let last_launch = last_launches(&launches);
    apps.sort_by(by_name);
    let mut result = Vec::new();
    for app in &apps {
        let app_id = app.get("id");
        let own_assignments: Vec<Record> = assignments
            .iter()
            .filter(|assignment| assignment.get("appId") == app_id)
            .cloned()
            .collect();
        let own_launches: Vec<Record> = launches
            .iter()
            .filter(|launch| launch.get("appId") == app_id)
            .cloned()
            .collect();
        let unused: Vec<Value> =
            unused_assignments(&own_assignments, &own_launches, now, unused_days)
                .iter()
                .map(|assignment| {
                    let subject_id = member_string(assignment, "subjectId");
                    let last = last_launch.get(&format!("{}:{subject_id}", js_string(app_id)));
                    let name = names.get(&subject_id);
                    let mut entry = Map::new();
                    entry.insert(
                        "assignmentId".into(),
                        assignment.get("id").cloned().unwrap_or(Value::Null),
                    );
                    entry.insert("identityId".into(), Value::String(subject_id.clone()));
                    if let Some(name) = name.filter(|name| truthy(Some(name))) {
                        entry.insert("name".into(), name.clone());
                    }
                    if let Some(last) = last {
                        entry.insert("lastLaunchedAt".into(), last.clone());
                    }
                    Value::Object(entry)
                })
                .collect();
        let mut entry = Map::new();
        entry.insert("appId".into(), app_id.cloned().unwrap_or(Value::Null));
        entry.insert("key".into(), app.get("key").cloned().unwrap_or(Value::Null));
        entry.insert(
            "name".into(),
            app.get("name").cloned().unwrap_or(Value::Null),
        );
        entry.insert(
            "people".into(),
            number(
                holders
                    .get(&member_string(app, "id"))
                    .copied()
                    .unwrap_or(0.0),
            ),
        );
        entry.insert(
            "launchedLast30Days".into(),
            number(launched_last_30_days(&launches, app_id, now) as f64),
        );
        entry.insert("unused".into(), Value::Array(unused));
        result.push(Value::Object(entry));
    }
    Ok(Value::Array(result))
}

/// The `applications` API group (`createApplicationsApi(ctx)`): one method per route `applications/{method}`.
pub struct ApplicationsApi {
    ctx: Arc<ServerContext>,
}

/// `createApplicationsApi(ctx)`.
pub fn create_applications_api(ctx: &Arc<ServerContext>) -> IamResult<ApplicationsApi> {
    Ok(ApplicationsApi { ctx: ctx.clone() })
}

impl ApplicationsApi {
    /// May the caller see people's names and addresses (`iam:identities:read`)?
    async fn directory(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
    ) -> IamResult<bool> {
        Ok(self
            .ctx
            .decisions()?
            .decide(
                tx,
                principal,
                &AuthorizationRequest {
                    credential: CredentialInput::default(),
                    tenant_id: tenant_id.to_owned(),
                    action: "iam:identities:read".into(),
                    resource: ResourceTarget {
                        kind: "iam".into(),
                        id: tenant_id.to_owned(),
                    },
                },
                true,
            )
            .await?
            .allowed)
    }

    /// `audit(tx, principal, action, tenantId, resourceId, metadata)`: an allowed event of the acting principal.
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
                AuditOutcome::Allow,
                false,
                Some(metadata),
            )
            .await
    }

    /// `applications/assign`: gives an app to a person or a group, optionally until `expiresAt`. Audited as
    /// `app:assign`.
    pub async fn assign(
        &self,
        credential: &CredentialInput,
        input: Body<applications::AssignInput>,
    ) -> IamResult<Reply<applications::AssignOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let app_id = text(input.get("appId"), "appId", 256)?;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let app = ctx
                        .scoped(&tx, "applications", body.get("appId"), &tenant.id)
                        .await?;
                    let subject_type = match body.get("subjectType").and_then(Value::as_str) {
                        Some(kind @ ("identity" | "group")) => kind.to_owned(),
                        _ => {
                            return Err(invalid("subjectType must be 'identity' or 'group'").into());
                        }
                    };
                    let subject_id = text(body.get("subjectId"), "subjectId", 256)?;
                    if subject_type == "identity" {
                        let identity = ctx.active_identity(&tx, &subject_id, &tenant.id).await?;
                        if identity.kind != IdentityKind::User {
                            return Err(invalid("Apps are assigned to people and groups").into());
                        }
                    } else {
                        ctx.scoped(
                            &tx,
                            "groups",
                            Some(&Value::String(subject_id.clone())),
                            &tenant.id,
                        )
                        .await?;
                    }
                    let expires_at = match body.get("expiresAt") {
                        None => None,
                        Some(value) => Some(ctx.binding_expiry(Some(value))?),
                    };
                    let app_id = member_string(&app, "id");
                    let unique_key = format!("{app_id}:{subject_type}:{subject_id}");
                    let existing = find_records(
                        &tx,
                        "appAssignments",
                        Filter::new()
                            .eq("tenantId", tenant.id.clone())
                            .eq("uniqueKey", unique_key.clone()),
                    )
                    .await?
                    .into_iter()
                    .next();
                    if existing.is_none()
                        && find_records(
                            &tx,
                            "appAssignments",
                            Filter::new()
                                .eq("tenantId", tenant.id.clone())
                                .eq("appId", app_id.clone()),
                        )
                        .await?
                        .len()
                            >= MAX_ASSIGNMENTS_PER_APP
                    {
                        return Err(IamError::with_status(
                            "LIMIT_EXCEEDED",
                            format!(
                                "At most {MAX_ASSIGNMENTS_PER_APP} assignments per app; assign groups instead"
                            ),
                            409,
                        )
                        .into());
                    }
                    let now = ctx.now();
                    let mut assignment = Record::new();
                    assignment.insert(
                        "id".into(),
                        existing
                            .as_ref()
                            .and_then(|existing| existing.get("id").cloned())
                            .unwrap_or_else(|| Value::String(id())),
                    );
                    assignment.insert("tenantId".into(), Value::String(tenant.id.clone()));
                    assignment.insert("uniqueKey".into(), Value::String(unique_key));
                    assignment.insert("appId".into(), Value::String(app_id.clone()));
                    assignment.insert("subjectType".into(), Value::String(subject_type.clone()));
                    assignment.insert("subjectId".into(), Value::String(subject_id.clone()));
                    assignment.insert(
                        "assignedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    assignment.insert("assignedAt".into(), number(now));
                    if let Some(expires_at) = expires_at {
                        assignment.insert("expiresAt".into(), number(expires_at));
                    }
                    if existing.is_some() {
                        tx.put("appAssignments", &assignment).await?;
                    } else {
                        tx.insert("appAssignments", &assignment).await?;
                    }
                    let mut metadata = Map::new();
                    metadata.insert("key".into(), app.get("key").cloned().unwrap_or(Value::Null));
                    metadata.insert("subjectType".into(), Value::String(subject_type));
                    metadata.insert("subjectId".into(), Value::String(subject_id));
                    if let Some(expires_at) = expires_at {
                        metadata.insert("expiresAt".into(), number(expires_at));
                    }
                    self.audit(&tx, &principal, "app:assign", &tenant.id, &app_id, metadata)
                        .await?;
                    Ok(Value::Object(assignment))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:applications:assign",
                &app_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `applications/check`: whether a person may use an app (by `appId` or its `oauthClientId`), for a sign-in or
    /// consent page that enforces assignments. An OAuth client with no app in the catalog is not governed here.
    pub async fn check(
        &self,
        credential: &CredentialInput,
        input: Body<applications::CheckInput>,
    ) -> IamResult<Reply<applications::CheckOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move { Ok(check_access(ctx, &tx, &tenant, body).await?) })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:applications:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `applications/create`: registers an app. Audited as `app:create`.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<applications::CreateInput>,
    ) -> IamResult<Reply<applications::CreateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    if body.get("launchUrl").is_none_or(null_or_empty) {
                        return Err(invalid("launchUrl is required").into());
                    }
                    let values = app_fields(ctx, &tx, &tenant.id, body, None).await?;
                    let existing = find_records(
                        &tx,
                        "applications",
                        Filter::new().eq("tenantId", tenant.id.clone()),
                    )
                    .await?;
                    if existing
                        .iter()
                        .any(|app| app.get("uniqueKey") == values.get("uniqueKey"))
                    {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "An app with this key exists",
                            409,
                        )
                        .into());
                    }
                    if existing.len() >= MAX_APPS {
                        return Err(IamError::with_status(
                            "LIMIT_EXCEEDED",
                            format!("At most {MAX_APPS} apps"),
                            409,
                        )
                        .into());
                    }
                    let now = ctx.now();
                    let mut record = values;
                    record.insert("id".into(), Value::String(id()));
                    record.insert("tenantId".into(), Value::String(tenant.id.clone()));
                    record.insert("createdAt".into(), number(now));
                    record.insert("updatedAt".into(), number(now));
                    let app = tx.insert("applications", &record).await?;
                    self.audit(
                        &tx,
                        &principal,
                        "app:create",
                        &tenant.id,
                        &member_string(&app, "id"),
                        keyed_state(&app),
                    )
                    .await?;
                    Ok(Value::Object(app))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:applications:manage",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `applications/delete`: deletes an app with its assignments and launch history. An app that governs an OAuth
    /// client needs `releaseClient: true`. Audited as `app:delete`.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<applications::DeleteInput>,
    ) -> IamResult<Reply<applications::DeleteOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let app_id = text(input.get("appId"), "appId", 256)?;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let app = ctx
                        .scoped(&tx, "applications", body.get("appId"), &tenant.id)
                        .await?;
                    assert_released(&app, body.get("releaseClient"))?;
                    let app_id = member_string(&app, "id");
                    for collection in ["appAssignments", "appLaunches"] {
                        for row in find_records(
                            &tx,
                            collection,
                            Filter::new()
                                .eq("tenantId", tenant.id.clone())
                                .eq("appId", app_id.clone()),
                        )
                        .await?
                        {
                            tx.delete(collection, better_iam_core::record_id(&row))
                                .await?;
                        }
                    }
                    tx.delete("applications", &app_id).await?;
                    self.audit(
                        &tx,
                        &principal,
                        "app:delete",
                        &tenant.id,
                        &app_id,
                        keyed_state(&app),
                    )
                    .await?;
                    Ok(json!({ "deleted": true }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:applications:manage",
                &app_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `applications/launch`: launches an app the caller has: records the launch (audited as `app:launch`) and
    /// returns where to go. Refused while an administrator views as the person (`IMPERSONATION_RESTRICTED`).
    pub async fn launch(
        &self,
        credential: &CredentialInput,
        input: Body<applications::LaunchInput>,
    ) -> IamResult<Reply<applications::LaunchOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let app_id = text(input.get("appId"), "appId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let result = ctx
            .store
            .transaction(|tx| {
                let authenticated = &authenticated;
                let tenant_id = &tenant_id;
                let app_id = &app_id;
                async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    self_session(&principal, tenant_id)?;
                    if principal
                        .session
                        .impersonator_id
                        .as_deref()
                        .is_some_and(|id| !id.is_empty())
                    {
                        return Err(IamError::with_status(
                            "IMPERSONATION_RESTRICTED",
                            "Apps cannot be launched while viewing as someone else",
                            403,
                        ));
                    }
                    let mine = apps_for(ctx, &tx, &principal.identity, ctx.now()).await?;
                    let Some(entry) = mine.get(app_id.as_str()) else {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "This app is not assigned to you",
                            403,
                        ));
                    };
                    let now = ctx.now();
                    let unique_key = format!("{app_id}:{}", principal.identity.id);
                    let previous = find_records(
                        &tx,
                        "appLaunches",
                        Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("uniqueKey", unique_key.clone()),
                    )
                    .await?
                    .into_iter()
                    .next();
                    let mut launch = Record::new();
                    launch.insert(
                        "id".into(),
                        previous
                            .as_ref()
                            .and_then(|previous| nullish_free(previous.get("id")).cloned())
                            .unwrap_or_else(|| Value::String(id())),
                    );
                    launch.insert("tenantId".into(), Value::String(tenant_id.clone()));
                    launch.insert("uniqueKey".into(), Value::String(unique_key));
                    launch.insert("appId".into(), Value::String(app_id.clone()));
                    launch.insert(
                        "identityId".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    launch.insert(
                        "firstAt".into(),
                        previous
                            .as_ref()
                            .and_then(|previous| nullish_free(previous.get("firstAt")).cloned())
                            .unwrap_or_else(|| number(now)),
                    );
                    launch.insert("lastAt".into(), number(now));
                    let count = previous
                        .as_ref()
                        .and_then(|previous| nullish_free(previous.get("count")))
                        .map_or(0.0, core_js::to_number);
                    launch.insert("count".into(), number(count + 1.0));
                    if previous.is_some() {
                        tx.put("appLaunches", &launch).await?;
                    } else {
                        tx.insert("appLaunches", &launch).await?;
                    }
                    let mut metadata = Map::new();
                    metadata.insert(
                        "key".into(),
                        entry.app.get("key").cloned().unwrap_or(Value::Null),
                    );
                    self.audit(&tx, &principal, "app:launch", tenant_id, app_id, metadata)
                        .await?;
                    let mut out = Map::new();
                    if let Some(url) = entry.app.get("launchUrl") {
                        out.insert("url".into(), url.clone());
                    }
                    Ok(Value::Object(out))
                }
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `applications/list`: the tenant's apps by name, with how many live assignments each has and how many people
    /// launched it within 30 days.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<applications::ListInput>,
    ) -> IamResult<Reply<applications::ListOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let now = ctx.now();
                let assignments = find_records(
                    &tx,
                    "appAssignments",
                    Filter::new().eq("tenantId", tenant.id.clone()),
                )
                .await?;
                let launches = find_records(
                    &tx,
                    "appLaunches",
                    Filter::new().eq("tenantId", tenant.id.clone()),
                )
                .await?;
                let mut apps = find_records(
                    &tx,
                    "applications",
                    Filter::new().eq("tenantId", tenant.id.clone()),
                )
                .await?;
                apps.sort_by(by_name);
                let result: Vec<Value> = apps
                    .into_iter()
                    .map(|mut app| {
                        let app_id = app.get("id").cloned();
                        let live = assignments
                            .iter()
                            .filter(|assignment| {
                                assignment.get("appId") == app_id.as_ref()
                                    && assignment
                                        .get("expiresAt")
                                        .is_none_or(|at| core_js::to_number(at) > now)
                            })
                            .count();
                        let launched = launched_last_30_days(&launches, app_id.as_ref(), now);
                        app.insert("assignments".into(), number(live as f64));
                        app.insert("launchedLast30Days".into(), number(launched as f64));
                        Value::Object(app)
                    })
                    .collect();
                Ok(Value::Array(result))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:applications:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `applications/listAssignments`: assignments of one app, or of every app when `appId` is left out.
    pub async fn list_assignments(
        &self,
        credential: &CredentialInput,
        input: Body<applications::ListAssignmentsInput>,
    ) -> IamResult<Reply<applications::ListAssignmentsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let resource_id = match input.get("appId") {
            None => string_member(&input, "tenantId"),
            Some(value) => text(Some(value), "appId", 256)?,
        };
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let app = match body.get("appId") {
                        None => None,
                        Some(value) => Some(
                            ctx.scoped(&tx, "applications", Some(value), &tenant.id)
                                .await?,
                        ),
                    };
                    let mut filter = Filter::new().eq("tenantId", tenant.id.clone());
                    if let Some(app) = &app {
                        filter = filter.eq("appId", member_string(app, "id"));
                    }
                    let launches =
                        last_launches(&find_records(&tx, "appLaunches", filter.clone()).await?);
                    let names = self.directory(&tx, &principal, &tenant.id).await?;
                    let mut result: Vec<(String, Record)> = Vec::new();
                    for mut assignment in find_records(&tx, "appAssignments", filter).await? {
                        let subject_id = member_string(&assignment, "subjectId");
                        let identity_subject =
                            member_str(&assignment, "subjectType") == Some("identity");
                        let mut subject_name: Option<Value> = None;
                        if member_str(&assignment, "subjectType") == Some("group") {
                            subject_name = tx
                                .get("groups", &subject_id)
                                .await?
                                .and_then(|group| group.get("name").cloned());
                        } else if names {
                            subject_name =
                                tx.get("identities", &subject_id)
                                    .await?
                                    .and_then(|identity| {
                                        nullish_free(identity.get("email"))
                                            .or(identity.get("name"))
                                            .cloned()
                                    });
                        }
                        let last_launched_at = if identity_subject {
                            launches
                                .get(&format!(
                                    "{}:{subject_id}",
                                    js_string(assignment.get("appId"))
                                ))
                                .cloned()
                        } else {
                            None
                        };
                        let subject_name = subject_name.filter(|name| truthy(Some(name)));
                        let sort_name = match &subject_name {
                            Some(name) if !name.is_null() => js_string(Some(name)),
                            _ => js_string(assignment.get("subjectId")),
                        };
                        if let Some(name) = subject_name {
                            assignment.insert("subjectName".into(), name);
                        }
                        if let Some(last) = last_launched_at {
                            assignment.insert("lastLaunchedAt".into(), last);
                        }
                        result.push((sort_name, assignment));
                    }
                    result.sort_by(|a, b| locale_compare(&a.0, &b.0));
                    Ok(Value::Array(
                        result
                            .into_iter()
                            .map(|(_, assignment)| Value::Object(assignment))
                            .collect(),
                    ))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:applications:read",
                &resource_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `applications/mine`: the caller's launcher: the apps they may launch now (with when they last did), and the
    /// apps they could request through an access package. Needs only a signed-in session of the organization.
    pub async fn mine(
        &self,
        credential: &CredentialInput,
        input: Body<applications::MineInput>,
    ) -> IamResult<Reply<applications::MineOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let result = ctx
            .store
            .transaction(|tx| {
                let authenticated = &authenticated;
                let tenant_id = &tenant_id;
                async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    self_session(&principal, tenant_id)?;
                    let now = ctx.now();
                    let mine = apps_for(ctx, &tx, &principal.identity, now).await?;
                    let mut launches: IndexMap<String, Value> = IndexMap::new();
                    for launch in find_records(
                        &tx,
                        "appLaunches",
                        Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("identityId", principal.identity.id.clone()),
                    )
                    .await?
                    {
                        launches.insert(
                            js_string(launch.get("appId")),
                            launch.get("lastAt").cloned().unwrap_or(Value::Null),
                        );
                    }
                    let mut requestable: IndexMap<String, bool> = IndexMap::new();
                    let mut result: Vec<Map<String, Value>> = Vec::new();
                    for app in find_records(
                        &tx,
                        "applications",
                        Filter::new().eq("tenantId", tenant_id.clone()),
                    )
                    .await?
                    {
                        if !truthy(app.get("enabled")) {
                            continue;
                        }
                        let app_id = member_string(&app, "id");
                        let entry = mine.get(&app_id);
                        // A package deleted (or no longer requestable) since it was named is not offered.
                        if entry.is_none() {
                            let offered = match app.get("requestPackageId") {
                                Some(package) if truthy(Some(package)) => {
                                    let package_id = js_string(Some(package));
                                    if !requestable.contains_key(&package_id) {
                                        let found = tx.get("accessPackages", &package_id).await?;
                                        requestable.insert(
                                            package_id.clone(),
                                            found.is_some_and(|found| {
                                                member_str(&found, "tenantId")
                                                    == Some(tenant_id.as_str())
                                                    && truthy(found.get("requestable"))
                                            }),
                                        );
                                    }
                                    requestable[&package_id]
                                }
                                _ => false,
                            };
                            if !offered {
                                continue;
                            }
                        }
                        let mut item = Map::new();
                        for key in ["id", "key", "name"] {
                            item.insert(key.into(), app.get(key).cloned().unwrap_or(Value::Null));
                        }
                        for key in ["description", "category", "logoUrl"] {
                            if truthy(app.get(key)) {
                                item.insert(key.into(), app[key].clone());
                            }
                        }
                        match entry {
                            Some(entry) => {
                                item.insert("via".into(), Value::String(entry.via.into()));
                            }
                            None => {
                                item.insert(
                                    "requestPackageId".into(),
                                    app.get("requestPackageId").cloned().unwrap_or(Value::Null),
                                );
                            }
                        }
                        if let Some(last) = launches.get(&app_id) {
                            item.insert("lastLaunchedAt".into(), last.clone());
                        }
                        result.push(item);
                    }
                    let last_of = |item: &Map<String, Value>| {
                        nullish_free(item.get("lastLaunchedAt")).map_or(0.0, core_js::to_number)
                    };
                    result.sort_by(|a, b| {
                        let requested = |item: &Map<String, Value>| {
                            usize::from(truthy(item.get("requestPackageId")))
                        };
                        requested(a)
                            .cmp(&requested(b))
                            .then_with(|| {
                                last_of(b)
                                    .partial_cmp(&last_of(a))
                                    .unwrap_or(Ordering::Equal)
                            })
                            .then_with(|| {
                                locale_compare(&js_string(a.get("name")), &js_string(b.get("name")))
                            })
                    });
                    Ok(Value::Array(
                        result.into_iter().map(Value::Object).collect(),
                    ))
                }
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `applications/removeUnused`: removes direct assignments of an app unused for `unusedDays` (group assignments
    /// stay). Audited as `app:unassign`.
    pub async fn remove_unused(
        &self,
        credential: &CredentialInput,
        input: Body<applications::RemoveUnusedInput>,
    ) -> IamResult<Reply<applications::RemoveUnusedOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let app_id = text(input.get("appId"), "appId", 256)?;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let app = ctx
                        .scoped(&tx, "applications", body.get("appId"), &tenant.id)
                        .await?;
                    let days = integer(body.get("unusedDays"), "unusedDays", 7.0, 3650.0)?;
                    let app_id = member_string(&app, "id");
                    let filter = Filter::new()
                        .eq("tenantId", tenant.id.clone())
                        .eq("appId", app_id.clone());
                    let unused = unused_assignments(
                        &find_records(&tx, "appAssignments", filter.clone()).await?,
                        &find_records(&tx, "appLaunches", filter).await?,
                        ctx.now(),
                        days,
                    );
                    for assignment in &unused {
                        tx.delete("appAssignments", better_iam_core::record_id(assignment))
                            .await?;
                        let mut metadata = Map::new();
                        metadata.insert("subjectType".into(), json!("identity"));
                        metadata.insert(
                            "subjectId".into(),
                            assignment.get("subjectId").cloned().unwrap_or(Value::Null),
                        );
                        metadata.insert(
                            "reason".into(),
                            Value::String(format!(
                                "unused {} days",
                                core_js::number_to_string(days)
                            )),
                        );
                        self.audit(
                            &tx,
                            &principal,
                            "app:unassign",
                            &tenant.id,
                            &app_id,
                            metadata,
                        )
                        .await?;
                    }
                    Ok(json!({ "removed": unused.len() }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:applications:assign",
                &app_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `applications/unassign`: removes one assignment; authorized on its app, like `assign`. Audited as
    /// `app:unassign`.
    pub async fn unassign(
        &self,
        credential: &CredentialInput,
        input: Body<applications::UnassignInput>,
    ) -> IamResult<Reply<applications::UnassignOutput>> {
        let ctx = &self.ctx;
        let assignment_id = text(input.get("assignmentId"), "assignmentId", 256)?;
        // Authorized on the assignment's app (per-app administrators), or on the ID itself when there is no such
        // record.
        let found = ctx.store.get("appAssignments", &assignment_id).await?;
        let resource_id = match &found {
            Some(found) if found.get("tenantId") == input.get("tenantId") => {
                js_string(found.get("appId"))
            }
            _ => assignment_id.clone(),
        };
        let resource = &resource_id;
        let assignment_ref = &assignment_id;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let assignment = ctx
                        .scoped(
                            &tx,
                            "appAssignments",
                            Some(&Value::String(assignment_ref.clone())),
                            &tenant.id,
                        )
                        .await?;
                    if member_str(&assignment, "appId") != Some(resource.as_str()) {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "The assignment changed; try again",
                            409,
                        )
                        .into());
                    }
                    tx.delete("appAssignments", better_iam_core::record_id(&assignment))
                        .await?;
                    let mut metadata = Map::new();
                    for key in ["subjectType", "subjectId"] {
                        metadata.insert(
                            key.into(),
                            assignment.get(key).cloned().unwrap_or(Value::Null),
                        );
                    }
                    self.audit(
                        &tx,
                        &principal,
                        "app:unassign",
                        &tenant.id,
                        &member_string(&assignment, "appId"),
                        metadata,
                    )
                    .await?;
                    Ok(json!({ "removed": true }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:applications:assign",
                &resource_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `applications/update`: changes an app. Clearing `oauthClientId` needs `releaseClient: true` (the client stops
    /// being governed). Audited as `app:update` with the state before and after.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<applications::UpdateInput>,
    ) -> IamResult<Reply<applications::UpdateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let app_id = text(input.get("appId"), "appId", 256)?;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let previous = ctx
                        .scoped(&tx, "applications", body.get("appId"), &tenant.id)
                        .await?;
                    let values = app_fields(ctx, &tx, &tenant.id, body, Some(&previous)).await?;
                    if truthy(previous.get("oauthClientId"))
                        && values.get("oauthClientId") != previous.get("oauthClientId")
                    {
                        assert_released(&previous, body.get("releaseClient"))?;
                    }
                    let mut next = previous.clone();
                    for key in [
                        "description",
                        "category",
                        "logoUrl",
                        "oauthClientId",
                        "requestPackageId",
                    ] {
                        next.shift_remove(key);
                    }
                    for (key, value) in values {
                        next.insert(key, value);
                    }
                    next.insert("updatedAt".into(), number(ctx.now()));
                    let app = tx.put("applications", &next).await?;
                    let mut metadata = Map::new();
                    metadata.insert("key".into(), app.get("key").cloned().unwrap_or(Value::Null));
                    metadata.insert("before".into(), Value::Object(app_state(&previous)));
                    metadata.insert("after".into(), Value::Object(app_state(&app)));
                    self.audit(
                        &tx,
                        &principal,
                        "app:update",
                        &tenant.id,
                        &member_string(&app, "id"),
                        metadata,
                    )
                    .await?;
                    Ok(Value::Object(app))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:applications:manage",
                &app_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `applications/usage`: assignment hygiene: per app, how many people have it, how many launched it in 30 days,
    /// and the direct assignments unused for `unusedDays` (default 90).
    pub async fn usage(
        &self,
        credential: &CredentialInput,
        input: Body<applications::UsageInput>,
    ) -> IamResult<Reply<applications::UsageOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let default_days = json!(90);
                    let days = integer(
                        Some(nullish_free(body.get("unusedDays")).unwrap_or(&default_days)),
                        "unusedDays",
                        1.0,
                        3650.0,
                    )?;
                    let names = self.directory(&tx, &principal, &tenant.id).await?;
                    Ok(usage_of(ctx, &tx, &tenant.id, days, names).await?)
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:applications:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// The catalog for the deployment's own code (`iam.applications`): an unaudited access check for sign-in pages.
pub struct ApplicationsRuntime {
    ctx: Arc<ServerContext>,
}

/// `createApplicationsRuntime(ctx)`.
pub fn create_applications_runtime(ctx: &Arc<ServerContext>) -> IamResult<ApplicationsRuntime> {
    Ok(ApplicationsRuntime { ctx: ctx.clone() })
}

impl ApplicationsRuntime {
    /// Whether `identityId` may use the app registered for `oauthClientId` (or `appId`). The built-in OAuth provider
    /// already enforces this for catalog clients; call it from other sign-in or consent pages. Ungoverned clients are
    /// allowed. Answers `{ allowed, governed, appId? }`.
    pub async fn allowed(&self, input: &Value) -> IamResult<Value> {
        let ctx = &self.ctx;
        let empty = Map::new();
        let input = input.as_object().unwrap_or(&empty);
        ctx.store
            .transaction(|tx| async move {
                let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
                let tenant = ctx.tenant(&tx, &tenant_id).await?;
                check_access(ctx, &tx, &tenant, input).await
            })
            .await
    }

    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        match method {
            "allowed" => Some(self.allowed(args.first().unwrap_or(&Value::Null)).await),
            _ => None,
        }
    }
}
