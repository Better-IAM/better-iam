//! Port of `packages/server/src/applications.ts`.
//!
//! The application catalog behind the "My apps" launcher: the tenant's applications (OpenID Connect clients of this
//! deployment, or plain links to other tools), who may see and launch each one (everyone, or assigned people and
//! groups), launch history, and the access package people request to get an app. For an OpenID Connect app the
//! assignment is enforced: the OAuth provider refuses to issue or refresh tokens for people without the app
//! (`iam.protocolHost.clientAllowed`).

use std::sync::Arc;

use better_iam_core::{
    Filter, FindOptions, IamError, IamResult, IamStoreExt, IdentityKind, IdentityStatus, Record,
    TenantStatus, js as core_js,
};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use url::Url;

use crate::context::{ServerContext, Store};
use crate::hosts::url_hostname;
use crate::port::decode;
use crate::validation::text;

/// An app given to a person or a group, optionally until `expiresAt` (uniqueKey
/// `{appId}:{subjectType}:{subjectId}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppAssignment {
    #[serde(rename = "appId")]
    pub app_id: String,
    #[serde(rename = "subjectType")]
    pub subject_type: String,
    #[serde(rename = "subjectId")]
    pub subject_id: String,
    #[serde(rename = "assignedBy")]
    pub assigned_by: String,
    #[serde(rename = "assignedAt")]
    pub assigned_at: f64,
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

/// A person's launches of an app: the last one and how many (uniqueKey `{appId}:{identityId}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AppLaunch {
    #[serde(rename = "appId")]
    pub app_id: String,
    #[serde(rename = "identityId")]
    pub identity_id: String,
    #[serde(rename = "lastAt")]
    pub last_at: f64,
    #[serde(rename = "firstAt")]
    pub first_at: f64,
    #[serde(rename = "count")]
    pub count: f64,
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

/// The application catalog behind the "My apps" launcher: the tenant's applications (OpenID Connect clients of this
/// deployment, or plain links to other tools), who may see and launch each one (everyone, or assigned people and
/// groups), launch history, and the access package people request to get an app. For an OpenID Connect app the
/// assignment is enforced: the OAuth provider refuses to issue or refresh tokens for people without the app
/// (`iam.protocolHost.clientAllowed`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Application {
    /// Short identifier, unique per tenant (uniqueKey `key:{key}`).
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
    #[serde(rename = "category", default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Where launching sends the person: the app's sign-in URL.
    #[serde(rename = "launchUrl")]
    pub launch_url: String,
    #[serde(rename = "logoUrl", default, skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    /// `oidc`: an OAuth/OpenID Connect client of this deployment (`oauthClientId`, one app per client); `link`: any
    /// other tool.
    #[serde(rename = "kind")]
    pub kind: String,
    #[serde(
        rename = "oauthClientId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub oauth_client_id: Option<String>,
    /// `everyone`: every active person of the tenant sees it; `assigned`: only assigned people and group members.
    #[serde(rename = "visibility")]
    pub visibility: String,
    #[serde(rename = "enabled")]
    pub enabled: bool,
    /// People without access see "Request access", which requests this access package (it should grant a group the app
    /// is assigned to).
    #[serde(
        rename = "requestPackageId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub request_package_id: Option<String>,
    /// People to contact about the app.
    #[serde(rename = "ownerIds")]
    pub owner_ids: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
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

/// One app a person may launch (`{ app, via }` of `appsFor`): the stored app record and why they have it,
/// `everyone`, `direct` or `group`.
#[derive(Debug, Clone, PartialEq)]
pub struct AppGrant {
    pub app: Record,
    pub via: &'static str,
}

/// Every record of a collection matching the filter.
pub(crate) async fn find_records(
    tx: &Store,
    collection: &str,
    filter: Filter,
) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

/// A string member of a stored record (`record.key` where it is a string).
pub(crate) fn member_str<'a>(record: &'a Record, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

/// A string member of a stored record, or "" (records written by the server always carry their string members).
pub(crate) fn member_string(record: &Record, key: &str) -> String {
    member_str(record, key).unwrap_or_default().to_owned()
}

/// `record.key === true`.
fn member_true(record: &Record, key: &str) -> bool {
    record.get(key) == Some(&Value::Bool(true))
}

/// `expiresAt === undefined || expiresAt > now`.
fn live(expires_at: Option<&Value>, now: f64) -> bool {
    match expires_at {
        None => true,
        Some(value) => core_js::to_number(value) > now,
    }
}

const LOCAL_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "[::1]"];

/// `/^[a-z][a-z0-9._-]{0,63}$/`.
fn key_shape(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some('a'..='z'))
        && key.chars().count() <= 64
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '.' | '_' | '-'))
}

pub fn app_key(value: Option<&Value>) -> IamResult<String> {
    let key = text(value, "key", 64)?;
    if !key_shape(&key) {
        return Err(IamError::new(
            "INVALID_INPUT",
            "App keys use lowercase letters, digits, dots, underscores or hyphens",
        ));
    }
    Ok(key)
}

/// Whether the deployment itself runs on the local machine (development), where apps may use plain http locally.
pub fn local_deployment(base_url: Option<&str>) -> IamResult<bool> {
    Ok(match base_url.map(Url::parse) {
        Some(Ok(url)) => LOCAL_HOSTS.contains(&url_hostname(&url).as_str()),
        _ => false,
    })
}

/// Launch and logo URLs: https, or http on the local machine when the deployment itself is local (development).
pub fn app_url(value: Option<&Value>, name: &str, allow_local: bool) -> IamResult<String> {
    let raw = text(value, name, 2048)?;
    let Ok(url) = Url::parse(&raw) else {
        return Err(IamError::new(
            "INVALID_INPUT",
            format!("{name} must be an absolute URL"),
        ));
    };
    let local = allow_local && LOCAL_HOSTS.contains(&url_hostname(&url).as_str());
    if url.scheme() != "https" && !(url.scheme() == "http" && local) {
        return Err(IamError::new(
            "INVALID_INPUT",
            format!("{name} must use https"),
        ));
    }
    if !url.username().is_empty() || url.password().is_some_and(|password| !password.is_empty()) {
        return Err(IamError::new(
            "INVALID_INPUT",
            format!("{name} cannot carry credentials"),
        ));
    }
    Ok(url.to_string())
}

/// Whether an identity may hold apps at all: an active, unexpired person.
fn eligible(ctx: &ServerContext, identity: &better_iam_core::Identity) -> bool {
    identity.kind == IdentityKind::User
        && identity.status == IdentityStatus::Active
        && !ctx.identity_expired(identity)
}

/// Which enabled apps a person may launch right now: everyone apps, apps assigned to them, and apps assigned to a
/// group they belong to (memberships and assignments that have not ended). Only active, unexpired people have apps.
pub async fn apps_for(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    identity: &better_iam_core::Identity,
    now: f64,
) -> IamResult<IndexMap<String, AppGrant>> {
    let mut result: IndexMap<String, AppGrant> = IndexMap::new();
    if !eligible(ctx, identity) {
        return Ok(result);
    }
    let tenant_id = identity.tenant_id.clone();
    let mut apps: IndexMap<String, Record> = IndexMap::new();
    for app in find_records(
        tx,
        "applications",
        Filter::new().eq("tenantId", tenant_id.clone()),
    )
    .await?
    {
        if member_true(&app, "enabled") {
            apps.insert(member_string(&app, "id"), app);
        }
    }
    if apps.is_empty() {
        return Ok(result);
    }
    for (app_id, app) in &apps {
        if member_str(app, "visibility") == Some("everyone") {
            result.insert(
                app_id.clone(),
                AppGrant {
                    app: app.clone(),
                    via: "everyone",
                },
            );
        }
    }
    let mut groups: IndexSet<String> = IndexSet::new();
    for member in find_records(
        tx,
        "groupMembers",
        Filter::new()
            .eq("tenantId", tenant_id.clone())
            .eq("identityId", identity.id.clone()),
    )
    .await?
    {
        if live(member.get("expiresAt"), now) {
            groups.insert(member_string(&member, "groupId"));
        }
    }
    // Only this person's and their groups' assignments (`subjectId` is indexed), never the whole tenant's.
    let mut assignments = find_records(
        tx,
        "appAssignments",
        Filter::new()
            .eq("tenantId", tenant_id.clone())
            .eq("subjectType", "identity")
            .eq("subjectId", identity.id.clone()),
    )
    .await?;
    for group_id in &groups {
        assignments.extend(
            find_records(
                tx,
                "appAssignments",
                Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq("subjectType", "group")
                    .eq("subjectId", group_id.clone()),
            )
            .await?,
        );
    }
    for assignment in assignments {
        let Some(app) = member_str(&assignment, "appId").and_then(|id| apps.get(id)) else {
            continue;
        };
        if !live(assignment.get("expiresAt"), now) {
            continue;
        }
        let direct = member_str(&assignment, "subjectType") == Some("identity");
        let app_id = member_string(app, "id");
        let replace = match result.get(&app_id) {
            None => true,
            Some(previous) => previous.via == "everyone" || (previous.via == "group" && direct),
        };
        if replace {
            result.insert(
                app_id,
                AppGrant {
                    app: app.clone(),
                    via: if direct { "direct" } else { "group" },
                },
            );
        }
    }
    Ok(result)
}

/// How many people hold each app now, in one pass over the tenant (for usage reports): everyone apps count every
/// eligible person, assigned apps the union of direct assignees and live members of assigned groups.
pub async fn app_holders(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    now: f64,
) -> IamResult<IndexMap<String, f64>> {
    let mut people: IndexSet<String> = IndexSet::new();
    for record in find_records(tx, "identities", Filter::new().eq("tenantId", tenant_id)).await? {
        let identity: better_iam_core::Identity = decode(record)?;
        if eligible(ctx, &identity) {
            people.insert(identity.id);
        }
    }
    let mut members: IndexMap<String, Vec<String>> = IndexMap::new();
    for member in find_records(tx, "groupMembers", Filter::new().eq("tenantId", tenant_id)).await? {
        let identity_id = member_string(&member, "identityId");
        if live(member.get("expiresAt"), now) && people.contains(&identity_id) {
            members
                .entry(member_string(&member, "groupId"))
                .or_default()
                .push(identity_id);
        }
    }
    let mut holders: IndexMap<String, IndexSet<String>> = IndexMap::new();
    for assignment in find_records(
        tx,
        "appAssignments",
        Filter::new().eq("tenantId", tenant_id),
    )
    .await?
    {
        if !live(assignment.get("expiresAt"), now) {
            continue;
        }
        let mut set = holders
            .get(&member_string(&assignment, "appId"))
            .cloned()
            .unwrap_or_default();
        let subject_id = member_string(&assignment, "subjectId");
        if member_str(&assignment, "subjectType") == Some("identity") {
            if people.contains(&subject_id) {
                set.insert(subject_id);
            }
        } else {
            for identity_id in members.get(&subject_id).into_iter().flatten() {
                set.insert(identity_id.clone());
            }
        }
        holders.insert(member_string(&assignment, "appId"), set);
    }
    let mut result = IndexMap::new();
    for app in find_records(tx, "applications", Filter::new().eq("tenantId", tenant_id)).await? {
        let app_id = member_string(&app, "id");
        let count = if !member_true(&app, "enabled") {
            0.0
        } else if member_str(&app, "visibility") == Some("everyone") {
            people.len() as f64
        } else {
            holders.get(&app_id).map_or(0.0, |set| set.len() as f64)
        };
        result.insert(app_id, count);
    }
    Ok(result)
}

/// Whether a person may use an app, by its ID or its OAuth client: `governed: false` when no app in the catalog
/// names the client (nothing to enforce). Refuses people of another tenant, an inactive tenant, and people who are
/// not active. `target` is `{ appId }` or `{ oauthClientId }`; the answer is `{ allowed, governed, appId? }`.
pub async fn app_access(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant: &better_iam_core::Tenant,
    identity_id: &str,
    target: &Value,
) -> IamResult<Value> {
    let apps = find_records(
        tx,
        "applications",
        Filter::new().eq("tenantId", tenant.id.clone()),
    )
    .await?;
    let by_app = target.get("appId").is_some();
    let app = if by_app {
        apps.into_iter()
            .find(|item| item.get("id") == target.get("appId"))
    } else {
        apps.into_iter()
            .find(|item| item.get("oauthClientId") == target.get("oauthClientId"))
    };
    let Some(app) = app else {
        if by_app {
            return Err(IamError::with_status("NOT_FOUND", "App not found", 404));
        }
        return Ok(json!({ "allowed": true, "governed": false }));
    };
    let app_id = app.get("id").cloned().unwrap_or(Value::Null);
    let identity = match tx.get("identities", identity_id).await? {
        Some(record) => Some(decode::<better_iam_core::Identity>(record)?),
        None => None,
    };
    let Some(identity) = identity.filter(|identity| {
        identity.tenant_id == tenant.id && tenant.status == TenantStatus::Active
    }) else {
        return Ok(json!({ "allowed": false, "governed": true, "appId": app_id }));
    };
    let allowed = apps_for(ctx, tx, &identity, ctx.now())
        .await?
        .contains_key(&member_string(&app, "id"));
    Ok(json!({ "allowed": allowed, "governed": true, "appId": app_id }))
}

/// The OAuth provider's gate (`protocolHost.clientAllowed`): may this person get tokens for this client?
pub async fn app_client_allowed(
    ctx: &Arc<ServerContext>,
    identity_id: &str,
    tenant_id: &str,
    client_id: &str,
) -> IamResult<bool> {
    ctx.store
        .transaction(|tx| async move {
            let Some(tenant) = tx.get("tenants", tenant_id).await? else {
                return Ok(false);
            };
            let tenant: better_iam_core::Tenant = decode(tenant)?;
            let access = app_access(
                ctx,
                &tx,
                &tenant,
                identity_id,
                &json!({ "oauthClientId": client_id }),
            )
            .await?;
            Ok(access.get("allowed") == Some(&Value::Bool(true)))
        })
        .await
}

/// When a person is deleted: their assignments and launch history go, and they stop being an app owner.
pub async fn release_app_records_of(
    tx: &Store,
    identity: &better_iam_core::Identity,
) -> IamResult<()> {
    let tenant_id = identity.tenant_id.clone();
    for assignment in find_records(
        tx,
        "appAssignments",
        Filter::new()
            .eq("tenantId", tenant_id.clone())
            .eq("subjectType", "identity")
            .eq("subjectId", identity.id.clone()),
    )
    .await?
    {
        tx.delete("appAssignments", better_iam_core::record_id(&assignment))
            .await?;
    }
    for launch in find_records(
        tx,
        "appLaunches",
        Filter::new()
            .eq("tenantId", tenant_id.clone())
            .eq("identityId", identity.id.clone()),
    )
    .await?
    {
        tx.delete("appLaunches", better_iam_core::record_id(&launch))
            .await?;
    }
    for mut app in find_records(
        tx,
        "applications",
        Filter::new().eq("tenantId", tenant_id.clone()),
    )
    .await?
    {
        let owners: Vec<Value> = match app.get("ownerIds") {
            Some(Value::Array(owners)) => owners.clone(),
            _ => continue,
        };
        let own = Value::String(identity.id.clone());
        if owners.contains(&own) {
            app.insert(
                "ownerIds".into(),
                Value::Array(owners.into_iter().filter(|owner| owner != &own).collect()),
            );
            tx.put("applications", &app).await?;
        }
    }
    Ok(())
}

/// When a group is deleted: its app assignments go with it.
pub async fn release_group_apps(tx: &Store, tenant_id: &str, group_id: &str) -> IamResult<()> {
    for assignment in find_records(
        tx,
        "appAssignments",
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("subjectType", "group")
            .eq("subjectId", group_id),
    )
    .await?
    {
        tx.delete("appAssignments", better_iam_core::record_id(&assignment))
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_urls() {
        assert_eq!(app_key(Some(&json!("wiki.v2_a-b"))).unwrap(), "wiki.v2_a-b");
        assert_eq!(
            app_key(Some(&json!("Wiki"))).unwrap_err().message,
            "App keys use lowercase letters, digits, dots, underscores or hyphens"
        );
        assert_eq!(
            app_key(Some(&json!(""))).unwrap_err().message,
            "Invalid key"
        );
        assert!(local_deployment(Some("http://localhost:3000")).unwrap());
        assert!(!local_deployment(Some("https://iam.example.com")).unwrap());
        assert!(!local_deployment(Some("not a url")).unwrap());
        assert!(!local_deployment(None).unwrap());
        assert_eq!(
            app_url(Some(&json!("https://ci.acme.test")), "launchUrl", false).unwrap(),
            "https://ci.acme.test/"
        );
        assert_eq!(
            app_url(Some(&json!("http://ci.acme.test")), "launchUrl", true)
                .unwrap_err()
                .message,
            "launchUrl must use https"
        );
        assert_eq!(
            app_url(Some(&json!("http://localhost:8080/x")), "launchUrl", true).unwrap(),
            "http://localhost:8080/x"
        );
        assert_eq!(
            app_url(Some(&json!("http://localhost:8080/x")), "logoUrl", false)
                .unwrap_err()
                .message,
            "logoUrl must use https"
        );
        assert_eq!(
            app_url(Some(&json!("nope")), "launchUrl", false)
                .unwrap_err()
                .message,
            "launchUrl must be an absolute URL"
        );
        assert_eq!(
            app_url(Some(&json!("https://a:b@x.test")), "launchUrl", false)
                .unwrap_err()
                .message,
            "launchUrl cannot carry credentials"
        );
    }
}
