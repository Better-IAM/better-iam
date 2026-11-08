//! Reference plugin providing tenant-scoped project records (the Rust port of `@better-iam/projects`).
//!
//! Registering the plugin adds the `projects:read` and `projects:write` actions to the catalog and mounts
//! `POST /api/iam/plugins/projects/{create|list|get|update|archive|restore}`. Every endpoint runs in the server's
//! transactional authorization service; root override, tenant scope, ancestry boundaries, and policies apply
//! unchanged. Endpoints on one project are authorized on `iam/project/{id}`, so policies about that project apply.
//!
//! ```ignore
//! let mut options = BetterIamOptions::new(store, secret, base_url);
//! options.plugins = Some(vec![better_iam_projects::create_projects_plugin()]);
//! ```
#![forbid(unsafe_code)]

use std::cmp::Ordering;
use std::sync::Arc;

use better_iam_core::js;
use better_iam_core::{
    Filter, FindOptions, IamError, IamPlugin, IamResult, IamStore, PluginEndpoint,
    PluginEndpointContext, Record,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The plugin id, and the first path segment of its endpoints.
pub const PLUGIN_ID: &str = "projects";
/// The collection of project records.
pub const COLLECTION: &str = "projects";

const NAME_MAX_LENGTH: usize = 100;
const DESCRIPTION_MAX_LENGTH: usize = 500;

/// `ProjectStatus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProjectStatus {
    Active,
    Archived,
}

/// Tenant-scoped project record owned by this plugin (`Project`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub status: ProjectStatus,
    pub created_by: String,
    pub created_at: f64,
    pub updated_at: f64,
}

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

/// `String(value)`.
fn js_string(value: Option<&Value>) -> String {
    match value {
        None => "undefined".to_owned(),
        Some(Value::Null) => "null".to_owned(),
        Some(Value::Bool(flag)) => flag.to_string(),
        Some(Value::Number(number)) => js::number_to_string(js::number_value(number)),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::Null => String::new(),
                other => js_string(Some(other)),
            })
            .collect::<Vec<_>>()
            .join(","),
        Some(Value::Object(_)) => "[object Object]".to_owned(),
    }
}

/// Whether a value is JavaScript-truthy.
fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => {
            let value = js::number_value(number);
            value != 0.0 && !value.is_nan()
        }
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(_) | Value::Object(_)) => true,
    }
}

fn object(input: &Value) -> IamResult<&Map<String, Value>> {
    match input {
        Value::Object(map) => Ok(map),
        _ => Err(invalid("A JSON object is required")),
    }
}

fn reject_unknown(input: &Map<String, Value>, allowed: &[&str]) -> IamResult<()> {
    for key in js::keys(input) {
        if !allowed.contains(&key.as_str()) {
            return Err(invalid(format!("Unexpected field {key}")));
        }
    }
    Ok(())
}

fn text(value: Option<&Value>, field: &str) -> IamResult<String> {
    let Some(Value::String(value)) = value else {
        return Err(invalid(format!("{field} is required")));
    };
    let trimmed = js::trim(value);
    if trimmed.is_empty() || js::utf16_len(trimmed) > NAME_MAX_LENGTH {
        return Err(invalid(format!(
            "{field} must be 1-{NAME_MAX_LENGTH} characters"
        )));
    }
    Ok(trimmed.to_owned())
}

fn optional_text(value: Option<&Value>, field: &str) -> IamResult<Option<String>> {
    let value = match value {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(value)) => value,
        Some(_) => return Err(invalid(format!("{field} must be text"))),
    };
    let trimmed = js::trim(value);
    if trimmed.is_empty() {
        return Ok(None);
    }
    if js::utf16_len(trimmed) > DESCRIPTION_MAX_LENGTH {
        return Err(invalid(format!(
            "{field} must be at most {DESCRIPTION_MAX_LENGTH} characters"
        )));
    }
    Ok(Some(trimmed.to_owned()))
}

/// Project IDs are generated UUIDs; anything else (wildcards, slashes) could never name one and must not reach the
/// resource the endpoint is authorized on.
fn project_id(input: Option<&Value>) -> IamResult<String> {
    match input {
        Some(Value::String(id))
            if !id.is_empty()
                && id.len() <= 128
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-') =>
        {
            Ok(id.clone())
        }
        _ => Err(invalid("projectId is required")),
    }
}

/// `{ tenantId: input.tenantId }`, the start of every validated input (the server always sets the member).
fn scoped(input: &Map<String, Value>) -> Map<String, Value> {
    let mut validated = Map::new();
    if let Some(tenant_id) = input.get("tenantId") {
        validated.insert("tenantId".into(), tenant_id.clone());
    }
    validated
}

fn now() -> Value {
    js::number(js::now_ms()).unwrap_or(Value::Null)
}

fn not_found() -> IamError {
    IamError::with_status("NOT_FOUND", "Project not found", 404)
}

async fn load(store: &dyn IamStore, id: &str, tenant_id: &str) -> IamResult<Record> {
    match store.get(COLLECTION, id).await? {
        Some(project) if project.get("tenantId") == Some(&Value::String(tenant_id.to_owned())) => {
            Ok(project)
        }
        _ => Err(not_found()),
    }
}

async fn tenant_projects(store: &dyn IamStore, filter: Filter) -> IamResult<Vec<Record>> {
    store
        .find(COLLECTION, &filter, &FindOptions::default())
        .await
}

async fn assert_name_available(
    store: &dyn IamStore,
    tenant_id: &str,
    name: &str,
    except_id: Option<&str>,
) -> IamResult<()> {
    let projects =
        tenant_projects(store, Filter::new().eq("tenantId", tenant_id.to_owned())).await?;
    let taken = projects.iter().any(|project| {
        project.get("name").and_then(Value::as_str) == Some(name)
            && project.get("id").and_then(Value::as_str) != except_id
    });
    if taken {
        return Err(IamError::with_status(
            "CONFLICT",
            "A project with this name already exists",
            409,
        ));
    }
    Ok(())
}

/// `a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1)`.
fn by_creation(a: &Record, b: &Record) -> Ordering {
    let created = |record: &Record| record.get("createdAt").map_or(f64::NAN, js::to_number);
    let difference = created(a) - created(b);
    if difference != 0.0 && !difference.is_nan() {
        return if difference < 0.0 {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    let id = |record: &Record| js_string(record.get("id"));
    if js::cmp_utf16(&id(a), &id(b)) == Ordering::Less {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endpoint {
    Create,
    List,
    Get,
    Update,
    Archive,
    Restore,
}

impl Endpoint {
    const ALL: [Endpoint; 6] = [
        Endpoint::Create,
        Endpoint::List,
        Endpoint::Get,
        Endpoint::Update,
        Endpoint::Archive,
        Endpoint::Restore,
    ];
}

struct ProjectsEndpoint(Endpoint);

#[async_trait::async_trait]
impl PluginEndpoint for ProjectsEndpoint {
    fn path(&self) -> &str {
        match self.0 {
            Endpoint::Create => "create",
            Endpoint::List => "list",
            Endpoint::Get => "get",
            Endpoint::Update => "update",
            Endpoint::Archive => "archive",
            Endpoint::Restore => "restore",
        }
    }

    fn action(&self) -> &str {
        match self.0 {
            Endpoint::List | Endpoint::Get => "projects:read",
            _ => "projects:write",
        }
    }

    fn validate(&self, value: &Value) -> IamResult<Map<String, Value>> {
        let input = object(value)?;
        match self.0 {
            Endpoint::Create => {
                reject_unknown(input, &["tenantId", "name", "description"])?;
                let mut validated = scoped(input);
                validated.insert(
                    "name".into(),
                    Value::String(text(input.get("name"), "name")?),
                );
                if let Some(description) = optional_text(input.get("description"), "description")? {
                    validated.insert("description".into(), Value::String(description));
                }
                Ok(validated)
            }
            Endpoint::List => {
                reject_unknown(input, &["tenantId", "status"])?;
                let status = input.get("status").filter(|status| !status.is_null());
                if let Some(status) = status
                    && !["active", "archived"].contains(&js_string(Some(status)).as_str())
                {
                    return Err(invalid("status must be active or archived"));
                }
                let mut validated = scoped(input);
                if let Some(status) = status {
                    validated.insert("status".into(), Value::String(js_string(Some(status))));
                }
                Ok(validated)
            }
            Endpoint::Update => {
                reject_unknown(input, &["tenantId", "projectId", "name", "description"])?;
                if !input.contains_key("name") && !input.contains_key("description") {
                    return Err(invalid("Provide a name or description"));
                }
                let mut validated = scoped(input);
                validated.insert(
                    "projectId".into(),
                    Value::String(project_id(input.get("projectId"))?),
                );
                if input.contains_key("name") {
                    validated.insert(
                        "name".into(),
                        Value::String(text(input.get("name"), "name")?),
                    );
                }
                if input.contains_key("description") {
                    // An explicit empty description clears the field; absent leaves it unchanged.
                    match optional_text(input.get("description"), "description")? {
                        Some(description) => {
                            validated.insert("description".into(), Value::String(description));
                        }
                        None => {
                            validated.insert("clearDescription".into(), Value::Bool(true));
                        }
                    }
                }
                Ok(validated)
            }
            Endpoint::Get | Endpoint::Archive | Endpoint::Restore => {
                reject_unknown(input, &["tenantId", "projectId"])?;
                let mut validated = scoped(input);
                validated.insert(
                    "projectId".into(),
                    Value::String(project_id(input.get("projectId"))?),
                );
                Ok(validated)
            }
        }
    }

    fn resource(&self, input: &Map<String, Value>) -> Option<String> {
        match self.0 {
            Endpoint::Create | Endpoint::List => None,
            _ => Some(format!("project/{}", js_string(input.get("projectId")))),
        }
    }

    async fn handler(
        &self,
        context: PluginEndpointContext,
        input: Map<String, Value>,
    ) -> IamResult<Value> {
        let store = context.store.as_ref();
        let tenant_id = context.tenant_id.as_str();
        match self.0 {
            Endpoint::Create => {
                let name = js_string(input.get("name"));
                assert_name_available(store, tenant_id, &name, None).await?;
                let now = now();
                let mut record = Map::new();
                record.insert("id".into(), Value::String(uuid::Uuid::new_v4().to_string()));
                record.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
                record.insert("name".into(), Value::String(name));
                if truthy(input.get("description")) {
                    record.insert(
                        "description".into(),
                        Value::String(js_string(input.get("description"))),
                    );
                }
                record.insert("status".into(), Value::String("active".into()));
                record.insert(
                    "createdBy".into(),
                    Value::String(context.principal.identity.id.clone()),
                );
                record.insert("createdAt".into(), now.clone());
                record.insert("updatedAt".into(), now);
                Ok(Value::Object(store.insert(COLLECTION, &record).await?))
            }
            Endpoint::List => {
                let mut filter = Filter::new().eq("tenantId", tenant_id.to_owned());
                if truthy(input.get("status")) {
                    filter = filter.eq("status", js_string(input.get("status")));
                }
                let mut projects = tenant_projects(store, filter).await?;
                projects.sort_by(by_creation);
                Ok(Value::Array(
                    projects.into_iter().map(Value::Object).collect(),
                ))
            }
            Endpoint::Get => Ok(Value::Object(
                load(store, &js_string(input.get("projectId")), tenant_id).await?,
            )),
            Endpoint::Update => {
                let mut project =
                    load(store, &js_string(input.get("projectId")), tenant_id).await?;
                let id = js_string(project.get("id"));
                if input.contains_key("name") {
                    let name = js_string(input.get("name"));
                    assert_name_available(store, tenant_id, &name, Some(&id)).await?;
                    project.insert("name".into(), Value::String(name));
                }
                if truthy(input.get("clearDescription")) {
                    project.shift_remove("description");
                } else if input.contains_key("description") {
                    project.insert(
                        "description".into(),
                        Value::String(js_string(input.get("description"))),
                    );
                }
                project.insert("updatedAt".into(), now());
                Ok(Value::Object(store.put(COLLECTION, &project).await?))
            }
            Endpoint::Archive | Endpoint::Restore => {
                let mut project =
                    load(store, &js_string(input.get("projectId")), tenant_id).await?;
                let (from, to, message) = if self.0 == Endpoint::Archive {
                    ("active", "archived", "Project is not active")
                } else {
                    ("archived", "active", "Project is not archived")
                };
                if project.get("status").and_then(Value::as_str) != Some(from) {
                    return Err(IamError::new("INVALID_TRANSITION", message));
                }
                project.insert("status".into(), Value::String(to.into()));
                project.insert("updatedAt".into(), now());
                Ok(Value::Object(store.put(COLLECTION, &project).await?))
            }
        }
    }
}

/// The projects plugin (`createProjectsPlugin()`).
#[derive(Debug, Clone, Copy, Default)]
pub struct ProjectsPlugin;

#[async_trait::async_trait]
impl IamPlugin for ProjectsPlugin {
    fn id(&self) -> &str {
        PLUGIN_ID
    }

    fn actions(&self) -> Vec<String> {
        vec!["projects:read".into(), "projects:write".into()]
    }

    fn endpoints(&self) -> Vec<Arc<dyn PluginEndpoint>> {
        Endpoint::ALL
            .into_iter()
            .map(|endpoint| Arc::new(ProjectsEndpoint(endpoint)) as Arc<dyn PluginEndpoint>)
            .collect()
    }

    /// Runs inside the server's purge transaction before tenant records are removed.
    async fn purge(&self, store: &dyn IamStore, tenant_ids: &[String]) -> IamResult<()> {
        for tenant_id in tenant_ids {
            for project in
                tenant_projects(store, Filter::new().eq("tenantId", tenant_id.clone())).await?
            {
                store
                    .delete(COLLECTION, &js_string(project.get("id")))
                    .await?;
            }
        }
        Ok(())
    }
}

/// `createProjectsPlugin()`: the plugin, ready for `BetterIamOptions.plugins`.
pub fn create_projects_plugin() -> Arc<dyn IamPlugin> {
    Arc::new(ProjectsPlugin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn endpoint(kind: Endpoint) -> ProjectsEndpoint {
        ProjectsEndpoint(kind)
    }

    #[test]
    fn validates_create_input_like_the_typescript_plugin() {
        let create = endpoint(Endpoint::Create);
        let ok = create
            .validate(&json!({ "tenantId": "t", "name": "  Platform  ", "description": " Owned " }))
            .unwrap();
        assert_eq!(
            Value::Object(ok),
            json!({ "tenantId": "t", "name": "Platform", "description": "Owned" })
        );
        let error = create
            .validate(&json!({ "tenantId": "t", "name": "   " }))
            .unwrap_err();
        assert_eq!(error.message, "name must be 1-100 characters");
        let error = create.validate(&json!({ "tenantId": "t" })).unwrap_err();
        assert_eq!(error.message, "name is required");
        let error = create
            .validate(&json!({ "tenantId": "t", "name": "x", "owner": "forged" }))
            .unwrap_err();
        assert_eq!(error.message, "Unexpected field owner");
        let error = create.validate(&json!([])).unwrap_err();
        assert_eq!(error.message, "A JSON object is required");
        let error = create
            .validate(&json!({ "tenantId": "t", "name": "x", "description": 5 }))
            .unwrap_err();
        assert_eq!(error.message, "description must be text");
        let long = "d".repeat(501);
        let error = create
            .validate(&json!({ "tenantId": "t", "name": "x", "description": long }))
            .unwrap_err();
        assert_eq!(error.message, "description must be at most 500 characters");
        // An empty description is left out.
        let ok = create
            .validate(&json!({ "tenantId": "t", "name": "x", "description": " " }))
            .unwrap();
        assert!(!ok.contains_key("description"));
    }

    #[test]
    fn validates_list_update_and_project_ids() {
        let list = endpoint(Endpoint::List);
        assert_eq!(
            Value::Object(
                list.validate(&json!({ "tenantId": "t", "status": null }))
                    .unwrap()
            ),
            json!({ "tenantId": "t" })
        );
        assert_eq!(
            list.validate(&json!({ "tenantId": "t", "status": "gone" }))
                .unwrap_err()
                .message,
            "status must be active or archived"
        );
        let update = endpoint(Endpoint::Update);
        assert_eq!(
            update
                .validate(&json!({ "tenantId": "t", "projectId": "p" }))
                .unwrap_err()
                .message,
            "Provide a name or description"
        );
        assert_eq!(
            Value::Object(
                update
                    .validate(&json!({ "tenantId": "t", "projectId": "p", "description": "" }))
                    .unwrap()
            ),
            json!({ "tenantId": "t", "projectId": "p", "clearDescription": true })
        );
        let get = endpoint(Endpoint::Get);
        for bad in [json!("*"), json!("a/b"), json!(""), json!(5), Value::Null] {
            assert_eq!(
                get.validate(&json!({ "tenantId": "t", "projectId": bad }))
                    .unwrap_err()
                    .message,
                "projectId is required"
            );
        }
        let validated = get
            .validate(&json!({ "tenantId": "t", "projectId": "abc-1" }))
            .unwrap();
        assert_eq!(get.resource(&validated).as_deref(), Some("project/abc-1"));
        assert_eq!(endpoint(Endpoint::List).resource(&validated), None);
    }
}
