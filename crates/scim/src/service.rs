//! Port of `packages/scim/src/index.ts`: the SCIM 2.0 provisioning server: connection-scoped bearer tokens, Users and
//! Groups with RFC 7644 filtering, sorting, attribute projection, `/.search`, PATCH value paths, `/Bulk`, ETags and
//! pagination, explicit administrator-controlled group-to-role mappings, and the JSON administration API for
//! connections.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use base64::Engine;
use better_iam_core::{
    CredentialInput, Filter, IamError, IamResult, IamStoreExt, Record, ResourceRef, js as core_js,
};
use bytes::Bytes;
use serde_json::{Map, Value, json};

use crate::filter::{attribute_list, parse_scim_filter, project_resource, sort_resources};
use crate::js::{
    date_now, decode_uri_component, encode_uri_component, is_unexpected, js_string, locale_compare,
    number, random_bytes, random_uuid, truthy, unexpected,
};
use crate::provisioning::{Provisioning, create_provisioning, find, put_member};
use crate::resources::{
    HttpResponse, RESOURCE_TYPE_DOCUMENTS, SCHEMA_DOCUMENTS, SERVICE_PROVIDER_CONFIG,
    group_resource, http_response, list_response, response, user_resource,
};
use crate::types::{
    BULK_MAX_OPERATIONS, BULK_REQUEST_SCHEMA, BULK_RESPONSE_SCHEMA, ERROR_SCHEMA, MAX_PAYLOAD_SIZE,
    ObjectValue, ResourceType, SEARCH_SCHEMA, ScimConfig, Store,
};
use crate::validation::{active_tenant, fields, hash, object, required_text};

/// A buffered HTTP request.
pub type HttpRequest = http::Request<Bytes>;

/// A SCIM operation's result before it becomes an HTTP response or a bulk operation entry.
struct Outcome {
    status: u16,
    body: Value,
    headers: Vec<(&'static str, String)>,
}

impl Outcome {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// Query parameters of a request (`URLSearchParams`): `get` answers the first value.
#[derive(Debug, Clone, Default)]
struct Query(Vec<(String, String)>);

impl Query {
    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn value(&self, name: &str) -> Option<Value> {
        self.get(name).map(|value| Value::String(value.to_owned()))
    }
}

/// One Users/Groups/discovery request, from HTTP or from a bulk operation.
struct ScimRequest {
    method: String,
    resource_type: String,
    resource_id: Option<String>,
    body: Option<ObjectValue>,
    if_match: Option<String>,
    if_none_match: Option<String>,
    /// Query parameters (filter, sorting, paging, projection); bulk operations have none.
    query: Option<Query>,
}

struct ListQuery {
    filter: Option<String>,
    start_index: f64,
    count: f64,
    sort_by: Option<String>,
    sort_order: Option<String>,
    attributes: Option<Vec<String>>,
    excluded_attributes: Option<Vec<String>>,
}

/// The JSON parse failure of a request body (a `SyntaxError` in TypeScript).
fn syntax_outcome() -> Outcome {
    Outcome {
        status: 400,
        body: json!({
            "schemas": [ERROR_SCHEMA],
            "status": "400",
            "scimType": "invalidSyntax",
            "detail": "Invalid JSON.",
        }),
        headers: Vec::new(),
    }
}

fn error_outcome(error: &IamError) -> Outcome {
    if is_unexpected(error) {
        return Outcome {
            status: 500,
            body: json!({
                "schemas": [ERROR_SCHEMA],
                "status": "500",
                "scimType": "invalidSyntax",
                "detail": "The SCIM operation failed.",
            }),
            headers: Vec::new(),
        };
    }
    Outcome {
        status: error.status,
        body: json!({
            "schemas": [ERROR_SCHEMA],
            "status": error.status.to_string(),
            "scimType": error.code,
            "detail": error.message,
        }),
        headers: Vec::new(),
    }
}

fn to_response(outcome: &Outcome) -> HttpResponse {
    response(&outcome.body, outcome.status, &outcome.headers)
}

const ADMIN_MAX_BODY: usize = 64 * 1024;

/// `Number(value)` of a query or body value, for pagination.
fn to_number(value: &Value) -> f64 {
    core_js::to_number(value)
}

fn pagination(start_index: Option<&Value>, count: Option<&Value>) -> IamResult<(f64, f64)> {
    let start = match start_index {
        None | Some(Value::Null) => 1.0,
        Some(value) => to_number(value),
    };
    let size = match count {
        None | Some(Value::Null) => 100.0,
        Some(value) => to_number(value),
    };
    let integer = |value: f64| value.is_finite() && value.fract() == 0.0;
    if !integer(start) || start < 1.0 || !integer(size) || size < 0.0 {
        return Err(IamError::new("invalidValue", "Invalid pagination."));
    }
    Ok((start, size.min(200.0)))
}

fn query_from_url(params: &Query) -> IamResult<ListQuery> {
    let filter = params.get("filter").map(str::to_owned);
    let (start_index, count) = pagination(
        params.value("startIndex").as_ref(),
        params.value("count").as_ref(),
    )?;
    Ok(ListQuery {
        filter,
        start_index,
        count,
        sort_by: params.get("sortBy").map(str::to_owned),
        sort_order: params.get("sortOrder").map(str::to_owned),
        attributes: attribute_list(params.value("attributes").as_ref())?,
        excluded_attributes: attribute_list(params.value("excludedAttributes").as_ref())?,
    })
}

/// POST `/.search` (RFC 7644 §3.4.3) carries the query in a SearchRequest body.
fn query_from_body(body: &ObjectValue) -> IamResult<ListQuery> {
    fields(
        body,
        &[
            "schemas",
            "filter",
            "startIndex",
            "count",
            "sortBy",
            "sortOrder",
            "attributes",
            "excludedAttributes",
        ],
    )?;
    match body.get("schemas") {
        Some(Value::Array(schemas)) if schemas.len() == 1 && schemas[0] == json!(SEARCH_SCHEMA) => {
        }
        _ => {
            return Err(IamError::new(
                "invalidSyntax",
                "A SearchRequest body is required.",
            ));
        }
    }
    for key in ["filter", "sortBy", "sortOrder"] {
        if let Some(value) = body.get(key)
            && !value.is_string()
        {
            return Err(IamError::new(
                "invalidValue",
                format!("{key} must be a string."),
            ));
        }
    }
    let string = |key: &str| body.get(key).and_then(Value::as_str).map(str::to_owned);
    let (start_index, count) = pagination(body.get("startIndex"), body.get("count"))?;
    Ok(ListQuery {
        filter: string("filter"),
        start_index,
        count,
        sort_by: string("sortBy"),
        sort_order: string("sortOrder"),
        attributes: attribute_list(body.get("attributes"))?,
        excluded_attributes: attribute_list(body.get("excludedAttributes"))?,
    })
}

/// `headers.get(name)` of a fetch `Headers`: every value of the name joined with ", ".
fn header(request: &HttpRequest, name: &str) -> Option<String> {
    let values: Vec<String> = request
        .headers()
        .get_all(name)
        .iter()
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

/// The request credential: its headers (`{ headers: request.headers }`).
fn credential_of(request: &HttpRequest) -> CredentialInput {
    CredentialInput {
        headers: Some(
            request
                .headers()
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_str().to_owned(),
                        String::from_utf8_lossy(value.as_bytes()).into_owned(),
                    )
                })
                .collect(),
        ),
        token: None,
    }
}

/// `new URL(request.url)`: the request's absolute target, or its path on the `Host` it names.
pub(crate) fn request_url(request: &HttpRequest) -> Option<url::Url> {
    let uri = request.uri();
    if uri.scheme().is_some() && uri.authority().is_some() {
        return url::Url::parse(&uri.to_string()).ok();
    }
    let host = header(request, "host").unwrap_or_else(|| "localhost".to_owned());
    let target = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    url::Url::parse(&format!("http://{host}{target}")).ok()
}

/// `url.origin`.
pub(crate) fn url_origin(url: &url::Url) -> String {
    url.origin().ascii_serialization()
}

fn url_query(url: &url::Url) -> Query {
    Query(
        url.query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect(),
    )
}

/// The members of a JSON input object (`input.key`).
fn member<'a>(input: &'a Value, key: &str) -> Option<&'a Value> {
    input.as_object().and_then(|map| map.get(key))
}

/// A string member, or "" for anything else (the resource reference of the authorization call).
fn string_member(input: &Value, key: &str) -> String {
    member(input, key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn bulk_id_valid(value: &str) -> bool {
    let count = value.chars().count();
    (1..=64).contains(&count)
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// The `bulkId:` references of a serialized operation, in order (`/bulkId:([\w.-]+)/g`).
fn bulk_references(serialized: &str) -> Vec<(usize, usize, String)> {
    let mut found = Vec::new();
    let mut search = 0;
    while let Some(offset) = serialized[search..].find("bulkId:") {
        let start = search + offset;
        let rest = &serialized[start + 7..];
        let length = rest
            .char_indices()
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')))
            .map(|(index, _)| index)
            .unwrap_or(rest.len());
        if length == 0 {
            search = start + 7;
            continue;
        }
        found.push((start, start + 7 + length, rest[..length].to_owned()));
        search = start + 7 + length;
    }
    found
}

/// A parsed bulk operation.
#[derive(Clone)]
struct BulkOperation {
    method: String,
    bulk_id: Option<String>,
    path: String,
    data: Option<Value>,
    version: Option<String>,
}

struct Inner {
    config: ScimConfig,
    store: Store,
    base_path: String,
    admin_base_path: String,
    provisioning: Provisioning,
}

/// The SCIM 2.0 provisioning server (`createScimService(config)`). Cheap to clone.
#[derive(Clone)]
pub struct ScimService {
    inner: Arc<Inner>,
}

/// `createScimService(config)`.
pub fn create_scim_service(config: ScimConfig) -> IamResult<ScimService> {
    ScimService::new(config)
}

fn trim_trailing_slash(value: &str) -> String {
    value.strip_suffix('/').unwrap_or(value).to_owned()
}

impl ScimService {
    /// `createScimService(config)`.
    pub fn new(config: ScimConfig) -> IamResult<Self> {
        let base_path = trim_trailing_slash(config.base_path.as_deref().unwrap_or("/scim/v2"));
        if !base_path.starts_with('/') {
            return Err(IamError::new(
                "configuration",
                "SCIM basePath must be absolute.",
            ));
        }
        let admin_base_path =
            trim_trailing_slash(config.admin_base_path.as_deref().unwrap_or("/scim/admin"));
        if !admin_base_path.starts_with('/') {
            return Err(IamError::new(
                "configuration",
                "SCIM adminBasePath must be absolute.",
            ));
        }
        if admin_base_path == base_path
            || admin_base_path.starts_with(&format!("{base_path}/"))
            || base_path.starts_with(&format!("{admin_base_path}/"))
        {
            return Err(IamError::new(
                "configuration",
                "SCIM adminBasePath must not overlap basePath.",
            ));
        }
        let provisioning = create_provisioning(&config)?;
        Ok(Self {
            inner: Arc::new(Inner {
                store: config.store.clone(),
                config,
                base_path,
                admin_base_path,
                provisioning,
            }),
        })
    }

    /// `basePath`.
    pub fn base_path(&self) -> &str {
        &self.inner.base_path
    }

    /// `adminBasePath`.
    pub fn admin_base_path(&self) -> &str {
        &self.inner.admin_base_path
    }

    fn lifetime(expires_in: Option<&Value>) -> IamResult<f64> {
        let seconds = match expires_in {
            None | Some(Value::Null) => Some(90.0 * 86400.0),
            Some(Value::Number(value)) => Some(core_js::number_value(value)),
            Some(_) => None,
        };
        match seconds {
            Some(seconds)
                if seconds.is_finite()
                    && seconds.fract() == 0.0
                    && (60.0..=365.0 * 86400.0).contains(&seconds) =>
            {
                Ok(seconds)
            }
            _ => Err(IamError::new(
                "invalidValue",
                "Credential lifetime must be between 60 seconds and one year.",
            )),
        }
    }

    fn new_token() -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes(32))
    }

    async fn authorize(
        &self,
        credential: &CredentialInput,
        action: &str,
        tenant_id: &str,
        id: &str,
    ) -> IamResult<()> {
        (self.inner.config.authorize)(
            credential.clone(),
            action.to_owned(),
            ResourceRef {
                tenant_id: tenant_id.to_owned(),
                kind: "scim".to_owned(),
                id: id.to_owned(),
            },
        )
        .await
    }

    async fn authenticate(&self, credential: &CredentialInput) -> IamResult<String> {
        (self.inner.config.authenticate)(credential.clone()).await
    }

    fn summary(&self, connection: &Record, users: usize, groups: usize) -> Value {
        let mut map = Map::new();
        put_member(&mut map, "id", connection.get("id"));
        put_member(&mut map, "tenantId", connection.get("tenantId"));
        put_member(&mut map, "name", connection.get("name"));
        map.insert(
            "path".into(),
            json!(format!(
                "{}/{}",
                self.inner.base_path,
                js_string(connection.get("id"))
            )),
        );
        put_member(&mut map, "expiresAt", connection.get("expiresAt"));
        put_member(&mut map, "revoked", connection.get("revoked"));
        put_member(&mut map, "createdAt", connection.get("createdAt"));
        put_member(&mut map, "lastUsedAt", connection.get("lastUsedAt"));
        put_member(&mut map, "rotatedAt", connection.get("rotatedAt"));
        map.insert("users".into(), json!(users));
        map.insert("groups".into(), json!(groups));
        put_member(&mut map, "roleMappings", connection.get("roleMappings"));
        Value::Object(map)
    }

    /// `createConnection(credential, { tenantId, name, expiresIn? })`: issues a connection-scoped bearer token; the
    /// plaintext is returned once and stored only as a hash. Answers `{ id, tenantId, token, expiresAt, path }`.
    pub async fn create_connection(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Value> {
        let name = required_text(member(input, "name"), "name")?;
        let expires_in = Self::lifetime(member(input, "expiresIn"))?;
        let token = Self::new_token();
        let tenant_id = string_member(input, "tenantId");
        let mut connection = Map::new();
        connection.insert("id".into(), json!(random_uuid()));
        put_member(&mut connection, "tenantId", member(input, "tenantId"));
        connection.insert("name".into(), json!(name));
        connection.insert("tokenHash".into(), json!(hash(&token)));
        connection.insert("expiresAt".into(), number(date_now() + expires_in * 1000.0));
        connection.insert("revoked".into(), json!(false));
        connection.insert("roleMappings".into(), json!({}));
        connection.insert("createdAt".into(), number(date_now()));
        let this = self.clone();
        let record = connection.clone();
        self.inner
            .store
            .transaction(move |tx| async move {
                this.authorize(credential, "iam:scim:connections:create", &tenant_id, "*")
                    .await?;
                let principal = this.authenticate(credential).await?;
                active_tenant(tx.as_ref(), &tenant_id).await?;
                tx.insert("scimConnections", &record).await?;
                let id = js_string(record.get("id"));
                this.inner
                    .provisioning
                    .audit(
                        &tx,
                        &record,
                        "iam:scim:CreateConnection",
                        &id,
                        Some(&principal),
                    )
                    .await
            })
            .await?;
        let id = js_string(connection.get("id"));
        let mut result = Map::new();
        result.insert("id".into(), json!(id));
        put_member(&mut result, "tenantId", connection.get("tenantId"));
        result.insert("token".into(), json!(token));
        put_member(&mut result, "expiresAt", connection.get("expiresAt"));
        result.insert(
            "path".into(),
            json!(format!("{}/{id}", self.inner.base_path)),
        );
        Ok(Value::Object(result))
    }

    /// `listConnections(credential, { tenantId })`: a tenant's connections with usage metadata and provisioned counts;
    /// tokens are never returned.
    pub async fn list_connections(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Value> {
        let tenant_id = string_member(input, "tenantId");
        let this = self.clone();
        self.inner
            .store
            .transaction(move |tx| async move {
                this.authorize(credential, "iam:scim:connections:read", &tenant_id, "*")
                    .await?;
                let filter = || Filter::new().eq("tenantId", tenant_id.clone());
                let mut connections = find(tx.as_ref(), "scimConnections", filter()).await?;
                let users = find(tx.as_ref(), "scimUsers", filter()).await?;
                let groups = find(tx.as_ref(), "scimGroups", filter()).await?;
                let created = |record: &Record| match record.get("createdAt") {
                    Some(Value::Number(value)) => core_js::number_value(value),
                    _ => 0.0,
                };
                connections.sort_by(|a, b| {
                    let difference = created(a) - created(b);
                    if difference != 0.0 && !difference.is_nan() {
                        return difference
                            .partial_cmp(&0.0)
                            .unwrap_or(std::cmp::Ordering::Equal);
                    }
                    locale_compare(&js_string(a.get("id")), &js_string(b.get("id")))
                });
                Ok(Value::Array(
                    connections
                        .iter()
                        .map(|connection| {
                            let id = connection.get("id");
                            this.summary(
                                connection,
                                users
                                    .iter()
                                    .filter(|row| row.get("connectionId") == id)
                                    .count(),
                                groups
                                    .iter()
                                    .filter(|row| row.get("connectionId") == id)
                                    .count(),
                            )
                        })
                        .collect(),
                ))
            })
            .await
    }

    /// `rotateToken(credential, { tenantId, connectionId, expiresIn? })`: replaces the connection's bearer token: the
    /// old token stops working immediately, provisioned users, groups and role mappings are kept, and the new token is
    /// returned once.
    pub async fn rotate_token(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Value> {
        let expires_in = Self::lifetime(member(input, "expiresIn"))?;
        let token = Self::new_token();
        let tenant_id = string_member(input, "tenantId");
        let connection_id = string_member(input, "connectionId");
        let this = self.clone();
        self.inner
            .store
            .transaction(move |tx| async move {
                this.authorize(
                    credential,
                    "iam:scim:credentials:create",
                    &tenant_id,
                    &connection_id,
                )
                .await?;
                let principal = this.authenticate(credential).await?;
                let connection = tx.get("scimConnections", &connection_id).await?;
                let Some(connection) = connection.filter(|connection| {
                    connection.get("tenantId").and_then(Value::as_str) == Some(tenant_id.as_str())
                }) else {
                    return Err(IamError::with_status(
                        "notFound",
                        "Connection not found.",
                        404,
                    ));
                };
                if truthy(connection.get("revoked")) {
                    return Err(IamError::with_status(
                        "CONFLICT",
                        "A revoked connection cannot be rotated.",
                        409,
                    ));
                }
                active_tenant(tx.as_ref(), &tenant_id).await?;
                let now = date_now();
                let mut rotated = connection.clone();
                rotated.insert("tokenHash".into(), json!(hash(&token)));
                rotated.insert("expiresAt".into(), number(now + expires_in * 1000.0));
                rotated.insert("rotatedAt".into(), number(now));
                tx.put("scimConnections", &rotated).await?;
                let id = js_string(rotated.get("id"));
                this.inner
                    .provisioning
                    .audit(&tx, &rotated, "iam:scim:RotateToken", &id, Some(&principal))
                    .await?;
                let mut result = Map::new();
                result.insert("id".into(), json!(id));
                put_member(&mut result, "tenantId", rotated.get("tenantId"));
                result.insert("token".into(), json!(token));
                put_member(&mut result, "expiresAt", rotated.get("expiresAt"));
                result.insert(
                    "path".into(),
                    json!(format!("{}/{id}", this.inner.base_path)),
                );
                Ok(Value::Object(result))
            })
            .await
    }

    /// `revokeConnection(credential, { tenantId, connectionId })`: invalidates the token immediately and removes the
    /// bindings its role mappings created.
    pub async fn revoke_connection(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<()> {
        let tenant_id = string_member(input, "tenantId");
        let connection_id = string_member(input, "connectionId");
        let this = self.clone();
        self.inner
            .store
            .transaction(move |tx| async move {
                this.authorize(
                    credential,
                    "iam:scim:connections:delete",
                    &tenant_id,
                    &connection_id,
                )
                .await?;
                let principal = this.authenticate(credential).await?;
                let connection = tx.get("scimConnections", &connection_id).await?;
                let Some(connection) = connection.filter(|connection| {
                    connection.get("tenantId").and_then(Value::as_str) == Some(tenant_id.as_str())
                }) else {
                    return Err(IamError::with_status(
                        "notFound",
                        "Connection not found.",
                        404,
                    ));
                };
                let mut revoked = connection.clone();
                revoked.insert("revoked".into(), json!(true));
                tx.put("scimConnections", &revoked).await?;
                for binding in find(
                    tx.as_ref(),
                    "bindings",
                    Filter::new().eq("tenantId", tenant_id.clone()).eq(
                        "scimConnectionId",
                        connection.get("id").cloned().unwrap_or(Value::Null),
                    ),
                )
                .await?
                {
                    tx.delete("bindings", &js_string(binding.get("id"))).await?;
                }
                let id = js_string(connection.get("id"));
                this.inner
                    .provisioning
                    .audit(
                        &tx,
                        &connection,
                        "iam:scim:RevokeConnection",
                        &id,
                        Some(&principal),
                    )
                    .await
            })
            .await
    }

    /// `listGroups(credential, { tenantId, connectionId })`: the groups the IdP pushed through a connection, by name,
    /// with member counts and mapped roles.
    pub async fn list_groups(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Value> {
        let tenant_id = string_member(input, "tenantId");
        let connection_id = string_member(input, "connectionId");
        let this = self.clone();
        self.inner
            .store
            .transaction(move |tx| async move {
                this.authorize(
                    credential,
                    "iam:scim:connections:read",
                    &tenant_id,
                    &connection_id,
                )
                .await?;
                let connection = tx.get("scimConnections", &connection_id).await?;
                let Some(connection) = connection.filter(|connection| {
                    connection.get("tenantId").and_then(Value::as_str) == Some(tenant_id.as_str())
                }) else {
                    return Err(IamError::with_status(
                        "notFound",
                        "Connection not found.",
                        404,
                    ));
                };
                let mut groups = find(
                    tx.as_ref(),
                    "scimGroups",
                    Filter::new().eq("tenantId", tenant_id.clone()).eq(
                        "connectionId",
                        connection.get("id").cloned().unwrap_or(Value::Null),
                    ),
                )
                .await?;
                groups.sort_by(|a, b| {
                    locale_compare(
                        &js_string(a.get("displayName")),
                        &js_string(b.get("displayName")),
                    )
                    .then_with(|| locale_compare(&js_string(a.get("id")), &js_string(b.get("id"))))
                });
                let mappings = connection.get("roleMappings").and_then(Value::as_object);
                Ok(Value::Array(
                    groups
                        .iter()
                        .map(|group| {
                            let mut map = Map::new();
                            put_member(&mut map, "id", group.get("id"));
                            put_member(&mut map, "groupId", group.get("groupId"));
                            put_member(&mut map, "displayName", group.get("displayName"));
                            put_member(&mut map, "externalId", group.get("externalId"));
                            map.insert(
                                "members".into(),
                                json!(
                                    group
                                        .get("members")
                                        .and_then(Value::as_array)
                                        .map_or(0, Vec::len)
                                ),
                            );
                            let roles = mappings
                                .and_then(|mappings| mappings.get(&js_string(group.get("id"))))
                                .and_then(Value::as_array)
                                .cloned()
                                .unwrap_or_default();
                            map.insert("roleIds".into(), Value::Array(roles));
                            Value::Object(map)
                        })
                        .collect(),
                ))
            })
            .await
    }

    /// `setRoleMappings(credential, { tenantId, connectionId, groupId, roleIds })`: maps a SCIM group to roles; the
    /// administrator must hold `iam:bindings:create` on every role.
    pub async fn set_role_mappings(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<()> {
        if self.inner.config.sync_role_mappings.is_none() {
            return Err(IamError::new(
                "configuration",
                "Role mapping callback is required.",
            ));
        }
        let role_ids: Vec<String> = match member(input, "roleIds") {
            Some(Value::Array(items))
                if items.len() <= 100
                    && items
                        .iter()
                        .all(|item| matches!(item, Value::String(text) if !text.is_empty())) =>
            {
                items.iter().map(|item| js_string(Some(item))).collect()
            }
            _ => {
                return Err(IamError::new(
                    "invalidValue",
                    "roleIds must list at most 100 role IDs.",
                ));
            }
        };
        let tenant_id = string_member(input, "tenantId");
        let connection_id = string_member(input, "connectionId");
        let group_id = string_member(input, "groupId");
        let this = self.clone();
        self.inner
            .store
            .transaction(move |tx| async move {
                this.authorize(
                    credential,
                    "iam:scim:mappings:update",
                    &tenant_id,
                    &connection_id,
                )
                .await?;
                let principal = this.authenticate(credential).await?;
                let connection = tx.get("scimConnections", &connection_id).await?;
                let group = tx.get("scimGroups", &group_id).await?;
                let (Some(mut connection), Some(group)) = (connection, group) else {
                    return Err(IamError::with_status(
                        "notFound",
                        "Connection or group not found.",
                        404,
                    ));
                };
                if connection.get("tenantId").and_then(Value::as_str) != Some(tenant_id.as_str())
                    || group.get("connectionId") != connection.get("id")
                {
                    return Err(IamError::with_status(
                        "notFound",
                        "Connection or group not found.",
                        404,
                    ));
                }
                for role_id in &role_ids {
                    let role = tx.get("roles", role_id).await?;
                    let available = role.as_ref().is_some_and(|role| {
                        role.get("tenantId").and_then(Value::as_str) == Some(tenant_id.as_str())
                            && role.get("protected") != Some(&Value::Bool(true))
                    });
                    if !available {
                        return Err(IamError::new("invalidValue", "Role is unavailable."));
                    }
                    (this.inner.config.authorize)(
                        credential.clone(),
                        "iam:bindings:create".to_owned(),
                        ResourceRef {
                            tenant_id: tenant_id.clone(),
                            kind: "iam".to_owned(),
                            id: role_id.clone(),
                        },
                    )
                    .await?;
                }
                let mut unique: Vec<String> = Vec::new();
                for role_id in &role_ids {
                    if !unique.contains(role_id) {
                        unique.push(role_id.clone());
                    }
                }
                let mut mappings = connection
                    .get("roleMappings")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                mappings.insert(group_id.clone(), json!(unique));
                connection.insert("roleMappings".into(), Value::Object(mappings));
                tx.put("scimConnections", &connection).await?;
                this.inner
                    .provisioning
                    .sync_group(&tx, &connection, &group, Some(credential))
                    .await?;
                let id = js_string(group.get("id"));
                this.inner
                    .provisioning
                    .audit(
                        &tx,
                        &connection,
                        "iam:scim:SetRoleMappings",
                        &id,
                        Some(&principal),
                    )
                    .await
            })
            .await
    }

    async fn perform(
        &self,
        tx: &Store,
        connection: &Record,
        base: &str,
        request: &ScimRequest,
    ) -> IamResult<Outcome> {
        let method = request.method.as_str();
        let resource_type = request.resource_type.as_str();
        let resource_id = request.resource_id.as_deref();
        if method == "GET" && resource_type == "ServiceProviderConfig" {
            return Ok(Outcome {
                status: 200,
                body: SERVICE_PROVIDER_CONFIG.clone(),
                headers: Vec::new(),
            });
        }
        if method == "GET" && (resource_type == "ResourceTypes" || resource_type == "Schemas") {
            let resources: &Vec<Value> = if resource_type == "ResourceTypes" {
                &RESOURCE_TYPE_DOCUMENTS
            } else {
                &SCHEMA_DOCUMENTS
            };
            if let Some(resource_id) = resource_id.filter(|id| !id.is_empty()) {
                let Some(resource) = resources
                    .iter()
                    .find(|row| row.get("id").and_then(Value::as_str) == Some(resource_id))
                else {
                    return Err(IamError::with_status("notFound", "Schema not found.", 404));
                };
                return Ok(Outcome {
                    status: 200,
                    body: resource.clone(),
                    headers: Vec::new(),
                });
            }
            return Ok(Outcome {
                status: 200,
                body: list_response(resources.clone(), resources.len(), 1.0),
                headers: Vec::new(),
            });
        }
        let Some(kind) = ResourceType::parse(resource_type) else {
            return Err(IamError::with_status(
                "notFound",
                "Unsupported SCIM resource.",
                404,
            ));
        };
        let collection = match kind {
            ResourceType::Users => "scimUsers",
            ResourceType::Groups => "scimGroups",
        };
        let render = |row: &Record| -> IamResult<ObjectValue> {
            match kind {
                ResourceType::Users => user_resource(row, base),
                ResourceType::Groups => group_resource(row, base),
            }
        };
        let (projection_attributes, projection_excluded) = match &request.query {
            Some(query) => (
                attribute_list(query.value("attributes").as_ref())?,
                attribute_list(query.value("excludedAttributes").as_ref())?,
            ),
            None => (None, None),
        };
        let present = |row: &Record| -> IamResult<Value> {
            Ok(Value::Object(project_resource(
                &render(row)?,
                projection_attributes.as_deref(),
                projection_excluded.as_deref(),
            )?))
        };

        let search = resource_id == Some(".search");
        let listing = (method == "GET" && resource_id.is_none_or(str::is_empty))
            || (method == "POST" && search);
        if listing {
            let query = if search {
                query_from_body(request.body.as_ref().unwrap_or(&ObjectValue::new()))?
            } else {
                query_from_url(request.query.as_ref().unwrap_or(&Query::default()))?
            };
            let mut rows = find(
                tx.as_ref(),
                collection,
                Filter::new()
                    .eq(
                        "tenantId",
                        connection.get("tenantId").cloned().unwrap_or(Value::Null),
                    )
                    .eq(
                        "connectionId",
                        connection.get("id").cloned().unwrap_or(Value::Null),
                    ),
            )
            .await?;
            rows.sort_by(|a, b| locale_compare(&js_string(a.get("id")), &js_string(b.get("id"))));
            let rendered = rows
                .iter()
                .map(|row| render(row).map(Value::Object))
                .collect::<IamResult<Vec<Value>>>()?;
            let predicate = parse_scim_filter(query.filter.as_deref())?;
            let filtered: Vec<Value> = rendered
                .into_iter()
                .filter(|value| predicate(value))
                .collect();
            let matches = sort_resources(
                filtered,
                query.sort_by.as_deref(),
                query.sort_order.as_deref(),
            )?;
            let start = (query.start_index - 1.0) as usize;
            let end = start.saturating_add(query.count as usize);
            let page: Vec<Value> = matches
                .iter()
                .skip(start)
                .take(end.saturating_sub(start))
                .map(|resource| {
                    project_resource(
                        resource
                            .as_object()
                            .expect("rendered resources are objects"),
                        query.attributes.as_deref(),
                        query.excluded_attributes.as_deref(),
                    )
                    .map(Value::Object)
                })
                .collect::<IamResult<Vec<Value>>>()?;
            return Ok(Outcome {
                status: 200,
                body: list_response(page, matches.len(), query.start_index),
                headers: Vec::new(),
            });
        }
        if search {
            return Err(IamError::with_status(
                "invalidMethod",
                "/.search accepts POST only.",
                405,
            ));
        }

        let resource_id = resource_id.filter(|id| !id.is_empty());
        let row = match resource_id {
            Some(id) => tx.get(collection, id).await?,
            None => None,
        };
        if resource_id.is_some() {
            let owned = row.as_ref().is_some_and(|row| {
                row.get("tenantId") == connection.get("tenantId")
                    && row.get("connectionId") == connection.get("id")
            });
            if !owned {
                return Err(IamError::with_status(
                    "notFound",
                    "Resource not found.",
                    404,
                ));
            }
        }
        let etag_of = |row: &Record| format!("W/\"{}\"", js_string(row.get("version")));
        if let (Some(row), Some(if_match)) = (&row, request.if_match.as_deref())
            && !if_match.is_empty()
            && if_match != "*"
            && if_match != etag_of(row)
        {
            return Err(IamError::with_status(
                "invalidVers",
                "Version conflict.",
                412,
            ));
        }
        if method == "GET"
            && let Some(row) = &row
        {
            let etag = etag_of(row);
            if request.if_none_match.as_deref() == Some(etag.as_str())
                || request.if_none_match.as_deref() == Some("*")
            {
                return Ok(Outcome {
                    status: 304,
                    body: Value::Null,
                    headers: vec![("etag", etag)],
                });
            }
            return Ok(Outcome {
                status: 200,
                body: present(row)?,
                headers: vec![("etag", etag)],
            });
        }
        let provisioning = &self.inner.provisioning;
        let empty = ObjectValue::new();
        let body = request.body.as_ref().unwrap_or(&empty);
        if method == "POST" && resource_id.is_none() {
            let saved = match kind {
                ResourceType::Users => provisioning.save_user(tx, connection, body, None).await?,
                ResourceType::Groups => provisioning.save_group(tx, connection, body, None).await?,
            };
            return Ok(Outcome {
                status: 201,
                body: present(&saved)?,
                headers: vec![
                    (
                        "location",
                        format!("{base}/{resource_type}/{}", js_string(saved.get("id"))),
                    ),
                    ("etag", etag_of(&saved)),
                ],
            });
        }
        if let Some(row) = &row
            && (method == "PUT" || method == "PATCH")
        {
            let saved = if method == "PATCH" {
                provisioning.patch(tx, connection, kind, row, body).await?
            } else {
                match kind {
                    ResourceType::Users => {
                        provisioning
                            .save_user(tx, connection, body, Some(row))
                            .await?
                    }
                    ResourceType::Groups => {
                        provisioning
                            .save_group(tx, connection, body, Some(row))
                            .await?
                    }
                }
            };
            return Ok(Outcome {
                status: 200,
                body: present(&saved)?,
                headers: vec![
                    (
                        "location",
                        format!("{base}/{resource_type}/{}", js_string(saved.get("id"))),
                    ),
                    ("etag", etag_of(&saved)),
                ],
            });
        }
        if let Some(row) = &row
            && method == "DELETE"
        {
            match kind {
                ResourceType::Users => provisioning.delete_user(tx, connection, row).await?,
                ResourceType::Groups => provisioning.delete_group(tx, connection, row).await?,
            }
            let id = js_string(row.get("id"));
            tx.delete(collection, &id).await?;
            provisioning
                .audit(
                    tx,
                    connection,
                    match kind {
                        ResourceType::Users => "iam:scim:DeleteUser",
                        ResourceType::Groups => "iam:scim:DeleteGroup",
                    },
                    &id,
                    None,
                )
                .await?;
            return Ok(Outcome {
                status: 204,
                body: Value::Null,
                headers: Vec::new(),
            });
        }
        Err(IamError::with_status(
            "invalidMethod",
            "Method is not supported for this resource.",
            405,
        ))
    }

    /// Runs one request in its own transaction, so a failed bulk operation never leaves partial writes.
    async fn run(
        &self,
        authorization: Option<&str>,
        connection_id: &str,
        base: &str,
        request: &ScimRequest,
    ) -> IamResult<Outcome> {
        let this = self.clone();
        let authorization = authorization.map(str::to_owned);
        self.inner
            .store
            .transaction(move |tx| async move {
                let connection = this
                    .inner
                    .provisioning
                    .authenticate(&tx, authorization.as_deref(), connection_id)
                    .await?;
                this.perform(&tx, &connection, base, request).await
            })
            .await
    }

    /// RFC 7644 §3.7 bulk: each operation commits independently; `bulkId:` references resolve to resources created
    /// earlier in the request in any order, and `failOnErrors` stops processing after that many failures.
    async fn bulk(
        &self,
        authorization: Option<&str>,
        connection_id: &str,
        base: &str,
        body: &ObjectValue,
    ) -> IamResult<Outcome> {
        fields(body, &["schemas", "Operations", "failOnErrors"])?;
        match body.get("schemas") {
            Some(Value::Array(schemas))
                if schemas.len() == 1 && schemas[0] == json!(BULK_REQUEST_SCHEMA) => {}
            _ => {
                return Err(IamError::new(
                    "invalidSyntax",
                    "A BulkRequest body is required.",
                ));
            }
        }
        let items = match body.get("Operations") {
            Some(Value::Array(items)) if !items.is_empty() => items,
            _ => {
                return Err(IamError::new(
                    "invalidSyntax",
                    "Bulk requests require at least one operation.",
                ));
            }
        };
        if items.len() > BULK_MAX_OPERATIONS {
            return Err(IamError::with_status(
                "tooMany",
                format!("Bulk requests accept at most {BULK_MAX_OPERATIONS} operations."),
                413,
            ));
        }
        let fail_on_errors = match body.get("failOnErrors") {
            None => None,
            Some(Value::Number(value))
                if core_js::number_value(value).is_finite()
                    && core_js::number_value(value).fract() == 0.0
                    && core_js::number_value(value) >= 1.0 =>
            {
                Some(core_js::number_value(value))
            }
            Some(_) => {
                return Err(IamError::new(
                    "invalidValue",
                    "failOnErrors must be a positive integer.",
                ));
            }
        };
        // An invalid credential fails the whole request rather than every operation individually.
        {
            let this = self.clone();
            let authorization = authorization.map(str::to_owned);
            let connection_id = connection_id.to_owned();
            self.inner
                .store
                .transaction(move |tx| async move {
                    this.inner
                        .provisioning
                        .authenticate(&tx, authorization.as_deref(), &connection_id)
                        .await
                        .map(|_| ())
                })
                .await?;
        }

        let mut declared: HashSet<String> = HashSet::new();
        let mut operations: Vec<BulkOperation> = Vec::new();
        for (index, item) in items.iter().enumerate() {
            let op = object(Some(item))?;
            fields(op, &["method", "bulkId", "path", "data", "version"])?;
            let method = match op.get("method") {
                Some(Value::String(text)) => text.to_uppercase(),
                _ => String::new(),
            };
            if !["POST", "PUT", "PATCH", "DELETE"].contains(&method.as_str()) {
                return Err(IamError::new(
                    "invalidSyntax",
                    format!("Operation {} has an unsupported method.", index + 1),
                ));
            }
            let path = required_text(op.get("path"), "path")?;
            let bulk_id = match op.get("bulkId") {
                None => None,
                Some(value) => Some(required_text(Some(value), "bulkId")?),
            };
            if let Some(bulk_id) = &bulk_id {
                if !bulk_id_valid(bulk_id) || declared.contains(bulk_id) {
                    return Err(IamError::new(
                        "invalidValue",
                        format!("bulkId \"{bulk_id}\" is invalid or duplicated."),
                    ));
                }
                declared.insert(bulk_id.clone());
            }
            if method == "POST" && bulk_id.is_none() {
                return Err(IamError::new(
                    "invalidSyntax",
                    "POST operations require a bulkId.",
                ));
            }
            if method != "DELETE" && op.get("data").is_none() {
                return Err(IamError::new(
                    "invalidSyntax",
                    format!("{method} operations require data."),
                ));
            }
            let version = match op.get("version") {
                None => None,
                Some(value) => Some(required_text(Some(value), "version")?),
            };
            operations.push(BulkOperation {
                method,
                bulk_id,
                path,
                data: op.get("data").cloned(),
                version,
            });
        }

        let mut created: HashMap<String, String> = HashMap::new();
        let mut failed: HashSet<String> = HashSet::new();
        let mut results: Vec<Value> = Vec::new();
        let mut errors = 0usize;
        let mut pending = operations;
        let stopped = |errors: usize| fail_on_errors.is_some_and(|limit| errors as f64 >= limit);
        let mut record = |operation: &BulkOperation,
                          outcome: Outcome,
                          errors: &mut usize,
                          created: &mut HashMap<String, String>,
                          failed: &mut HashSet<String>| {
            let mut entry = Map::new();
            entry.insert("method".into(), json!(operation.method));
            entry.insert("status".into(), json!(outcome.status.to_string()));
            if let Some(bulk_id) = &operation.bulk_id {
                entry.insert("bulkId".into(), json!(bulk_id));
            }
            if let Some(location) = outcome.header("location").filter(|value| !value.is_empty()) {
                entry.insert("location".into(), json!(location));
            }
            if let Some(etag) = outcome.header("etag").filter(|value| !value.is_empty()) {
                entry.insert("version".into(), json!(etag));
            }
            if outcome.status >= 400 {
                entry.insert("response".into(), outcome.body.clone());
                *errors += 1;
                if let Some(bulk_id) = &operation.bulk_id {
                    failed.insert(bulk_id.clone());
                }
            } else if operation.method == "POST"
                && let Some(bulk_id) = &operation.bulk_id
            {
                created.insert(bulk_id.clone(), js_string(outcome.body.get("id")));
            }
            results.push(Value::Object(entry));
        };
        while !pending.is_empty() && !stopped(errors) {
            let mut deferred: Vec<BulkOperation> = Vec::new();
            for operation in &pending {
                if stopped(errors) {
                    break;
                }
                let mut wrapper = Map::new();
                wrapper.insert("path".into(), json!(operation.path));
                wrapper.insert("data".into(), operation.data.clone().unwrap_or(Value::Null));
                let serialized = core_js::stringify(&Value::Object(wrapper));
                let references = bulk_references(&serialized);
                let unknown = references
                    .iter()
                    .find(|(_, _, reference)| !declared.contains(reference))
                    .map(|(_, _, reference)| reference.clone());
                let broken = references
                    .iter()
                    .find(|(_, _, reference)| failed.contains(reference))
                    .map(|(_, _, reference)| reference.clone());
                if unknown.is_some() || broken.is_some() {
                    let error = match &unknown {
                        Some(unknown) => IamError::new(
                            "invalidValue",
                            format!("Unknown bulkId reference \"{unknown}\"."),
                        ),
                        None => IamError::with_status(
                            "invalidValue",
                            format!(
                                "Referenced operation \"{}\" failed.",
                                broken.clone().unwrap_or_default()
                            ),
                            409,
                        ),
                    };
                    record(
                        operation,
                        error_outcome(&error),
                        &mut errors,
                        &mut created,
                        &mut failed,
                    );
                    continue;
                }
                if references
                    .iter()
                    .any(|(_, _, reference)| !created.contains_key(reference))
                {
                    deferred.push(operation.clone());
                    continue;
                }
                let mut replaced = String::with_capacity(serialized.len());
                let mut last = 0;
                for (start, end, reference) in &references {
                    replaced.push_str(&serialized[last..*start]);
                    replaced.push_str(
                        created
                            .get(reference)
                            .map(String::as_str)
                            .unwrap_or_default(),
                    );
                    last = *end;
                }
                replaced.push_str(&serialized[last..]);
                let outcome = match self
                    .bulk_operation(authorization, connection_id, base, operation, &replaced)
                    .await
                {
                    Ok(outcome) => outcome,
                    Err(error) => error_outcome(&error),
                };
                record(operation, outcome, &mut errors, &mut created, &mut failed);
            }
            if deferred.len() == pending.len() {
                // Nothing progressed: the remaining operations reference each other in a cycle.
                for operation in &deferred {
                    record(
                        operation,
                        error_outcome(&IamError::with_status(
                            "invalidValue",
                            "Circular bulkId references cannot be resolved.",
                            409,
                        )),
                        &mut errors,
                        &mut created,
                        &mut failed,
                    );
                }
                break;
            }
            pending = deferred;
        }
        Ok(Outcome {
            status: 200,
            body: json!({ "schemas": [BULK_RESPONSE_SCHEMA], "Operations": results }),
            headers: Vec::new(),
        })
    }

    /// One resolved bulk operation (its `bulkId:` references replaced).
    async fn bulk_operation(
        &self,
        authorization: Option<&str>,
        connection_id: &str,
        base: &str,
        operation: &BulkOperation,
        resolved: &str,
    ) -> IamResult<Outcome> {
        let resolved = core_js::parse(resolved).map_err(|_| unexpected("Unexpected token"))?;
        let path = js_string(resolved.get("path"));
        let data = resolved.get("data").cloned().unwrap_or(Value::Null);
        // /^\/(Users|Groups)(?:\/([^/?]+))?$/
        let matched = path.strip_prefix('/').and_then(|rest| {
            let (resource, id) = match rest.split_once('/') {
                Some((resource, id)) => (resource, Some(id)),
                None => (rest, None),
            };
            if resource != "Users" && resource != "Groups" {
                return None;
            }
            match id {
                Some(id) if id.is_empty() || id.contains('/') || id.contains('?') => None,
                Some(id) => Some((resource.to_owned(), Some(id.to_owned()))),
                None if resource.contains('?') => None,
                None => Some((resource.to_owned(), None)),
            }
        });
        let Some((resource_type, id)) =
            matched.filter(|(_, id)| (operation.method == "POST") != id.is_some())
        else {
            return Err(IamError::new(
                "invalidPath",
                format!("Invalid bulk operation path \"{}\".", operation.path),
            ));
        };
        let resource_id = match id {
            Some(id) => Some(decode_uri_component(&id).ok_or_else(|| unexpected("URI malformed"))?),
            None => None,
        };
        let body = match data {
            Value::Null => None,
            other => Some(object(Some(&other))?.clone()),
        };
        let mut outcome = self
            .run(
                authorization,
                connection_id,
                base,
                &ScimRequest {
                    method: operation.method.clone(),
                    resource_type,
                    resource_id,
                    body,
                    if_match: operation.version.clone(),
                    if_none_match: None,
                    query: None,
                },
            )
            .await?;
        if operation.method == "DELETE" {
            outcome.headers = vec![("location", format!("{base}{path}"))];
        }
        Ok(outcome)
    }

    /// `handler(request)`: the fetch handler for `{basePath}/{connectionId}/{Users|Groups|ServiceProviderConfig|
    /// ResourceTypes|Schemas}[/{id}]`, `{Users|Groups}/.search`, and `Bulk`, plus the JSON administration API under
    /// `{adminBasePath}/connections/…`. None for requests outside both paths.
    pub async fn handler(&self, request: &HttpRequest) -> Option<HttpResponse> {
        let url = request_url(request)?;
        let pathname = url.path().to_owned();
        if pathname.starts_with(&format!("{}/", self.inner.admin_base_path)) {
            return Some(self.admin(request, &url).await);
        }
        let base_path = &self.inner.base_path;
        if !pathname.starts_with(&format!("{base_path}/")) {
            return None;
        }
        Some(match self.protocol(request, &url, &pathname).await {
            Ok(outcome) => to_response(&outcome),
            Err(outcome) => to_response(&outcome),
        })
    }

    async fn protocol(
        &self,
        request: &HttpRequest,
        url: &url::Url,
        pathname: &str,
    ) -> Result<Outcome, Outcome> {
        let fail = |error: IamError| error_outcome(&error);
        let base_path = &self.inner.base_path;
        let parts: Vec<String> = pathname[base_path.len() + 1..]
            .split('/')
            .map(|part| decode_uri_component(part).ok_or_else(|| fail(unexpected("URI malformed"))))
            .collect::<Result<_, _>>()?;
        let connection_id = parts.first().cloned().unwrap_or_default();
        let resource_type = parts.get(1).cloned().unwrap_or_default();
        let resource_id = parts.get(2).cloned();
        if connection_id.is_empty() || resource_type.is_empty() || parts.len() > 3 {
            return Err(fail(IamError::with_status(
                "notFound",
                "SCIM resource not found.",
                404,
            )));
        }
        // Body is parsed before opening a database transaction; network input cannot hold the writer lock.
        let method = request.method().as_str().to_owned();
        let mut body: Option<ObjectValue> = None;
        if ["POST", "PUT", "PATCH"].contains(&method.as_str()) {
            let json_type = header(request, "content-type").is_some_and(|value| {
                let lower = value.to_ascii_lowercase();
                lower.contains("application/json") || lower.contains("application/scim+json")
            });
            if !json_type {
                return Err(fail(IamError::with_status(
                    "invalidSyntax",
                    "A JSON content type is required.",
                    415,
                )));
            }
            // Read with a cap: the body arrives before the connection's token is checked.
            if request.body().len() > MAX_PAYLOAD_SIZE {
                return Err(fail(IamError::with_status(
                    "tooLarge",
                    "Request body is too large.",
                    413,
                )));
            }
            let raw = String::from_utf8_lossy(request.body());
            let parsed = core_js::parse(&raw).map_err(|_| syntax_outcome())?;
            body = Some(object(Some(&parsed)).map_err(fail)?.clone());
        }
        let base = format!(
            "{}{base_path}/{}",
            url_origin(url),
            encode_uri_component(&connection_id)
        );
        let authorization = header(request, "authorization");
        if resource_type == "Bulk" {
            if method != "POST" || resource_id.as_deref().is_some_and(|id| !id.is_empty()) {
                return Err(fail(IamError::with_status(
                    "invalidMethod",
                    "Bulk accepts POST only.",
                    405,
                )));
            }
            return self
                .bulk(
                    authorization.as_deref(),
                    &connection_id,
                    &base,
                    body.as_ref().unwrap_or(&ObjectValue::new()),
                )
                .await
                .map_err(fail);
        }
        self.run(
            authorization.as_deref(),
            &connection_id,
            &base,
            &ScimRequest {
                method,
                resource_type,
                resource_id,
                body,
                if_match: header(request, "if-match"),
                if_none_match: header(request, "if-none-match"),
                query: Some(url_query(url)),
            },
        )
        .await
        .map_err(fail)
    }

    /// One JSON administration route: turns the request body into a service call.
    async fn admin_route(
        &self,
        path: &str,
        credential: &CredentialInput,
        body: &Value,
    ) -> Option<IamResult<Value>> {
        let id = |field: &str| required_text(member(body, field), field);
        let ids = |names: &[&str]| -> IamResult<Value> {
            let mut input = Map::new();
            for name in names {
                input.insert((*name).to_owned(), json!(id(name)?));
            }
            Ok(Value::Object(input))
        };
        let with = |mut input: Value, key: &str| {
            if let (Value::Object(map), Some(value)) = (&mut input, member(body, key)) {
                map.insert(key.to_owned(), value.clone());
            }
            input
        };
        Some(match path {
            "connections/list" => match ids(&["tenantId"]) {
                Ok(input) => self.list_connections(credential, &input).await,
                Err(error) => Err(error),
            },
            "connections/create" => match ids(&["tenantId"]) {
                Ok(input) => {
                    let input = with(with(input, "name"), "expiresIn");
                    self.create_connection(credential, &input).await
                }
                Err(error) => Err(error),
            },
            "connections/rotate" => match ids(&["tenantId", "connectionId"]) {
                Ok(input) => {
                    let input = with(input, "expiresIn");
                    self.rotate_token(credential, &input).await
                }
                Err(error) => Err(error),
            },
            "connections/revoke" => match ids(&["tenantId", "connectionId"]) {
                Ok(input) => self
                    .revoke_connection(credential, &input)
                    .await
                    .map(|()| Value::Null),
                Err(error) => Err(error),
            },
            "connections/groups" => match ids(&["tenantId", "connectionId"]) {
                Ok(input) => self.list_groups(credential, &input).await,
                Err(error) => Err(error),
            },
            "connections/mappings" => match ids(&["tenantId", "connectionId", "groupId"]) {
                Ok(input) => {
                    let input = with(input, "roleIds");
                    self.set_role_mappings(credential, &input)
                        .await
                        .map(|()| Value::Null)
                }
                Err(error) => Err(error),
            },
            _ => return None,
        })
    }

    /// JSON administration API for consoles and scripts: `POST {adminBasePath}/connections/…` with the caller's IAM
    /// credential. Like the IAM API it requires `X-Better-IAM: 1`, a JSON object body, and a same-origin `Origin` when
    /// one is sent, and answers `{ data }` or `{ error: { code, message } }`.
    async fn admin(&self, request: &HttpRequest, url: &url::Url) -> HttpResponse {
        let reply = |body: Value, status: u16| {
            http_response(
                status,
                Some(core_js::stringify(&body)),
                &[
                    ("content-type", "application/json".to_owned()),
                    ("cache-control", "no-store".to_owned()),
                    ("x-content-type-options", "nosniff".to_owned()),
                ],
            )
        };
        let path = url.path()[self.inner.admin_base_path.len() + 1..].to_owned();
        const ROUTES: [&str; 6] = [
            "connections/list",
            "connections/create",
            "connections/rotate",
            "connections/revoke",
            "connections/groups",
            "connections/mappings",
        ];
        if !ROUTES.contains(&path.as_str()) {
            return reply(
                json!({ "error": { "code": "NOT_FOUND", "message": "Unknown route." } }),
                404,
            );
        }
        let result: IamResult<Value> = async {
            if request.method() != http::Method::POST {
                return Err(IamError::with_status(
                    "METHOD_NOT_ALLOWED",
                    "Use POST.",
                    405,
                ));
            }
            let content_type = header(request, "content-type").map(|value| value.to_lowercase());
            if header(request, "x-better-iam").as_deref() != Some("1")
                || !content_type.is_some_and(|value| value.starts_with("application/json"))
            {
                return Err(IamError::with_status(
                    "CSRF_REJECTED",
                    "JSON requests require X-Better-IAM: 1.",
                    403,
                ));
            }
            if let Some(origin) = header(request, "origin")
                && origin != url_origin(url)
            {
                return Err(IamError::with_status(
                    "CSRF_REJECTED",
                    "Cross-origin requests are rejected.",
                    403,
                ));
            }
            if request.body().len() > ADMIN_MAX_BODY {
                return Err(IamError::with_status(
                    "PAYLOAD_TOO_LARGE",
                    "Request body is too large.",
                    413,
                ));
            }
            let raw = String::from_utf8_lossy(request.body());
            let body = core_js::parse(&raw)
                .map_err(|_| IamError::new("INVALID_INPUT", "The body must be JSON."))?;
            if !body.is_object() {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    "The body must be a JSON object.",
                ));
            }
            let credential = credential_of(request);
            self.admin_route(&path, &credential, &body)
                .await
                .unwrap_or_else(|| Err(unexpected("Unknown route.")))
        }
        .await;
        match result {
            Ok(data) => reply(json!({ "data": data }), 200),
            Err(error) if is_unexpected(&error) => reply(
                json!({
                    "error": {
                        "code": "INTERNAL_ERROR",
                        "message": "The SCIM administration request failed.",
                    }
                }),
                500,
            ),
            Err(error) => reply(
                json!({ "error": { "code": error.code, "message": error.message } }),
                error.status,
            ),
        }
    }
}
