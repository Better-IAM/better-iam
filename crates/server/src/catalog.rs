//! Port of `packages/server/src/catalog.ts`: the permission catalog (platform actions and resource types declared in
//! configuration plus, per tenant, the types and `{type}:{verb}` actions a tenant registered itself), and the
//! attribute and relation validators.

use std::sync::{Arc, LazyLock};

use better_iam_core::{
    AttributeType, Filter, FindOptions, IamError, IamPlugin, IamResult, IamStore, Record,
    validate_policy,
};
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::context_keys::{CLEARANCE_SERVER_KEYS, RESERVED_SESSION_PRINCIPAL_NAMES};
use crate::js::{
    self, has_control, internal_error, invalid_config, invalid_input, is_object, js_string, member,
    utf16_len,
};
use crate::models::{ActionDefinition, ResourceRecord, ResourceTypeRecord};
use crate::options::{BetterIamOptions, ResolvedResource, ServerConfig};
use crate::options_value::options_value;
use crate::utils::id;
use crate::validation::{object, strings, text, text256};

const BUILT_IN_ACTION_NAMES: &[&str] = &[
    "tenants:create",
    "tenants:read",
    "tenants:update",
    "tenants:delete",
    "identities:create",
    "identities:read",
    "identities:update",
    "identities:delete",
    "identities:impersonate",
    "groups:create",
    "groups:read",
    "groups:update",
    "groups:delete",
    "roles:create",
    "roles:read",
    "roles:update",
    "roles:delete",
    "policies:create",
    "policies:read",
    "policies:update",
    "policies:delete",
    "bindings:create",
    "bindings:read",
    "bindings:delete",
    "bindings:activate",
    "bindings:approve",
    "packages:create",
    "packages:read",
    "packages:update",
    "packages:delete",
    "packages:assign",
    "packages:request",
    "packages:approve",
    "authorities:create",
    "authorities:revoke",
    "boundaries:update",
    "actions:create",
    "actions:read",
    "actions:delete",
    "resource-types:create",
    "resource-types:read",
    "resource-types:update",
    "resource-types:delete",
    "resources:create",
    "resources:read",
    "resources:update",
    "resources:delete",
    "relationships:create",
    "relationships:read",
    "relationships:delete",
    "credentials:create",
    "credentials:read",
    "credentials:revoke",
    "trust:create",
    "trust:read",
    "trust:update",
    "trust:revoke",
    "roles:assume",
    "roles:revoke-sessions",
    "session-tokens:create",
    "oidc-providers:create",
    "oidc-providers:read",
    "oidc-providers:update",
    "oidc-providers:delete",
    "audit:read",
    "assertions:create",
    "policies:simulate",
    "config:read",
    "config:apply",
    "root:grant",
    "access-requests:create",
    "access-requests:read",
    "access-requests:review",
    "webhooks:create",
    "webhooks:read",
    "webhooks:update",
    "webhooks:delete",
    "oauth:clients:create",
    "oauth:clients:read",
    "oauth:clients:delete",
    "oauth:clients:update",
    "oauth:grants:read",
    "oauth:grants:revoke",
    "scim:connections:create",
    "scim:connections:read",
    "scim:connections:delete",
    "scim:credentials:create",
    "scim:credentials:revoke",
    "scim:mappings:update",
    "scim:targets:create",
    "scim:targets:read",
    "scim:targets:update",
    "scim:targets:delete",
    "scim:targets:sync",
    "saml:connections:create",
    "saml:connections:read",
    "saml:connections:update",
    "saml:connections:delete",
    "ssf:streams:create",
    "ssf:streams:read",
    "ssf:streams:update",
    "ssf:streams:delete",
    "domains:create",
    "domains:read",
    "domains:update",
    "domains:delete",
    "hostnames:create",
    "hostnames:read",
    "hostnames:update",
    "hostnames:delete",
    "analysis:read",
    "analysis:update",
    "certifications:read",
    "certifications:review",
    "certifications:manage",
    "sod:read",
    "sod:manage",
    "security:read",
    "security:manage",
    "invariants:read",
    "invariants:manage",
    "agreements:read",
    "agreements:manage",
    "features:read",
    "features:manage",
    "features:override",
    "onboarding:read",
    "onboarding:manage",
    // AI agents as accounts and the delegations people give them (agents.ts, delegations.ts).
    "agents:create",
    "agents:read",
    "agents:update",
    "agents:delete",
    "delegations:read",
    "delegations:revoke",
    // Inference access control (inference.ts).
    "inference:manage",
    "inference:read",
    "inference:record",
    // Teams (teams.ts) and departments (departments.ts).
    "teams:create",
    "teams:read",
    "teams:update",
    "teams:delete",
    "departments:read",
    "departments:manage",
    // Billing and spend tracking (billing.ts).
    "billing:read",
    "billing:manage",
    "billing:record",
    // Key management (kms.ts).
    "kms:create",
    "kms:read",
    "kms:update",
    "kms:delete",
    "kms:grant",
    "kms:encrypt",
    "kms:decrypt",
    "kms:generate-data-key",
    "kms:sign",
    "kms:verify",
    "kms:generate-mac",
    "kms:verify-mac",
    // Private certificate authority (pki.ts).
    "pki:create",
    "pki:read",
    "pki:update",
    "pki:issue",
    "pki:request",
    "pki:revoke",
    // Data protection (tokenization.ts).
    "protection:read",
    "protection:manage",
    "protection:tokenize",
    "protection:detokenize",
    "protection:mask",
    "protection:delete",
    // Secrets vault (vault.ts).
    "vault:read",
    "vault:reveal",
    "vault:write",
    "vault:rotate",
    "vault:lease",
    "vault:manage",
    // API usage plans and quotas (quotas.ts).
    "quotas:read",
    "quotas:manage",
    // Privacy and consent (privacy.ts).
    "privacy:read",
    "privacy:manage",
    "privacy:record",
    "privacy:check",
    "privacy:handle",
    // SSH certificate authority (ssh.ts, api/ssh.ts).
    "ssh:read",
    "ssh:manage",
    // Identity threat detection and response (threats.ts, api/threats.ts).
    "threats:read",
    "threats:manage",
    "threats:respond",
    // Lifecycle workflows (workflows.ts, api/workflows.ts).
    "workflows:read",
    "workflows:manage",
    "workflows:run",
    // Compliance center (compliance.ts, api/compliance.ts).
    "compliance:read",
    "compliance:evaluate",
    "compliance:manage",
    // Application catalog (applications.ts, api/applications.ts).
    "applications:read",
    "applications:manage",
    "applications:assign",
    // Verifiable credentials (vc.ts, api/verifiable-credentials.ts).
    "vc:read",
    "vc:manage",
    "vc:issue",
    "vc:revoke",
    // The LDAP directory gateway (ldap.ts, api/ldap.ts).
    "ldap:read",
    "ldap:manage",
    // Device posture (devices.ts, api/devices.ts).
    "devices:read",
    "devices:manage",
    "devices:report",
    // Shared Signals receiver (signal-receiver.ts, api/signals.ts).
    "signals:read",
    "signals:manage",
    // License management (licenses.ts, api/licenses.ts).
    "licenses:read",
    "licenses:manage",
    "licenses:assign",
    // B2B guest collaboration (guests.ts, api/guests.ts).
    "guests:read",
    "guests:invite",
    "guests:manage",
    "guests:settings",
    // Security clearances (clearances.ts, api/clearances.ts).
    "clearances:read",
    "clearances:adjudicate",
    "clearances:suspend",
    "classifications:manage",
    "classifications:label",
    "classifications:declassify",
];

/// `builtInActions`: every operation the platform itself authorizes (`iam:` + name).
pub static BUILT_IN_ACTIONS: LazyLock<Vec<String>> = LazyLock::new(|| {
    BUILT_IN_ACTION_NAMES
        .iter()
        .map(|action| format!("iam:{action}"))
        .collect()
});

/// `internalResourceTypes`: resource types the platform resolves itself; products and tenants cannot redefine them.
pub const INTERNAL_RESOURCE_TYPES: [&str; 6] =
    ["iam", "oauth-client", "scim", "saml", "ssf", "role"];

/// `reservedResourceTypes`.
pub const RESERVED_RESOURCE_TYPES: [&str; 9] = [
    "iam",
    "oauth-client",
    "scim",
    "saml",
    "ssf",
    "role",
    "tenant",
    "identity",
    "session",
];

/// Whether a type is one of [`INTERNAL_RESOURCE_TYPES`].
pub fn is_internal_resource_type(name: &str) -> bool {
    INTERNAL_RESOURCE_TYPES.contains(&name)
}

static RESOURCE_TYPE_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("^[a-z][a-z0-9-]{0,63}$").expect("regex"));
static RELATION_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("^[a-z][a-z0-9_-]{0,63}$").expect("regex"));
static ATTRIBUTE_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("^[a-zA-Z][a-zA-Z0-9_]{0,63}$").expect("regex"));
static TENANT_ACTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new("^([a-z][a-z0-9-]{0,63}):([a-zA-Z][a-zA-Z0-9_-]{0,63})$").expect("regex")
});

/// `resourceTypeName.test(name)`.
pub fn is_resource_type_name(name: &str) -> bool {
    RESOURCE_TYPE_NAME.is_match(name)
}

fn attribute_type(name: &str) -> Option<AttributeType> {
    match name {
        "string" => Some(AttributeType::String),
        "number" => Some(AttributeType::Number),
        "boolean" => Some(AttributeType::Boolean),
        _ => None,
    }
}

/// The name of an attribute type.
pub fn attribute_type_name(kind: AttributeType) -> &'static str {
    match kind {
        AttributeType::String => "string",
        AttributeType::Number => "number",
        AttributeType::Boolean => "boolean",
    }
}

/// `CatalogResourceType`.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CatalogResourceType {
    pub name: String,
    /// `'platform' | 'tenant'`.
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub actions: Vec<String>,
    pub attributes: IndexMap<String, AttributeType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    pub managed: bool,
    /// Relation names identities and groups may hold on resources of this type.
    pub relations: Vec<String>,
}

/// `relationNames(value)`: short identifiers; at most 32 distinct relations per type.
pub fn relation_names(value: Option<&Value>) -> IamResult<Vec<String>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let unique = js::unique(strings(Some(value), "relations")?);
    if unique.len() > 32 || unique.iter().any(|name| !RELATION_NAME.is_match(name)) {
        return Err(invalid_input(
            "relations must contain at most 32 lowercase identifiers",
        ));
    }
    Ok(unique)
}

/// `attributeSchema(value, reserved?)`: names the deployment reserves besides `tenantId` are refused.
pub fn attribute_schema(
    value: Option<&Value>,
    reserved: Option<&IndexSet<String>>,
) -> IamResult<IndexMap<String, AttributeType>> {
    let Some(value) = value else {
        return Ok(IndexMap::new());
    };
    let schema = object(Some(value))?;
    if schema.len() > 64 {
        return Err(invalid_input("At most 64 attributes may be declared"));
    }
    let mut result = IndexMap::new();
    for (key, kind) in js::entries(schema) {
        if !ATTRIBUTE_NAME.is_match(key) || key == "tenantId" {
            return Err(invalid_input(format!("Invalid attribute name {key}")));
        }
        if reserved.is_some_and(|names| names.contains(key)) {
            return Err(invalid_input(format!("Attribute name {key} is reserved")));
        }
        let Some(kind) = kind.as_str().and_then(attribute_type) else {
            return Err(invalid_input(format!(
                "Attribute {key} must be string, number, or boolean"
            )));
        };
        result.insert(key.clone(), kind);
    }
    Ok(result)
}

/// `attributeValues(schema, value)`: declared attributes of the declared types only.
pub fn attribute_values(
    schema: &IndexMap<String, AttributeType>,
    value: Option<&Value>,
) -> IamResult<Map<String, Value>> {
    let Some(value) = value else {
        return Ok(Map::new());
    };
    let input = object(Some(value))?;
    let mut result = Map::new();
    for (key, item) in js::entries(input) {
        let Some(kind) = schema.get(key) else {
            return Err(invalid_input(format!(
                "Attribute {key} is not declared for this resource type"
            )));
        };
        let valid = match (kind, item) {
            (AttributeType::String, Value::String(text)) => {
                utf16_len(text) <= 2048 && !has_control(text)
            }
            (AttributeType::Number, Value::Number(_)) => true,
            (AttributeType::Boolean, Value::Bool(_)) => true,
            _ => false,
        };
        if !valid {
            return Err(invalid_input(format!(
                "Attribute {key} must be a {}",
                attribute_type_name(*kind)
            )));
        }
        result.insert(key.clone(), item.clone());
    }
    Ok(result)
}

fn decode<T: serde::de::DeserializeOwned>(record: Record) -> IamResult<T> {
    serde_json::from_value(Value::Object(record)).map_err(|_| {
        IamError::with_status("STORAGE_CORRUPT", "Record does not match its type", 500)
    })
}

/// `managedResource(tx, tenantId, type, resourceId)`: a registered managed resource.
pub async fn managed_resource(
    tx: &dyn IamStore,
    tenant_id: &str,
    kind: &str,
    resource_id: &str,
) -> IamResult<Option<ResourceRecord>> {
    let found = tx
        .find(
            "resources",
            &Filter::new()
                .eq("tenantId", tenant_id)
                .eq("uniqueKey", format!("{kind}/{resource_id}")),
            &FindOptions::default(),
        )
        .await?;
    found.into_iter().next().map(decode).transpose()
}

/// `resolvedManaged(record)`: a managed registration as the policy engine sees it (attributes plus owner and
/// parent links).
pub fn resolved_managed(record: &ResourceRecord) -> ResolvedResource {
    let mut attributes = record.attributes.clone();
    if let Some(owner) = &record.owner_id {
        attributes.insert("ownerId".into(), Value::String(owner.clone()));
    }
    if let Some(parent) = &record.parent_id {
        attributes.insert("parentId".into(), Value::String(parent.clone()));
        // `attributes.parentType = record.parentType`: an undefined member when the record has none.
        match &record.parent_type {
            Some(parent_type) => {
                attributes.insert("parentType".into(), Value::String(parent_type.clone()));
            }
            None => {
                attributes.shift_remove("parentType");
            }
        }
    }
    ResolvedResource {
        tenant_id: record.tenant_id.clone(),
        kind: record.kind.clone(),
        id: record.resource_id.clone(),
        attributes: Some(attributes),
        classification: None,
    }
}

const RESERVED_PRINCIPAL_BASE: [&str; 28] = [
    "id",
    "tenantId",
    "mfa",
    "kind",
    "owner",
    "rootAdmin",
    "groups",
    "roles",
    "sessionKind",
    "authMethod",
    "impersonated",
    "impersonatorId",
    "agreements",
    "pendingAgreements",
    "onboarding",
    "pendingOnboarding",
    "teams",
    "departments",
    "departmentId",
    "spendExceeded",
    "budgetsExceeded",
    "consents",
    "riskLevel",
    "riskScore",
    "licenses",
    "guest",
    "guestSponsorId",
    "homeTenantId",
];

/// `reservedPrincipalKeys`: principal context keys the server derives itself; identity attributes cannot shadow them.
pub static RESERVED_PRINCIPAL_KEYS: LazyLock<IndexSet<String>> = LazyLock::new(|| {
    RESERVED_PRINCIPAL_BASE
        .iter()
        .chain(RESERVED_SESSION_PRINCIPAL_NAMES.iter())
        .map(|name| (*name).to_owned())
        .collect()
});

fn clearance_names(prefix: &str) -> IndexSet<String> {
    CLEARANCE_SERVER_KEYS
        .iter()
        .filter_map(|key| key.strip_prefix(prefix))
        .map(str::to_owned)
        .collect()
}

/// `clearancePrincipalNames`: reserved as identity attributes only with `options.clearances`.
pub static CLEARANCE_PRINCIPAL_NAMES: LazyLock<IndexSet<String>> =
    LazyLock::new(|| clearance_names("principal."));
/// `classificationAttributeNames`: a classification label's keys, reserved as resource attributes only with
/// `options.clearances`.
pub static CLASSIFICATION_ATTRIBUTE_NAMES: LazyLock<IndexSet<String>> =
    LazyLock::new(|| clearance_names("resource."));

/// `Object.entries(value)` of a model value (`?? {}` applied by the caller).
fn model_entries(value: Option<&Value>) -> Vec<(String, Value)> {
    match value {
        Some(Value::Object(map)) if is_object(value) => js::entries(map)
            .into_iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        Some(Value::Array(items)) => items
            .iter()
            .enumerate()
            .map(|(index, item)| (index.to_string(), item.clone()))
            .collect(),
        Some(Value::String(text)) => text
            .chars()
            .enumerate()
            .map(|(index, c)| (index.to_string(), Value::String(c.into())))
            .collect(),
        _ => Vec::new(),
    }
}

/// `[...value]` of a model value: arrays and strings; anything else is a TypeError.
fn model_spread(value: Option<&Value>) -> IamResult<Vec<Value>> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => Ok(items.clone()),
        Some(Value::String(text)) => Ok(text.chars().map(|c| Value::String(c.into())).collect()),
        Some(_) => Err(internal_error()),
    }
}

/// `Catalog`.
#[derive(Debug, Clone)]
pub struct Catalog {
    pub actions: IndexSet<String>,
    pub action_types: IndexMap<String, String>,
    pub resource_types: IndexMap<String, CatalogResourceType>,
    pub namespaces: IndexSet<String>,
    /// Typed attributes administrators may set on identities; exposed to policies as `principal.{name}`.
    pub identity_attributes: IndexMap<String, AttributeType>,
    /// Resource attribute names this deployment reserves besides `tenantId`: a classification label's keys when
    /// `options.clearances` is set, none otherwise. Pass to [`attribute_schema`].
    pub reserved_attributes: Option<&'static IndexSet<String>>,
    tenant_defined: bool,
    strict_resource_types: bool,
}

impl Catalog {
    /// `new Catalog(options, plugins, config)`.
    pub fn new(
        options: &BetterIamOptions,
        plugins: &[Arc<dyn IamPlugin>],
        config: &ServerConfig,
    ) -> IamResult<Self> {
        let model = options_value(options);
        let permissions = member(Some(&model), "permissions");
        let mut catalog = Self {
            actions: BUILT_IN_ACTIONS.iter().cloned().collect(),
            action_types: IndexMap::new(),
            resource_types: IndexMap::new(),
            namespaces: IndexSet::new(),
            identity_attributes: IndexMap::new(),
            reserved_attributes: None,
            tenant_defined: config.tenant_defined,
            strict_resource_types: config.strict_resource_types,
        };
        let mut configured = model_spread(js::defined(member(permissions, "actions")))?;
        for plugin in plugins {
            configured.extend(plugin.actions().into_iter().map(Value::String));
        }
        for action in &configured {
            catalog.register_action(action, None)?;
        }
        catalog.identity_attributes =
            attribute_schema(member(permissions, "identityAttributes"), None).map_err(|error| {
                invalid_config(format!("identityAttributes: {}", error.message))
            })?;
        for key in catalog.identity_attributes.keys() {
            if RESERVED_PRINCIPAL_KEYS.contains(key)
                || (config.clearances.is_some() && CLEARANCE_PRINCIPAL_NAMES.contains(key))
            {
                return Err(invalid_config(format!(
                    "identityAttributes cannot redefine principal.{key}"
                )));
            }
        }
        catalog.reserved_attributes = config
            .clearances
            .is_some()
            .then_some(&*CLASSIFICATION_ATTRIBUTE_NAMES);
        let mut declared = model_entries(js::defined(member(permissions, "resourceTypes")));
        for plugin in plugins {
            for (name, definition) in plugin.resource_types() {
                declared.push((
                    name,
                    serde_json::to_value(definition).unwrap_or(Value::Null),
                ));
            }
        }
        let mut parents: IndexMap<String, Option<Value>> = IndexMap::new();
        for (name, definition) in declared {
            if !is_resource_type_name(&name) || RESERVED_RESOURCE_TYPES.contains(&name.as_str()) {
                return Err(invalid_config(format!(
                    "Invalid or reserved resource type name {name}"
                )));
            }
            if catalog.resource_types.contains_key(&name) {
                return Err(invalid_config(format!(
                    "Resource type {name} is declared more than once"
                )));
            }
            let declared = object(Some(&definition))?;
            let attributes =
                attribute_schema(declared.get("attributes"), catalog.reserved_attributes)
                    .and_then(|attributes| {
                        relation_names(declared.get("relations"))
                            .map(|relations| (attributes, relations))
                    })
                    .map_err(|error| {
                        invalid_config(format!("Resource type {name}: {}", error.message))
                    })?;
            let (attributes, relations) = attributes;
            let empty = Value::Array(Vec::new());
            let type_actions = strings(
                Some(js::defined(declared.get("actions")).unwrap_or(&empty)),
                "actions",
            )?;
            for action in &type_actions {
                catalog.register_action(&Value::String(action.clone()), Some(&name))?;
            }
            let description = match declared.get("description") {
                None => None,
                Some(value) => Some(text(Some(value), "description", 512)?),
            };
            let parent = declared.get("parent").cloned();
            parents.insert(name.clone(), parent.clone());
            catalog.resource_types.insert(
                name.clone(),
                CatalogResourceType {
                    name: name.clone(),
                    source: "platform".into(),
                    description,
                    actions: type_actions,
                    attributes,
                    parent: parent.as_ref().and_then(Value::as_str).map(str::to_owned),
                    managed: js::truthy(js::defined(declared.get("managed"))),
                    relations,
                },
            );
        }
        for definition in catalog.resource_types.values() {
            let mut seen: IndexSet<String> = IndexSet::new();
            let mut current = parents.get(&definition.name).cloned().flatten();
            while let Some(parent) = current {
                let key = match &parent {
                    Value::String(text) => Some(text.clone()),
                    _ => None,
                };
                let Some(key) = key.filter(|key| {
                    key != &definition.name
                        && !seen.contains(key)
                        && catalog.resource_types.contains_key(key)
                }) else {
                    return Err(invalid_config(format!(
                        "Resource type {} has an invalid parent chain",
                        definition.name
                    )));
                };
                if definition.managed && !catalog.resource_types[&key].managed {
                    return Err(invalid_config(format!(
                        "Managed resource type {} requires a managed parent",
                        definition.name
                    )));
                }
                current = parents.get(&key).cloned().flatten();
                seen.insert(key);
            }
        }
        catalog.namespaces = catalog
            .actions
            .iter()
            .map(|action| action.split(':').next().unwrap_or("").to_owned())
            .collect();
        Ok(catalog)
    }

    fn register_action(&mut self, action: &Value, resource_type: Option<&str>) -> IamResult<()> {
        let action = text256(Some(action), "action")?;
        if action.starts_with("iam:")
            || action.starts_with("tenant/")
            || action.contains(['*', '?'])
            || js::has_js_whitespace(&action)
        {
            return Err(invalid_config("Reserved or invalid action"));
        }
        if let Some(kind) = resource_type
            && !self.action_types.contains_key(&action)
        {
            self.action_types.insert(action.clone(), kind.to_owned());
        }
        self.actions.insert(action);
        Ok(())
    }

    /// The tenant-defined resource type record of a name.
    pub async fn tenant_resource_type(
        &self,
        tx: &dyn IamStore,
        tenant_id: &str,
        name: &str,
    ) -> IamResult<Option<ResourceTypeRecord>> {
        let found = tx
            .find(
                "resourceTypes",
                &Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("uniqueKey", name),
                &FindOptions::default(),
            )
            .await?;
        found.into_iter().next().map(decode).transpose()
    }

    /// `resourceTypeDefinition(tx, tenantId, name)`: a platform or tenant-defined resource type.
    pub async fn resource_type_definition(
        &self,
        tx: &dyn IamStore,
        tenant_id: &str,
        name: &str,
    ) -> IamResult<Option<CatalogResourceType>> {
        if let Some(platform) = self.resource_types.get(name) {
            return Ok(Some(platform.clone()));
        }
        let Some(record) = self.tenant_resource_type(tx, tenant_id, name).await? else {
            return Ok(None);
        };
        let actions = tx
            .find(
                "actions",
                &Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("resourceType", name),
                &FindOptions::default(),
            )
            .await?
            .into_iter()
            .map(|action| js_string(action.get("name")))
            .collect();
        Ok(Some(CatalogResourceType {
            name: name.to_owned(),
            source: "tenant".into(),
            description: record.description,
            actions,
            attributes: record.attributes,
            parent: record.parent,
            managed: true,
            relations: record.relations.unwrap_or_default(),
        }))
    }

    /// `managedDefinition(tx, tenantId, type)`: a managed type (platform-declared with `managed: true`, or any
    /// tenant-defined type).
    pub async fn managed_definition(
        &self,
        tx: &dyn IamStore,
        tenant_id: &str,
        kind: Option<&Value>,
    ) -> IamResult<CatalogResourceType> {
        let kind = text(kind, "resource type", 64)?;
        let Some(definition) = self.resource_type_definition(tx, tenant_id, &kind).await? else {
            return Err(IamError::new(
                "INVALID_RESOURCE_TYPE",
                "Unknown resource type",
            ));
        };
        if !definition.managed {
            return Err(IamError::new(
                "INVALID_RESOURCE_TYPE",
                "This resource type is resolved by the application, not registered with IAM",
            ));
        }
        Ok(definition)
    }

    /// `knownAction(tx, tenantId, action)`.
    pub async fn known_action(
        &self,
        tx: &dyn IamStore,
        tenant_id: &str,
        action: &str,
    ) -> IamResult<bool> {
        if self.actions.contains(action) {
            return Ok(true);
        }
        Ok(!tx
            .find(
                "actions",
                &Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("uniqueKey", action),
                &FindOptions::default(),
            )
            .await?
            .is_empty())
    }

    /// `registerTenantAction(tx, tenantId, rawName, description?)`: tenant-defined actions are namespaced under a
    /// tenant-defined resource type, `{type}:{verb}`.
    pub async fn register_tenant_action(
        &self,
        tx: &dyn IamStore,
        tenant_id: &str,
        raw_name: Option<&Value>,
        description: Option<&Value>,
    ) -> IamResult<ActionDefinition> {
        if !self.tenant_defined {
            return Err(IamError::with_status(
                "CATALOG_LOCKED",
                "Tenant-defined actions are disabled",
                403,
            ));
        }
        let name = text(raw_name, "action", 128)?;
        let prefix = TENANT_ACTION
            .captures(&name)
            .map(|captures| captures[1].to_owned());
        let Some(prefix) = prefix
            .filter(|prefix| !self.actions.contains(&name) && !self.namespaces.contains(prefix))
        else {
            return Err(IamError::new(
                "INVALID_ACTION",
                "Tenant actions must be {resourceType}:{verb} under a tenant-defined resource type",
            ));
        };
        if self
            .tenant_resource_type(tx, tenant_id, &prefix)
            .await?
            .is_none()
        {
            return Err(IamError::new(
                "INVALID_ACTION",
                format!("Register resource type {prefix} before its actions"),
            ));
        }
        if self.known_action(tx, tenant_id, &name).await? {
            return Err(IamError::with_status(
                "CONFLICT",
                "Action already exists",
                409,
            ));
        }
        let mut definition = Record::new();
        definition.insert("id".into(), Value::String(id()));
        definition.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
        definition.insert("uniqueKey".into(), Value::String(name.clone()));
        definition.insert("name".into(), Value::String(name));
        definition.insert("resourceType".into(), Value::String(prefix));
        if let Some(description) = description {
            definition.insert(
                "description".into(),
                Value::String(text(Some(description), "description", 512)?),
            );
        }
        decode(tx.insert("actions", &definition).await?)
    }

    /// `assertActionUnused(tx, tenantId, name)`: refused while any policy or inline role document names the action.
    pub async fn assert_action_unused(
        &self,
        tx: &dyn IamStore,
        tenant_id: &str,
        name: &str,
    ) -> IamResult<()> {
        let referenced = |document: &Value| -> IamResult<bool> {
            let Some(statements) = document.get("statements").and_then(Value::as_array) else {
                return Err(internal_error());
            };
            for statement in statements {
                let Some(actions) = statement.get("actions").and_then(Value::as_array) else {
                    return Err(internal_error());
                };
                if actions.iter().any(|action| action.as_str() == Some(name)) {
                    return Ok(true);
                }
            }
            Ok(false)
        };
        let filter = Filter::new().eq("tenantId", tenant_id);
        let policies = tx
            .find("policies", &filter, &FindOptions::default())
            .await?;
        let mut used = false;
        for policy in &policies {
            if referenced(policy.get("document").unwrap_or(&Value::Null))? {
                used = true;
                break;
            }
        }
        if !used {
            let roles = tx.find("roles", &filter, &FindOptions::default()).await?;
            for role in &roles {
                if let Some(document) = js::defined(role.get("document"))
                    && js::truthy(Some(document))
                    && referenced(document)?
                {
                    used = true;
                    break;
                }
            }
        }
        if used {
            return Err(IamError::with_status(
                "RESOURCE_IN_USE",
                "Remove the action from policies and roles first",
                409,
            ));
        }
        Ok(())
    }

    /// `validate(tx, tenantId, document)`: policies may only name actions and resource types that exist for the
    /// tenant; wildcard patterns are not resolved.
    pub async fn validate(
        &self,
        tx: &dyn IamStore,
        tenant_id: &str,
        document: &Value,
    ) -> IamResult<()> {
        validate_policy(document)?;
        let statements = document
            .get("statements")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for statement in &statements {
            for action in statement
                .get("actions")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                if !action.contains(['*', '?']) && !self.known_action(tx, tenant_id, action).await?
                {
                    return Err(IamError::new(
                        "INVALID_ACTION",
                        format!("Unknown action {action}"),
                    ));
                }
            }
            if !self.strict_resource_types {
                continue;
            }
            for pattern in statement
                .get("resources")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                let kind = pattern.split('/').next().unwrap_or("");
                if !kind.contains(['*', '?'])
                    && !is_internal_resource_type(kind)
                    && self
                        .resource_type_definition(tx, tenant_id, kind)
                        .await?
                        .is_none()
                {
                    return Err(IamError::new(
                        "INVALID_RESOURCE_TYPE",
                        format!("Unknown resource type {kind}"),
                    ));
                }
            }
        }
        Ok(())
    }

    /// [`Catalog::validate`] for a typed document.
    pub async fn validate_document(
        &self,
        tx: &dyn IamStore,
        tenant_id: &str,
        document: &better_iam_core::PolicyDocument,
    ) -> IamResult<()> {
        self.validate(tx, tenant_id, &document.to_value()).await
    }
}
