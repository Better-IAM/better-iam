//! Port of `packages/server/src/departments.ts`.
//!
//! Departments: the organization's reporting structure. Departments nest (`parentId`), may name a head, and hold
//! people; each person belongs to at most one department (`departmentMembers`, uniqueKey `identity:{identityId}`).
//! Policies see `principal.departmentId` and `principal.departments` (the department and every department above it),
//! teams may name the department they belong to, and roll-ups (spend, reports) walk `departmentPath`.

use std::sync::LazyLock;

use better_iam_core::{Filter, FindOptions, IamError, IamResult, Record};
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::Store;
use crate::port::decode;

/// The `departments` collection.
pub const DEPARTMENTS: &str = "departments";
/// The `departmentMembers` collection.
pub const DEPARTMENT_MEMBERS: &str = "departmentMembers";

/// A department; names are unique per tenant (uniqueKey `name:{lowercase}`), codes too when set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Department {
    #[serde(rename = "name")]
    pub name: String,
    /// A short reference such as `ENG` or `FIN-AP` (1-32 letters, digits, `-`, `_` or `.`), unique per tenant.
    #[serde(rename = "code", default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(rename = "parentId", default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    /// The person who leads the department (an active person of the tenant).
    #[serde(rename = "headId", default, skip_serializing_if = "Option::is_none")]
    pub head_id: Option<String>,
    /// Free-form cost-center reference printed on reports and statements.
    #[serde(
        rename = "costCenter",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cost_center: Option<String>,
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

/// A person's department (uniqueKey `identity:{identityId}`: one department per person).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DepartmentMember {
    #[serde(rename = "departmentId")]
    pub department_id: String,
    #[serde(rename = "identityId")]
    pub identity_id: String,
    /// The person's title within the department (informational).
    #[serde(rename = "title", default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(rename = "since")]
    pub since: f64,
    #[serde(rename = "assignedBy")]
    pub assigned_by: String,
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

/// Collections owned by the departments module.
pub static DEPARTMENT_COLLECTIONS: LazyLock<Value> =
    LazyLock::new(|| json!({"departments":"departments","members":"departmentMembers"}));

/// Deepest department nesting (a department and nineteen levels above it).
pub const MAX_DEPARTMENT_DEPTH: f64 = 20.0;

/// Departments per tenant.
pub const MAX_DEPARTMENTS: f64 = 2000.0;

static CODE_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$").expect("code pattern"));

/// A department code: 1-32 letters, digits, `.`, `_` or `-`, starting with a letter or digit.
pub fn department_code(value: Option<&Value>) -> IamResult<String> {
    match value {
        Some(Value::String(code)) if CODE_PATTERN.is_match(code) => Ok(code.clone()),
        _ => Err(IamError::new(
            "INVALID_INPUT",
            "code must use 1-32 letters, digits, dots, underscores, or hyphens",
        )),
    }
}

/// Loads a department of the tenant or fails with NOT_FOUND.
pub async fn load_department(
    tx: &Store,
    tenant_id: &str,
    department_id: Option<&Value>,
) -> IamResult<Department> {
    let department_id = match department_id {
        Some(Value::String(id)) if !id.is_empty() => id,
        _ => return Err(IamError::new("INVALID_INPUT", "Invalid departmentId")),
    };
    match tx.get(DEPARTMENTS, department_id).await? {
        Some(record) if record.get("tenantId").and_then(Value::as_str) == Some(tenant_id) => {
            decode(record)
        }
        _ => Err(IamError::with_status(
            "NOT_FOUND",
            "Department not found",
            404,
        )),
    }
}

/// The department followed by the departments above it, nearest first; stops at a missing parent.
pub fn department_chain(
    departments: &IndexMap<String, Department>,
    department_id: &str,
) -> IamResult<Vec<Department>> {
    Ok(department_chain_of(departments, department_id))
}

/// [`department_chain`] without the `Result` (it cannot fail).
pub fn department_chain_of(
    departments: &IndexMap<String, Department>,
    department_id: &str,
) -> Vec<Department> {
    let mut chain: Vec<Department> = Vec::new();
    let mut seen: IndexSet<String> = IndexSet::new();
    let mut current = departments.get(department_id);
    while let Some(department) = current {
        if seen.contains(&department.id) || chain.len() as f64 > MAX_DEPARTMENT_DEPTH {
            break;
        }
        chain.push(department.clone());
        seen.insert(department.id.clone());
        current = department
            .parent_id
            .as_deref()
            .filter(|parent| !parent.is_empty())
            .and_then(|parent| departments.get(parent));
    }
    chain
}

/// Decodes a JSON array (or object of records) of departments, as the iterables TypeScript passes.
fn departments_from(value: &Value) -> IamResult<Vec<Department>> {
    let items: Vec<&Value> = match value {
        Value::Array(items) => items.iter().collect(),
        Value::Object(map) => map.values().collect(),
        _ => Vec::new(),
    };
    items
        .into_iter()
        .map(|item| match item {
            Value::Object(record) => decode(record.clone()),
            _ => decode(Record::new()),
        })
        .collect()
}

/// Every department below `departmentId`, not including the department itself. `departments` is a JSON array of
/// department records (any iterable of departments in TypeScript); [`department_descendants_of`] takes them typed.
pub fn department_descendants(
    departments: &Value,
    department_id: &str,
) -> IamResult<Vec<Department>> {
    let list = departments_from(departments)?;
    Ok(department_descendants_of(list.iter(), department_id))
}

/// [`department_descendants`] over typed departments.
pub fn department_descendants_of<'a>(
    departments: impl IntoIterator<Item = &'a Department>,
    department_id: &str,
) -> Vec<Department> {
    let mut children: IndexMap<String, Vec<Department>> = IndexMap::new();
    for department in departments {
        if let Some(parent) = department.parent_id.as_deref().filter(|id| !id.is_empty()) {
            children
                .entry(parent.to_owned())
                .or_default()
                .push(department.clone());
        }
    }
    let mut result: Vec<Department> = Vec::new();
    let mut seen: IndexSet<String> = IndexSet::from([department_id.to_owned()]);
    let mut queue: std::collections::VecDeque<Department> = children
        .get(department_id)
        .cloned()
        .unwrap_or_default()
        .into();
    while let Some(next) = queue.pop_front() {
        if seen.contains(&next.id) {
            continue;
        }
        seen.insert(next.id.clone());
        if let Some(below) = children.get(&next.id) {
            queue.extend(below.iter().cloned());
        }
        result.push(next);
    }
    result
}

/// The tenant's departments by ID.
pub async fn tenant_departments(
    tx: &Store,
    tenant_id: &str,
) -> IamResult<IndexMap<String, Department>> {
    let mut departments = IndexMap::new();
    for record in tx
        .find(
            DEPARTMENTS,
            &Filter::new().eq("tenantId", tenant_id),
            &FindOptions::default(),
        )
        .await?
    {
        let department: Department = decode(record)?;
        departments.insert(department.id.clone(), department);
    }
    Ok(departments)
}

/// The person's department membership record, if any.
pub async fn department_membership(
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
) -> IamResult<Option<DepartmentMember>> {
    match department_membership_record(tx, tenant_id, identity_id).await? {
        Some(record) => decode(record).map(Some),
        None => Ok(None),
    }
}

/// The raw membership record (kept whole for writes).
async fn department_membership_record(
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
) -> IamResult<Option<Record>> {
    Ok(tx
        .find(
            DEPARTMENT_MEMBERS,
            &Filter::new()
                .eq("tenantId", tenant_id)
                .eq("uniqueKey", format!("identity:{identity_id}")),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .next())
}

/// The ID of the department a person belongs to, if any.
pub async fn department_of(
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
) -> IamResult<Option<String>> {
    let Some(membership) = department_membership(tx, tenant_id, identity_id).await? else {
        return Ok(None);
    };
    let Some(department) = tx.get(DEPARTMENTS, &membership.department_id).await? else {
        return Ok(None);
    };
    if department.get("tenantId").and_then(Value::as_str) != Some(tenant_id) {
        return Ok(None);
    }
    Ok(department
        .get("id")
        .and_then(Value::as_str)
        .map(str::to_owned))
}

/// Department IDs from the top of the tree down to `departmentId` itself (for roll-ups); empty when unknown.
pub async fn department_path(
    tx: &Store,
    tenant_id: &str,
    department_id: &str,
) -> IamResult<Vec<String>> {
    let departments = tenant_departments(tx, tenant_id).await?;
    let mut path: Vec<String> = department_chain_of(&departments, department_id)
        .into_iter()
        .map(|department| department.id)
        .collect();
    path.reverse();
    Ok(path)
}

/// The heads of a department (identity IDs): its own head and, with `includeAncestors`, the heads of the
/// departments above it, nearest first and without duplicates. `options` is `{ includeAncestors?: boolean }`.
pub async fn department_heads(
    tx: &Store,
    tenant_id: &str,
    department_id: &str,
    options: Option<&Value>,
) -> IamResult<Vec<String>> {
    let include_ancestors = crate::js::truthy(crate::js::member(options, "includeAncestors"));
    department_heads_of(tx, tenant_id, department_id, include_ancestors).await
}

/// [`department_heads`] with a typed option.
pub async fn department_heads_of(
    tx: &Store,
    tenant_id: &str,
    department_id: &str,
    include_ancestors: bool,
) -> IamResult<Vec<String>> {
    let chain = department_chain_of(&tenant_departments(tx, tenant_id).await?, department_id);
    let mut heads: Vec<String> = Vec::new();
    let considered = if include_ancestors {
        &chain[..]
    } else {
        &chain[..chain.len().min(1)]
    };
    for department in considered {
        if let Some(head) = department
            .head_id
            .as_deref()
            .filter(|head| !head.is_empty())
            && !heads.iter().any(|known| known == head)
        {
            heads.push(head.to_owned());
        }
    }
    Ok(heads)
}

/// Removes a person from their department; true when they had one.
pub async fn remove_from_department(
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
) -> IamResult<bool> {
    let membership = department_membership_record(tx, tenant_id, identity_id).await?;
    if let Some(membership) = &membership {
        tx.delete(DEPARTMENT_MEMBERS, better_iam_core::record_id(membership))
            .await?;
    }
    Ok(membership.is_some())
}

/// What [`release_departments`] changed.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepartmentRelease {
    pub left: bool,
    pub heads_reassigned: f64,
    pub heads_cleared: f64,
}

/// Offboarding and deletion: takes the person out of their department, and hands the departments they head to
/// `successorId` (or leaves them without a head). Returns what changed (`{ left, headsReassigned, headsCleared }`).
pub async fn release_departments(
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    now: f64,
    successor_id: Option<&str>,
) -> IamResult<Value> {
    let release = release_departments_of(tx, tenant_id, identity_id, now, successor_id).await?;
    Ok(json!({
        "left": release.left,
        "headsReassigned": crate::js::number(release.heads_reassigned),
        "headsCleared": crate::js::number(release.heads_cleared),
    }))
}

/// [`release_departments`] with a typed result.
pub async fn release_departments_of(
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    now: f64,
    successor_id: Option<&str>,
) -> IamResult<DepartmentRelease> {
    // `successorId ? ... : ...`: an empty successor counts as none.
    let successor_id = successor_id.filter(|successor| !successor.is_empty());
    let left = remove_from_department(tx, tenant_id, identity_id).await?;
    let mut heads_reassigned = 0.0;
    let mut heads_cleared = 0.0;
    for mut department in tx
        .find(
            DEPARTMENTS,
            &Filter::new()
                .eq("tenantId", tenant_id)
                .eq("headId", identity_id),
            &FindOptions::default(),
        )
        .await?
    {
        department.shift_remove("headId");
        if let Some(successor) = successor_id {
            department.insert("headId".into(), Value::String(successor.to_owned()));
        }
        department.insert("updatedAt".into(), crate::js::number(now));
        tx.put(DEPARTMENTS, &department).await?;
        if successor_id.is_some() {
            heads_reassigned += 1.0;
        } else {
            heads_cleared += 1.0;
        }
    }
    Ok(DepartmentRelease {
        left,
        heads_reassigned,
        heads_cleared,
    })
}

/// Policy context for a person in their own tenant: `principal.departmentId` (absent without a department) and
/// `principal.departments`, the department with every department above it.
pub async fn department_context(
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
) -> IamResult<Map<String, Value>> {
    let mut context = Map::new();
    let Some(department_id) = department_of(tx, tenant_id, identity_id)
        .await?
        .filter(|id| !id.is_empty())
    else {
        context.insert("principal.departments".into(), json!([]));
        return Ok(context);
    };
    let mut path = department_path(tx, tenant_id, &department_id).await?;
    crate::js::sort_strings(&mut path);
    context.insert(
        "principal.departmentId".into(),
        Value::String(department_id),
    );
    context.insert("principal.departments".into(), json!(path));
    Ok(context)
}
