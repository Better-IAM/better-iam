//! Port of `packages/server/src/api/departments.ts`: the organization's reporting structure (departments.ts).
//! `iam:departments:read` lists and reads it, `iam:departments:manage` changes it and places people. Policies see
//! `principal.departmentId` and `principal.departments`; `syncManagers` turns department heads into managers for
//! approvals routed to managers.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use better_iam_core::js::{cmp_utf16, to_lower, trim, utf16_len};
use better_iam_core::{
    AttributeType, AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions,
    IamError, IamResult, IamStoreExt, Identity, IdentityKind, Record, Tenant,
};
use better_iam_types::api::departments;
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};

use crate::api::package_automation::after_identity_change;
use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::departments::{
    DEPARTMENT_COLLECTIONS, Department, MAX_DEPARTMENT_DEPTH, MAX_DEPARTMENTS, department_chain,
    department_code, department_descendants, department_membership, load_department,
    tenant_departments,
};
use crate::js::truthy;
use crate::metrics::locale_compare;
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::org_insights::{birthright_options, suggest_birthright};
use crate::org_rules::packages_naming;
use crate::session_kinds::acts_in_own_right;
use crate::teams::TEAM_COLLECTIONS;
use crate::utils::id;
use crate::validation::{strings, text};

/// `maxAssign`: people one `assign` call places.
const MAX_ASSIGN: usize = 100;

/// `departmentCollections.departments`.
fn departments_collection() -> &'static str {
    DEPARTMENT_COLLECTIONS["departments"]
        .as_str()
        .unwrap_or("departments")
}

/// `departmentCollections.members`.
fn members_collection() -> &'static str {
    DEPARTMENT_COLLECTIONS["members"]
        .as_str()
        .unwrap_or("departmentMembers")
}

/// `teamCollections.teams`.
fn teams_collection() -> &'static str {
    TEAM_COLLECTIONS["teams"].as_str().unwrap_or("teams")
}

/// Every record of a find (no pagination).
fn all() -> FindOptions {
    FindOptions::default()
}

/// `{ tenantId }`.
fn by_tenant(tenant_id: &str) -> Filter {
    Filter::new().eq("tenantId", tenant_id)
}

/// A string member of a stored record, "" when absent.
fn member_str<'a>(record: &'a Record, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// `String(value)` of a request-body member already known to be a string.
fn string_value(value: &str) -> Value {
    Value::String(value.to_owned())
}

/// `optionalText(value, name, max)`: absent, null and "" are undefined; anything else must be valid text (trimmed).
fn optional_text(value: Option<&Value>, name: &str, max: usize) -> IamResult<Option<String>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if text.is_empty() => Ok(None),
        Some(value) => Ok(Some(trim(&text(Some(value), name, max)?).to_owned())),
    }
}

/// `value === null || value === ''` for a defined request member.
fn clears(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(text) => text.is_empty(),
        _ => false,
    }
}

/// `value.slice(0, max)` in UTF-16 code units (a surrogate pair is never split).
fn slice_utf16(value: &str, max: usize) -> String {
    if utf16_len(value) <= max {
        return value.to_owned();
    }
    let mut out = String::new();
    let mut units = 0;
    for ch in value.chars() {
        units += ch.len_utf16();
        if units > max {
            break;
        }
        out.push(ch);
    }
    out
}

/// `person(identity)`: the public view of a person record.
fn person(identity: &Record) -> Map<String, Value> {
    let mut view = Map::new();
    copy_member(&mut view, identity, "id");
    copy_member(&mut view, identity, "name");
    if truthy(identity.get("email")) {
        view.insert("email".into(), identity["email"].clone());
    }
    copy_member(&mut view, identity, "status");
    view
}

/// `{ key: record.key }`: an absent member stays absent (`undefined` is left out of JSON).
fn copy_member(view: &mut Map<String, Value>, record: &Record, key: &str) {
    if let Some(value) = record.get(key) {
        view.insert(key.into(), value.clone());
    }
}

/// `ref(department)`.
fn department_ref(department: &Department) -> Map<String, Value> {
    let mut view = Map::new();
    view.insert("id".into(), string_value(&department.id));
    view.insert("name".into(), string_value(&department.name));
    if let Some(code) = department.code.as_deref().filter(|code| !code.is_empty()) {
        view.insert("code".into(), string_value(code));
    }
    view
}

/// A department as stored, in the member order the TypeScript server writes, without `uniqueKey` (`{ uniqueKey,
/// ...rest }`).
fn department_rest(department: &Department) -> Map<String, Value> {
    let mut view = Map::new();
    view.insert("id".into(), string_value(&department.id));
    view.insert("tenantId".into(), string_value(&department.tenant_id));
    view.insert("name".into(), string_value(&department.name));
    let optional = [
        ("code", &department.code),
        ("description", &department.description),
        ("parentId", &department.parent_id),
        ("headId", &department.head_id),
        ("costCenter", &department.cost_center),
    ];
    for (key, value) in optional {
        if let Some(value) = value {
            view.insert(key.into(), string_value(value));
        }
    }
    view.insert("createdAt".into(), crate::js::number(department.created_at));
    view.insert("updatedAt".into(), crate::js::number(department.updated_at));
    for (key, value) in &department.extra {
        view.insert(key.clone(), value.clone());
    }
    view
}

/// `departmentDescendants(departments.values(), departmentId)`.
fn descendants(
    departments: &IndexMap<String, Department>,
    department_id: &str,
) -> IamResult<Vec<Department>> {
    let list = Value::Array(
        departments
            .values()
            .map(|department| Value::Object(crate::port::encode(department)))
            .collect(),
    );
    department_descendants(&list, department_id)
}

/// `departmentChain(departments, id).reverse().map(ref)`.
fn path_refs(chain: Vec<Department>) -> Value {
    Value::Array(
        chain
            .iter()
            .rev()
            .map(|department| Value::Object(department_ref(department)))
            .collect(),
    )
}

/// The sort of member views: heads first, then by email (or name).
fn by_head_then_name(a: &Map<String, Value>, b: &Map<String, Value>) -> Ordering {
    let head = |view: &Map<String, Value>| u8::from(truthy(view.get("head")));
    let key = |view: &Map<String, Value>| {
        crate::js::defined(view.get("email"))
            .or_else(|| crate::js::defined(view.get("name")))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    head(b)
        .cmp(&head(a))
        .then_with(|| locale_compare(&key(a), &key(b)))
}

/// A member view (`DepartmentMemberView`) of a placement.
fn member_view(identity: &Record, item: &Department, member: &Record) -> Map<String, Value> {
    let mut view = person(identity);
    view.insert("department".into(), Value::Object(department_ref(item)));
    if truthy(member.get("title")) {
        view.insert("title".into(), member["title"].clone());
    }
    copy_member(&mut view, member, "since");
    let identity_id = identity.get("id").and_then(Value::as_str);
    if item.head_id.is_some() && item.head_id.as_deref() == identity_id {
        view.insert("head".into(), Value::Bool(true));
    }
    if truthy(identity.get("managerId")) {
        view.insert("managerId".into(), identity["managerId"].clone());
    }
    view
}

/// The views of the people placed in `scope`, skipping deleted identities, in placement order.
async fn member_views(
    tx: &Store,
    tenant_id: &str,
    scope: &[Department],
) -> IamResult<Vec<Map<String, Value>>> {
    let mut views = Vec::new();
    for item in scope {
        for member in tx
            .find(
                members_collection(),
                &by_tenant(tenant_id).eq("departmentId", item.id.as_str()),
                &all(),
            )
            .await?
        {
            let Some(identity) = tx
                .get("identities", member_str(&member, "identityId"))
                .await?
            else {
                continue;
            };
            if identity.get("status").and_then(Value::as_str) == Some("deleted") {
                continue;
            }
            views.push(member_view(&identity, item, &member));
        }
    }
    Ok(views)
}

/// The identities a change touched (`reconciling`'s `touch`), shared with the mutation.
#[derive(Default, Clone)]
struct Touched(Arc<Mutex<IndexSet<String>>>);

impl Touched {
    fn touch(&self, identity_ids: impl IntoIterator<Item = String>) {
        let mut touched = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
        touched.extend(identity_ids);
    }

    fn ids(&self) -> Vec<String> {
        let touched = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
        touched.iter().cloned().collect()
    }
}

/// What deleting a department changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepartmentDeletion {
    /// People taken out of it.
    pub unassigned: usize,
    /// Teams that lost the link to it.
    pub teams: usize,
}

/// Transaction-level department changes (`departmentModule(ctx).helpers`), shared by the API and configuration
/// sync: the same validation and audit events. Callers authorize each change first.
pub struct DepartmentMutations {
    ctx: Arc<ServerContext>,
}

impl DepartmentMutations {
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

    /// An active person of the tenant who can head a department or belong to one.
    pub async fn department_person(
        &self,
        tx: &Store,
        tenant_id: &str,
        identity_id: Option<&Value>,
    ) -> IamResult<Identity> {
        let identity_id = text(identity_id, "identityId", 128)?;
        let identity = self
            .ctx
            .active_identity(tx, &identity_id, tenant_id)
            .await?;
        if identity.kind != IdentityKind::User {
            return Err(IamError::new(
                "INVALID_INPUT",
                "Departments hold people; service accounts and agents have none",
            ));
        }
        Ok(identity)
    }

    async fn assert_unique(
        &self,
        tx: &Store,
        tenant_id: &str,
        name: &str,
        code: Option<&str>,
        except_id: Option<&str>,
    ) -> IamResult<()> {
        let lowered = to_lower(name);
        for other in tenant_departments(tx, tenant_id).await?.values() {
            if Some(other.id.as_str()) == except_id {
                continue;
            }
            if to_lower(&other.name) == lowered {
                return Err(IamError::with_status(
                    "CONFLICT",
                    format!("A department named {} exists", other.name),
                    409,
                ));
            }
            if let Some(code) = code
                && other
                    .code
                    .as_deref()
                    .is_some_and(|other_code| to_lower(other_code) == to_lower(code))
            {
                return Err(IamError::with_status(
                    "CONFLICT",
                    format!("The code {code} is taken by {}", other.name),
                    409,
                ));
            }
        }
        Ok(())
    }

    fn depth_check(
        departments: &IndexMap<String, Department>,
        parent: &Department,
        subtree_height: usize,
    ) -> IamResult<()> {
        if (department_chain(departments, &parent.id)?.len() + subtree_height) as f64
            > MAX_DEPARTMENT_DEPTH
        {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!(
                    "Departments nest at most {} levels deep",
                    crate::js::number_to_string(MAX_DEPARTMENT_DEPTH)
                ),
            ));
        }
        Ok(())
    }

    /// Places a person in a department (moving them out of any other); returns false when they were already there.
    pub async fn place(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        department: &Department,
        identity_id: &str,
        title: Option<&str>,
    ) -> IamResult<bool> {
        let existing = department_membership(tx, &department.tenant_id, identity_id).await?;
        if let Some(existing) = &existing
            && existing.department_id == department.id
            && existing.title.as_deref() == title
        {
            return Ok(false);
        }
        let mut record = Map::new();
        record.insert(
            "id".into(),
            Value::String(
                existing
                    .as_ref()
                    .map(|existing| existing.id.clone())
                    .unwrap_or_else(id),
            ),
        );
        record.insert("tenantId".into(), string_value(&department.tenant_id));
        record.insert(
            "uniqueKey".into(),
            Value::String(format!("identity:{identity_id}")),
        );
        record.insert("departmentId".into(), string_value(&department.id));
        record.insert("identityId".into(), string_value(identity_id));
        if let Some(title) = title.filter(|title| !title.is_empty()) {
            record.insert("title".into(), string_value(title));
        }
        let since = match &existing {
            Some(existing) if existing.department_id == department.id => existing.since,
            _ => self.ctx.now(),
        };
        record.insert("since".into(), crate::js::number(since));
        record.insert("assignedBy".into(), string_value(&principal.identity.id));
        if existing.is_some() {
            tx.put(members_collection(), &record).await?;
        } else {
            tx.insert(members_collection(), &record).await?;
        }
        let mut metadata = Map::new();
        metadata.insert("identityId".into(), string_value(identity_id));
        if let Some(existing) = &existing
            && existing.department_id != department.id
        {
            metadata.insert(
                "previousDepartmentId".into(),
                string_value(&existing.department_id),
            );
        }
        if let Some(title) = title.filter(|title| !title.is_empty()) {
            metadata.insert("title".into(), string_value(title));
        }
        self.audit(
            tx,
            principal,
            "department:assign",
            &department.tenant_id,
            &department.id,
            metadata,
        )
        .await?;
        Ok(true)
    }

    /// Creates a department; the caller has authorized `iam:departments:manage`.
    pub async fn create_department(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant: &Tenant,
        input: &Map<String, Value>,
    ) -> IamResult<Department> {
        let departments = tenant_departments(tx, &tenant.id).await?;
        if departments.len() as f64 >= MAX_DEPARTMENTS {
            return Err(IamError::with_status(
                "LIMIT_EXCEEDED",
                format!(
                    "At most {} departments",
                    crate::js::number_to_string(MAX_DEPARTMENTS)
                ),
                409,
            ));
        }
        let name = trim(&text(input.get("name"), "name", 100)?).to_owned();
        let code = match input.get("code") {
            None => None,
            Some(Value::String(code)) if code.is_empty() => None,
            Some(code) => Some(department_code(Some(code))?),
        };
        self.assert_unique(tx, &tenant.id, &name, code.as_deref(), None)
            .await?;
        let mut parent_id = None;
        if let Some(value) = input.get("parentId") {
            let parent = load_department(tx, &tenant.id, Some(value)).await?;
            Self::depth_check(&departments, &parent, 1)?;
            parent_id = Some(parent.id);
        }
        let head_id = match input.get("headId") {
            None => None,
            Some(value) => Some(
                self.department_person(tx, &tenant.id, Some(value))
                    .await?
                    .id,
            ),
        };
        let description = optional_text(input.get("description"), "description", 512)?;
        let cost_center = optional_text(input.get("costCenter"), "costCenter", 64)?;
        let now = self.ctx.now();
        let mut record = Map::new();
        record.insert("id".into(), Value::String(id()));
        record.insert("tenantId".into(), string_value(&tenant.id));
        record.insert(
            "uniqueKey".into(),
            Value::String(format!("name:{}", to_lower(&name))),
        );
        record.insert("name".into(), string_value(&name));
        let optional = [
            ("code", &code),
            ("description", &description),
            ("parentId", &parent_id),
            ("headId", &head_id),
            ("costCenter", &cost_center),
        ];
        for (key, value) in optional {
            if let Some(value) = value.as_deref().filter(|value| !value.is_empty()) {
                record.insert(key.into(), string_value(value));
            }
        }
        record.insert("createdAt".into(), crate::js::number(now));
        record.insert("updatedAt".into(), crate::js::number(now));
        tx.insert(departments_collection(), &record).await?;
        let department: Department = crate::port::decode(record)?;
        let mut metadata = Map::new();
        metadata.insert("name".into(), string_value(&name));
        if let Some(parent_id) = parent_id.as_deref().filter(|id| !id.is_empty()) {
            metadata.insert("parentId".into(), string_value(parent_id));
        }
        self.audit(
            tx,
            principal,
            "department:create",
            &tenant.id,
            &department.id,
            metadata,
        )
        .await?;
        Ok(department)
    }

    /// Changes a department; the caller has authorized `iam:departments:manage` on it.
    pub async fn update_department(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant: &Tenant,
        input: &Map<String, Value>,
    ) -> IamResult<Department> {
        let department = load_department(tx, &tenant.id, input.get("departmentId")).await?;
        let fields: Vec<&str> = [
            "name",
            "code",
            "description",
            "parentId",
            "headId",
            "costCenter",
        ]
        .into_iter()
        .filter(|key| input.get(*key).is_some())
        .collect();
        if fields.is_empty() {
            return Err(IamError::new("INVALID_INPUT", "Nothing to update"));
        }
        let departments = tenant_departments(tx, &tenant.id).await?;
        // `{ ...department, updatedAt }`: the stored record, so members this version does not know survive.
        let mut next = match tx.get(departments_collection(), &department.id).await? {
            Some(stored) => stored,
            None => crate::port::encode(&department),
        };
        next.insert("updatedAt".into(), crate::js::number(self.ctx.now()));
        if let Some(name) = input.get("name") {
            let name = trim(&text(Some(name), "name", 100)?).to_owned();
            let unique_key = format!("name:{}", to_lower(&name));
            next.insert("name".into(), Value::String(name));
            next.insert("uniqueKey".into(), Value::String(unique_key));
        }
        if let Some(code) = input.get("code") {
            next.shift_remove("code");
            if !clears(code) {
                next.insert("code".into(), Value::String(department_code(Some(code))?));
            }
        }
        let next_name = member_str(&next, "name").to_owned();
        let next_code = next.get("code").and_then(Value::as_str).map(str::to_owned);
        self.assert_unique(
            tx,
            &tenant.id,
            &next_name,
            next_code.as_deref(),
            Some(&department.id),
        )
        .await?;
        if let Some(description) = input.get("description") {
            next.shift_remove("description");
            if let Some(description) =
                optional_text(Some(description), "description", 512)?.filter(|d| !d.is_empty())
            {
                next.insert("description".into(), Value::String(description));
            }
        }
        if let Some(cost_center) = input.get("costCenter") {
            next.shift_remove("costCenter");
            if let Some(cost_center) =
                optional_text(Some(cost_center), "costCenter", 64)?.filter(|c| !c.is_empty())
            {
                next.insert("costCenter".into(), Value::String(cost_center));
            }
        }
        if let Some(head_id) = input.get("headId") {
            next.shift_remove("headId");
            if !clears(head_id) {
                let head = self
                    .department_person(tx, &tenant.id, Some(head_id))
                    .await?;
                next.insert("headId".into(), Value::String(head.id));
            }
        }
        if let Some(parent_id) = input.get("parentId") {
            next.shift_remove("parentId");
            if !clears(parent_id) {
                let parent = load_department(tx, &tenant.id, Some(parent_id)).await?;
                let below = descendants(&departments, &department.id)?;
                if parent.id == department.id || below.iter().any(|item| item.id == parent.id) {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "A department cannot move under itself or a department below it",
                    ));
                }
                let mut height = 1;
                for item in &below {
                    let chain = department_chain(&departments, &item.id)?;
                    let index = chain
                        .iter()
                        .position(|step| step.id == department.id)
                        .map_or(0, |index| index + 1);
                    height = height.max(index);
                }
                Self::depth_check(&departments, &parent, height)?;
                next.insert("parentId".into(), Value::String(parent.id));
            }
        }
        tx.put(departments_collection(), &next).await?;
        let mut metadata = Map::new();
        metadata.insert(
            "fields".into(),
            Value::Array(fields.iter().map(|field| string_value(field)).collect()),
        );
        self.audit(
            tx,
            principal,
            "department:update",
            &tenant.id,
            &department.id,
            metadata,
        )
        .await?;
        crate::port::decode(next)
    }

    /// Deletes a department, unassigning its people and unfiling its teams.
    pub async fn delete_department(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant: &Tenant,
        input: &Map<String, Value>,
    ) -> IamResult<DepartmentDeletion> {
        let department = load_department(tx, &tenant.id, input.get("departmentId")).await?;
        let departments = tenant_departments(tx, &tenant.id).await?;
        let children: Vec<&Department> = departments
            .values()
            .filter(|other| other.parent_id.as_deref() == Some(department.id.as_str()))
            .collect();
        if !children.is_empty() {
            return Err(IamError::with_status(
                "RESOURCE_IN_USE",
                format!(
                    "Move or delete the departments below it first: {}",
                    children
                        .iter()
                        .map(|child| child.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                409,
            ));
        }
        // A department a birthright rule names stays until the package stops naming it (like groups).
        let naming = packages_naming(
            tx,
            &tenant.id,
            "identity.departments",
            std::slice::from_ref(&department.id),
            None,
        )
        .await?;
        if !naming.is_empty() {
            return Err(IamError::with_status(
                "RESOURCE_IN_USE",
                format!("Access packages name it in a rule: {}", naming.join(", ")),
                409,
            ));
        }
        let mut unassigned = 0;
        for member in tx
            .find(
                members_collection(),
                &by_tenant(&tenant.id).eq("departmentId", department.id.as_str()),
                &all(),
            )
            .await?
        {
            tx.delete(members_collection(), member_str(&member, "id"))
                .await?;
            unassigned += 1;
        }
        let mut teams = 0;
        for mut team in tx
            .find(teams_collection(), &by_tenant(&tenant.id), &all())
            .await?
        {
            if team.get("departmentId").and_then(Value::as_str) == Some(department.id.as_str()) {
                team.shift_remove("departmentId");
                team.insert("updatedAt".into(), crate::js::number(self.ctx.now()));
                tx.put(teams_collection(), &team).await?;
                teams += 1;
            }
        }
        tx.delete(departments_collection(), &department.id).await?;
        let mut metadata = Map::new();
        metadata.insert("name".into(), string_value(&department.name));
        metadata.insert("unassigned".into(), json!(unassigned));
        metadata.insert("teams".into(), json!(teams));
        self.audit(
            tx,
            principal,
            "department:delete",
            &tenant.id,
            &department.id,
            metadata,
        )
        .await?;
        Ok(DepartmentDeletion { unassigned, teams })
    }

    /// The people placed in a department or any department below it.
    async fn people_below(
        &self,
        tx: &Store,
        tenant_id: &str,
        department_id: &str,
    ) -> IamResult<Vec<String>> {
        let departments = tenant_departments(tx, tenant_id).await?;
        let mut scope = IndexSet::new();
        scope.insert(department_id.to_owned());
        for item in descendants(&departments, department_id)? {
            scope.insert(item.id);
        }
        Ok(tx
            .find(members_collection(), &by_tenant(tenant_id), &all())
            .await?
            .iter()
            .filter(|placement| scope.contains(member_str(placement, "departmentId")))
            .map(|placement| member_str(placement, "identityId").to_owned())
            .collect())
    }

    async fn summaries(
        &self,
        tx: &Store,
        tenant_id: &str,
    ) -> IamResult<IndexMap<String, Map<String, Value>>> {
        let departments = tenant_departments(tx, tenant_id).await?;
        let mut members: HashMap<String, usize> = HashMap::new();
        for member in tx
            .find(members_collection(), &by_tenant(tenant_id), &all())
            .await?
        {
            *members
                .entry(member_str(&member, "departmentId").to_owned())
                .or_default() += 1;
        }
        let mut teams: HashMap<String, usize> = HashMap::new();
        for team in tx
            .find(teams_collection(), &by_tenant(tenant_id), &all())
            .await?
        {
            if let Some(department_id) = team
                .get("departmentId")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
            {
                *teams.entry(department_id.to_owned()).or_default() += 1;
            }
        }
        let count = |map: &HashMap<String, usize>, key: &str| map.get(key).copied().unwrap_or(0);
        let mut result = IndexMap::new();
        for department in departments.values() {
            let below = descendants(&departments, &department.id)?;
            let mut summary = department_rest(department);
            summary.insert("memberCount".into(), json!(count(&members, &department.id)));
            let total: usize = std::iter::once(department)
                .chain(below.iter())
                .map(|item| count(&members, &item.id))
                .sum();
            summary.insert("totalMemberCount".into(), json!(total));
            let child_count = departments
                .values()
                .filter(|other| other.parent_id.as_deref() == Some(department.id.as_str()))
                .count();
            summary.insert("childCount".into(), json!(child_count));
            summary.insert("teamCount".into(), json!(count(&teams, &department.id)));
            result.insert(department.id.clone(), summary);
        }
        Ok(result)
    }

    async fn head_of(
        &self,
        tx: &Store,
        department: &Department,
    ) -> IamResult<Option<Map<String, Value>>> {
        let Some(head_id) = department.head_id.as_deref().filter(|id| !id.is_empty()) else {
            return Ok(None);
        };
        let identity = tx.get("identities", head_id).await?;
        Ok(identity
            .filter(|identity| member_str(identity, "tenantId") == department.tenant_id)
            .map(|identity| person(&identity)))
    }

    async fn detail(&self, tx: &Store, department: &Department) -> IamResult<Value> {
        let departments = tenant_departments(tx, &department.tenant_id).await?;
        let all_summaries = self.summaries(tx, &department.tenant_id).await?;
        let mut children: Vec<&Department> = departments
            .values()
            .filter(|other| other.parent_id.as_deref() == Some(department.id.as_str()))
            .collect();
        children.sort_by(|a, b| locale_compare(&a.name, &b.name));
        let head = self.head_of(tx, department).await?;
        let mut teams: Vec<Record> = tx
            .find(
                teams_collection(),
                &by_tenant(&department.tenant_id),
                &all(),
            )
            .await?
            .into_iter()
            .filter(|team| {
                team.get("departmentId").and_then(Value::as_str) == Some(department.id.as_str())
            })
            .collect();
        teams.sort_by(|a, b| locale_compare(member_str(a, "name"), member_str(b, "name")));
        let mut view = all_summaries
            .get(&department.id)
            .cloned()
            .unwrap_or_default();
        let chain = department_chain(&departments, &department.id)?;
        view.insert(
            "path".into(),
            path_refs(chain.into_iter().skip(1).collect()),
        );
        let children: Vec<Value> = children
            .iter()
            .map(|child| {
                let mut entry = department_ref(child);
                let summary = all_summaries.get(&child.id);
                entry.insert(
                    "memberCount".into(),
                    summary
                        .and_then(|summary| summary.get("memberCount").cloned())
                        .unwrap_or(Value::Null),
                );
                entry.insert(
                    "totalMemberCount".into(),
                    summary
                        .and_then(|summary| summary.get("totalMemberCount").cloned())
                        .unwrap_or(Value::Null),
                );
                Value::Object(entry)
            })
            .collect();
        view.insert("children".into(), Value::Array(children));
        if let Some(head) = head {
            view.insert("head".into(), Value::Object(head));
        }
        view.insert(
            "teams".into(),
            Value::Array(
                teams
                    .iter()
                    .map(|team| {
                        json!({
                            "id": team.get("id").cloned().unwrap_or(Value::Null),
                            "name": team.get("name").cloned().unwrap_or(Value::Null),
                            "slug": team.get("slug").cloned().unwrap_or(Value::Null),
                        })
                    })
                    .collect(),
            ),
        );
        Ok(Value::Object(view))
    }

    /// A person's placement (`DepartmentPlacement`), or None without a department.
    async fn placement(
        &self,
        tx: &Store,
        tenant_id: &str,
        identity_id: &str,
        departments: &IndexMap<String, Department>,
    ) -> IamResult<Option<Map<String, Value>>> {
        let membership = department_membership(tx, tenant_id, identity_id).await?;
        let Some(membership) = membership else {
            return Ok(None);
        };
        let Some(department) = departments.get(&membership.department_id) else {
            return Ok(None);
        };
        let head = self.head_of(tx, department).await?;
        let mut view = Map::new();
        view.insert(
            "department".into(),
            Value::Object(department_ref(department)),
        );
        view.insert(
            "path".into(),
            path_refs(department_chain(departments, &department.id)?),
        );
        if let Some(title) = membership
            .title
            .as_deref()
            .filter(|title| !title.is_empty())
        {
            view.insert("title".into(), string_value(title));
        }
        view.insert("since".into(), crate::js::number(membership.since));
        if let Some(head) = head {
            view.insert("head".into(), Value::Object(head));
        }
        if let Some(cost_center) = department
            .cost_center
            .as_deref()
            .filter(|cost_center| !cost_center.is_empty())
        {
            view.insert("costCenter".into(), string_value(cost_center));
        }
        Ok(Some(view))
    }
}

/// The `departments` API group (`createDepartmentsApi(ctx)`): one method per route `departments/{method}`.
pub struct DepartmentsApi {
    ctx: Arc<ServerContext>,
    helpers: DepartmentMutations,
}

/// `createDepartmentsApi(ctx)`.
pub fn create_departments_api(ctx: &Arc<ServerContext>) -> IamResult<DepartmentsApi> {
    Ok(DepartmentsApi {
        ctx: ctx.clone(),
        helpers: DepartmentMutations { ctx: ctx.clone() },
    })
}

impl DepartmentsApi {
    /// `reconciling(tenantId, run)`, after the change committed: re-evaluates the birthright access package rules of
    /// the people it touched (rules may test identity.departments and identity.managerId).
    async fn reconciled(
        &self,
        input: &Map<String, Value>,
        touched: &Touched,
        result: Value,
    ) -> IamResult<Value> {
        after_identity_change(
            &self.ctx,
            &string_member(input, "tenantId"),
            &touched.ids(),
            &result,
        )
        .await
    }

    /// `departments/assign`: places up to 100 people (`identityIds`, or one `identityId`) in a department, moving
    /// them out of their previous one, with an optional `title`. Returns how many changed.
    pub async fn assign(
        &self,
        credential: &CredentialInput,
        input: Body<departments::AssignInput>,
    ) -> IamResult<Reply<departments::AssignOutput>> {
        let ctx = &self.ctx;
        let helpers = &self.helpers;
        let body = &input;
        let touched = Touched::default();
        let touch = touched.clone();
        let resource = text(input.get("departmentId"), "departmentId", 128)?;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let department = load_department(&tx, &tenant_id, body.get("departmentId")).await?;
                if body.get("identityIds").is_none() == body.get("identityId").is_none() {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "Provide identityIds or identityId",
                    )
                    .into());
                }
                let listed = match body.get("identityIds") {
                    Some(ids) => strings(Some(ids), "identityIds")?,
                    None => vec![text(body.get("identityId"), "identityId", 128)?],
                };
                let identity_ids: Vec<String> = listed
                    .into_iter()
                    .collect::<IndexSet<String>>()
                    .into_iter()
                    .collect();
                if identity_ids.is_empty() || identity_ids.len() > MAX_ASSIGN {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        format!("Provide 1-{MAX_ASSIGN} identityIds"),
                    )
                    .into());
                }
                let title = optional_text(body.get("title"), "title", 100)?;
                let mut assigned = 0;
                for identity_id in &identity_ids {
                    let identity = helpers
                        .department_person(&tx, &tenant_id, Some(&string_value(identity_id)))
                        .await?;
                    if helpers
                        .place(&tx, &principal, &department, &identity.id, title.as_deref())
                        .await?
                    {
                        assigned += 1;
                        touch.touch([identity_id.clone()]);
                    }
                }
                Ok(json!({ "assigned": assigned, "unchanged": identity_ids.len() - assigned }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:departments:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(
            self.reconciled(&input, &touched, result).await?,
        ))
    }

    /// `departments/create`: creates a department, optionally under a parent and with a head (an active person of
    /// the organization).
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<departments::CreateInput>,
    ) -> IamResult<Reply<departments::CreateOutput>> {
        let ctx = &self.ctx;
        let helpers = &self.helpers;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let department = helpers
                        .create_department(&tx, &principal, &tenant, body)
                        .await?;
                    Ok(helpers.detail(&tx, &department).await?)
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:departments:manage",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `departments/delete`: its people become unassigned and teams filed under it lose the link; departments below
    /// it must be moved or deleted first (RESOURCE_IN_USE).
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<departments::DeleteInput>,
    ) -> IamResult<Reply<departments::DeleteOutput>> {
        let ctx = &self.ctx;
        let helpers = &self.helpers;
        let body = &input;
        let touched = Touched::default();
        let touch = touched.clone();
        let resource = text(input.get("departmentId"), "departmentId", 128)?;
        let resource_id = resource.clone();
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    touch.touch(helpers.people_below(&tx, &tenant.id, &resource_id).await?);
                    let removed = helpers
                        .delete_department(&tx, &principal, &tenant, body)
                        .await?;
                    Ok(json!({
                        "deleted": true,
                        "unassigned": removed.unassigned,
                        "teams": removed.teams,
                    }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:departments:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(
            self.reconciled(&input, &touched, result).await?,
        ))
    }

    /// `departments/get`: one department with its path, sub-departments, head, and teams.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<departments::GetInput>,
    ) -> IamResult<Reply<departments::GetOutput>> {
        let ctx = &self.ctx;
        let helpers = &self.helpers;
        let body = &input;
        let resource = text(input.get("departmentId"), "departmentId", 128)?;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let department = load_department(
                    &tx,
                    &string_member(body, "tenantId"),
                    body.get("departmentId"),
                )
                .await?;
                Ok(helpers.detail(&tx, &department).await?)
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:departments:read",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `departments/importFromAttribute`: builds department membership from a string identity attribute (such as
    /// `department`, which SCIM provisioning fills): each active person moves to the department whose name or code
    /// equals the value (case-insensitive). `createMissing` creates top-level departments for unmatched values;
    /// `dryRun` reports without changing anything.
    pub async fn import_from_attribute(
        &self,
        credential: &CredentialInput,
        input: Body<departments::ImportFromAttributeInput>,
    ) -> IamResult<Reply<departments::ImportFromAttributeOutput>> {
        let ctx = &self.ctx;
        let helpers = &self.helpers;
        let body = &input;
        let touched = Touched::default();
        let touch = touched.clone();
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let attribute = text(body.get("attribute"), "attribute", 64)?;
                    if ctx.catalog.identity_attributes.get(&attribute)
                        != Some(&AttributeType::String)
                    {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            format!(
                                "{attribute} is not a declared string identity attribute (permissions.identityAttributes)"
                            ),
                        )
                        .into());
                    }
                    let dry_run = body.get("dryRun") == Some(&Value::Bool(true));
                    let departments = tenant_departments(&tx, &tenant.id).await?;
                    let mut by_key: HashMap<String, Department> = HashMap::new();
                    for department in departments.values() {
                        by_key.insert(to_lower(&department.name), department.clone());
                        if let Some(code) =
                            department.code.as_deref().filter(|code| !code.is_empty())
                        {
                            by_key.insert(to_lower(code), department.clone());
                        }
                    }
                    let mut created: Vec<String> = Vec::new();
                    let mut assigned = 0usize;
                    let mut unchanged = 0usize;
                    let mut missing = 0usize;
                    let people: Vec<Record> = tx
                        .find("identities", &by_tenant(&tenant.id), &all())
                        .await?
                        .into_iter()
                        .filter(|identity| {
                            identity.get("kind").and_then(Value::as_str) == Some("user")
                                && identity.get("status").and_then(Value::as_str) == Some("active")
                        })
                        .collect();
                    let mut unmatched: IndexSet<String> = IndexSet::new();
                    for identity in &people {
                        let raw = identity
                            .get("attributes")
                            .and_then(|attributes| attributes.get(&attribute));
                        let value = match raw {
                            Some(Value::String(raw)) => trim(raw).to_owned(),
                            _ => String::new(),
                        };
                        if value.is_empty() {
                            missing += 1;
                            continue;
                        }
                        let mut department = by_key.get(&to_lower(&value)).cloned();
                        if department.is_none() && truthy(body.get("createMissing")) {
                            if (departments.len() + created.len()) as f64 >= MAX_DEPARTMENTS {
                                return Err(IamError::with_status(
                                    "LIMIT_EXCEEDED",
                                    format!(
                                        "At most {} departments",
                                        crate::js::number_to_string(MAX_DEPARTMENTS)
                                    ),
                                    409,
                                )
                                .into());
                            }
                            let name = slice_utf16(&value, 100);
                            let now = ctx.now();
                            let mut record = Map::new();
                            record.insert("id".into(), Value::String(id()));
                            record.insert("tenantId".into(), string_value(&tenant.id));
                            record.insert(
                                "uniqueKey".into(),
                                Value::String(format!("name:{}", to_lower(&name))),
                            );
                            record.insert("name".into(), string_value(&name));
                            record.insert("createdAt".into(), crate::js::number(now));
                            record.insert("updatedAt".into(), crate::js::number(now));
                            let fresh: Department = crate::port::decode(record.clone())?;
                            if !dry_run {
                                tx.insert(departments_collection(), &record).await?;
                                let mut metadata = Map::new();
                                metadata.insert("name".into(), string_value(&name));
                                metadata.insert(
                                    "source".into(),
                                    Value::String(format!("attribute:{attribute}")),
                                );
                                helpers
                                    .audit(
                                        &tx,
                                        &principal,
                                        "department:create",
                                        &tenant.id,
                                        &fresh.id,
                                        metadata,
                                    )
                                    .await?;
                            }
                            by_key.insert(to_lower(&name), fresh.clone());
                            created.push(name);
                            department = Some(fresh);
                        }
                        let Some(department) = department else {
                            unmatched.insert(value);
                            continue;
                        };
                        let identity_id = member_str(identity, "id");
                        let current = department_membership(&tx, &tenant.id, identity_id).await?;
                        if current
                            .as_ref()
                            .is_some_and(|current| current.department_id == department.id)
                        {
                            unchanged += 1;
                            continue;
                        }
                        if !dry_run {
                            let title = current.as_ref().and_then(|current| current.title.clone());
                            helpers
                                .place(&tx, &principal, &department, identity_id, title.as_deref())
                                .await?;
                            touch.touch([identity_id.to_owned()]);
                        }
                        assigned += 1;
                    }
                    let mut unmatched: Vec<String> = unmatched.into_iter().collect();
                    unmatched.sort_by(|a, b| cmp_utf16(a, b));
                    Ok(json!({
                        "dryRun": dry_run,
                        "created": created,
                        "assigned": assigned,
                        "unchanged": unchanged,
                        "unmatched": unmatched,
                        "missing": missing,
                    }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:departments:manage",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(
            self.reconciled(&input, &touched, result).await?,
        ))
    }

    /// `departments/list`: every department with member counts, in name order.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<departments::ListInput>,
    ) -> IamResult<Reply<departments::ListOutput>> {
        let ctx = &self.ctx;
        let helpers = &self.helpers;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let mut summaries: Vec<Map<String, Value>> = helpers
                    .summaries(&tx, &string_member(body, "tenantId"))
                    .await?
                    .into_values()
                    .collect();
                summaries.sort_by(|a, b| {
                    locale_compare(member_str(a, "name"), member_str(b, "name")).then_with(|| {
                        if cmp_utf16(member_str(a, "id"), member_str(b, "id")) == Ordering::Less {
                            Ordering::Less
                        } else {
                            Ordering::Greater
                        }
                    })
                });
                Ok(Value::Array(
                    summaries.into_iter().map(Value::Object).collect(),
                ))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:departments:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `departments/listMembers`: the people of a department (with `includeSubdepartments`, of every department
    /// below it too), by name.
    pub async fn list_members(
        &self,
        credential: &CredentialInput,
        input: Body<departments::ListMembersInput>,
    ) -> IamResult<Reply<departments::ListMembersOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let resource = text(input.get("departmentId"), "departmentId", 128)?;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let department = load_department(&tx, &tenant_id, body.get("departmentId")).await?;
                let departments = tenant_departments(&tx, &tenant_id).await?;
                let mut scope = vec![department.clone()];
                if truthy(body.get("includeSubdepartments")) {
                    scope.extend(descendants(&departments, &department.id)?);
                }
                let mut views = member_views(&tx, &tenant_id, &scope).await?;
                views.sort_by(by_head_then_name);
                Ok(Value::Array(views.into_iter().map(Value::Object).collect()))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:departments:read",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `departments/mine`: the caller's own department (with the departments above it, their title, and their head)
    /// and, for department heads, the people of each department they head and of every department below it. Needs
    /// only an ordinary session of a person in the organization.
    pub async fn mine(
        &self,
        credential: &CredentialInput,
        input: Body<departments::MineInput>,
    ) -> IamResult<Reply<departments::MineOutput>> {
        let ctx = self.ctx.clone();
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let helpers = DepartmentMutations { ctx: ctx.clone() };
        let store = ctx.store.clone();
        let result = store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                if !acts_in_own_right(principal.session.kind)
                    || principal.session.tenant_id != tenant_id
                    || principal.identity.tenant_id != tenant_id
                    || principal.identity.kind != IdentityKind::User
                {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "Departments are read from a person\u{2019}s own session in their organization",
                        403,
                    ));
                }
                let me = principal.identity.id.clone();
                let departments = tenant_departments(&tx, &tenant_id).await?;
                let placement = helpers
                    .placement(&tx, &tenant_id, &me, &departments)
                    .await?;
                let mut led: Vec<&Department> = departments
                    .values()
                    .filter(|item| item.head_id.as_deref() == Some(me.as_str()))
                    .collect();
                led.sort_by(|a, b| locale_compare(&a.name, &b.name));
                let mut leads = Vec::new();
                for department in led {
                    let mut scope = vec![department.clone()];
                    scope.extend(descendants(&departments, &department.id)?);
                    let mut people = member_views(&tx, &tenant_id, &scope).await?;
                    people.sort_by(by_head_then_name);
                    leads.push(json!({
                        "department": department_ref(department),
                        "path": path_refs(department_chain(&departments, &department.id)?),
                        "people": people,
                    }));
                }
                Ok(json!({
                    "department": placement.map_or(Value::Null, Value::Object),
                    "leads": leads,
                }))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `departments/ofIdentity`: a person's department with the departments above it (top first), or null without
    /// one.
    pub async fn of_identity(
        &self,
        credential: &CredentialInput,
        input: Body<departments::OfIdentityInput>,
    ) -> IamResult<Reply<departments::OfIdentityOutput>> {
        let ctx = &self.ctx;
        let helpers = &self.helpers;
        let body = &input;
        let resource = text(input.get("identityId"), "identityId", 128)?;
        let identity_id = resource.clone();
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                ctx.scoped(&tx, "identities", body.get("identityId"), &tenant_id)
                    .await?;
                let departments = tenant_departments(&tx, &tenant_id).await?;
                let placement = helpers
                    .placement(&tx, &tenant_id, &identity_id, &departments)
                    .await?;
                Ok(placement.map_or(Value::Null, Value::Object))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:departments:read",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `departments/suggestBirthright`: roles and groups that at least `minShare` (default 0.8) of a department's
    /// people hold by hand, for departments of at least `minPeople` (default 3) people, as a ready-made automatic
    /// access package whose rule names the department. Read-only; requires iam:analysis:read.
    pub async fn suggest_birthright(
        &self,
        credential: &CredentialInput,
        input: Body<departments::SuggestBirthrightInput>,
    ) -> IamResult<Reply<departments::SuggestBirthrightOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let raw = Value::Object((**body).clone());
                let options = birthright_options(&raw)?;
                if let Some(department_id) = body.get("departmentId") {
                    load_department(&tx, &tenant.id, Some(department_id)).await?;
                }
                let mut merged = match options {
                    Value::Object(options) => options,
                    _ => Map::new(),
                };
                if let Some(department_id) = body.get("departmentId") {
                    merged.insert("unitId".into(), department_id.clone());
                }
                let suggestions =
                    suggest_birthright(ctx, &tx, &tenant.id, "department", &Value::Object(merged))
                        .await?;
                Ok(serde_json::to_value(suggestions).map_err(|error| {
                    IamError::with_status("INTERNAL_ERROR", error.to_string(), 500)
                })?)
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:analysis:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `departments/syncManagers`: makes department heads the managers (`Identity.managerId`) of their departments'
    /// people, so approvals routed to managers follow the org chart: each person reports to their department's head,
    /// and a head to the nearest head above. Without `overwrite` only people without a manager change;
    /// `departmentId` limits it to one department (and the ones below it); `dryRun` reports only. Cycles are never
    /// created.
    pub async fn sync_managers(
        &self,
        credential: &CredentialInput,
        input: Body<departments::SyncManagersInput>,
    ) -> IamResult<Reply<departments::SyncManagersOutput>> {
        let ctx = &self.ctx;
        let helpers = &self.helpers;
        let body = &input;
        let touched = Touched::default();
        let touch = touched.clone();
        let resource = match input.get("departmentId") {
            None => string_member(&input, "tenantId"),
            Some(department_id) => text(Some(department_id), "departmentId", 128)?,
        };
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let decisions = ctx.decisions()?;
                    let denied = decisions
                        .decide(
                            &tx,
                            &principal,
                            &AuthorizationRequest {
                                credential: CredentialInput::default(),
                                tenant_id: tenant.id.clone(),
                                action: "iam:departments:read".into(),
                                resource: ResourceTarget {
                                    kind: "iam".into(),
                                    id: tenant.id.clone(),
                                },
                            },
                            true,
                        )
                        .await?;
                    if !denied.allowed {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "Reading departments needs iam:departments:read",
                            403,
                        )
                        .into());
                    }
                    let departments = tenant_departments(&tx, &tenant.id).await?;
                    let scope: Vec<Department> = match body.get("departmentId") {
                        None => departments.values().cloned().collect(),
                        Some(department_id) => {
                            let root = department_id
                                .as_str()
                                .and_then(|department_id| departments.get(department_id))
                                .ok_or_else(|| {
                                    IamError::with_status("NOT_FOUND", "Department not found", 404)
                                })?;
                            let mut scope = vec![root.clone()];
                            scope.extend(descendants(&departments, &root.id)?);
                            scope
                        }
                    };
                    let dry_run = body.get("dryRun") == Some(&Value::Bool(true));
                    let mut updated: Vec<Value> = Vec::new();
                    let mut kept = 0usize;
                    let mut no_head = 0usize;
                    let mut identities: IndexMap<String, Record> = IndexMap::new();
                    for identity in tx
                        .find("identities", &by_tenant(&tenant.id), &all())
                        .await?
                    {
                        identities.insert(member_str(&identity, "id").to_owned(), identity);
                    }
                    for department in &scope {
                        for member in tx
                            .find(
                                members_collection(),
                                &by_tenant(&tenant.id).eq("departmentId", department.id.as_str()),
                                &all(),
                            )
                            .await?
                        {
                            let Some(identity) =
                                identities.get(member_str(&member, "identityId")).cloned()
                            else {
                                continue;
                            };
                            if identity.get("status").and_then(Value::as_str) != Some("active") {
                                continue;
                            }
                            let identity_id = member_str(&identity, "id").to_owned();
                            let live_head = |department: &Department| -> Option<Record> {
                                let head = department
                                    .head_id
                                    .as_deref()
                                    .filter(|id| !id.is_empty())
                                    .and_then(|head_id| identities.get(head_id))?;
                                (head.get("status").and_then(Value::as_str) == Some("active"))
                                    .then(|| head.clone())
                            };
                            let manager = department_chain(&departments, &department.id)?
                                .iter()
                                .map(live_head)
                                .find(|head| {
                                    head.as_ref()
                                        .is_some_and(|head| member_str(head, "id") != identity_id)
                                })
                                .flatten();
                            let Some(manager) = manager else {
                                no_head += 1;
                                continue;
                            };
                            let manager_id = member_str(&manager, "id").to_owned();
                            let current = identity.get("managerId");
                            if current.and_then(Value::as_str) == Some(manager_id.as_str()) {
                                continue;
                            }
                            if truthy(current) && !truthy(body.get("overwrite")) {
                                kept += 1;
                                continue;
                            }
                            // Whether `managerId`'s own chain of managers reaches the person (a cycle).
                            let reaches = {
                                let mut cursor = identities.get(&manager_id);
                                let mut found = false;
                                let mut depth = 0;
                                while let Some(step) = cursor {
                                    if depth >= 100 {
                                        break;
                                    }
                                    if member_str(step, "id") == identity_id {
                                        found = true;
                                        break;
                                    }
                                    cursor = if truthy(step.get("managerId")) {
                                        identities.get(member_str(step, "managerId"))
                                    } else {
                                        None
                                    };
                                    depth += 1;
                                }
                                found
                            };
                            if reaches {
                                kept += 1;
                                continue;
                            }
                            // Each person is updated as identities.update would: a deny protecting that identity
                            // holds.
                            let may = decisions
                                .decide(
                                    &tx,
                                    &principal,
                                    &AuthorizationRequest {
                                        credential: CredentialInput::default(),
                                        tenant_id: tenant.id.clone(),
                                        action: "iam:identities:update".into(),
                                        resource: ResourceTarget {
                                            kind: "iam".into(),
                                            id: identity_id.clone(),
                                        },
                                    },
                                    true,
                                )
                                .await?;
                            if !may.allowed {
                                kept += 1;
                                continue;
                            }
                            updated.push(json!({
                                "identityId": identity_id,
                                "name": identity.get("name").cloned().unwrap_or(Value::Null),
                                "managerId": manager_id,
                                "managerName": manager.get("name").cloned().unwrap_or(Value::Null),
                            }));
                            let mut next = identity.clone();
                            next.insert("managerId".into(), Value::String(manager_id));
                            identities.insert(identity_id, next.clone());
                            if !dry_run {
                                tx.put("identities", &next).await?;
                            }
                        }
                    }
                    if !dry_run && !updated.is_empty() {
                        let mut metadata = Map::new();
                        metadata.insert("updated".into(), json!(updated.len()));
                        if truthy(body.get("departmentId")) {
                            metadata.insert("departmentId".into(), body["departmentId"].clone());
                        }
                        helpers
                            .audit(
                                &tx,
                                &principal,
                                "department:sync-managers",
                                &tenant.id,
                                &tenant.id,
                                metadata,
                            )
                            .await?;
                    }
                    // Rules may test identity.managerId.
                    if !dry_run {
                        touch.touch(updated.iter().map(|entry| {
                            entry
                                .get("identityId")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_owned()
                        }));
                    }
                    Ok(json!({
                        "dryRun": dry_run,
                        "updated": updated,
                        "kept": kept,
                        "noHead": no_head,
                    }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:identities:update",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(
            self.reconciled(&input, &touched, result).await?,
        ))
    }

    /// `departments/tree`: the department tree (org chart): top-level departments with their sub-departments and
    /// heads.
    pub async fn tree(
        &self,
        credential: &CredentialInput,
        input: Body<departments::TreeInput>,
    ) -> IamResult<Reply<departments::TreeOutput>> {
        let ctx = &self.ctx;
        let helpers = &self.helpers;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let departments = tenant_departments(&tx, &tenant_id).await?;
                let all_summaries = helpers.summaries(&tx, &tenant_id).await?;
                let mut heads: HashMap<String, Map<String, Value>> = HashMap::new();
                for department in departments.values() {
                    if let Some(head) = helpers.head_of(&tx, department).await? {
                        heads.insert(department.id.clone(), head);
                    }
                }
                Ok(Value::Array(build_tree(
                    &departments,
                    &all_summaries,
                    &heads,
                    None,
                    0,
                )))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:departments:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `departments/unassign`: takes a person out of their department.
    pub async fn unassign(
        &self,
        credential: &CredentialInput,
        input: Body<departments::UnassignInput>,
    ) -> IamResult<Reply<departments::UnassignOutput>> {
        let ctx = &self.ctx;
        let helpers = &self.helpers;
        let body = &input;
        let touched = Touched::default();
        let touch = touched.clone();
        let resource = text(input.get("identityId"), "identityId", 128)?;
        let identity_id = resource.clone();
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let membership = department_membership(&tx, &tenant_id, &identity_id)
                    .await?
                    .ok_or_else(|| {
                        IamError::with_status("NOT_FOUND", "Not in a department", 404)
                    })?;
                tx.delete(members_collection(), &membership.id).await?;
                let mut metadata = Map::new();
                metadata.insert("identityId".into(), string_value(&identity_id));
                helpers
                    .audit(
                        &tx,
                        &principal,
                        "department:unassign",
                        &tenant_id,
                        &membership.department_id,
                        metadata,
                    )
                    .await?;
                touch.touch([identity_id.clone()]);
                Ok(json!({ "deleted": true }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:departments:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(
            self.reconciled(&input, &touched, result).await?,
        ))
    }

    /// `departments/update`: renames, re-codes, moves (`parentId`, null for top level), or changes the head or cost
    /// center of a department.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<departments::UpdateInput>,
    ) -> IamResult<Reply<departments::UpdateOutput>> {
        let ctx = &self.ctx;
        let helpers = &self.helpers;
        let body = &input;
        let touched = Touched::default();
        let touch = touched.clone();
        let resource = text(input.get("departmentId"), "departmentId", 128)?;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let updated = helpers
                        .update_department(&tx, &principal, &tenant, body)
                        .await?;
                    // A move changes identity.departments for everyone at or below it.
                    if body.get("parentId").is_some() {
                        touch.touch(helpers.people_below(&tx, &tenant.id, &updated.id).await?);
                    }
                    Ok(helpers.detail(&tx, &updated).await?)
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:departments:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(
            self.reconciled(&input, &touched, result).await?,
        ))
    }
}

/// `build(parentId, depth)` of `tree`: the departments under `parent_id` (a department whose parent is gone is shown
/// at the top), by name, each with its sub-departments.
fn build_tree(
    departments: &IndexMap<String, Department>,
    summaries: &IndexMap<String, Map<String, Value>>,
    heads: &HashMap<String, Map<String, Value>>,
    parent_id: Option<&str>,
    depth: usize,
) -> Vec<Value> {
    if depth as f64 > MAX_DEPARTMENT_DEPTH {
        return Vec::new();
    }
    let mut level: Vec<&Department> = departments
        .values()
        .filter(|department| {
            department.parent_id.as_deref() == parent_id
                || (parent_id.is_none()
                    && department
                        .parent_id
                        .as_deref()
                        .is_some_and(|parent| !departments.contains_key(parent)))
        })
        .collect();
    level.sort_by(|a, b| locale_compare(&a.name, &b.name));
    level
        .into_iter()
        .map(|department| {
            let mut node = summaries.get(&department.id).cloned().unwrap_or_default();
            if let Some(head) = heads.get(&department.id) {
                node.insert("head".into(), Value::Object(head.clone()));
            }
            node.insert(
                "children".into(),
                Value::Array(build_tree(
                    departments,
                    summaries,
                    heads,
                    Some(&department.id),
                    depth + 1,
                )),
            );
            Value::Object(node)
        })
        .collect()
}

/// Transaction-level department changes for configuration sync (org-sync.ts): the same validation and audit events
/// as the API. Callers authorize each change first.
pub fn department_mutations(ctx: &Arc<ServerContext>) -> IamResult<DepartmentMutations> {
    Ok(DepartmentMutations { ctx: ctx.clone() })
}
