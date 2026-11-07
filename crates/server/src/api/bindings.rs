//! Port of `packages/server/src/api/bindings.ts`: role bindings (standing, temporary, future-dated, windowed and
//! eligible just-in-time grants), their activations and approval requests (`bindings` group), and delegated grant
//! authorities (`authorities` group).
//!
//! Bindings and activations are handled as raw records (`better_iam_core::Record`), so members this version does not
//! know and the member order of records written by the TypeScript server survive a read-modify-write; values are read
//! with JavaScript semantics where the TypeScript compares them.

use std::cmp::Ordering;
use std::sync::Arc;

use better_iam_auth::outbox::EnqueueInput;
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, OutboxKind, Record, record_id,
};
use better_iam_types::api::{authorities, bindings};
use serde_json::{Map, Value, json};

use crate::access_policy::{MAX_ACTIVATION_MS, activation_rules};
use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::js::{
    MAX_SAFE_INTEGER, defined, invalid_input, js_string, number, number_to_string, truthy,
};
use crate::models::Binding;
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::session_kinds::acts_in_own_right;
use crate::utils::id;
use crate::validation::{integer, text};

/// `maxActivation`: the longest activation a binding may allow (seven days).
const MAX_ACTIVATION: f64 = MAX_ACTIVATION_MS;

/// The eligibility settings a binding create or update accepts (`EligibilityInput`).
const ELIGIBILITY_KEYS: [&str; 7] = [
    "eligible",
    "maxActivationMs",
    "requireJustification",
    "requireMfa",
    "requireApproval",
    "approverGroupId",
    "managerApproval",
];

fn find_all() -> FindOptions {
    FindOptions::default()
}

/// `boolean(value, name)`: `typeof value === 'boolean'`.
fn boolean(value: Option<&Value>, name: &str) -> IamResult<bool> {
    match value {
        Some(Value::Bool(flag)) => Ok(*flag),
        _ => Err(invalid_input(format!("{name} must be boolean"))),
    }
}

/// A member read as a JavaScript number for a relational comparison or arithmetic (`ToNumber`): an absent member
/// (`undefined`) is NaN, which no comparison accepts.
fn numeric(record: &Map<String, Value>, key: &str) -> f64 {
    record
        .get(key)
        .map_or(f64::NAN, better_iam_core::js::to_number)
}

/// A string member, or "" when it is absent or not a string.
fn str_of<'a>(record: &'a Map<String, Value>, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or("")
}

/// `String(record.key)` for a member used in keys, payloads and messages.
fn string_of(record: &Map<String, Value>, key: &str) -> String {
    js_string(record.get(key))
}

/// `ctx.liveBinding(binding)` on a raw record.
fn live_binding(ctx: &ServerContext, binding: &Map<String, Value>) -> bool {
    let now = ctx.now();
    (binding.get("startsAt").is_none() || numeric(binding, "startsAt") <= now)
        && (binding.get("expiresAt").is_none() || numeric(binding, "expiresAt") > now)
}

/// `ctx.expiredBinding(binding)` on a raw record.
fn expired_binding(ctx: &ServerContext, binding: &Map<String, Value>) -> bool {
    binding.get("expiresAt").is_some() && numeric(binding, "expiresAt") <= ctx.now()
}

/// `ctx.liveMembership(member)` on a raw record.
fn live_membership(ctx: &ServerContext, member: &Map<String, Value>) -> bool {
    member.get("expiresAt").is_none() || numeric(member, "expiresAt") > ctx.now()
}

/// An activation past its end (or still awaiting approval, or denied) grants nothing.
fn live_activation(activation: &Map<String, Value>, now: f64) -> bool {
    let status = activation.get("status").and_then(Value::as_str);
    numeric(activation, "expiresAt") > now && status != Some("pending") && status != Some("denied")
}

/// A request that still waits for a decision.
fn pending_activation(activation: &Map<String, Value>, now: f64) -> bool {
    activation.get("status").and_then(Value::as_str) == Some("pending")
        && numeric(activation, "expiresAt") > now
}

/// An access window as `accessWindow` writes it (`from`, `to`, `timeZone`, then `days`), numbers in JavaScript form.
fn window_value(window: &crate::models::AccessWindow) -> Value {
    let mut map = Map::new();
    map.insert("from".into(), Value::String(window.from.clone()));
    map.insert("to".into(), Value::String(window.to.clone()));
    map.insert("timeZone".into(), Value::String(window.time_zone.clone()));
    if let Some(days) = &window.days {
        map.insert(
            "days".into(),
            Value::Array(days.iter().map(|day| number(*day)).collect()),
        );
    }
    Value::Object(map)
}

/// The binding record as its typed form, for the activation rules.
fn typed_binding(binding: &Record) -> IamResult<Binding> {
    crate::port::decode(binding.clone())
}

/// Applies eligibility settings to a binding; activation options are only meaningful on eligible bindings.
fn apply_eligibility(binding: &mut Record, input: &Map<String, Value>) -> IamResult<()> {
    if let Some(eligible) = input.get("eligible") {
        if boolean(Some(eligible), "eligible")? {
            binding.insert("eligible".into(), Value::Bool(true));
        } else {
            for key in ELIGIBILITY_KEYS {
                binding.shift_remove(key);
            }
        }
    }
    for flag in [
        "requireJustification",
        "requireMfa",
        "requireApproval",
        "managerApproval",
    ] {
        if let Some(value) = input.get(flag) {
            boolean(Some(value), flag)?;
        }
    }
    // Explicit `false` flags are harmless on standing bindings (forms send every checkbox); settings are not.
    let set = |key: &str| input.get(key) == Some(&Value::Bool(true));
    let settings = input.get("maxActivationMs").is_some()
        || set("requireJustification")
        || set("requireMfa")
        || set("requireApproval")
        || set("managerApproval")
        || defined(input.get("approverGroupId")).is_some();
    let eligible = truthy(binding.get("eligible"));
    if settings && !eligible {
        return Err(invalid_input(
            "Activation settings apply to eligible bindings only",
        ));
    }
    if !eligible {
        return Ok(());
    }
    let flag = |binding: &mut Record, key: &str| {
        if let Some(value) = input.get(key) {
            if value == &Value::Bool(true) {
                binding.insert(key.into(), Value::Bool(true));
            } else {
                binding.shift_remove(key);
            }
        }
    };
    flag(binding, "requireApproval");
    flag(binding, "managerApproval");
    if let Some(value) = input.get("maxActivationMs") {
        let max = integer(Some(value), "maxActivationMs", 60_000.0, MAX_ACTIVATION)?;
        binding.insert("maxActivationMs".into(), number(max));
    }
    flag(binding, "requireJustification");
    flag(binding, "requireMfa");
    Ok(())
}

/// Sets or clears the approver group of an eligible binding; the group must belong to the tenant.
async fn apply_approvers(
    ctx: &ServerContext,
    tx: &Store,
    binding: &mut Record,
    input: &Map<String, Value>,
) -> IamResult<()> {
    let Some(approver_group_id) = input.get("approverGroupId") else {
        return Ok(());
    };
    if approver_group_id.is_null() {
        binding.shift_remove("approverGroupId");
        return Ok(());
    }
    if !truthy(binding.get("eligible")) {
        return Ok(());
    }
    let tenant_id = str_of(binding, "tenantId").to_owned();
    ctx.scoped(tx, "groups", Some(approver_group_id), &tenant_id)
        .await?;
    binding.insert("approverGroupId".into(), approver_group_id.clone());
    Ok(())
}

/// The `authorityId` argument of `grantingAuthority`: a truthy value that is not a string fails its ID validation,
/// after the impersonation check `grantingAuthority` makes first.
fn authority_argument<'a>(
    principal: &AuthenticatedPrincipal,
    value: Option<&'a Value>,
) -> IamResult<Option<&'a str>> {
    match value {
        Some(Value::String(authority_id)) => Ok(Some(authority_id.as_str())),
        other if truthy(other) => {
            if principal.session.impersonator_id.is_some() {
                return Err(IamError::with_status(
                    "IMPERSONATION_RESTRICTED",
                    "Access cannot be granted while impersonating",
                    403,
                ));
            }
            Err(invalid_input("Invalid id"))
        }
        _ => Ok(None),
    }
}

/// [`create_binding`] returning the stored record (member order as the TypeScript writes it).
pub async fn create_binding_record(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    input: &Map<String, Value>,
    package_assignment_id: Option<&str>,
) -> IamResult<Record> {
    let tenant_id = str_of(input, "tenantId").to_owned();
    let role = ctx
        .scoped(tx, "roles", input.get("roleId"), &tenant_id)
        .await?;
    if truthy(role.get("protected")) {
        return Err(IamError::with_status(
            "PROTECTED_RESOURCE",
            "Use owner transfer for protected roles",
            403,
        ));
    }
    let subject_type = input.get("subjectType").and_then(Value::as_str);
    if subject_type != Some("identity") && subject_type != Some("group") {
        return Err(invalid_input("Invalid subject type"));
    }
    if subject_type == Some("identity") {
        ctx.active_identity(tx, str_of(input, "subjectId"), &tenant_id)
            .await?;
    } else {
        ctx.scoped(tx, "groups", input.get("subjectId"), &tenant_id)
            .await?;
    }
    let authority_id = authority_argument(principal, input.get("authorityId"))?;
    let authority = ctx
        .granting_authority(tx, principal, &tenant_id, authority_id)
        .await?;
    let package_assignment_id = package_assignment_id.filter(|id| !id.is_empty());
    let mut binding = Record::new();
    binding.insert("id".into(), Value::String(id()));
    binding.insert("tenantId".into(), Value::String(tenant_id.clone()));
    binding.insert(
        "uniqueKey".into(),
        Value::String(format!(
            "{}:{}:{}:{}{}",
            string_of(input, "subjectType"),
            string_of(input, "subjectId"),
            string_of(input, "roleId"),
            authority.id,
            package_assignment_id
                .map(|package| format!(":package:{package}"))
                .unwrap_or_default()
        )),
    );
    binding.insert(
        "subjectType".into(),
        input.get("subjectType").cloned().unwrap_or(Value::Null),
    );
    binding.insert(
        "subjectId".into(),
        input.get("subjectId").cloned().unwrap_or(Value::Null),
    );
    binding.insert(
        "roleId".into(),
        input.get("roleId").cloned().unwrap_or(Value::Null),
    );
    binding.insert("authorityId".into(), Value::String(authority.id.clone()));
    if let Some(package) = package_assignment_id {
        binding.insert(
            "packageAssignmentId".into(),
            Value::String(package.to_owned()),
        );
    }
    if let Some(expires_at) = input.get("expiresAt") {
        binding.insert(
            "expiresAt".into(),
            number(ctx.binding_expiry(Some(expires_at))?),
        );
    }
    if let Some(starts_at) = input.get("startsAt") {
        binding.insert(
            "startsAt".into(),
            number(ctx.binding_start(Some(starts_at))?),
        );
    }
    if binding.contains_key("startsAt")
        && binding.contains_key("expiresAt")
        && numeric(&binding, "startsAt") >= numeric(&binding, "expiresAt")
    {
        return Err(invalid_input("startsAt must be before expiresAt"));
    }
    if let Some(window) = input.get("window") {
        let window = ctx.access_window(Some(window))?;
        binding.insert("window".into(), window_value(&window));
    }
    apply_eligibility(&mut binding, input)?;
    apply_approvers(ctx, tx, &mut binding, input).await?;
    tx.insert("bindings", &binding).await
}

/// Creates a binding under the caller's grant authority; shared by `bindings.create`, invitations, access packages,
/// and configuration sync. A package assignment's bindings carry `packageAssignmentId` and a key of their own, so
/// they never collide with, replace, or depend on a binding someone granted by hand. `input` is the `BindingInput`
/// object; `options` is `{ packageAssignmentId? }`.
pub async fn create_binding(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    input: &Value,
    options: Option<&Value>,
) -> IamResult<crate::models::Binding> {
    let empty = Map::new();
    let input = match input {
        Value::Object(input) => input,
        _ => &empty,
    };
    let package_assignment_id = options
        .and_then(|options| options.get("packageAssignmentId"))
        .filter(|value| truthy(Some(value)))
        .map(|value| js_string(Some(value)));
    let record =
        create_binding_record(ctx, tx, principal, input, package_assignment_id.as_deref()).await?;
    crate::port::decode(record)
}

/// Whether the caller issued a binding: its authority is their own, or they are root. A "view as" session never
/// counts as the member it shows, so it cannot lengthen, change or remove what the member granted.
async fn issued_by_caller(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    binding: &Map<String, Value>,
) -> IamResult<bool> {
    let authority = tx
        .get("grantAuthorities", str_of(binding, "authorityId"))
        .await?;
    let own = authority.as_ref().is_some_and(|authority| {
        authority.get("identityId").and_then(Value::as_str) == Some(principal.identity.id.as_str())
    }) && principal.session.impersonator_id.is_none();
    Ok(own || ctx.root_principal(tx, principal).await?)
}

/// [`delete_binding`] for a raw binding record.
pub async fn delete_binding_record(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    binding: &Map<String, Value>,
) -> IamResult<()> {
    let role = tx.get("roles", str_of(binding, "roleId")).await?;
    if role
        .as_ref()
        .is_some_and(|role| truthy(role.get("protected")))
    {
        return Err(IamError::with_status(
            "PROTECTED_RESOURCE",
            "Use owner transfer",
            403,
        ));
    }
    if !issued_by_caller(ctx, tx, principal, binding).await? {
        return Err(IamError::with_status(
            "ACCESS_DENIED",
            "Cannot mutate a higher authority binding",
            403,
        ));
    }
    let binding_id = str_of(binding, "id");
    let activations = tx
        .find(
            "bindingActivations",
            &Filter::new()
                .eq(
                    "tenantId",
                    binding.get("tenantId").cloned().unwrap_or(Value::Null),
                )
                .eq("bindingId", binding_id),
            &find_all(),
        )
        .await?;
    for activation in activations {
        tx.delete("bindingActivations", record_id(&activation))
            .await?;
    }
    tx.delete("bindings", binding_id).await
}

/// A binding may be removed by the administrator whose authority issued it, or by root.
pub async fn delete_binding(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    binding: &crate::models::Binding,
) -> IamResult<()> {
    delete_binding_record(ctx, tx, principal, &crate::port::encode(binding)).await
}

/// `publicActivation(activation, now)`: the record without its unique key, with its status (`active` by default)
/// and whether it grants the role right now.
fn public_activation(activation: &Map<String, Value>, now: f64) -> Map<String, Value> {
    let mut rest = activation.clone();
    rest.shift_remove("uniqueKey");
    let status = defined(activation.get("status"))
        .cloned()
        .unwrap_or_else(|| Value::String("active".into()));
    rest.insert("status".into(), status);
    rest.insert(
        "active".into(),
        Value::Bool(live_activation(activation, now)),
    );
    rest
}

/// The resource ID of an operation that authorizes on the first defined member
/// (`input.roleId ?? input.subjectId ?? input.tenantId`); a non-string value becomes "", which the envelope refuses.
fn first_defined(input: &Map<String, Value>, keys: &[&str]) -> String {
    keys.iter()
        .find_map(|key| defined(input.get(*key)))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

/// `a.at - b.at || (a.id < b.id ? -1 : 1)` (ascending) for activation records.
fn by_time_then_id(a: &Map<String, Value>, b: &Map<String, Value>, key: &str) -> Ordering {
    let difference = numeric(a, key) - numeric(b, key);
    if difference != 0.0 && !difference.is_nan() {
        return if difference < 0.0 {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    if crate::js::cmp_utf16(str_of(a, "id"), str_of(b, "id")) == Ordering::Less {
        Ordering::Less
    } else {
        Ordering::Greater
    }
}

fn denied(message: &str) -> IamError {
    IamError::with_status("ACCESS_DENIED", message, 403)
}

/// The `bindings` API group (`createBindingsApi(ctx)`): one method per route `bindings/{method}`.
pub struct BindingsApi {
    ctx: Arc<ServerContext>,
}

/// `createBindingsApi(ctx)`.
pub fn create_bindings_api(ctx: &Arc<ServerContext>) -> IamResult<BindingsApi> {
    Ok(BindingsApi { ctx: ctx.clone() })
}

/// Whether a binding's subject is this identity, directly or through group membership.
async fn applies_to(
    ctx: &ServerContext,
    tx: &Store,
    binding: &Map<String, Value>,
    identity_id: &str,
) -> IamResult<bool> {
    if binding.get("subjectType").and_then(Value::as_str) == Some("identity") {
        return Ok(binding.get("subjectId").and_then(Value::as_str) == Some(identity_id));
    }
    let members = tx
        .find(
            "groupMembers",
            &Filter::new()
                .eq(
                    "tenantId",
                    binding.get("tenantId").cloned().unwrap_or(Value::Null),
                )
                .eq(
                    "groupId",
                    binding.get("subjectId").cloned().unwrap_or(Value::Null),
                )
                .eq("identityId", identity_id),
            &find_all(),
        )
        .await?;
    Ok(members.iter().any(|member| live_membership(ctx, member)))
}

/// Queues an email through the host outbox when the deployment delivers email at all.
async fn notify(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
    to: Option<&str>,
    template: &str,
    payload: Map<String, Value>,
) -> IamResult<()> {
    let Some(to) = to.filter(|to| !to.is_empty()) else {
        return Ok(());
    };
    let sends_email = ctx
        .options
        .authentication
        .as_ref()
        .is_some_and(|authentication| authentication.send_email.is_some());
    if !sends_email {
        return Ok(());
    }
    ctx.auth
        .enqueue_delivery(
            tx,
            EnqueueInput {
                tenant_id: tenant_id.to_owned(),
                kind: OutboxKind::Email,
                to: to.to_owned(),
                template: template.to_owned(),
                payload,
                reference: None,
            },
        )
        .await?;
    Ok(())
}

/// Whether the caller may decide on an activation of this binding: anyone holding the permission when the binding
/// names no approvers; otherwise root, the requester's manager (`managerApproval`), or an approver-group member.
async fn may_approve(
    ctx: &ServerContext,
    tx: &Store,
    binding: &Map<String, Value>,
    principal: &AuthenticatedPrincipal,
    requester_id: &str,
) -> IamResult<bool> {
    let approver_group = truthy(binding.get("approverGroupId"));
    let manager_approval = truthy(binding.get("managerApproval"));
    if !approver_group && !manager_approval {
        return Ok(true);
    }
    if ctx.root_principal(tx, principal).await? {
        return Ok(true);
    }
    if manager_approval {
        let requester = tx.get("identities", requester_id).await?;
        if requester.as_ref().is_some_and(|requester| {
            requester.get("managerId").and_then(Value::as_str)
                == Some(principal.identity.id.as_str())
        }) {
            return Ok(true);
        }
    }
    if !approver_group {
        return Ok(false);
    }
    let members = tx
        .find(
            "groupMembers",
            &Filter::new()
                .eq(
                    "tenantId",
                    binding.get("tenantId").cloned().unwrap_or(Value::Null),
                )
                .eq(
                    "groupId",
                    binding
                        .get("approverGroupId")
                        .cloned()
                        .unwrap_or(Value::Null),
                )
                .eq("identityId", principal.identity.id.clone()),
            &find_all(),
        )
        .await?;
    Ok(members.iter().any(|member| live_membership(ctx, member)))
}

/// Who is emailed an activation request: live approver-group members and, with `managerApproval`, the requester's
/// manager (insertion order, never the requester).
async fn approver_ids(
    ctx: &ServerContext,
    tx: &Store,
    binding: &Map<String, Value>,
    requester_id: &str,
) -> IamResult<Vec<String>> {
    let mut recipients: indexmap::IndexSet<String> = indexmap::IndexSet::new();
    if truthy(binding.get("approverGroupId")) {
        let members = tx
            .find(
                "groupMembers",
                &Filter::new()
                    .eq(
                        "tenantId",
                        binding.get("tenantId").cloned().unwrap_or(Value::Null),
                    )
                    .eq(
                        "groupId",
                        binding
                            .get("approverGroupId")
                            .cloned()
                            .unwrap_or(Value::Null),
                    ),
                &find_all(),
            )
            .await?;
        for member in members {
            if live_membership(ctx, &member) {
                recipients.insert(string_of(&member, "identityId"));
            }
        }
    }
    if truthy(binding.get("managerApproval")) {
        let requester = tx.get("identities", requester_id).await?;
        if let Some(manager_id) = requester
            .as_ref()
            .and_then(|requester| defined(requester.get("managerId")))
            .filter(|manager| truthy(Some(manager)))
        {
            recipients.insert(js_string(Some(manager_id)));
        }
    }
    recipients.shift_remove(requester_id);
    Ok(recipients.into_iter().collect())
}

/// `Math.min` / `Math.max` of two JavaScript numbers (NaN wins).
fn js_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.min(b)
    }
}

fn js_max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.max(b)
    }
}

/// A string payload member of an outbox message.
fn payload_string(value: impl Into<String>) -> Value {
    Value::String(value.into())
}

impl BindingsApi {
    /// The `operation` envelope with a mutation (the TypeScript `operation(credential, tenantId, action, resourceId,
    /// fn)`).
    async fn run(
        &self,
        credential: &CredentialInput,
        tenant_id: Option<&Value>,
        action: &str,
        resource_id: &str,
        mutation: Mutation<'_>,
    ) -> IamResult<Value> {
        self.ctx
            .operations()?
            .operation(credential, tenant_id, action, resource_id, mutation, false)
            .await
    }

    /// `decideActivation(credential, input, decision)`: approves or denies a pending activation request.
    async fn decide_activation(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
        decision: &'static str,
    ) -> IamResult<Value> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let existing = ctx
            .scoped(
                &ctx.store,
                "bindingActivations",
                input.get("activationId"),
                &tenant_id,
            )
            .await?;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(input, "tenantId");
                let activation = ctx
                    .scoped(
                        &tx,
                        "bindingActivations",
                        input.get("activationId"),
                        &tenant_id,
                    )
                    .await?;
                let now = ctx.now();
                if !pending_activation(&activation, now) {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "This request is not awaiting a decision",
                        409,
                    )
                    .into());
                }
                let requester_id = string_of(&activation, "identityId");
                if activation.get("identityId").and_then(Value::as_str)
                    == Some(principal.identity.id.as_str())
                {
                    return Err(invalid_input("You cannot decide on your own request").into());
                }
                // Two-person control: an administrator viewing as an approver must not decide in their name.
                if principal.session.impersonator_id.is_some() {
                    return Err(IamError::with_status(
                        "IMPERSONATION_RESTRICTED",
                        "Requests cannot be decided while impersonating",
                        403,
                    )
                    .into());
                }
                let binding = tx.get("bindings", str_of(&activation, "bindingId")).await?;
                let binding = match binding {
                    Some(binding)
                        if truthy(binding.get("eligible")) && live_binding(ctx, &binding) =>
                    {
                        binding
                    }
                    _ => {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "The binding is no longer eligible",
                            409,
                        )
                        .into());
                    }
                };
                if !may_approve(ctx, &tx, &binding, &principal, &requester_id).await? {
                    return Err(denied("Only the designated approvers may decide").into());
                }
                let note = match input.get("note") {
                    Some(note) => Some(text(Some(note), "note", 2048)?),
                    None => None,
                };
                let mut decided = activation.clone();
                decided.insert(
                    "decidedBy".into(),
                    Value::String(principal.identity.id.clone()),
                );
                decided.insert("decidedAt".into(), number(now));
                if let Some(note) = &note {
                    decided.insert("note".into(), Value::String(note.clone()));
                }
                if decision == "approved" {
                    let tenant = ctx.tenant(&tx, &tenant_id).await?;
                    let limit =
                        activation_rules(&typed_binding(&binding)?, tenant.access_policy.as_ref())
                            .max_activation_ms;
                    // Approvers may shorten what was asked for, never lengthen it.
                    let requested = match defined(activation.get("requestedDurationMs")) {
                        None => limit,
                        Some(value) => js_min(better_iam_core::js::to_number(value), limit),
                    };
                    let requested_value = number(requested);
                    let duration_ms = integer(
                        defined(input.get("durationMs")).or(Some(&requested_value)),
                        "durationMs",
                        60_000.0,
                        js_max(requested, 60_000.0),
                    )?;
                    decided.insert("status".into(), Value::String("active".into()));
                    decided.insert("activatedAt".into(), number(now));
                    decided.insert("expiresAt".into(), number(now + duration_ms));
                } else {
                    decided.insert("status".into(), Value::String("denied".into()));
                    decided.insert("expiresAt".into(), number(now));
                }
                tx.put("bindingActivations", &decided).await?;
                let role = tx.get("roles", str_of(&activation, "roleId")).await?;
                let mut metadata = Map::new();
                metadata.insert(
                    "activationId".into(),
                    activation.get("id").cloned().unwrap_or(Value::Null),
                );
                metadata.insert(
                    "roleId".into(),
                    activation.get("roleId").cloned().unwrap_or(Value::Null),
                );
                metadata.insert(
                    "identityId".into(),
                    activation.get("identityId").cloned().unwrap_or(Value::Null),
                );
                if decision == "approved" {
                    metadata.insert(
                        "expiresAt".into(),
                        decided.get("expiresAt").cloned().unwrap_or(Value::Null),
                    );
                }
                if let Some(note) = &note {
                    metadata.insert("note".into(), Value::String(note.clone()));
                }
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        &format!("binding:activation-{decision}"),
                        &tenant_id,
                        str_of(&activation, "bindingId"),
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                let requester = tx.get("identities", &requester_id).await?;
                let mut payload = Map::new();
                payload.insert(
                    "activationId".into(),
                    payload_string(string_of(&activation, "id")),
                );
                payload.insert(
                    "roleId".into(),
                    payload_string(string_of(&activation, "roleId")),
                );
                payload.insert(
                    "roleName".into(),
                    payload_string(
                        role.as_ref()
                            .and_then(|role| defined(role.get("name")))
                            .map(|name| js_string(Some(name)))
                            .unwrap_or_else(|| string_of(&activation, "roleId")),
                    ),
                );
                payload.insert("decision".into(), payload_string(decision));
                payload.insert(
                    "deciderName".into(),
                    payload_string(principal.identity.name.clone()),
                );
                if let Some(note) = &note {
                    payload.insert("note".into(), payload_string(note.clone()));
                }
                if decision == "approved" {
                    payload.insert(
                        "expiresAt".into(),
                        payload_string(number_to_string(numeric(&decided, "expiresAt"))),
                    );
                }
                notify(
                    ctx,
                    &tx,
                    &tenant_id,
                    requester
                        .as_ref()
                        .and_then(|requester| requester.get("email"))
                        .and_then(Value::as_str),
                    "activation-decided",
                    payload,
                )
                .await?;
                Ok(Value::Object(public_activation(&decided, now)))
            })
        });
        self.run(
            credential,
            input.get("tenantId"),
            "iam:bindings:approve",
            str_of(&existing, "roleId"),
            mutation,
        )
        .await
    }

    /// `bindings/activate`: just-in-time elevation. The subject of an eligible binding (directly, or through a
    /// group) activates it for `durationMs` (at most the binding's `maxActivationMs`, one hour by default) with an
    /// optional justification. Requires iam:bindings:activate on the role (`iam/{roleId}`) from an ordinary session of
    /// the tenant; the binding may require MFA, a justification, or an approver's decision. Audited as
    /// `binding:activate` (or `binding:activation-requested`) with the justification.
    pub async fn activate(
        &self,
        credential: &CredentialInput,
        input: Body<bindings::ActivateInput>,
    ) -> IamResult<Reply<bindings::ActivateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let existing = ctx
            .scoped(&ctx.store, "bindings", input.get("bindingId"), &tenant_id)
            .await?;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let binding = ctx
                    .scoped(&tx, "bindings", body.get("bindingId"), &tenant_id)
                    .await?;
                if !truthy(binding.get("eligible")) || !live_binding(ctx, &binding) {
                    return Err(
                        invalid_transition("This binding is not eligible for activation").into(),
                    );
                }
                if !acts_in_own_right(principal.session.kind)
                    || principal.session.tenant_id != tenant_id
                {
                    return Err(invalid_input(
                        "Activations are made from an ordinary session of the target tenant",
                    )
                    .into());
                }
                if principal.session.impersonator_id.is_some() {
                    return Err(IamError::with_status(
                        "IMPERSONATION_RESTRICTED",
                        "Roles cannot be activated while impersonating",
                        403,
                    )
                    .into());
                }
                if !applies_to(ctx, &tx, &binding, &principal.identity.id).await? {
                    return Err(denied("This binding does not apply to you").into());
                }
                let tenant = ctx.tenant(&tx, &tenant_id).await?;
                let rules =
                    activation_rules(&typed_binding(&binding)?, tenant.access_policy.as_ref());
                if rules.require_mfa && !principal.session.mfa {
                    return Err(IamError::with_status(
                        "MFA_REQUIRED",
                        "Activation requires an MFA-verified session",
                        403,
                    )
                    .into());
                }
                let justification = match body.get("justification") {
                    Some(value) => Some(text(Some(value), "justification", 2048)?),
                    None => None,
                };
                if rules.require_justification && justification.is_none() {
                    return Err(invalid_input("This activation requires a justification").into());
                }
                let limit = rules.max_activation_ms;
                let limit_value = number(limit);
                let duration_ms = integer(
                    defined(body.get("durationMs")).or(Some(&limit_value)),
                    "durationMs",
                    60_000.0,
                    limit,
                )?;
                let now = ctx.now();
                let binding_id = string_of(&binding, "id");
                let unique_key = format!("{binding_id}:{}", principal.identity.id);
                let previous = tx
                    .find(
                        "bindingActivations",
                        &Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("uniqueKey", unique_key.clone()),
                        &find_all(),
                    )
                    .await?
                    .into_iter()
                    .next();
                if let Some(previous) = previous {
                    if live_activation(&previous, now) {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "This role is already active for you",
                            409,
                        )
                        .into());
                    }
                    if pending_activation(&previous, now) {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "Your request is still awaiting a decision",
                            409,
                        )
                        .into());
                    }
                    tx.delete("bindingActivations", record_id(&previous))
                        .await?;
                }
                let approval = rules.require_approval;
                // A request that names its approvers must reach at least one who can act on it.
                if approval
                    && (truthy(binding.get("approverGroupId"))
                        || truthy(binding.get("managerApproval")))
                {
                    let mut available = false;
                    for approver_id in
                        approver_ids(ctx, &tx, &binding, &principal.identity.id).await?
                    {
                        let approver = tx.get("identities", &approver_id).await?;
                        if approver.as_ref().is_some_and(|approver| {
                            approver.get("status").and_then(Value::as_str) == Some("active")
                        }) {
                            available = true;
                            break;
                        }
                    }
                    if !available {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "Nobody can approve this request: the approver group is empty and you have no active manager",
                            409,
                        )
                        .into());
                    }
                }
                let expires_at = now
                    + if approval {
                        rules.approval_lifetime_ms
                    } else {
                        duration_ms
                    };
                let mut activation = Record::new();
                activation.insert("id".into(), Value::String(id()));
                activation.insert("tenantId".into(), Value::String(tenant_id.clone()));
                activation.insert("uniqueKey".into(), Value::String(unique_key));
                activation.insert(
                    "bindingId".into(),
                    binding.get("id").cloned().unwrap_or(Value::Null),
                );
                activation.insert(
                    "identityId".into(),
                    Value::String(principal.identity.id.clone()),
                );
                activation.insert(
                    "roleId".into(),
                    binding.get("roleId").cloned().unwrap_or(Value::Null),
                );
                activation.insert("activatedAt".into(), number(now));
                activation.insert("expiresAt".into(), number(expires_at));
                activation.insert(
                    "sessionId".into(),
                    Value::String(principal.session.id.clone()),
                );
                if approval {
                    activation.insert("status".into(), Value::String("pending".into()));
                    activation.insert("requestedDurationMs".into(), number(duration_ms));
                }
                if let Some(justification) = &justification {
                    activation.insert("justification".into(), Value::String(justification.clone()));
                }
                tx.insert("bindingActivations", &activation).await?;
                let mut metadata = Map::new();
                metadata.insert(
                    "activationId".into(),
                    activation.get("id").cloned().unwrap_or(Value::Null),
                );
                metadata.insert(
                    "roleId".into(),
                    binding.get("roleId").cloned().unwrap_or(Value::Null),
                );
                metadata.insert("expiresAt".into(), number(expires_at));
                if approval {
                    metadata.insert("requestedDurationMs".into(), number(duration_ms));
                }
                if let Some(justification) = &justification {
                    metadata.insert("justification".into(), Value::String(justification.clone()));
                }
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        if approval {
                            "binding:activation-requested"
                        } else {
                            "binding:activate"
                        },
                        &tenant_id,
                        &binding_id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                // The designated approvers (group members, the requester's manager) learn about the request by email.
                if approval {
                    let role = tx.get("roles", str_of(&binding, "roleId")).await?;
                    let role_id = string_of(&binding, "roleId");
                    let role_name = role
                        .as_ref()
                        .and_then(|role| defined(role.get("name")))
                        .map(|name| js_string(Some(name)))
                        .unwrap_or_else(|| role_id.clone());
                    for approver_id in
                        approver_ids(ctx, &tx, &binding, &principal.identity.id).await?
                    {
                        let approver = tx.get("identities", &approver_id).await?;
                        let Some(approver) = approver.filter(|approver| {
                            approver.get("status").and_then(Value::as_str) == Some("active")
                        }) else {
                            continue;
                        };
                        let mut payload = Map::new();
                        payload.insert(
                            "activationId".into(),
                            payload_string(string_of(&activation, "id")),
                        );
                        payload.insert("roleId".into(), payload_string(role_id.clone()));
                        payload.insert("roleName".into(), payload_string(role_name.clone()));
                        payload.insert(
                            "requesterId".into(),
                            payload_string(principal.identity.id.clone()),
                        );
                        payload.insert(
                            "requesterName".into(),
                            payload_string(principal.identity.name.clone()),
                        );
                        if let Some(email) = principal
                            .identity
                            .email
                            .as_ref()
                            .filter(|email| !email.is_empty())
                        {
                            payload.insert("requesterEmail".into(), payload_string(email.clone()));
                        }
                        payload.insert(
                            "requestedDurationMs".into(),
                            payload_string(number_to_string(duration_ms)),
                        );
                        payload.insert(
                            "expiresAt".into(),
                            payload_string(number_to_string(expires_at)),
                        );
                        if let Some(justification) = &justification {
                            payload.insert(
                                "justification".into(),
                                payload_string(justification.clone()),
                            );
                        }
                        notify(
                            ctx,
                            &tx,
                            &tenant_id,
                            approver.get("email").and_then(Value::as_str),
                            "activation-request",
                            payload,
                        )
                        .await?;
                    }
                }
                Ok(Value::Object(public_activation(&activation, now)))
            })
        });
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:bindings:activate",
                str_of(&existing, "roleId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `bindings/approveActivation`: grants a pending activation request; the role becomes live for the requested
    /// duration (or the approver's shorter `durationMs`), bounded by the binding's `maxActivationMs`. Requires
    /// iam:bindings:approve on the role (`iam/{roleId}`), membership of the binding's approver group when one is set,
    /// and never one's own request. Audited as `binding:activation-approved`; the requester is emailed
    /// (`activation-decided`).
    pub async fn approve_activation(
        &self,
        credential: &CredentialInput,
        input: Body<bindings::ApproveActivationInput>,
    ) -> IamResult<Reply<bindings::ApproveActivationOutput>> {
        Ok(Reply::json(
            self.decide_activation(credential, &input, "approved")
                .await?,
        ))
    }

    /// `bindings/create`: `expiresAt` (epoch milliseconds) makes the grant temporary; it must lie in the future and
    /// within ten years. `eligible` makes it a just-in-time grant: the subject holds the role only after
    /// `bindings.activate`, for at most `maxActivationMs` (default one hour), optionally with a justification and an
    /// MFA-verified session.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<bindings::CreateInput>,
    ) -> IamResult<Reply<bindings::CreateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let record = create_binding_record(ctx, &tx, &principal, body, None).await?;
                Ok(Value::Object(record))
            })
        });
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:bindings:create",
                &string_member(&input, "roleId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `bindings/deactivate`: ends the caller's own activation early (or cancels their pending request). Audited as
    /// `binding:deactivate`.
    pub async fn deactivate(
        &self,
        credential: &CredentialInput,
        input: Body<bindings::DeactivateInput>,
    ) -> IamResult<Reply<bindings::DeactivateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let existing = ctx
            .scoped(
                &ctx.store,
                "bindingActivations",
                input.get("activationId"),
                &tenant_id,
            )
            .await?;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let activation = ctx
                    .scoped(
                        &tx,
                        "bindingActivations",
                        body.get("activationId"),
                        &tenant_id,
                    )
                    .await?;
                if activation.get("identityId").and_then(Value::as_str)
                    != Some(principal.identity.id.as_str())
                {
                    return Err(denied("Only the holder can end this activation").into());
                }
                let cancelled = activation.get("status").and_then(Value::as_str) == Some("pending");
                tx.delete("bindingActivations", record_id(&activation))
                    .await?;
                let mut metadata = Map::new();
                metadata.insert(
                    "activationId".into(),
                    activation.get("id").cloned().unwrap_or(Value::Null),
                );
                metadata.insert(
                    "roleId".into(),
                    activation.get("roleId").cloned().unwrap_or(Value::Null),
                );
                if cancelled {
                    metadata.insert("cancelled".into(), Value::Bool(true));
                }
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "binding:deactivate",
                        &tenant_id,
                        str_of(&activation, "bindingId"),
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                Ok(json!({ "deactivated": true }))
            })
        });
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:bindings:activate",
                str_of(&existing, "roleId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `bindings/delete`: removes a binding (and its activations); only its issuing authority or root may.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<bindings::DeleteInput>,
    ) -> IamResult<Reply<bindings::DeleteOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let binding = ctx
                    .scoped(&tx, "bindings", body.get("bindingId"), &tenant_id)
                    .await?;
                delete_binding_record(ctx, &tx, &principal, &binding).await?;
                Ok(json!({ "deleted": true }))
            })
        });
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:bindings:delete",
                &string_member(&input, "bindingId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `bindings/denyActivation`: refuses a pending activation request, with an optional note. Audited as
    /// `binding:activation-denied`.
    pub async fn deny_activation(
        &self,
        credential: &CredentialInput,
        input: Body<bindings::DenyActivationInput>,
    ) -> IamResult<Reply<bindings::DenyActivationOutput>> {
        // `{ ...input, durationMs: undefined }`: a denial never reads a duration.
        let mut input = input.into_inner();
        input.shift_remove("durationMs");
        Ok(Reply::json(
            self.decide_activation(credential, &input, "denied").await?,
        ))
    }

    /// `bindings/list`: the tenant's bindings, optionally of one role or subject, eligible or standing only, or
    /// expiring before a time; expired temporary bindings only with `includeExpired`.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<bindings::ListInput>,
    ) -> IamResult<Reply<bindings::ListOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let mut filter = Filter::new().eq(
                    "tenantId",
                    body.get("tenantId").cloned().unwrap_or(Value::Null),
                );
                if let Some(role_id) = body.get("roleId") {
                    filter = filter.eq("roleId", text(Some(role_id), "roleId", 256)?);
                }
                if let Some(subject_type) = body.get("subjectType") {
                    if subject_type.as_str() != Some("identity")
                        && subject_type.as_str() != Some("group")
                    {
                        return Err(invalid_input("Invalid subject type").into());
                    }
                    filter = filter.eq("subjectType", subject_type.clone());
                }
                if let Some(subject_id) = body.get("subjectId") {
                    filter = filter.eq("subjectId", text(Some(subject_id), "subjectId", 256)?);
                }
                let eligible = match body.get("eligible") {
                    Some(value) => Some(boolean(Some(value), "eligible")?),
                    None => None,
                };
                let expires_before = match body.get("expiresBefore") {
                    Some(value) => Some(integer(
                        Some(value),
                        "expiresBefore",
                        0.0,
                        MAX_SAFE_INTEGER,
                    )?),
                    None => None,
                };
                let include_expired = body.get("includeExpired") == Some(&Value::Bool(true));
                let found = tx.find("bindings", &filter, &find_all()).await?;
                let result: Vec<Value> = found
                    .into_iter()
                    .filter(|binding| {
                        (include_expired || !expired_binding(ctx, binding))
                            && eligible
                                .is_none_or(|eligible| truthy(binding.get("eligible")) == eligible)
                            && expires_before.is_none_or(|before| {
                                binding.get("expiresAt").is_some()
                                    && numeric(binding, "expiresAt") <= before
                            })
                    })
                    .map(Value::Object)
                    .collect();
                Ok(Value::Array(result))
            })
        });
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:bindings:read",
                &first_defined(&input, &["roleId", "subjectId", "tenantId"]),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `bindings/listActivations`: activations of eligible bindings, newest first. Without `status`, live
    /// activations; `status: 'pending'` lists open requests and `'denied'` refused ones; ended records are included
    /// only with includeExpired.
    pub async fn list_activations(
        &self,
        credential: &CredentialInput,
        input: Body<bindings::ListActivationsInput>,
    ) -> IamResult<Reply<bindings::ListActivationsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let mut filter = Filter::new().eq(
                    "tenantId",
                    body.get("tenantId").cloned().unwrap_or(Value::Null),
                );
                if let Some(binding_id) = body.get("bindingId") {
                    filter = filter.eq("bindingId", text(Some(binding_id), "bindingId", 256)?);
                }
                if let Some(identity_id) = body.get("identityId") {
                    filter = filter.eq("identityId", text(Some(identity_id), "identityId", 256)?);
                }
                if let Some(role_id) = body.get("roleId") {
                    filter = filter.eq("roleId", text(Some(role_id), "roleId", 256)?);
                }
                let status = body.get("status");
                if let Some(status) = status
                    && !matches!(status.as_str(), Some("pending" | "active" | "denied"))
                {
                    return Err(invalid_input("status must be pending, active, or denied").into());
                }
                let include_expired = body.get("includeExpired") == Some(&Value::Bool(true));
                let now = ctx.now();
                let mut found: Vec<Record> = tx
                    .find("bindingActivations", &filter, &find_all())
                    .await?
                    .into_iter()
                    .filter(|activation| match status {
                        None => include_expired || live_activation(activation, now),
                        Some(status) => {
                            let current = defined(activation.get("status"))
                                .cloned()
                                .unwrap_or_else(|| Value::String("active".into()));
                            current == *status
                                && (include_expired
                                    || status.as_str() == Some("denied")
                                    || numeric(activation, "expiresAt") > now)
                        }
                    })
                    .collect();
                // `b.activatedAt - a.activatedAt || (a.id < b.id ? -1 : 1)`: newest first, ties by ascending id.
                found.sort_by(|a, b| {
                    let difference = numeric(b, "activatedAt") - numeric(a, "activatedAt");
                    if difference != 0.0 && !difference.is_nan() {
                        if difference < 0.0 {
                            Ordering::Less
                        } else {
                            Ordering::Greater
                        }
                    } else if crate::js::cmp_utf16(str_of(a, "id"), str_of(b, "id"))
                        == Ordering::Less
                    {
                        Ordering::Less
                    } else {
                        Ordering::Greater
                    }
                });
                Ok(Value::Array(
                    found
                        .iter()
                        .map(|activation| Value::Object(public_activation(activation, now)))
                        .collect(),
                ))
            })
        });
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:bindings:read",
                &first_defined(&input, &["bindingId", "identityId", "roleId", "tenantId"]),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `bindings/listApprovals`: pending activation requests the caller may decide on: those of bindings whose
    /// approver group they belong to (any binding without a group, for holders of iam:bindings:approve on the role),
    /// never their own. Requires iam:bindings:approve on the tenant.
    pub async fn list_approvals(
        &self,
        credential: &CredentialInput,
        input: Body<bindings::ListApprovalsInput>,
    ) -> IamResult<Reply<bindings::ListApprovalsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let now = ctx.now();
                let mut activations = tx
                    .find(
                        "bindingActivations",
                        &Filter::new().eq("tenantId", tenant_id.clone()),
                        &find_all(),
                    )
                    .await?;
                activations.sort_by(|a, b| by_time_then_id(a, b, "activatedAt"));
                let mut result: Vec<Value> = Vec::new();
                for activation in activations {
                    if !pending_activation(&activation, now)
                        || activation.get("identityId").and_then(Value::as_str)
                            == Some(principal.identity.id.as_str())
                    {
                        continue;
                    }
                    let Some(binding) =
                        tx.get("bindings", str_of(&activation, "bindingId")).await?
                    else {
                        continue;
                    };
                    if !may_approve(
                        ctx,
                        &tx,
                        &binding,
                        &principal,
                        &string_of(&activation, "identityId"),
                    )
                    .await?
                    {
                        continue;
                    }
                    let decision = ctx
                        .decisions()?
                        .decide(
                            &tx,
                            &principal,
                            &AuthorizationRequest {
                                credential: CredentialInput::default(),
                                tenant_id: tenant_id.clone(),
                                action: "iam:bindings:approve".into(),
                                resource: ResourceTarget {
                                    kind: "iam".into(),
                                    id: string_of(&activation, "roleId"),
                                },
                            },
                            true,
                        )
                        .await?;
                    if !decision.allowed {
                        continue;
                    }
                    let role = tx.get("roles", str_of(&activation, "roleId")).await?;
                    let requester = tx
                        .get("identities", str_of(&activation, "identityId"))
                        .await?;
                    let mut item = public_activation(&activation, now);
                    if let Some(role) = role {
                        item.insert(
                            "role".into(),
                            json!({
                                "id": role.get("id").cloned().unwrap_or(Value::Null),
                                "name": role.get("name").cloned().unwrap_or(Value::Null),
                            }),
                        );
                    }
                    if let Some(requester) = requester {
                        let mut summary = Map::new();
                        summary.insert(
                            "id".into(),
                            requester.get("id").cloned().unwrap_or(Value::Null),
                        );
                        summary.insert(
                            "name".into(),
                            requester.get("name").cloned().unwrap_or(Value::Null),
                        );
                        if let Some(email) =
                            requester.get("email").filter(|email| truthy(Some(email)))
                        {
                            summary.insert("email".into(), email.clone());
                        }
                        item.insert("requester".into(), Value::Object(summary));
                    }
                    result.push(Value::Object(item));
                }
                Ok(Value::Array(result))
            })
        });
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:bindings:approve",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `bindings/listMine`: the caller's own bindings, direct and through groups, including eligible ones and their
    /// live activation. Needs only iam:bindings:activate on the tenant, so members can see what they may elevate to.
    pub async fn list_mine(
        &self,
        credential: &CredentialInput,
        input: Body<bindings::ListMineInput>,
    ) -> IamResult<Reply<bindings::ListMineOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                if !acts_in_own_right(principal.session.kind)
                    || principal.session.tenant_id != tenant_id
                {
                    return Err(invalid_input(
                        "Bindings are listed from an ordinary session of the target tenant",
                    )
                    .into());
                }
                let effective = ctx
                    .decisions()?
                    .effective_bindings(&tx, &tenant_id, &principal.identity.id)
                    .await?;
                Ok(Value::Array(
                    effective.iter().map(|binding| binding.to_json()).collect(),
                ))
            })
        });
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:bindings:activate",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `bindings/revokeActivation`: ends someone else's activation (incident response). Requires
    /// iam:bindings:delete on the binding and the binding's own authority, like deleting it. Audited as
    /// `binding:deactivate` with the holder.
    pub async fn revoke_activation(
        &self,
        credential: &CredentialInput,
        input: Body<bindings::RevokeActivationInput>,
    ) -> IamResult<Reply<bindings::RevokeActivationOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let existing = ctx
            .scoped(
                &ctx.store,
                "bindingActivations",
                input.get("activationId"),
                &tenant_id,
            )
            .await?;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let activation = ctx
                    .scoped(
                        &tx,
                        "bindingActivations",
                        body.get("activationId"),
                        &tenant_id,
                    )
                    .await?;
                let binding = tx.get("bindings", str_of(&activation, "bindingId")).await?;
                if let Some(binding) = &binding
                    && !issued_by_caller(ctx, &tx, &principal, binding).await?
                {
                    return Err(denied("Cannot mutate a higher authority binding").into());
                }
                tx.delete("bindingActivations", record_id(&activation))
                    .await?;
                let mut metadata = Map::new();
                metadata.insert(
                    "activationId".into(),
                    activation.get("id").cloned().unwrap_or(Value::Null),
                );
                metadata.insert(
                    "roleId".into(),
                    activation.get("roleId").cloned().unwrap_or(Value::Null),
                );
                metadata.insert(
                    "identityId".into(),
                    activation.get("identityId").cloned().unwrap_or(Value::Null),
                );
                metadata.insert("revoked".into(), Value::Bool(true));
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "binding:deactivate",
                        &tenant_id,
                        str_of(&activation, "bindingId"),
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                Ok(json!({ "deactivated": true }))
            })
        });
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:bindings:delete",
                str_of(&existing, "bindingId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `bindings/update`: extends, shortens, or removes (null) a binding's expiry, sets or clears (null) its access
    /// window, or changes its eligibility settings. Requires iam:bindings:create on the role and the binding's own
    /// authority, like delete. Turning eligibility off ends every activation of the binding.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<bindings::UpdateInput>,
    ) -> IamResult<Reply<bindings::UpdateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let existing = ctx
            .scoped(&ctx.store, "bindings", input.get("bindingId"), &tenant_id)
            .await?;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = string_member(body, "tenantId");
                let binding = ctx
                    .scoped(&tx, "bindings", body.get("bindingId"), &tenant_id)
                    .await?;
                let role = tx.get("roles", str_of(&binding, "roleId")).await?;
                if role
                    .as_ref()
                    .is_some_and(|role| truthy(role.get("protected")))
                {
                    return Err(IamError::with_status(
                        "PROTECTED_RESOURCE",
                        "Use owner transfer",
                        403,
                    )
                    .into());
                }
                if !issued_by_caller(ctx, &tx, &principal, &binding).await? {
                    return Err(denied("Cannot mutate a higher authority binding").into());
                }
                if ["startsAt", "expiresAt", "window"]
                    .iter()
                    .chain(ELIGIBILITY_KEYS.iter())
                    .all(|key| body.get(*key).is_none())
                {
                    return Err(invalid_input("Nothing to update").into());
                }
                // Editing a package's binding by hand takes it over: revoking the package no longer removes it.
                let mut next = binding.clone();
                next.shift_remove("packageAssignmentId");
                match body.get("expiresAt") {
                    Some(Value::Null) => {
                        next.shift_remove("expiresAt");
                    }
                    Some(expires_at) => {
                        next.insert(
                            "expiresAt".into(),
                            number(ctx.binding_expiry(Some(expires_at))?),
                        );
                    }
                    None => {}
                }
                match body.get("startsAt") {
                    Some(Value::Null) => {
                        next.shift_remove("startsAt");
                    }
                    Some(starts_at) => {
                        next.insert(
                            "startsAt".into(),
                            number(ctx.binding_start(Some(starts_at))?),
                        );
                    }
                    None => {}
                }
                if next.contains_key("startsAt")
                    && next.contains_key("expiresAt")
                    && numeric(&next, "startsAt") >= numeric(&next, "expiresAt")
                {
                    return Err(invalid_input("startsAt must be before expiresAt").into());
                }
                match body.get("window") {
                    Some(Value::Null) => {
                        next.shift_remove("window");
                    }
                    Some(window) => {
                        let window = ctx.access_window(Some(window))?;
                        next.insert("window".into(), window_value(&window));
                    }
                    None => {}
                }
                apply_eligibility(&mut next, body)?;
                apply_approvers(ctx, &tx, &mut next, body).await?;
                if truthy(binding.get("eligible")) && !truthy(next.get("eligible")) {
                    let activations = tx
                        .find(
                            "bindingActivations",
                            &Filter::new()
                                .eq("tenantId", tenant_id.clone())
                                .eq("bindingId", str_of(&binding, "id")),
                            &find_all(),
                        )
                        .await?;
                    for activation in activations {
                        tx.delete("bindingActivations", record_id(&activation))
                            .await?;
                    }
                }
                Ok(Value::Object(tx.put("bindings", &next).await?))
            })
        });
        let result = self
            .run(
                credential,
                input.get("tenantId"),
                "iam:bindings:create",
                str_of(&existing, "roleId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// `new IamError('INVALID_TRANSITION', message)` (status 400).
fn invalid_transition(message: &str) -> IamError {
    IamError::new("INVALID_TRANSITION", message)
}

/// The `authorities` API group (`createAuthoritiesApi(ctx)`): one method per route `authorities/{method}`.
pub struct AuthoritiesApi {
    ctx: Arc<ServerContext>,
}

/// `createAuthoritiesApi(ctx)`.
pub fn create_authorities_api(ctx: &Arc<ServerContext>) -> IamResult<AuthoritiesApi> {
    Ok(AuthoritiesApi { ctx: ctx.clone() })
}

impl AuthoritiesApi {
    /// `authorities/create`: delegates a narrower grant authority to another identity; the ceiling is validated against
    /// the catalog.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<authorities::CreateInput>,
    ) -> IamResult<Reply<authorities::CreateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = crate::api::string_member(body, "tenantId");
                ctx.auth.require_recent(&principal)?;
                let ceiling = body.get("ceiling").cloned().unwrap_or(Value::Null);
                ctx.catalog
                    .validate(tx.as_ref(), &tenant_id, &ceiling)
                    .await?;
                ctx.scoped(&tx, "identities", body.get("identityId"), &tenant_id)
                    .await?;
                let identity_id = crate::api::string_member(body, "identityId");
                if identity_id == principal.identity.id
                    && !ctx.root_principal(&tx, &principal).await?
                {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "Cannot issue authority to yourself",
                        403,
                    )
                    .into());
                }
                let parent_id = body.get("parentAuthorityId").and_then(Value::as_str);
                let parent = ctx
                    .granting_authority(&tx, &principal, &tenant_id, parent_id)
                    .await?;
                let mut record = Map::new();
                record.insert("id".into(), Value::String(crate::utils::id()));
                record.insert("tenantId".into(), Value::String(tenant_id.clone()));
                record.insert("identityId".into(), Value::String(identity_id));
                record.insert("ceiling".into(), ceiling);
                record.insert("parentAuthorityId".into(), Value::String(parent.id.clone()));
                record.insert("revoked".into(), Value::Bool(false));
                Ok(Value::Object(tx.insert("grantAuthorities", &record).await?))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:authorities:create",
                &crate::api::string_member(&input, "identityId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `authorities/revoke`: only the superior authority (or root) may revoke a grant.
    pub async fn revoke(
        &self,
        credential: &CredentialInput,
        input: Body<authorities::RevokeInput>,
    ) -> IamResult<Reply<authorities::RevokeOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let tenant_id = crate::api::string_member(body, "tenantId");
                ctx.auth.require_recent(&principal)?;
                let mut authority = ctx
                    .scoped(&tx, "grantAuthorities", body.get("authorityId"), &tenant_id)
                    .await?;
                let parent_id = authority
                    .get("parentAuthorityId")
                    .and_then(Value::as_str)
                    .filter(|id| !id.is_empty())
                    .map(str::to_owned);
                let parent = match &parent_id {
                    Some(parent_id) => tx.get("grantAuthorities", parent_id).await?,
                    None => None,
                };
                let identity_of = |record: &Map<String, Value>| {
                    record
                        .get("identityId")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                };
                let superior = parent.as_ref().is_some_and(|parent| {
                    identity_of(parent).as_deref() == Some(principal.identity.id.as_str())
                }) && identity_of(&authority).as_deref()
                    != Some(principal.identity.id.as_str());
                if !ctx.root_principal(&tx, &principal).await? && !superior {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "Only superior authority can revoke this grant",
                        403,
                    )
                    .into());
                }
                authority.insert("revoked".into(), Value::Bool(true));
                Ok(Value::Object(tx.put("grantAuthorities", &authority).await?))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:authorities:revoke",
                &crate::api::string_member(&input, "authorityId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}
