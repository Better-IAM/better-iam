//! Port of `packages/server/src/threat-response.ts`.
//!
//! Response actions of the threats module (`threats.rs`): ending an identity's sessions, forgetting its remembered
//! devices, containing it (disabled until `threats.release`), suspending its security clearance (until an officer's
//! `clearances.reinstate`), blocking a network, and emailing an incident. The same primitives serve people responding
//! through the API (who act under their own principal and are checked like the identities and security APIs check
//! them) and automatic playbooks (the `threat-detection` actor, which never touches owners or root administrators and
//! is braked by `maxAutomaticContainments`). Every action taken or skipped is kept as a `ThreatResponse` row for the
//! incident timeline; the applied ones are audited under `threat:*` actions.

use std::sync::Arc;

use better_iam_auth::outbox::EnqueueInput;
use better_iam_core::boxed;
use better_iam_core::js as core_js;
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, Identity, IdentityKind, IdentityStatus, OutboxKind, Record, SessionKind, ip_matches,
    is_ip_range,
};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::api::identities::{assert_owner_control, revoke_invitations_by};
use crate::api::package_automation::after_identity_change;
use crate::clearances::{assert_clearances, suspend_clearance};
use crate::context::{ServerContext, Store};
use crate::contracts::{OperationDenied, OperationResult};
use crate::delegations::delete_delegated_sessions;
use crate::js::{number, sort_strings};
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::port::{decode, encode};
use crate::threats::{
    INCIDENTS, RESPONSES, RISK, ResolvedThreatSettings, THREAT_ACTOR, ThreatDetection,
    ThreatIncident, ThreatResponse, ThreatSubject, severity_at_least,
};
use crate::utils::id;
use crate::validation::integer_number;

const MINUTE: f64 = 60_000.0;
const DAY: f64 = 24.0 * 60.0 * MINUTE;

/// Bounds of a `block-network` response's length (`blockDurationBounds`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BlockDurationBounds {
    pub min: f64,
    pub max: f64,
    pub default: f64,
}

/// Bounds of a `block-network` response's length.
pub const BLOCK_DURATION_BOUNDS: BlockDurationBounds = BlockDurationBounds {
    min: MINUTE,
    max: 30.0 * DAY,
    default: DAY,
};

/// Who responds: a person through the API (`{ principal }`), or the detection engine running a playbook
/// (`{ automatic: true }`).
#[derive(Debug, Clone, PartialEq)]
pub enum ResponseActor {
    Principal(Box<AuthenticatedPrincipal>),
    Automatic,
}

impl ResponseActor {
    /// `{ principal }`.
    pub fn person(principal: AuthenticatedPrincipal) -> Self {
        Self::Principal(Box::new(principal))
    }

    /// The person responding, when it is one (`manualPrincipal`).
    pub fn principal(&self) -> Option<&AuthenticatedPrincipal> {
        match self {
            Self::Principal(principal) => Some(principal),
            Self::Automatic => None,
        }
    }

    /// The identity id recorded as the actor (`actorIdOf`): the person, or `threat-detection`.
    pub fn actor_id(&self) -> String {
        match self {
            Self::Principal(principal) => principal.identity.id.clone(),
            Self::Automatic => THREAT_ACTOR.to_owned(),
        }
    }
}

/// The per-run containment brake of automatic playbooks: `contained` counts the identities contained so far, and
/// `braked` the containments held back once it reached the tenant's `maxAutomaticContainments`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlaybookBrake {
    #[serde(rename = "contained")]
    pub contained: f64,
    #[serde(rename = "braked", default, skip_serializing_if = "Option::is_none")]
    pub braked: Option<f64>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One response action to take for an incident, a detection, or directly for an identity or network.
#[derive(Debug, Clone, PartialEq)]
pub struct ResponseRequest {
    pub action: crate::threats::ResponseAction,
    /// What the response is about; identity actions fall back to `identityId`, `block-network` to `network`.
    pub subject: crate::threats::ThreatSubject,
    pub identity_id: Option<String>,
    pub network: Option<String>,
    pub incident_id: Option<String>,
    pub detection_id: Option<String>,
    pub playbook_id: Option<String>,
    /// Why, recorded on the response, the audit event, and (for `contain`) the identity's risk record.
    pub reason: String,
    /// A person responding (API) or the automatic actor.
    pub actor: ResponseActor,
}

/// Records an audit event of the threats module: under the responding person (with their session context) or under
/// the `threat-detection` actor, stamped with the service clock. Always `allow`, so SSF receivers and webhooks see
/// it.
pub async fn threat_audit(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    actor: &ResponseActor,
    action: &str,
    resource_id: &str,
    metadata: &IndexMap<String, better_iam_core::Json>,
) -> IamResult<()> {
    let metadata: Map<String, Value> = metadata
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    if let Some(principal) = actor.principal() {
        return ctx
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
            .await;
    }
    let mut event = Record::new();
    event.insert("id".into(), Value::String(id()));
    event.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    event.insert("actorId".into(), Value::String(THREAT_ACTOR.to_owned()));
    event.insert("action".into(), Value::String(action.to_owned()));
    event.insert("resourceId".into(), Value::String(resource_id.to_owned()));
    event.insert("timestamp".into(), number(ctx.now()));
    event.insert("outcome".into(), Value::String("allow".into()));
    event.insert("metadata".into(), Value::Object(metadata));
    ctx.events()?.record_audit(tx, &event).await
}

/// A display name for an identity: its name, else its email.
fn identity_name(identity: &Identity) -> String {
    if !identity.name.is_empty() {
        return identity.name.clone();
    }
    match identity.email.as_deref() {
        Some(email) if !email.is_empty() => email.to_owned(),
        _ => identity.id.clone(),
    }
}

/// `network.split('/')[0]`.
fn first_address(network: &str) -> &str {
    network.split('/').next().unwrap_or_default()
}

/// Two networks (addresses or CIDR blocks) overlap when either contains the other's first address.
fn overlaps(a: &str, b: &str) -> bool {
    ip_matches(first_address(a), b) || ip_matches(first_address(b), a)
}

/// The prefix length of a network (an address counts as a full-length block).
fn prefix_of(network: &str) -> f64 {
    if let Some(slash) = network.find('/') {
        return core_js::string_to_number(&network[slash + 1..]);
    }
    if network.contains(':') { 128.0 } else { 32.0 }
}

/// True when `outer` covers every address of `inner`.
fn covers(outer: &str, inner: &str) -> bool {
    prefix_of(outer) <= prefix_of(inner) && ip_matches(first_address(inner), outer)
}

/// Refs shared by the response row and the audit metadata.
fn references(request: &ResponseRequest) -> Vec<(&'static str, String)> {
    let mut refs = Vec::new();
    if let Some(incident_id) = &request.incident_id {
        refs.push(("incidentId", incident_id.clone()));
    }
    if let Some(detection_id) = &request.detection_id {
        refs.push(("detectionId", detection_id.clone()));
    }
    if let Some(playbook_id) = &request.playbook_id {
        refs.push(("playbookId", playbook_id.clone()));
    }
    refs
}

/// Audit metadata built in the TypeScript member order.
#[derive(Default)]
struct Metadata(IndexMap<String, Value>);

impl Metadata {
    fn with(mut self, key: &str, value: Value) -> Self {
        self.0.insert(key.to_owned(), value);
        self
    }

    fn refs(mut self, refs: &[(&'static str, String)]) -> Self {
        for (key, value) in refs {
            self.0
                .insert((*key).to_owned(), Value::String(value.clone()));
        }
        self
    }
}

/// `value.slice(0, max)` in UTF-16 code units (a surrogate pair is never split).
fn slice_utf16(value: &str, max: usize) -> String {
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

/// Every record of a collection matching an equality filter.
async fn find(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

/// A string member of a record.
fn str_member<'a>(record: &'a Record, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

/// `{ ...identity, status }` written back, keeping the stored record's members and their order.
async fn put_status(tx: &Store, identity: &Identity, status: &str) -> IamResult<()> {
    let mut record = match tx.get("identities", &identity.id).await? {
        Some(record) => record,
        None => encode(identity),
    };
    record.insert("status".into(), Value::String(status.to_owned()));
    tx.put("identities", &record).await?;
    Ok(())
}

/// What `applyResponse` writes for every response: the `ThreatResponse` row (`save`).
struct Responses<'a> {
    tx: &'a Store,
    tenant_id: &'a str,
    action: Value,
    refs: Vec<(&'static str, String)>,
    actor_id: String,
    now: f64,
}

impl Responses<'_> {
    async fn save(
        &self,
        subject: &ThreatSubject,
        outcome: &str,
        reason: Option<&str>,
        details: Option<Map<String, Value>>,
    ) -> IamResult<ThreatResponse> {
        let mut record = Record::new();
        record.insert("id".into(), Value::String(id()));
        record.insert("tenantId".into(), Value::String(self.tenant_id.to_owned()));
        record.insert("action".into(), self.action.clone());
        record.insert(
            "subject".into(),
            serde_json::to_value(subject).unwrap_or(Value::Null),
        );
        record.insert("outcome".into(), Value::String(outcome.to_owned()));
        if let Some(reason) = reason {
            record.insert("reason".into(), Value::String(reason.to_owned()));
        }
        for (key, value) in &self.refs {
            record.insert((*key).to_owned(), Value::String(value.clone()));
        }
        record.insert("actorId".into(), Value::String(self.actor_id.clone()));
        if let Some(details) = details {
            record.insert("details".into(), Value::Object(details));
        }
        record.insert("createdAt".into(), number(self.now));
        decode(self.tx.insert(RESPONSES, &record).await?)
    }

    async fn skip(&self, why: &str, subject: &ThreatSubject) -> IamResult<ThreatResponse> {
        self.save(subject, "skipped", Some(why), None).await
    }
}

/// `{ type: 'identity', id, name }` of an identity.
fn identity_subject(identity: &Identity) -> ThreatSubject {
    ThreatSubject {
        r#type: Value::String("identity".into()),
        id: identity.id.clone(),
        name: Some(identity_name(identity)),
        extra: Map::new(),
    }
}

/// A details object built in the TypeScript member order.
fn details(members: &[(&str, Value)]) -> Map<String, Value> {
    members
        .iter()
        .map(|(key, value)| ((*key).to_owned(), value.clone()))
        .collect()
}

/// The identity an identity action targets, or why there is none (`target`).
async fn target(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    request: &ResponseRequest,
) -> IamResult<Result<Identity, &'static str>> {
    let identity_id = if request.subject.r#type == "identity" {
        Some(request.subject.id.clone())
    } else {
        request.identity_id.clone()
    };
    let Some(identity_id) = identity_id.filter(|id| !id.is_empty()) else {
        return Ok(Err("not-identity"));
    };
    if request.actor.principal().is_some() {
        return Ok(Ok(ctx.active_identity(tx, &identity_id, tenant_id).await?));
    }
    let Some(record) = tx.get("identities", &identity_id).await? else {
        return Ok(Err("not-found"));
    };
    let identity: Identity = decode(record)?;
    if identity.tenant_id != tenant_id || identity.status == IdentityStatus::Deleted {
        return Ok(Err("not-found"));
    }
    Ok(Ok(identity))
}

/// Takes one response action and records it: inserts the `ThreatResponse` row (applied or skipped with a reason)
/// and, when applied, the audit event (`threat:revoke-sessions`, `threat:forget-devices`, `threat:contain`,
/// `threat:suspend-clearance` after `clearance:suspend`, `threat:block-network`, `threat:notify`). Automatic actors
/// skip protected targets (owners and root administrators are never contained, nor their clearances suspended,
/// automatically) and, with a `brake`, containments beyond the tenant's `maxAutomaticContainments` (skipped
/// `braked`, audited once per brake as `threat:response-braked`), and never block networks on the root tenant.
/// People are refused instead: a root administrator only by root, an owner only by an owner in person or root, the
/// last owner (`LAST_OWNER`), themselves, networks that cover their own address, blocks on the root tenant unless
/// they are root, and a clearance suspension without `iam:clearances:suspend` (as `clearances.suspend` refuses it).
/// Runs inside the caller's transaction; after it commits the caller runs `afterThreatResponses` (package
/// reconciliation of contained identities, network block caches). Refusals are `OperationDenied` (audited as a
/// denial by the operation envelope).
pub async fn apply_response(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    request: &crate::threat_response::ResponseRequest,
    settings: &crate::threats::ResolvedThreatSettings,
    brake: Option<&mut crate::threat_response::PlaybookBrake>,
) -> OperationResult<crate::threats::ThreatResponse> {
    let mut brake = brake;
    let now = ctx.now();
    let principal = request.actor.principal();
    let actor_id = request.actor.actor_id();
    let trimmed = slice_utf16(core_js::trim(&request.reason), 512);
    let reason = if trimmed.is_empty() {
        "Threat response".to_owned()
    } else {
        trimmed
    };
    let refs = references(request);
    let responses = Responses {
        tx,
        tenant_id,
        action: request.action.kind.clone(),
        refs: refs.clone(),
        actor_id: actor_id.clone(),
        now,
    };
    let kind = request.action.kind.as_str().unwrap_or_default();

    match kind {
        "revoke-sessions" => {
            let identity = match boxed(|| target(ctx, tx, tenant_id, request)).await? {
                Ok(identity) => identity,
                Err(why) => return Ok(boxed(|| responses.skip(why, &request.subject)).await?),
            };
            // As identities.revokeSessions: a root administrator's sessions are ended by root (or by themselves).
            if let Some(principal) = principal
                && identity.root_admin
                && principal.identity.id != identity.id
                && !boxed(|| ctx.root_principal(tx, principal)).await?
            {
                return Err(OperationDenied::new(Some("Root capability is protected")));
            }
            let keep_api_keys = request.action.keep_api_keys != Some(false);
            // A person revoking their own sessions keeps the one they are responding from.
            let own = principal.map(|principal| principal.session.id.clone());
            let skipped = |session: &Record| {
                own.as_deref()
                    .is_some_and(|own| str_member(session, "id") == Some(own))
                    || (keep_api_keys && str_member(session, "kind") == Some("api-key"))
            };
            let mut revoked = 0.0;
            for session in boxed(|| {
                find(
                    tx,
                    "sessions",
                    Filter::new().eq("identityId", identity.id.clone()),
                )
            })
            .await?
            {
                if skipped(&session) {
                    continue;
                }
                boxed(|| {
                    ctx.auth
                        .end_session(tx, str_member(&session, "id").unwrap_or_default())
                })
                .await?;
                revoked += 1.0;
            }
            // Role sessions the identity assumed in other tenants, then delegated sessions acting as an agent.
            for session in boxed(|| {
                find(
                    tx,
                    "sessions",
                    Filter::new().eq("originalIdentityId", identity.id.clone()),
                )
            })
            .await?
            {
                if skipped(&session) {
                    continue;
                }
                boxed(|| tx.delete("sessions", str_member(&session, "id").unwrap_or_default()))
                    .await?;
                revoked += 1.0;
            }
            if identity.kind == IdentityKind::Agent {
                revoked += boxed(|| async {
                    delete_delegated_sessions(tx, &json!({ "agentId": identity.id })).await
                })
                .await?;
            }
            boxed(|| delete_challenges(tx, &identity.id)).await?;
            boxed(|| async {
                threat_audit(
                    ctx,
                    tx,
                    tenant_id,
                    &request.actor,
                    "threat:revoke-sessions",
                    &identity.id,
                    &Metadata::default()
                        .with("revoked", number(revoked))
                        .with("keptApiKeys", Value::Bool(keep_api_keys))
                        .with("reason", Value::String(reason.clone()))
                        .refs(&refs)
                        .0,
                )
                .await
            })
            .await?;
            Ok(boxed(|| async {
                responses
                    .save(
                        &identity_subject(&identity),
                        "applied",
                        None,
                        Some(details(&[
                            ("revoked", number(revoked)),
                            ("keptApiKeys", Value::Bool(keep_api_keys)),
                        ])),
                    )
                    .await
            })
            .await?)
        }
        "forget-devices" => {
            let identity = match boxed(|| target(ctx, tx, tenant_id, request)).await? {
                Ok(identity) => identity,
                Err(why) => return Ok(boxed(|| responses.skip(why, &request.subject)).await?),
            };
            let mut removed = 0.0;
            for device in boxed(|| {
                find(
                    tx,
                    "authDevices",
                    Filter::new().eq("identityId", identity.id.clone()),
                )
            })
            .await?
            {
                boxed(|| tx.delete("authDevices", str_member(&device, "id").unwrap_or_default()))
                    .await?;
                removed += 1.0;
            }
            boxed(|| async {
                threat_audit(
                    ctx,
                    tx,
                    tenant_id,
                    &request.actor,
                    "threat:forget-devices",
                    &identity.id,
                    &Metadata::default()
                        .with("removed", number(removed))
                        .with("reason", Value::String(reason.clone()))
                        .refs(&refs)
                        .0,
                )
                .await
            })
            .await?;
            Ok(boxed(|| async {
                responses
                    .save(
                        &identity_subject(&identity),
                        "applied",
                        None,
                        Some(details(&[("removed", number(removed))])),
                    )
                    .await
            })
            .await?)
        }
        "contain" => {
            let identity = match boxed(|| target(ctx, tx, tenant_id, request)).await? {
                Ok(identity) => identity,
                Err(why) => return Ok(boxed(|| responses.skip(why, &request.subject)).await?),
            };
            let subject = identity_subject(&identity);
            if let Some(principal) = principal
                && principal.identity.id == identity.id
            {
                return Err(IamError::new("INVALID_INPUT", "You cannot contain yourself").into());
            }
            let risk = boxed(|| tx.get(RISK, &identity.id))
                .await?
                .filter(|stored| str_member(stored, "tenantId") == Some(tenant_id));
            if identity.status != IdentityStatus::Active {
                let contained = risk
                    .as_ref()
                    .is_some_and(|risk| crate::js::truthy(risk.get("contained")));
                let why = if contained {
                    "already-applied"
                } else {
                    "inactive"
                };
                return Ok(boxed(|| responses.skip(why, &subject)).await?);
            }
            if identity.root_admin {
                let Some(principal) = principal else {
                    return Ok(boxed(|| responses.skip("protected", &subject)).await?);
                };
                if !boxed(|| ctx.root_principal(tx, principal)).await? {
                    return Err(OperationDenied::new(Some("Root capability is protected")));
                }
            }
            if identity.owner && principal.is_none() {
                return Ok(boxed(|| responses.skip("protected", &subject)).await?);
            }
            if let Some(principal) = principal {
                // As identities.setStatus: disabling an owner takes an owner of the tenant in person or a root
                // principal, never a permission alone.
                boxed(|| {
                    assert_owner_control(
                        ctx,
                        tx,
                        principal,
                        &identity,
                        "Only an owner can contain an owner",
                    )
                })
                .await?;
                boxed(|| ctx.protect_last_owner(tx, &identity)).await?;
            }
            if let Some(brake) = brake.as_deref_mut()
                && brake.contained >= settings.max_automatic_containments
            {
                let first = brake
                    .braked
                    .is_none_or(|braked| braked == 0.0 || braked.is_nan());
                brake.braked = Some(brake.braked.unwrap_or(0.0) + 1.0);
                if first {
                    let resource = match request.playbook_id.as_deref() {
                        Some(playbook_id) if !playbook_id.is_empty() => {
                            format!("threats/playbooks/{playbook_id}")
                        }
                        _ => "threats/playbooks".to_owned(),
                    };
                    boxed(|| async {
                        threat_audit(
                            ctx,
                            tx,
                            tenant_id,
                            &request.actor,
                            "threat:response-braked",
                            &resource,
                            &Metadata::default()
                                .with("threshold", number(settings.max_automatic_containments))
                                .with("identityId", Value::String(identity.id.clone()))
                                .refs(&refs)
                                .0,
                        )
                        .await
                    })
                    .await?;
                }
                return Ok(boxed(|| responses.skip("braked", &subject)).await?);
            }
            boxed(|| put_status(tx, &identity, "disabled")).await?;
            // Every credential but the API keys ends now; the keys are refused while the identity is disabled and
            // work again after a release, so containment is reversible without reissuing them.
            let mut sessions_ended = 0.0;
            for session in boxed(|| {
                find(
                    tx,
                    "sessions",
                    Filter::new().eq("identityId", identity.id.clone()),
                )
            })
            .await?
            {
                if str_member(&session, "kind") == Some(SessionKind::ApiKey.as_str()) {
                    continue;
                }
                boxed(|| {
                    ctx.auth
                        .end_session(tx, str_member(&session, "id").unwrap_or_default())
                })
                .await?;
                sessions_ended += 1.0;
            }
            for session in boxed(|| {
                find(
                    tx,
                    "sessions",
                    Filter::new().eq("originalIdentityId", identity.id.clone()),
                )
            })
            .await?
            {
                if str_member(&session, "kind") == Some(SessionKind::ApiKey.as_str()) {
                    continue;
                }
                boxed(|| tx.delete("sessions", str_member(&session, "id").unwrap_or_default()))
                    .await?;
                sessions_ended += 1.0;
            }
            if identity.kind == IdentityKind::Agent {
                sessions_ended += boxed(|| async {
                    delete_delegated_sessions(tx, &json!({ "agentId": identity.id })).await
                })
                .await?;
            }
            for device in boxed(|| {
                find(
                    tx,
                    "authDevices",
                    Filter::new().eq("identityId", identity.id.clone()),
                )
            })
            .await?
            {
                boxed(|| tx.delete("authDevices", str_member(&device, "id").unwrap_or_default()))
                    .await?;
            }
            boxed(|| delete_challenges(tx, &identity.id)).await?;
            // As when an identity is disabled: invitations it sent (an intruder's among them) stay dead after a
            // release.
            boxed(|| revoke_invitations_by(tx, &identity.id)).await?;
            let mut contained = Map::new();
            contained.insert("at".into(), number(now));
            contained.insert("by".into(), Value::String(actor_id.clone()));
            contained.insert("reason".into(), Value::String(reason.clone()));
            if let Some(incident_id) = &request.incident_id {
                contained.insert("incidentId".into(), Value::String(incident_id.clone()));
            }
            if let Some(mut risk) = risk {
                risk.insert("contained".into(), Value::Object(contained));
                risk.insert("updatedAt".into(), number(now));
                boxed(|| tx.put(RISK, &risk)).await?;
            } else {
                let mut record = Record::new();
                record.insert("id".into(), Value::String(identity.id.clone()));
                record.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
                record.insert("identityId".into(), Value::String(identity.id.clone()));
                record.insert("contributions".into(), Value::Array(Vec::new()));
                record.insert("score".into(), number(0.0));
                record.insert("level".into(), Value::String("none".into()));
                record.insert("contained".into(), Value::Object(contained));
                record.insert("updatedAt".into(), number(now));
                boxed(|| tx.insert(RISK, &record)).await?;
            }
            if let Some(brake) = brake {
                brake.contained += 1.0;
            }
            boxed(|| async {
                threat_audit(
                    ctx,
                    tx,
                    tenant_id,
                    &request.actor,
                    "threat:contain",
                    &identity.id,
                    &Metadata::default()
                        .with("reason", Value::String(reason.clone()))
                        .with("sessionsEnded", number(sessions_ended))
                        .refs(&refs)
                        .0,
                )
                .await
            })
            .await?;
            Ok(boxed(|| async {
                responses
                    .save(
                        &subject,
                        "applied",
                        None,
                        Some(details(&[("sessionsEnded", number(sessions_ended))])),
                    )
                    .await
            })
            .await?)
        }
        "suspend-clearance" => {
            let identity = match boxed(|| target(ctx, tx, tenant_id, request)).await? {
                Ok(identity) => identity,
                Err(why) => return Ok(boxed(|| responses.skip(why, &request.subject)).await?),
            };
            let subject = identity_subject(&identity);
            if let Some(principal) = principal {
                // As clearances.suspend: the deployment enables clearances, and the responder may suspend this
                // clearance besides responding to threats (checked before anything about the clearance is read, so
                // the response tells nobody else whether the person holds one); never while impersonating, never a
                // guest of the tenant.
                assert_clearances(ctx)?;
                if principal.session.impersonator_id.is_some() {
                    return Err(IamError::with_status(
                        "IMPERSONATION_RESTRICTED",
                        "Clearances cannot be changed while impersonating",
                        403,
                    )
                    .into());
                }
                if principal.identity.guest.is_some() && principal.identity.tenant_id == tenant_id {
                    return Err(OperationDenied::new(Some(
                        "Guests cannot suspend clearances",
                    )));
                }
                let decision = ctx
                    .decisions()?
                    .decide(
                        tx,
                        principal,
                        &AuthorizationRequest {
                            credential: CredentialInput::default(),
                            tenant_id: tenant_id.to_owned(),
                            action: "iam:clearances:suspend".into(),
                            resource: ResourceTarget {
                                kind: "iam".into(),
                                id: format!("clearances/{}", identity.id),
                            },
                        },
                        true,
                    )
                    .await?;
                if !decision.allowed {
                    return Err(OperationDenied::new(Some(
                        "Suspending a clearance requires iam:clearances:suspend",
                    )));
                }
            } else {
                if ctx.options.clearances.is_none() {
                    return Ok(boxed(|| responses.skip("feature-disabled", &subject)).await?);
                }
                // As with containment, automatic responses never touch an owner's or a root administrator's
                // clearance.
                if identity.owner || identity.root_admin {
                    return Ok(boxed(|| responses.skip("protected", &subject)).await?);
                }
            }
            // Lifted only by an officer's clearances.reinstate; threats.release never touches it.
            let mut input = Map::new();
            input.insert("by".into(), Value::String(actor_id.clone()));
            input.insert("at".into(), number(now));
            input.insert("reason".into(), Value::String(reason.clone()));
            if let Some(incident_id) = &request.incident_id {
                input.insert("incidentId".into(), Value::String(incident_id.clone()));
            }
            let result = boxed(|| async {
                suspend_clearance(tx, &Value::Object(encode(&identity)), &Value::Object(input))
                    .await
            })
            .await?;
            let outcome = result
                .get("outcome")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if outcome != "suspended" {
                return Ok(boxed(|| responses.skip(outcome, &subject)).await?);
            }
            let level = result
                .get("record")
                .and_then(|record| record.get("level"))
                .cloned()
                .unwrap_or(Value::Null);
            // The clearance's own history (`clearance:*`, as clearances.suspend records it), then the response.
            let mut history = Metadata::default()
                .with("level", level.clone())
                .with("reason", Value::String(reason.clone()));
            if let Some(incident_id) = &request.incident_id {
                history = history.with("incidentId", Value::String(incident_id.clone()));
            }
            boxed(|| {
                threat_audit(
                    ctx,
                    tx,
                    tenant_id,
                    &request.actor,
                    "clearance:suspend",
                    &identity.id,
                    &history.0,
                )
            })
            .await?;
            boxed(|| async {
                threat_audit(
                    ctx,
                    tx,
                    tenant_id,
                    &request.actor,
                    "threat:suspend-clearance",
                    &identity.id,
                    &Metadata::default()
                        .with("level", level)
                        .with("reason", Value::String(reason.clone()))
                        .refs(&refs)
                        .0,
                )
                .await
            })
            .await?;
            Ok(boxed(|| responses.save(&subject, "applied", None, None)).await?)
        }
        "block-network" => {
            let source = if request.subject.r#type == "network" {
                Some(request.subject.id.as_str())
            } else {
                request.network.as_deref()
            };
            let network = source.map(core_js::trim).unwrap_or_default().to_owned();
            if network.is_empty() {
                return Ok(boxed(|| responses.skip("no-network", &request.subject)).await?);
            }
            let subject = ThreatSubject {
                r#type: Value::String("network".into()),
                id: network.clone(),
                name: None,
                extra: Map::new(),
            };
            if !is_ip_range(&network) {
                if principal.is_some() {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "network must be an IPv4/IPv6 address or CIDR block",
                    )
                    .into());
                }
                return Ok(boxed(|| responses.skip("invalid-network", &subject)).await?);
            }
            // As security.blockNetwork: the root tenant's blocks decide whether root administrators can sign in, so
            // only root sets them. Playbooks, which any iam:threats:manage holder may write, never do.
            if boxed(|| ctx.tenant(tx, tenant_id))
                .await?
                .parent_id
                .is_none()
            {
                let Some(principal) = principal else {
                    return Ok(boxed(|| responses.skip("protected", &subject)).await?);
                };
                if !boxed(|| ctx.root_principal(tx, principal)).await? {
                    return Err(OperationDenied::new(Some(
                        "Blocks on the root tenant are set by root administrators",
                    )));
                }
            }
            if settings
                .trusted_networks
                .iter()
                .any(|trusted| overlaps(&network, trusted))
            {
                return Ok(boxed(|| responses.skip("trusted-network", &subject)).await?);
            }
            if let Some(principal) = principal {
                // As security.blockNetwork: never the address the responder's session came from or this request
                // comes from.
                let own = [
                    principal
                        .session
                        .client
                        .as_ref()
                        .and_then(|client| client.ip.clone()),
                    ctx.auth.current_client().and_then(|client| client.ip),
                ];
                if own.iter().flatten().any(|ip| ip_matches(ip, &network)) {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "That network includes your own address",
                    )
                    .into());
                }
            }
            let requested = request
                .action
                .duration_ms
                .unwrap_or(BLOCK_DURATION_BOUNDS.default);
            let duration_ms = if principal.is_some() {
                integer_number(
                    requested,
                    "durationMs",
                    BLOCK_DURATION_BOUNDS.min,
                    BLOCK_DURATION_BOUNDS.max,
                )?
            } else {
                let requested = if core_js::is_safe_integer(requested) {
                    requested
                } else {
                    BLOCK_DURATION_BOUNDS.default
                };
                BLOCK_DURATION_BOUNDS
                    .max
                    .min(BLOCK_DURATION_BOUNDS.min.max(requested))
            };
            let expires_at = now + duration_ms;
            // The tenant's own blocks plus the platform-wide ones, which apply to every tenant.
            let mut blocks = boxed(|| {
                find(
                    tx,
                    "authBlocks",
                    Filter::new().eq("tenantId", tenant_id.to_owned()),
                )
            })
            .await?;
            blocks.extend(
                boxed(|| find(tx, "authBlocks", Filter::new().eq("platform", true))).await?,
            );
            // A block that already covers the network for at least as long makes this one redundant.
            let lasting = |block: &Record| match block.get("expiresAt") {
                None => true,
                Some(value) => core_js::to_number(value) >= expires_at,
            };
            if blocks.iter().any(|block| {
                str_member(block, "network").is_some_and(|block_network| {
                    is_ip_range(block_network) && lasting(block) && covers(block_network, &network)
                })
            }) {
                return Ok(boxed(|| responses.skip("already-applied", &subject)).await?);
            }
            let existing = blocks.iter().find(|block| {
                str_member(block, "tenantId") == Some(tenant_id)
                    && !crate::js::truthy(block.get("platform"))
                    && str_member(block, "network") == Some(network.as_str())
            });
            let block_id = existing
                .and_then(|block| str_member(block, "id"))
                .map(str::to_owned)
                .unwrap_or_else(id);
            let renewed = existing.is_some();
            let mut block = Record::new();
            block.insert("id".into(), Value::String(block_id.clone()));
            block.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
            block.insert("network".into(), Value::String(network.clone()));
            block.insert(
                "reason".into(),
                Value::String(slice_utf16(&format!("threat: {reason}"), 512)),
            );
            block.insert("createdAt".into(), number(now));
            block.insert("createdBy".into(), Value::String(actor_id.clone()));
            block.insert("expiresAt".into(), number(expires_at));
            if renewed {
                boxed(|| tx.put("authBlocks", &block)).await?;
            } else {
                boxed(|| tx.insert("authBlocks", &block)).await?;
            }
            ctx.auth.invalidate_network_blocks();
            boxed(|| async {
                threat_audit(
                    ctx,
                    tx,
                    tenant_id,
                    &request.actor,
                    "threat:block-network",
                    &format!("threats/networks/{network}"),
                    &Metadata::default()
                        .with("network", Value::String(network.clone()))
                        .with("expiresAt", number(expires_at))
                        .with("renewed", Value::Bool(renewed))
                        .with("reason", Value::String(reason.clone()))
                        .refs(&refs)
                        .0,
                )
                .await
            })
            .await?;
            Ok(boxed(|| async {
                responses
                    .save(
                        &subject,
                        "applied",
                        None,
                        Some(details(&[
                            ("network", Value::String(network.clone())),
                            ("blockId", Value::String(block_id)),
                            ("expiresAt", number(expires_at)),
                            ("renewed", Value::Bool(renewed)),
                        ])),
                    )
                    .await
            })
            .await?)
        }
        "notify" => {
            let stored = match &request.incident_id {
                Some(incident_id) => boxed(|| tx.get(INCIDENTS, incident_id)).await?,
                None => None,
            };
            let incident =
                stored.filter(|stored| str_member(stored, "tenantId") == Some(tenant_id));
            let Some(incident) = incident else {
                return Ok(boxed(|| responses.skip("no-incident", &request.subject)).await?);
            };
            let incident: ThreatIncident = decode(incident)?;
            if !sends_email(ctx) {
                return Ok(boxed(|| responses.skip("no-transport", &request.subject)).await?);
            }
            let recipients = boxed(|| incident_recipients(tx, tenant_id, settings)).await?;
            if recipients.is_empty() {
                return Ok(boxed(|| responses.skip("no-recipients", &request.subject)).await?);
            }
            if principal.is_none() {
                // Playbooks email an incident once, and again only when its severity has risen since.
                let earlier = boxed(|| {
                    find(
                        tx,
                        RESPONSES,
                        Filter::new()
                            .eq("tenantId", tenant_id.to_owned())
                            .eq("incidentId", incident.id.clone())
                            .eq("action", "notify")
                            .eq("outcome", "applied"),
                    )
                })
                .await?;
                let mut notified = false;
                for response in &earlier {
                    let severity = response
                        .get("details")
                        .and_then(|details| details.get("severity"))
                        .filter(|severity| severity.is_string());
                    if let Some(severity) = severity
                        && severity_at_least(severity, &incident.severity)?
                    {
                        notified = true;
                        break;
                    }
                }
                if notified {
                    return Ok(
                        boxed(|| responses.skip("already-applied", &request.subject)).await?,
                    );
                }
            }
            let sent = boxed(|| {
                deliver_incident(ctx, tx, tenant_id, &incident, &recipients, &request.actor)
            })
            .await?;
            Ok(boxed(|| async {
                responses
                    .save(
                        &request.subject,
                        "applied",
                        None,
                        Some(details(&[
                            ("recipients", number(sent)),
                            ("severity", incident.severity.clone()),
                        ])),
                    )
                    .await
            })
            .await?)
        }
        _ => Err(IamError::new("INVALID_INPUT", "Unknown response action").into()),
    }
}

/// Deletes the identity's pending sign-in challenges.
async fn delete_challenges(tx: &Store, identity_id: &str) -> IamResult<()> {
    for challenge in find(
        tx,
        "authChallenges",
        Filter::new().eq("identityId", identity_id.to_owned()),
    )
    .await?
    {
        tx.delete(
            "authChallenges",
            str_member(&challenge, "id").unwrap_or_default(),
        )
        .await?;
    }
    Ok(())
}

/// `ctx.options.authentication?.sendEmail` is set.
fn sends_email(ctx: &Arc<ServerContext>) -> bool {
    ctx.options
        .authentication
        .as_ref()
        .is_some_and(|authentication| authentication.send_email.is_some())
}

/// Lifts a containment: the identity is active again and its risk record no longer marks it contained (the risk
/// score is kept). Only an identity the threats module contained and that nothing else has disabled, suspended, or
/// re-enabled since can be released (`INVALID_TRANSITION` 409 otherwise, or when it has expired since); a root
/// administrator only by root. Audited as `threat:release` and kept as a `release` response. After commit the
/// caller runs `afterThreatResponses`.
pub async fn release_identity(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    actor: &ResponseActor,
    note: Option<&str>,
) -> OperationResult<crate::threats::ThreatResponse> {
    let now = ctx.now();
    let identity = ctx.active_identity(tx, identity_id, tenant_id).await?;
    let risk = tx
        .get(RISK, &identity.id)
        .await?
        .filter(|stored| str_member(stored, "tenantId") == Some(tenant_id));
    // A suspended agent is held by its kill switch (agents.resume lifts it); other paths that disable or re-enable
    // an identity drop the mark (endContainment), so what they did is never undone here.
    let suspended_agent = identity
        .agent
        .as_ref()
        .is_some_and(|agent| agent.suspended.is_some());
    let contained_risk = risk.filter(|risk| crate::js::truthy(risk.get("contained")));
    let Some(mut risk) =
        contained_risk.filter(|_| identity.status == IdentityStatus::Disabled && !suspended_agent)
    else {
        return Err(IamError::with_status(
            "INVALID_TRANSITION",
            "The identity is not contained",
            409,
        )
        .into());
    };
    if let Some(principal) = actor.principal()
        && identity.root_admin
        && !ctx.root_principal(tx, principal).await?
    {
        return Err(OperationDenied::new(Some("Root capability is protected")));
    }
    if ctx.identity_expired(&identity) {
        return Err(IamError::with_status(
            "INVALID_TRANSITION",
            "Extend or clear expiresAt before releasing an expired identity",
            409,
        )
        .into());
    }
    let contained = risk.shift_remove("contained").unwrap_or(Value::Null);
    put_status(tx, &identity, "active").await?;
    risk.insert("updatedAt".into(), number(now));
    tx.put(RISK, &risk).await?;
    let cleaned = note
        .map(|note| slice_utf16(core_js::trim(note), 1024))
        .filter(|cleaned| !cleaned.is_empty());
    let incident_id = contained.get("incidentId").cloned();
    let mut metadata = Metadata::default();
    if let Some(cleaned) = &cleaned {
        metadata = metadata.with("note", Value::String(cleaned.clone()));
    }
    metadata = metadata.with(
        "containedAt",
        contained.get("at").cloned().unwrap_or(Value::Null),
    );
    if let Some(incident_id) = &incident_id {
        metadata = metadata.with("incidentId", incident_id.clone());
    }
    threat_audit(
        ctx,
        tx,
        tenant_id,
        actor,
        "threat:release",
        &identity.id,
        &metadata.0,
    )
    .await?;
    let mut record = Record::new();
    record.insert("id".into(), Value::String(id()));
    record.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    record.insert("action".into(), Value::String("release".into()));
    record.insert(
        "subject".into(),
        serde_json::to_value(identity_subject(&identity)).unwrap_or(Value::Null),
    );
    record.insert("outcome".into(), Value::String("applied".into()));
    if let Some(incident_id) = incident_id {
        record.insert("incidentId".into(), incident_id);
    }
    record.insert("actorId".into(), Value::String(actor.actor_id()));
    if let Some(cleaned) = cleaned {
        record.insert("details".into(), json!({ "note": cleaned }));
    }
    record.insert("createdAt".into(), number(now));
    Ok(decode(tx.insert(RESPONSES, &record).await?)?)
}

/// Who is emailed about incidents: the tenant's listed addresses plus, when `notify.owners` is set, its active
/// owners with a verified email. Lowercased, without duplicates.
async fn incident_recipients(
    tx: &Store,
    tenant_id: &str,
    settings: &ResolvedThreatSettings,
) -> IamResult<Vec<String>> {
    let mut recipients: indexmap::IndexSet<String> = settings
        .notify
        .get("emails")
        .and_then(Value::as_array)
        .map(|emails| {
            emails
                .iter()
                .map(|address| core_js::to_lower(&crate::js::js_string(Some(address))))
                .collect()
        })
        .unwrap_or_default();
    if crate::js::truthy(settings.notify.get("owners")) {
        for owner in find(
            tx,
            "identities",
            Filter::new()
                .eq("tenantId", tenant_id.to_owned())
                .eq("owner", true)
                .eq("status", "active"),
        )
        .await?
        {
            if let Some(email) = str_member(&owner, "email").filter(|email| !email.is_empty())
                && crate::js::truthy(owner.get("emailVerified"))
            {
                recipients.insert(core_js::to_lower(email));
            }
        }
    }
    let mut sorted: Vec<String> = recipients.into_iter().collect();
    sort_strings(&mut sorted);
    Ok(sorted)
}

/// Queues one `threat-alert` email per recipient and audits `threat:notify`; returns the number queued.
async fn deliver_incident(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    incident: &ThreatIncident,
    recipients: &[String],
    actor: &ResponseActor,
) -> IamResult<f64> {
    let tenant = tx.get("tenants", tenant_id).await?;
    let latest = match incident.detection_ids.last() {
        Some(latest_id) => tx.get(crate::threats::DETECTIONS, latest_id).await?,
        None => None,
    };
    let mut payload = Map::new();
    payload.insert("incidentId".into(), Value::String(incident.id.clone()));
    payload.insert("title".into(), Value::String(incident.title.clone()));
    payload.insert("severity".into(), incident.severity.clone());
    payload.insert(
        "subject".into(),
        Value::String(
            incident
                .subject
                .name
                .clone()
                .unwrap_or_else(|| incident.subject.id.clone()),
        ),
    );
    payload.insert("subjectType".into(), incident.subject.r#type.clone());
    payload.insert(
        "detections".into(),
        Value::String(core_js::number_to_string(incident.detection_count)),
    );
    payload.insert(
        "tenantName".into(),
        tenant
            .as_ref()
            .and_then(|tenant| tenant.get("name"))
            .filter(|name| !name.is_null())
            .cloned()
            .unwrap_or_else(|| Value::String(tenant_id.to_owned())),
    );
    if let Some(latest) = latest.filter(|latest| str_member(latest, "tenantId") == Some(tenant_id))
    {
        let latest: ThreatDetection = decode(latest)?;
        payload.insert("summary".into(), Value::String(latest.summary));
    }
    for to in recipients {
        ctx.auth
            .enqueue_delivery(
                tx,
                EnqueueInput {
                    tenant_id: tenant_id.to_owned(),
                    kind: OutboxKind::Email,
                    to: to.clone(),
                    template: "threat-alert".into(),
                    payload: payload.clone(),
                    reference: None,
                },
            )
            .await?;
    }
    threat_audit(
        ctx,
        tx,
        tenant_id,
        actor,
        "threat:notify",
        &format!("threats/incidents/{}", incident.id),
        &Metadata::default()
            .with("recipients", number(recipients.len() as f64))
            .with("severity", incident.severity.clone())
            .with("incidentId", Value::String(incident.id.clone()))
            .0,
    )
    .await?;
    Ok(recipients.len() as f64)
}

/// Emails an incident to the tenant's configured recipients (`threat-alert` template) and audits `threat:notify`.
/// Sends nothing (`sent: 0`, no audit) without an email delivery callback or recipients. The automatic actor is
/// used unless a responding person is given. Answers `{ sent }`.
pub async fn notify_incident(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    incident: &ThreatIncident,
    settings: &ResolvedThreatSettings,
    actor: Option<&ResponseActor>,
) -> IamResult<Value> {
    if !sends_email(ctx) {
        return Ok(json!({ "sent": 0 }));
    }
    let recipients = incident_recipients(tx, tenant_id, settings).await?;
    if recipients.is_empty() {
        return Ok(json!({ "sent": 0 }));
    }
    let actor = actor.cloned().unwrap_or(ResponseActor::Automatic);
    let sent = deliver_incident(ctx, tx, tenant_id, incident, &recipients, &actor).await?;
    Ok(json!({ "sent": number(sent) }))
}

/// Post-commit follow-up of responses: reconciles access-package rules for identities contained or released
/// (`afterIdentityChange`, which never throws) and clears this process's network block cache again after a block,
/// so a read racing the transaction cannot keep the pre-change list for a few seconds.
pub async fn after_threat_responses(
    ctx: &Arc<ServerContext>,
    tenant_id: &str,
    responses: &[crate::threats::ThreatResponse],
) -> IamResult<()> {
    let applied: Vec<&ThreatResponse> = responses
        .iter()
        .filter(|response| response.outcome == "applied")
        .collect();
    if applied
        .iter()
        .any(|response| response.action == "block-network")
    {
        ctx.auth.invalidate_network_blocks();
    }
    let changed = crate::js::unique(
        applied
            .iter()
            .filter(|response| {
                (response.action == "contain" || response.action == "release")
                    && response.subject.r#type == "identity"
            })
            .map(|response| response.subject.id.clone()),
    );
    // `afterIdentityChange` does nothing for an empty list.
    if !changed.is_empty() {
        after_identity_change(ctx, tenant_id, &changed, &Value::Null).await?;
    }
    Ok(())
}
