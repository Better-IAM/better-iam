//! Port of `packages/server/src/threats.ts`.
//!
//! Identity threat detection and response (ITDR): detection rules read the audit trail each tenant already keeps
//! (sign-ins, failures, session mismatches, administrative changes, directory pushes), raise detections, group them
//! into incidents per subject, keep a decaying risk score per identity (exposed to policies as principal.riskLevel /
//! principal.riskScore), and run response playbooks. The engine (`threat_engine.rs`) is a scheduled job,
//! `iam.detectThreats()`, that reads each tenant's audit chain from a cursor, so it also sees events the protocol
//! packages write without fan-out, verifies the chain as it goes, and never slows a sign-in.
//!
//! The string unions of the TypeScript module (`ThreatSeverity`, `RiskLevel`, `ThreatRuleId`, ...) are JSON strings
//! here, as the record types other modules decode carry them.

use std::sync::LazyLock;

use better_iam_core::IamResult;
use better_iam_core::js as core_js;
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::Store;
use crate::js::{ThrownError, number};
use crate::port::decode;

/// `open`, `dismissed` or `resolved`: a string union in TypeScript, kept as its JSON string (other modules compare it with `== "..."`).
pub type DetectionStatus = Value;

/// An identity's risk (`id` = identity id, stored in the identity's tenant). The score is recomputed from live
/// contributions whenever it is read, so it decays without a writer; `score`/`level` are the values as of
/// `updatedAt`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IdentityRisk {
    #[serde(rename = "identityId")]
    pub identity_id: String,
    /// At most 50, newest last.
    #[serde(rename = "contributions")]
    pub contributions: Vec<crate::threats::RiskContribution>,
    #[serde(rename = "score")]
    pub score: f64,
    #[serde(rename = "level")]
    pub level: crate::threats::RiskLevel,
    /// An administrator's floor ("confirmed compromised"): the effective level is never below it until it expires.
    #[serde(rename = "override", default, skip_serializing_if = "Option::is_none")]
    pub r#override: Option<Value>,
    /// Set while the identity is contained by the threats module (`contain` response): who, when, why.
    #[serde(rename = "contained", default, skip_serializing_if = "Option::is_none")]
    pub contained: Option<Value>,
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

/// `true-positive`, `false-positive` or `benign`: a string union in TypeScript, kept as its JSON string (other modules compare it with `== "..."`).
pub type IncidentResolution = Value;

/// `open`, `investigating` or `resolved`: a string union in TypeScript, kept as its JSON string (other modules compare it with `== "..."`).
pub type IncidentStatus = Value;

/// Settings with every default applied, as the engine and the API use them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedThreatSettings {
    #[serde(rename = "rules")]
    pub rules: Value,
    #[serde(rename = "trustedNetworks")]
    pub trusted_networks: Vec<String>,
    #[serde(rename = "dormantDays")]
    pub dormant_days: f64,
    #[serde(rename = "riskHalfLifeHours")]
    pub risk_half_life_hours: f64,
    #[serde(rename = "notify")]
    pub notify: Value,
    #[serde(rename = "maxAutomaticContainments")]
    pub max_automatic_containments: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResponseAction {
    #[serde(rename = "kind")]
    pub kind: crate::threats::ResponseActionKind,
    /// `block-network`: block length (one minute to 30 days; default one day).
    #[serde(
        rename = "durationMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub duration_ms: Option<f64>,
    /// `revoke-sessions`: keep API keys (default true).
    #[serde(
        rename = "keepApiKeys",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub keep_api_keys: Option<bool>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Response actions. `revoke-sessions` ends the identity's sessions (API keys kept unless `keepApiKeys: false`);
/// `forget-devices` removes remembered devices so the next sign-in needs the second factor again; `contain`
/// disables the identity (credentials kept but refused) until `threats.release`; `suspend-clearance` suspends the
/// identity's security clearance (the `clearances` option) until an officer reinstates it through
/// `clearances.reinstate`; `block-network` blocks the detection's network for `durationMs` (default one day);
/// `notify` emails the tenant's configured recipients.
/// One of [`RESPONSE_ACTION_KINDS`]: a string union in TypeScript, kept as its JSON string (other modules compare it with `== "..."`).
pub type ResponseActionKind = Value;

/// Points one detection adds to an identity's risk, decaying with the tenant's half-life.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskContribution {
    #[serde(rename = "detectionId")]
    pub detection_id: String,
    #[serde(rename = "ruleId")]
    pub rule_id: crate::threats::ThreatRuleId,
    #[serde(rename = "severity")]
    pub severity: crate::threats::ThreatSeverity,
    #[serde(rename = "points")]
    pub points: f64,
    #[serde(rename = "at")]
    pub at: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A risk level derived from an identity's score; `none` below the `low` threshold.
/// One of [`RISK_LEVELS`]: a string union in TypeScript, kept as its JSON string (other modules compare it with `== "..."`).
pub type RiskLevel = Value;

/// Learned sign-in habits of one identity (`id` = identity id), used by the new-network and dormancy rules.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatBaseline {
    #[serde(rename = "identityId")]
    pub identity_id: String,
    /// Networks seen at successful sign-ins, most recent last, at most 25.
    #[serde(rename = "networks")]
    pub networks: Vec<Value>,
    /// User agents seen at successful sign-ins, most recent last, at most 10.
    #[serde(rename = "userAgents")]
    pub user_agents: Vec<Value>,
    #[serde(
        rename = "lastSignInAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_sign_in_at: Option<f64>,
    /// The last sign-in a sign-in rule flagged, opening the account-takeover-persistence window.
    #[serde(
        rename = "riskySignIn",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub risky_sign_in: Option<Value>,
    #[serde(rename = "firstSeenAt")]
    pub first_seen_at: f64,
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

/// How far the engine has read a tenant's audit chain (`id` = tenant id): the last verified event's sequence and
/// hash, plus small state some rules compare against (the previous tenant sign-in policy).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatCursor {
    #[serde(rename = "sequence")]
    pub sequence: f64,
    #[serde(rename = "hash", default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    /// The tenant sign-in policy as of the last `tenant:auth-policy` event read (for `guardrail-weakened`).
    #[serde(
        rename = "authPolicy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub auth_policy: Option<IndexMap<String, better_iam_core::Json>>,
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

/// One rule firing. `uniqueKey` is `{ruleId}:{dedupeKey}`, so re-reading the same events never raises a second
/// detection; rules choose a dedupe key per burst (window bucket) or per triggering event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatDetection {
    #[serde(rename = "ruleId")]
    pub rule_id: crate::threats::ThreatRuleId,
    #[serde(rename = "severity")]
    pub severity: crate::threats::ThreatSeverity,
    #[serde(rename = "title")]
    pub title: String,
    /// One sentence for lists and emails.
    #[serde(rename = "summary")]
    pub summary: String,
    #[serde(rename = "subject")]
    pub subject: crate::threats::ThreatSubject,
    /// The identity whose risk this detection raises, when there is one (the subject, or the actor behind it).
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    /// Network key (`ipCounterKey` form) the activity came from, when known.
    #[serde(rename = "network", default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(rename = "evidence")]
    pub evidence: crate::threats::ThreatEvidence,
    #[serde(rename = "metadata", default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<IndexMap<String, better_iam_core::Json>>,
    #[serde(rename = "status")]
    pub status: crate::threats::DetectionStatus,
    #[serde(
        rename = "incidentId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub incident_id: Option<String>,
    /// When the triggering activity happened (the latest event's timestamp).
    #[serde(rename = "occurredAt")]
    pub occurred_at: f64,
    /// When the engine (or a report) recorded it.
    #[serde(rename = "detectedAt")]
    pub detected_at: f64,
    #[serde(
        rename = "dismissedBy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub dismissed_by: Option<String>,
    #[serde(
        rename = "dismissedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub dismissed_at: Option<f64>,
    #[serde(
        rename = "dismissReason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub dismiss_reason: Option<String>,
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

/// What one `iam.detectThreats()` run did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatDetectionRun {
    #[serde(rename = "tenants")]
    pub tenants: f64,
    #[serde(rename = "eventsScanned")]
    pub events_scanned: f64,
    #[serde(rename = "detections")]
    pub detections: f64,
    #[serde(rename = "incidentsOpened")]
    pub incidents_opened: f64,
    #[serde(rename = "responses")]
    pub responses: f64,
    /// Automatic containments held back by `maxAutomaticContainments`.
    #[serde(rename = "braked")]
    pub braked: f64,
    /// Tenants whose audit chain failed verification in this run.
    #[serde(rename = "chainBreaks")]
    pub chain_breaks: f64,
    /// Tenants with more unread events than one run reads (`maxEvents`); the next run continues.
    #[serde(rename = "pending")]
    pub pending: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What a detection points at: up to 20 audit event ids plus counts, so a reviewer can open the underlying trail.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatEvidence {
    #[serde(rename = "eventIds")]
    pub event_ids: Vec<String>,
    #[serde(rename = "count")]
    pub count: f64,
    #[serde(rename = "firstAt")]
    pub first_at: f64,
    #[serde(rename = "lastAt")]
    pub last_at: f64,
    /// Network keys involved (`ipCounterKey` form), at most 20.
    #[serde(rename = "networks", default, skip_serializing_if = "Option::is_none")]
    pub networks: Option<Vec<String>>,
    /// Identities involved (targets of a spray, subjects of a mass deletion), at most 20.
    #[serde(
        rename = "identityIds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_ids: Option<Vec<String>>,
    /// Distinct audit actions involved, at most 20.
    #[serde(rename = "actions", default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Detections about one subject grouped for investigation. While open it holds `uniqueKey`
/// `open:{subject.type}:{subject.id}` (so one open incident per subject); resolving drops the key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatIncident {
    #[serde(rename = "subject")]
    pub subject: crate::threats::ThreatSubject,
    /// The identity the incident concerns, which responses to the incident act on. An incident about anything but an
    /// identity (the tenant, a network, a connection) names one only while all its detections that name an identity
    /// name the same one; once they differ it names none and `severalIdentities` is set.
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    #[serde(
        rename = "severalIdentities",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub several_identities: Option<bool>,
    #[serde(rename = "network", default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(rename = "severity")]
    pub severity: crate::threats::ThreatSeverity,
    #[serde(rename = "title")]
    pub title: String,
    #[serde(rename = "status")]
    pub status: crate::threats::IncidentStatus,
    /// Newest last, at most 200 (older ids stay findable through `threatDetections.incidentId`).
    #[serde(rename = "detectionIds")]
    pub detection_ids: Vec<String>,
    #[serde(rename = "detectionCount")]
    pub detection_count: f64,
    #[serde(rename = "ruleIds")]
    pub rule_ids: Vec<crate::threats::ThreatRuleId>,
    #[serde(rename = "firstDetectedAt")]
    pub first_detected_at: f64,
    #[serde(rename = "lastDetectedAt")]
    pub last_detected_at: f64,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(
        rename = "assigneeId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub assignee_id: Option<String>,
    #[serde(
        rename = "resolution",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub resolution: Option<String>,
    #[serde(
        rename = "resolvedBy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub resolved_by: Option<String>,
    #[serde(
        rename = "resolvedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub resolved_at: Option<f64>,
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

/// A free-text investigation note on an incident (`threats.addNote`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatNote {
    #[serde(rename = "incidentId")]
    pub incident_id: String,
    #[serde(rename = "authorId")]
    pub author_id: String,
    #[serde(rename = "body")]
    pub body: String,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
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

/// An automatic response: when a new detection matches `trigger`, the actions run under the threat-detection actor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatPlaybook {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(rename = "enabled")]
    pub enabled: bool,
    #[serde(rename = "trigger")]
    pub trigger: Value,
    #[serde(rename = "actions")]
    pub actions: Vec<crate::threats::ResponseAction>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(rename = "updatedBy")]
    pub updated_by: String,
    #[serde(rename = "lastRunAt", default, skip_serializing_if = "Option::is_none")]
    pub last_run_at: Option<f64>,
    #[serde(rename = "runs")]
    pub runs: f64,
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

/// One response action taken (automatically or by a person), kept for the incident timeline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatResponse {
    #[serde(rename = "action")]
    pub action: String,
    #[serde(rename = "subject")]
    pub subject: crate::threats::ThreatSubject,
    #[serde(rename = "outcome")]
    pub outcome: String,
    /// Why a response was skipped: `protected`, `no-network`, `trusted-network`, `already-applied`, `braked`,
    /// `no-recipients`, `not-identity`, `no-clearance`, `feature-disabled`, ...
    #[serde(rename = "reason", default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(
        rename = "incidentId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub incident_id: Option<String>,
    #[serde(
        rename = "detectionId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub detection_id: Option<String>,
    #[serde(
        rename = "playbookId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub playbook_id: Option<String>,
    /// Identity id of the person who responded, or `threat-detection` for playbooks.
    #[serde(rename = "actorId")]
    pub actor_id: String,
    #[serde(rename = "details", default, skip_serializing_if = "Option::is_none")]
    pub details: Option<IndexMap<String, better_iam_core::Json>>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
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

/// `sign-in`, `account`, `privilege`, `activity` or `integrity`: a string union in TypeScript, kept as its JSON string (other modules compare it with `== "..."`).
pub type ThreatRuleCategory = Value;

/// A built-in detection rule; tenants tune it with `threats.configure` (`ThreatRuleSetting`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatRuleDefinition {
    #[serde(rename = "id")]
    pub id: crate::threats::ThreatRuleId,
    #[serde(rename = "title")]
    pub title: String,
    #[serde(rename = "description")]
    pub description: String,
    #[serde(rename = "category")]
    pub category: crate::threats::ThreatRuleCategory,
    #[serde(rename = "severity")]
    pub severity: crate::threats::ThreatSeverity,
    #[serde(rename = "subject")]
    pub subject: crate::threats::ThreatSubjectType,
    /// Default count that trips the rule, when the rule counts.
    #[serde(rename = "threshold", default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
    /// Default sliding window, when the rule counts or correlates over time.
    #[serde(rename = "windowMs", default, skip_serializing_if = "Option::is_none")]
    pub window_ms: Option<f64>,
    /// Bounds `threats.configure` enforces on a tenant's `threshold` / `windowMs`.
    #[serde(rename = "tunable", default, skip_serializing_if = "Option::is_none")]
    pub tunable: Option<Value>,
    #[serde(rename = "enabledByDefault")]
    pub enabled_by_default: bool,
    /// MITRE ATT&CK technique the rule maps to.
    #[serde(rename = "technique")]
    pub technique: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The id of a rule of [`threat_rules`]: a string union in TypeScript, kept as its JSON string (other modules compare it with `== "..."`).
pub type ThreatRuleId = Value;

/// A tenant's adjustment of one rule; unset fields keep the rule's defaults.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatRuleSetting {
    #[serde(rename = "enabled", default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(rename = "threshold", default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
    #[serde(rename = "windowMs", default, skip_serializing_if = "Option::is_none")]
    pub window_ms: Option<f64>,
    #[serde(rename = "severity", default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// `new-network` only: report non-privileged people too (at low severity).
    #[serde(rename = "everyone", default, skip_serializing_if = "Option::is_none")]
    pub everyone: Option<bool>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Per-tenant settings, one record per tenant (`id` = tenant id), written by `threats.configure`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatSettings {
    #[serde(rename = "rules")]
    pub rules: Value,
    /// Networks (IP or CIDR) that network rules never report and responses never block: offices, VPN egress.
    #[serde(rename = "trustedNetworks")]
    pub trusted_networks: Vec<String>,
    /// Days without a sign-in after which an account counts as dormant (`dormant-reactivated`); default 90.
    #[serde(rename = "dormantDays")]
    pub dormant_days: f64,
    /// Risk contributions halve every this many hours; default 24.
    #[serde(rename = "riskHalfLifeHours")]
    pub risk_half_life_hours: f64,
    /// Who is emailed when a playbook's `notify` action runs: active owners and/or listed addresses.
    #[serde(rename = "notify")]
    pub notify: Value,
    /// Largest number of identities automatic playbooks may contain in one run before braking (default 3).
    #[serde(rename = "maxAutomaticContainments")]
    pub max_automatic_containments: f64,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(rename = "updatedBy")]
    pub updated_by: String,
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

/// One of [`THREAT_SEVERITIES`]: a string union in TypeScript, kept as its JSON string (other modules compare it with `== "..."`).
pub type ThreatSeverity = Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ThreatSubject {
    #[serde(rename = "type")]
    pub r#type: crate::threats::ThreatSubjectType,
    /// Identity id, network key (`ipCounterKey` form: an IPv4 address or an IPv6 /64), tenant id, or
    /// `scim:{connectionId}`.
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "name", default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What a detection is about: a person or machine identity, a client network, the tenant itself, or a directory
/// connection.
/// `identity`, `network`, `tenant` or `connection`: a string union in TypeScript, kept as its JSON string (other modules compare it with `== "..."`).
pub type ThreatSubjectType = Value;

/// Storage collection names of the threats module (`threatCollections`), as constants.
pub const DETECTIONS: &str = "threatDetections";
pub const INCIDENTS: &str = "threatIncidents";
pub const NOTES: &str = "threatNotes";
pub const RISK: &str = "identityRisk";
pub const BASELINES: &str = "threatBaselines";
pub const CURSORS: &str = "threatCursors";
pub const SETTINGS: &str = "threatSettings";
pub const PLAYBOOKS: &str = "threatPlaybooks";
pub const RESPONSES: &str = "threatResponses";

const MINUTE: f64 = 60_000.0;
const HOUR: f64 = 60.0 * MINUTE;
const DAY: f64 = 24.0 * HOUR;

/// `defaultThreatSettings`.
pub static DEFAULT_THREAT_SETTINGS: std::sync::LazyLock<Value> = std::sync::LazyLock::new(
    || json!({"dormantDays":90,"riskHalfLifeHours":24,"maxAutomaticContainments":3}),
);
const DEFAULT_DORMANT_DAYS: f64 = 90.0;
const DEFAULT_RISK_HALF_LIFE_HOURS: f64 = 24.0;
const DEFAULT_MAX_AUTOMATIC_CONTAINMENTS: f64 = 3.0;

/// One entry of the rule catalog, as written in threats.ts.
struct RuleSpec {
    id: &'static str,
    title: &'static str,
    description: &'static str,
    category: &'static str,
    severity: &'static str,
    subject: &'static str,
    threshold: Option<f64>,
    window_ms: Option<f64>,
    tunable_threshold: Option<(f64, f64)>,
    tunable_window_ms: Option<(f64, f64)>,
    technique: &'static str,
}

const RULE_SPECS: &[RuleSpec] = &[
    RuleSpec {
        id: "password-spray",
        title: "Password spray",
        description: "One network fails password sign-ins for many different people in a short window: someone is trying common passwords across accounts.",
        category: "sign-in",
        severity: "high",
        subject: "network",
        threshold: Some(10.0),
        window_ms: Some(15.0 * MINUTE),
        tunable_threshold: Some((3.0, 1000.0)),
        tunable_window_ms: Some((MINUTE, DAY)),
        technique: "T1110.003",
    },
    RuleSpec {
        id: "brute-force",
        title: "Password guessing",
        description: "Many failed password sign-ins for one person in a short window.",
        category: "sign-in",
        severity: "medium",
        subject: "identity",
        threshold: Some(10.0),
        window_ms: Some(15.0 * MINUTE),
        tunable_threshold: Some((3.0, 1000.0)),
        tunable_window_ms: Some((MINUTE, DAY)),
        technique: "T1110.001",
    },
    RuleSpec {
        id: "brute-force-success",
        title: "Sign-in after repeated failures",
        description: "A person signed in right after a run of failed attempts; high when the success came from a network that was failing.",
        category: "sign-in",
        severity: "high",
        subject: "identity",
        threshold: Some(5.0),
        window_ms: Some(30.0 * MINUTE),
        tunable_threshold: Some((2.0, 1000.0)),
        tunable_window_ms: Some((MINUTE, DAY)),
        technique: "T1110",
    },
    RuleSpec {
        id: "mfa-bombardment",
        title: "Second-factor guessing",
        description: "Repeated wrong second-factor codes for one person: the password was right, so someone else probably knows it.",
        category: "sign-in",
        severity: "high",
        subject: "identity",
        threshold: Some(5.0),
        window_ms: Some(15.0 * MINUTE),
        tunable_threshold: Some((2.0, 1000.0)),
        tunable_window_ms: Some((MINUTE, DAY)),
        technique: "T1621",
    },
    RuleSpec {
        id: "session-hijack",
        title: "Session used from another network",
        description: "A session bound to one network was presented from another (tenant policy bindSessionsToIp): a stolen cookie or token.",
        category: "sign-in",
        severity: "high",
        subject: "identity",
        threshold: None,
        window_ms: None,
        tunable_threshold: None,
        tunable_window_ms: None,
        technique: "T1550.004",
    },
    RuleSpec {
        id: "new-network",
        title: "Sign-in from a new network",
        description: "A privileged person (owner, root administrator, or holder of an administrator role) signed in from a network not seen for them before.",
        category: "sign-in",
        severity: "medium",
        subject: "identity",
        threshold: None,
        window_ms: None,
        tunable_threshold: None,
        tunable_window_ms: None,
        technique: "T1078",
    },
    RuleSpec {
        id: "dormant-reactivated",
        title: "Dormant account signed in",
        description: "Someone signed in to an account that had not been used for longer than the dormancy period.",
        category: "account",
        severity: "medium",
        subject: "identity",
        threshold: None,
        window_ms: None,
        tunable_threshold: None,
        tunable_window_ms: None,
        technique: "T1078",
    },
    RuleSpec {
        id: "account-takeover-persistence",
        title: "Account changes after a risky sign-in",
        description: "Shortly after a risky sign-in the account changed its sign-in methods (second factor removed, passkey or trusted device added, email or password changed, API key created).",
        category: "account",
        severity: "high",
        subject: "identity",
        threshold: None,
        window_ms: Some(HOUR),
        tunable_threshold: None,
        tunable_window_ms: Some((5.0 * MINUTE, 7.0 * DAY)),
        technique: "T1098",
    },
    RuleSpec {
        id: "privilege-escalation",
        title: "Self-granted administrator role",
        description: "Someone granted an administrator role and now holds it themselves.",
        category: "privilege",
        severity: "high",
        subject: "identity",
        threshold: None,
        window_ms: None,
        tunable_threshold: None,
        tunable_window_ms: None,
        technique: "T1098.003",
    },
    RuleSpec {
        id: "root-admin-granted",
        title: "Root administrator granted",
        description: "A person was made a root administrator of the deployment.",
        category: "privilege",
        severity: "high",
        subject: "identity",
        threshold: None,
        window_ms: None,
        tunable_threshold: None,
        tunable_window_ms: None,
        technique: "T1098",
    },
    RuleSpec {
        id: "mass-deletion",
        title: "Mass deletion",
        description: "One actor deleted or revoked many identities, roles, policies, groups, bindings, keys, or trusts in a short window.",
        category: "activity",
        severity: "high",
        subject: "identity",
        threshold: Some(20.0),
        window_ms: Some(10.0 * MINUTE),
        tunable_threshold: Some((3.0, 10_000.0)),
        tunable_window_ms: Some((MINUTE, DAY)),
        technique: "T1531",
    },
    RuleSpec {
        id: "directory-mass-change",
        title: "Directory mass change",
        description: "A SCIM connection updated or deleted many people in a short window.",
        category: "activity",
        severity: "medium",
        subject: "connection",
        threshold: Some(25.0),
        window_ms: Some(10.0 * MINUTE),
        tunable_threshold: Some((3.0, 100_000.0)),
        tunable_window_ms: Some((MINUTE, DAY)),
        technique: "T1531",
    },
    RuleSpec {
        id: "impersonation-burst",
        title: "Repeated impersonation",
        description: "One administrator started many \"view as\" sessions in a day.",
        category: "activity",
        severity: "medium",
        subject: "identity",
        threshold: Some(5.0),
        window_ms: Some(DAY),
        tunable_threshold: Some((2.0, 1000.0)),
        tunable_window_ms: Some((HOUR, 7.0 * DAY)),
        technique: "T1078",
    },
    RuleSpec {
        id: "denial-burst",
        title: "Burst of denied requests",
        description: "One actor was denied many times in a few minutes: probing for access it does not have (agents included).",
        category: "activity",
        severity: "medium",
        subject: "identity",
        threshold: Some(30.0),
        window_ms: Some(10.0 * MINUTE),
        tunable_threshold: Some((5.0, 100_000.0)),
        tunable_window_ms: Some((MINUTE, DAY)),
        technique: "T1069",
    },
    RuleSpec {
        id: "classified-access-attempts",
        title: "Repeated classified access attempts",
        description: "One actor was refused classified resources for want of a clearance several times within an hour (security clearances): reading up, or probing for what is classified.",
        category: "activity",
        severity: "high",
        subject: "identity",
        threshold: Some(3.0),
        window_ms: Some(HOUR),
        tunable_threshold: Some((1.0, 1000.0)),
        tunable_window_ms: Some((MINUTE, 7.0 * DAY)),
        technique: "T1213",
    },
    RuleSpec {
        id: "recon-burst",
        title: "Directory enumeration",
        description: "One actor read identities, bindings, credentials, or the audit trail far more than usual in a short window, or exported many people.",
        category: "activity",
        severity: "low",
        subject: "identity",
        threshold: Some(300.0),
        window_ms: Some(10.0 * MINUTE),
        tunable_threshold: Some((20.0, 1_000_000.0)),
        tunable_window_ms: Some((MINUTE, DAY)),
        technique: "T1087",
    },
    RuleSpec {
        id: "guardrail-weakened",
        title: "Security settings weakened",
        description: "The tenant sign-in policy dropped a protection (MFA requirement, IP allowlist, session binding), a network block was lifted, or threat detection was turned off or weakened (a rule, the risk half-life, trusted networks, the containment brake).",
        category: "integrity",
        severity: "medium",
        subject: "tenant",
        threshold: None,
        window_ms: None,
        tunable_threshold: None,
        tunable_window_ms: None,
        technique: "T1562",
    },
    RuleSpec {
        id: "token-replay",
        title: "Token replay",
        description: "A web identity token was presented a second time to assume a role.",
        category: "sign-in",
        severity: "high",
        subject: "identity",
        threshold: None,
        window_ms: None,
        tunable_threshold: None,
        tunable_window_ms: None,
        technique: "T1550",
    },
    RuleSpec {
        id: "audit-tampering",
        title: "Audit trail tampering",
        description: "The tenant audit hash chain no longer verifies: an event was changed, removed, or inserted outside the recorder.",
        category: "integrity",
        severity: "critical",
        subject: "tenant",
        threshold: None,
        window_ms: None,
        tunable_threshold: None,
        tunable_window_ms: None,
        technique: "T1070",
    },
    RuleSpec {
        id: "invariant-broken",
        title: "Access invariant broken",
        description: "A monitored access invariant stopped holding (invariant:broken).",
        category: "integrity",
        severity: "medium",
        subject: "tenant",
        threshold: None,
        window_ms: None,
        tunable_threshold: None,
        tunable_window_ms: None,
        technique: "T1098",
    },
    RuleSpec {
        id: "user-reported",
        title: "Reported by the account holder",
        description: "The person said a sign-in or change on their account was not them (threats.reportSuspicious).",
        category: "account",
        severity: "high",
        subject: "identity",
        threshold: None,
        window_ms: None,
        tunable_threshold: None,
        tunable_window_ms: None,
        technique: "T1078",
    },
    RuleSpec {
        id: "upstream-signal",
        title: "Reported by an upstream identity provider",
        description: "An upstream identity provider reported a compromised credential, a disabled or purged account, a required credential change, or medium or high risk for a person (Shared Signals). The severity follows the event: high for credential compromise and high risk, medium for disabled accounts and medium risk, low for credential changes.",
        category: "account",
        severity: "high",
        subject: "identity",
        threshold: None,
        window_ms: None,
        tunable_threshold: None,
        tunable_window_ms: None,
        technique: "T1078",
    },
];

/// The rule catalog, in display order (`threatRules`); every built-in rule is enabled by default.
static THREAT_RULES: LazyLock<Vec<ThreatRuleDefinition>> = LazyLock::new(|| {
    RULE_SPECS
        .iter()
        .map(|spec| {
            let mut tunable = Map::new();
            if let Some((min, max)) = spec.tunable_threshold {
                tunable.insert("threshold".into(), json!([number(min), number(max)]));
            }
            if let Some((min, max)) = spec.tunable_window_ms {
                tunable.insert("windowMs".into(), json!([number(min), number(max)]));
            }
            ThreatRuleDefinition {
                id: Value::String(spec.id.into()),
                title: spec.title.into(),
                description: spec.description.into(),
                category: Value::String(spec.category.into()),
                severity: Value::String(spec.severity.into()),
                subject: Value::String(spec.subject.into()),
                threshold: spec.threshold,
                window_ms: spec.window_ms,
                tunable: (!tunable.is_empty()).then_some(Value::Object(tunable)),
                enabled_by_default: true,
                technique: spec.technique.into(),
                extra: Map::new(),
            }
        })
        .collect()
});

/// The rule catalog, in display order (`threatRules`).
pub fn threat_rules() -> IamResult<Vec<crate::threats::ThreatRuleDefinition>> {
    Ok(THREAT_RULES.clone())
}

/// The ids of the rule catalog (`threatRuleIds`).
pub fn threat_rule_ids() -> IamResult<IndexSet<crate::threats::ThreatRuleId>> {
    Ok(THREAT_RULES.iter().map(|rule| rule.id.clone()).collect())
}

/// `threatRule(id)`: the catalog entry of a rule; a plain `Error` (answered as INTERNAL_ERROR) for an unknown id.
pub fn threat_rule(
    id: &crate::threats::ThreatRuleId,
) -> IamResult<crate::threats::ThreatRuleDefinition> {
    match THREAT_RULES.iter().find(|candidate| candidate.id == *id) {
        Some(rule) => Ok(rule.clone()),
        None => Err(ThrownError::error(format!(
            "Unknown threat rule {}",
            crate::js::js_string(Some(id))
        ))
        .into()),
    }
}

/// Applies rule defaults and deployment defaults to a tenant's stored settings (absent when never configured).
pub fn resolve_threat_settings(
    stored: Option<&crate::threats::ThreatSettings>,
) -> IamResult<crate::threats::ResolvedThreatSettings> {
    let mut rules = Map::new();
    for rule in THREAT_RULES.iter() {
        let rule_id = rule.id.as_str().unwrap_or_default();
        let own = stored
            .and_then(|settings| settings.rules.get(rule_id))
            .filter(|own| !own.is_null());
        let mut resolved = match own {
            Some(Value::Object(own)) => own.clone(),
            _ => Map::new(),
        };
        let own_member = |key: &str| {
            own.and_then(|own| own.get(key))
                .filter(|value| !value.is_null())
                .cloned()
        };
        resolved.insert(
            "enabled".into(),
            own_member("enabled").unwrap_or(Value::Bool(rule.enabled_by_default)),
        );
        resolved.insert(
            "severity".into(),
            own_member("severity").unwrap_or_else(|| rule.severity.clone()),
        );
        if let Some(threshold) = rule.threshold {
            resolved.insert(
                "threshold".into(),
                own_member("threshold").unwrap_or_else(|| number(threshold)),
            );
        }
        if let Some(window_ms) = rule.window_ms {
            resolved.insert(
                "windowMs".into(),
                own_member("windowMs").unwrap_or_else(|| number(window_ms)),
            );
        }
        rules.insert(rule_id.to_owned(), Value::Object(resolved));
    }
    Ok(ResolvedThreatSettings {
        rules: Value::Object(rules),
        trusted_networks: stored
            .map(|settings| settings.trusted_networks.clone())
            .unwrap_or_default(),
        dormant_days: stored.map_or(DEFAULT_DORMANT_DAYS, |settings| settings.dormant_days),
        risk_half_life_hours: stored.map_or(DEFAULT_RISK_HALF_LIFE_HOURS, |settings| {
            settings.risk_half_life_hours
        }),
        notify: stored
            .map(|settings| settings.notify.clone())
            .filter(|notify| !notify.is_null())
            .unwrap_or_else(|| json!({ "owners": false, "emails": [] })),
        max_automatic_containments: stored.map_or(DEFAULT_MAX_AUTOMATIC_CONTAINMENTS, |settings| {
            settings.max_automatic_containments
        }),
        extra: Map::new(),
    })
}

/// Risk points per detection severity.
pub static RISK_POINTS: std::sync::LazyLock<Value> =
    std::sync::LazyLock::new(|| json!({"low":10,"medium":25,"high":50,"critical":80}));

/// Lowest score of each level (`riskThresholds`).
pub static RISK_THRESHOLDS: std::sync::LazyLock<Value> =
    std::sync::LazyLock::new(|| json!({"low":10,"medium":40,"high":70}));
const RISK_THRESHOLD_LOW: f64 = 10.0;
const RISK_THRESHOLD_MEDIUM: f64 = 40.0;
const RISK_THRESHOLD_HIGH: f64 = 70.0;

/// `Math.max(a, b)`: NaN when either is NaN.
fn js_max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.max(b)
    }
}

/// `Math.min(a, b)`: NaN when either is NaN.
fn js_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.min(b)
    }
}

/// `Math.round(value)`: halves round towards positive infinity.
fn js_round(value: f64) -> f64 {
    if !value.is_finite() {
        return value;
    }
    let floor = value.floor();
    if value - floor >= 0.5 {
        floor + 1.0
    } else {
        floor
    }
}

/// Decayed score of the contributions at `now` (0-100).
pub fn risk_score(
    contributions: &[crate::threats::RiskContribution],
    now: f64,
    half_life_hours: f64,
) -> IamResult<f64> {
    Ok(decayed_score(contributions, now, half_life_hours))
}

fn decayed_score(contributions: &[RiskContribution], now: f64, half_life_hours: f64) -> f64 {
    let half_life_ms = js_max(1.0, half_life_hours) * HOUR;
    let mut total = 0.0;
    for contribution in contributions {
        let age = js_max(0.0, now - contribution.at);
        total += contribution.points * 0.5f64.powf(age / half_life_ms);
    }
    js_min(100.0, js_round(total))
}

/// `riskLevelFor(score)`: the level of a score.
pub fn risk_level_for(score: f64) -> crate::threats::RiskLevel {
    Value::String(level_for(score).into())
}

fn level_for(score: f64) -> &'static str {
    if score >= RISK_THRESHOLD_HIGH {
        "high"
    } else if score >= RISK_THRESHOLD_MEDIUM {
        "medium"
    } else if score >= RISK_THRESHOLD_LOW {
        "low"
    } else {
        "none"
    }
}

/// `levelRank[level]` (undefined for anything but a risk level).
fn level_rank(level: &Value) -> Option<u8> {
    match level.as_str()? {
        "none" => Some(0),
        "low" => Some(1),
        "medium" => Some(2),
        "high" => Some(3),
        _ => None,
    }
}

/// `severityRank[severity]` (undefined for anything but a severity).
fn severity_rank(severity: &Value) -> Option<u8> {
    match severity.as_str()? {
        "low" => Some(0),
        "medium" => Some(1),
        "high" => Some(2),
        "critical" => Some(3),
        _ => None,
    }
}

/// `rank[a] >= rank[b]`, false when either is undefined (a comparison with `undefined` is false in JavaScript).
fn at_least(a: Option<u8>, b: Option<u8>) -> bool {
    matches!((a, b), (Some(a), Some(b)) if a >= b)
}

/// `maxRiskLevel(a, b)`: the higher of two levels.
pub fn max_risk_level(
    a: &crate::threats::RiskLevel,
    b: &crate::threats::RiskLevel,
) -> crate::threats::RiskLevel {
    if at_least(level_rank(a), level_rank(b)) {
        a.clone()
    } else {
        b.clone()
    }
}

pub fn risk_level_at_least(
    level: &crate::threats::RiskLevel,
    floor: &crate::threats::RiskLevel,
) -> IamResult<bool> {
    Ok(at_least(level_rank(level), level_rank(floor)))
}

pub fn severity_at_least(
    severity: &crate::threats::ThreatSeverity,
    floor: &crate::threats::ThreatSeverity,
) -> IamResult<bool> {
    Ok(at_least(severity_rank(severity), severity_rank(floor)))
}

pub fn max_severity(
    a: &crate::threats::ThreatSeverity,
    b: &crate::threats::ThreatSeverity,
) -> IamResult<crate::threats::ThreatSeverity> {
    Ok(if at_least(severity_rank(a), severity_rank(b)) {
        a.clone()
    } else {
        b.clone()
    })
}

/// The score and level in force at `now` (the members of [`effective_risk`]).
fn effective(record: &IdentityRisk, now: f64, half_life_hours: f64) -> (f64, Value) {
    let score = decayed_score(&record.contributions, now, half_life_hours);
    let mut level = risk_level_for(score);
    if let Some(Value::Object(over)) = &record.r#override {
        let unexpired = match over.get("expiresAt") {
            None => true,
            Some(expires_at) => core_js::to_number(expires_at) > now,
        };
        if unexpired {
            level = max_risk_level(&level, over.get("level").unwrap_or(&Value::Null));
        }
    }
    let floor = match level.as_str() {
        Some("none") => 0.0,
        Some("low") => RISK_THRESHOLD_LOW,
        Some("medium") => RISK_THRESHOLD_MEDIUM,
        Some("high") => RISK_THRESHOLD_HIGH,
        _ => f64::NAN,
    };
    (js_max(score, floor), level)
}

/// The score and level in force at `now`: decayed contributions, raised to an unexpired override's level. Answers
/// `{ score, level }`.
pub fn effective_risk(
    record: Option<&crate::threats::IdentityRisk>,
    now: f64,
    half_life_hours: f64,
) -> IamResult<Value> {
    let Some(record) = record else {
        return Ok(json!({ "score": 0, "level": "none" }));
    };
    let (score, level) = effective(record, now, half_life_hours);
    let mut out = Map::new();
    out.insert("score".into(), number(score));
    out.insert("level".into(), level);
    Ok(Value::Object(out))
}

/// The policy context keys this module fills (decisions.rs reads them lazily when a document mentions them).
pub const RISK_CONTEXT_KEYS: &[&str] = &["principal.riskLevel", "principal.riskScore"];

/// True when any statement of the documents refers to principal.riskLevel / principal.riskScore (conditions or
/// variables).
pub fn mentions_risk(documents: &[&better_iam_core::PolicyDocument]) -> bool {
    documents.iter().any(|document| {
        let serialized = better_iam_core::js::stringify(
            &serde_json::to_value(&document.statements).unwrap_or(Value::Null),
        );
        ["principal.risk"]
            .iter()
            .any(|key| serialized.contains(key))
    })
}

/// The risk keys for a decision. Simulated principals (invariants, impact previews, policy simulation, birthright
/// automation) always get `none`/0 so an incident never flips an invariant or stalls automation; a delegated
/// session takes the higher of the person's and the agent's risk.
pub async fn risk_context(
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    now: f64,
) -> IamResult<Map<String, Value>> {
    let keys = |level: Value, score: f64| {
        let mut out = Map::new();
        out.insert("principal.riskLevel".into(), level);
        out.insert("principal.riskScore".into(), number(score));
        out
    };
    if principal.session.id == "simulation" {
        return Ok(keys(Value::String("none".into()), 0.0));
    }
    let mut ids = vec![principal.identity.id.clone()];
    if let Some(agent_id) = principal
        .session
        .agent_id
        .as_ref()
        .filter(|id| !id.is_empty())
    {
        ids.push(agent_id.clone());
    }
    let mut level = Value::String("none".into());
    let mut score: f64 = 0.0;
    for identity_id in ids {
        let Some(record) = tx.get(RISK, &identity_id).await? else {
            continue;
        };
        let record: IdentityRisk = decode(record)?;
        let settings = tx.get(SETTINGS, &record.tenant_id).await?;
        let half_life = settings
            .as_ref()
            .and_then(|settings| settings.get("riskHalfLifeHours"))
            .filter(|value| !value.is_null())
            .map_or(DEFAULT_RISK_HALF_LIFE_HOURS, core_js::to_number);
        let (risk_score, risk_level) = effective(&record, now, half_life);
        level = max_risk_level(&level, &risk_level);
        score = js_max(score, risk_score);
    }
    Ok(keys(level, score))
}

/// Ends the threats module's hold on an identity whose status another path changed (identities.setStatus and
/// offboard, service accounts, agents.suspend and resume, lifecycle workflows): the containment mark goes, so
/// `threats.release` never re-activates what that path disabled, and a later disable is not taken for a
/// containment. The risk score stays. Nothing happens for an identity that is not contained.
pub async fn end_containment(tx: &Store, identity_id: &str, now: f64) -> IamResult<()> {
    let Some(mut record) = tx.get(RISK, identity_id).await? else {
        return Ok(());
    };
    if !crate::js::truthy(record.get("contained")) {
        return Ok(());
    }
    record.shift_remove("contained");
    record.insert("updatedAt".into(), number(now));
    tx.put(RISK, &record).await?;
    Ok(())
}

pub const RESPONSE_ACTION_KINDS: &[&str] = &[
    "revoke-sessions",
    "forget-devices",
    "contain",
    "suspend-clearance",
    "block-network",
    "notify",
];

pub const RISK_LEVELS: &[&str] = &["none", "low", "medium", "high"];

/// The actor recorded on audit events the detection engine and automatic playbooks write.
pub const THREAT_ACTOR: &str = "threat-detection";

/// Storage collections of the threats module; every one is tenant-scoped (lifecycle.ts tenantCollections).
pub static THREAT_COLLECTIONS: std::sync::LazyLock<Value> = std::sync::LazyLock::new(
    || json!({"detections":"threatDetections","incidents":"threatIncidents","notes":"threatNotes","risk":"identityRisk","baselines":"threatBaselines","cursors":"threatCursors","settings":"threatSettings","playbooks":"threatPlaybooks","responses":"threatResponses"}),
);

pub const THREAT_SEVERITIES: &[&str] = &["low", "medium", "high", "critical"];
