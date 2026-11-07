//! Port of `packages/server/src/api/compliance.ts`.
//!
//! The compliance center: turn the built-in checks into controls (by adopting SOC 2, ISO 27001, NIST 800-53 or GDPR
//! mappings, or one by one), evaluate them (the scheduler job `iam.compliance.evaluateAll`, or `evaluate`), grant
//! time-boxed exceptions for accepted findings (a second person approves each), see each framework requirement's
//! status, and export signed evidence. Reading needs `iam:compliance:read`, running evaluations
//! `iam:compliance:evaluate`, the rest `iam:compliance:manage`. Findings name people only for callers who may read
//! the directory (`iam:identities:read`).

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use better_iam_auth::util::{base64url, node_base64_decode};
use better_iam_core::js as core_js;
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, IamStoreExt, Record, canonical_json,
};
use better_iam_types::api::compliance;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::api::{Body, Reply, string_member};
use crate::compliance::{
    CheckFinding, check_by_id, check_params, checkpoint_id, compliance_checks,
    compliance_frameworks, effective_params, evaluate_check, exception_active, framework_by_id,
    params_json,
};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::js::cmp_utf16;
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::utils::{id, same_hash};
use crate::validation::{integer, object, strings, text};

const MAX_CONTROLS: usize = 200;
const RESULT_RETENTION_MS: f64 = 400.0 * 86_400_000.0;
const STALE_AFTER_MS: f64 = 3.0 * 86_400_000.0;
/// Manual evaluations per tenant: at most one a minute (the scheduled job is not limited).
const MANUAL_INTERVAL_MS: f64 = 60_000.0;

/// The statuses a run counts, in the TypeScript member order.
const STATUSES: [&str; 4] = ["pass", "fail", "warn", "not-applicable"];

/// An Ed25519 evidence key derived from a deployment secret.
struct EvidenceKey {
    signing: SigningKey,
    /// The public JWK (`EvidenceKey`): `kty`, `crv`, `x`, `kid`, `alg`, `use`.
    jwk: Value,
    kid: String,
}

/// Ed25519 keys derived from the deployment secret, so every instance signs alike and rotation keeps old packs valid.
static KEY_CACHE: LazyLock<Mutex<HashMap<String, Arc<EvidenceKey>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn evidence_key(secret: &str) -> Arc<EvidenceKey> {
    if let Some(cached) = KEY_CACHE
        .lock()
        .ok()
        .and_then(|cache| cache.get(secret).cloned())
    {
        return cached;
    }
    let seed: [u8; 32] =
        Sha256::digest(format!("better-iam:compliance-evidence:ed25519:{secret}").as_bytes())
            .into();
    let signing = SigningKey::from_bytes(&seed);
    let x = base64url(signing.verifying_key().as_bytes());
    // RFC 7638 thumbprint: the required members in lexicographic order.
    let kid = base64url(Sha256::digest(
        canonical_json(&json!({ "crv": "Ed25519", "kty": "OKP", "x": x })).as_bytes(),
    ));
    let entry = Arc::new(EvidenceKey {
        signing,
        jwk: json!({ "kty": "OKP", "crv": "Ed25519", "x": x, "kid": kid, "alg": "EdDSA", "use": "sig" }),
        kid,
    });
    if let Ok(mut cache) = KEY_CACHE.lock() {
        cache.insert(secret.to_owned(), entry.clone());
    }
    entry
}

fn pack_digest(body: &Value) -> String {
    base64url(Sha256::digest(canonical_json(body).as_bytes()))
}

/// Version 1 packs (HMAC-SHA256 under the deployment secret) still verify on the deployment that made them.
fn legacy_signature(secret: &str, body: &Value) -> String {
    let key = Sha256::digest(format!("better-iam:compliance-evidence:{secret}").as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(&key).expect("HMAC takes any key length");
    mac.update(canonical_json(body).as_bytes());
    base64url(mac.finalize().into_bytes())
}

/// `verify(null, Buffer.from(digest), publicKey(x), Buffer.from(signature, 'base64url'))`; None when the key cannot be
/// imported (`createPublicKey` throws).
fn ed25519_verify(x: &Value, digest: &str, signature: &str) -> Option<bool> {
    let x = x.as_str()?;
    let bytes: [u8; 32] = node_base64_decode(x).try_into().ok()?;
    let key = VerifyingKey::from_bytes(&bytes).ok()?;
    let signature = node_base64_decode(signature);
    Some(match Signature::from_slice(&signature) {
        Ok(signature) => key.verify(digest.as_bytes(), &signature).is_ok(),
        Err(_) => false,
    })
}

/// The result of [`verify_evidence_pack`]: `{ valid, kid?, reason? }`.
fn verdict(valid: bool, kid: Option<&Value>, reason: Option<&str>) -> Value {
    let mut out = Map::new();
    out.insert("valid".into(), Value::Bool(valid));
    if let Some(kid) = kid {
        out.insert("kid".into(), kid.clone());
    }
    if let Some(reason) = reason {
        out.insert("reason".into(), Value::String(reason.to_owned()));
    }
    Value::Object(out)
}

/// Verifies an evidence pack offline, with the deployment's published evidence keys (`compliance.evidenceKeys`, a
/// list of keys or `{ keys }`): the digest must match the pack's content and the signature must verify with the key
/// it names. Needs no server. Answers `{ valid, kid?, reason? }`.
pub fn verify_evidence_pack(pack: &Value, keys: &Value) -> Value {
    if !crate::js::truthy(Some(pack)) || !matches!(pack, Value::Object(_) | Value::Array(_)) {
        return verdict(false, None, Some("not a pack"));
    }
    let Value::Object(map) = pack else {
        return verdict(false, None, Some("unsigned"));
    };
    let digest = map.get("digest");
    let signature = map.get("signature");
    let signature_value = signature.and_then(|signature| match signature {
        Value::Object(signature) => signature.get("value"),
        _ => None,
    });
    let (Some(Value::String(digest)), Some(Value::String(signature_value))) =
        (digest, signature_value)
    else {
        return verdict(false, None, Some("unsigned"));
    };
    let mut body = map.clone();
    body.shift_remove("digest");
    body.shift_remove("signature");
    if pack_digest(&Value::Object(body)) != *digest {
        return verdict(false, None, Some("digest mismatch"));
    }
    let list: &[Value] = match keys {
        Value::Array(list) => list,
        _ => match keys.get("keys") {
            Some(Value::Array(list)) => list,
            _ => &[],
        },
    };
    let wanted = signature.and_then(|signature| signature.get("kid"));
    let Some(key) = list.iter().find(|item| same(item.get("kid"), wanted)) else {
        return verdict(false, None, Some("unknown key"));
    };
    match key
        .get("x")
        .and_then(|x| ed25519_verify(x, digest, signature_value))
    {
        Some(true) => verdict(true, key.get("kid"), None),
        _ => verdict(false, None, Some("bad signature")),
    }
}

/// `a === b` of two optional JSON values (`undefined === undefined`).
fn same(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => core_js::strict_equal(a, b),
        _ => false,
    }
}

/// `/^[a-z][a-z0-9._-]{0,63}$/`.
fn key_shape(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some('a'..='z'))
        && key.chars().count() <= 64
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '.' | '_' | '-'))
}

fn control_key(value: Option<&Value>) -> IamResult<String> {
    let key = text(value, "key", 64)?;
    if !key_shape(&key) {
        return Err(IamError::new(
            "INVALID_INPUT",
            "Control keys use lowercase letters, digits, dots, underscores or hyphens",
        ));
    }
    Ok(key)
}

fn mappings(value: Option<&Value>) -> IamResult<Vec<String>> {
    if value.is_none() {
        return Ok(vec![]);
    }
    let mut unique: IndexSet<String> = IndexSet::new();
    for item in strings(value, "mappings")? {
        let item = text(Some(&Value::String(item)), "mappings", 64)?;
        unique.insert(core_js::trim(&item).to_owned());
    }
    if unique.len() > 50 {
        return Err(IamError::new("INVALID_INPUT", "At most 50 mappings"));
    }
    let mut list: Vec<String> = unique.into_iter().collect();
    crate::js::sort_strings(&mut list);
    Ok(list)
}

fn empty_counts() -> IndexMap<&'static str, f64> {
    STATUSES.iter().map(|status| (*status, 0.0)).collect()
}

fn counts_json(counts: &IndexMap<&'static str, f64>) -> Map<String, Value> {
    counts
        .iter()
        .map(|(status, count)| ((*status).to_owned(), crate::js::number(*count)))
        .collect()
}

/// Worst first: a requirement is as good as its worst control.
fn severity(status: &str) -> Option<i32> {
    Some(match status {
        "fail" => 6,
        "disabled" => 5,
        "not-evaluated" => 4,
        "no-control" => 3,
        "warn" => 2,
        "pass" => 1,
        "not-applicable" => 0,
        _ => return None,
    })
}

/// Whether a finding names this person (an exception for it would be their own).
fn names_identity(subject: &str, identity_id: &str) -> bool {
    subject == format!("identity:{identity_id}")
        || subject.starts_with(&format!("identity:{identity_id}:"))
}

/// `exception.status ?? 'approved'`.
fn exception_status(exception: &Record) -> Value {
    match exception.get("status") {
        None | Some(Value::Null) => Value::String("approved".into()),
        Some(status) => status.clone(),
    }
}

fn s<'a>(record: &'a Record, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn num(record: &Record, key: &str) -> Option<f64> {
    record.get(key).and_then(core_js::as_number)
}

fn by_tenant(tenant_id: &str) -> Filter {
    Filter::new().eq("tenantId", tenant_id)
}

async fn find(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

/// `(a, b) => (a.key < b.key ? -1 : 1)`.
fn by_key(a: &Record, b: &Record) -> Ordering {
    cmp_utf16(s(a, "key"), s(b, "key"))
}

/// `(a, b) => b[field] - a[field]`.
fn newest(a: &Record, b: &Record, field: &str) -> Ordering {
    let difference = num(b, field).unwrap_or(f64::NAN) - num(a, field).unwrap_or(f64::NAN);
    difference.partial_cmp(&0.0).unwrap_or(Ordering::Equal)
}

/// `(a, b) => a[field] - b[field]`.
fn oldest(a: &Record, b: &Record, field: &str) -> Ordering {
    newest(b, a, field)
}

fn includes(list: Option<&Value>, wanted: &str) -> bool {
    match list {
        Some(Value::Array(items)) => items.iter().any(|item| item.as_str() == Some(wanted)),
        _ => false,
    }
}

fn mapping_prefix(control: &Record, prefix: &str) -> bool {
    match control.get("mappings") {
        Some(Value::Array(items)) => items
            .iter()
            .any(|item| item.as_str().is_some_and(|item| item.starts_with(prefix))),
        _ => false,
    }
}

/// A check the evaluation ran and the result it will record.
struct Evaluated {
    control: Record,
    result: Record,
}

/// Runs a tenant's enabled controls (or the named ones) and records the results, a run, and an audit event. The checks
/// read outside any transaction; only the results are written, in one short transaction. Returns the run and the
/// results.
pub async fn evaluate_compliance(
    ctx: &Arc<ServerContext>,
    tenant_id: &str,
    triggered_by: &str,
    keys: Option<&[String]>,
    min_interval_ms: Option<f64>,
) -> IamResult<(Record, Vec<Record>)> {
    let store = &ctx.store;
    let tenant = ctx.tenant(store, tenant_id).await?;
    let now = ctx.now();
    if let Some(min_interval) = min_interval_ms.filter(|interval| *interval != 0.0) {
        let last = find(store, "complianceRuns", by_tenant(tenant_id))
            .await?
            .iter()
            .fold(0.0f64, |latest, run| {
                let at = num(run, "evaluatedAt").unwrap_or(f64::NAN);
                // Math.max: NaN wins.
                if at.is_nan() || latest.is_nan() {
                    f64::NAN
                } else {
                    latest.max(at)
                }
            });
        if last > now - min_interval {
            return Err(IamError::with_status(
                "RATE_LIMITED",
                "The controls were evaluated less than a minute ago",
                429,
            ));
        }
    }
    let mut controls: Vec<Record> = find(store, "complianceControls", by_tenant(tenant_id))
        .await?
        .into_iter()
        .filter(|control| {
            crate::js::truthy(control.get("enabled"))
                && keys.is_none_or(|keys| {
                    keys.iter()
                        .any(|key| control.get("key").and_then(Value::as_str) == Some(key.as_str()))
                })
        })
        .collect();
    controls.sort_by(by_key);
    let exceptions: Vec<Record> = find(store, "complianceExceptions", by_tenant(tenant_id))
        .await?
        .into_iter()
        .filter(|exception| exception_active(exception, now))
        .collect();
    let run_id = id();
    let mut evaluated: Vec<Evaluated> = Vec::new();
    let mut checkpoint: Option<(f64, String)> = None;
    for control in controls {
        let Some(check) = check_by_id(s(&control, "checkId")) else {
            continue;
        };
        let excepted: IndexSet<String> = if check.no_exceptions {
            IndexSet::new()
        } else {
            exceptions
                .iter()
                .filter(|item| item.get("controlKey") == control.get("key"))
                .map(|item| crate::js::js_string(item.get("subject")))
                .collect()
        };
        let status: &str;
        let raw_status: &str;
        let summary: String;
        let mut metrics = Map::new();
        let mut findings: Vec<(CheckFinding, bool)> = Vec::new();
        let outcome = match effective_params(check, control.get("params")) {
            Ok(params) => evaluate_check(check, ctx, store, &tenant, &params, now).await,
            Err(error) => Err(error),
        };
        match outcome {
            Ok(outcome) => {
                metrics = outcome.metrics_json();
                findings = outcome
                    .findings
                    .iter()
                    .map(|finding| (finding.clone(), excepted.contains(&finding.subject)))
                    .collect();
                raw_status = (outcome.judge)(&outcome.findings).status;
                let remaining: Vec<CheckFinding> = findings
                    .iter()
                    .filter(|(_, excepted)| !excepted)
                    .map(|(finding, _)| finding.clone())
                    .collect();
                let judgement = (outcome.judge)(&remaining);
                status = judgement.status;
                summary = judgement.summary;
                if let Some(found) = outcome.checkpoint {
                    checkpoint = Some(found);
                }
            }
            Err(error) => {
                // A check that cannot run fails, visibly, rather than passing by omission.
                status = "fail";
                raw_status = "fail";
                summary = slice_utf16(&format!("The check could not run: {}", error.message), 300);
            }
        }
        let findings_json: Vec<Value> = findings
            .iter()
            .take(200)
            .map(|(finding, excepted)| {
                let mut out = Map::new();
                out.insert("subject".into(), Value::String(finding.subject.clone()));
                out.insert("detail".into(), Value::String(finding.detail.clone()));
                if *excepted {
                    out.insert("excepted".into(), Value::Bool(true));
                }
                Value::Object(out)
            })
            .collect();
        let excepted_count = findings.iter().filter(|(_, excepted)| *excepted).count();
        let mut result = Record::new();
        result.insert("id".into(), Value::String(id()));
        result.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
        result.insert("runId".into(), Value::String(run_id.clone()));
        result.insert(
            "controlId".into(),
            control.get("id").cloned().unwrap_or(Value::Null),
        );
        result.insert(
            "controlKey".into(),
            control.get("key").cloned().unwrap_or(Value::Null),
        );
        result.insert(
            "checkId".into(),
            control.get("checkId").cloned().unwrap_or(Value::Null),
        );
        result.insert("status".into(), Value::String(status.to_owned()));
        result.insert("rawStatus".into(), Value::String(raw_status.to_owned()));
        result.insert("summary".into(), Value::String(summary));
        result.insert("metrics".into(), Value::Object(metrics));
        result.insert("findings".into(), Value::Array(findings_json));
        result.insert(
            "findingsTotal".into(),
            crate::js::number(findings.len() as f64),
        );
        result.insert("excepted".into(), crate::js::number(excepted_count as f64));
        result.insert("evaluatedAt".into(), crate::js::number(now));
        result.insert(
            "expiresAt".into(),
            crate::js::number(now + RESULT_RETENTION_MS),
        );
        evaluated.push(Evaluated { control, result });
    }
    let ctx = ctx.clone();
    let tenant_id = tenant_id.to_owned();
    let triggered_by = triggered_by.to_owned();
    ctx.store
        .clone()
        .transaction(move |tx| async move {
            let events = ctx.events()?;
            let mut results: Vec<Record> = Vec::new();
            let mut counts = empty_counts();
            for Evaluated {
                control: read,
                result,
            } in evaluated
            {
                // The control may have changed or gone while the checks ran; results follow the stored one.
                let Some(mut control) = tx.get("complianceControls", s(&read, "id")).await? else {
                    continue;
                };
                if s(&control, "tenantId") != tenant_id || control.get("key") != read.get("key") {
                    continue;
                }
                let status = s(&result, "status").to_owned();
                if let Some(count) = counts.get_mut(status.as_str()) {
                    *count += 1.0;
                }
                tx.insert("complianceResults", &result).await?;
                let last_status = control.get("lastStatus").cloned();
                let last = last_status.as_ref().and_then(Value::as_str);
                if last != Some(status.as_str()) && (status == "fail" || last == Some("fail")) {
                    let mut metadata = Map::new();
                    metadata.insert(
                        "key".into(),
                        control.get("key").cloned().unwrap_or(Value::Null),
                    );
                    metadata.insert(
                        "checkId".into(),
                        control.get("checkId").cloned().unwrap_or(Value::Null),
                    );
                    metadata.insert("status".into(), Value::String(status.clone()));
                    if crate::js::truthy(last_status.as_ref()) {
                        metadata.insert(
                            "previous".into(),
                            last_status.clone().unwrap_or(Value::Null),
                        );
                    }
                    metadata.insert(
                        "summary".into(),
                        result.get("summary").cloned().unwrap_or(Value::Null),
                    );
                    let mut event = Record::new();
                    event.insert("id".into(), Value::String(id()));
                    event.insert("tenantId".into(), Value::String(tenant_id.clone()));
                    event.insert("actorId".into(), Value::String(triggered_by.clone()));
                    event.insert(
                        "action".into(),
                        Value::String(
                            if status == "fail" {
                                "compliance:control:fail"
                            } else {
                                "compliance:control:recover"
                            }
                            .into(),
                        ),
                    );
                    event.insert(
                        "resourceId".into(),
                        control.get("id").cloned().unwrap_or(Value::Null),
                    );
                    event.insert("timestamp".into(), crate::js::number(now));
                    event.insert(
                        "outcome".into(),
                        Value::String(if status == "fail" { "deny" } else { "allow" }.into()),
                    );
                    event.insert("metadata".into(), Value::Object(metadata));
                    events.record_audit(&tx, &event).await?;
                }
                control.insert("lastStatus".into(), Value::String(status.clone()));
                control.insert("lastEvaluatedAt".into(), crate::js::number(now));
                control.insert(
                    "lastResultId".into(),
                    result.get("id").cloned().unwrap_or(Value::Null),
                );
                tx.put("complianceControls", &control).await?;
                results.push(result);
            }
            if let Some((sequence, hash)) = checkpoint {
                let saved = tx
                    .get("complianceCheckpoints", &checkpoint_id(&tenant_id))
                    .await?;
                let mut record = Record::new();
                record.insert("id".into(), Value::String(checkpoint_id(&tenant_id)));
                record.insert("tenantId".into(), Value::String(tenant_id.clone()));
                record.insert("sequence".into(), crate::js::number(sequence));
                record.insert("hash".into(), Value::String(hash));
                record.insert("verifiedAt".into(), crate::js::number(now));
                match saved {
                    None => {
                        tx.insert("complianceCheckpoints", &record).await?;
                    }
                    Some(saved)
                        if num(&saved, "sequence").is_some_and(|stored| stored < sequence) =>
                    {
                        tx.put("complianceCheckpoints", &record).await?;
                    }
                    Some(_) => {}
                }
            }
            let summary: Vec<Value> = results
                .iter()
                .map(|result| {
                    json!({
                        "control": result.get("controlKey").cloned().unwrap_or(Value::Null),
                        "status": result.get("status").cloned().unwrap_or(Value::Null),
                        "findings": result.get("findingsTotal").cloned().unwrap_or(Value::Null),
                        "excepted": result.get("excepted").cloned().unwrap_or(Value::Null),
                        "metrics": result.get("metrics").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect();
            let digest = hex::encode(Sha256::digest(
                canonical_json(&Value::Array(summary)).as_bytes(),
            ));
            let mut run = Record::new();
            run.insert("id".into(), Value::String(run_id.clone()));
            run.insert("tenantId".into(), Value::String(tenant_id.clone()));
            run.insert("evaluatedAt".into(), crate::js::number(now));
            run.insert("counts".into(), Value::Object(counts_json(&counts)));
            run.insert("digest".into(), Value::String(digest.clone()));
            run.insert("triggeredBy".into(), Value::String(triggered_by.clone()));
            run.insert(
                "expiresAt".into(),
                crate::js::number(now + RESULT_RETENTION_MS),
            );
            tx.insert("complianceRuns", &run).await?;
            let mut metadata = counts_json(&counts);
            metadata.insert("digest".into(), Value::String(digest));
            let mut event = Record::new();
            event.insert("id".into(), Value::String(id()));
            event.insert("tenantId".into(), Value::String(tenant_id.clone()));
            event.insert("actorId".into(), Value::String(triggered_by.clone()));
            event.insert("action".into(), Value::String("compliance:evaluate".into()));
            event.insert("resourceId".into(), Value::String(run_id.clone()));
            event.insert("timestamp".into(), crate::js::number(now));
            event.insert("outcome".into(), Value::String("allow".into()));
            event.insert("metadata".into(), Value::Object(metadata));
            events.record_audit(&tx, &event).await?;
            Ok((run, results))
        })
        .await
}

/// `message.slice(0, max)`: the first `max` UTF-16 code units.
fn slice_utf16(message: &str, max: usize) -> String {
    let mut units = 0;
    let mut out = String::new();
    for c in message.chars() {
        units += c.len_utf16();
        if units > max {
            break;
        }
        out.push(c);
    }
    out
}

/// The newest result of each control, by its pointer (controls evaluated before pointers fall back to a lookup).
async fn latest_results(
    tx: &Store,
    tenant_id: &str,
    controls: &[Record],
) -> IamResult<IndexMap<String, Record>> {
    let mut latest: IndexMap<String, Record> = IndexMap::new();
    for control in controls {
        let key = crate::js::js_string(control.get("key"));
        if crate::js::truthy(control.get("lastResultId")) {
            let result_id = crate::js::js_string(control.get("lastResultId"));
            if let Some(result) = tx.get("complianceResults", &result_id).await?
                && s(&result, "tenantId") == tenant_id
            {
                latest.insert(key, result);
            }
            continue;
        }
        if control.get("lastEvaluatedAt").is_none() {
            continue;
        }
        for result in find(
            tx,
            "complianceResults",
            by_tenant(tenant_id).eq(
                "controlKey",
                control.get("key").cloned().unwrap_or(Value::Null),
            ),
        )
        .await?
        {
            let current = latest
                .get(&key)
                .and_then(|item| num(item, "evaluatedAt"))
                .unwrap_or(-1.0);
            if num(&result, "evaluatedAt").is_some_and(|at| current < at) {
                latest.insert(key.clone(), result);
            }
        }
    }
    Ok(latest)
}

/// `/^identity:([^:]+)/`: the identity a finding names.
fn finding_identity(subject: &str) -> Option<&str> {
    let rest = subject.strip_prefix("identity:")?;
    let id = rest.split(':').next().unwrap_or_default();
    (!id.is_empty()).then_some(id)
}

/// The `compliance` API group (`createComplianceApi(ctx)`): one method per route `compliance/{method}`.
pub struct ComplianceApi {
    ctx: Arc<ServerContext>,
}

/// `createComplianceApi(ctx)`.
pub fn create_compliance_api(ctx: &Arc<ServerContext>) -> IamResult<ComplianceApi> {
    Ok(ComplianceApi { ctx: ctx.clone() })
}

/// May the caller see people's names and addresses (`iam:identities:read`)?
async fn directory(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
) -> IamResult<bool> {
    Ok(ctx
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

/// Results as readers see them: names added for directory readers, staleness marked.
async fn views(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    results: Vec<Record>,
) -> IamResult<Vec<Record>> {
    let mut names: HashMap<String, Value> = HashMap::new();
    if directory(ctx, tx, principal, tenant_id).await? {
        let mut ids: IndexSet<String> = IndexSet::new();
        for result in &results {
            for finding in finding_list(result) {
                if let Some(identity_id) = finding
                    .get("subject")
                    .and_then(Value::as_str)
                    .and_then(finding_identity)
                {
                    ids.insert(identity_id.to_owned());
                }
            }
        }
        for identity_id in ids {
            if let Some(identity) = tx.get("identities", &identity_id).await?
                && s(&identity, "tenantId") == tenant_id
            {
                let name = match identity.get("email") {
                    None | Some(Value::Null) => {
                        identity.get("name").cloned().unwrap_or(Value::Null)
                    }
                    Some(email) => email.clone(),
                };
                names.insert(identity_id, name);
            }
        }
    }
    let now = ctx.now();
    Ok(results
        .into_iter()
        .map(|mut result| {
            let stale = num(&result, "evaluatedAt").is_some_and(|at| at < now - STALE_AFTER_MS);
            let findings: Vec<Value> = finding_list(&result)
                .iter()
                .map(|finding| {
                    let subject = finding
                        .get("subject")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let name = names.get(finding_identity(subject).unwrap_or_default());
                    match (name, finding) {
                        (Some(name), Value::Object(map)) if crate::js::truthy(Some(name)) => {
                            let mut map = map.clone();
                            map.insert("name".into(), name.clone());
                            Value::Object(map)
                        }
                        _ => finding.clone(),
                    }
                })
                .collect();
            result.insert("stale".into(), Value::Bool(stale));
            result.insert("findings".into(), Value::Array(findings));
            result
        })
        .collect())
}

fn finding_list(result: &Record) -> Vec<Value> {
    match result.get("findings") {
        Some(Value::Array(items)) => items.clone(),
        _ => vec![],
    }
}

/// `controlState(control)`: what an audit event records of a control.
fn control_state(control: &Record) -> Value {
    let mut out = Map::new();
    for key in ["name", "params", "mappings", "enabled"] {
        if let Some(value) = control.get(key) {
            out.insert(key.into(), value.clone());
        }
    }
    Value::Object(out)
}

async fn audit(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    action: &str,
    tenant_id: &str,
    resource_id: &str,
    metadata: Map<String, Value>,
) -> IamResult<()> {
    ctx.events()?
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

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

/// `input.member === undefined ? undefined : frameworkById.get(text(input.member, 'framework', 32))`, with the
/// unknown-framework refusal.
fn selected_framework(input: &Map<String, Value>) -> IamResult<Option<&'static Value>> {
    match input.get("framework") {
        None => Ok(None),
        Some(value) => match framework_by_id(&text(Some(value), "framework", 32)?) {
            Some(framework) => Ok(Some(framework)),
            None => Err(invalid("Unknown framework")),
        },
    }
}

fn framework_ref(framework: &Value) -> String {
    format!(
        "{}:",
        framework
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
    )
}

impl ComplianceApi {
    async fn run(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
        action: &str,
        resource_id: &str,
        mutation: Mutation<'_>,
    ) -> IamResult<Value> {
        self.ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                action,
                resource_id,
                mutation,
                false,
            )
            .await
    }

    /// `compliance/adoptFramework`: adopts a framework: one control per check its requirements use. A control already
    /// running that check (the one keyed by the check's ID first, else the first by key) gains the framework's mappings
    /// instead. Returns the controls it created or extended.
    pub async fn adopt_framework(
        &self,
        credential: &CredentialInput,
        input: Body<compliance::AdoptFrameworkInput>,
    ) -> IamResult<Reply<compliance::AdoptFrameworkOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let framework = framework_by_id(&text(body.get("framework"), "framework", 32)?)
                        .ok_or_else(|| {
                            invalid(format!(
                                "framework must be one of {}",
                                compliance_frameworks()
                                    .iter()
                                    .map(|item| item
                                        .get("id")
                                        .and_then(Value::as_str)
                                        .unwrap_or_default())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ))
                        })?;
                    let framework_id = framework
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    let now = ctx.now();
                    let mut controls =
                        find(&tx, "complianceControls", by_tenant(&tenant.id)).await?;
                    controls.sort_by(by_key);
                    let mut touched: Vec<Record> = Vec::new();
                    let mut by_check: IndexMap<String, Vec<String>> = IndexMap::new();
                    for requirement in framework
                        .get("requirements")
                        .and_then(Value::as_array)
                        .map(Vec::as_slice)
                        .unwrap_or_default()
                    {
                        let requirement_id = requirement
                            .get("id")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        for check_id in requirement
                            .get("checks")
                            .and_then(Value::as_array)
                            .map(Vec::as_slice)
                            .unwrap_or_default()
                        {
                            by_check
                                .entry(check_id.as_str().unwrap_or_default().to_owned())
                                .or_default()
                                .push(format!("{framework_id}:{requirement_id}"));
                        }
                    }
                    for (check_id, mut refs) in by_check {
                        let check = check_by_id(&check_id).ok_or_else(crate::js::internal_error)?;
                        let existing = controls
                            .iter()
                            .find(|control| s(control, "key") == check_id)
                            .or_else(|| {
                                controls
                                    .iter()
                                    .find(|control| s(control, "checkId") == check_id)
                            });
                        if let Some(existing) = existing {
                            let mut merged: IndexSet<String> = IndexSet::new();
                            if let Some(Value::Array(items)) = existing.get("mappings") {
                                for item in items {
                                    merged.insert(crate::js::js_string(Some(item)));
                                }
                            }
                            for item in &refs {
                                merged.insert(item.clone());
                            }
                            let mut merged: Vec<String> = merged.into_iter().collect();
                            crate::js::sort_strings(&mut merged);
                            let mut updated = existing.clone();
                            updated.insert(
                                "mappings".into(),
                                Value::Array(merged.into_iter().map(Value::String).collect()),
                            );
                            updated.insert("updatedAt".into(), crate::js::number(now));
                            touched.push(tx.put("complianceControls", &updated).await?);
                            continue;
                        }
                        if controls.len() + touched.len() >= MAX_CONTROLS {
                            return Err(IamError::with_status(
                                "LIMIT_EXCEEDED",
                                format!("At most {MAX_CONTROLS} controls"),
                                409,
                            )
                            .into());
                        }
                        if controls.iter().any(|control| s(control, "key") == check_id) {
                            return Err(IamError::with_status(
                                "CONFLICT",
                                format!("A control keyed {check_id} runs another check"),
                                409,
                            )
                            .into());
                        }
                        crate::js::sort_strings(&mut refs);
                        let mut control = Record::new();
                        control.insert("id".into(), Value::String(id()));
                        control.insert("tenantId".into(), Value::String(tenant.id.clone()));
                        control
                            .insert("uniqueKey".into(), Value::String(format!("key:{check_id}")));
                        control.insert("key".into(), Value::String(check_id.clone()));
                        control.insert("name".into(), Value::String(check.title.to_owned()));
                        control.insert(
                            "description".into(),
                            Value::String(check.description.to_owned()),
                        );
                        control.insert("checkId".into(), Value::String(check_id.clone()));
                        control.insert(
                            "params".into(),
                            Value::Object(params_json(&check_params(check, None)?)),
                        );
                        control.insert(
                            "mappings".into(),
                            Value::Array(refs.into_iter().map(Value::String).collect()),
                        );
                        control.insert("enabled".into(), Value::Bool(true));
                        control.insert("createdAt".into(), crate::js::number(now));
                        control.insert("updatedAt".into(), crate::js::number(now));
                        touched.push(tx.insert("complianceControls", &control).await?);
                    }
                    let mut metadata = Map::new();
                    metadata.insert("framework".into(), Value::String(framework_id.to_owned()));
                    metadata.insert(
                        "controls".into(),
                        Value::Array(
                            touched
                                .iter()
                                .map(|control| control.get("key").cloned().unwrap_or(Value::Null))
                                .collect(),
                        ),
                    );
                    audit(
                        ctx,
                        &tx,
                        &principal,
                        "compliance:framework:adopt",
                        &tenant.id,
                        &tenant.id,
                        metadata,
                    )
                    .await?;
                    Ok(json!({
                        "framework": framework_id,
                        "controls": touched.into_iter().map(Value::Object).collect::<Vec<_>>(),
                    }))
                })
            },
        );
        let result = self
            .run(
                credential,
                &input,
                "iam:compliance:manage",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `compliance/approveException`: approves a pending exception: someone other than its author, and not the subject
    /// of the finding.
    pub async fn approve_exception(
        &self,
        credential: &CredentialInput,
        input: Body<compliance::ApproveExceptionInput>,
    ) -> IamResult<Reply<compliance::ApproveExceptionOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let resource = text(input.get("exceptionId"), "exceptionId", 256)?;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let mut exception = ctx
                        .scoped(
                            &tx,
                            "complianceExceptions",
                            body.get("exceptionId"),
                            &tenant.id,
                        )
                        .await?;
                    if exception_status(&exception).as_str() != Some("pending") {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "The exception is not pending",
                            409,
                        )
                        .into());
                    }
                    if num(&exception, "expiresAt").is_some_and(|expires| expires <= ctx.now()) {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "The exception has expired",
                            409,
                        )
                        .into());
                    }
                    let me = principal.identity.id.as_str();
                    if exception.get("createdBy").and_then(Value::as_str) == Some(me) {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "A second person approves an exception",
                            403,
                        )
                        .into());
                    }
                    if names_identity(s(&exception, "subject"), me) {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "An exception for your own finding needs someone else",
                            403,
                        )
                        .into());
                    }
                    let original = exception.clone();
                    exception.insert("status".into(), Value::String("approved".into()));
                    exception.insert("approvedBy".into(), Value::String(me.to_owned()));
                    exception.insert("approvedAt".into(), crate::js::number(ctx.now()));
                    let approved = tx.put("complianceExceptions", &exception).await?;
                    let mut metadata = Map::new();
                    for key in ["controlKey", "subject", "createdBy", "expiresAt"] {
                        if let Some(value) = original.get(key) {
                            metadata.insert(key.into(), value.clone());
                        }
                    }
                    audit(
                        ctx,
                        &tx,
                        &principal,
                        "compliance:exception:approve",
                        &tenant.id,
                        s(&original, "id"),
                        metadata,
                    )
                    .await?;
                    Ok(Value::Object(approved))
                })
            },
        );
        let result = self
            .run(
                credential,
                &input,
                "iam:compliance:manage",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `compliance/catalog`: the built-in checks (with their parameters) and framework mappings.
    pub async fn catalog(
        &self,
        credential: &CredentialInput,
        input: Body<compliance::CatalogInput>,
    ) -> IamResult<Reply<compliance::CatalogOutput>> {
        let mutation: Mutation<'_> = Box::new(|_| {
            Box::pin(async move {
                let checks: Vec<Value> = compliance_checks()
                    .iter()
                    .map(|check| {
                        let mut out = Map::new();
                        out.insert("id".into(), Value::String(check.id.to_owned()));
                        out.insert("title".into(), Value::String(check.title.to_owned()));
                        out.insert(
                            "description".into(),
                            Value::String(check.description.to_owned()),
                        );
                        out.insert(
                            "params".into(),
                            Value::Array(
                                check.params.iter().map(|param| param.to_json()).collect(),
                            ),
                        );
                        if check.no_exceptions {
                            out.insert("noExceptions".into(), Value::Bool(true));
                        }
                        Value::Object(out)
                    })
                    .collect();
                Ok(json!({ "checks": checks, "frameworks": compliance_frameworks() }))
            })
        });
        let result = self
            .run(
                credential,
                &input,
                "iam:compliance:read",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `compliance/createControl`.
    pub async fn create_control(
        &self,
        credential: &CredentialInput,
        input: Body<compliance::CreateControlInput>,
    ) -> IamResult<Reply<compliance::CreateControlOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let key = control_key(body.get("key"))?;
                    let check = check_by_id(&text(body.get("checkId"), "checkId", 64)?)
                        .ok_or_else(|| {
                            invalid(format!(
                                "Unknown check {}",
                                crate::js::js_string(body.get("checkId"))
                            ))
                        })?;
                    let controls = find(&tx, "complianceControls", by_tenant(&tenant.id)).await?;
                    if controls.iter().any(|control| s(control, "key") == key) {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "A control with this key exists",
                            409,
                        )
                        .into());
                    }
                    if controls.len() >= MAX_CONTROLS {
                        return Err(IamError::with_status(
                            "LIMIT_EXCEEDED",
                            format!("At most {MAX_CONTROLS} controls"),
                            409,
                        )
                        .into());
                    }
                    let enabled = body.get("enabled");
                    if enabled.is_some_and(|enabled| !enabled.is_boolean()) {
                        return Err(invalid("enabled must be a boolean").into());
                    }
                    let now = ctx.now();
                    let mut control = Record::new();
                    control.insert("id".into(), Value::String(id()));
                    control.insert("tenantId".into(), Value::String(tenant.id.clone()));
                    control.insert("uniqueKey".into(), Value::String(format!("key:{key}")));
                    control.insert("key".into(), Value::String(key.clone()));
                    control.insert(
                        "name".into(),
                        Value::String(
                            core_js::trim(&text(body.get("name"), "name", 120)?).to_owned(),
                        ),
                    );
                    if crate::js::truthy(body.get("description")) {
                        control.insert(
                            "description".into(),
                            Value::String(text(body.get("description"), "description", 1000)?),
                        );
                    }
                    control.insert("checkId".into(), Value::String(check.id.to_owned()));
                    control.insert(
                        "params".into(),
                        Value::Object(params_json(&check_params(check, body.get("params"))?)),
                    );
                    control.insert(
                        "mappings".into(),
                        Value::Array(
                            mappings(body.get("mappings"))?
                                .into_iter()
                                .map(Value::String)
                                .collect(),
                        ),
                    );
                    control.insert(
                        "enabled".into(),
                        enabled.cloned().unwrap_or(Value::Bool(true)),
                    );
                    control.insert("createdAt".into(), crate::js::number(now));
                    control.insert("updatedAt".into(), crate::js::number(now));
                    let control = tx.insert("complianceControls", &control).await?;
                    let mut metadata = Map::new();
                    metadata.insert("key".into(), Value::String(key));
                    metadata.insert("checkId".into(), Value::String(check.id.to_owned()));
                    if let Value::Object(state) = control_state(&control) {
                        metadata.extend(state);
                    }
                    audit(
                        ctx,
                        &tx,
                        &principal,
                        "compliance:control:create",
                        &tenant.id,
                        s(&control, "id"),
                        metadata,
                    )
                    .await?;
                    Ok(Value::Object(control))
                })
            },
        );
        let result = self
            .run(
                credential,
                &input,
                "iam:compliance:manage",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `compliance/createException`: proposes accepting a finding for a while (a compensating control, a planned fix).
    /// It covers the finding only once a second person approves it (`approveException`), until `expiresAt` (at most a
    /// year). Nobody may propose or approve an exception for a finding about themselves, and audit-integrity findings
    /// cannot be excepted.
    pub async fn create_exception(
        &self,
        credential: &CredentialInput,
        input: Body<compliance::CreateExceptionInput>,
    ) -> IamResult<Reply<compliance::CreateExceptionOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let key = control_key(body.get("controlKey"))?;
                    let control = find(
                        &tx,
                        "complianceControls",
                        by_tenant(&tenant.id).eq("key", key.clone()),
                    )
                    .await?
                    .into_iter()
                    .next()
                    .ok_or_else(|| IamError::with_status("NOT_FOUND", "Control not found", 404))?;
                    if check_by_id(s(&control, "checkId")).is_some_and(|check| check.no_exceptions)
                    {
                        return Err(invalid(format!(
                            "Findings of {} cannot be excepted",
                            crate::js::js_string(control.get("checkId"))
                        ))
                        .into());
                    }
                    let subject = text(body.get("subject"), "subject", 300)?;
                    if names_identity(&subject, &principal.identity.id) {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "An exception for your own finding needs someone else",
                            403,
                        )
                        .into());
                    }
                    let now = ctx.now();
                    let expires_at = integer(
                        body.get("expiresAt"),
                        "expiresAt",
                        now + 60_000.0,
                        now + 366.0 * 86_400_000.0,
                    )?;
                    let mut exception = Record::new();
                    exception.insert("id".into(), Value::String(id()));
                    exception.insert("tenantId".into(), Value::String(tenant.id.clone()));
                    exception.insert("controlKey".into(), Value::String(key.clone()));
                    exception.insert("subject".into(), Value::String(subject.clone()));
                    exception.insert(
                        "reason".into(),
                        Value::String(text(body.get("reason"), "reason", 1000)?),
                    );
                    exception.insert("expiresAt".into(), crate::js::number(expires_at));
                    exception.insert(
                        "createdBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    exception.insert("createdAt".into(), crate::js::number(now));
                    exception.insert("status".into(), Value::String("pending".into()));
                    tx.insert("complianceExceptions", &exception).await?;
                    let mut metadata = Map::new();
                    metadata.insert("controlKey".into(), Value::String(key));
                    metadata.insert("subject".into(), Value::String(subject));
                    metadata.insert("expiresAt".into(), crate::js::number(expires_at));
                    metadata.insert("status".into(), Value::String("pending".into()));
                    audit(
                        ctx,
                        &tx,
                        &principal,
                        "compliance:exception",
                        &tenant.id,
                        s(&exception, "id"),
                        metadata,
                    )
                    .await?;
                    Ok(Value::Object(exception))
                })
            },
        );
        let result = self
            .run(
                credential,
                &input,
                "iam:compliance:manage",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `compliance/deleteControl`: deletes a control; its exceptions end (kept as revoked history) and its past
    /// results stay until they expire.
    pub async fn delete_control(
        &self,
        credential: &CredentialInput,
        input: Body<compliance::DeleteControlInput>,
    ) -> IamResult<Reply<compliance::DeleteControlOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let resource = text(input.get("controlId"), "controlId", 256)?;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let control = ctx
                        .scoped(&tx, "complianceControls", body.get("controlId"), &tenant.id)
                        .await?;
                    let now = ctx.now();
                    for mut exception in find(
                        &tx,
                        "complianceExceptions",
                        by_tenant(&tenant.id).eq(
                            "controlKey",
                            control.get("key").cloned().unwrap_or(Value::Null),
                        ),
                    )
                    .await?
                    {
                        if exception_status(&exception).as_str() != Some("revoked") {
                            exception.insert("status".into(), Value::String("revoked".into()));
                            exception.insert(
                                "revokedBy".into(),
                                Value::String(principal.identity.id.clone()),
                            );
                            exception.insert("revokedAt".into(), crate::js::number(now));
                            tx.put("complianceExceptions", &exception).await?;
                        }
                    }
                    tx.delete("complianceControls", s(&control, "id")).await?;
                    let mut metadata = Map::new();
                    metadata.insert(
                        "key".into(),
                        control.get("key").cloned().unwrap_or(Value::Null),
                    );
                    metadata.insert(
                        "checkId".into(),
                        control.get("checkId").cloned().unwrap_or(Value::Null),
                    );
                    metadata.insert("before".into(), control_state(&control));
                    audit(
                        ctx,
                        &tx,
                        &principal,
                        "compliance:control:delete",
                        &tenant.id,
                        s(&control, "id"),
                        metadata,
                    )
                    .await?;
                    Ok(json!({ "deleted": true }))
                })
            },
        );
        let result = self
            .run(
                credential,
                &input,
                "iam:compliance:manage",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `compliance/evaluate`: runs the enabled controls (or `controlKeys`) now, at most once a minute per tenant.
    /// Audited as `compliance:evaluate` with the run's digest. Returns the run and each control's status and counts;
    /// the findings are read with `listResults` (which needs `iam:compliance:read`).
    pub async fn evaluate(
        &self,
        credential: &CredentialInput,
        input: Body<compliance::EvaluateInput>,
    ) -> IamResult<Reply<compliance::EvaluateOutput>> {
        let keys = match input.get("controlKeys") {
            None => None,
            Some(value) => Some(strings(Some(value), "controlKeys")?),
        };
        let mutation: Mutation<'_> = Box::new(|MutationContext { principal, .. }| {
            Box::pin(async move { Ok(Value::String(principal.identity.id.clone())) })
        });
        let caller = self
            .run(
                credential,
                &input,
                "iam:compliance:evaluate",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        let caller = crate::js::js_string(Some(&caller));
        let (run, results) = evaluate_compliance(
            &self.ctx,
            &text(input.get("tenantId"), "tenantId", 256)?,
            &caller,
            keys.as_deref(),
            Some(MANUAL_INTERVAL_MS),
        )
        .await?;
        let results: Vec<Value> = results
            .iter()
            .map(|result| {
                let mut out = Map::new();
                for key in [
                    "controlKey",
                    "checkId",
                    "status",
                    "rawStatus",
                    "summary",
                    "findingsTotal",
                    "excepted",
                ] {
                    if let Some(value) = result.get(key) {
                        out.insert(key.into(), value.clone());
                    }
                }
                Value::Object(out)
            })
            .collect();
        Ok(Reply::json(json!({ "run": run, "results": results })))
    }

    /// `compliance/evidenceKeys`: the public keys evidence packs are signed with (JWKS; the current key first), for
    /// auditors' offline checks.
    pub async fn evidence_keys(
        &self,
        credential: &CredentialInput,
        input: Body<compliance::EvidenceKeysInput>,
    ) -> IamResult<Reply<compliance::EvidenceKeysOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(|_| {
            Box::pin(async move {
                let keys: Vec<Value> = secrets(ctx)
                    .iter()
                    .map(|secret| evidence_key(secret).jwk.clone())
                    .collect();
                Ok(json!({ "keys": keys }))
            })
        });
        let result = self
            .run(
                credential,
                &input,
                "iam:compliance:read",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `compliance/exportEvidence`: an evidence pack for auditors: the controls (of one framework, or all; disabled
    /// ones included and marked), their latest results with findings (stale ones marked), every exception with its
    /// history, recent runs, and the audit chain head. Signed with the deployment's Ed25519 evidence key; the pack's
    /// digest is recorded in the audit chain (`compliance:evidence-export`). Findings name people only when the caller
    /// may read the directory.
    pub async fn export_evidence(
        &self,
        credential: &CredentialInput,
        input: Body<compliance::ExportEvidenceInput>,
    ) -> IamResult<Reply<compliance::ExportEvidenceOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let framework = selected_framework(body)?;
                    let now = ctx.now();
                    let mut controls: Vec<Record> =
                        find(&tx, "complianceControls", by_tenant(&tenant.id))
                            .await?
                            .into_iter()
                            .filter(|control| {
                                framework.is_none_or(|framework| {
                                    mapping_prefix(control, &framework_ref(framework))
                                })
                            })
                            .collect();
                    controls.sort_by(by_key);
                    let latest = latest_results(&tx, &tenant.id, &controls).await?;
                    let shown: IndexMap<String, Record> = views(
                        ctx,
                        &tx,
                        &principal,
                        &tenant.id,
                        latest.into_values().collect(),
                    )
                    .await?
                    .into_iter()
                    .map(|result| (crate::js::js_string(result.get("controlKey")), result))
                    .collect();
                    let keys: IndexSet<String> = controls
                        .iter()
                        .map(|control| crate::js::js_string(control.get("key")))
                        .collect();
                    let head = tx.get("auditChains", &tenant.id).await?;
                    let mut pack = Map::new();
                    pack.insert(
                        "format".into(),
                        Value::String("better-iam.compliance-evidence".into()),
                    );
                    pack.insert("version".into(), json!(2));
                    pack.insert(
                        "generatedAt".into(),
                        Value::String(
                            core_js::iso_string(now).ok_or_else(crate::js::internal_error)?,
                        ),
                    );
                    pack.insert(
                        "tenant".into(),
                        json!({ "id": tenant.id, "name": tenant.name }),
                    );
                    if let Some(framework) = framework {
                        pack.insert(
                            "framework".into(),
                            json!({
                                "id": framework.get("id").cloned().unwrap_or(Value::Null),
                                "name": framework.get("name").cloned().unwrap_or(Value::Null),
                            }),
                        );
                    }
                    let pack_controls: Vec<Value> = controls
                        .iter()
                        .map(|control| {
                            let mut out = Map::new();
                            for key in ["key", "name", "checkId", "params", "mappings", "enabled"] {
                                if let Some(value) = control.get(key) {
                                    out.insert(key.into(), value.clone());
                                }
                            }
                            if let Some(result) =
                                shown.get(&crate::js::js_string(control.get("key")))
                            {
                                let mut view = Map::new();
                                for key in [
                                    "runId",
                                    "status",
                                    "rawStatus",
                                    "summary",
                                    "metrics",
                                    "findings",
                                    "findingsTotal",
                                    "excepted",
                                    "evaluatedAt",
                                    "stale",
                                ] {
                                    if let Some(value) = result.get(key) {
                                        view.insert(key.into(), value.clone());
                                    }
                                }
                                out.insert("result".into(), Value::Object(view));
                            }
                            Value::Object(out)
                        })
                        .collect();
                    pack.insert("controls".into(), Value::Array(pack_controls));
                    let mut exceptions: Vec<Record> =
                        find(&tx, "complianceExceptions", by_tenant(&tenant.id))
                            .await?
                            .into_iter()
                            .filter(|exception| {
                                keys.contains(&crate::js::js_string(exception.get("controlKey")))
                            })
                            .collect();
                    exceptions.sort_by(|a, b| oldest(a, b, "createdAt"));
                    let exceptions: Vec<Value> = exceptions
                        .iter()
                        .map(|exception| {
                            let mut out = Map::new();
                            for key in [
                                "controlKey",
                                "subject",
                                "reason",
                                "expiresAt",
                                "createdBy",
                                "createdAt",
                            ] {
                                if let Some(value) = exception.get(key) {
                                    out.insert(key.into(), value.clone());
                                }
                            }
                            out.insert("status".into(), exception_status(exception));
                            for (by, at) in
                                [("approvedBy", "approvedAt"), ("revokedBy", "revokedAt")]
                            {
                                if crate::js::truthy(exception.get(by)) {
                                    out.insert(
                                        by.into(),
                                        exception.get(by).cloned().unwrap_or(Value::Null),
                                    );
                                    if let Some(value) = exception.get(at) {
                                        out.insert(at.into(), value.clone());
                                    }
                                }
                            }
                            Value::Object(out)
                        })
                        .collect();
                    pack.insert("exceptions".into(), Value::Array(exceptions));
                    let mut runs = find(&tx, "complianceRuns", by_tenant(&tenant.id)).await?;
                    runs.sort_by(|a, b| newest(a, b, "evaluatedAt"));
                    let runs: Vec<Value> = runs
                        .iter()
                        .take(30)
                        .map(|run| {
                            let mut out = Map::new();
                            for key in ["id", "evaluatedAt", "counts", "digest"] {
                                if let Some(value) = run.get(key) {
                                    out.insert(key.into(), value.clone());
                                }
                            }
                            Value::Object(out)
                        })
                        .collect();
                    pack.insert("runs".into(), Value::Array(runs));
                    if let Some(head) = &head {
                        let mut out = Map::new();
                        for key in ["sequence", "hash"] {
                            if let Some(value) = head.get(key) {
                                out.insert(key.into(), value.clone());
                            }
                        }
                        pack.insert("auditHead".into(), Value::Object(out));
                    }
                    let digest = pack_digest(&Value::Object(pack.clone()));
                    let key = evidence_key(&ctx.options.secret);
                    let mut metadata = Map::new();
                    if let Some(framework) = framework {
                        metadata.insert(
                            "framework".into(),
                            framework.get("id").cloned().unwrap_or(Value::Null),
                        );
                    }
                    metadata.insert("controls".into(), crate::js::number(controls.len() as f64));
                    metadata.insert("digest".into(), Value::String(digest.clone()));
                    metadata.insert("kid".into(), Value::String(key.kid.clone()));
                    audit(
                        ctx,
                        &tx,
                        &principal,
                        "compliance:evidence-export",
                        &tenant.id,
                        &tenant.id,
                        metadata,
                    )
                    .await?;
                    let signature = base64url(key.signing.sign(digest.as_bytes()).to_bytes());
                    pack.insert("digest".into(), Value::String(digest));
                    pack.insert(
                        "signature".into(),
                        json!({ "alg": "EdDSA", "kid": key.kid, "value": signature }),
                    );
                    Ok(Value::Object(pack))
                })
            },
        );
        let result = self
            .run(
                credential,
                &input,
                "iam:compliance:read",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `compliance/listControls`.
    pub async fn list_controls(
        &self,
        credential: &CredentialInput,
        input: Body<compliance::ListControlsInput>,
    ) -> IamResult<Reply<compliance::ListControlsOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let mut controls =
                        find(&tx, "complianceControls", by_tenant(&tenant.id)).await?;
                    controls.sort_by(|a, b| {
                        crate::metrics::locale_compare(
                            &crate::js::js_string(a.get("name")),
                            &crate::js::js_string(b.get("name")),
                        )
                    });
                    let latest = latest_results(&tx, &tenant.id, &controls).await?;
                    let shown = views(
                        ctx,
                        &tx,
                        &principal,
                        &tenant.id,
                        latest.into_values().collect(),
                    )
                    .await?;
                    let by_key: IndexMap<String, Record> = shown
                        .into_iter()
                        .map(|result| (crate::js::js_string(result.get("controlKey")), result))
                        .collect();
                    Ok(Value::Array(
                        controls
                            .into_iter()
                            .map(|mut control| {
                                if let Some(latest) =
                                    by_key.get(&crate::js::js_string(control.get("key")))
                                {
                                    control.insert("latest".into(), Value::Object(latest.clone()));
                                } else {
                                    control.shift_remove("latest");
                                }
                                Value::Object(control)
                            })
                            .collect(),
                    ))
                })
            },
        );
        let result = self
            .run(
                credential,
                &input,
                "iam:compliance:read",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `compliance/listExceptions`: every exception with its status; `active` ones cover findings now. Records are
    /// kept 400 days after expiry.
    pub async fn list_exceptions(
        &self,
        credential: &CredentialInput,
        input: Body<compliance::ListExceptionsInput>,
    ) -> IamResult<Reply<compliance::ListExceptionsOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let now = ctx.now();
                let mut exceptions: Vec<Record> =
                    find(&tx, "complianceExceptions", by_tenant(&tenant.id))
                        .await?
                        .into_iter()
                        .map(|mut exception| {
                            let status = exception_status(&exception);
                            let active = exception_active(&exception, now);
                            exception.insert("status".into(), status);
                            exception.insert("active".into(), Value::Bool(active));
                            exception
                        })
                        .collect();
                exceptions.sort_by(|a, b| oldest(a, b, "expiresAt"));
                Ok(Value::Array(
                    exceptions.into_iter().map(Value::Object).collect(),
                ))
            })
        });
        let result = self
            .run(
                credential,
                &input,
                "iam:compliance:read",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `compliance/listResults`: results, newest first: of one control (its history), of one run, or the latest of
    /// every control.
    pub async fn list_results(
        &self,
        credential: &CredentialInput,
        input: Body<compliance::ListResultsInput>,
    ) -> IamResult<Reply<compliance::ListResultsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let limit = integer(
                        Some(default_when_nullish(body.get("limit"), 100.0).as_ref()),
                        "limit",
                        1.0,
                        1000.0,
                    )?;
                    if body.get("controlKey").is_none() && body.get("runId").is_none() {
                        let controls =
                            find(&tx, "complianceControls", by_tenant(&tenant.id)).await?;
                        let mut latest: Vec<Record> = latest_results(&tx, &tenant.id, &controls)
                            .await?
                            .into_values()
                            .collect();
                        latest.sort_by(|a, b| cmp_utf16(s(a, "controlKey"), s(b, "controlKey")));
                        let shown = views(ctx, &tx, &principal, &tenant.id, latest).await?;
                        return Ok(Value::Array(shown.into_iter().map(Value::Object).collect()));
                    }
                    let mut filter = by_tenant(&tenant.id);
                    if let Some(value) = body.get("controlKey") {
                        filter = filter.eq("controlKey", text(Some(value), "controlKey", 64)?);
                    }
                    if let Some(value) = body.get("runId") {
                        filter = filter.eq("runId", text(Some(value), "runId", 256)?);
                    }
                    let mut results = find(&tx, "complianceResults", filter).await?;
                    results.sort_by(|a, b| match newest(a, b, "evaluatedAt") {
                        Ordering::Equal => cmp_utf16(s(a, "controlKey"), s(b, "controlKey")),
                        other => other,
                    });
                    results.truncate(limit as usize);
                    let shown = views(ctx, &tx, &principal, &tenant.id, results).await?;
                    Ok(Value::Array(shown.into_iter().map(Value::Object).collect()))
                })
            },
        );
        let result = self
            .run(
                credential,
                &input,
                "iam:compliance:read",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `compliance/listRuns`.
    pub async fn list_runs(
        &self,
        credential: &CredentialInput,
        input: Body<compliance::ListRunsInput>,
    ) -> IamResult<Reply<compliance::ListRunsOutput>> {
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let mut runs = find(&tx, "complianceRuns", by_tenant(&tenant.id)).await?;
                runs.sort_by(|a, b| newest(a, b, "evaluatedAt"));
                let limit = integer(
                    Some(default_when_nullish(body.get("limit"), 30.0).as_ref()),
                    "limit",
                    1.0,
                    500.0,
                )?;
                runs.truncate(limit as usize);
                Ok(Value::Array(runs.into_iter().map(Value::Object).collect()))
            })
        });
        let result = self
            .run(
                credential,
                &input,
                "iam:compliance:read",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `compliance/revokeException`: ends an exception (or withdraws a pending one); the record stays as history.
    pub async fn revoke_exception(
        &self,
        credential: &CredentialInput,
        input: Body<compliance::RevokeExceptionInput>,
    ) -> IamResult<Reply<compliance::RevokeExceptionOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let resource = text(input.get("exceptionId"), "exceptionId", 256)?;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let mut exception = ctx
                        .scoped(
                            &tx,
                            "complianceExceptions",
                            body.get("exceptionId"),
                            &tenant.id,
                        )
                        .await?;
                    if exception_status(&exception).as_str() == Some("revoked") {
                        return Ok(json!({ "revoked": true }));
                    }
                    let mut metadata = Map::new();
                    for key in ["controlKey", "subject"] {
                        if let Some(value) = exception.get(key) {
                            metadata.insert(key.into(), value.clone());
                        }
                    }
                    let exception_id = s(&exception, "id").to_owned();
                    exception.insert("status".into(), Value::String("revoked".into()));
                    exception.insert(
                        "revokedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    exception.insert("revokedAt".into(), crate::js::number(ctx.now()));
                    tx.put("complianceExceptions", &exception).await?;
                    audit(
                        ctx,
                        &tx,
                        &principal,
                        "compliance:exception:revoke",
                        &tenant.id,
                        &exception_id,
                        metadata,
                    )
                    .await?;
                    Ok(json!({ "revoked": true }))
                })
            },
        );
        let result = self
            .run(
                credential,
                &input,
                "iam:compliance:manage",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `compliance/status`: each framework's requirements with the latest status of the controls that evidence them.
    pub async fn status(
        &self,
        credential: &CredentialInput,
        input: Body<compliance::StatusInput>,
    ) -> IamResult<Reply<compliance::StatusOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let selected = selected_framework(body)?;
                let controls = find(&tx, "complianceControls", by_tenant(&tenant.id)).await?;
                let latest = latest_results(&tx, &tenant.id, &controls).await?;
                let now = ctx.now();
                let frameworks: Vec<&Value> = match selected {
                    Some(framework) => vec![framework],
                    None => compliance_frameworks()
                        .iter()
                        .filter(|framework| {
                            let prefix = framework_ref(framework);
                            controls
                                .iter()
                                .any(|control| mapping_prefix(control, &prefix))
                        })
                        .collect(),
                };
                let statuses: Vec<Value> = frameworks
                    .into_iter()
                    .map(|framework| framework_status(framework, &controls, &latest, now))
                    .collect();
                Ok(Value::Array(statuses))
            })
        });
        let result = self
            .run(
                credential,
                &input,
                "iam:compliance:read",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `compliance/updateControl`: changes a control; audited as `compliance:control:update` with its state before
    /// and after.
    pub async fn update_control(
        &self,
        credential: &CredentialInput,
        input: Body<compliance::UpdateControlInput>,
    ) -> IamResult<Reply<compliance::UpdateControlOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let resource = text(input.get("controlId"), "controlId", 256)?;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let control = ctx
                        .scoped(&tx, "complianceControls", body.get("controlId"), &tenant.id)
                        .await?;
                    let check = check_by_id(s(&control, "checkId"));
                    let enabled = body.get("enabled");
                    if enabled.is_some_and(|enabled| !enabled.is_boolean()) {
                        return Err(invalid("enabled must be a boolean").into());
                    }
                    let mut updated = control.clone();
                    if let Some(name) = body.get("name") {
                        updated.insert(
                            "name".into(),
                            Value::String(
                                core_js::trim(&text(Some(name), "name", 120)?).to_owned(),
                            ),
                        );
                    }
                    if let Some(description) = body.get("description") {
                        updated.insert(
                            "description".into(),
                            Value::String(text(Some(description), "description", 1000)?),
                        );
                    }
                    if let Some(params) = body.get("params") {
                        // `checkById.get(control.checkId)!`: a control of an unknown check cannot take parameters.
                        let check = check.ok_or_else(|| {
                            crate::js::ThrownError::type_error(
                                "Cannot read properties of undefined (reading 'params')",
                            )
                            .into_iam()
                        })?;
                        updated.insert(
                            "params".into(),
                            Value::Object(params_json(&check_params(check, Some(params))?)),
                        );
                    }
                    if let Some(value) = body.get("mappings") {
                        updated.insert(
                            "mappings".into(),
                            Value::Array(
                                mappings(Some(value))?
                                    .into_iter()
                                    .map(Value::String)
                                    .collect(),
                            ),
                        );
                    }
                    if let Some(enabled) = enabled {
                        updated.insert("enabled".into(), enabled.clone());
                    }
                    updated.insert("updatedAt".into(), crate::js::number(ctx.now()));
                    let updated = tx.put("complianceControls", &updated).await?;
                    let mut metadata = Map::new();
                    metadata.insert(
                        "key".into(),
                        control.get("key").cloned().unwrap_or(Value::Null),
                    );
                    metadata.insert("before".into(), control_state(&control));
                    metadata.insert("after".into(), control_state(&updated));
                    audit(
                        ctx,
                        &tx,
                        &principal,
                        "compliance:control:update",
                        &tenant.id,
                        s(&control, "id"),
                        metadata,
                    )
                    .await?;
                    Ok(Value::Object(updated))
                })
            },
        );
        let result = self
            .run(
                credential,
                &input,
                "iam:compliance:manage",
                &resource,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `compliance/verifyEvidence`: whether an evidence pack is unaltered and was signed by this deployment (current or
    /// previous secret). Pass the `pack`, or only its `digest` and `signature` when the pack is too large to send.
    pub async fn verify_evidence(
        &self,
        credential: &CredentialInput,
        input: Body<compliance::VerifyEvidenceInput>,
    ) -> IamResult<Reply<compliance::VerifyEvidenceOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tenant, .. }| {
            Box::pin(async move {
                let secrets = secrets(ctx);
                let jwks: Vec<Value> = secrets
                    .iter()
                    .map(|secret| evidence_key(secret).jwk.clone())
                    .collect();
                let Some(pack) = body.get("pack") else {
                    let digest = text(body.get("digest"), "digest", 100)?;
                    let signature = object(body.get("signature"))?;
                    let key = jwks
                        .iter()
                        .find(|item| same(item.get("kid"), signature.get("kid")));
                    let (Some(key), Some(Value::String(value))) = (key, signature.get("value"))
                    else {
                        return Ok(json!({ "valid": false }));
                    };
                    let valid = key
                        .get("x")
                        .and_then(|x| ed25519_verify(x, &digest, value))
                        .unwrap_or(false);
                    return Ok(json!({ "valid": valid }));
                };
                let pack = object(Some(pack))?;
                let pack_tenant = match pack.get("tenant") {
                    Some(Value::Object(owner)) => owner.get("id"),
                    _ => None,
                };
                if pack_tenant.and_then(Value::as_str) != Some(tenant.id.as_str()) {
                    return Ok(json!({ "valid": false }));
                }
                if pack.get("version").and_then(core_js::as_number) == Some(1.0)
                    && let Some(Value::String(signature)) = pack.get("signature")
                {
                    let mut rest = pack.clone();
                    rest.shift_remove("signature");
                    let rest = Value::Object(rest);
                    return Ok(json!({
                        "valid": secrets
                            .iter()
                            .any(|secret| same_hash(&legacy_signature(secret, &rest), signature)),
                    }));
                }
                let verdict =
                    verify_evidence_pack(&Value::Object(pack.clone()), &Value::Array(jwks));
                Ok(json!({ "valid": verdict.get("valid").cloned().unwrap_or(Value::Bool(false)) }))
            })
        });
        let result = self
            .run(
                credential,
                &input,
                "iam:compliance:read",
                &string_member(&input, "tenantId"),
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// `value ?? fallback`.
fn default_when_nullish(value: Option<&Value>, fallback: f64) -> std::borrow::Cow<'_, Value> {
    match value {
        None | Some(Value::Null) => std::borrow::Cow::Owned(crate::js::number(fallback)),
        Some(value) => std::borrow::Cow::Borrowed(value),
    }
}

/// `[ctx.options.secret, ...(ctx.options.previousSecrets ?? [])]`.
fn secrets(ctx: &ServerContext) -> Vec<String> {
    let mut list = vec![ctx.options.secret.clone()];
    list.extend(ctx.options.previous_secrets.iter().flatten().cloned());
    list
}

/// One framework's requirements with the latest status of the controls that evidence them (`FrameworkStatus`).
fn framework_status(
    framework: &Value,
    controls: &[Record],
    latest: &IndexMap<String, Record>,
    now: f64,
) -> Value {
    let framework_id = framework
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let requirements: Vec<Value> = framework
        .get("requirements")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|requirement| {
            let requirement_id = requirement
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let reference = format!("{framework_id}:{requirement_id}");
            let mut mapped: Vec<&Record> = controls
                .iter()
                .filter(|control| includes(control.get("mappings"), &reference))
                .collect();
            mapped.sort_by(|a, b| by_key(a, b));
            let mut statuses: Vec<Value> = Vec::new();
            let mapped: Vec<Value> = mapped
                .into_iter()
                .map(|control| {
                    let mut out = Map::new();
                    for key in ["key", "name", "enabled"] {
                        if let Some(value) = control.get(key) {
                            out.insert(key.into(), value.clone());
                        }
                    }
                    let result = latest.get(&crate::js::js_string(control.get("key")));
                    let mut stale = false;
                    if let Some(result) = result {
                        if let Some(status) = result.get("status") {
                            out.insert("status".into(), status.clone());
                        }
                        if let Some(at) = result.get("evaluatedAt") {
                            out.insert("evaluatedAt".into(), at.clone());
                        }
                        stale =
                            num(result, "evaluatedAt").is_some_and(|at| at < now - STALE_AFTER_MS);
                        out.insert("stale".into(), Value::Bool(stale));
                    }
                    statuses.push(if !crate::js::truthy(control.get("enabled")) {
                        Value::String("disabled".into())
                    } else {
                        match out.get("status") {
                            None => Value::String("not-evaluated".into()),
                            Some(_) if stale => Value::String("not-evaluated".into()),
                            Some(status) => status.clone(),
                        }
                    });
                    Value::Object(out)
                })
                .collect();
            let status = if mapped.is_empty() {
                Value::String("no-control".into())
            } else {
                let mut worst = statuses[0].clone();
                for item in &statuses[1..] {
                    let rank = |value: &Value| value.as_str().and_then(severity);
                    if let (Some(item_rank), Some(worst_rank)) = (rank(item), rank(&worst))
                        && item_rank > worst_rank
                    {
                        worst = item.clone();
                    }
                }
                worst
            };
            json!({
                "id": requirement.get("id").cloned().unwrap_or(Value::Null),
                "title": requirement.get("title").cloned().unwrap_or(Value::Null),
                "status": status,
                "controls": mapped,
            })
        })
        .collect();
    let covered: Vec<&Value> = requirements
        .iter()
        .filter(|item| item.get("status").and_then(Value::as_str) != Some("no-control"))
        .collect();
    let passing = covered
        .iter()
        .filter(|item| {
            matches!(
                item.get("status").and_then(Value::as_str),
                Some("pass" | "not-applicable")
            )
        })
        .count();
    json!({
        "framework": {
            "id": framework.get("id").cloned().unwrap_or(Value::Null),
            "name": framework.get("name").cloned().unwrap_or(Value::Null),
        },
        "total": requirements.len(),
        "covered": covered.len(),
        "passing": passing,
        "requirements": requirements,
    })
}

/// Compliance for the deployment's own code (`iam.compliance`): the scheduler job `evaluateAll` (daily).
pub struct ComplianceRuntime {
    ctx: Arc<ServerContext>,
}

/// `createComplianceRuntime(ctx)`.
pub fn create_compliance_runtime(ctx: &Arc<ServerContext>) -> IamResult<ComplianceRuntime> {
    Ok(ComplianceRuntime { ctx: ctx.clone() })
}

impl ComplianceRuntime {
    /// Evaluates every active tenant (or one) that has enabled controls, one after another. A tenant's failure is
    /// reported in `failed` and never stops the others.
    pub async fn evaluate_all(&self, input: Option<&Value>) -> IamResult<Value> {
        let ctx = &self.ctx;
        let tenant_member = match input {
            None => None,
            Some(Value::Null) => {
                return Err(crate::js::ThrownError::type_error(
                    "Cannot read properties of null (reading 'tenantId')",
                )
                .into_iam());
            }
            Some(input) => input.get("tenantId"),
        };
        let filter = match tenant_member {
            None => Filter::new(),
            Some(value) => by_tenant(&text(Some(value), "tenantId", 256)?),
        };
        let controls = find(&ctx.store, "complianceControls", filter).await?;
        let mut tenants: Vec<String> = crate::js::unique(
            controls
                .iter()
                .filter(|control| crate::js::truthy(control.get("enabled")))
                .map(|control| crate::js::js_string(control.get("tenantId"))),
        );
        crate::js::sort_strings(&mut tenants);
        let mut evaluated: Vec<Value> = Vec::new();
        let mut failed: Vec<Value> = Vec::new();
        for tenant_id in tenants {
            let tenant = ctx.store.get("tenants", &tenant_id).await?;
            if tenant
                .as_ref()
                .and_then(|tenant| tenant.get("status"))
                .and_then(Value::as_str)
                != Some("active")
            {
                continue;
            }
            match evaluate_compliance(ctx, &tenant_id, "deployment-operator", None, None).await {
                Ok((run, _)) => evaluated.push(json!({
                    "tenantId": tenant_id,
                    "runId": run.get("id").cloned().unwrap_or(Value::Null),
                    "counts": run.get("counts").cloned().unwrap_or(Value::Null),
                })),
                Err(error) => failed.push(json!({
                    "tenantId": tenant_id,
                    "code": error.code,
                    "message": slice_utf16(&error.message, 300),
                })),
            }
        }
        Ok(json!({ "evaluated": evaluated, "failed": failed }))
    }

    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        match method {
            "evaluateAll" => Some(self.evaluate_all(args.first()).await),
            _ => None,
        }
    }
}
