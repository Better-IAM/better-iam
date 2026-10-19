//! Tamper-evident audit log (`audit.ts`): every tenant's audit events form a hash chain. Each event carries its
//! position (`sequence`), the hash of the previous event (`previousHash`), and its own hash over the canonical JSON of
//! the event body. The chain head per tenant lives in `auditChains`.
//!
//! The functions work on [`Record`]s, so every stored member of an event is covered by its hash, exactly as the
//! TypeScript implementation hashes the stored object.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::js;
use crate::{IamResult, IamStore, Record};

/// The `auditChains` record of a tenant (`AuditChainHead`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditChainHead {
    pub id: String,
    pub tenant_id: String,
    pub sequence: f64,
    pub hash: String,
    pub updated_at: f64,
}

/// Why a chain failed verification (`AuditChainFailure`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuditChainFailure {
    SequenceGap,
    PreviousHashMismatch,
    HashMismatch,
    HeadMismatch,
    /// The whole chain starts after sequence 1 with no `audit:prune` checkpoint in it for the missing events.
    MissingPrefix,
    /// The whole chain holds an event without chain fields: every writer chains, so it was inserted around them.
    Unchained,
}

/// Where verification failed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditChainFailureDetail {
    pub sequence: f64,
    pub id: String,
    pub reason: AuditChainFailure,
}

/// The result of [`verify_audit_chain`] (`AuditChainVerification`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditChainVerification {
    pub valid: bool,
    /// Chained events that were checked.
    pub checked: u64,
    /// Events without chain fields.
    pub unchained: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<AuditChainFailureDetail>,
}

/// The `previousHash` of the first event of every chain (`auditGenesis`).
pub const AUDIT_GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Deterministic JSON (`canonicalJson`): object keys sorted recursively (by UTF-16 code units), arrays kept in order,
/// then written by `JSON.stringify`, which puts integer-like keys first.
pub fn canonical_json(value: &Value) -> String {
    js::stringify(&sorted(value))
}

fn sorted(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|left, right| js::cmp_utf16(left, right));
            Value::Object(
                keys.into_iter()
                    .map(|key| (key.clone(), sorted(&map[key.as_str()])))
                    .collect(),
            )
        }
        other => other.clone(),
    }
}

/// SHA-256 of a string's UTF-8 bytes, lower-case hex.
pub fn sha256_hex(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The hash of an event (`auditEventHash`): SHA-256 over the canonical JSON of every member except `hash` itself.
pub fn audit_event_hash(event: &Record) -> String {
    let body: Map<String, Value> = event
        .iter()
        .filter(|(key, _)| key.as_str() != "hash")
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    sha256_hex(&canonical_json(&Value::Object(body)))
}

/// Assigns the next chain position to an event and advances the tenant's chain head (`chainAuditEvent`). The caller
/// stores the returned event; [`append_audit_event`] does both. Must run inside the transaction that records the
/// event.
pub async fn chain_audit_event(tx: &dyn IamStore, event: &Record) -> IamResult<Record> {
    let tenant_id = event
        .get("tenantId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let head = tx.get("auditChains", &tenant_id).await?;
    let sequence = head
        .as_ref()
        .and_then(|head| head.get("sequence"))
        .and_then(js::as_number)
        .unwrap_or(0.0)
        + 1.0;
    let previous = head
        .as_ref()
        .and_then(|head| head.get("hash"))
        .filter(|hash| !hash.is_null())
        .cloned()
        .unwrap_or_else(|| Value::String(AUDIT_GENESIS.to_owned()));
    let mut chained = event.clone();
    chained.insert(
        "sequence".into(),
        js::number(sequence).unwrap_or(Value::Null),
    );
    chained.insert("previousHash".into(), previous);
    let hash = audit_event_hash(&chained);
    chained.insert("hash".into(), Value::String(hash.clone()));
    let mut next = Map::new();
    next.insert("id".into(), Value::String(tenant_id.clone()));
    next.insert("tenantId".into(), Value::String(tenant_id));
    next.insert(
        "sequence".into(),
        js::number(sequence).unwrap_or(Value::Null),
    );
    next.insert("hash".into(), Value::String(hash));
    if let Some(timestamp) = event.get("timestamp") {
        next.insert("updatedAt".into(), timestamp.clone());
    }
    if head.is_some() {
        tx.put("auditChains", &next).await?;
    } else {
        tx.insert("auditChains", &next).await?;
    }
    Ok(chained)
}

/// Records an audit event at the end of its tenant's chain (`appendAuditEvent`). Every audit insert must go through
/// here.
pub async fn append_audit_event(tx: &dyn IamStore, event: &Record) -> IamResult<Record> {
    let chained = chain_audit_event(tx, event).await?;
    tx.insert("audit", &chained).await?;
    Ok(chained)
}

/// The expected chain head for [`verify_audit_chain`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChainHead {
    pub sequence: f64,
    pub hash: String,
}

/// Options of [`verify_audit_chain`].
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyAuditChainOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<ChainHead>,
}

fn same(left: Option<&Value>, right: Option<&Value>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => js::deep_equal(left, right),
        _ => false,
    }
}

/// Verifies a run of events from one tenant (`verifyAuditChain`): contiguous sequences, each `previousHash` equal to
/// the previous event's hash (or `previousHash` of the first event when the run starts mid-chain), and every hash
/// recomputable. Events are sorted by sequence first.
///
/// With `head`, the events are the tenant's whole stored chain: it must end at the head (even when no event is
/// left), start at sequence 1 or right after an `audit:prune` checkpoint recorded inside it, and hold no unchained
/// events.
pub fn verify_audit_chain(
    events: &[Record],
    options: &VerifyAuditChainOptions,
) -> AuditChainVerification {
    let sequence_of = |event: &Record| event.get("sequence").and_then(js::as_number);
    let id_of = |event: &Record| {
        event
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let mut chained: Vec<&Record> = events
        .iter()
        .filter(|event| sequence_of(event).is_some())
        .collect();
    chained.sort_by(|left, right| {
        sequence_of(left)
            .partial_cmp(&sequence_of(right))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let mut result = AuditChainVerification {
        valid: true,
        checked: 0,
        unchained: (events.len() - chained.len()) as u64,
        first: None,
        last: None,
        last_hash: None,
        failure: None,
    };
    let mut expected_previous: Option<Value> = options.previous_hash.clone().map(Value::String);
    let mut expected_sequence: Option<f64> = None;
    for event in &chained {
        let sequence = sequence_of(event).unwrap_or_default();
        if expected_sequence.is_none() {
            expected_sequence = Some(sequence);
            if expected_previous.is_none() {
                expected_previous = if sequence == 1.0 {
                    Some(Value::String(AUDIT_GENESIS.to_owned()))
                } else {
                    event.get("previousHash").cloned()
                };
            }
            result.first = Some(sequence);
        }
        let fail = |mut result: AuditChainVerification, reason| {
            result.valid = false;
            result.failure = Some(AuditChainFailureDetail {
                sequence,
                id: id_of(event),
                reason,
            });
            result
        };
        if Some(sequence) != expected_sequence {
            return fail(result, AuditChainFailure::SequenceGap);
        }
        if !same(event.get("previousHash"), expected_previous.as_ref()) {
            return fail(result, AuditChainFailure::PreviousHashMismatch);
        }
        let hash = audit_event_hash(event);
        if event.get("hash").and_then(Value::as_str) != Some(hash.as_str()) {
            return fail(result, AuditChainFailure::HashMismatch);
        }
        result.checked += 1;
        result.last = Some(sequence);
        result.last_hash = Some(hash.clone());
        expected_previous = Some(Value::String(hash));
        expected_sequence = Some(sequence + 1.0);
    }
    let Some(head) = &options.head else {
        return result;
    };
    let fail = |mut result: AuditChainVerification, sequence: f64, id: String, reason| {
        result.valid = false;
        result.failure = Some(AuditChainFailureDetail {
            sequence,
            id,
            reason,
        });
        result
    };
    if Some(head.sequence) != result.last || Some(&head.hash) != result.last_hash.as_ref() {
        let sequence = result.last.unwrap_or(head.sequence);
        let id = chained.last().map(|event| id_of(event)).unwrap_or_default();
        return fail(result, sequence, id, AuditChainFailure::HeadMismatch);
    }
    let start = chained[0];
    let start_sequence = sequence_of(start).unwrap_or_default();
    if start_sequence > 1.0
        && !chained.iter().any(|event| {
            let metadata = event.get("metadata").and_then(Value::as_object);
            event.get("action").and_then(Value::as_str) == Some("audit:prune")
                && metadata
                    .and_then(|metadata| metadata.get("prunedThroughSequence"))
                    .and_then(js::as_number)
                    == Some(start_sequence - 1.0)
                && same(
                    metadata.and_then(|metadata| metadata.get("prunedThroughHash")),
                    start.get("previousHash"),
                )
        })
    {
        return fail(
            result,
            start_sequence,
            id_of(start),
            AuditChainFailure::MissingPrefix,
        );
    }
    if let Some(loose) = events.iter().find(|event| sequence_of(event).is_none()) {
        return fail(result, 0.0, id_of(loose), AuditChainFailure::Unchained);
    }
    result
}
