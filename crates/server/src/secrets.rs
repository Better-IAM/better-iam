//! Port of `packages/server/src/secrets.ts`: `rotateSecrets`, which re-seals every value encrypted with a previous
//! deployment secret using the current one, so the previous secret can be retired.
//!
//! Sealed values use the byte-compatible format of `better_iam_auth::crypto` (`encryptSecret` / `openSecret`), so a
//! value one implementation re-sealed opens on the others.

use std::sync::Mutex;

use better_iam_auth::{encrypt_secret, open_secret};
use better_iam_core::{Filter, FindOptions, IamError, IamResult, IamStore, IamStoreExt, Record};
use indexmap::IndexMap;
use serde::Serialize;
use serde_json::Value;

use crate::context::{ServerContext, Store};
use crate::js::{js_string, number_to_string, to_number};

/// `SecretRotationOptions`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SecretRotationOptions {
    /// Report what would change without writing anything.
    pub dry_run: bool,
    /// Records read per transaction (default 200, 1-2000).
    pub batch_size: Option<f64>,
    /// Most records examined per collection (a sample, for `selfCheck`); by default all of them.
    pub limit: Option<f64>,
}

/// `SecretRotationResult`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct SecretRotationResult {
    /// Values re-sealed with the current secret (or, in a dry run, that would be), per collection.
    pub resealed: IndexMap<String, f64>,
    /// Values no configured secret opens, per collection.
    pub unreadable: IndexMap<String, f64>,
    /// Values already sealed with the current secret.
    pub current: f64,
    /// Every record was examined; false when `limit` cut a collection short.
    pub complete: bool,
    /// Nothing sealed with a previous secret remains; only then can `previousSecrets` go.
    pub done: bool,
}

/// A sealed value inside a record: where it lives and the context it was sealed for (`SealedField`).
struct SealedField {
    collection: &'static str,
    /// Only records that still hold a sealed value (pending outbox messages, for example).
    filter: fn() -> Filter,
    read: fn(&Record) -> Option<String>,
    write: fn(&Record, String) -> Record,
    context: fn(&Record) -> String,
}

fn string_member(record: &Record, key: &str) -> Option<String> {
    record.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn with_member(record: &Record, key: &str, sealed: String) -> Record {
    let mut copy = record.clone();
    copy.insert(key.to_owned(), Value::String(sealed));
    copy
}

fn nested(record: &Record, parent: &str, key: &str) -> Option<String> {
    record
        .get(parent)
        .and_then(|value| value.get(key))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// `{ ...record, [parent]: { ...record[parent], [key]: sealed } }`.
fn with_nested(record: &Record, parent: &str, key: &str, sealed: String) -> Record {
    let mut copy = record.clone();
    let mut inner = match record.get(parent) {
        Some(Value::Object(map)) => map.clone(),
        _ => serde_json::Map::new(),
    };
    inner.insert(key.to_owned(), Value::String(sealed));
    copy.insert(parent.to_owned(), Value::Object(inner));
    copy
}

fn id_of(record: &Record) -> String {
    js_string(record.get("id"))
}

const FIELDS: [SealedField; 10] = [
    // TOTP authenticator secrets.
    SealedField {
        collection: "authMfa",
        filter: Filter::new,
        read: |record| string_member(record, "encryptedSecret"),
        write: |record, sealed| with_member(record, "encryptedSecret", sealed),
        context: |record| format!("mfa:{}", js_string(record.get("identityId"))),
    },
    // Webhook signing secrets.
    SealedField {
        collection: "webhooks",
        filter: Filter::new,
        read: |record| string_member(record, "secretSealed"),
        write: |record, sealed| with_member(record, "secretSealed", sealed),
        context: |record| format!("webhook:{}", id_of(record)),
    },
    // Undelivered email, SMS, and webhook payloads (delivered ones are cleared).
    SealedField {
        collection: "outbox",
        filter: || Filter::new().absent("deliveredAt").absent("failedAt"),
        read: |record| nested(record, "payload", "sealed"),
        write: |record, sealed| with_nested(record, "payload", "sealed", sealed),
        context: |record| format!("outbox:{}", id_of(record)),
    },
    // Inference provider API keys (inference.ts `providerKeyContext`).
    SealedField {
        collection: "inferenceProviders",
        filter: Filter::new,
        read: |record| string_member(record, "keySealed"),
        write: |record, sealed| with_member(record, "keySealed", sealed),
        context: |record| format!("inference-provider:{}", id_of(record)),
    },
    // KMS key material sealed under the deployment secret (kms.ts `kmsSealedField`).
    SealedField {
        collection: "kmsKeyVersions",
        filter: || Filter::new().eq("wrapper", "secret"),
        read: |record| string_member(record, "materialSealed"),
        write: |record, sealed| with_member(record, "materialSealed", sealed),
        context: |record| {
            format!(
                "kms-key:{}:{}",
                js_string(record.get("keyId")),
                number_to_string(to_number(record.get("version").unwrap_or(&Value::Null)))
            )
        },
    },
    // Vault secret values (vault.ts `versionContext`); values under a customer-managed key are KMS ciphertexts.
    SealedField {
        collection: "vaultVersions",
        filter: Filter::new,
        read: |record| {
            if record.contains_key("kmsKeyId") {
                None
            } else {
                string_member(record, "sealed")
            }
        },
        write: |record, sealed| with_member(record, "sealed", sealed),
        context: |record| {
            format!(
                "vault:{}:{}:{}",
                js_string(record.get("tenantId")),
                js_string(record.get("secretId")),
                js_string(record.get("version"))
            )
        },
    },
    // Dynamic secret engines' revocation handles (vault.ts `leaseHandleContext`).
    SealedField {
        collection: "vaultLeases",
        filter: Filter::new,
        read: |record| string_member(record, "handleSealed"),
        write: |record, sealed| with_member(record, "handleSealed", sealed),
        context: |record| format!("vault-lease:{}", id_of(record)),
    },
    // SSH certificate authority keys (ssh.ts `authorityContext`).
    SealedField {
        collection: "sshAuthorities",
        filter: Filter::new,
        read: |record| string_member(record, "keySealed"),
        write: |record, sealed| with_member(record, "keySealed", sealed),
        context: |record| format!("ssh-authority:{}", id_of(record)),
    },
    // Verifiable credential issuer keys (vc.ts `keyContext`).
    SealedField {
        collection: "vcIssuerKeys",
        filter: Filter::new,
        read: |record| string_member(record, "keySealed"),
        write: |record, sealed| with_member(record, "keySealed", sealed),
        context: |record| format!("vc-issuer-key:{}", id_of(record)),
    },
    // Shared Signals poll sources' bearer tokens (signal-receiver.ts `pollTokenContext`).
    SealedField {
        collection: "signalSources",
        filter: Filter::new,
        read: |record| nested(record, "poll", "tokenSealed"),
        write: |record, sealed| with_nested(record, "poll", "tokenSealed", sealed),
        context: |record| format!("signal-poll:{}", id_of(record)),
    },
];

/// `rotateSecrets(options)` (`createSecretRotation(ctx)`): configure the new `secret` with the old one in
/// `previousSecrets`, run this until `done`, wait a day for pending challenges and assertions to expire, then remove
/// `previousSecrets`. Sessions and API keys are hashed without the secret, so nobody is signed out.
pub async fn rotate_secrets(
    ctx: &ServerContext,
    options: &SecretRotationOptions,
) -> IamResult<SecretRotationResult> {
    let batch_size = options.batch_size.unwrap_or(200.0);
    if !better_iam_core::js::is_safe_integer(batch_size) || !(1.0..=2000.0).contains(&batch_size) {
        return Err(IamError::new(
            "INVALID_INPUT",
            "batchSize must be an integer between 1 and 2000",
        ));
    }
    let limit = options.limit.unwrap_or(f64::INFINITY);
    if limit != f64::INFINITY && (!better_iam_core::js::is_safe_integer(limit) || limit < 1.0) {
        return Err(IamError::new(
            "INVALID_INPUT",
            "limit must be a positive integer",
        ));
    }
    let mut secrets = vec![ctx.options.secret.clone()];
    secrets.extend(ctx.options.previous_secrets.clone().unwrap_or_default());
    let result = Mutex::new(SecretRotationResult {
        complete: true,
        done: true,
        ..SecretRotationResult::default()
    });
    let lock = || {
        result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    };
    for field in &FIELDS {
        let mut after: Option<String> = None;
        let mut examined = 0.0;
        loop {
            let size = batch_size.min(limit - examined);
            if size <= 0.0 {
                // The limit stopped this collection after a full page: records may remain unexamined.
                lock().complete = false;
                break;
            }
            let find = FindOptions {
                limit: Some(size as i64),
                offset: None,
                after: after.clone(),
            };
            // Each page reads and rewrites in one short transaction, so a value changed meanwhile is re-read rather
            // than overwritten with a stale copy.
            let records = if options.dry_run {
                page(
                    ctx,
                    field,
                    ctx.store.as_ref(),
                    &find,
                    &secrets,
                    &result,
                    true,
                )
                .await?
            } else {
                let (find, secrets, result) = (&find, &secrets, &result);
                ctx.store
                    .transaction(move |tx: Store| async move {
                        page(ctx, field, tx.as_ref(), find, secrets, result, false).await
                    })
                    .await?
            };
            examined += records.len() as f64;
            if (records.len() as f64) < size {
                break;
            }
            after = records.last().map(id_of);
        }
    }
    let mut result = result.into_inner().unwrap_or_else(|p| p.into_inner());
    result.done = result.complete && !(options.dry_run && !result.resealed.is_empty());
    Ok(result)
}

/// One page of one sealed field: counts, and (outside a dry run) re-seals what a previous secret opens.
async fn page(
    ctx: &ServerContext,
    field: &SealedField,
    tx: &dyn IamStore,
    find: &FindOptions,
    secrets: &[String],
    result: &Mutex<SecretRotationResult>,
    dry_run: bool,
) -> IamResult<Vec<Record>> {
    let lock = || {
        result
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    };
    let records = tx.find(field.collection, &(field.filter)(), find).await?;
    for record in &records {
        let Some(sealed) = (field.read)(record) else {
            continue;
        };
        let context = (field.context)(record);
        let Some((opened, index)) = open_secret(&sealed, secrets, &context) else {
            *lock()
                .unreadable
                .entry(field.collection.to_owned())
                .or_insert(0.0) += 1.0;
            continue;
        };
        if index == 0 {
            lock().current += 1.0;
            continue;
        }
        *lock()
            .resealed
            .entry(field.collection.to_owned())
            .or_insert(0.0) += 1.0;
        if !dry_run {
            let resealed = encrypt_secret(&opened, &ctx.options.secret, &context);
            tx.put(field.collection, &(field.write)(record, resealed))
                .await?;
        }
    }
    Ok(records)
}
