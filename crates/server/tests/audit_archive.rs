//! Continuous audit archiving (`iam.archiveAudit`, `archiveCursor`) and the JSON Lines file sink
//! (`createJsonlAuditArchive`). Ported from tests/audit-archive.test.ts; the CLI case belongs to the CLI port.
//! Where the TypeScript fixture produces audit events through `identities.create`, these tests create roles through
//! the API, which audits the same way.

mod organization_fixture;

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use better_iam_core::{
    ChainHead, Filter, FindOptions, IamError, IamStoreExt, Record, VerifyAuditChainOptions,
    verify_audit_chain,
};
use better_iam_server::audit_archive::create_jsonl_audit_archive;
use better_iam_server::options::{AuditArchiveBatch, AuditArchiveOptions, BetterIamOptions};
use organization_fixture::{Org, body, organization, run};
use serde_json::{Value, json};

const DAY: f64 = 86_400_000.0;

type Written = Arc<Mutex<Vec<AuditArchiveBatch>>>;

/// A sink collecting batches in memory (failing while `failing` is set).
fn memory_sink(
    written: &Written,
    failing: Option<Arc<AtomicBool>>,
    batch_size: Option<f64>,
) -> AuditArchiveOptions {
    let written = written.clone();
    AuditArchiveOptions {
        write: Some(Arc::new(move |batch: AuditArchiveBatch| {
            let written = written.clone();
            let failing = failing.clone();
            Box::pin(async move {
                if failing.is_some_and(|failing| failing.load(Ordering::SeqCst)) {
                    return Err(IamError::with_status(
                        "INTERNAL_ERROR",
                        "bucket unavailable",
                        500,
                    ));
                }
                written.lock().unwrap().push(batch);
                Ok(())
            })
        })),
        batch_size,
        lease_ms: None,
    }
}

async fn fixture(sink: AuditArchiveOptions) -> Org {
    organization(move |options: &mut BetterIamOptions| {
        options.audit_archive = Some(sink);
    })
    .await
}

/// Audited activity in the organization: `count` roles created through the API.
async fn activity(f: &Org, count: usize) {
    for _ in 0..count {
        f.iam
            .api
            .roles
            .create(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": format!("Role {}", better_iam_server::utils::id()),
                    "permissions": ["documents:read"],
                })),
            )
            .await
            .expect("roles.create");
    }
}

async fn archive(f: &Org, input: Value) -> Value {
    f.iam.archive_audit(Some(&input)).await.unwrap()
}

async fn head(f: &Org, tenant_id: &str) -> ChainHead {
    let record = f
        .iam
        .store
        .get("auditChains", tenant_id)
        .await
        .unwrap()
        .unwrap();
    ChainHead {
        sequence: record["sequence"].as_f64().unwrap(),
        hash: record["hash"].as_str().unwrap().to_owned(),
    }
}

/// Every archived event of one tenant, read back from the JSON Lines files in name order.
fn archived_events(root: &Path, tenant_id: &str) -> Vec<Record> {
    let folder = root.join(tenant_id);
    let mut names: Vec<String> = std::fs::read_dir(&folder)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".jsonl"))
        .collect();
    names.sort();
    let mut by_sequence: std::collections::BTreeMap<u64, Record> = Default::default();
    for name in names {
        let text = std::fs::read_to_string(folder.join(name)).unwrap();
        for line in text.trim().split('\n') {
            let event: Record = serde_json::from_str(line).unwrap();
            by_sequence.insert(event["sequence"].as_u64().unwrap(), event);
        }
    }
    by_sequence.into_values().collect()
}

fn verified(events: &[Record], head: ChainHead) -> better_iam_core::AuditChainVerification {
    verify_audit_chain(
        events,
        &VerifyAuditChainOptions {
            previous_hash: None,
            head: Some(head),
        },
    )
}

#[test]
fn archives_every_chain_verified_and_in_order_incrementally_into_json_lines_files() {
    run(|| async {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().to_path_buf();
        let f = fixture(create_jsonl_audit_archive(&path)).await;
        activity(&f, 2).await;
        let heads = f
            .iam
            .store
            .find("auditChains", &Filter::new(), &FindOptions::default())
            .await
            .unwrap();
        assert!(!heads.is_empty());
        let first = archive(&f, json!({})).await;
        assert_eq!(first["failed"], json!([]));
        assert_eq!(first["gaps"], json!([]));
        assert_eq!(first["busy"], json!([]));
        assert_eq!(first["truncated"], json!(false));
        for chain in &heads {
            assert_eq!(
                first["archived"][chain["id"].as_str().unwrap()].as_f64(),
                chain["sequence"].as_f64()
            );
        }
        let before = head(&f, &f.tenant_id).await;
        // The cursor records how far the chain went.
        let cursor = f
            .iam
            .audit_archive
            .archive_cursor(&f.tenant_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cursor["sequence"].as_f64(), Some(before.sequence));
        assert_eq!(cursor["hash"], json!(before.hash));
        assert!(cursor.get("leaseId").is_none());
        assert!(cursor.get("leaseUntil").is_none());

        // Only the new events go out on the next run, and the files add up to the whole chain.
        activity(&f, 2).await;
        let second = archive(&f, json!({})).await;
        let after = head(&f, &f.tenant_id).await;
        assert_eq!(
            second["archived"][f.tenant_id.as_str()].as_f64(),
            Some(after.sequence - before.sequence)
        );
        let events = archived_events(&path, &f.tenant_id);
        let verification = verified(&events, after.clone());
        assert!(verification.valid);
        assert_eq!(verification.first, Some(1.0));
        assert_eq!(verification.last, Some(after.sequence));
        let again = archive(&f, json!({})).await;
        assert_eq!(again["archived"], json!({}));
        assert_eq!(again["batches"], json!(0));
        // File names are the zero-padded sequence range.
        let names: Vec<String> = std::fs::read_dir(path.join(&f.tenant_id))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&format!(
            "000000000001-{:012}.jsonl",
            before.sequence as u64
        )));
    });
}

#[test]
fn keeps_events_the_archive_does_not_hold_yet_when_pruning() {
    run(|| async {
        let written: Written = Arc::default();
        let failing = Arc::new(AtomicBool::new(false));
        let f = fixture(memory_sink(&written, Some(failing.clone()), Some(3.0))).await;
        activity(&f, 3).await;
        // Nothing archived yet: pruning everything older than now deletes nothing.
        assert_eq!(
            prune(&f).await,
            json!({ "deleted": 0, "heldForArchive": true })
        );
        // A failing sink leaves the cursor where it was.
        failing.store(true, Ordering::SeqCst);
        let failed = archive(&f, json!({ "tenantId": f.tenant_id })).await;
        assert_eq!(
            failed["failed"],
            json!([{ "tenantId": f.tenant_id, "code": "ARCHIVE_WRITE_FAILED", "message": "bucket unavailable" }])
        );
        assert_eq!(prune(&f).await["deleted"], json!(0));
        failing.store(false, Ordering::SeqCst);
        // Batches of three, chained to each other.
        let archived = archive(&f, json!({ "tenantId": f.tenant_id })).await;
        assert_eq!(archived["failed"], json!([]));
        let batches = written.lock().unwrap().clone();
        assert!(batches.len() > 1);
        for (index, batch) in batches.iter().enumerate() {
            assert!(batch.events.len() <= 3);
            if index > 0 {
                assert_eq!(batch.previous_hash, batches[index - 1].last_hash);
                assert_eq!(batch.from_sequence, batches[index - 1].to_sequence + 1.0);
            } else {
                assert_eq!(batch.from_sequence, 1.0);
                assert_eq!(batch.previous_hash, better_iam_core::AUDIT_GENESIS);
            }
        }
        let through = batches.last().unwrap().to_sequence;
        assert_eq!(archived["batches"].as_f64(), Some(batches.len() as f64));
        // Now pruning removes exactly what the archive holds.
        let pruned = prune(&f).await;
        assert_eq!(pruned["deleted"].as_f64(), Some(through));
        assert_eq!(pruned["prunedThroughSequence"].as_f64(), Some(through));
        // The prune checkpoint event itself is new, so it is archived next.
        assert_eq!(
            archive(&f, json!({ "tenantId": f.tenant_id })).await["archived"][f.tenant_id.as_str()],
            json!(1)
        );
        assert_eq!(
            written.lock().unwrap().last().unwrap().events[0]["action"],
            json!("audit:prune")
        );
    });
}

#[test]
fn refuses_to_archive_a_chain_that_does_not_verify_and_reports_gaps_it_cannot_fill() {
    run(|| async {
        let written: Written = Arc::default();
        let f = fixture(memory_sink(&written, None, None)).await;
        activity(&f, 3).await;
        let mut victim = f
            .find(
                "audit",
                Filter::new()
                    .eq("tenantId", f.tenant_id.clone())
                    .eq("sequence", 2),
            )
            .await
            .remove(0);
        victim.insert("action".into(), json!("tampered"));
        f.put("audit", victim).await;
        let result = archive(&f, json!({ "tenantId": f.tenant_id })).await;
        assert_eq!(result["failed"].as_array().unwrap().len(), 1);
        assert_eq!(result["failed"][0]["tenantId"], json!(f.tenant_id));
        assert_eq!(result["failed"][0]["code"], json!("AUDIT_CHAIN_BROKEN"));
        assert_eq!(
            result["failed"][0]["message"],
            json!("The chain does not verify at sequence 2")
        );
        assert!(written.lock().unwrap().is_empty());
        assert_eq!(
            f.iam
                .prune_audit(&json!({ "tenantId": f.tenant_id, "retentionMs": 0 }))
                .await
                .unwrap()["deleted"],
            json!(0)
        );

        // Events deleted outside the archive show up as a gap; the rest is archived from there.
        let g = fixture(memory_sink(&written, None, None)).await;
        activity(&g, 3).await;
        let tenant_id = g.tenant_id.clone();
        g.iam
            .store
            .transaction(|tx| async move {
                for sequence in [1, 2] {
                    for event in tx
                        .find(
                            "audit",
                            &Filter::new()
                                .eq("tenantId", tenant_id.clone())
                                .eq("sequence", sequence),
                            &FindOptions::default(),
                        )
                        .await?
                    {
                        tx.delete("audit", event["id"].as_str().unwrap()).await?;
                    }
                }
                Ok(())
            })
            .await
            .unwrap();
        let resumed = archive(&g, json!({ "tenantId": g.tenant_id })).await;
        assert_eq!(resumed["failed"], json!([]));
        assert_eq!(
            resumed["gaps"],
            json!([{ "tenantId": g.tenant_id, "fromSequence": 1, "toSequence": 2 }])
        );
    });
}

#[test]
fn lets_one_run_at_a_time_archive_a_tenant_so_overlapping_runs_never_lose_events() {
    run(|| async {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().to_path_buf();
        let files = create_jsonl_audit_archive(&path).write.unwrap();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let entered = Arc::new(Mutex::new(Some(entered_tx)));
        let release = Arc::new(tokio::sync::Mutex::new(Some(release_rx)));
        let sink = AuditArchiveOptions {
            write: Some(Arc::new(move |batch: AuditArchiveBatch| {
                let (entered, release, files) = (entered.clone(), release.clone(), files.clone());
                Box::pin(async move {
                    let first = entered.lock().unwrap().take();
                    if let Some(entered) = first {
                        let _ = entered.send(());
                        let waiting = release.lock().await.take();
                        if let Some(waiting) = waiting {
                            let _ = waiting.await;
                        }
                    }
                    files(batch).await
                })
            })),
            batch_size: Some(2.0),
            lease_ms: None,
        };
        let f = fixture(sink).await;
        activity(&f, 2).await;
        let input = json!({ "tenantId": f.tenant_id });
        let slow = f.iam.archive_audit(Some(&input));
        let overlapping = async {
            entered_rx.await.unwrap();
            // New events arrive while the first run is stuck in its sink; a second run must not race it.
            activity(&f, 2).await;
            let second = f.iam.archive_audit(Some(&input)).await.unwrap();
            let _ = release_tx.send(());
            second
        };
        let (slow, second) = tokio::join!(slow, overlapping);
        assert_eq!(second["archived"], json!({}));
        assert_eq!(second["busy"], json!([f.tenant_id]));
        assert_eq!(slow.unwrap()["failed"], json!([]));
        archive(&f, input.clone()).await;
        let chain = head(&f, &f.tenant_id).await;
        // Everything pruned is in the archive: the files hold the whole chain.
        let pruned = f
            .iam
            .prune_audit(&json!({ "tenantId": f.tenant_id, "retentionMs": 0 }))
            .await
            .unwrap();
        assert_eq!(
            pruned["prunedThroughSequence"].as_f64(),
            Some(chain.sequence)
        );
        let verification = verified(&archived_events(&path, &f.tenant_id), chain.clone());
        assert!(verification.valid);
        assert_eq!(verification.first, Some(1.0));
        assert_eq!(verification.last, Some(chain.sequence));
    });
}

#[test]
fn never_overwrites_an_archived_file_with_different_events() {
    run(|| async {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().to_path_buf();
        let files = create_jsonl_audit_archive(&path).write.unwrap();
        let event = |sequence: u64, action: &str| -> Record {
            serde_json::from_value(json!({ "id": format!("e{sequence}"), "tenantId": "t", "sequence": sequence, "action": action })).unwrap()
        };
        let batch = |action: &str| AuditArchiveBatch {
            tenant_id: "t".into(),
            from_sequence: 1.0,
            to_sequence: 2.0,
            previous_hash: "0".repeat(64),
            last_hash: "x".into(),
            events: vec![event(1, action), event(2, action)],
        };
        files(batch("original")).await.unwrap();
        files(batch("original")).await.unwrap();
        let error = files(batch("forged")).await.unwrap_err();
        assert_eq!(error.code, "ARCHIVE_CONFLICT");
        assert_eq!(error.status, 409);
        assert_eq!(
            error.message,
            "t/000000000001-000000000002.jsonl already holds different events"
        );
        let stored = archived_events(&path, "t");
        assert_eq!(stored[0]["action"], json!("original"));
        // One JSON object per line, as JSON.stringify writes it.
        assert_eq!(
            std::fs::read_to_string(path.join("t").join("000000000001-000000000002.jsonl"))
                .unwrap(),
            "{\"id\":\"e1\",\"tenantId\":\"t\",\"sequence\":1,\"action\":\"original\"}\n{\"id\":\"e2\",\"tenantId\":\"t\",\"sequence\":2,\"action\":\"original\"}\n"
        );
        // No temporary files are left behind.
        let temporary: Vec<String> = std::fs::read_dir(path.join("t"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".tmp"))
            .collect();
        assert!(temporary.is_empty());
        for unsafe_id in ["../escape", ".hidden", "", "a/b"] {
            let mut escaping = batch("x");
            escaping.tenant_id = unsafe_id.into();
            let error = files(escaping).await.unwrap_err();
            assert_eq!(error.code, "INVALID_INPUT", "{unsafe_id}");
            assert_eq!(error.message, "Tenant id is not a safe file name");
        }
    });
}

#[test]
fn keeps_unarchived_events_from_a_process_that_does_not_configure_the_archive() {
    run(|| async {
        let written: Written = Arc::default();
        let f = fixture(memory_sink(&written, None, Some(2.0))).await;
        activity(&f, 3).await;
        archive(&f, json!({ "tenantId": f.tenant_id, "limit": 2 })).await;
        // Another process, say a retention worker, runs without the auditArchive option.
        let worker = better_iam_server::better_iam(BetterIamOptions::new(
            f.store(),
            "organization-fixture-secret-with-32-characters",
            organization_fixture::ORIGIN,
        ))
        .unwrap();
        let pruned = worker
            .prune_audit(&json!({ "tenantId": f.tenant_id, "retentionMs": 0 }))
            .await
            .unwrap();
        assert_eq!(pruned["deleted"], json!(2));
        assert_eq!(pruned["prunedThroughSequence"], json!(2));
        assert_eq!(pruned["heldForArchive"], json!(true));
        // Without a sink there is nothing to archive to.
        let error = worker.archive_audit(None).await.unwrap_err();
        assert_eq!(error.code, "NO_AUDIT_ARCHIVE");
        assert_eq!(error.status, 501);
    });
}

#[test]
fn stops_at_the_limit_and_the_self_check_notices_an_archive_that_falls_behind() {
    run(|| async {
        let written: Written = Arc::default();
        let f = fixture(memory_sink(&written, None, Some(2.0))).await;
        activity(&f, 2).await;
        let limited = archive(&f, json!({ "limit": 3 })).await;
        assert_eq!(limited["truncated"], json!(true));
        let total: f64 = limited["archived"]
            .as_object()
            .unwrap()
            .values()
            .map(|count| count.as_f64().unwrap())
            .sum();
        assert_eq!(total, 3.0);
        let checks = |report: &Value| -> Vec<Value> {
            report["findings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|finding| finding["check"].clone())
                .collect()
        };
        let report = f.iam.self_check(None).await.unwrap();
        assert!(!checks(&report).contains(&json!("audit-archive-behind")));
        f.advance(2.0 * DAY);
        let late = f.iam.self_check(None).await.unwrap();
        let finding = late["findings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|finding| finding["check"] == json!("audit-archive-behind"))
            .cloned()
            .expect("audit-archive-behind");
        assert_eq!(finding["severity"], json!("warning"));
        assert_eq!(archive(&f, json!({})).await["truncated"], json!(false));
        let report = f.iam.self_check(None).await.unwrap();
        assert!(!checks(&report).contains(&json!("audit-archive-behind")));
    });
}

#[test]
fn validates_its_options() {
    run(|| async {
        let written: Written = Arc::default();
        let f = fixture(memory_sink(&written, None, None)).await;
        for limit in [json!(0), json!(1.5), json!(10_000_001), json!("5")] {
            let error = f
                .iam
                .archive_audit(Some(&json!({ "limit": limit })))
                .await
                .unwrap_err();
            assert_eq!(error.code, "INVALID_INPUT");
            assert_eq!(error.message, "limit must be between 1 and 10000000");
        }
        // The sink's own settings are checked when the deployment is composed.
        for (batch_size, lease_ms, message) in [
            (
                Some(0.0),
                None,
                "auditArchive.batchSize must be between 1 and 10000",
            ),
            (
                Some(10_001.0),
                None,
                "auditArchive.batchSize must be between 1 and 10000",
            ),
            (
                None,
                Some(59_999.0),
                "auditArchive.leaseMs must be between 60000 and 3600000",
            ),
            (
                None,
                Some(1.5 * 3_600_000.0),
                "auditArchive.leaseMs must be between 60000 and 3600000",
            ),
        ] {
            let mut options = BetterIamOptions::new(
                f.store(),
                "organization-fixture-secret-with-32-characters",
                organization_fixture::ORIGIN,
            );
            let mut sink = memory_sink(&written, None, batch_size);
            sink.lease_ms = lease_ms;
            options.audit_archive = Some(sink);
            let error = better_iam_server::better_iam(options)
                .err()
                .expect("refused");
            assert_eq!(error.code, "INVALID_CONFIG");
            assert_eq!(error.message, message);
        }
        // An archive cursor is undefined until something was archived.
        assert_eq!(
            f.iam.audit_archive.archive_cursor("nobody").await.unwrap(),
            None
        );
    });
}

/// `iam.pruneAudit({ tenantId, retentionMs: 0 })`.
async fn prune(f: &Org) -> Value {
    f.iam
        .prune_audit(&json!({ "tenantId": f.tenant_id, "retentionMs": 0 }))
        .await
        .unwrap()
}
