//! The threat detection engine (threat-engine.ts): chain verification, cursors, baselines, playbooks, and the
//! robustness of `iam.detectThreats()`. Ported from tests/threats-engine.test.ts.
//!
//! The scenarios that run detection need `resolveThreatSettings`, `threatRule` and the other helpers of threats.ts,
//! and `threatAudit` / `afterThreatResponses` / `applyResponse` of threat-response.ts; the response scenarios also
//! need the `threats` API group. Those are other port units, so those tests are ignored until they land. The input
//! validation of `detectThreats` runs today.

mod organization_fixture;
mod threat_support;

use better_iam_auth::templates::{
    TemplateLinks, TemplateOptions, ThreatsLink, render_delivery_message,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use better_iam_core::{
    Filter, FindOptions, IamResult, IamStore, IamStoreExt, OrderOptions, Record, TransactionFn,
    TransactionValue, append_audit_event,
};
use serde_json::{Value, json};
use threat_support::{
    Threats, assert_matches, body, fails, fixture, number, ok, organization, run,
};

#[test]
fn rejects_an_unknown_tenant_and_invalid_limits_before_reading_anything() {
    run(|| async {
        let f = fixture().await;
        let missing = f
            .iam
            .detect_threats(Some(&json!({ "tenantId": "no-such-tenant" })))
            .await
            .unwrap_err();
        assert_eq!((missing.code.as_str(), missing.status), ("NOT_FOUND", 404));
        for max_events in [json!(0), json!(20_001), json!(1.5), json!("10")] {
            let error = f
                .iam
                .detect_threats(Some(&json!({ "maxEvents": max_events })))
                .await
                .unwrap_err();
            assert_eq!(
                (error.code.as_str(), error.message.as_str()),
                ("INVALID_INPUT", "Invalid maxEvents")
            );
        }
        let error = f
            .iam
            .detect_threats(Some(&json!({ "tenantId": "" })))
            .await
            .unwrap_err();
        assert_eq!(error.code, "INVALID_INPUT");
    });
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule and threat-response.ts threatAudit (other port units)"]
fn verifies_the_chain_reports_tampering_once_and_survives_a_prune() {
    run(|| async {
        let f = fixture().await;
        let first = f.detect_threats(None).await;
        assert_eq!(number(&first, "chainBreaks"), 0.0);
        assert!(number(&first, "tenants") >= 2.0);
        let again = f.detect_threats(None).await;
        assert_eq!(number(&again, "chainBreaks"), 0.0);

        f.member("alice").await;
        let newest = f.audit_newest_first().await.remove(0);
        let mut forged = newest.clone();
        forged.insert("metadata".into(), json!({ "forged": true }));
        f.overwrite("audit", forged).await;
        let tampered = f
            .detect_threats(Some(json!({ "tenantId": f.tenant_id })))
            .await;
        assert_eq!(number(&tampered, "chainBreaks"), 1.0);
        assert_eq!(number(&tampered, "detections"), 1.0);
        assert_eq!(number(&tampered, "incidentsOpened"), 1.0);
        let detections = f.tenant_records("threatDetections").await;
        let rules: Vec<&Value> = detections.iter().map(|d| &d["ruleId"]).collect();
        assert_eq!(rules, vec![&json!("audit-tampering")]);
        let next = f
            .detect_threats(Some(json!({ "tenantId": f.tenant_id })))
            .await;
        assert_eq!(number(&next, "chainBreaks"), 0.0);
        let audit = f.tenant_records("audit").await;
        assert!(
            audit
                .iter()
                .any(|event| event["action"] == "threat:detection")
        );
        assert!(
            audit
                .iter()
                .any(|event| event["action"] == "threat:incident-open")
        );

        f.member("bob").await;
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        f.iam
            .prune_audit(&json!({ "tenantId": f.tenant_id, "retentionMs": 0 }))
            .await
            .expect("prune");
        let after_prune = f
            .detect_threats(Some(json!({ "tenantId": f.tenant_id })))
            .await;
        assert_eq!(number(&after_prune, "chainBreaks"), 0.0);
        assert!(number(&after_prune, "eventsScanned") >= 1.0);
        // Rolling the chain head back behind the cursor is reported.
        let mut head = f.get("auditChains", &f.tenant_id).await.unwrap();
        head["sequence"] = json!(1);
        f.overwrite("auditChains", head.as_object().unwrap().clone())
            .await;
        let rolled = f
            .detect_threats(Some(json!({ "tenantId": f.tenant_id })))
            .await;
        assert_eq!(number(&rolled, "chainBreaks"), 1.0);
        assert_eq!(number(&rolled, "detections"), 1.0);
    });
}

#[test]
#[ignore = "needs the threats API group and threat-response.ts (other port units)"]
fn contains_releases_blocks_and_notifies_through_responses() {
    run(|| async {
        let f = fixture().await;
        let api = &f.iam.api;
        let alice = f.member("alice").await;
        let signed_in = f.sign_in_as("alice").await;
        let owner = f.owner_sign_in().await;
        let respond = |input: Value| {
            let mut input = input;
            input["tenantId"] = json!(f.tenant_id);
            let owner = owner.clone();
            async move { api.threats.respond(&owner, body(input)).await }
        };
        let contained = ok(respond(json!({
            "identityId": alice, "actions": [{ "kind": "contain" }], "reason": "smoke",
        }))
        .await);
        assert_eq!(contained[0]["outcome"], "applied");
        let disabled = f.get("identities", &alice).await.unwrap();
        assert_eq!(disabled["status"], "disabled");
        assert!(
            f.iam
                .api
                .auth
                .call(
                    "getSession",
                    better_iam_server::http::AuthArgs::Authenticated(
                        threat_support::bearer(signed_in["token"].as_str().unwrap()),
                        json!({}),
                    ),
                )
                .await
                .is_err()
        );
        assert!(
            f.password_sign_in("alice@acme.test", "a strong alice password")
                .await
                .is_err()
        );
        let risk = f.get("identityRisk", &alice).await.unwrap();
        assert!(risk.get("contained").is_some_and(|value| !value.is_null()));
        let again = ok(respond(json!({
            "identityId": alice, "actions": [{ "kind": "contain" }], "reason": "smoke",
        }))
        .await);
        assert_eq!(again[0]["outcome"], "skipped");
        assert_eq!(again[0]["reason"], "already-applied");
        let refused = fails(
            respond(json!({
                "identityId": f.owner_id, "actions": [{ "kind": "contain" }], "reason": "smoke",
            }))
            .await,
        );
        assert_eq!(refused.code, "INVALID_INPUT");
        let released = ok(api
            .threats
            .release(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "identityId": alice, "note": "ok" })),
            )
            .await);
        assert_eq!(released["action"], "release");
        assert_eq!(
            f.get("identities", &alice).await.unwrap()["status"],
            "active"
        );
        f.sign_in_as("alice").await;
        let twice = fails(
            api.threats
                .release(
                    &owner,
                    body(json!({ "tenantId": f.tenant_id, "identityId": alice })),
                )
                .await,
        );
        assert_eq!(twice.code, "INVALID_TRANSITION");

        ok(api
            .threats
            .configure(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "trustedNetworks": ["203.0.113.0/24"],
                    "notify": { "owners": true, "emails": ["soc@example.test"] },
                })),
            )
            .await);
        let trusted = ok(respond(json!({
            "network": "203.0.113.7", "actions": [{ "kind": "block-network" }], "reason": "smoke",
        }))
        .await);
        assert_eq!(trusted[0]["reason"], "trusted-network");
        let blocked = ok(respond(json!({
            "network": "198.51.100.7",
            "actions": [{ "kind": "block-network", "durationMs": 3_600_000 }],
            "reason": "smoke",
        }))
        .await);
        assert_eq!(blocked[0]["outcome"], "applied");
        let blocks: Vec<Value> = f
            .tenant_records("authBlocks")
            .await
            .into_iter()
            .map(|block| block["network"].clone())
            .collect();
        assert_eq!(blocks, vec![json!("198.51.100.7")]);
        let redundant = ok(respond(json!({
            "network": "198.51.100.7",
            "actions": [{ "kind": "block-network", "durationMs": 60_000 }],
            "reason": "smoke",
        }))
        .await);
        assert_eq!(redundant[0]["reason"], "already-applied");

        // A playbook emails new incidents once.
        ok(api
            .threats
            .create_playbook(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Email the SOC",
                    "trigger": {},
                    "actions": [{ "kind": "notify" }, { "kind": "contain" }],
                })),
            )
            .await);
        f.detect_threats(Some(json!({ "tenantId": f.tenant_id })))
            .await;
        f.member("dave").await;
        let mut newest = f.audit_newest_first().await.remove(0);
        newest.insert("metadata".into(), json!({ "forged": true }));
        f.overwrite("audit", newest).await;
        let detected = f
            .detect_threats(Some(json!({ "tenantId": f.tenant_id })))
            .await;
        assert_eq!(number(&detected, "detections"), 1.0);
        f.iam.auth.dispatch_outbox(None).await.unwrap();
        let alerts: Vec<_> = f
            .inbox
            .lock()
            .unwrap()
            .iter()
            .filter(|message| message.template == "threat-alert")
            .cloned()
            .collect();
        let mut recipients: Vec<&str> = alerts.iter().map(|m| m.to.as_str()).collect();
        recipients.sort();
        assert_eq!(recipients, vec!["owner@acme.test", "soc@example.test"]);
        let rendered = render_delivery_message(
            &(&alerts[0]).into(),
            &TemplateOptions {
                app_name: None,
                links: TemplateLinks {
                    threats: Some(Box::new(|link: ThreatsLink| {
                        format!(
                            "https://x.test/{}/{}",
                            link.tenant_id,
                            link.incident_id.unwrap_or_default()
                        )
                    })),
                    ..TemplateLinks::default()
                },
            },
        )
        .unwrap();
        assert!(
            rendered
                .subject
                .contains("Critical security incident at Acme")
        );
        assert!(rendered.text.contains("https://x.test/"));
        let responses = f.tenant_records("threatResponses").await;
        // The tenant subject has no identity: contain is skipped.
        let contain = responses
            .iter()
            .find(|r| r["action"] == "contain" && r.get("playbookId").is_some())
            .unwrap();
        assert_eq!(contain["reason"], "not-identity");
    });
}

/// Six wrong-password sign-ins for `email` from 198.51.100.30.
async fn fail_six(f: &Threats, email: &str) {
    for _ in 0..6 {
        let _ = f
            .as_test_client(
                "198.51.100.30",
                f.password_sign_in(email, "wrong password here"),
            )
            .await;
    }
}

#[test]
#[ignore = "needs the threats API group and threat-response.ts applyResponse (other port units)"]
fn contains_automatically_protects_owners_and_brakes() {
    run(|| async {
        let f = fixture().await;
        f.member("erin").await;
        f.member("frank").await;
        let owner = f.owner_sign_in().await;
        ok(f.iam
            .api
            .threats
            .configure(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "maxAutomaticContainments": 1,
                    "rules": { "brute-force": { "threshold": 5 } },
                })),
            )
            .await);
        ok(f.iam
            .api
            .threats
            .create_playbook(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Contain guessing",
                    "trigger": { "ruleIds": ["brute-force"] },
                    "actions": [{ "kind": "revoke-sessions" }, { "kind": "contain" }],
                })),
            )
            .await);
        f.detect_threats(None).await;
        fail_six(&f, "erin@acme.test").await;
        fail_six(&f, "frank@acme.test").await;
        fail_six(&f, "owner@acme.test").await;
        f.iam.auth.settle_bookkeeping().await;
        let detected = f
            .detect_threats(Some(json!({ "tenantId": f.tenant_id })))
            .await;
        assert_eq!(number(&detected, "braked"), 1.0);
        let responses = f.tenant_records("threatResponses").await;
        let mut contains: Vec<String> = responses
            .iter()
            .filter(|r| r["action"] == "contain")
            .map(|r| {
                r.get("reason")
                    .unwrap_or(&r["outcome"])
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect();
        contains.sort();
        assert_eq!(contains, vec!["applied", "braked", "protected"]);
        let audit = f.tenant_records("audit").await;
        let count = |action: &str| audit.iter().filter(|e| e["action"] == action).count();
        assert_eq!(count("threat:response-braked"), 1);
        assert_eq!(count("threat:contain"), 1);
        assert_eq!(count("threat:revoke-sessions"), 3);
        assert_eq!(f.tenant_records("identityRisk").await.len(), 3);
        assert!(count("threat:risk-change") >= 3);
        let again = f
            .detect_threats(Some(json!({ "tenantId": f.tenant_id })))
            .await;
        assert_eq!(number(&again, "detections"), 0.0);
    });
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule and threat-response.ts threatAudit (other port units)"]
fn raises_brute_force_from_failed_sign_ins_through_the_rules() {
    run(|| async {
        let f = fixture().await;
        f.member("carol").await;
        f.detect_threats(None).await;
        for _ in 0..10 {
            let _ = f
                .as_test_client(
                    "198.51.100.20",
                    f.password_sign_in("carol@acme.test", "wrong password here"),
                )
                .await;
        }
        f.iam.auth.settle_bookkeeping().await;
        let detected = f
            .detect_threats(Some(json!({ "tenantId": f.tenant_id })))
            .await;
        let detections = f.tenant_records("threatDetections").await;
        assert!(number(&detected, "detections") >= 1.0);
        assert!(detections.iter().any(|d| d["ruleId"] == "brute-force"));
        assert_eq!(f.tenant_records("identityRisk").await.len(), 1);
    });
}

/// Appends events to the fixture tenant's audit chain as the recorders would (no fan-out).
async fn append(f: &Threats, events: Vec<Value>) {
    let tenant_id = f.tenant_id.clone();
    f.store()
        .transaction(|tx| async move {
            for event in events {
                let mut record: Record = event.as_object().unwrap().clone();
                record.insert("tenantId".into(), json!(tenant_id));
                append_audit_event(tx.as_ref(), &record).await?;
            }
            Ok(())
        })
        .await
        .unwrap();
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule and threat-response.ts threatAudit (other port units)"]
fn never_counts_refused_web_identity_tokens_as_the_trust_accounts_denials() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        let created = f
            .iam
            .api
            .service_accounts
            .create(
                &f.owner_credential,
                body(json!({ "tenantId": tenant_id, "name": "ci" })),
            )
            .await;
        // `serviceAccounts.create` ends in package automation (`afterIdentityChange`, another port unit): while that
        // answers NOT_IMPLEMENTED after the commit, the committed account is read back instead.
        let account_id = match created {
            Err(error)
                if error.code == "NOT_IMPLEMENTED"
                    && error.message.contains("afterIdentityChange") =>
            {
                f.find(
                    "identities",
                    Filter::new()
                        .eq("tenantId", tenant_id.clone())
                        .eq("name", "ci"),
                )
                .await[0]["id"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            }
            created => {
                let account = ok(created);
                account.get("identity").unwrap_or(&account)["id"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            }
        };
        f.detect_threats(Some(json!({ "tenantId": tenant_id })))
            .await;
        f.detect_threats(Some(json!({ "tenantId": tenant_id })))
            .await;
        let now = f.now();
        let denials = |action: &str, from: usize| -> Vec<Value> {
            (0..40)
                .map(|index| {
                    json!({
                        "id": format!("{action}-{}", from + index),
                        "actorId": account_id,
                        "action": action,
                        "resourceId": "role-deploy",
                        "timestamp": now + (from + index) as f64,
                        "outcome": "deny",
                        "rootOverride": false,
                        "metadata": { "reason": "malformed" },
                    })
                })
                .collect()
        };
        // Anyone may post junk tokens for a trust: they are recorded under its service account, never as its burst.
        append(&f, denials("role:assumed-with-web-identity", 0)).await;
        let quiet = f
            .detect_threats(Some(json!({ "tenantId": tenant_id })))
            .await;
        assert_eq!(number(&quiet, "detections"), 0.0);
        // The account's own refusals still are.
        append(&f, denials("documents:read", 100)).await;
        let loud = f
            .detect_threats(Some(json!({ "tenantId": tenant_id })))
            .await;
        assert_eq!(number(&loud, "detections"), 1.0);
        let bursts = f
            .find(
                "threatDetections",
                Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq("ruleId", "denial-burst"),
            )
            .await;
        assert_eq!(bursts[0]["evidence"]["count"], json!(40));
    });
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule and threat-response.ts threatAudit (other port units)"]
fn reports_an_event_stripped_of_its_fields_as_tampering_and_keeps_detecting() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        f.detect_threats(Some(json!({ "tenantId": tenant_id })))
            .await;
        f.member("alice").await;
        let mut stripped = f.audit_newest_first().await.remove(0);
        stripped.shift_remove("timestamp");
        stripped.shift_remove("action");
        f.overwrite("audit", stripped).await;
        let tampered = f
            .detect_threats(Some(json!({ "tenantId": tenant_id })))
            .await;
        assert_matches(&tampered, json!({ "chainBreaks": 1, "detections": 1 }));
        let tampering = f
            .find(
                "threatDetections",
                Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq("ruleId", "audit-tampering"),
            )
            .await;
        assert!(tampering[0]["occurredAt"].is_number());
        // The cursor moved past it: the next run reads new events.
        f.member("bob").await;
        let next = f
            .detect_threats(Some(json!({ "tenantId": tenant_id })))
            .await;
        assert_eq!(number(&next, "chainBreaks"), 0.0);
        assert!(number(&next, "eventsScanned") > 0.0);
    });
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule (another port unit)"]
fn writes_the_sign_in_baselines_of_at_most_500_people_per_run_and_continues_in_the_next() {
    run(|| async {
        let f = fixture().await;
        let tenant_id = f.tenant_id.clone();
        f.detect_threats(Some(json!({ "tenantId": tenant_id })))
            .await;
        f.detect_threats(Some(json!({ "tenantId": tenant_id })))
            .await;
        let now = f.now();
        append(
            &f,
            (0..501)
                .map(|index| {
                    json!({
                        "id": format!("sign-in-{index}"),
                        "actorId": format!("person-{index}"),
                        "action": "auth:session:create",
                        "resourceId": format!("person-{index}"),
                        "timestamp": now,
                        "outcome": "allow",
                        "metadata": { "ip": "192.0.2.10" },
                    })
                })
                .collect(),
        )
        .await;
        assert_matches(
            &f.detect_threats(Some(json!({ "tenantId": tenant_id })))
                .await,
            json!({ "eventsScanned": 500, "pending": 1 }),
        );
        assert_matches(
            &f.detect_threats(Some(json!({ "tenantId": tenant_id })))
                .await,
            json!({ "eventsScanned": 1, "pending": 0 }),
        );
    });
}

/// A store that, once armed, changes the tenant's threat settings in its own transaction right before the first
/// transaction that follows a read of those settings (the TypeScript test wraps `store.get` and
/// `store.transaction` the same way).
struct SettingsChanger {
    inner: Arc<dyn IamStore>,
    armed: AtomicBool,
    settings_read: AtomicBool,
    changed: AtomicBool,
    tenant_id: Mutex<String>,
}

#[async_trait::async_trait]
impl IamStore for SettingsChanger {
    async fn get(&self, collection: &str, id: &str) -> IamResult<Option<Record>> {
        if self.armed.load(Ordering::SeqCst)
            && collection == "threatSettings"
            && id == *self.tenant_id.lock().unwrap()
        {
            self.settings_read.store(true, Ordering::SeqCst);
        }
        self.inner.get(collection, id).await
    }
    async fn find(
        &self,
        collection: &str,
        filter: &Filter,
        options: &FindOptions,
    ) -> IamResult<Vec<Record>> {
        self.inner.find(collection, filter, options).await
    }
    fn has_find_ordered(&self) -> bool {
        self.inner.has_find_ordered()
    }
    async fn find_ordered(
        &self,
        collection: &str,
        filter: &Filter,
        order: &OrderOptions,
    ) -> IamResult<Vec<Record>> {
        self.inner.find_ordered(collection, filter, order).await
    }
    async fn insert(&self, collection: &str, record: &Record) -> IamResult<Record> {
        self.inner.insert(collection, record).await
    }
    async fn put(&self, collection: &str, record: &Record) -> IamResult<Record> {
        self.inner.put(collection, record).await
    }
    async fn delete(&self, collection: &str, id: &str) -> IamResult<()> {
        self.inner.delete(collection, id).await
    }
    async fn transaction_dyn(&self, run: TransactionFn<'_>) -> IamResult<TransactionValue> {
        if self.armed.load(Ordering::SeqCst)
            && self.settings_read.load(Ordering::SeqCst)
            && !self.changed.swap(true, Ordering::SeqCst)
        {
            let tenant_id = self.tenant_id.lock().unwrap().clone();
            self.inner
                .transaction(|tx| async move {
                    let mut stored = tx.get("threatSettings", &tenant_id).await?.unwrap();
                    let mut rules = stored["rules"].as_object().cloned().unwrap_or_default();
                    rules.insert("brute-force".into(), json!({ "enabled": false }));
                    stored.insert("rules".into(), Value::Object(rules));
                    let updated = stored["updatedAt"].as_f64().unwrap() + 1.0;
                    stored.insert("updatedAt".into(), json!(updated));
                    tx.put("threatSettings", &stored).await
                })
                .await?;
        }
        self.inner.transaction_dyn(run).await
    }
    async fn migrate(&self) -> IamResult<()> {
        self.inner.migrate().await
    }
    async fn close(&self) -> IamResult<()> {
        self.inner.close().await
    }
}

#[test]
#[ignore = "needs the threats API group (configure, createPlaybook) and threat-response.ts (other port units)"]
fn records_nothing_from_a_run_whose_settings_changed_while_it_evaluated() {
    run(|| async {
        let changer: Arc<Mutex<Option<Arc<SettingsChanger>>>> = Arc::default();
        let slot = changer.clone();
        let f = organization(move |options| {
            let wrapped = Arc::new(SettingsChanger {
                inner: options.database.take().unwrap(),
                armed: AtomicBool::new(false),
                settings_read: AtomicBool::new(false),
                changed: AtomicBool::new(false),
                tenant_id: Mutex::new(String::new()),
            });
            *slot.lock().unwrap() = Some(wrapped.clone());
            options.database = Some(wrapped);
        })
        .await;
        let changer = changer.lock().unwrap().clone().unwrap();
        let f = Threats {
            f,
            inbox: Arc::default(),
        };
        let tenant_id = f.tenant_id.clone();
        *changer.tenant_id.lock().unwrap() = tenant_id.clone();
        let erin = f.member("erin").await;
        let owner = f.owner_sign_in().await;
        ok(f.iam
            .api
            .threats
            .configure(
                &owner,
                body(json!({ "tenantId": tenant_id, "rules": { "brute-force": { "threshold": 5 } } })),
            )
            .await);
        ok(f.iam
            .api
            .threats
            .create_playbook(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "Contain guessing",
                    "trigger": { "ruleIds": ["brute-force"] },
                    "actions": [{ "kind": "contain" }],
                })),
            )
            .await);
        f.detect_threats(Some(json!({ "tenantId": tenant_id })))
            .await;
        for _ in 0..6 {
            let _ = f
                .as_test_client(
                    "198.51.100.31",
                    f.password_sign_in("erin@acme.test", "wrong password"),
                )
                .await;
        }
        f.iam.auth.settle_bookkeeping().await;

        // An administrator turns the rule off after the run read the settings and before it writes.
        changer.armed.store(true, Ordering::SeqCst);
        let detected = f
            .detect_threats(Some(json!({ "tenantId": tenant_id })))
            .await;
        changer.armed.store(false, Ordering::SeqCst);
        assert!(changer.changed.load(Ordering::SeqCst));
        assert_matches(&detected, json!({ "detections": 0, "responses": 0 }));
        assert_eq!(
            f.get("identities", &erin).await.unwrap()["status"],
            "active"
        );
        // The next run reads the same events under the new settings: the rule is off.
        let next = f
            .detect_threats(Some(json!({ "tenantId": tenant_id })))
            .await;
        assert!(number(&next, "eventsScanned") > 0.0);
        assert_eq!(number(&next, "detections"), 0.0);
        assert_eq!(
            f.get("identities", &erin).await.unwrap()["status"],
            "active"
        );
    });
}
