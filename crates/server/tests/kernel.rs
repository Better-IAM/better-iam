//! Behavior of the server kernel against a real SQLite store, ported from the TypeScript suites that exercise these
//! modules (events.test.ts, audit-session-context.test.ts, secret-rotation.test.ts, the guarded envelope of the KMS
//! and PKI suites, the record helpers of the provisioning suites). Services outside the kernel (decisions,
//! principals) are stubbed with the behavior those suites rely on.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_iam_auth::{decrypt_secret, encrypt_secret, open_secret};
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Decision, Filter, FindOptions, IamError,
    IamResult, IamStoreExt, Identity, PolicyDocument, ResourceRef, Session, Tenant,
    VerifyAuditChainOptions, verify_audit_chain,
};
use better_iam_server::context::{ServerContext, Store};
use better_iam_server::contracts::{
    ActivationSummary, BindingVia, DecisionService, EffectiveBinding, GrantPath, GrantSources,
    OperationDenied, PreparedDecision, PrincipalService,
};
use better_iam_server::delegations::use_confirmation;
use better_iam_server::events::{VerifyWebhookInput, verify_webhook_signature};
use better_iam_server::grant_deadline::grant_deadline;
use better_iam_server::guarded::{GuardAction, GuardOptions, Target, create_guard};
use better_iam_server::models::{Binding, GrantAuthority, Role};
use better_iam_server::options::{
    AuthorizationRequest, BetterIamOptions, EventOptions, ResolvedResource,
};
use better_iam_server::secrets::{SecretRotationOptions, rotate_secrets};
use better_iam_server::temporary_credentials::audit_session_context;
use better_iam_server::utils::all_value;
use common::memory_store;
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};

const SECRET: &str = "kernel-test-secret-with-at-least-32-characters";
const NOW: f64 = 1_767_225_600_000.0;

fn record(value: Value) -> Map<String, Value> {
    value.as_object().expect("object").clone()
}

fn identity(id: &str, tenant: &str, extra: Value) -> Identity {
    let mut value = json!({
        "id": id, "tenantId": tenant, "kind": "user", "name": format!("Person {id}"), "status": "active",
        "emailVerified": true, "rootAdmin": false, "owner": false, "createdAt": 1,
    });
    for (key, item) in extra.as_object().unwrap() {
        value[key] = item.clone();
    }
    serde_json::from_value(value).expect("identity")
}

fn session(id: &str, tenant: &str, identity: &str, extra: Value) -> Session {
    let mut value = json!({
        "id": id, "tenantId": tenant, "identityId": identity, "tokenHash": "h", "createdAt": 1, "expiresAt": NOW * 2.0,
        "lastSeenAt": 1, "authenticatedAt": 1, "mfa": false, "kind": "user",
    });
    for (key, item) in extra.as_object().unwrap() {
        value[key] = item.clone();
    }
    serde_json::from_value(value).expect("session")
}

fn principal(identity: Identity, session: Session) -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        identity,
        session,
        device_proof: None,
    }
}

async fn put(ctx: &ServerContext, collection: &'static str, value: Value) {
    let item = record(value);
    ctx.store
        .transaction(move |tx| async move {
            let id = item["id"].as_str().unwrap_or("").to_owned();
            if tx.get(collection, &id).await?.is_some() {
                tx.put(collection, &item).await.map(|_| ())
            } else {
                tx.insert(collection, &item).await.map(|_| ())
            }
        })
        .await
        .unwrap();
}

async fn all(ctx: &ServerContext, collection: &str) -> Vec<Map<String, Value>> {
    ctx.store
        .find(collection, &Filter::new(), &FindOptions::default())
        .await
        .unwrap()
}

async fn tenants(ctx: &ServerContext) {
    put(
        ctx,
        "tenants",
        json!({ "id": "root", "tenantId": "root", "name": "Root", "type": "root", "reference": null, "parentId": null, "status": "active", "createdAt": 1 }),
    )
    .await;
    put(
        ctx,
        "tenants",
        json!({ "id": "acme", "tenantId": "acme", "name": "Acme", "type": "organization", "reference": null, "parentId": "root", "status": "active", "createdAt": 1 }),
    )
    .await;
}

async fn migrated(options: BetterIamOptions, now: f64) -> Arc<ServerContext> {
    let ctx = common::context(options, now);
    ctx.store.migrate().await.unwrap();
    tenants(&ctx).await;
    ctx
}

#[test]
fn audit_session_context_is_an_allowlist() {
    let base = session(
        "session-1",
        "tenant-1",
        "identity-1",
        json!({
            "kind": "role", "roleId": "role-1", "trustId": "trust-1", "sourceSessionId": "source-1",
            "sourceAuthorityIds": ["authority-1"], "credentialAuthorityId": "authority-2",
            "policy": { "version": 1, "statements": [] }, "sessionTags": { "team": "secret" }, "format": "jwt",
            "webIdentity": { "providerId": "provider-1", "issuer": "https://idp.test", "subject": "s".repeat(300) },
            "sessionName": "ci-run", "sourceIdentity": "repo:acme/app", "uniqueKey": "u",
        }),
    );
    let context = audit_session_context(Some(&base)).unwrap();
    assert_eq!(
        serde_json::to_value(&context).unwrap(),
        json!({
            "sessionId": "session-1", "kind": "role", "roleId": "role-1", "trustId": "trust-1",
            "sessionName": "ci-run", "sourceIdentity": "repo:acme/app", "webIdentityProviderId": "provider-1",
            "webIdentitySubject": "s".repeat(256), "format": "jwt",
        })
    );
    let mut simulated = base.clone();
    simulated.id = "simulation".into();
    assert!(audit_session_context(Some(&simulated)).is_none());
    assert!(audit_session_context(None).is_none());
    let mut opaque = base;
    opaque.format = None;
    assert!(
        audit_session_context(Some(&opaque))
            .unwrap()
            .format
            .is_none()
    );
}

#[tokio::test]
async fn audit_events_chain_and_dispatch_after_commit() {
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let sink = seen.clone();
    let mut options = BetterIamOptions::new(memory_store(), SECRET, "http://localhost:3000");
    options.events = Some(EventOptions {
        on_event: Some(Arc::new(move |event| {
            sink.lock()
                .unwrap()
                .push(format!("callback:{}", event["action"].as_str().unwrap()));
            Box::pin(async { Ok(()) })
        })),
        ..EventOptions::default()
    });
    let ctx = migrated(options, NOW).await;
    let events = ctx.events().unwrap().clone();
    let actor = principal(
        identity("owner", "acme", json!({})),
        session("ses-1", "acme", "owner", json!({ "kind": "api-key" })),
    );
    let sink = seen.clone();
    let subscription = events
        .subscribe(
            &["iam:groups:*"],
            Arc::new(move |event| {
                sink.lock().unwrap().push(format!(
                    "groups:{}:{}",
                    event["action"].as_str().unwrap(),
                    event["tenantId"] == "acme"
                ));
                Box::pin(async { Ok(()) })
            }),
        )
        .unwrap();
    assert!(
        events
            .subscribe(&[""], Arc::new(|_| Box::pin(async { Ok(()) })))
            .is_err()
    );
    let (first, second) = (actor.clone(), actor.clone());
    let audited = events.clone();
    ctx.store
        .transaction(move |tx| async move {
            audited
                .audit(
                    &tx,
                    &first,
                    "iam:groups:create",
                    "acme",
                    "group-1",
                    AuditOutcome::Allow,
                    false,
                    None,
                )
                .await?;
            let mut metadata = Map::new();
            metadata.insert("reason".into(), json!("refused"));
            audited
                .audit(
                    &tx,
                    &second,
                    "iam:roles:create",
                    "acme",
                    "role-1",
                    AuditOutcome::Deny,
                    false,
                    Some(metadata),
                )
                .await
        })
        .await
        .unwrap();
    // A rolled-back mutation leaves no audit event and nothing to dispatch.
    let rolled = events.clone();
    let third = actor.clone();
    let failed: IamResult<()> = ctx
        .store
        .transaction(move |tx| async move {
            rolled
                .audit(
                    &tx,
                    &third,
                    "iam:groups:create",
                    "acme",
                    "group-2",
                    AuditOutcome::Allow,
                    false,
                    None,
                )
                .await?;
            Err(IamError::new("INVALID_INPUT", "Invalid name"))
        })
        .await;
    assert!(failed.is_err());
    let audit = all(&ctx, "audit").await;
    assert_eq!(audit.len(), 2);
    let first_event = audit
        .iter()
        .find(|event| event["resourceId"] == "group-1")
        .unwrap();
    assert_eq!(first_event["sequence"], json!(1));
    assert_eq!(first_event["actorId"], "owner");
    assert_eq!(first_event["rootOverride"], false);
    assert_eq!(
        first_event["sessionContext"],
        json!({ "sessionId": "ses-1", "kind": "api-key" })
    );
    let chain = verify_audit_chain(&audit, &VerifyAuditChainOptions::default());
    assert!(chain.valid, "{chain:?}");
    assert_eq!(chain.checked, 2);
    assert!(seen.lock().unwrap().is_empty());
    assert_eq!(events.dispatch().await.unwrap().dispatched, 2);
    // Rows are dispatched in store (id) order; for each event the callback runs before the subscribers.
    let dispatched = seen.lock().unwrap().clone();
    assert_eq!(dispatched.len(), 3);
    let position = |entry: &str| dispatched.iter().position(|item| item == entry).unwrap();
    assert!(position("callback:iam:groups:create") < position("groups:iam:groups:create:true"));
    assert!(dispatched.contains(&"callback:iam:roles:create".to_owned()));
    assert_eq!(events.dispatch().await.unwrap().dispatched, 0);
    let hooks = all(&ctx, "auditHooks").await;
    assert!(
        hooks
            .iter()
            .all(|hook| hook["delivered"] == true && hook["deliveredAt"].as_f64() == Some(NOW))
    );
    subscription.unsubscribe();
    let fourth = actor.clone();
    let audited = events.clone();
    ctx.store
        .transaction(move |tx| async move {
            audited
                .audit(
                    &tx,
                    &fourth,
                    "iam:groups:create",
                    "acme",
                    "group-3",
                    AuditOutcome::Allow,
                    false,
                    None,
                )
                .await
        })
        .await
        .unwrap();
    events.dispatch().await.unwrap();
    assert_eq!(seen.lock().unwrap().len(), 4);
    assert_eq!(seen.lock().unwrap()[3], "callback:iam:groups:create");
}

/// A loopback HTTP endpoint answering 500 first, then 204, recording each request.
async fn endpoint() -> (u16, Arc<Mutex<Vec<(String, String)>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let log = requests.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let log = log.clone();
            tokio::spawn(async move {
                let mut buffer = Vec::new();
                let mut chunk = [0u8; 4096];
                loop {
                    let read = socket.read(&mut chunk).await.unwrap_or(0);
                    if read == 0 {
                        break;
                    }
                    buffer.extend_from_slice(&chunk[..read]);
                    let text = String::from_utf8_lossy(&buffer).to_string();
                    if let Some(split) = text.find("\r\n\r\n") {
                        let head = text[..split].to_lowercase();
                        let length = head
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length:"))
                            .map(|value| value.trim().parse::<usize>().unwrap())
                            .unwrap_or(0);
                        if buffer.len() >= split + 4 + length {
                            let body = text[split + 4..split + 4 + length].to_owned();
                            let status = {
                                let mut log = log.lock().unwrap();
                                log.push((text[..split].to_owned(), body));
                                if log.len() == 1 {
                                    "500 Internal Server Error"
                                } else {
                                    "204 No Content"
                                }
                            };
                            let response = format!(
                                "HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                            );
                            let _ = socket.write_all(response.as_bytes()).await;
                            break;
                        }
                    }
                }
            });
        }
    });
    (port, requests)
}

#[tokio::test(flavor = "multi_thread")]
async fn webhooks_fan_out_through_the_outbox_and_the_built_in_transport() {
    let (port, requests) = endpoint().await;
    let options = BetterIamOptions::new(memory_store(), SECRET, "http://localhost:3000");
    let ctx = common::context(options, NOW);
    ctx.store.migrate().await.unwrap();
    tenants(&ctx).await;
    let events = ctx.events().unwrap().clone();
    // Endpoint rules: an http baseURL lets webhooks reach loopback endpoints over http.
    let url = events
        .webhook_url(Some(&json!(format!("http://127.0.0.1:{port}/ingest"))))
        .unwrap();
    let sealed = events.sealed_webhook_secret("hook-1").unwrap();
    assert!(sealed.secret.starts_with("whsec_"));
    put(&ctx, "webhooks", json!({
        "id": "hook-1", "tenantId": "root", "url": url, "events": ["iam:groups:create"], "active": true,
        "scope": "subtree", "secretSealed": sealed.sealed, "createdAt": 1, "updatedAt": 1, "createdBy": "root",
    }))
    .await;
    put(&ctx, "webhooks", json!({
        "id": "hook-2", "tenantId": "root", "url": url, "events": ["iam:groups:create"], "active": true,
        "scope": "tenant", "secretSealed": sealed.sealed, "createdAt": 1, "updatedAt": 1, "createdBy": "root",
    }))
    .await;
    put(&ctx, "webhooks", json!({
        "id": "hook-3", "tenantId": "acme", "url": url, "events": ["iam:roles:*"], "active": true,
        "scope": "tenant", "outcomes": ["deny"], "secretSealed": sealed.sealed, "createdAt": 1, "updatedAt": 1, "createdBy": "root",
    }))
    .await;
    let actor = principal(
        identity("owner", "acme", json!({})),
        session("ses-1", "acme", "owner", json!({})),
    );
    let audited = events.clone();
    ctx.store
        .transaction(move |tx| async move {
            audited
                .audit(
                    &tx,
                    &actor,
                    "iam:groups:create",
                    "acme",
                    "group-1",
                    AuditOutcome::Allow,
                    false,
                    None,
                )
                .await?;
            audited
                .audit(
                    &tx,
                    &actor,
                    "iam:roles:create",
                    "acme",
                    "role-1",
                    AuditOutcome::Allow,
                    false,
                    None,
                )
                .await
        })
        .await
        .unwrap();
    // Only the subtree subscription of the root tenant matches the organization's group event.
    let outbox = all(&ctx, "outbox").await;
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0]["to"], "hook-1");
    assert_eq!(outbox[0]["kind"], "webhook");
    assert_eq!(outbox[0]["tenantId"], "root");
    let first = ctx.auth.dispatch_outbox(None).await.unwrap();
    assert_eq!((first.delivered, first.failed), (0, 1));
    let failed = all(&ctx, "outbox").await;
    assert_eq!(
        failed[0]["lastError"],
        "IamError: Webhook endpoint responded with status 500"
    );
    // Retry past the backoff: the auth clock is fixed, so move the stored retry time instead.
    let mut retry = failed[0].clone();
    retry.insert("leaseUntil".into(), json!(0));
    let item = retry.clone();
    ctx.store
        .transaction(move |tx| async move { tx.put("outbox", &item).await.map(|_| ()) })
        .await
        .unwrap();
    let second = ctx.auth.dispatch_outbox(None).await.unwrap();
    let requests = requests.lock().unwrap().clone();
    assert_eq!((second.delivered, second.failed), (1, 0));
    assert_eq!(requests.len(), 2);
    let (head, body) = &requests[0];
    assert!(head.starts_with("POST /ingest HTTP/1.1"));
    let header = |name: &str| {
        head.lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case(name)
                    .then(|| value.trim().to_owned())
            })
            .unwrap()
    };
    assert_eq!(header("x-better-iam-event"), "iam:groups:create");
    assert_eq!(header("x-better-iam-webhook"), "hook-1");
    assert_eq!(header("user-agent"), "better-iam-webhooks/1");
    assert!(verify_webhook_signature(&VerifyWebhookInput {
        secret: &sealed.secret,
        timestamp: &json!(header("x-better-iam-timestamp")),
        body,
        signature: &header("x-better-iam-signature"),
        tolerance_seconds: None,
        now: Some(NOW),
    }));
    let parsed: Value = serde_json::from_str(body).unwrap();
    assert_eq!(parsed["type"], "iam:groups:create");
    assert_eq!(parsed["tenantId"], "acme");
    assert_eq!(parsed["sequence"], json!(1));
    // A paused subscription drops its pending deliveries; unreachable endpoints are reported without detail.
    put(&ctx, "webhooks", json!({
        "id": "hook-4", "tenantId": "root", "url": "http://127.0.0.1:1/x", "events": ["*"], "active": true,
        "scope": "tenant", "secretSealed": encrypt_secret(&sealed.secret, SECRET, "webhook:hook-4"), "createdAt": 1, "updatedAt": 1, "createdBy": "root",
    }))
    .await;
    let mut payload = Map::new();
    payload.insert("url".into(), json!("http://127.0.0.1:1/x"));
    payload.insert("body".into(), json!("{}"));
    let message = better_iam_auth::DeliveryMessage {
        id: "out-x".into(),
        tenant_id: "root".into(),
        to: "hook-4".into(),
        template: "iam:x".into(),
        payload: payload.clone(),
        sign_in_url: None,
    };
    let error = events
        .deliver_webhook_message(message.clone())
        .await
        .unwrap_err();
    assert_eq!(
        error.recorded(),
        "IamError: Webhook endpoint could not be reached"
    );
    let missing = better_iam_auth::DeliveryMessage {
        to: "hook-missing".into(),
        ..message.clone()
    };
    assert!(events.deliver_webhook_message(missing).await.is_ok());
    let mut incomplete = message;
    incomplete.payload.remove("body");
    assert_eq!(
        events
            .deliver_webhook_message(incomplete)
            .await
            .unwrap_err()
            .recorded(),
        "IamError: Webhook payload is incomplete"
    );
}

#[tokio::test]
async fn rotate_secrets_reseals_every_sealed_field() {
    const OLD: &str = "rotation-test-old-secret-with-plenty-of-characters-1";
    const NEW: &str = "rotation-test-new-secret-with-plenty-of-characters-2";
    const OTHER: &str = "rotation-test-unrelated-secret-with-many-characters-3";
    let mut options = BetterIamOptions::new(memory_store(), NEW, "http://localhost:3000");
    options.previous_secrets = Some(vec![OLD.to_owned()]);
    let ctx = migrated(options, NOW).await;
    put(&ctx, "authMfa", json!({ "id": "m1", "tenantId": "acme", "identityId": "i1", "encryptedSecret": encrypt_secret("JBSWY3DP", OLD, "mfa:i1") })).await;
    put(&ctx, "authMfa", json!({ "id": "m2", "tenantId": "acme", "identityId": "i2", "encryptedSecret": encrypt_secret("JBSWY3DQ", NEW, "mfa:i2") })).await;
    put(&ctx, "webhooks", json!({ "id": "w1", "tenantId": "acme", "secretSealed": encrypt_secret("whsec_1", OLD, "webhook:w1") })).await;
    put(&ctx, "outbox", json!({ "id": "o1", "tenantId": "acme", "payload": { "sealed": encrypt_secret("{}", OLD, "outbox:o1") } })).await;
    put(&ctx, "outbox", json!({ "id": "o2", "tenantId": "acme", "deliveredAt": 5, "payload": { "sealed": encrypt_secret("{}", OLD, "outbox:o2") } })).await;
    put(&ctx, "kmsKeyVersions", json!({ "id": "k1", "tenantId": "acme", "keyId": "key-1", "version": 2, "wrapper": "secret", "materialSealed": encrypt_secret("material", OLD, "kms-key:key-1:2") })).await;
    put(&ctx, "kmsKeyVersions", json!({ "id": "k2", "tenantId": "acme", "keyId": "key-2", "version": 1, "wrapper": "kms", "materialSealed": encrypt_secret("material", OLD, "kms-key:key-2:1") })).await;
    put(&ctx, "vaultVersions", json!({ "id": "v1", "tenantId": "acme", "secretId": "s1", "version": 3, "sealed": encrypt_secret("value", OLD, "vault:acme:s1:3") })).await;
    put(&ctx, "vaultVersions", json!({ "id": "v2", "tenantId": "acme", "secretId": "s2", "version": 1, "kmsKeyId": "key-1", "sealed": "kms-ciphertext" })).await;
    put(&ctx, "signalSources", json!({ "id": "src1", "tenantId": "acme", "poll": { "url": "https://ssf.example.com", "tokenSealed": encrypt_secret("token", OLD, "signal-poll:src1") } })).await;
    put(&ctx, "sshAuthorities", json!({ "id": "ssh1", "tenantId": "acme", "keySealed": encrypt_secret("key", OTHER, "ssh-authority:ssh1") })).await;
    let invalid = rotate_secrets(
        &ctx,
        &SecretRotationOptions {
            batch_size: Some(0.0),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        invalid.message,
        "batchSize must be an integer between 1 and 2000"
    );
    let invalid = rotate_secrets(
        &ctx,
        &SecretRotationOptions {
            limit: Some(1.5),
            ..Default::default()
        },
    )
    .await
    .unwrap_err();
    assert_eq!(invalid.message, "limit must be a positive integer");
    let dry = rotate_secrets(
        &ctx,
        &SecretRotationOptions {
            dry_run: true,
            batch_size: Some(1.0),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    common::assert_same(
        "dry run",
        &serde_json::to_value(&dry).unwrap(),
        &json!({
            "resealed": { "authMfa": 1, "webhooks": 1, "outbox": 1, "kmsKeyVersions": 1, "vaultVersions": 1, "signalSources": 1 },
            "unreadable": { "sshAuthorities": 1 }, "current": 1, "complete": true, "done": false,
        }),
    );
    // A sample (limit) is never complete.
    let sample = rotate_secrets(
        &ctx,
        &SecretRotationOptions {
            dry_run: true,
            limit: Some(1.0),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(!sample.complete && !sample.done);
    let applied = rotate_secrets(
        &ctx,
        &SecretRotationOptions {
            batch_size: Some(1.0),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(applied.resealed.values().sum::<f64>(), 6.0);
    assert!(applied.done);
    let check = |records: Vec<Map<String, Value>>,
                 read: &dyn Fn(&Map<String, Value>) -> Option<String>,
                 context: &dyn Fn(&Map<String, Value>) -> String| {
        for item in records {
            if let Some(sealed) = read(&item) {
                let opened = open_secret(&sealed, &[NEW, OLD], &context(&item));
                if let Some((_, index)) = opened {
                    assert_eq!(index, 0, "{item:?}");
                }
            }
        }
    };
    check(
        all(&ctx, "authMfa").await,
        &|r| r["encryptedSecret"].as_str().map(str::to_owned),
        &|r| format!("mfa:{}", r["identityId"].as_str().unwrap()),
    );
    let outbox = all(&ctx, "outbox").await;
    let delivered = outbox.iter().find(|r| r["id"] == "o2").unwrap();
    // Delivered messages are not touched.
    assert_eq!(
        open_secret(
            delivered["payload"]["sealed"].as_str().unwrap(),
            &[NEW, OLD],
            "outbox:o2"
        )
        .unwrap()
        .1,
        1
    );
    let pending = outbox.iter().find(|r| r["id"] == "o1").unwrap();
    assert_eq!(
        decrypt_secret(
            pending["payload"]["sealed"].as_str().unwrap(),
            &[NEW],
            "outbox:o1"
        )
        .unwrap(),
        "{}"
    );
    let kms = all(&ctx, "kmsKeyVersions").await;
    assert_eq!(
        open_secret(
            kms.iter().find(|r| r["id"] == "k1").unwrap()["materialSealed"]
                .as_str()
                .unwrap(),
            &[NEW],
            "kms-key:key-1:2"
        )
        .unwrap()
        .0,
        "material"
    );
    assert_eq!(
        open_secret(
            kms.iter().find(|r| r["id"] == "k2").unwrap()["materialSealed"]
                .as_str()
                .unwrap(),
            &[NEW, OLD],
            "kms-key:key-2:1"
        )
        .unwrap()
        .1,
        1
    );
    let vault = all(&ctx, "vaultVersions").await;
    assert_eq!(
        vault.iter().find(|r| r["id"] == "v2").unwrap()["sealed"],
        "kms-ciphertext"
    );
    let sources = all(&ctx, "signalSources").await;
    assert_eq!(sources[0]["poll"]["url"], "https://ssf.example.com");
    assert_eq!(
        decrypt_secret(
            sources[0]["poll"]["tokenSealed"].as_str().unwrap(),
            &[NEW],
            "signal-poll:src1"
        )
        .unwrap(),
        "token"
    );
    let again = rotate_secrets(
        &ctx,
        &SecretRotationOptions {
            dry_run: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(again.resealed.is_empty());
    assert_eq!(again.current, 7.0);
    assert!(again.done);
    assert_eq!(again.unreadable.get("sshAuthorities"), Some(&1.0));
}

// --- the guarded envelope ------------------------------------------------------------------------------------------

struct Principals(AuthenticatedPrincipal);

#[async_trait]
impl PrincipalService for Principals {
    async fn authenticate(&self, _input: &CredentialInput) -> IamResult<AuthenticatedPrincipal> {
        Ok(self.0.clone())
    }
    async fn current_principal(
        &self,
        _tx: &Store,
        principal: &AuthenticatedPrincipal,
    ) -> IamResult<AuthenticatedPrincipal> {
        Ok(principal.clone())
    }
}

/// Decisions as the suites configure them: `allowed` actions are granted on resources whose `owner` attribute is the
/// caller, everything else has no applicable grant. Effective bindings and role grants come from the test.
#[derive(Default)]
struct Decisions {
    allowed: Vec<String>,
    bindings: Vec<EffectiveBinding>,
    grants: IndexMap<String, Vec<PolicyDocument>>,
    sources: GrantSources,
}

fn not_needed() -> IamError {
    IamError::not_implemented("not used by this test")
}

#[async_trait]
impl DecisionService for Decisions {
    async fn role_grants(
        &self,
        _tx: &Store,
        role: &Role,
        _tenant_id: &str,
        _ceilings: &[PolicyDocument],
        authority_id: &str,
        _seen: Option<&mut IndexSet<String>>,
        _lapsed: Option<&mut Vec<GrantPath>>,
    ) -> IamResult<Vec<GrantPath>> {
        Ok(vec![GrantPath {
            grants: self.grants.get(&role.id).cloned().unwrap_or_default(),
            boundaries: Vec::new(),
            authority_id: authority_id.to_owned(),
        }])
    }
    async fn grant_sources(
        &self,
        _tx: &Store,
        _identity_id: &str,
        _tenant_id: &str,
    ) -> IamResult<GrantSources> {
        Ok(self.sources.clone())
    }
    async fn live_activations(
        &self,
        _tx: &Store,
        _tenant_id: &str,
        _identity_id: &str,
    ) -> IamResult<IndexMap<String, better_iam_server::models::BindingActivation>> {
        Err(not_needed())
    }
    async fn identity_grants(
        &self,
        _tx: &Store,
        _identity_id: &str,
        _tenant_id: &str,
        _sources: Option<&GrantSources>,
        _lapsed: Option<&mut Vec<GrantPath>>,
    ) -> IamResult<Vec<GrantPath>> {
        Err(not_needed())
    }
    async fn effective_bindings(
        &self,
        _tx: &Store,
        _tenant_id: &str,
        _identity_id: &str,
    ) -> IamResult<Vec<EffectiveBinding>> {
        Ok(self.bindings.clone())
    }
    async fn resolve(
        &self,
        _tx: &Store,
        _reference: &ResourceRef,
        _internal: bool,
        _action: Option<&str>,
        _known: Option<&better_iam_server::clearances::KnownLabeling>,
    ) -> IamResult<ResolvedResource> {
        Err(not_needed())
    }
    async fn prepare_decision(
        &self,
        _tx: &Store,
        principal: &AuthenticatedPrincipal,
        _target: &Tenant,
        action: &str,
    ) -> IamResult<PreparedDecision> {
        if action == "kms:list-nothing" {
            return Ok(PreparedDecision::Fixed(Decision {
                allowed: false,
                reason: "NO_APPLICABLE_GRANT".into(),
                matched: Vec::new(),
            }));
        }
        let granted = self.allowed.iter().any(|allowed| allowed == action);
        let caller = principal.identity.id.clone();
        Ok(PreparedDecision::Evaluator {
            evaluate: Arc::new(move |resource, _| {
                let owner = resource
                    .attributes
                    .as_ref()
                    .and_then(|attributes| attributes.get("owner"))
                    .and_then(Value::as_str);
                let allowed = granted && owner == Some(caller.as_str());
                Ok(Decision {
                    allowed,
                    reason: if allowed {
                        "ALLOWED".into()
                    } else {
                        "NO_APPLICABLE_GRANT".into()
                    },
                    matched: Vec::new(),
                })
            }),
            inputs: None,
            root_override: false,
        })
    }
    async fn decide(
        &self,
        _tx: &Store,
        _principal: &AuthenticatedPrincipal,
        _request: &AuthorizationRequest,
        _internal_resource: bool,
    ) -> IamResult<Decision> {
        Err(not_needed())
    }
    fn simulated_principal(&self, identity: &Identity, _mfa: bool) -> AuthenticatedPrincipal {
        principal(
            identity.clone(),
            session("simulation", &identity.tenant_id, &identity.id, json!({})),
        )
    }
}

fn target(id: &str, owner: &str) -> Target {
    Target {
        resource_id: format!("kms/{id}"),
        attributes: record(json!({ "owner": owner })),
    }
}

#[tokio::test]
async fn guarded_envelope_decides_audits_and_records_refusals() {
    let ctx = migrated(
        BetterIamOptions::new(memory_store(), SECRET, "http://localhost:3000"),
        NOW,
    )
    .await;
    let caller = principal(
        identity("alice", "acme", json!({})),
        session("ses-a", "acme", "alice", json!({})),
    );
    ctx.attach_principals(Arc::new(Principals(caller.clone())));
    ctx.attach_decisions(Arc::new(Decisions {
        allowed: vec!["kms:encrypt".into(), "kms:read".into()],
        ..Decisions::default()
    }));
    let mut options: GuardOptions<Target> = GuardOptions {
        describe: Some(Arc::new(|target: &Target| {
            record(json!({ "key": target.resource_id }))
        })),
        ..GuardOptions::default()
    };
    options
        .recorded_failures
        .insert("KEY_DISABLED".into(), "disabled".into());
    options.fallback = Some(Arc::new(|_, _, action, target: Target| {
        Box::pin(async move {
            Ok(
                (action == "kms:decrypt" && target.resource_id == "kms/granted")
                    .then(|| record(json!({ "grant": "grant-1" }))),
            )
        })
    }));
    let guard = create_guard(ctx.clone(), "kms", options);
    let credential = CredentialInput::default();
    let tenant = json!("acme");
    // Allowed by policy: runs, audits allow with the described target and what the call noted.
    let value: Value = guard
        .run(
            &credential,
            Some(&tenant),
            GuardAction::Fixed("kms:encrypt".into()),
            |_, _| Box::pin(async { Ok(target("k1", "alice")) }),
            |call, located| {
                Box::pin(async move {
                    call.note("bytes", json!(5));
                    let other = call.allowed("kms:read", &target("k2", "bob")).await?;
                    Ok(json!({ "target": located.resource_id, "other": other }))
                })
            },
        )
        .await
        .unwrap();
    assert_eq!(value, json!({ "target": "kms/k1", "other": false }));
    // Allowed through the fallback when no policy applies.
    guard
        .run(
            &credential,
            Some(&tenant),
            GuardAction::Of(Arc::new(|_: &Target| "kms:decrypt".to_owned())),
            |_, _| Box::pin(async { Ok(target("granted", "bob")) }),
            |_, _| Box::pin(async { Ok(json!(true)) }),
        )
        .await
        .unwrap();
    // Denied: only the deny audit commits.
    let denied = guard
        .run(
            &credential,
            Some(&tenant),
            GuardAction::Fixed("kms:encrypt".into()),
            |_, _| Box::pin(async { Ok(target("k3", "bob")) }),
            |_, _| Box::pin(async { Ok(json!(1)) }),
        )
        .await
        .unwrap_err();
    assert_eq!(
        (denied.code.as_str(), denied.status),
        ("ACCESS_DENIED", 403)
    );
    // A refusal inside the call rolls it back and is audited as refused.
    let refused = guard
        .run(
            &credential,
            Some(&tenant),
            GuardAction::Fixed("kms:encrypt".into()),
            |_, _| Box::pin(async { Ok(target("k4", "alice")) }),
            |call, _| {
                Box::pin(async move {
                    call.tx
                        .insert(
                            "kmsKeys",
                            &record(json!({ "id": "leak", "tenantId": "acme" })),
                        )
                        .await?;
                    Err::<Value, _>(OperationDenied::new(Some("Key is pending deletion")))
                })
            },
        )
        .await
        .unwrap_err();
    assert_eq!(refused.message, "Key is pending deletion");
    assert!(ctx.store.get("kmsKeys", "leak").await.unwrap().is_none());
    // A recorded failure code is audited with its reason; other failures are not.
    let failure = guard
        .run(
            &credential,
            Some(&tenant),
            GuardAction::Fixed("kms:encrypt".into()),
            |_, _| Box::pin(async { Ok(target("k5", "alice")) }),
            |_, _| {
                Box::pin(async {
                    Err::<Value, _>(IamError::new("KEY_DISABLED", "Key is disabled").into())
                })
            },
        )
        .await
        .unwrap_err();
    assert_eq!(failure.code, "KEY_DISABLED");
    guard
        .run(
            &credential,
            Some(&tenant),
            GuardAction::Fixed("kms:encrypt".into()),
            |_, _| Box::pin(async { Ok(target("k6", "alice")) }),
            |_, _| Box::pin(async { Err::<Value, _>(IamError::new("OTHER", "Other").into()) }),
        )
        .await
        .unwrap_err();
    // Another tenant's caller learns nothing: refused before the lookup, recorded on the collection.
    let lookups = Arc::new(AtomicU64::new(0));
    let counted = lookups.clone();
    let outsider = guard
        .run(
            &credential,
            Some(&json!("root")),
            GuardAction::Fixed("kms:encrypt".into()),
            move |_, _| {
                counted.fetch_add(1, Ordering::SeqCst);
                Box::pin(async { Ok(target("k7", "alice")) })
            },
            |_, _| Box::pin(async { Ok(json!(1)) }),
        )
        .await
        .unwrap_err();
    assert_eq!(outsider.code, "ACCESS_DENIED");
    assert_eq!(lookups.load(Ordering::SeqCst), 0);
    let unknown = guard
        .run(
            &credential,
            Some(&json!("")),
            GuardAction::Fixed("kms:encrypt".into()),
            |_, _| Box::pin(async { Ok(target("k8", "alice")) }),
            |_, _| Box::pin(async { Ok(json!(1)) }),
        )
        .await
        .unwrap_err();
    assert_eq!(unknown.message, "Invalid tenantId");
    // Listing: one allowed event with the count.
    let listed = guard
        .visible(&credential, Some(&tenant), "kms:read", "kms", |_, _| {
            Box::pin(async {
                Ok(vec![
                    ("mine", target("k1", "alice")),
                    ("theirs", target("k2", "bob")),
                ])
            })
        })
        .await
        .unwrap();
    assert_eq!(listed, vec!["mine"]);
    let nothing = guard
        .visible(
            &credential,
            Some(&tenant),
            "kms:list-nothing",
            "kms",
            |_, _| Box::pin(async { Ok(Vec::<(u8, Target)>::new()) }),
        )
        .await
        .unwrap_err();
    assert_eq!(nothing.code, "ACCESS_DENIED");
    let audit = all(&ctx, "audit").await;
    let summary: Vec<(String, String, String, Value)> = audit
        .iter()
        .map(|event| {
            (
                event["action"].as_str().unwrap().to_owned(),
                event["resourceId"].as_str().unwrap().to_owned(),
                event["outcome"].as_str().unwrap().to_owned(),
                event.get("metadata").cloned().unwrap_or(Value::Null),
            )
        })
        .collect();
    let expected = vec![
        (
            "kms:encrypt",
            "kms/k1",
            "allow",
            json!({ "key": "kms/k1", "bytes": 5 }),
        ),
        (
            "kms:decrypt",
            "kms/granted",
            "allow",
            json!({ "key": "kms/granted", "grant": "grant-1" }),
        ),
        ("kms:encrypt", "kms/k3", "deny", json!({ "key": "kms/k3" })),
        (
            "kms:encrypt",
            "kms/k4",
            "deny",
            json!({ "reason": "refused" }),
        ),
        (
            "kms:encrypt",
            "kms/k5",
            "deny",
            json!({ "reason": "disabled" }),
        ),
        ("kms:encrypt", "kms", "deny", json!({ "reason": "tenant" })),
        ("kms:read", "kms", "allow", json!({ "listed": 1 })),
        ("kms:list-nothing", "kms", "deny", Value::Null),
    ];
    let mut sorted = summary.clone();
    sorted.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    let mut expected: Vec<(String, String, String, Value)> = expected
        .into_iter()
        .map(|(a, b, c, d)| (a.to_owned(), b.to_owned(), c.to_owned(), d))
        .collect();
    expected.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    assert_eq!(sorted.len(), expected.len(), "{summary:?}");
    for (actual, wanted) in sorted.iter().zip(&expected) {
        assert_eq!(actual.0, wanted.0);
        assert_eq!(actual.1, wanted.1);
        assert_eq!(actual.2, wanted.2, "{actual:?}");
        assert!(
            better_iam_core::js::deep_equal(&actual.3, &wanted.3),
            "{actual:?} vs {wanted:?}"
        );
    }
    // Impersonation sessions are refused outright.
    let viewer = principal(
        identity("alice", "acme", json!({})),
        session(
            "ses-v",
            "acme",
            "alice",
            json!({ "impersonatorId": "root" }),
        ),
    );
    let ctx2 = migrated(
        BetterIamOptions::new(memory_store(), SECRET, "http://localhost:3000"),
        NOW,
    )
    .await;
    ctx2.attach_principals(Arc::new(Principals(viewer)));
    ctx2.attach_decisions(Arc::new(Decisions::default()));
    let guard2 = create_guard::<Target>(ctx2.clone(), "kms", GuardOptions::default());
    assert!(
        guard2
            .run(
                &credential,
                Some(&tenant),
                GuardAction::Fixed("kms:encrypt".into()),
                |_, _| Box::pin(async { Ok(target("k1", "alice")) }),
                |_, _| Box::pin(async { Ok(json!(1)) })
            )
            .await
            .is_err()
    );
    let audit = all(&ctx2, "audit").await;
    assert_eq!(audit[0]["metadata"], json!({ "reason": "impersonation" }));
    assert_eq!(audit[0]["impersonatorId"], "root");
}

// --- grant deadlines -----------------------------------------------------------------------------------------------

fn binding(id: &str, extra: Value) -> Binding {
    let mut value = json!({ "id": id, "tenantId": "acme", "subjectType": "identity", "subjectId": "alice", "roleId": "r1", "authorityId": "a1" });
    for (key, item) in extra.as_object().unwrap() {
        value[key] = item.clone();
    }
    serde_json::from_value(value).unwrap()
}

fn role(id: &str) -> Role {
    serde_json::from_value(
        json!({ "id": id, "tenantId": "acme", "name": id, "policyIds": [], "protected": false }),
    )
    .unwrap()
}

fn effective(binding: Binding, role_id: Option<&str>, via: BindingVia) -> EffectiveBinding {
    EffectiveBinding {
        binding,
        role: role_id.map(role),
        via,
        activation: None,
        pending_activation: None,
        in_window: None,
    }
}

#[tokio::test]
async fn grant_deadline_is_the_earliest_end_of_a_granting_source() {
    let ctx = migrated(
        BetterIamOptions::new(memory_store(), SECRET, "http://localhost:3000"),
        NOW,
    )
    .await;
    let horizon = NOW + 30.0 * 86_400_000.0;
    let ssh = |pattern: &str| -> PolicyDocument {
        serde_json::from_value(json!({ "version": 1, "statements": [{ "effect": "allow", "actions": [pattern], "resources": ["*"] }] })).unwrap()
    };
    let mut grants = IndexMap::new();
    grants.insert("r-ssh".to_owned(), vec![ssh("ssh:*")]);
    grants.insert("r-other".to_owned(), vec![ssh("vc:request")]);
    put(&ctx, "groupMembers", json!({ "id": "gm1", "tenantId": "acme", "groupId": "g1", "identityId": "alice", "expiresAt": NOW + 3_600_000.0 })).await;
    let mut activated = effective(
        binding("b4", json!({ "eligible": true })),
        Some("r-ssh"),
        BindingVia::Identity,
    );
    activated.activation = Some(ActivationSummary {
        id: "act".into(),
        activated_at: NOW,
        expires_at: NOW + 7_200_000.0,
    });
    let decisions = Decisions {
        bindings: vec![
            // Standing grant of the action: no limit.
            effective(
                binding("b1", json!({})),
                Some("r-ssh"),
                BindingVia::Identity,
            ),
            // Temporary, but grants something else.
            effective(
                binding("b2", json!({ "expiresAt": NOW + 60_000.0 })),
                Some("r-other"),
                BindingVia::Identity,
            ),
            // Through a group whose membership ends in an hour.
            effective(
                binding("b3", json!({ "subjectType": "group", "subjectId": "g1" })),
                Some("r-ssh"),
                BindingVia::Group("g1".into()),
            ),
            // A live activation ends in two hours.
            activated,
            // Eligible without activation, expired, or without a role: ignored.
            effective(
                binding("b5", json!({ "eligible": true, "expiresAt": NOW + 1.0 })),
                Some("r-ssh"),
                BindingVia::Identity,
            ),
            effective(
                binding("b6", json!({ "expiresAt": NOW - 1.0 })),
                Some("r-ssh"),
                BindingVia::Identity,
            ),
            effective(
                binding("b7", json!({ "expiresAt": NOW + 1.0 })),
                None,
                BindingVia::Identity,
            ),
        ],
        grants,
        ..Decisions::default()
    };
    ctx.attach_decisions(Arc::new(decisions));
    let alice = principal(
        identity("alice", "acme", json!({})),
        session("s", "acme", "alice", json!({})),
    );
    let store = ctx.store.clone();
    let deadline = grant_deadline(&ctx, &store, &alice, "acme", horizon, "ssh:login")
        .await
        .unwrap();
    assert_eq!(deadline, NOW + 3_600_000.0);
    // Temporary sessions and other tenants are bounded by their session instead.
    let role_session = principal(
        identity("alice", "acme", json!({})),
        session("s", "acme", "alice", json!({ "kind": "role" })),
    );
    assert_eq!(
        grant_deadline(&ctx, &store, &role_session, "acme", horizon, "ssh:login")
            .await
            .unwrap(),
        horizon
    );
    assert_eq!(
        grant_deadline(&ctx, &store, &alice, "root", horizon, "ssh:login")
            .await
            .unwrap(),
        horizon
    );
    assert_eq!(
        grant_deadline(&ctx, &store, &alice, "acme", horizon, "vc:request")
            .await
            .unwrap(),
        NOW + 60_000.0
    );
}

// --- record helpers ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn record_helpers_follow_the_typescript_rules() {
    let ctx = migrated(
        BetterIamOptions::new(memory_store(), SECRET, "http://localhost:3000"),
        NOW,
    )
    .await;
    let store = ctx.store.clone();
    let acme = ctx.tenant(&store, "acme").await.unwrap();
    assert_eq!(ctx.ancestry(&store, &acme).await.unwrap().len(), 2);
    assert_eq!(
        ctx.ancestor_ids(&store, "acme").await.unwrap(),
        vec!["acme", "root"]
    );
    assert_eq!(
        ctx.ancestor_ids(&store, "gone").await.unwrap(),
        vec!["gone"]
    );
    assert_eq!(
        ctx.tenant(&store, "nope").await.unwrap_err().message,
        "Tenant not found"
    );
    assert_eq!(
        ctx.tenant(&store, " ").await.unwrap_err().message,
        "Invalid tenantId"
    );
    put(&ctx, "tenants", json!({ "id": "loop-a", "tenantId": "loop-a", "name": "A", "type": "organization", "reference": null, "parentId": "loop-b", "status": "active", "createdAt": 1 })).await;
    put(&ctx, "tenants", json!({ "id": "loop-b", "tenantId": "loop-b", "name": "B", "type": "organization", "reference": null, "parentId": "loop-a", "status": "active", "createdAt": 1 })).await;
    let looped = ctx.tenant(&store, "loop-a").await.unwrap();
    let error = ctx.ancestry(&store, &looped).await.unwrap_err();
    assert_eq!(
        (error.code.as_str(), error.status),
        ("INVALID_HIERARCHY", 500)
    );
    // Grant authorities.
    let admin = identity("admin", "acme", json!({}));
    let user = principal(admin.clone(), session("s1", "acme", "admin", json!({})));
    let error = ctx
        .granting_authority(&store, &user, "acme", None)
        .await
        .unwrap_err();
    assert_eq!(error.code, "GRANT_AUTHORITY_REQUIRED");
    put(&ctx, "grantAuthorities", json!({ "id": "parent", "tenantId": "acme", "identityId": "root-admin", "ceiling": all_value(), "revoked": false })).await;
    put(&ctx, "grantAuthorities", json!({ "id": "delegated", "tenantId": "acme", "identityId": "admin", "ceiling": all_value(), "parentAuthorityId": "parent", "revoked": false })).await;
    let authority: GrantAuthority = ctx
        .granting_authority(&store, &user, "acme", None)
        .await
        .unwrap();
    assert_eq!(authority.id, "delegated");
    assert_eq!(
        ctx.authority_chain(&store, "delegated")
            .await
            .unwrap()
            .unwrap()
            .len(),
        2
    );
    let error = ctx
        .granting_authority(&store, &user, "acme", Some("parent"))
        .await
        .unwrap_err();
    assert_eq!(
        error.message,
        "Cannot use another administrator\u{2019}s grant authority"
    );
    put(&ctx, "grantAuthorities", json!({ "id": "parent", "tenantId": "acme", "identityId": "root-admin", "ceiling": all_value(), "revoked": true })).await;
    assert!(
        ctx.authority_chain(&store, "delegated")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        ctx.granting_authority(&store, &user, "acme", None)
            .await
            .unwrap_err()
            .code,
        "GRANT_AUTHORITY_REQUIRED"
    );
    let viewer = principal(
        admin.clone(),
        session("s2", "acme", "admin", json!({ "impersonatorId": "x" })),
    );
    assert_eq!(
        ctx.granting_authority(&store, &viewer, "acme", None)
            .await
            .unwrap_err()
            .code,
        "IMPERSONATION_RESTRICTED"
    );
    // Root: an MFA user session of a root-tenant root administrator gets a root-issued authority once.
    let root = principal(
        identity("root-admin", "root", json!({ "rootAdmin": true })),
        session("s3", "root", "root-admin", json!({ "mfa": true })),
    );
    assert!(ctx.root_principal(&store, &root).await.unwrap());
    let issued = store
        .transaction({
            let (ctx, root) = (ctx.clone(), root.clone());
            move |tx| async move { ctx.granting_authority(&tx, &root, "acme", None).await }
        })
        .await
        .unwrap();
    assert_eq!(issued.extra.get("rootIssued"), Some(&json!(true)));
    assert_eq!(
        ctx.granting_authority(&store, &root, "acme", None)
            .await
            .unwrap()
            .id,
        issued.id
    );
    let no_mfa = principal(
        root.identity.clone(),
        session("s4", "root", "root-admin", json!({})),
    );
    assert!(!ctx.root_principal(&store, &no_mfa).await.unwrap());
    let error = ctx
        .can_edit_grant_resource(
            &store,
            &user,
            &record(json!({ "id": "r", "tenantId": "acme" })),
        )
        .await
        .unwrap_err();
    assert_eq!(
        (error.code.as_str(), error.status),
        ("PROTECTED_RESOURCE", 403)
    );
    ctx.can_edit_grant_resource(
        &store,
        &root,
        &record(json!({ "id": "r", "tenantId": "acme" })),
    )
    .await
    .unwrap();
    // Owners, limits, slugs, scoped records.
    let owner = identity("o1", "acme", json!({ "owner": true }));
    put(&ctx, "identities", serde_json::to_value(&owner).unwrap()).await;
    assert_eq!(
        ctx.protect_last_owner(&store, &owner)
            .await
            .unwrap_err()
            .code,
        "LAST_OWNER"
    );
    put(
        &ctx,
        "identities",
        serde_json::to_value(identity("o2", "acme", json!({ "owner": true }))).unwrap(),
    )
    .await;
    ctx.protect_last_owner(&store, &owner).await.unwrap();
    let mut limited = acme.clone();
    limited.limits = Some(better_iam_core::TenantLimits {
        roles: Some(2.0),
        ..Default::default()
    });
    let error = ctx
        .enforce_limit(&limited, "roles", || async { Ok(2.0) }, None)
        .await
        .unwrap_err();
    assert_eq!(error.message, "This tenant has reached its role limit (2)");
    assert_eq!(error.status, 409);
    ctx.enforce_limit(&limited, "roles", || async { Ok(1.0) }, None)
        .await
        .unwrap();
    ctx.enforce_limit(&limited, "groups", || async { Ok(100.0) }, None)
        .await
        .unwrap();
    let claimed = store
        .transaction({
            let ctx = ctx.clone();
            move |tx| async move { ctx.claim_slug(&tx, "acme", Some(&json!("Acme"))).await }
        })
        .await
        .unwrap();
    assert_eq!(claimed, "acme");
    let taken = store
        .transaction({
            let ctx = ctx.clone();
            move |tx| async move { ctx.claim_slug(&tx, "other", Some(&json!("acme"))).await }
        })
        .await
        .unwrap_err();
    assert_eq!((taken.code.as_str(), taken.status), ("SLUG_TAKEN", 409));
    assert_eq!(
        ctx.scoped(&store, "identities", Some(&json!("o1")), "root")
            .await
            .unwrap_err()
            .message,
        "Resource not found"
    );
    assert_eq!(
        ctx.active_identity(&store, "o1", "acme").await.unwrap().id,
        "o1"
    );
    assert_eq!(
        ctx.service_account(&store, "o1", "acme")
            .await
            .unwrap_err()
            .message,
        "Service account not found"
    );
    // Owner setup writes the protected Owner policy, role and binding.
    let authority = issued.clone();
    let realm = acme.clone();
    let person = owner.clone();
    let setup = ctx.clone();
    store
        .transaction(
            move |tx| async move { setup.owner_setup(&tx, &realm, &person, &authority).await },
        )
        .await
        .unwrap();
    let policies = all(&ctx, "policies").await;
    assert_eq!(policies[0]["uniqueKey"], "system:owner");
    assert_eq!(policies[0]["document"], all_value());
    let roles = all(&ctx, "roles").await;
    assert_eq!(roles[0]["policyIds"], json!([policies[0]["id"]]));
    assert_eq!(roles[0]["protected"], true);
    let bindings = all(&ctx, "bindings").await;
    assert_eq!(bindings[0]["subjectId"], "o1");
    assert_eq!(bindings[0]["roleId"], roles[0]["id"]);
    assert_eq!(
        store
            .get("grantAuthorities", &issued.id)
            .await
            .unwrap()
            .unwrap()["identityId"],
        "o1"
    );
    // Live bindings and memberships.
    assert!(ctx.live_binding(&binding(
        "x",
        json!({ "startsAt": NOW, "expiresAt": NOW + 1.0 })
    )));
    assert!(!ctx.live_binding(&binding("x", json!({ "startsAt": NOW + 1.0 }))));
    assert!(ctx.expired_binding(&binding("x", json!({ "expiresAt": NOW }))));
    assert!(!ctx.expired_binding(&binding("x", json!({ "startsAt": NOW + 5.0 }))));
    assert!(ctx.identity_expired(&identity("e", "acme", json!({ "expiresAt": NOW }))));
    // The revocation of every session of an identity, including assumed-role sessions.
    put(
        &ctx,
        "sessions",
        serde_json::to_value(session("own", "acme", "o1", json!({}))).unwrap(),
    )
    .await;
    put(
        &ctx,
        "sessions",
        serde_json::to_value(session(
            "assumed",
            "root",
            "role-x",
            json!({ "kind": "role", "originalIdentityId": "o1" }),
        ))
        .unwrap(),
    )
    .await;
    put(
        &ctx,
        "sessions",
        serde_json::to_value(session("other", "acme", "o2", json!({}))).unwrap(),
    )
    .await;
    let revoke = ctx.clone();
    store
        .transaction(move |tx| async move { revoke.revoke_all(&tx, "o1").await })
        .await
        .unwrap();
    let left: Vec<Value> = all(&ctx, "sessions")
        .await
        .into_iter()
        .map(|row| row["id"].clone())
        .collect();
    assert_eq!(left, vec![json!("other")]);
}

#[tokio::test]
async fn confirmations_are_used_once_per_transaction() {
    let ctx = migrated(
        BetterIamOptions::new(memory_store(), SECRET, "http://localhost:3000"),
        NOW,
    )
    .await;
    put(
        &ctx,
        "delegations",
        json!({ "id": "d1", "tenantId": "acme", "confirm": ["kms:*"] }),
    )
    .await;
    for (id, expires) in [
        ("c-late", NOW + 9_000.0),
        ("c-soon", NOW + 1_000.0),
        ("c-expired", NOW - 1.0),
    ] {
        put(&ctx, "delegationConfirmations", json!({
            "id": id, "tenantId": "acme", "delegationId": "d1", "action": "kms:encrypt", "resourceType": "iam",
            "resourceId": "kms/k1", "status": "approved", "expiresAt": expires,
        }))
        .await;
    }
    let agent = principal(
        identity("agent", "acme", json!({ "kind": "agent" })),
        session(
            "s",
            "acme",
            "agent",
            json!({ "kind": "delegated", "delegationId": "d1" }),
        ),
    );
    let first = agent.clone();
    ctx.store
        .transaction(move |tx| async move {
            use_confirmation(&tx, &first, "kms:encrypt", "iam", "kms/k1", NOW).await?;
            // Checked again in the same transaction: the approval it used still opens the call.
            use_confirmation(&tx, &first, "kms:encrypt", "iam", "kms/k1", NOW).await
        })
        .await
        .unwrap();
    let rows = all(&ctx, "delegationConfirmations").await;
    let status = |id: &str| rows.iter().find(|row| row["id"] == id).unwrap()["status"].clone();
    assert_eq!(status("c-soon"), "used");
    assert_eq!(status("c-late"), "approved");
    assert_eq!(
        rows.iter().find(|row| row["id"] == "c-soon").unwrap()["usedAt"].as_f64(),
        Some(NOW)
    );
    // A new transaction uses the next approval; actions the delegation does not hold back are untouched.
    let second = agent.clone();
    ctx.store
        .transaction(move |tx| async move {
            use_confirmation(&tx, &second, "kms:encrypt", "iam", "kms/k1", NOW).await?;
            use_confirmation(&tx, &second, "vault:read", "iam", "kms/k1", NOW).await
        })
        .await
        .unwrap();
    let rows = all(&ctx, "delegationConfirmations").await;
    assert_eq!(
        rows.iter().find(|row| row["id"] == "c-late").unwrap()["status"],
        "used"
    );
    assert_eq!(
        rows.iter().find(|row| row["id"] == "c-expired").unwrap()["status"],
        "approved"
    );
}
