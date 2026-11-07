//! Webhook subscriptions (tests/events.test.ts `webhooks`, tests/bulk-and-redelivery.test.ts redelivery). The
//! TypeScript tests produce audit events through the `identities` and `groups` groups; these produce them through
//! `domains.add` (`iam:domains:create`), which is part of this unit.

mod directory_support;

use std::sync::{Arc, Mutex};

use better_iam_auth::DeliveryError;
use better_iam_core::{Filter, FindOptions, PermissionsConfig};
use better_iam_server::events::{VerifyWebhookInput, verify_webhook_signature};
use better_iam_server::options::{EventOptions, ResolvedResource, WebhookDelivery};
use directory_support::{Fixture, Org, body, err, fixture, ok, run};
use serde_json::{Value, json};

struct Webhooks {
    f: Fixture,
    org: Org,
    deliveries: Arc<Mutex<Vec<WebhookDelivery>>>,
    reject: Arc<Mutex<bool>>,
}

async fn setup() -> Webhooks {
    let deliveries: Arc<Mutex<Vec<WebhookDelivery>>> = Arc::default();
    let reject: Arc<Mutex<bool>> = Arc::default();
    let (sink, failing) = (deliveries.clone(), reject.clone());
    let f = fixture(
        "events-test-secret-with-at-least-32-characters",
        move |options| {
            options
                .authentication
                .as_mut()
                .unwrap()
                .max_delivery_attempts = Some(3.0);
            options.events = Some(EventOptions {
                deliver_webhook: Some(Arc::new(move |delivery| {
                    let refused = *failing.lock().unwrap();
                    if !refused {
                        sink.lock().unwrap().push(delivery);
                    }
                    Box::pin(async move {
                        if refused {
                            Err(DeliveryError::new("Error", "endpoint down"))
                        } else {
                            Ok(())
                        }
                    })
                })),
                ..EventOptions::default()
            });
            options.permissions = Some(PermissionsConfig {
                actions: Some(vec!["documents:read".into()]),
                ..PermissionsConfig::default()
            });
            options.resolve_resource = Some(Arc::new(|reference| {
                Box::pin(async move { Ok(ResolvedResource::of(&reference)) })
            }));
        },
    )
    .await;
    let org = f.organization("Acme", "owner@acme.test").await;
    Webhooks {
        f,
        org,
        deliveries,
        reject,
    }
}

impl Webhooks {
    /// An audited change in the organization: `domains.add`.
    async fn change(&self, domain: &str) {
        ok(self
            .f
            .iam
            .api
            .domains
            .add(
                &self.org.owner,
                body(json!({ "tenantId": self.org.tenant_id, "domain": domain })),
            )
            .await);
    }

    async fn dispatch(&self) -> (u32, u32, u32) {
        let result = self.f.iam.auth.dispatch_outbox(None).await.unwrap();
        (result.delivered, result.failed, result.abandoned)
    }

    fn delivered(&self) -> Vec<WebhookDelivery> {
        self.deliveries.lock().unwrap().clone()
    }

    fn set_reject(&self, value: bool) {
        *self.reject.lock().unwrap() = value;
    }
}

fn signed(secret: &str, delivery: &WebhookDelivery, now: f64, body_suffix: &str) -> bool {
    let timestamp = Value::String(delivery.headers["x-better-iam-timestamp"].clone());
    let body = format!("{}{body_suffix}", delivery.body);
    verify_webhook_signature(&VerifyWebhookInput {
        secret,
        timestamp: &timestamp,
        body: &body,
        signature: &delivery.headers["x-better-iam-signature"],
        tolerance_seconds: None,
        now: Some(now),
    })
}

#[test]
fn delivers_signed_events_for_matching_subscriptions_through_the_outbox_and_exposes_delivery_history()
 {
    run(|| async {
        let w = setup().await;
        let (f, org) = (&w.f, &w.org);
        let api = &f.iam.api.webhooks;
        for input in [
            json!({ "url": "http://hooks.example.test/iam", "events": ["*"] }),
            json!({ "url": "https://user:pw@hooks.example.test/iam", "events": ["*"] }),
            json!({ "url": "https://hooks.example.test/iam", "events": ["bad pattern"] }),
            json!({ "url": "https://hooks.example.test/iam", "events": ["*"], "scope": "galaxy" }),
            json!({ "url": "https://hooks.example.test/iam", "events": ["*"], "outcomes": ["maybe"] }),
            json!({ "url": "https://hooks.example.test/iam", "events": ["*"], "resources": [] }),
        ] {
            let mut input = input;
            input["tenantId"] = json!(org.tenant_id);
            assert_eq!(
                err(api.create(&org.owner, body(input.clone())).await).code,
                "INVALID_INPUT",
                "{input}"
            );
        }
        let subtree = err(api
            .create(
                &org.owner,
                body(json!({
                    "tenantId": org.tenant_id,
                    "url": "https://hooks.example.test/iam",
                    "events": ["*"],
                    "scope": "subtree",
                })),
            )
            .await);
        assert_eq!(subtree.code, "ACCESS_DENIED");
        let created = ok(api
            .create(
                &org.owner,
                body(json!({
                    "tenantId": org.tenant_id,
                    "url": "https://hooks.example.test/iam",
                    "events": ["iam:domains:*"],
                    "description": "SIEM",
                    "outcomes": ["allow", "allow"],
                })),
            )
            .await);
        let (webhook, secret) = (
            created["webhook"].clone(),
            created["secret"].as_str().unwrap().to_owned(),
        );
        assert!(secret.starts_with("whsec_"));
        assert!(webhook.get("secretSealed").is_none());
        assert_eq!(webhook["active"], json!(true));
        assert_eq!(webhook["scope"], json!("tenant"));
        assert_eq!(webhook["outcomes"], json!(["allow"]));
        assert_eq!(webhook["createdBy"], json!(org.owner_id));
        let webhook_id = webhook["id"].as_str().unwrap().to_owned();
        let listed = ok(api
            .list(&org.owner, body(json!({ "tenantId": org.tenant_id })))
            .await);
        assert_eq!(listed, json!([webhook.clone()]));
        let stored = f
            .iam
            .store
            .find("webhooks", &Filter::new(), &FindOptions::default())
            .await
            .unwrap();
        assert!(!json!(stored).to_string().contains(&secret));
        let fetched = ok(api
            .get(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "webhookId": webhook_id })),
            )
            .await);
        assert_eq!(fetched, webhook);

        w.change("one.example").await;
        w.change("two.example").await;
        assert_eq!(w.dispatch().await, (2, 0, 0));
        let deliveries = w.delivered();
        assert!(
            deliveries
                .iter()
                .all(|delivery| delivery.event == "iam:domains:create")
        );
        let first = &deliveries[0];
        assert_eq!(first.webhook_id, webhook_id);
        assert_eq!(first.url, "https://hooks.example.test/iam");
        assert_eq!(first.tenant_id, org.tenant_id);
        let event: Value = serde_json::from_str(&first.body).unwrap();
        assert_eq!(event["type"], json!("iam:domains:create"));
        assert_eq!(event["tenantId"], json!(org.tenant_id));
        assert_eq!(event["actorId"], json!(org.owner_id));
        assert_eq!(event["outcome"], json!("allow"));
        assert_eq!(first.headers["x-better-iam-event"], "iam:domains:create");
        assert_eq!(first.headers["x-better-iam-webhook"], webhook_id);
        assert!(signed(&secret, first, f.now(), ""));
        assert!(!signed("whsec_wrong", first, f.now(), ""));
        assert!(!signed(&secret, first, f.now() + 10.0 * 60_000.0, ""));
        assert!(!signed(&secret, first, f.now(), " "));

        // Failures back off, retry, and are abandoned after the configured attempts; history never carries payloads.
        w.set_reject(true);
        w.change("three.example").await;
        assert_eq!(w.dispatch().await, (0, 1, 0));
        assert_eq!(w.dispatch().await, (0, 0, 0));
        f.advance(31_000.0);
        assert_eq!(w.dispatch().await, (0, 1, 0));
        f.advance(61_000.0);
        assert_eq!(w.dispatch().await, (0, 1, 1));
        let history = ok(api
            .list_deliveries(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "webhookId": webhook_id })),
            )
            .await);
        let history = history.as_array().unwrap();
        let mut summary: Vec<(String, String, f64)> = history
            .iter()
            .map(|item| {
                (
                    item["event"].as_str().unwrap().to_owned(),
                    item["status"].as_str().unwrap().to_owned(),
                    item["attempts"].as_f64().unwrap(),
                )
            })
            .collect();
        summary.sort_by(|a, b| a.partial_cmp(b).unwrap());
        assert_eq!(
            summary,
            vec![
                ("iam:domains:create".into(), "delivered".into(), 1.0),
                ("iam:domains:create".into(), "delivered".into(), 1.0),
                ("iam:domains:create".into(), "failed".into(), 3.0),
            ]
        );
        let abandoned = history
            .iter()
            .find(|item| item["status"] == json!("failed"))
            .unwrap();
        assert!(
            abandoned["lastError"]
                .as_str()
                .unwrap()
                .contains("endpoint down")
        );
        assert!(abandoned.get("payload").is_none());
        assert!(abandoned["failedAt"].is_number());
        assert!(abandoned["eventId"].is_string());
        let limited = ok(api
            .list_deliveries(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "webhookId": webhook_id, "limit": 1 })),
            )
            .await);
        assert_eq!(limited.as_array().unwrap().len(), 1);
        w.set_reject(false);

        // Rotation signs later deliveries with the new secret; pausing drops pending deliveries; ping verifies an
        // endpoint.
        let rotated = ok(api
            .rotate_secret(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "webhookId": webhook_id })),
            )
            .await);
        let rotated_secret = rotated["secret"].as_str().unwrap().to_owned();
        assert_ne!(rotated_secret, secret);
        assert!(rotated["webhook"].get("secretSealed").is_none());
        let pinged = ok(api
            .ping(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "webhookId": webhook_id })),
            )
            .await);
        assert!(pinged["deliveryId"].is_string());
        w.dispatch().await;
        let ping = w.delivered().last().cloned().unwrap();
        assert_eq!(ping.event, "webhook:ping");
        assert!(signed(&rotated_secret, &ping, f.now(), ""));
        let ping_body: Value = serde_json::from_str(&ping.body).unwrap();
        assert_eq!(ping_body["type"], json!("webhook:ping"));
        assert_eq!(ping_body["resourceId"], json!(webhook_id));
        assert_eq!(ping_body["actorId"], json!(org.owner_id));
        ok(api
            .update(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "webhookId": webhook_id, "active": false, "events": ["*"] })),
            )
            .await);
        assert_eq!(
            err(api
                .ping(
                    &org.owner,
                    body(json!({ "tenantId": org.tenant_id, "webhookId": webhook_id })),
                )
                .await)
            .code,
            "INVALID_TRANSITION"
        );
        w.change("paused.example").await;
        assert_eq!(w.dispatch().await, (0, 0, 0));
        assert_eq!(w.delivered().last().unwrap().event, "webhook:ping");
        ok(api
            .update(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "webhookId": webhook_id, "active": true })),
            )
            .await);
        w.change("resumed.example").await;
        w.dispatch().await;
        // Resuming is itself audited after the subscription is active again, so both events arrive.
        let delivered = w.delivered();
        let mut last: Vec<&str> = delivered[delivered.len() - 2..]
            .iter()
            .map(|delivery| delivery.event.as_str())
            .collect();
        last.sort();
        assert_eq!(last, vec!["iam:domains:create", "iam:webhooks:update"]);
        // Another tenant's events are never delivered to this subscription.
        let globex = f.organization("Globex", "owner@globex.test").await;
        ok(f.iam
            .api
            .domains
            .add(
                &globex.owner,
                body(json!({ "tenantId": globex.tenant_id, "domain": "globex.example" })),
            )
            .await);
        w.dispatch().await;
        assert!(
            w.delivered()
                .iter()
                .all(|delivery| delivery.tenant_id == org.tenant_id)
        );
        // A member without iam:webhooks:read cannot read the subscription.
        let member = f.member(org, "member").await;
        assert_eq!(
            err(api
                .get(
                    &member.credential,
                    body(json!({ "tenantId": org.tenant_id, "webhookId": webhook_id })),
                )
                .await)
            .code,
            "ACCESS_DENIED"
        );
        // Deleting the subscription clears its queue.
        w.change("queued.example").await;
        ok(api
            .delete(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "webhookId": webhook_id })),
            )
            .await);
        let remaining = f
            .iam
            .store
            .find(
                "outbox",
                &Filter::new()
                    .eq("tenantId", org.tenant_id.clone())
                    .eq("kind", "webhook")
                    .eq("to", webhook_id.clone()),
                &FindOptions::default(),
            )
            .await
            .unwrap();
        assert!(!remaining.is_empty());
        assert!(remaining.iter().all(|message| {
            message.get("deliveredAt").is_some() || message.get("failedAt").is_some()
        }));
        assert_eq!(w.dispatch().await, (0, 0, 0));
        assert_eq!(
            err(api
                .get(
                    &org.owner,
                    body(json!({ "tenantId": org.tenant_id, "webhookId": webhook_id })),
                )
                .await)
            .status,
            404
        );
    });
}

#[test]
fn redelivers_a_webhook_event_from_its_audit_record() {
    run(|| async {
        let w = setup().await;
        let (f, org) = (&w.f, &w.org);
        let api = &f.iam.api.webhooks;
        let created = ok(api
            .create(
                &org.owner,
                body(json!({
                    "tenantId": org.tenant_id,
                    "url": "https://hooks.example.test/iam",
                    "events": ["iam:domains:*"],
                })),
            )
            .await);
        let webhook_id = created["webhook"]["id"].as_str().unwrap().to_owned();
        w.set_reject(true);
        // One attempt per dispatch until abandoned.
        w.change("team.example").await;
        assert_eq!(w.dispatch().await, (0, 1, 0));
        f.advance(31_000.0);
        w.dispatch().await;
        f.advance(61_000.0);
        assert_eq!(w.dispatch().await, (0, 1, 1));
        let history = ok(api
            .list_deliveries(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "webhookId": webhook_id })),
            )
            .await);
        let failed = history
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["event"] == json!("iam:domains:create"))
            .unwrap()
            .clone();
        assert_eq!(failed["status"], json!("failed"));
        assert!(failed["eventId"].is_string());
        w.set_reject(false);
        let queued = ok(api
            .redeliver(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "webhookId": webhook_id, "deliveryId": failed["id"] })),
            )
            .await);
        assert_eq!(queued["eventId"], failed["eventId"]);
        assert_eq!(w.dispatch().await, (1, 0, 0));
        let replayed = w
            .delivered()
            .into_iter()
            .find(|delivery| json!(delivery.id) == queued["deliveryId"])
            .expect("redelivered");
        let event: Value = serde_json::from_str(&replayed.body).unwrap();
        assert_eq!(event["id"], failed["eventId"]);
        assert_eq!(event["type"], json!("iam:domains:create"));
        assert_eq!(event["resourceId"], json!("domains/team.example"));
        let missing = err(api
            .redeliver(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "webhookId": webhook_id, "deliveryId": "out_missing" })),
            )
            .await);
        assert_eq!(missing.code, "NOT_FOUND");
        // A ping cannot be rebuilt: it has no audit record.
        let ping = ok(api
            .ping(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "webhookId": webhook_id })),
            )
            .await);
        let refused = err(api
            .redeliver(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "webhookId": webhook_id, "deliveryId": ping["deliveryId"] })),
            )
            .await);
        assert_eq!(refused.code, "INVALID_TRANSITION");
        assert_eq!(refused.message, "This delivery cannot be rebuilt");
    });
}

#[test]
fn keeps_subtree_subscriptions_platform_controlled() {
    run(|| async {
        let w = setup().await;
        let (f, org) = (&w.f, &w.org);
        let api = &f.iam.api.webhooks;
        // Root subscribes a platform endpoint to its whole subtree.
        let platform = ok(api
            .create(
                &f.root,
                body(json!({
                    "tenantId": f.root_tenant_id,
                    "url": "https://platform.example.test/ingest",
                    "events": ["iam:domains:create"],
                    "scope": "subtree",
                })),
            )
            .await);
        assert_eq!(platform["webhook"]["scope"], json!("subtree"));
        w.change("acme.example").await;
        assert_eq!(w.dispatch().await, (1, 0, 0));
        let delivery = w.delivered().last().cloned().unwrap();
        assert_eq!(delivery.event, "iam:domains:create");
        assert!(signed(
            platform["secret"].as_str().unwrap(),
            &delivery,
            f.now(),
            ""
        ));
        let event: Value = serde_json::from_str(&delivery.body).unwrap();
        assert_eq!(event["tenantId"], json!(org.tenant_id));
        // A subtree subscription root placed in the organization stays root's.
        let placed = ok(api
            .create(
                &f.root,
                body(json!({
                    "tenantId": org.tenant_id,
                    "url": "https://platform.example.test/acme",
                    "events": ["*"],
                    "scope": "subtree",
                })),
            )
            .await);
        let placed_id = placed["webhook"]["id"].clone();
        for (name, result) in [
            (
                "update",
                api.update(
                    &org.owner,
                    body(json!({ "tenantId": org.tenant_id, "webhookId": placed_id, "active": false })),
                )
                .await
                .map(|_| ()),
            ),
            (
                "rotateSecret",
                api.rotate_secret(
                    &org.owner,
                    body(json!({ "tenantId": org.tenant_id, "webhookId": placed_id })),
                )
                .await
                .map(|_| ()),
            ),
            (
                "delete",
                api.delete(
                    &org.owner,
                    body(json!({ "tenantId": org.tenant_id, "webhookId": placed_id })),
                )
                .await
                .map(|_| ()),
            ),
        ] {
            let error = result.expect_err(name);
            assert_eq!(
                (error.code.as_str(), error.message.as_str()),
                (
                    "ACCESS_DENIED",
                    "Subtree subscriptions are platform controlled"
                ),
                "{name}"
            );
        }
        // Reading it is still the tenant's permission.
        ok(api
            .get(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "webhookId": placed_id })),
            )
            .await);
        ok(api
            .delete(
                &f.root,
                body(json!({ "tenantId": org.tenant_id, "webhookId": placed_id })),
            )
            .await);
    });
}

#[test]
fn validates_updates_and_clears_optional_members() {
    run(|| async {
        let w = setup().await;
        let (f, org) = (&w.f, &w.org);
        let api = &f.iam.api.webhooks;
        let created = ok(api
            .create(
                &org.owner,
                body(json!({
                    "tenantId": org.tenant_id,
                    "url": "https://hooks.example.test/iam",
                    "events": ["iam:*"],
                    "description": "Audit",
                    "outcomes": ["deny"],
                    "resources": ["domains/*", "domains/*"],
                })),
            )
            .await);
        let webhook_id = created["webhook"]["id"].clone();
        assert_eq!(created["webhook"]["resources"], json!(["domains/*"]));
        let update = |changes: Value| {
            let mut input = changes;
            input["tenantId"] = json!(org.tenant_id);
            input["webhookId"] = webhook_id.clone();
            api.update(&org.owner, body(input))
        };
        let nothing = err(update(json!({})).await);
        assert_eq!(
            (nothing.code.as_str(), nothing.message.as_str()),
            ("INVALID_INPUT", "Nothing to update")
        );
        let flag = err(update(json!({ "active": "yes" })).await);
        assert_eq!(flag.message, "active must be boolean");
        let outcomes = err(update(json!({ "outcomes": [] })).await);
        assert_eq!(outcomes.message, "outcomes must list allow, deny, or both");
        let patterns = err(update(json!({ "resources": [] })).await);
        assert_eq!(patterns.message, "resources must contain 1-20 patterns");
        let cleared = ok(update(json!({
            "description": null,
            "outcomes": null,
            "resources": null,
            "url": "https://hooks.example.test/v2",
        }))
        .await);
        assert!(cleared.get("description").is_none());
        assert!(cleared.get("outcomes").is_none());
        assert!(cleared.get("resources").is_none());
        assert_eq!(cleared["url"], json!("https://hooks.example.test/v2"));
        assert!(
            cleared["updatedAt"].as_f64().unwrap()
                >= created["webhook"]["createdAt"].as_f64().unwrap()
        );
        // Unknown subscriptions are not found; the action is audited on the webhook ID.
        let missing = err(api
            .update(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "webhookId": "missing", "active": true })),
            )
            .await);
        assert_eq!(missing.status, 404);
        let events = f.audit(&org.tenant_id, "iam:webhooks:update").await;
        assert!(
            events.iter().any(
                |event| event["resourceId"] == webhook_id && event["outcome"] == json!("allow")
            )
        );
    });
}
