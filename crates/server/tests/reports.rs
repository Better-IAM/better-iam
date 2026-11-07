//! The access report (tests/reports.test.ts). Members, roles, bindings, activations and API keys are written to the
//! store directly where the TypeScript test uses the `identities`, `roles`, `bindings`, `serviceAccounts` and
//! `credentials` groups.

mod directory_support;

use better_iam_server::api::reports::{report_has_findings, report_windows};
use better_iam_server::utils::id;
use directory_support::{Fixture, Org, body, err, fixture, ok, run};
use serde_json::{Value, json};

const DAY: f64 = 86_400_000.0;

/// A number as the server writes it (JavaScript formatting: integers without a fraction).
fn n(value: f64) -> Value {
    better_iam_server::js::number(value)
}

async fn role(f: &Fixture, org: &Org, name: &str, actions: &[&str]) -> String {
    let role_id = id();
    f.insert(
        "roles",
        json!({
            "id": role_id,
            "tenantId": org.tenant_id,
            "name": name,
            "policyIds": [],
            "document": { "version": 1, "statements": [{ "effect": "allow", "actions": actions, "resources": ["*"] }] },
            "protected": false,
            "authorityId": org.authority_id,
        }),
    )
    .await;
    role_id
}

/// An API key session of `identity_id` (`credentials.create`).
async fn api_key(
    f: &Fixture,
    org: &Org,
    identity_id: &str,
    name: &str,
    expires_at: f64,
    last_seen_at: Option<f64>,
) -> String {
    let key_id = id();
    let mut session = json!({
        "id": key_id,
        "tenantId": org.tenant_id,
        "identityId": identity_id,
        "kind": "api-key",
        "name": name,
        "tokenHash": id(),
        "createdAt": f.now(),
        "expiresAt": expires_at,
    });
    if let Some(seen) = last_seen_at {
        session["lastSeenAt"] = json!(seen);
    }
    f.insert("sessions", session).await;
    key_id
}

async fn report(f: &Fixture, org: &Org, credential_of: &str, input: Value) -> Value {
    let credential = f.session(credential_of).await;
    let mut input = input;
    input["tenantId"] = json!(org.tenant_id);
    ok(f.iam.api.reports.access(&credential, body(input)).await)
}

fn ids(items: &Value, key: &str) -> Vec<Value> {
    items
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item[key].clone())
        .collect()
}

#[test]
fn collects_expiring_identities_and_bindings_live_activations_pending_requests_and_unused_keys() {
    run(|| async {
        let f = fixture("organization-fixture-secret-with-32-characters", |_| {}).await;
        let org = f.organization("Acme", "owner@acme.test").await;
        let alice = f.member(&org, "alice").await;
        let contractor = f.member(&org, "contractor").await;
        f.update(
            "identities",
            &contractor.id,
            json!({ "expiresAt": f.now() + 5.0 * DAY }),
        )
        .await;
        let later = f.member(&org, "later").await;
        f.update(
            "identities",
            &later.id,
            json!({ "expiresAt": f.now() + 90.0 * DAY }),
        )
        .await;
        let reader = role(&f, &org, "Reader", &["documents:read"]).await;
        let member = role(&f, &org, "Member", &["iam:bindings:activate"]).await;
        f.bind(&org, &member, "identity", &alice.id, json!({}))
            .await;
        let temporary = f
            .bind(
                &org,
                &reader,
                "identity",
                &contractor.id,
                json!({ "expiresAt": f.now() + 5.0 * DAY }),
            )
            .await;
        let eligible = f
            .bind(
                &org,
                &reader,
                "identity",
                &alice.id,
                json!({ "eligible": true, "window": { "from": "00:00", "to": "23:59", "timeZone": "UTC" } }),
            )
            .await;
        let account = f.member(&org, "ci").await;
        f.update("identities", &account.id, json!({ "kind": "service" }))
            .await;
        let start = f.now();
        let stale = api_key(&f, &org, &account.id, "stale", start + 20.0 * DAY, None).await;
        api_key(
            &f,
            &org,
            &account.id,
            "fresh",
            start + 365.0 * DAY,
            Some(start + 2.0 * DAY),
        )
        .await;
        f.advance(2.0 * DAY);
        // Activated now, so the one-hour default is still live when the report runs.
        let activation = id();
        f.insert(
            "bindingActivations",
            json!({
                "id": activation,
                "tenantId": org.tenant_id,
                "bindingId": eligible,
                "identityId": alice.id,
                "roleId": reader,
                "activatedAt": f.now(),
                "expiresAt": f.now() + 3_600_000.0,
                "justification": "report",
                "sessionId": id(),
            }),
        )
        .await;
        let report_now = report(
            &f,
            &org,
            &org.owner_id,
            json!({ "withinMs": 30.0 * DAY, "unusedForMs": DAY }),
        )
        .await;
        assert_eq!(report_now["omitted"], json!([]));
        assert_eq!(report_now["withinMs"], n(30.0 * DAY));
        assert_eq!(report_now["unusedForMs"], n(DAY));
        // Owner, alice, contractor, later, and the service account.
        assert_eq!(report_now["identities"]["total"], json!(5));
        let expiring = &report_now["identities"]["expiring"];
        assert_eq!(ids(expiring, "id"), vec![json!(contractor.id)]);
        assert_eq!(expiring[0]["expired"], json!(false));
        assert_eq!(expiring[0]["email"], json!("contractor@acme.test"));
        assert_eq!(expiring[0]["kind"], json!("user"));
        assert_eq!(expiring[0]["status"], json!("active"));
        // The owner's protected binding, Member, the temporary Reader, and the eligible Reader.
        let bindings = &report_now["bindings"];
        assert_eq!(bindings["total"], json!(4));
        assert_eq!(bindings["eligible"], json!(1));
        assert_eq!(bindings["windowed"], json!(1));
        assert_eq!(bindings["pendingRequests"], json!(0));
        assert_eq!(ids(&bindings["expiring"], "id"), vec![json!(temporary)]);
        assert_eq!(bindings["expiring"][0]["roleName"], json!("Reader"));
        assert_eq!(bindings["expiring"][0]["subjectName"], json!("contractor"));
        assert_eq!(bindings["expiring"][0]["eligible"], json!(false));
        assert_eq!(bindings["starting"], json!([]));
        assert_eq!(bindings["expiringMemberships"], json!([]));
        let activations = bindings["activations"].as_array().unwrap();
        assert_eq!(activations.len(), 1);
        assert_eq!(activations[0]["id"], json!(activation));
        assert_eq!(activations[0]["identityName"], json!("alice"));
        assert_eq!(activations[0]["roleName"], json!("Reader"));
        assert_eq!(activations[0]["justification"], json!("report"));
        let credentials = &report_now["credentials"];
        assert_eq!(credentials["total"], json!(2));
        assert_eq!(ids(&credentials["unused"], "name"), vec![json!("stale")]);
        assert_eq!(ids(&credentials["expiring"], "name"), vec![json!("stale")]);
        assert_eq!(credentials["unused"][0]["id"], json!(stale));
        assert!(report_has_findings(&report_now).unwrap());
        // Past the deadline the identity is reported as expired until the worker disables it.
        f.advance(4.0 * DAY);
        let after = report(&f, &org, &org.owner_id, json!({})).await;
        let expiring = &after["identities"]["expiring"];
        assert_eq!(ids(expiring, "id"), vec![json!(contractor.id)]);
        assert_eq!(expiring[0]["expired"], json!(true));
        assert_eq!(after["bindings"]["activations"], json!([]));
        // A caller without the binding and credential permissions gets those sections omitted.
        let viewer = role(&f, &org, "Directory viewer", &["iam:identities:read"]).await;
        let bob = f.member(&org, "bob").await;
        f.bind(&org, &viewer, "identity", &bob.id, json!({})).await;
        let partial = report(&f, &org, &bob.id, json!({})).await;
        assert_eq!(partial["omitted"], json!(["bindings", "credentials"]));
        assert!(partial.get("bindings").is_none());
        assert!(partial.get("credentials").is_none());
        assert_eq!(partial["identities"]["total"], json!(6));
        let as_alice = f.session(&alice.id).await;
        let denied = err(f
            .iam
            .api
            .reports
            .access(&as_alice, body(json!({ "tenantId": org.tenant_id })))
            .await);
        assert_eq!(denied.code, "ACCESS_DENIED");
        let admin = f.session(&org.owner_id).await;
        let invalid = err(f
            .iam
            .api
            .reports
            .access(
                &admin,
                body(json!({ "tenantId": org.tenant_id, "withinMs": -1 })),
            )
            .await);
        assert_eq!(invalid.code, "INVALID_INPUT");
    });
}

#[test]
fn reports_scheduled_bindings_ending_memberships_and_pending_requests() {
    run(|| async {
        let f = fixture("organization-fixture-secret-with-32-characters", |_| {}).await;
        let org = f.organization("Acme", "owner@acme.test").await;
        let alice = f.member(&org, "alice").await;
        let bob = f.member(&org, "bob").await;
        let reader = role(&f, &org, "Reader", &["documents:read"]).await;
        let team = f.group(&org, "Team").await;
        f.add_member(&org, &team, &alice.id, Some(f.now() + 3.0 * DAY))
            .await;
        f.add_member(&org, &team, &bob.id, Some(f.now() + 2.0 * DAY))
            .await;
        // Starts within the window, and one that starts after it.
        let soon = f
            .bind(
                &org,
                &reader,
                "group",
                &team,
                json!({ "startsAt": f.now() + DAY }),
            )
            .await;
        f.bind(
            &org,
            &reader,
            "identity",
            &bob.id,
            json!({ "startsAt": f.now() + 60.0 * DAY }),
        )
        .await;
        // A group binding that is eligible: requests count while the requester is still a member.
        let eligible = f
            .bind(&org, &reader, "group", &team, json!({ "eligible": true }))
            .await;
        for (who, status) in [(&alice.id, "pending"), (&bob.id, "denied")] {
            f.insert(
                "bindingActivations",
                json!({
                    "id": id(),
                    "tenantId": org.tenant_id,
                    "bindingId": eligible,
                    "identityId": who,
                    "roleId": reader,
                    "activatedAt": f.now(),
                    "expiresAt": f.now() + 3_600_000.0,
                    "sessionId": id(),
                    "status": status,
                }),
            )
            .await;
        }
        let result = report(&f, &org, &org.owner_id, json!({ "withinMs": 7.0 * DAY })).await;
        let bindings = &result["bindings"];
        assert_eq!(ids(&bindings["starting"], "id"), vec![json!(soon)]);
        assert_eq!(bindings["starting"][0]["subjectType"], json!("group"));
        assert_eq!(bindings["starting"][0]["subjectName"], json!("Team"));
        assert_eq!(bindings["starting"][0]["expiresAt"], n(f.now() + DAY));
        // Ending soonest first.
        assert_eq!(
            ids(&bindings["expiringMemberships"], "identityId"),
            vec![json!(bob.id), json!(alice.id)]
        );
        assert_eq!(
            bindings["expiringMemberships"][0]["groupName"],
            json!("Team")
        );
        assert_eq!(
            bindings["expiringMemberships"][0]["identityName"],
            json!("bob")
        );
        assert_eq!(bindings["pendingRequests"], json!(1));
        assert_eq!(bindings["activations"], json!([]));
        // A disabled requester's request no longer counts.
        f.update("identities", &alice.id, json!({ "status": "disabled" }))
            .await;
        let result = report(&f, &org, &org.owner_id, json!({ "withinMs": 7.0 * DAY })).await;
        assert_eq!(result["bindings"]["pendingRequests"], json!(0));
        assert_eq!(result["identities"]["disabled"], json!(1));
    });
}

#[test]
fn validates_windows_and_detects_findings() {
    run(|| async {
        assert_eq!(
            report_windows(&json!({})).unwrap(),
            json!({ "withinMs": n(30.0 * DAY), "unusedForMs": n(30.0 * DAY) })
        );
        assert_eq!(
            report_windows(&json!({ "withinMs": 0, "unusedForMs": null })).unwrap(),
            json!({ "withinMs": 0, "unusedForMs": n(30.0 * DAY) })
        );
        for input in [
            json!({ "withinMs": -1 }),
            json!({ "withinMs": 1.5 }),
            json!({ "unusedForMs": 11.0 * 365.0 * DAY }),
            json!({ "withinMs": "1" }),
        ] {
            let error = report_windows(&input).unwrap_err();
            assert_eq!(error.code, "INVALID_INPUT", "{input}");
        }
        let empty = json!({
            "identities": { "total": 1, "disabled": 0, "expiring": [] },
            "omitted": ["bindings", "credentials"],
        });
        assert!(!report_has_findings(&empty).unwrap());
        let mut pending = empty.clone();
        pending["bindings"] = json!({
            "expiring": [], "starting": [], "expiringMemberships": [], "activations": [], "pendingRequests": 2,
        });
        assert!(report_has_findings(&pending).unwrap());
        let mut keys = empty.clone();
        keys["credentials"] = json!({ "total": 1, "unused": [], "expiring": [{ "id": "k" }] });
        assert!(report_has_findings(&keys).unwrap());
    });
}
