//! The deployment jobs of lifecycle.ts: expiry reminders, the retention worker (`purgeDeleted`), birthright
//! reconciliation and the access digest. Ported from tests/expiry-reminders.test.ts, tests/identity-expiry.test.ts,
//! tests/lifecycle-review.test.ts, tests/membership-expiry.test.ts and tests/access-digest.test.ts. Roles, groups,
//! packages, bindings and memberships the TypeScript tests create through API groups other units port are written to
//! the store directly. The access digest and package reconciliation run on api/reports.ts and
//! api/package-automation.ts; their steps end the test early with a note until those units land.

mod tenants_support;

use serde_json::{Value, json};
use tenants_support::*;

const BINDING_AUTHORITY: &str = "authority";

async fn org(f: &Fixture) -> String {
    organization(f, "Acme", json!({})).await["tenant"]["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

/// A member with an email, optionally with a scheduled deactivation.
async fn person(f: &Fixture, tenant_id: &str, name: &str, expires_at: Option<f64>) -> String {
    let (id, _) = member(f, tenant_id, &format!("{name}@acme.test"), false).await;
    if let Some(expires_at) = expires_at {
        let mut identity = get(&f.iam, "identities", &id).await.unwrap();
        identity.insert("expiresAt".into(), json!(expires_at));
        put(&f.iam, "identities", identity).await;
    }
    id
}

async fn binding(
    f: &Fixture,
    tenant_id: &str,
    role_id: &str,
    subject: (&str, &str),
    extra: Value,
) -> String {
    let id = better_iam_server::utils::id();
    let mut record = json!({
        "id": id,
        "tenantId": tenant_id,
        "subjectType": subject.0,
        "subjectId": subject.1,
        "roleId": role_id,
        "authorityId": BINDING_AUTHORITY,
    });
    for (key, value) in extra.as_object().unwrap() {
        record[key] = value.clone();
    }
    insert(&f.iam, "bindings", record).await;
    id
}

async fn membership(
    f: &Fixture,
    tenant_id: &str,
    group_id: &str,
    identity_id: &str,
    extra: Value,
) -> String {
    let id = better_iam_server::utils::id();
    let mut record =
        json!({ "id": id, "tenantId": tenant_id, "groupId": group_id, "identityId": identity_id });
    for (key, value) in extra.as_object().unwrap() {
        record[key] = value.clone();
    }
    insert(&f.iam, "groupMembers", record).await;
    id
}

async fn activation(
    f: &Fixture,
    tenant_id: &str,
    binding_id: &str,
    identity_id: &str,
    expires_at: f64,
) -> String {
    let id = better_iam_server::utils::id();
    insert(
        &f.iam,
        "bindingActivations",
        json!({
            "id": id, "tenantId": tenant_id, "uniqueKey": format!("{binding_id}:{identity_id}"),
            "bindingId": binding_id, "identityId": identity_id, "roleId": "reader",
            "activatedAt": NOW - DAY, "expiresAt": expires_at, "sessionId": "session",
        }),
    )
    .await;
    id
}

fn items_of(f: &Fixture, to: &str) -> Value {
    let message = mails(f, "expiry-reminder")
        .into_iter()
        .rev()
        .find(|message| message.to == to)
        .expect("reminder");
    better_iam_core::js::parse(message.payload["items"].as_str().unwrap()).unwrap()
}

#[test]
fn emails_each_person_once_per_ending_item_and_again_when_the_end_moves() {
    run(|| async {
        let f = fixture(true, |_| {}).await;
        let tenant_id = org(&f).await;
        insert(
            &f.iam,
            "roles",
            json!({ "id": "reader", "tenantId": tenant_id, "name": "Reader", "policyIds": [] }),
        )
        .await;
        insert(
            &f.iam,
            "groups",
            json!({ "id": "project", "tenantId": tenant_id, "name": "Project X" }),
        )
        .await;
        insert(
            &f.iam,
            "accessPackages",
            json!({ "id": "kit", "tenantId": tenant_id, "name": "Kit" }),
        )
        .await;
        let alice = person(&f, &tenant_id, "alice", Some(NOW + 3.0 * DAY)).await;
        let bob = person(&f, &tenant_id, "bob", None).await;
        binding(
            &f,
            &tenant_id,
            "reader",
            ("identity", &bob),
            json!({ "expiresAt": NOW + 2.0 * DAY }),
        )
        .await;
        let carol = person(&f, &tenant_id, "carol", None).await;
        membership(
            &f,
            &tenant_id,
            "project",
            &carol,
            json!({ "expiresAt": NOW + 5.0 * DAY }),
        )
        .await;
        // Dave's package assignment, with the binding and membership it made (reminded as the package).
        let dave = person(&f, &tenant_id, "dave", None).await;
        let assignment = better_iam_server::utils::id();
        let packaged = json!({ "expiresAt": NOW + 4.0 * DAY, "packageAssignmentId": assignment });
        let dave_binding = binding(
            &f,
            &tenant_id,
            "reader",
            ("identity", &dave),
            packaged.clone(),
        )
        .await;
        let dave_member = membership(&f, &tenant_id, "project", &dave, packaged).await;
        insert(
            &f.iam,
            "packageAssignments",
            json!({
                "id": assignment, "tenantId": tenant_id, "uniqueKey": format!("kit:{dave}"),
                "packageId": "kit", "identityId": dave, "assignedBy": "owner", "assignedAt": NOW,
                "expiresAt": NOW + 4.0 * DAY, "bindingIds": [dave_binding], "membershipIds": [dave_member],
            }),
        )
        .await;
        // Erin's binding ends outside the window; a group binding is the owners' business, not a member's; an
        // eligible binding grants nothing until activated.
        let erin = person(&f, &tenant_id, "erin", None).await;
        binding(
            &f,
            &tenant_id,
            "reader",
            ("identity", &erin),
            json!({ "expiresAt": NOW + 20.0 * DAY }),
        )
        .await;
        binding(
            &f,
            &tenant_id,
            "reader",
            ("group", "project"),
            json!({ "expiresAt": NOW + DAY }),
        )
        .await;
        binding(
            &f,
            &tenant_id,
            "reader",
            ("identity", &erin),
            json!({ "expiresAt": NOW + DAY, "eligible": true }),
        )
        .await;
        let first = f
            .iam
            .send_expiry_reminders(Some(&json!({ "withinMs": 7.0 * DAY })))
            .await
            .unwrap();
        let mut sent: Vec<(String, f64)> = first["sent"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                (
                    entry["identityId"].as_str().unwrap().to_owned(),
                    entry["items"].as_f64().unwrap(),
                )
            })
            .collect();
        sent.sort_by(|a, b| a.0.cmp(&b.0));
        let mut expected = vec![
            (alice.clone(), 1.0),
            (bob.clone(), 1.0),
            (carol.clone(), 1.0),
            (dave.clone(), 1.0),
        ];
        expected.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(sent, expected);
        assert_eq!(first["skipped"], json!({ "inactive": 0, "quiet": 1 }));
        f.iam.auth.dispatch_outbox(None).await.unwrap();
        let mut delivered: Vec<(String, String)> = mails(&f, "expiry-reminder")
            .iter()
            .map(|message| {
                (
                    message.to.clone(),
                    message.payload["count"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        delivered.sort();
        assert_eq!(
            delivered,
            vec![
                ("alice@acme.test".to_owned(), "1".to_owned()),
                ("bob@acme.test".to_owned(), "1".to_owned()),
                ("carol@acme.test".to_owned(), "1".to_owned()),
                ("dave@acme.test".to_owned(), "1".to_owned()),
            ]
        );
        same(
            &items_of(&f, "alice@acme.test"),
            &json!([{ "kind": "account", "name": "alice", "expiresAt": NOW + 3.0 * DAY }]),
        );
        same(
            &items_of(&f, "bob@acme.test"),
            &json!([{ "kind": "role", "name": "Reader", "expiresAt": NOW + 2.0 * DAY }]),
        );
        same(
            &items_of(&f, "carol@acme.test"),
            &json!([{ "kind": "group", "name": "Project X", "expiresAt": NOW + 5.0 * DAY }]),
        );
        same(
            &items_of(&f, "dave@acme.test"),
            &json!([{ "kind": "package", "name": "Kit", "expiresAt": NOW + 4.0 * DAY }]),
        );
        let first_mail = &mails(&f, "expiry-reminder")[0];
        assert_eq!(first_mail.payload["tenantName"], "Acme");
        assert_eq!(first_mail.tenant_id, tenant_id);
        // Nothing new: the next run is quiet. Moving an end brings a fresh reminder for that item only.
        let again = f
            .iam
            .send_expiry_reminders(Some(&json!({ "withinMs": 7.0 * DAY })))
            .await
            .unwrap();
        assert_eq!(again["sent"], json!([]));
        let mut moved = get(&f.iam, "packageAssignments", &assignment)
            .await
            .unwrap();
        moved.insert("expiresAt".into(), json!(NOW + 6.0 * DAY));
        put(&f.iam, "packageAssignments", moved).await;
        let third = f
            .iam
            .send_expiry_reminders(Some(&json!({ "withinMs": 7.0 * DAY })))
            .await
            .unwrap();
        assert_eq!(
            third["sent"],
            json!([{ "tenantId": tenant_id, "identityId": dave, "items": 1 }])
        );
        let events = find(
            &f.iam,
            "audit",
            json!({ "tenantId": tenant_id, "action": "identity:expiry-reminder" }),
        )
        .await;
        assert_eq!(events.len(), 5);
        // Dave's two reminders, ordered by their sequence in the audit chain.
        let mut dave_events: Vec<&serde_json::Map<String, Value>> = events
            .iter()
            .filter(|event| event["resourceId"] == dave.as_str())
            .collect();
        dave_events.sort_by(|a, b| {
            a["sequence"]
                .as_f64()
                .partial_cmp(&b["sequence"].as_f64())
                .unwrap()
        });
        same(
            &dave_events[1]["metadata"],
            &json!({
                "count": 1,
                "earliest": NOW + 6.0 * DAY,
                "items": [format!("package:{assignment}:{}", better_iam_core::js::number_to_string(NOW + 6.0 * DAY))],
            }),
        );
        assert_eq!(dave_events[1]["actorId"], "deployment-operator");
        assert_eq!(
            find(
                &f.iam,
                "expiryReminderMarks",
                json!({ "tenantId": tenant_id })
            )
            .await
            .len(),
            5
        );
        let error = failure(
            f.iam
                .send_expiry_reminders(Some(&json!({ "withinMs": 0 })))
                .await,
        );
        assert_eq!(error.code, "INVALID_INPUT");
        assert_eq!(error.message, "Invalid withinMs");
        let error = failure(
            f.iam
                .send_expiry_reminders(Some(&json!({ "tenantId": "missing" })))
                .await,
        );
        assert_eq!(error.code, "NOT_FOUND");
        // One tenant only; an inactive one is skipped.
        json(
            f.iam
                .api
                .tenants
                .set_status(
                    &f.root,
                    body(json!({ "tenantId": tenant_id, "status": "suspended" })),
                )
                .await,
        )
        .unwrap();
        let skipped = f
            .iam
            .send_expiry_reminders(Some(&json!({ "tenantId": tenant_id })))
            .await
            .unwrap();
        assert_eq!(
            skipped,
            json!({ "sent": [], "skipped": { "inactive": 1, "quiet": 0 } })
        );
    });
}

#[test]
fn reminders_and_the_digest_need_an_email_transport() {
    run(|| async {
        let f = fixture(false, |_| {}).await;
        let error = failure(f.iam.send_expiry_reminders(None).await);
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "DELIVERY_REQUIRED",
                "Expiry reminders require an email delivery callback"
            )
        );
        let error = or_skip!(f.iam.send_access_digest(None).await).unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "DELIVERY_REQUIRED",
                "The access digest requires an email delivery callback"
            )
        );
    });
}

#[test]
fn the_access_digest_validates_its_interval() {
    run(|| async {
        let f = fixture(true, |_| {}).await;
        let error = or_skip!(
            f.iam
                .send_access_digest(Some(&json!({ "minimumIntervalMs": -1 })))
                .await
        )
        .unwrap_err();
        assert_eq!(error.message, "Invalid minimumIntervalMs");
        let digest = f.iam.send_access_digest(None).await.unwrap();
        assert_eq!(
            digest["skipped"],
            json!({ "inactive": 0, "recent": 0, "quiet": 1, "noOwners": 0 })
        );
    });
}

#[test]
fn reconcile_packages_validates_its_input() {
    run(|| async {
        let f = fixture(true, |_| {}).await;
        let cases = [
            (json!({ "packageId": "p" }), "packageId needs tenantId"),
            (
                json!({ "tenantId": "t", "confirm": "yes" }),
                "confirm must be boolean",
            ),
            (
                json!({ "tenantId": "t", "confirm": true }),
                "confirm needs packageId",
            ),
            (json!({ "limit": 0 }), "Invalid limit"),
            (json!({ "tenantId": "" }), "Invalid tenantId"),
        ];
        for (input, message) in cases {
            let error = failure(f.iam.reconcile_packages(Some(&input)).await);
            assert_eq!(
                (error.code.as_str(), error.message.as_str()),
                ("INVALID_INPUT", message)
            );
        }
        let result = or_skip!(f.iam.reconcile_packages(None).await).unwrap();
        assert_eq!(result["trigger"], "schedule");
    });
}

#[test]
fn the_retention_worker_removes_what_ended() {
    run(|| async {
        let f = fixture(true, |_| {}).await;
        let tenant_id = org(&f).await;
        let alice = person(&f, &tenant_id, "alice", None).await;
        let bob = person(&f, &tenant_id, "bob", None).await;
        // An expired binding and its activation; an ended activation of a live binding.
        let expired = binding(
            &f,
            &tenant_id,
            "reader",
            ("identity", &alice),
            json!({ "expiresAt": NOW - DAY }),
        )
        .await;
        activation(&f, &tenant_id, &expired, &alice, NOW + DAY).await;
        let live = binding(
            &f,
            &tenant_id,
            "reader",
            ("identity", &alice),
            json!({ "eligible": true }),
        )
        .await;
        let ended = activation(&f, &tenant_id, &live, &alice, NOW).await;
        let future = binding(
            &f,
            &tenant_id,
            "reader",
            ("identity", &alice),
            json!({ "startsAt": NOW + DAY, "expiresAt": NOW + 2.0 * DAY }),
        )
        .await;
        // A lapsed membership ends the member's activations of the group's bindings.
        let group_binding = binding(
            &f,
            &tenant_id,
            "reader",
            ("group", "project"),
            json!({ "eligible": true }),
        )
        .await;
        let lapsed = membership(
            &f,
            &tenant_id,
            "project",
            &bob,
            json!({ "expiresAt": NOW - 1.0 }),
        )
        .await;
        let bob_activation = activation(&f, &tenant_id, &group_binding, &bob, NOW + DAY).await;
        let kept = membership(
            &f,
            &tenant_id,
            "project",
            &alice,
            json!({ "expiresAt": NOW + DAY }),
        )
        .await;
        let alice_group_activation =
            activation(&f, &tenant_id, &group_binding, &alice, NOW + DAY).await;
        insert(
            &f.iam,
            "packageAssignments",
            json!({
                "id": "ended-assignment", "tenantId": tenant_id, "packageId": "kit", "identityId": bob,
                "assignedBy": "owner", "assignedAt": NOW - 2.0 * DAY, "expiresAt": NOW,
                "bindingIds": [], "membershipIds": [],
            }),
        )
        .await;
        insert(
            &f.iam,
            "accessRequests",
            json!({ "id": "request", "tenantId": tenant_id, "status": "pending", "expiresAt": NOW - 1.0 }),
        )
        .await;
        insert(
            &f.iam,
            "accessRequests",
            json!({ "id": "open-request", "tenantId": tenant_id, "status": "pending", "expiresAt": NOW + DAY }),
        )
        .await;
        insert(
            &f.iam,
            "packageRequests",
            json!({ "id": "package-request", "tenantId": tenant_id, "status": "pending", "expiresAt": NOW }),
        )
        .await;
        insert(
            &f.iam,
            "expiryReminderMarks",
            json!({ "id": "mark", "tenantId": tenant_id, "uniqueKey": "identity:x:1", "identityId": "x", "expiresAt": NOW - 1.0 }),
        )
        .await;
        // A contractor past their deactivation date, with a session and an activation.
        let (contractor, contractor_credential) =
            member(&f, &tenant_id, "contractor@acme.test", false).await;
        let mut record = get(&f.iam, "identities", &contractor).await.unwrap();
        record.insert("expiresAt".into(), json!(NOW - 1.0));
        put(&f.iam, "identities", record).await;
        let contractor_activation = activation(&f, &tenant_id, &live, &contractor, NOW + DAY).await;
        // Authentication bookkeeping past its end, and some still running.
        insert(
            &f.iam,
            "authRateLimits",
            json!({ "id": "rate-old", "tenantId": "anything", "resetAt": NOW - 1.0 }),
        )
        .await;
        insert(
            &f.iam,
            "authRateLimits",
            json!({ "id": "rate-new", "tenantId": "anything", "resetAt": NOW + 1.0 }),
        )
        .await;
        insert(
            &f.iam,
            "authChallenges",
            json!({ "id": "challenge-old", "tenantId": "anything", "expiresAt": NOW }),
        )
        .await;
        insert(
            &f.iam,
            "authBlocks",
            json!({ "id": "block-old", "tenantId": tenant_id, "expiresAt": NOW - 1.0 }),
        )
        .await;

        let purge = f.iam.purge_deleted(None).await.unwrap();
        assert_eq!(
            purge,
            json!({
                "purgedTenants": [],
                "deletedRecords": 0,
                "expiredBindings": 1,
                "expiredRequests": 2,
                "expiredIdentities": 1,
                "expiredActivations": 3,
                "expiredMemberships": 1,
                "expiredAssignments": 1,
            })
        );
        assert!(get(&f.iam, "bindings", &expired).await.is_none());
        assert!(get(&f.iam, "bindings", &future).await.is_some());
        assert!(get(&f.iam, "bindingActivations", &ended).await.is_none());
        assert!(
            get(&f.iam, "bindingActivations", &bob_activation)
                .await
                .is_none()
        );
        assert!(
            get(&f.iam, "bindingActivations", &alice_group_activation)
                .await
                .is_some()
        );
        assert!(
            get(&f.iam, "bindingActivations", &contractor_activation)
                .await
                .is_none()
        );
        assert!(get(&f.iam, "groupMembers", &lapsed).await.is_none());
        assert!(get(&f.iam, "groupMembers", &kept).await.is_some());
        assert!(
            get(&f.iam, "packageAssignments", "ended-assignment")
                .await
                .is_none()
        );
        assert_eq!(
            get(&f.iam, "accessRequests", "request").await.unwrap()["status"],
            "expired"
        );
        assert_eq!(
            get(&f.iam, "accessRequests", "open-request").await.unwrap()["status"],
            "pending"
        );
        assert_eq!(
            get(&f.iam, "packageRequests", "package-request")
                .await
                .unwrap()["status"],
            "expired"
        );
        assert!(get(&f.iam, "expiryReminderMarks", "mark").await.is_none());
        assert_eq!(
            get(&f.iam, "identities", &contractor).await.unwrap()["status"],
            "disabled"
        );
        assert_eq!(
            failure(f.iam.authenticate(&contractor_credential).await).code,
            "UNAUTHENTICATED"
        );
        let events = find(
            &f.iam,
            "audit",
            json!({ "tenantId": tenant_id, "action": "identity:expire" }),
        )
        .await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["resourceId"], contractor.as_str());
        same(
            &events[0]["metadata"],
            &json!({ "kind": "user", "expiresAt": NOW - 1.0 }),
        );
        assert!(get(&f.iam, "authRateLimits", "rate-old").await.is_none());
        assert!(get(&f.iam, "authRateLimits", "rate-new").await.is_some());
        assert!(
            get(&f.iam, "authChallenges", "challenge-old")
                .await
                .is_none()
        );
        assert!(get(&f.iam, "authBlocks", "block-old").await.is_none());
        // A second run finds nothing more.
        let again = f.iam.purge_deleted(None).await.unwrap();
        assert_eq!(again["expiredIdentities"], 0);
        assert_eq!(again["expiredActivations"], 0);
        for retention in [json!(-1), json!(1.5), json!("30")] {
            let error = failure(
                f.iam
                    .purge_deleted(Some(&json!({ "retentionMs": retention })))
                    .await,
            );
            assert_eq!(error.message, "Invalid retentionMs");
        }
    });
}

#[test]
fn the_retention_worker_purges_deleted_tenants_past_retention() {
    run(|| async {
        let f = fixture(true, |_| {}).await;
        let gone = org(&f).await;
        let project = json(
            f.iam
                .api
                .tenants
                .create(
                    &f.root,
                    body(json!({
                        "parentId": gone, "type": "project", "name": "Apollo",
                        "ownerEmail": "lead@acme.test", "activate": true, "slug": "apollo",
                    })),
                )
                .await,
        )
        .unwrap();
        let project_id = project["tenant"]["id"].as_str().unwrap().to_owned();
        let survivor = organization(&f, "Globex", json!({})).await["tenant"]["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let (gone_person, _) = member(&f, &gone, "alice@acme.test", false).await;
        let (survivor_person, _) = member(&f, &survivor, "sam@globex.test", false).await;
        insert(
            &f.iam,
            "identityLinks",
            json!({ "id": "link", "tenantId": survivor, "leftId": survivor_person, "rightId": gone_person }),
        )
        .await;
        insert(
            &f.iam,
            "trusts",
            json!({ "id": "trust", "tenantId": survivor, "sourceTenantId": gone }),
        )
        .await;
        insert(
            &f.iam,
            "sessions",
            json!({ "id": "role-session", "tenantId": survivor, "sourceTenantId": project_id, "expiresAt": NOW + DAY }),
        )
        .await;
        insert(
            &f.iam,
            "oauthArtifacts",
            json!({ "id": "artifact", "tenantId": survivor, "accountId": gone_person }),
        )
        .await;
        // Deleted long ago (the retention window runs on the wall clock), descendants with it.
        for tenant_id in [&gone, &project_id] {
            let mut realm = get(&f.iam, "tenants", tenant_id).await.unwrap();
            realm.insert("status".into(), json!("deleted"));
            realm.insert("deletedAt".into(), json!(1));
            put(&f.iam, "tenants", realm).await;
        }
        // Deleted just now: kept until the retention window passes.
        let recent = organization(&f, "Initech", json!({})).await["tenant"]["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let mut realm = get(&f.iam, "tenants", &recent).await.unwrap();
        realm.insert("status".into(), json!("deleted"));
        realm.insert(
            "deletedAt".into(),
            json!(better_iam_server::utils::date_now()),
        );
        put(&f.iam, "tenants", realm).await;

        let purge = f.iam.purge_deleted(None).await.unwrap();
        let mut purged = vec![gone.clone(), project_id.clone()];
        purged.sort();
        assert_eq!(purge["purgedTenants"], json!(purged));
        let deleted_records = purge["deletedRecords"].as_f64().unwrap();
        assert!(deleted_records > 10.0, "{deleted_records}");
        for tenant_id in [&gone, &project_id] {
            assert!(get(&f.iam, "tenants", tenant_id).await.is_none());
            for collection in [
                "identities",
                "sessions",
                "roles",
                "bindings",
                "grantAuthorities",
            ] {
                assert!(
                    find(&f.iam, collection, json!({ "tenantId": tenant_id }))
                        .await
                        .is_empty(),
                    "{collection}"
                );
            }
        }
        assert!(get(&f.iam, "tenantAliases", "apollo").await.is_none());
        assert!(get(&f.iam, "identityLinks", "link").await.is_none());
        assert!(get(&f.iam, "trusts", "trust").await.is_none());
        assert!(get(&f.iam, "sessions", "role-session").await.is_none());
        assert!(get(&f.iam, "oauthArtifacts", "artifact").await.is_none());
        assert!(get(&f.iam, "tenants", &survivor).await.is_some());
        assert!(get(&f.iam, "tenants", &recent).await.is_some());
        // The audit trail survives, with the purge recorded on the deleted root.
        let events = find(
            &f.iam,
            "audit",
            json!({ "tenantId": gone, "action": "tenants:purge" }),
        )
        .await;
        assert_eq!(events.len(), 1);
        let mut subtree: Vec<String> = events[0]["metadata"]["tenantIds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap().to_owned())
            .collect();
        subtree.sort();
        assert_eq!(subtree, purged);
        same(
            &events[0]["metadata"]["deletedRecords"],
            &json!(deleted_records),
        );
        assert!(
            !find(
                &f.iam,
                "audit",
                json!({ "tenantId": gone, "action": "tenant:activate" })
            )
            .await
            .is_empty()
        );
        // A zero retention purges the recent deletion too.
        let now = f
            .iam
            .purge_deleted(Some(&json!({ "retentionMs": 0 })))
            .await
            .unwrap();
        assert_eq!(now["purgedTenants"], json!([recent]));
    });
}
