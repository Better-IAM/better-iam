//! The threats API: ported from tests/threats-api.test.ts (rules and settings with the guardrail detection, reports,
//! risk, incidents, responses, release, playbooks, the protections, and the views), plus cases that pin the API
//! group's own behavior on stored detections and incidents: validation, permissions, recent sign-in, triage, notes,
//! resolution, the timeline and playbooks.
//!
//! Tenants, members and grants come from the organization fixture (written as `tenants.create`,
//! `identities.create`, `roles.create` and `bindings.create` write them). The TypeScript cases reach the threats
//! module (threats.ts `resolveThreatSettings`, `threatRules`, `effectiveRisk`, ...), the engine (threat-engine.ts),
//! responses (threat-response.ts) and the rules (threat-rules.ts), which other port units own; they are ignored until
//! those land. Two TypeScript cases stay in the TypeScript suite and the replayed traces: network blocks on the root
//! tenant (password sign-in failures from a client address) and invitations revoked by a containment (the outbox).

mod organization_fixture;

use better_iam_core::{CredentialInput, Filter};
use better_iam_server::options::{AuthorizationRequest, ClearanceOptions, ResourceTarget};
use organization_fixture::{Org, assert_matches, body, code, fails, ok, organization, run};
use serde_json::{Value, json};

const HOUR: f64 = 3_600_000.0;
const DAY: f64 = 24.0 * HOUR;
const THREAT_UNITS: &str =
    "needs threats.ts, threat-engine.ts, threat-response.ts and threat-rules.ts (threats units)";

fn threats_administration() -> Value {
    json!([{ "effect": "allow", "actions": ["iam:threats:*"], "resources": ["iam/threats/*"] }])
}

async fn fixture() -> Org {
    organization(|_| {}).await
}

/// `memberWith(f, name, statements)`: a person of the fixture tenant holding a role of `statements`, freshly signed
/// in.
async fn member_with(f: &Org, name: &str, statements: Value) -> (String, CredentialInput) {
    let id = f.member(name).await;
    f.grant(&id, statements).await;
    let credential = f.sign_in(&id).await;
    (id, credential)
}

fn merged(base: Value, extra: Value) -> Value {
    let mut out = base.as_object().cloned().unwrap_or_default();
    for (key, value) in extra.as_object().cloned().unwrap_or_default() {
        out.insert(key, value);
    }
    Value::Object(out)
}

async fn status_of(f: &Org, identity_id: &str) -> Option<String> {
    f.find("identities", Filter::new().eq("id", identity_id.to_owned()))
        .await
        .into_iter()
        .next()
        .and_then(|identity| {
            identity
                .get("status")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
}

fn ids(list: &Value, key: &str) -> Vec<String> {
    list[key]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["id"].as_str().unwrap().to_owned())
        .collect()
}

async fn can_read(f: &Org, credential: &CredentialInput) -> bool {
    f.iam
        .authorize(&AuthorizationRequest {
            credential: credential.clone(),
            tenant_id: f.tenant_id.clone(),
            action: "documents:read".into(),
            resource: ResourceTarget {
                kind: "document".into(),
                id: "d1".into(),
            },
        })
        .await
        .unwrap()
        .allowed
}

/// A stored incident about a network, as the engine records one.
async fn seed_incident(f: &Org, network: &str, severity: &str, at: f64) -> String {
    let id = better_iam_server::utils::id();
    f.insert(
        "threatIncidents",
        json!({
            "id": id,
            "tenantId": f.tenant_id,
            "uniqueKey": format!("open:network:{network}"),
            "subject": { "type": "network", "id": network },
            "network": network,
            "severity": severity,
            "status": "open",
            "title": "Password spray",
            "ruleIds": ["password-spray"],
            "detectionCount": 1,
            "firstDetectedAt": at,
            "lastDetectedAt": at,
            "createdAt": at,
            "updatedAt": at,
        }),
    )
    .await;
    id
}

/// A stored detection, as the engine records one.
async fn seed_detection(f: &Org, incident_id: &str, subject: Value, at: f64) -> String {
    let id = better_iam_server::utils::id();
    f.insert(
        "threatDetections",
        json!({
            "id": id,
            "tenantId": f.tenant_id,
            "uniqueKey": format!("password-spray:{id}"),
            "ruleId": "password-spray",
            "severity": "high",
            "status": "open",
            "title": "Password spray",
            "summary": "Many accounts tried from one network.",
            "subject": subject,
            "incidentId": incident_id,
            "detectedAt": at,
            "occurredAt": at,
            "evidence": { "eventIds": [], "count": 12, "firstAt": at, "lastAt": at },
        }),
    )
    .await;
    id
}

// --- the API group on stored detections and incidents -------------------------------------------------------------

#[test]
fn validates_input_before_anything_runs() {
    run(|| async {
        let f = fixture().await;
        let threats = &f.iam.api.threats;
        let tenant = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let respond = |input: Value| {
            let input = merged(json!({ "tenantId": tenant, "reason": "x" }), input);
            let owner = owner.clone();
            async move { fails(threats.respond(&owner, body(input)).await) }
        };
        for (input, message) in [
            (
                json!({ "actions": [{ "kind": "notify" }] }),
                "Respond to exactly one of incidentId, identityId or network",
            ),
            (
                json!({ "identityId": "a", "network": "10.0.0.1", "actions": [{ "kind": "notify" }] }),
                "Respond to exactly one of incidentId, identityId or network",
            ),
            (
                json!({ "network": "not a network", "actions": [{ "kind": "notify" }] }),
                "network must be an IPv4/IPv6 address or CIDR block",
            ),
            (
                json!({ "network": "10.0.0.1", "actions": [] }),
                "actions must list 1-5 response actions",
            ),
            (
                json!({ "network": "10.0.0.1", "actions": [{ "kind": "block-network", "durationMs": 1 }] }),
                "Invalid durationMs",
            ),
        ] {
            let error = respond(input).await;
            assert_eq!(
                (code(&error), error.message.as_str()),
                ("INVALID_INPUT", message)
            );
        }
        let error = fails(
            threats
                .set_risk(
                    &owner,
                    body(json!({
                        "tenantId": tenant, "identityId": f.owner_id, "level": "none",
                        "reason": "x", "expiresInMs": HOUR,
                    })),
                )
                .await,
        );
        assert_eq!(error.message, "expiresInMs applies to a raised level only");
        let error = fails(
            threats
                .set_risk(
                    &owner,
                    body(json!({ "tenantId": tenant, "identityId": "a", "level": "severe", "reason": "x" })),
                )
                .await,
        );
        assert_eq!(
            error.message,
            "level must be one of none, low, medium, high"
        );
        let error = fails(
            threats
                .add_note(
                    &owner,
                    body(json!({ "tenantId": tenant, "incidentId": "i", "body": "\u{1}\u{2}" })),
                )
                .await,
        );
        assert_eq!(error.message, "body must be 1-4000 characters");
        let error = fails(
            threats
                .resolve_incident(
                    &owner,
                    body(json!({ "tenantId": tenant, "incidentId": "i", "resolution": "fixed" })),
                )
                .await,
        );
        assert_eq!(
            error.message,
            "resolution must be one of true-positive, false-positive, benign"
        );
        let error = fails(
            threats
                .list_detections(&owner, body(json!({ "tenantId": tenant, "limit": 0 })))
                .await,
        );
        assert_eq!(error.message, "Invalid limit");
        let error = fails(
            threats
                .list_detections(
                    &owner,
                    body(json!({ "tenantId": tenant, "status": "closed" })),
                )
                .await,
        );
        assert_eq!(
            error.message,
            "status must be one of open, dismissed, resolved"
        );
        let error = fails(
            threats
                .list_risk(
                    &owner,
                    body(json!({ "tenantId": tenant, "minLevel": "none" })),
                )
                .await,
        );
        assert_eq!(error.message, "minLevel must be one of low, medium, high");
        // `lists incidents in one status or several`: the refused statuses.
        for bad in [
            json!([]),
            json!(["open", "closed"]),
            json!("closed"),
            json!(3),
            json!(["open", "investigating", "resolved", "open"]),
        ] {
            let error = fails(
                threats
                    .list_incidents(&owner, body(json!({ "tenantId": tenant, "status": bad })))
                    .await,
            );
            assert_eq!(code(&error), "INVALID_INPUT");
        }
        // `bounds the timeline with until`: the refused windows.
        let at = f.now();
        for window in [
            json!({ "since": at, "until": at }),
            json!({ "since": at, "until": at - 1.0 }),
            json!({ "until": -1 }),
            json!({ "until": "soon" }),
        ] {
            let error = fails(
                threats
                    .timeline(
                        &owner,
                        body(merged(
                            json!({ "tenantId": tenant, "identityId": f.owner_id }),
                            window,
                        )),
                    )
                    .await,
            );
            assert_eq!(code(&error), "INVALID_INPUT");
        }
    });
}

#[test]
fn refuses_callers_without_the_permission_or_a_recent_sign_in() {
    run(|| async {
        let f = fixture().await;
        let threats = &f.iam.api.threats;
        let tenant = f.tenant_id.clone();
        let alice = f.member("alice").await;
        let plain = f.sign_in(&alice).await;
        let reads = [
            fails(
                threats
                    .list_detections(&plain, body(json!({ "tenantId": tenant })))
                    .await,
            ),
            fails(
                threats
                    .list_incidents(&plain, body(json!({ "tenantId": tenant })))
                    .await,
            ),
            fails(
                threats
                    .summary(&plain, body(json!({ "tenantId": tenant })))
                    .await,
            ),
            fails(
                threats
                    .rules(&plain, body(json!({ "tenantId": tenant })))
                    .await,
            ),
            fails(
                threats
                    .get_risk(
                        &plain,
                        body(json!({ "tenantId": tenant, "identityId": alice })),
                    )
                    .await,
            ),
        ];
        for error in reads {
            assert_eq!(code(&error), "ACCESS_DENIED");
        }
        // Reading does not allow triage.
        let (_, reader) = member_with(
            &f,
            "reader",
            json!([{ "effect": "allow", "actions": ["iam:threats:read"], "resources": ["iam/threats/*"] }]),
        )
        .await;
        let error = fails(
            threats
                .update_incident(
                    &reader,
                    body(json!({ "tenantId": tenant, "incidentId": "nope", "status": "investigating" })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        // Tuning and responding need a recent sign-in.
        f.advance(DAY);
        let error = fails(
            threats
                .configure(
                    &f.owner_credential,
                    body(json!({ "tenantId": tenant, "dormantDays": 30 })),
                )
                .await,
        );
        assert_eq!(code(&error), "RECENT_AUTH_REQUIRED");
        let error = fails(
            threats
                .respond(
                    &f.owner_credential,
                    body(json!({
                        "tenantId": tenant, "network": "198.51.100.0/24",
                        "actions": [{ "kind": "notify" }], "reason": "x",
                    })),
                )
                .await,
        );
        assert_eq!(code(&error), "RECENT_AUTH_REQUIRED");
        // Nobody sets their own risk level.
        let owner = f.session(&f.owner_id, false).await;
        let error = fails(
            threats
                .set_risk(
                    &owner,
                    body(json!({ "tenantId": tenant, "identityId": f.owner_id, "level": "none", "reason": "x" })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        assert_eq!(
            error.message,
            "Your own risk level is set by another administrator"
        );
        let denied = f
            .find(
                "audit",
                Filter::new()
                    .eq("tenantId", tenant.clone())
                    .eq("action", "iam:threats:respond")
                    .eq("outcome", "deny"),
            )
            .await;
        assert_eq!(denied.len(), 1);
    });
}

#[test]
fn reports_come_from_a_sign_in_session_of_the_account_s_own_tenant() {
    run(|| async {
        let f = fixture().await;
        let threats = &f.iam.api.threats;
        // The root administrator is not a member of the organization.
        let error = fails(
            threats
                .report_suspicious(&f.root_credential, body(json!({ "tenantId": f.tenant_id })))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        assert_eq!(
            error.message,
            "Suspicious activity is reported from a sign-in session of the account\u{2019}s own tenant"
        );
        // A member reports on their own tenant only.
        let alice = f.member("alice").await;
        let session = f.sign_in(&alice).await;
        let error = fails(
            threats
                .report_suspicious(&session, body(json!({ "tenantId": f.root_tenant })))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            threats
                .report_suspicious(
                    &session,
                    body(json!({ "tenantId": f.tenant_id, "note": "\u{7}" })),
                )
                .await,
        );
        assert_eq!(error.message, "note must be 1-1000 characters");
        assert!(
            f.find(
                "threatDetections",
                Filter::new().eq("tenantId", f.tenant_id.clone())
            )
            .await
            .is_empty()
        );
    });
}

#[test]
fn triages_notes_and_resolves_stored_incidents() {
    run(|| async {
        let f = fixture().await;
        let threats = &f.iam.api.threats;
        let tenant = f.tenant_id.clone();
        let owner = f.session(&f.owner_id, false).await;
        let start = f.now();
        let alice = f.member("alice").await;
        let older = seed_incident(&f, "203.0.113.0", "medium", start - 3.0 * HOUR).await;
        let newer = seed_incident(&f, "198.51.100.0", "high", start - HOUR).await;
        let first = seed_detection(
            &f,
            &newer,
            json!({ "type": "network", "id": "198.51.100.0" }),
            start - 2.0 * HOUR,
        )
        .await;
        let about_alice = seed_detection(
            &f,
            &newer,
            json!({ "type": "identity", "id": alice, "name": "alice (alice@acme.test)" }),
            start - HOUR,
        )
        .await;

        // Newest first; identity subjects gain their kind when read, never stored.
        let page = ok(threats
            .list_detections(&owner, body(json!({ "tenantId": tenant })))
            .await);
        assert_eq!(page["total"], json!(2));
        assert_eq!(
            ids(&page, "detections"),
            vec![about_alice.clone(), first.clone()]
        );
        assert_eq!(
            page["detections"][0]["subject"],
            json!({ "type": "identity", "id": alice, "name": "alice (alice@acme.test)", "kind": "user" })
        );
        assert_eq!(
            page["detections"][1]["subject"],
            json!({ "type": "network", "id": "198.51.100.0" })
        );
        let since = ok(threats
            .list_detections(
                &owner,
                body(json!({ "tenantId": tenant, "since": start - 90.0 * 60_000.0, "limit": 5 })),
            )
            .await);
        assert_eq!(ids(&since, "detections"), vec![about_alice.clone()]);
        assert_eq!(since["total"], json!(1));
        let stored = f
            .find(
                "threatDetections",
                Filter::new().eq("id", about_alice.clone()),
            )
            .await;
        assert!(stored[0]["subject"].get("kind").is_none());
        let detection = ok(threats
            .get_detection(
                &owner,
                body(json!({ "tenantId": tenant, "detectionId": first })),
            )
            .await);
        assert_eq!(detection["evidence"]["count"], json!(12));
        let error = fails(
            threats
                .get_detection(
                    &owner,
                    body(json!({ "tenantId": f.root_tenant, "detectionId": first })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");

        // Most recently active first, narrowed by status.
        let incidents = ok(threats
            .list_incidents(&owner, body(json!({ "tenantId": tenant })))
            .await);
        assert_eq!(
            ids(&incidents, "incidents"),
            vec![newer.clone(), older.clone()]
        );
        let updated = ok(threats
            .update_incident(
                &owner,
                body(json!({
                    "tenantId": tenant, "incidentId": older, "status": "investigating",
                    "assigneeId": f.owner_id, "severity": "critical",
                })),
            )
            .await);
        assert_matches(
            &updated,
            json!({ "status": "investigating", "severity": "critical", "assigneeId": f.owner_id }),
        );
        let audit = f
            .find(
                "audit",
                Filter::new()
                    .eq("tenantId", tenant.clone())
                    .eq("action", "threat:incident-update"),
            )
            .await;
        assert_eq!(
            audit[0]["metadata"],
            json!({
                "changes": ["status", "severity", "assigneeId"],
                "status": "investigating",
                "severity": "critical",
                "assigneeId": f.owner_id,
            })
        );
        let unassigned = ok(threats
            .update_incident(
                &owner,
                body(json!({ "tenantId": tenant, "incidentId": older, "assigneeId": null })),
            )
            .await);
        assert!(unassigned.get("assigneeId").is_none());
        let error = fails(
            threats
                .update_incident(
                    &owner,
                    body(json!({ "tenantId": tenant, "incidentId": older, "status": "resolved" })),
                )
                .await,
        );
        assert_eq!(error.message, "status must be one of open, investigating");
        let error = fails(
            threats
                .update_incident(
                    &owner,
                    body(
                        json!({ "tenantId": tenant, "incidentId": older, "assigneeId": "nobody" }),
                    ),
                )
                .await,
        );
        assert_eq!(code(&error), "NOT_FOUND");
        let list = |status: Value| {
            let owner = owner.clone();
            let tenant = tenant.clone();
            async move {
                ids(
                    &ok(threats
                        .list_incidents(
                            &owner,
                            body(json!({ "tenantId": tenant, "status": status })),
                        )
                        .await),
                    "incidents",
                )
            }
        };
        assert_eq!(list(json!("open")).await, vec![newer.clone()]);
        assert_eq!(list(json!(["investigating"])).await, vec![older.clone()]);
        assert_eq!(
            list(json!(["investigating", "open"])).await,
            vec![newer.clone(), older.clone()]
        );

        // Notes are cleaned, ordered oldest first, and audited without their text.
        ok(threats
            .add_note(
                &owner,
                body(json!({ "tenantId": tenant, "incidentId": newer, "body": "Called the ISP.\r\nBlocked." })),
            )
            .await);
        f.advance(1_000.0);
        let resolved = ok(threats
            .resolve_incident(
                &owner,
                body(json!({
                    "tenantId": tenant, "incidentId": newer, "resolution": "true-positive",
                    "note": "Confirmed spray.",
                })),
            )
            .await);
        assert_matches(
            &resolved,
            json!({ "status": "resolved", "resolution": "true-positive", "resolvedBy": f.owner_id }),
        );
        assert!(resolved.get("uniqueKey").is_none());
        let error = fails(
            threats
                .resolve_incident(
                    &owner,
                    body(
                        json!({ "tenantId": tenant, "incidentId": newer, "resolution": "benign" }),
                    ),
                )
                .await,
        );
        assert_eq!((code(&error), error.status), ("INVALID_TRANSITION", 409));
        let error = fails(
            threats
                .update_incident(
                    &owner,
                    body(json!({ "tenantId": tenant, "incidentId": newer, "status": "open" })),
                )
                .await,
        );
        assert_eq!(error.message, "Resolved incidents cannot be changed");
        let detail = ok(threats
            .get_incident(
                &owner,
                body(json!({ "tenantId": tenant, "incidentId": newer })),
            )
            .await);
        assert_eq!(detail["incident"]["status"], json!("resolved"));
        assert_eq!(
            ids(&detail, "detections"),
            vec![about_alice.clone(), first.clone()]
        );
        assert_eq!(detail["detections"][0]["status"], json!("resolved"));
        assert_eq!(detail["detections"][0]["subject"]["kind"], json!("user"));
        let notes: Vec<&str> = detail["notes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|note| note["body"].as_str().unwrap())
            .collect();
        assert_eq!(notes, vec!["Called the ISP.\nBlocked.", "Confirmed spray."]);
        assert_eq!(detail["responses"], json!([]));
        assert!(detail.get("risk").is_none());
        let audit = f
            .find(
                "audit",
                Filter::new()
                    .eq("tenantId", tenant.clone())
                    .eq("action", "threat:incident-resolve"),
            )
            .await;
        assert_eq!(
            audit[0]["metadata"],
            json!({
                "resolution": "true-positive",
                "severity": "high",
                "subjectType": "network",
                "subjectId": "198.51.100.0",
                "detectionsResolved": 2,
            })
        );
        let notes = f
            .find(
                "audit",
                Filter::new()
                    .eq("tenantId", tenant.clone())
                    .eq("action", "threat:note"),
            )
            .await;
        assert_eq!(notes[0]["metadata"]["length"], json!(24));
        assert_eq!(list(json!("resolved")).await, vec![newer.clone()]);

        // A dismissed detection is no longer open.
        let open = seed_detection(
            &f,
            &older,
            json!({ "type": "network", "id": "203.0.113.0" }),
            start,
        )
        .await;
        let error = fails(
            threats
                .dismiss_detection(
                    &owner,
                    body(json!({ "tenantId": tenant, "detectionId": first, "reason": "noise" })),
                )
                .await,
        );
        assert_eq!(error.message, "Only open detections can be dismissed");
        let dismissed = ok(threats
            .dismiss_detection(
                &owner,
                body(json!({ "tenantId": tenant, "detectionId": open, "reason": "  scanner  " })),
            )
            .await);
        assert_matches(
            &dismissed,
            json!({ "status": "dismissed", "dismissedBy": f.owner_id, "dismissReason": "scanner" }),
        );

        // The timeline lists what alice did and what was done to her.
        let timeline = ok(threats
            .timeline(
                &owner,
                body(json!({ "tenantId": tenant, "identityId": f.owner_id })),
            )
            .await);
        let actions: Vec<&str> = timeline
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["action"].as_str().unwrap())
            .collect();
        assert!(actions.contains(&"threat:incident-resolve"));
        assert!(actions.contains(&"threat:detection-dismiss"));
        let limited = ok(threats
            .timeline(
                &owner,
                body(json!({ "tenantId": tenant, "identityId": f.owner_id, "limit": 1 })),
            )
            .await);
        assert_eq!(limited.as_array().unwrap().len(), 1);
        // Newest first: the audited allow of the previous timeline read.
        assert_matches(
            &limited[0],
            json!({ "action": "iam:threats:read", "resourceId": format!("threats/risk/{}", f.owner_id) }),
        );
    });
}

#[test]
fn defines_changes_and_deletes_playbooks() {
    run(|| async {
        let f = fixture().await;
        let threats = &f.iam.api.threats;
        let tenant = f.tenant_id.clone();
        let owner = f.session(&f.owner_id, false).await;
        let playbook = ok(threats
            .create_playbook(
                &owner,
                body(json!({
                    "tenantId": tenant,
                    "name": "  Contain reporters ",
                    "trigger": { "minSeverity": "high", "subjectTypes": ["identity", "identity"] },
                    "actions": [
                        { "kind": "revoke-sessions", "keepApiKeys": false },
                        { "kind": "block-network", "durationMs": 60_000 },
                    ],
                })),
            )
            .await);
        assert_matches(
            &playbook,
            json!({
                "name": "Contain reporters",
                "uniqueKey": "name:contain reporters",
                "enabled": true,
                "trigger": { "minSeverity": "high", "subjectTypes": ["identity"] },
                "runs": 0,
                "createdBy": f.owner_id,
            }),
        );
        assert!(playbook.get("description").is_none());
        let playbook_id = playbook["id"].as_str().unwrap().to_owned();
        for (input, expected) in [
            (
                json!({ "name": "contain REPORTERS", "trigger": {}, "actions": [{ "kind": "notify" }] }),
                "CONFLICT",
            ),
            (
                json!({ "name": "dup", "trigger": {}, "actions": [{ "kind": "notify" }, { "kind": "notify" }] }),
                "INVALID_INPUT",
            ),
            (
                json!({ "name": "no trigger", "actions": [{ "kind": "notify" }] }),
                "INVALID_INPUT",
            ),
            (
                json!({ "name": "odd", "trigger": { "when": "always" }, "actions": [{ "kind": "notify" }] }),
                "INVALID_INPUT",
            ),
            (
                json!({ "name": " ", "trigger": {}, "actions": [{ "kind": "notify" }] }),
                "INVALID_INPUT",
            ),
            // Suspending clearances needs the clearances option.
            (
                json!({ "name": "suspend", "trigger": {}, "actions": [{ "kind": "suspend-clearance" }] }),
                "FEATURE_DISABLED",
            ),
        ] {
            let error = fails(
                threats
                    .create_playbook(&owner, body(merged(json!({ "tenantId": tenant }), input)))
                    .await,
            );
            assert_eq!(code(&error), expected, "{}", error.message);
        }
        let renamed = ok(threats
            .update_playbook(
                &owner,
                body(json!({
                    "tenantId": tenant, "playbookId": playbook_id, "name": "Sign reporters out",
                    "description": "d", "enabled": false,
                })),
            )
            .await);
        assert_matches(
            &renamed,
            json!({
                "name": "Sign reporters out",
                "uniqueKey": "name:sign reporters out",
                "enabled": false,
                "description": "d",
                "updatedBy": f.owner_id,
            }),
        );
        let cleared = ok(threats
            .update_playbook(
                &owner,
                body(json!({ "tenantId": tenant, "playbookId": playbook_id, "description": null })),
            )
            .await);
        assert!(cleared.get("description").is_none());
        assert_eq!(cleared["name"], json!("Sign reporters out"));
        let second = ok(threats
            .create_playbook(
                &owner,
                body(json!({
                    "tenantId": tenant, "name": "Alert", "description": "Tell people",
                    "trigger": {}, "actions": [{ "kind": "notify" }],
                })),
            )
            .await);
        let error = fails(
            threats
                .update_playbook(
                    &owner,
                    body(json!({ "tenantId": tenant, "playbookId": second["id"], "name": "sign REPORTERS out" })),
                )
                .await,
        );
        assert_eq!(code(&error), "CONFLICT");
        let listed = ok(threats
            .list_playbooks(&owner, body(json!({ "tenantId": tenant })))
            .await);
        let names: Vec<&str> = listed
            .as_array()
            .unwrap()
            .iter()
            .map(|playbook| playbook["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["Alert", "Sign reporters out"]);
        assert_eq!(
            ok(threats
                .delete_playbook(
                    &owner,
                    body(json!({ "tenantId": tenant, "playbookId": playbook_id }))
                )
                .await),
            json!({ "deleted": true })
        );
        let error = fails(
            threats
                .delete_playbook(
                    &owner,
                    body(json!({ "tenantId": tenant, "playbookId": playbook_id })),
                )
                .await,
        );
        assert_eq!(code(&error), "NOT_FOUND");
        let audit = |action: &'static str| {
            let tenant = tenant.clone();
            let f = &f;
            async move {
                f.find(
                    "audit",
                    Filter::new().eq("tenantId", tenant).eq("action", action),
                )
                .await
            }
        };
        let created = audit("threat:playbook-create").await;
        let first = created
            .iter()
            .find(|event| event["metadata"]["name"] == json!("Contain reporters"))
            .unwrap();
        assert_eq!(
            first["metadata"],
            json!({
                "name": "Contain reporters",
                "enabled": true,
                "trigger": { "minSeverity": "high", "subjectTypes": ["identity"] },
                "actions": [
                    { "kind": "revoke-sessions", "keepApiKeys": false },
                    { "kind": "block-network", "durationMs": 60_000 },
                ],
            })
        );
        let updates = audit("threat:playbook-update").await;
        assert_eq!(updates.len(), 2);
        assert_eq!(
            audit("threat:playbook-delete").await[0]["metadata"],
            json!({ "name": "Sign reporters out" })
        );
    });
}

#[test]
fn playbooks_that_suspend_clearances_need_the_clearance_officer_permission() {
    run(|| async {
        let f =
            organization(|options| options.clearances = Some(ClearanceOptions::default())).await;
        let threats = &f.iam.api.threats;
        let tenant = f.tenant_id.clone();
        let (_, analyst) = member_with(&f, "analyst", threats_administration()).await;
        let input = json!({
            "tenantId": tenant, "name": "Suspend", "trigger": {},
            "actions": [{ "kind": "suspend-clearance" }],
        });
        let error = fails(threats.create_playbook(&analyst, body(input.clone())).await);
        assert_eq!(
            (code(&error), error.message.as_str()),
            (
                "ACCESS_DENIED",
                "Playbooks that suspend clearances need iam:clearances:suspend"
            )
        );
        assert!(
            f.find(
                "threatPlaybooks",
                Filter::new().eq("tenantId", tenant.clone())
            )
            .await
            .is_empty()
        );
        let owner = f.session(&f.owner_id, false).await;
        let playbook = ok(threats.create_playbook(&owner, body(input)).await);
        // Renaming does not widen it; switching it on does.
        let renamed = ok(threats
            .update_playbook(
                &analyst,
                body(json!({ "tenantId": tenant, "playbookId": playbook["id"], "name": "Suspend people" })),
            )
            .await);
        assert_eq!(renamed["name"], json!("Suspend people"));
        ok(threats
            .update_playbook(
                &owner,
                body(json!({ "tenantId": tenant, "playbookId": playbook["id"], "enabled": false })),
            )
            .await);
        let error = fails(
            threats
                .update_playbook(
                    &analyst,
                    body(json!({ "tenantId": tenant, "playbookId": playbook["id"], "enabled": true })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let stored = f
            .find(
                "threatPlaybooks",
                Filter::new().eq("tenantId", tenant.clone()),
            )
            .await;
        assert_eq!(stored[0]["enabled"], json!(false));
        // Each refusal is an audited denial of the operation.
        let denials = f
            .find(
                "audit",
                Filter::new()
                    .eq("tenantId", tenant.clone())
                    .eq("action", "iam:threats:manage")
                    .eq("outcome", "deny"),
            )
            .await;
        assert_eq!(denials.len(), 2);
    });
}

// --- tests/threats-clearances.test.ts (the API's part) -------------------------------------------------------------

#[test]
#[ignore = "needs threats.ts, threat-engine.ts, threat-response.ts and threat-rules.ts (threats units)"]
fn lets_only_people_who_may_suspend_clearances_write_playbooks_that_do() {
    run(|| async {
        let f =
            organization(|options| options.clearances = Some(ClearanceOptions::default())).await;
        let tenant = f.tenant_id.clone();
        let threats = &f.iam.api.threats;
        let (manager_id, manager) = member_with(
            &f,
            "manager",
            json!([{ "effect": "allow", "actions": ["iam:threats:read", "iam:threats:manage"], "resources": ["*"] }]),
        )
        .await;
        let suspend = json!([{ "kind": "suspend-clearance" }]);
        let denied_for = || {
            let (tenant, manager_id) = (tenant.clone(), manager_id.clone());
            let f = &f;
            async move {
                f.find(
                    "audit",
                    Filter::new()
                        .eq("tenantId", tenant)
                        .eq("action", "iam:threats:manage")
                        .eq("outcome", "deny")
                        .eq("actorId", manager_id),
                )
                .await
                .len()
            }
        };
        let error = fails(
            threats
                .create_playbook(
                    &manager,
                    body(json!({ "tenantId": tenant, "name": "Suspend everyone", "trigger": {}, "actions": suspend })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        assert_eq!(denied_for().await, 1);
        let notify = ok(threats
            .create_playbook(
                &manager,
                body(json!({ "tenantId": tenant, "name": "Notify", "trigger": {}, "actions": [{ "kind": "notify" }] })),
            )
            .await);
        let error = fails(
            threats
                .update_playbook(
                    &manager,
                    body(json!({
                        "tenantId": tenant, "playbookId": notify["id"],
                        "actions": [{ "kind": "notify" }, { "kind": "suspend-clearance" }],
                    })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let stored = |playbook_id: Value| {
            let f = &f;
            async move {
                f.find("threatPlaybooks", Filter::new().eq("id", playbook_id))
                    .await
                    .remove(0)
            }
        };
        assert_eq!(
            stored(notify["id"].clone()).await["actions"],
            json!([{ "kind": "notify" }])
        );

        // Written by someone who may (the owner), it can be renamed, described and switched off by the manager, but
        // not switched back on or retriggered.
        let owner = f.session(&f.owner_id, false).await;
        let written = ok(threats
            .create_playbook(
                &owner,
                body(json!({
                    "tenantId": tenant, "name": "Suspend on probing",
                    "trigger": { "ruleIds": ["classified-access-attempts"] }, "actions": suspend,
                })),
            )
            .await);
        let update = |change: Value| {
            let (tenant, manager) = (tenant.clone(), manager.clone());
            let playbook_id = written["id"].clone();
            async move {
                threats
                    .update_playbook(
                        &manager,
                        body(merged(
                            json!({ "tenantId": tenant, "playbookId": playbook_id }),
                            change,
                        )),
                    )
                    .await
                    .and_then(|reply| reply.into_value())
            }
        };
        update(json!({ "name": "Suspend on classified probing", "description": "Owner-approved" }))
            .await
            .unwrap();
        assert_matches(
            &update(json!({ "enabled": false })).await.unwrap(),
            json!({ "enabled": false }),
        );
        for change in [json!({ "enabled": true }), json!({ "trigger": {} })] {
            assert_eq!(code(&update(change).await.unwrap_err()), "ACCESS_DENIED");
        }
        assert_matches(
            &Value::Object(stored(written["id"].clone()).await),
            json!({
                "name": "Suspend on classified probing",
                "enabled": false,
                "trigger": { "ruleIds": ["classified-access-attempts"] },
                "actions": suspend,
            }),
        );
        // Taking the suspension out only narrows what it does.
        assert_matches(
            &update(json!({ "actions": [{ "kind": "notify" }] }))
                .await
                .unwrap(),
            json!({ "actions": [{ "kind": "notify" }] }),
        );
        assert_eq!(denied_for().await, 4);
    });
}

// --- tests/threats-api.test.ts ------------------------------------------------------------------------------------

#[test]
#[ignore = "needs threats.ts, threat-engine.ts, threat-response.ts and threat-rules.ts (threats units)"]
fn rules_settings_guardrail_detection_validation() {
    let _ = THREAT_UNITS;
    run(|| async {
        let f = fixture().await;
        let threats = &f.iam.api.threats;
        let tenant = f.tenant_id.clone();
        let rules = ok(threats
            .rules(&f.owner_credential, body(json!({ "tenantId": tenant })))
            .await);
        assert_eq!(rules.as_array().unwrap().len(), 22);
        let new_network = rules
            .as_array()
            .unwrap()
            .iter()
            .find(|rule| rule["id"] == json!("new-network"))
            .unwrap();
        assert_matches(
            new_network,
            json!({ "everyone": false, "customized": false }),
        );
        assert_matches(
            &ok(threats
                .get_settings(&f.owner_credential, body(json!({ "tenantId": tenant })))
                .await),
            json!({ "configured": false, "dormantDays": 90 }),
        );
        let owner = f.session(&f.owner_id, false).await;
        for bad in [
            json!({ "rules": { "nope": { "enabled": false } } }),
            json!({ "rules": { "brute-force": { "threshold": 1 } } }),
            json!({ "rules": { "session-hijack": { "threshold": 5 } } }),
            json!({ "rules": { "brute-force": { "everyone": true } } }),
            json!({ "rules": { "brute-force": { "colour": "red" } } }),
            json!({ "trustedNetworks": ["0.0.0.0/0"] }),
            json!({ "trustedNetworks": ["::ffff:0:0/96"] }),
            json!({ "trustedNetworks": ["not an ip"] }),
            json!({ "dormantDays": 3 }),
            json!({ "notify": { "emails": ["nope"] } }),
        ] {
            let error = fails(
                threats
                    .configure(&owner, body(merged(json!({ "tenantId": tenant }), bad)))
                    .await,
            );
            assert_eq!(code(&error), "INVALID_INPUT");
        }
        let view = ok(threats
            .configure(
                &owner,
                body(json!({
                    "tenantId": tenant,
                    "rules": {
                        "brute-force": { "enabled": false, "threshold": 20 },
                        "new-network": { "everyone": true },
                    },
                    "trustedNetworks": ["10.0.0.0/8"],
                    "notify": { "owners": true },
                })),
            )
            .await);
        assert_matches(
            &view,
            json!({ "configured": true, "trustedNetworks": ["10.0.0.0/8"] }),
        );
        assert_matches(
            &view["rules"]["brute-force"],
            json!({ "enabled": false, "threshold": 20 }),
        );
        let audit = f
            .find(
                "audit",
                Filter::new()
                    .eq("tenantId", tenant.clone())
                    .eq("action", "threat:settings"),
            )
            .await;
        assert_matches(
            &audit[0]["metadata"],
            json!({ "changed": ["rules", "trustedNetworks", "notify"], "disabledRules": ["brute-force"] }),
        );
        let detections = ok(threats
            .list_detections(
                &f.owner_credential,
                body(json!({ "tenantId": tenant, "ruleId": "guardrail-weakened" })),
            )
            .await);
        assert_eq!(detections["total"], json!(1));
        assert_matches(
            &detections["detections"][0],
            json!({ "identityId": f.owner_id, "subject": { "type": "tenant" } }),
        );
        // A null rule clears its adjustments; re-enabling raises nothing.
        ok(threats
            .configure(
                &owner,
                body(json!({ "tenantId": tenant, "rules": { "brute-force": null } })),
            )
            .await);
        let rules = ok(threats
            .rules(&f.owner_credential, body(json!({ "tenantId": tenant })))
            .await);
        let brute_force = rules
            .as_array()
            .unwrap()
            .iter()
            .find(|rule| rule["id"] == json!("brute-force"))
            .unwrap();
        assert_matches(
            brute_force,
            json!({ "enabled": true, "threshold": 10, "customized": false }),
        );
        // Nobody dismisses a detection about themselves.
        let error = fails(
            threats
                .dismiss_detection(
                    &owner,
                    body(json!({
                        "tenantId": tenant, "detectionId": detections["detections"][0]["id"],
                        "reason": "mine",
                    })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let summary = ok(threats
            .summary(&f.owner_credential, body(json!({ "tenantId": tenant })))
            .await);
        assert_matches(
            &summary,
            json!({ "detections24h": 1, "byRule24h": { "guardrail-weakened": 1 } }),
        );
        assert_eq!(summary["openIncidents"]["medium"], json!(1));
        assert_eq!(summary["riskyIdentities"]["low"], json!(1));
    });
}

#[test]
#[ignore = "needs threats.ts, threat-engine.ts, threat-response.ts and threat-rules.ts (threats units)"]
fn report_risk_incidents_respond_release_playbooks() {
    run(|| async {
        let f = fixture().await;
        let threats = &f.iam.api.threats;
        let tenant = f.tenant_id.clone();
        let alice = f.member("alice").await;
        let first = f.sign_in(&alice).await;
        let second = f.sign_in(&alice).await;
        let report = ok(threats
            .report_suspicious(
                &second,
                body(json!({ "tenantId": tenant, "note": "line one\r\nline two\u{7}" })),
            )
            .await);
        assert_matches(
            &report,
            json!({ "sessionsEnded": 1, "devicesForgotten": 0 }),
        );
        assert_eq!(
            code(&f.iam.authenticate(&first).await.unwrap_err()),
            "UNAUTHENTICATED"
        );
        f.iam.authenticate(&second).await.unwrap();
        let error = fails(
            threats
                .list_detections(&second, body(json!({ "tenantId": tenant })))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let detection = ok(threats
            .get_detection(
                &f.owner_credential,
                body(json!({ "tenantId": tenant, "detectionId": report["detectionId"] })),
            )
            .await);
        assert_eq!(
            detection["metadata"],
            json!({ "note": "line one\nline two" })
        );
        let risk = ok(threats
            .get_risk(
                &f.owner_credential,
                body(json!({ "tenantId": tenant, "identityId": alice })),
            )
            .await);
        assert_matches(
            &risk,
            json!({ "level": "medium", "score": 50, "kind": "user" }),
        );

        // principal.riskLevel reaches decisions.
        f.grant(
            &alice,
            json!([{
                "effect": "allow",
                "actions": ["documents:read"],
                "resources": ["*"],
                "conditions": { "StringEquals": { "principal.riskLevel": "none" } },
            }]),
        )
        .await;
        assert!(!can_read(&f, &second).await);

        let owner = f.session(&f.owner_id, false).await;
        let incident = ok(threats
            .get_incident(
                &f.owner_credential,
                body(json!({ "tenantId": tenant, "incidentId": report["incidentId"] })),
            )
            .await);
        assert_eq!(incident["detections"].as_array().unwrap().len(), 1);
        let mut actions: Vec<&str> = incident["responses"]
            .as_array()
            .unwrap()
            .iter()
            .map(|response| response["action"].as_str().unwrap())
            .collect();
        actions.sort();
        assert_eq!(actions, vec!["forget-devices", "revoke-sessions"]);
        assert_matches(&incident["risk"], json!({ "level": "medium" }));
        ok(threats
            .add_note(
                &f.owner_credential,
                body(json!({
                    "tenantId": tenant, "incidentId": report["incidentId"],
                    "body": "Called alice.\nConfirmed.",
                })),
            )
            .await);
        let updated = ok(threats
            .update_incident(
                &f.owner_credential,
                body(json!({
                    "tenantId": tenant, "incidentId": report["incidentId"],
                    "status": "investigating", "assigneeId": f.owner_id,
                })),
            )
            .await);
        assert_matches(
            &updated,
            json!({ "status": "investigating", "assigneeId": f.owner_id }),
        );
        let unassigned = ok(threats
            .update_incident(
                &f.owner_credential,
                body(json!({ "tenantId": tenant, "incidentId": report["incidentId"], "assigneeId": null })),
            )
            .await);
        assert!(unassigned.get("assigneeId").is_none());

        let error = fails(
            threats
                .set_risk(
                    &owner,
                    body(json!({ "tenantId": tenant, "identityId": f.owner_id, "level": "none", "reason": "x" })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        assert_matches(
            &ok(threats
                .set_risk(
                    &owner,
                    body(json!({
                        "tenantId": tenant, "identityId": alice, "level": "high",
                        "reason": "confirmed", "expiresInMs": 3_600_000,
                    })),
                )
                .await),
            json!({ "level": "high", "override": { "level": "high", "active": true } }),
        );
        let listed = ok(threats
            .list_risk(
                &f.owner_credential,
                body(json!({ "tenantId": tenant, "minLevel": "high" })),
            )
            .await);
        let listed: Vec<&str> = listed["identities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["identityId"].as_str().unwrap())
            .collect();
        assert_eq!(listed, vec![alice.as_str()]);

        let contained = ok(threats
            .respond(
                &owner,
                body(json!({
                    "tenantId": tenant, "identityId": alice,
                    "actions": [{ "kind": "contain" }, { "kind": "notify" }],
                    "reason": "compromised",
                })),
            )
            .await);
        let outcomes: Vec<(Value, Value, Value)> = contained
            .as_array()
            .unwrap()
            .iter()
            .map(|response| {
                (
                    response["action"].clone(),
                    response["outcome"].clone(),
                    response.get("reason").cloned().unwrap_or(Value::Null),
                )
            })
            .collect();
        assert_eq!(
            outcomes,
            vec![
                (json!("contain"), json!("applied"), Value::Null),
                (json!("notify"), json!("skipped"), json!("no-recipients")),
            ]
        );
        assert_eq!(contained[0]["incidentId"], report["incidentId"]);
        assert!(f.iam.authenticate(&second).await.is_err());
        let released = ok(threats
            .release(
                &owner,
                body(json!({ "tenantId": tenant, "identityId": alice, "note": "ok" })),
            )
            .await);
        assert_matches(
            &released,
            json!({ "action": "release", "outcome": "applied" }),
        );
        let error = fails(
            threats
                .release(
                    &owner,
                    body(json!({ "tenantId": tenant, "identityId": alice })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_TRANSITION");

        let resolved = ok(threats
            .resolve_incident(
                &owner,
                body(json!({
                    "tenantId": tenant, "incidentId": report["incidentId"],
                    "resolution": "false-positive", "note": "Was the VPN.",
                })),
            )
            .await);
        assert_matches(
            &resolved,
            json!({ "status": "resolved", "resolution": "false-positive" }),
        );
        assert!(resolved.get("uniqueKey").is_none());
        let after = ok(threats
            .get_risk(
                &f.owner_credential,
                body(json!({ "tenantId": tenant, "identityId": alice })),
            )
            .await);
        assert_eq!(after["contributions"], json!([]));
        assert_eq!(after["level"], json!("high")); // the override still holds
        ok(threats
            .set_risk(
                &owner,
                body(json!({ "tenantId": tenant, "identityId": alice, "level": "none", "reason": "clear" })),
            )
            .await);
        assert_eq!(
            ok(threats
                .get_risk(
                    &f.owner_credential,
                    body(json!({ "tenantId": tenant, "identityId": alice })),
                )
                .await)["level"],
            json!("none")
        );
        let error = fails(
            threats
                .resolve_incident(
                    &owner,
                    body(json!({
                        "tenantId": tenant, "incidentId": report["incidentId"], "resolution": "benign",
                    })),
                )
                .await,
        );
        assert_eq!((code(&error), error.status), ("INVALID_TRANSITION", 409));
        let timeline = ok(threats
            .timeline(
                &f.owner_credential,
                body(json!({ "tenantId": tenant, "identityId": alice })),
            )
            .await);
        assert!(
            timeline
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["action"] == json!("threat:user-report"))
        );

        let playbook = ok(threats
            .create_playbook(
                &owner,
                body(json!({
                    "tenantId": tenant,
                    "name": "Contain reporters",
                    "trigger": { "ruleIds": ["user-reported"], "minSeverity": "high" },
                    "actions": [
                        { "kind": "revoke-sessions", "keepApiKeys": false },
                        { "kind": "block-network", "durationMs": 60_000 },
                    ],
                })),
            )
            .await);
        let error = fails(
            threats
                .create_playbook(
                    &owner,
                    body(json!({
                        "tenantId": tenant, "name": "contain REPORTERS", "trigger": {},
                        "actions": [{ "kind": "notify" }],
                    })),
                )
                .await,
        );
        assert_eq!(code(&error), "CONFLICT");
        let renamed = ok(threats
            .update_playbook(
                &owner,
                body(json!({
                    "tenantId": tenant, "playbookId": playbook["id"], "name": "Sign reporters out",
                    "description": "d", "enabled": false,
                })),
            )
            .await);
        assert_matches(
            &renamed,
            json!({ "name": "Sign reporters out", "enabled": false, "description": "d" }),
        );
        assert_eq!(
            ok(threats
                .list_playbooks(&f.owner_credential, body(json!({ "tenantId": tenant })))
                .await)
            .as_array()
            .unwrap()
            .len(),
            1
        );
        assert_eq!(
            ok(threats
                .delete_playbook(
                    &owner,
                    body(json!({ "tenantId": tenant, "playbookId": playbook["id"] })),
                )
                .await),
            json!({ "deleted": true })
        );

        let run = ok(threats
            .detect(&f.owner_credential, body(json!({ "tenantId": tenant })))
            .await);
        assert_eq!(run["tenants"], json!(1));
        let incidents = ok(threats
            .list_incidents(
                &f.owner_credential,
                body(json!({ "tenantId": tenant, "status": "resolved" })),
            )
            .await);
        assert_eq!(incidents["total"], json!(1));
    });
}

#[test]
#[ignore = "needs threats.ts, threat-engine.ts, threat-response.ts and threat-rules.ts (threats units)"]
fn protections_contain_an_owner_only_for_an_owner_in_person_or_root() {
    run(|| async {
        let f = fixture().await;
        let tenant = f.tenant_id.clone();
        let owner = f.session(&f.owner_id, false).await;
        let co_owner = f.member("coowner").await;
        ok(f.iam
            .api
            .identities
            .set_owner(
                &owner,
                body(json!({ "tenantId": tenant, "identityId": co_owner, "owner": true })),
            )
            .await);
        let (_, analyst) = member_with(&f, "analyst", threats_administration()).await;
        let error = fails(
            f.iam
                .api
                .threats
                .respond(
                    &analyst,
                    body(json!({
                        "tenantId": tenant, "identityId": co_owner,
                        "actions": [{ "kind": "contain" }], "reason": "looks odd",
                    })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        assert_eq!(status_of(&f, &co_owner).await.as_deref(), Some("active"));
        let contained = ok(f
            .iam
            .api
            .threats
            .respond(
                &owner,
                body(json!({
                    "tenantId": tenant, "identityId": co_owner,
                    "actions": [{ "kind": "contain" }], "reason": "confirmed",
                })),
            )
            .await);
        assert_matches(
            &contained[0],
            json!({ "action": "contain", "outcome": "applied" }),
        );
        assert_eq!(status_of(&f, &co_owner).await.as_deref(), Some("disabled"));
    });
}

#[test]
#[ignore = "needs threats.ts, threat-engine.ts, threat-response.ts and threat-rules.ts (threats units)"]
fn protections_never_release_what_another_path_disabled_suspended_or_re_enabled() {
    run(|| async {
        let f = fixture().await;
        let tenant = f.tenant_id.clone();
        let api = &f.iam.api;
        let owner = f.session(&f.owner_id, false).await;
        let contain = |identity_id: String| {
            let (owner, tenant) = (owner.clone(), tenant.clone());
            async move {
                ok(api
                    .threats
                    .respond(
                        &owner,
                        body(json!({
                            "tenantId": tenant, "identityId": identity_id,
                            "actions": [{ "kind": "contain" }], "reason": "test",
                        })),
                    )
                    .await)
            }
        };
        let release = |identity_id: String| {
            let (owner, tenant) = (owner.clone(), tenant.clone());
            async move {
                api.threats
                    .release(
                        &owner,
                        body(json!({ "tenantId": tenant, "identityId": identity_id })),
                    )
                    .await
                    .and_then(|reply| reply.into_value())
            }
        };
        let contained_mark = |identity_id: String| {
            let f = &f;
            async move {
                f.find("identityRisk", Filter::new().eq("id", identity_id))
                    .await
                    .into_iter()
                    .next()
                    .and_then(|record| record.get("contained").cloned())
            }
        };

        // Disabled again by an administrator.
        let alice = f.member("alice").await;
        contain(alice.clone()).await;
        ok(api
            .identities
            .set_status(
                &owner,
                body(json!({ "tenantId": tenant, "identityId": alice, "status": "disabled" })),
            )
            .await);
        assert_eq!(
            code(&release(alice.clone()).await.unwrap_err()),
            "INVALID_TRANSITION"
        );
        assert_eq!(status_of(&f, &alice).await.as_deref(), Some("disabled"));
        // Offboarded.
        let bob = f.member("bob").await;
        contain(bob.clone()).await;
        ok(api
            .identities
            .offboard(
                &owner,
                body(json!({ "tenantId": tenant, "identityId": bob, "reason": "left" })),
            )
            .await);
        assert_eq!(
            code(&release(bob.clone()).await.unwrap_err()),
            "INVALID_TRANSITION"
        );
        assert_eq!(status_of(&f, &bob).await.as_deref(), Some("disabled"));
        // Re-enabled, then disabled for another reason.
        let carol = f.member("carol").await;
        contain(carol.clone()).await;
        ok(api
            .identities
            .set_status(
                &owner,
                body(json!({ "tenantId": tenant, "identityId": carol, "status": "active" })),
            )
            .await);
        assert_eq!(contained_mark(carol.clone()).await, None);
        ok(api
            .identities
            .set_status(
                &owner,
                body(json!({ "tenantId": tenant, "identityId": carol, "status": "disabled" })),
            )
            .await);
        assert_eq!(
            code(&release(carol.clone()).await.unwrap_err()),
            "INVALID_TRANSITION"
        );
        // An agent its sponsor suspended as well.
        let agent = ok(api
            .agents
            .create(
                &owner,
                body(json!({ "tenantId": tenant, "name": "Triage bot", "sponsorId": f.owner_id })),
            )
            .await);
        let agent_id = agent["id"].as_str().unwrap().to_owned();
        contain(agent_id.clone()).await;
        ok(api
            .agents
            .suspend(
                &owner,
                body(json!({ "tenantId": tenant, "agentId": agent_id, "reason": "prompt injection" })),
            )
            .await);
        assert_eq!(
            code(&release(agent_id.clone()).await.unwrap_err()),
            "INVALID_TRANSITION"
        );
        assert_eq!(
            ok(api
                .agents
                .get(
                    &owner,
                    body(json!({ "tenantId": tenant, "agentId": agent_id }))
                )
                .await)["standing"],
            json!("suspended")
        );
        // A containment nothing else touched is still released.
        let dave = f.member("dave").await;
        contain(dave.clone()).await;
        assert_matches(
            &release(dave.clone()).await.unwrap(),
            json!({ "action": "release", "outcome": "applied" }),
        );
        assert_eq!(status_of(&f, &dave).await.as_deref(), Some("active"));
    });
}

#[test]
#[ignore = "needs threats.ts, threat-engine.ts, threat-response.ts and threat-rules.ts (threats units)"]
fn protections_name_nobody_on_a_tenant_incident_once_two_people_are_behind_it() {
    run(|| async {
        let f = fixture().await;
        let tenant = f.tenant_id.clone();
        let threats = &f.iam.api.threats;
        let (alice, alice_credential) = member_with(&f, "alice", threats_administration()).await;
        let (mallory, mallory_credential) =
            member_with(&f, "mallory", threats_administration()).await;
        ok(threats
            .configure(
                &alice_credential,
                body(
                    json!({ "tenantId": tenant, "rules": { "recon-burst": { "enabled": false } } }),
                ),
            )
            .await);
        let opened = ok(threats
            .list_incidents(&f.owner_credential, body(json!({ "tenantId": tenant })))
            .await)["incidents"][0]
            .clone();
        assert_matches(
            &opened,
            json!({ "subject": { "type": "tenant" }, "identityId": alice }),
        );
        ok(threats
            .configure(
                &mallory_credential,
                body(json!({ "tenantId": tenant, "rules": { "denial-burst": { "enabled": false } } })),
            )
            .await);
        let detail = ok(threats
            .get_incident(
                &f.owner_credential,
                body(json!({ "tenantId": tenant, "incidentId": opened["id"] })),
            )
            .await);
        assert_eq!(detail["incident"]["detectionCount"], json!(2));
        assert!(detail["incident"].get("identityId").is_none());
        assert_eq!(detail["incident"]["severalIdentities"], json!(true));
        assert!(detail.get("risk").is_none());
        // Containing "the incident" no longer contains whoever came first.
        let owner = f.session(&f.owner_id, false).await;
        let response = ok(threats
            .respond(
                &owner,
                body(json!({
                    "tenantId": tenant, "incidentId": opened["id"],
                    "actions": [{ "kind": "contain" }], "reason": "settings tampering",
                })),
            )
            .await);
        assert_matches(
            &response[0],
            json!({ "outcome": "skipped", "reason": "not-identity" }),
        );
        assert_eq!(status_of(&f, &alice).await.as_deref(), Some("active"));
        assert_eq!(status_of(&f, &mallory).await.as_deref(), Some("active"));
    });
}

#[test]
#[ignore = "needs threats.ts, threat-engine.ts, threat-response.ts and threat-rules.ts (threats units)"]
fn protections_report_weakened_settings_and_keep_people_from_decaying_their_own_risk() {
    run(|| async {
        let f = fixture().await;
        let tenant = f.tenant_id.clone();
        let threats = &f.iam.api.threats;
        let (_, sec) = member_with(&f, "sec", threats_administration()).await;
        // A detection about sec raises their risk; shortening the half-life would erase it at once.
        ok(threats
            .report_suspicious(&sec, body(json!({ "tenantId": tenant })))
            .await);
        let error = fails(
            threats
                .configure(
                    &sec,
                    body(json!({ "tenantId": tenant, "riskHalfLifeHours": 1 })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        assert_eq!(
            ok(threats
                .get_settings(&f.owner_credential, body(json!({ "tenantId": tenant })))
                .await)["riskHalfLifeHours"],
            json!(24)
        );

        let owner = f.session(&f.owner_id, false).await;
        ok(threats
            .configure(
                &owner,
                body(json!({
                    "tenantId": tenant,
                    "riskHalfLifeHours": 2,
                    "trustedNetworks": ["198.51.100.0/24"],
                    "maxAutomaticContainments": 0,
                    "rules": { "brute-force": { "threshold": 1000 } },
                })),
            )
            .await);
        let guardrails = || {
            let tenant = tenant.clone();
            let f = &f;
            async move {
                ok(f.iam
                    .api
                    .threats
                    .list_detections(
                        &f.owner_credential,
                        body(json!({ "tenantId": tenant, "ruleId": "guardrail-weakened" })),
                    )
                    .await)["detections"]
                    .as_array()
                    .unwrap()
                    .clone()
            }
        };
        let found = guardrails().await;
        assert_eq!(found.len(), 1);
        assert_matches(
            &found[0],
            json!({
                "identityId": f.owner_id,
                "title": "Threat detection weakened",
                "metadata": {
                    "disabledRules": [],
                    "weakened": [
                        "rules.brute-force.threshold",
                        "riskHalfLifeHours",
                        "trustedNetworks",
                        "maxAutomaticContainments",
                    ],
                },
            }),
        );
        // Strengthening them again raises nothing.
        ok(threats
            .configure(
                &owner,
                body(json!({
                    "tenantId": tenant,
                    "riskHalfLifeHours": 24,
                    "trustedNetworks": [],
                    "maxAutomaticContainments": 3,
                    "rules": { "brute-force": null },
                })),
            )
            .await);
        assert_eq!(guardrails().await.len(), 1);
    });
}

#[test]
#[ignore = "needs threats.ts, threat-engine.ts, threat-response.ts and threat-rules.ts (threats units)"]
fn protections_keep_risk_contributions_through_a_shortened_half_life() {
    run(|| async {
        let f = fixture().await;
        let tenant = f.tenant_id.clone();
        let threats = &f.iam.api.threats;
        let alice = f.member("alice").await;
        ok(threats
            .report_suspicious(
                &f.sign_in(&alice).await,
                body(json!({ "tenantId": tenant })),
            )
            .await);
        ok(threats
            .configure(
                &f.session(&f.owner_id, false).await,
                body(json!({ "tenantId": tenant, "riskHalfLifeHours": 1 })),
            )
            .await);
        f.advance(12.0 * HOUR);
        // A new detection recomputes the risk under the one-hour half-life: the older contribution is kept.
        ok(threats
            .report_suspicious(
                &f.sign_in(&alice).await,
                body(json!({ "tenantId": tenant })),
            )
            .await);
        let risk = || {
            let tenant = tenant.clone();
            let alice = alice.clone();
            let f = &f;
            async move {
                ok(f.iam
                    .api
                    .threats
                    .get_risk(
                        &f.owner_credential,
                        body(json!({ "tenantId": tenant, "identityId": alice })),
                    )
                    .await)
            }
        };
        assert_eq!(risk().await["contributions"].as_array().unwrap().len(), 2);
        // Restoring the half-life brings the earlier detection's weight back.
        ok(threats
            .configure(
                &f.session(&f.owner_id, false).await,
                body(json!({ "tenantId": tenant, "riskHalfLifeHours": 24 })),
            )
            .await);
        assert_matches(&risk().await, json!({ "level": "high", "score": 85 }));
    });
}

#[test]
#[ignore = "needs threats.ts, threat-engine.ts, threat-response.ts and threat-rules.ts (threats units)"]
fn views_name_people_as_the_rules_do_and_give_identity_subjects_their_kind() {
    run(|| async {
        let f = fixture().await;
        let tenant = f.tenant_id.clone();
        let threats = &f.iam.api.threats;
        let alice = f.member("alice").await;
        let report = ok(threats
            .report_suspicious(
                &f.sign_in(&alice).await,
                body(json!({ "tenantId": tenant })),
            )
            .await);
        let reported = ok(threats
            .get_detection(
                &f.owner_credential,
                body(json!({ "tenantId": tenant, "detectionId": report["detectionId"] })),
            )
            .await);
        assert_eq!(
            reported["subject"],
            json!({ "type": "identity", "id": alice, "name": "alice (alice@acme.test)", "kind": "user" })
        );
        assert_eq!(
            reported["summary"],
            json!("alice (alice@acme.test) reported activity on their account that was not them.")
        );
        let detail = ok(threats
            .get_incident(
                &f.owner_credential,
                body(json!({ "tenantId": tenant, "incidentId": report["incidentId"] })),
            )
            .await);
        assert_eq!(detail["incident"]["subject"], reported["subject"]);
        assert_eq!(detail["detections"][0]["subject"]["kind"], json!("user"));
        // The kind is looked up when read, never stored.
        for (collection, record_id) in [
            ("threatDetections", &report["detectionId"]),
            ("threatIncidents", &report["incidentId"]),
        ] {
            let stored = f
                .find(collection, Filter::new().eq("id", record_id.clone()))
                .await;
            assert_eq!(
                stored[0]["subject"],
                json!({ "type": "identity", "id": alice, "name": "alice (alice@acme.test)" })
            );
        }

        // An AI agent denied again and again: its detection and incident link to an agent.
        let owner = f.session(&f.owner_id, false).await;
        let agent = ok(f
            .iam
            .api
            .agents
            .create(
                &owner,
                body(json!({ "tenantId": tenant, "name": "Triage bot", "sponsorId": f.owner_id })),
            )
            .await);
        let agent_id = agent["id"].as_str().unwrap().to_owned();
        let key = ok(f
            .iam
            .api
            .credentials
            .create(
                &f.owner_credential,
                body(json!({ "tenantId": tenant, "identityId": agent_id })),
            )
            .await);
        let token = organization_fixture::bearer(key["token"].as_str().unwrap());
        ok(threats
            .configure(
                &owner,
                body(json!({
                    "tenantId": tenant,
                    "rules": { "denial-burst": { "threshold": 5 }, "recon-burst": { "enabled": false } },
                })),
            )
            .await);
        f.iam
            .detect_threats(Some(&json!({ "tenantId": tenant })))
            .await
            .unwrap();
        for _ in 0..5 {
            assert!(!can_read(&f, &token).await);
        }
        f.iam
            .detect_threats(Some(&json!({ "tenantId": tenant })))
            .await
            .unwrap();
        let denials = ok(threats
            .list_detections(
                &f.owner_credential,
                body(json!({ "tenantId": tenant, "ruleId": "denial-burst" })),
            )
            .await)["detections"][0]
            .clone();
        assert_matches(
            &denials["subject"],
            json!({ "type": "identity", "id": agent_id, "kind": "agent" }),
        );
        let agent_incident = ok(threats
            .list_incidents(
                &f.owner_credential,
                body(json!({ "tenantId": tenant, "identityId": agent_id })),
            )
            .await)["incidents"][0]
            .clone();
        assert_matches(
            &agent_incident["subject"],
            json!({ "id": agent_id, "kind": "agent" }),
        );
        assert_matches(
            &ok(threats
                .update_incident(
                    &f.owner_credential,
                    body(json!({
                        "tenantId": tenant, "incidentId": agent_incident["id"], "status": "investigating",
                    })),
                )
                .await),
            json!({ "status": "investigating", "subject": { "kind": "agent" } }),
        );

        // Subjects other than identities have no kind; the settings detection names its author as the rules do.
        let weakened = ok(threats
            .list_detections(
                &f.owner_credential,
                body(json!({ "tenantId": tenant, "ruleId": "guardrail-weakened" })),
            )
            .await)["detections"][0]
            .clone();
        assert_eq!(
            weakened["subject"],
            json!({ "type": "tenant", "id": tenant, "name": "Acme" })
        );
        assert!(
            weakened["summary"]
                .as_str()
                .unwrap()
                .starts_with("Acme owner (owner@acme.test) turned off 1 detection rule: ")
        );
    });
}

#[test]
#[ignore = "needs threats.ts, threat-engine.ts, threat-response.ts and threat-rules.ts (threats units)"]
fn views_list_incidents_in_one_status_or_several() {
    run(|| async {
        let f = fixture().await;
        let tenant = f.tenant_id.clone();
        let threats = &f.iam.api.threats;
        let mut reports = std::collections::HashMap::new();
        for name in ["alice", "bob", "carol"] {
            let id = f.member(name).await;
            let report = ok(threats
                .report_suspicious(&f.sign_in(&id).await, body(json!({ "tenantId": tenant })))
                .await);
            reports.insert(name, report["incidentId"].as_str().unwrap().to_owned());
            f.advance(60_000.0);
        }
        let owner = f.session(&f.owner_id, false).await;
        ok(threats
            .update_incident(
                &owner,
                body(json!({ "tenantId": tenant, "incidentId": reports["bob"], "status": "investigating" })),
            )
            .await);
        ok(threats
            .resolve_incident(
                &owner,
                body(json!({ "tenantId": tenant, "incidentId": reports["carol"], "resolution": "true-positive" })),
            )
            .await);
        let list = |status: Value, page: Value| {
            let tenant = tenant.clone();
            let f = &f;
            async move {
                let result = ok(f
                    .iam
                    .api
                    .threats
                    .list_incidents(
                        &f.owner_credential,
                        body(merged(
                            json!({ "tenantId": tenant, "status": status }),
                            page,
                        )),
                    )
                    .await);
                (ids(&result, "incidents"), result["total"].as_u64().unwrap())
            }
        };
        let (alice, bob, carol) = (
            reports["alice"].clone(),
            reports["bob"].clone(),
            reports["carol"].clone(),
        );
        // Most recently active first across the statuses asked for.
        assert_eq!(
            list(json!(["open", "investigating"]), json!({})).await,
            (vec![bob.clone(), alice.clone()], 2)
        );
        assert_eq!(
            list(
                json!(["open", "investigating"]),
                json!({ "limit": 1, "offset": 1 })
            )
            .await,
            (vec![alice.clone()], 2)
        );
        assert_eq!(
            list(json!("open"), json!({})).await,
            (vec![alice.clone()], 1)
        );
        assert_eq!(
            list(json!(["open", "open"]), json!({})).await,
            (vec![alice.clone()], 1)
        );
        assert_eq!(
            list(json!(["resolved"]), json!({})).await,
            (vec![carol.clone()], 1)
        );
        assert_eq!(
            list(json!(["resolved", "investigating", "open"]), json!({})).await,
            (vec![carol, bob, alice], 3)
        );
    });
}

#[test]
#[ignore = "needs threats.ts, threat-engine.ts, threat-response.ts and threat-rules.ts (threats units)"]
fn views_bound_the_timeline_with_until() {
    run(|| async {
        let f = fixture().await;
        let tenant = f.tenant_id.clone();
        let threats = &f.iam.api.threats;
        let alice = f.member("alice").await;
        ok(threats
            .report_suspicious(
                &f.sign_in(&alice).await,
                body(json!({ "tenantId": tenant })),
            )
            .await);
        // A later sign-in (auth events follow the injected clock).
        f.advance(HOUR);
        f.sign_in(&alice).await;
        let timeline = |window: Value| {
            let tenant = tenant.clone();
            let alice = alice.clone();
            let f = &f;
            async move {
                ok(f.iam
                    .api
                    .threats
                    .timeline(
                        &f.owner_credential,
                        body(merged(
                            json!({ "tenantId": tenant, "identityId": alice }),
                            window,
                        )),
                    )
                    .await)
                .as_array()
                .unwrap()
                .clone()
            }
        };
        let everything = timeline(json!({ "since": 0 })).await;
        let reported_at = everything
            .iter()
            .find(|event| event["action"] == json!("threat:user-report"))
            .unwrap()["timestamp"]
            .as_f64()
            .unwrap();
        let before: Vec<Value> = everything
            .iter()
            .filter(|event| event["timestamp"].as_f64().unwrap() <= reported_at)
            .map(|event| event["id"].clone())
            .collect();
        assert!(before.len() < everything.len());
        let bounded: Vec<Value> = timeline(json!({ "since": 0, "until": reported_at }))
            .await
            .iter()
            .map(|event| event["id"].clone())
            .collect();
        assert_eq!(bounded, before);
        // Without since, the window is the seven days before until.
        let recent: Vec<Value> = timeline(json!({ "until": reported_at }))
            .await
            .iter()
            .map(|event| event["id"].clone())
            .collect();
        assert_eq!(recent, before);
    });
}
