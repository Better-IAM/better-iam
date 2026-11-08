//! Response actions of the threats module (threat-response.ts): the respond, release, playbook-response and
//! notification scenarios of tests/threats-api.test.ts, tests/threats-engine.test.ts and
//! tests/threats-clearances.test.ts, calling `applyResponse`, `releaseIdentity`, `notifyIncident` and
//! `afterThreatResponses` directly inside a transaction where the TypeScript tests go through the `threats` API group
//! and the detection engine (ported in their own units).

mod organization_fixture;

use std::sync::{Arc, Mutex};

use better_iam_auth::{DeliveryMessage, delivery_fn};
use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, Filter, IamStoreExt, Record, SessionClientInfo,
};
use better_iam_server::contracts::OperationFailure;
use better_iam_server::options::ClearanceOptions;
use better_iam_server::threat_response::{
    PlaybookBrake, ResponseActor, ResponseRequest, after_threat_responses, apply_response,
    notify_incident, release_identity,
};
use better_iam_server::threats::{
    ResolvedThreatSettings, ResponseAction, ThreatIncident, ThreatResponse, ThreatSubject,
    end_containment, resolve_threat_settings,
};
use organization_fixture::{Org, assert_matches, organization, run};
use serde_json::{Map, Value, json};

const MINUTE: f64 = 60_000.0;
const DAY: f64 = 86_400_000.0;

fn subject(kind: &str, id: &str) -> ThreatSubject {
    ThreatSubject {
        r#type: json!(kind),
        id: id.to_owned(),
        name: None,
        extra: Map::new(),
    }
}

fn action(kind: &str) -> ResponseAction {
    ResponseAction {
        kind: json!(kind),
        duration_ms: None,
        keep_api_keys: None,
        extra: Map::new(),
    }
}

fn request(kind: &str, subject: ThreatSubject, actor: &ResponseActor) -> ResponseRequest {
    ResponseRequest {
        action: action(kind),
        subject,
        identity_id: None,
        network: None,
        incident_id: None,
        detection_id: None,
        playbook_id: None,
        reason: "test".into(),
        actor: actor.clone(),
    }
}

fn defaults() -> ResolvedThreatSettings {
    resolve_threat_settings(None).unwrap()
}

async fn principal(f: &Org, credential: &CredentialInput) -> AuthenticatedPrincipal {
    f.iam
        .ctx
        .principals()
        .unwrap()
        .authenticate(credential)
        .await
        .expect("principal")
}

async fn person(f: &Org, credential: &CredentialInput) -> ResponseActor {
    ResponseActor::person(principal(f, credential).await)
}

/// `applyResponse` in its own transaction, rolled back on failure (the refusal keeps its `OperationDenied` flag).
async fn respond_with(
    f: &Org,
    tenant_id: &str,
    request: ResponseRequest,
    settings: &ResolvedThreatSettings,
    brake: &mut Option<PlaybookBrake>,
) -> Result<ThreatResponse, OperationFailure> {
    let ctx = f.iam.ctx.clone();
    let stash: Arc<Mutex<Option<OperationFailure>>> = Arc::new(Mutex::new(None));
    let failed = stash.clone();
    let tenant_id = tenant_id.to_owned();
    let settings = settings.clone();
    let mut local = brake.clone();
    let result = f
        .iam
        .store
        .transaction(|tx| async move {
            match apply_response(&ctx, &tx, &tenant_id, &request, &settings, local.as_mut()).await {
                Ok(response) => Ok((response, local)),
                Err(failure) => {
                    let error = failure.error.clone();
                    *failed.lock().unwrap() = Some(failure);
                    Err(error)
                }
            }
        })
        .await;
    match result {
        Ok((response, next)) => {
            *brake = next;
            Ok(response)
        }
        Err(error) => Err(stash
            .lock()
            .unwrap()
            .take()
            .unwrap_or_else(|| OperationFailure::from(error))),
    }
}

async fn respond(f: &Org, request: ResponseRequest) -> Result<ThreatResponse, OperationFailure> {
    respond_with(f, &f.tenant_id.clone(), request, &defaults(), &mut None).await
}

/// `releaseIdentity` in its own transaction.
async fn release(
    f: &Org,
    identity_id: &str,
    actor: &ResponseActor,
    note: Option<&str>,
) -> Result<ThreatResponse, OperationFailure> {
    let ctx = f.iam.ctx.clone();
    let stash: Arc<Mutex<Option<OperationFailure>>> = Arc::new(Mutex::new(None));
    let failed = stash.clone();
    let (tenant_id, identity_id, actor) =
        (f.tenant_id.clone(), identity_id.to_owned(), actor.clone());
    let note = note.map(str::to_owned);
    let result = f
        .iam
        .store
        .transaction(|tx| async move {
            release_identity(&ctx, &tx, &tenant_id, &identity_id, &actor, note.as_deref())
                .await
                .map_err(|failure| {
                    let error = failure.error.clone();
                    *failed.lock().unwrap() = Some(failure);
                    error
                })
        })
        .await;
    result.map_err(|error| {
        stash
            .lock()
            .unwrap()
            .take()
            .unwrap_or_else(|| OperationFailure::from(error))
    })
}

#[track_caller]
fn applied(result: Result<ThreatResponse, OperationFailure>) -> ThreatResponse {
    match result {
        Ok(response) => response,
        Err(failure) => panic!("expected a response, got {:?}", failure.error),
    }
}

#[track_caller]
fn refused(result: Result<ThreatResponse, OperationFailure>) -> OperationFailure {
    match result {
        Ok(response) => panic!("expected a refusal, got {response:?}"),
        Err(failure) => failure,
    }
}

fn outcome(response: &ThreatResponse) -> (String, Option<String>) {
    (response.outcome.clone(), response.reason.clone())
}

fn skipped(reason: &str) -> (String, Option<String>) {
    ("skipped".into(), Some(reason.into()))
}

async fn status_of(f: &Org, identity_id: &str) -> Value {
    f.store()
        .get("identities", identity_id)
        .await
        .unwrap()
        .unwrap()["status"]
        .clone()
}

async fn audits(f: &Org, action: &str) -> Vec<Record> {
    f.find("audit", Filter::new().eq("action", action)).await
}

/// A session issued from a client address.
async fn session_from(f: &Org, identity_id: &str, ip: &str) -> CredentialInput {
    let client = SessionClientInfo {
        ip: Some(ip.to_owned()),
        user_agent: Some("test".into()),
        ..SessionClientInfo::default()
    };
    f.iam
        .auth
        .clone()
        .with_client(Some(client), f.session(identity_id, false))
        .await
}

#[test]
fn contains_and_releases_an_identity() {
    run(|| async {
        let f = organization(|_| {}).await;
        let owner = person(&f, &f.owner_credential.clone()).await;
        let alice = f.member("alice").await;
        let alice_session = f.sign_in(&alice).await;
        // An API key survives a containment (refused while disabled, working again after a release).
        f.insert(
            "sessions",
            json!({ "id": "key-1", "tenantId": f.tenant_id, "identityId": alice, "kind": "api-key" }),
        )
        .await;
        f.insert(
            "authDevices",
            json!({ "id": "device-1", "tenantId": f.tenant_id, "identityId": alice }),
        )
        .await;
        f.insert(
            "memberInvitations",
            json!({ "id": "inv-1", "tenantId": f.tenant_id, "inviterId": alice, "email": "attacker@evil.example" }),
        )
        .await;
        let mut contain = request("contain", subject("identity", &alice), &owner);
        contain.incident_id = Some("incident-1".into());
        contain.reason = "  compromised  ".into();
        let response = applied(respond(&f, contain).await);
        assert_eq!(outcome(&response), ("applied".into(), None));
        assert_eq!(response.action, "contain");
        assert_eq!(response.actor_id, f.owner_id);
        assert_eq!(response.incident_id.as_deref(), Some("incident-1"));
        assert_eq!(
            serde_json::to_value(&response.subject).unwrap(),
            json!({ "type": "identity", "id": alice, "name": "alice" })
        );
        assert_eq!(
            response.details.as_ref().unwrap()["sessionsEnded"],
            json!(1)
        );
        assert_eq!(status_of(&f, &alice).await, json!("disabled"));
        let store = f.store();
        assert!(store.get("sessions", "key-1").await.unwrap().is_some());
        assert!(
            store
                .get("authDevices", "device-1")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .get("memberInvitations", "inv-1")
                .await
                .unwrap()
                .unwrap()["revoked"],
            json!(true)
        );
        assert!(
            f.iam.auth.get_session(&alice_session).await.is_err(),
            "the person's sessions end"
        );
        let risk = store.get("identityRisk", &alice).await.unwrap().unwrap();
        assert_matches(
            &Value::Object(risk.clone()),
            json!({
                "identityId": alice, "score": 0, "level": "none",
                "contained": { "by": f.owner_id, "reason": "compromised", "incidentId": "incident-1" },
            }),
        );
        let events = audits(&f, "threat:contain").await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["actorId"], json!(f.owner_id));
        assert_eq!(
            events[0]["metadata"],
            json!({ "reason": "compromised", "sessionsEnded": 1, "incidentId": "incident-1" })
        );

        let released = applied(release(&f, &alice, &owner, Some(" ok ")).await);
        assert_eq!(released.action, "release");
        assert_eq!(outcome(&released), ("applied".into(), None));
        assert_eq!(released.incident_id.as_deref(), Some("incident-1"));
        assert_eq!(released.details.as_ref().unwrap()["note"], json!("ok"));
        assert_eq!(status_of(&f, &alice).await, json!("active"));
        let risk_after = store.get("identityRisk", &alice).await.unwrap().unwrap();
        assert!(!risk_after.contains_key("contained"));
        let release_events = audits(&f, "threat:release").await;
        assert_eq!(
            release_events[0]["metadata"],
            json!({ "note": "ok", "containedAt": risk["contained"]["at"], "incidentId": "incident-1" })
        );
        // Invitations it sent stay revoked after the release.
        assert_eq!(
            store
                .get("memberInvitations", "inv-1")
                .await
                .unwrap()
                .unwrap()["revoked"],
            json!(true)
        );
        let again = refused(release(&f, &alice, &owner, None).await);
        assert_eq!(
            (again.error.code.as_str(), again.error.status),
            ("INVALID_TRANSITION", 409)
        );
        assert_eq!(
            f.find(
                "threatResponses",
                Filter::new().eq("tenantId", f.tenant_id.clone())
            )
            .await
            .len(),
            2
        );
    });
}

#[test]
fn refuses_containments_a_person_may_not_make() {
    run(|| async {
        let f = organization(|_| {}).await;
        let owner = person(&f, &f.owner_credential.clone()).await;
        // Nobody contains themselves.
        let own = refused(
            respond(
                &f,
                request("contain", subject("identity", &f.owner_id), &owner),
            )
            .await,
        );
        assert_eq!(own.error.code, "INVALID_INPUT");
        assert_eq!(own.error.message, "You cannot contain yourself");
        assert!(!own.denied);

        // An owner only by an owner in person or root.
        let co_owner = f.member("coowner").await;
        let mut record = f
            .store()
            .get("identities", &co_owner)
            .await
            .unwrap()
            .unwrap();
        record.insert("owner".into(), json!(true));
        f.put("identities", record).await;
        let analyst = f.member("analyst").await;
        let analyst_credential = f.sign_in(&analyst).await;
        let analyst = person(&f, &analyst_credential).await;
        let denied = refused(
            respond(
                &f,
                request("contain", subject("identity", &co_owner), &analyst),
            )
            .await,
        );
        assert_eq!(
            (denied.error.code.as_str(), denied.error.message.as_str()),
            ("ACCESS_DENIED", "Only an owner can contain an owner")
        );
        assert!(denied.denied);
        assert_eq!(status_of(&f, &co_owner).await, json!("active"));
        let contained = applied(
            respond(
                &f,
                request("contain", subject("identity", &co_owner), &owner),
            )
            .await,
        );
        assert_eq!(outcome(&contained), ("applied".into(), None));
        assert_eq!(status_of(&f, &co_owner).await, json!("disabled"));

        // The last owner stays, even for root.
        let root = person(&f, &f.root_credential.clone()).await;
        let last = refused(
            respond(
                &f,
                request("contain", subject("identity", &f.owner_id), &root),
            )
            .await,
        );
        assert_eq!(last.error.code, "LAST_OWNER");
        assert_eq!(status_of(&f, &f.owner_id).await, json!("active"));

        // A disabled identity is not contained again; an inactive one is reported as such.
        let again = applied(
            respond(
                &f,
                request("contain", subject("identity", &co_owner), &owner),
            )
            .await,
        );
        assert_eq!(outcome(&again), skipped("already-applied"));

        // An identity of another tenant is not found.
        let missing = refused(
            respond(
                &f,
                request("contain", subject("identity", &f.root_id), &owner),
            )
            .await,
        );
        assert_eq!(missing.error.code, "NOT_FOUND");
    });
}

#[test]
fn automatic_responses_skip_protected_targets_and_brake() {
    run(|| async {
        let f = organization(|_| {}).await;
        let automatic = ResponseActor::Automatic;
        let tenant_id = f.tenant_id.clone();
        let owner_contain = applied(
            respond(
                &f,
                request("contain", subject("identity", &f.owner_id), &automatic),
            )
            .await,
        );
        assert_eq!(outcome(&owner_contain), skipped("protected"));
        assert_eq!(owner_contain.actor_id, "threat-detection");
        let tenant_subject = applied(
            respond(
                &f,
                request("contain", subject("tenant", &tenant_id), &automatic),
            )
            .await,
        );
        assert_eq!(outcome(&tenant_subject), skipped("not-identity"));
        let unknown = applied(
            respond(
                &f,
                request("contain", subject("identity", "nobody"), &automatic),
            )
            .await,
        );
        assert_eq!(outcome(&unknown), skipped("not-found"));
        // The root administrator lives in the root tenant: not found from the organization, protected there.
        let root_admin = applied(
            respond_with(
                &f,
                &f.root_tenant.clone(),
                request("contain", subject("identity", &f.root_id), &automatic),
                &defaults(),
                &mut None,
            )
            .await,
        );
        assert_eq!(outcome(&root_admin), skipped("protected"));

        let mut settings = defaults();
        settings.max_automatic_containments = 1.0;
        let mut brake = Some(PlaybookBrake {
            contained: 0.0,
            braked: None,
            extra: Map::new(),
        });
        let people = [
            f.member("alice").await,
            f.member("bob").await,
            f.member("carol").await,
        ];
        let mut outcomes = Vec::new();
        for identity_id in &people {
            let mut playbook = request("contain", subject("identity", identity_id), &automatic);
            playbook.playbook_id = Some("playbook-1".into());
            playbook.detection_id = Some("detection-1".into());
            outcomes.push(outcome(&applied(
                respond_with(&f, &tenant_id, playbook, &settings, &mut brake).await,
            )));
        }
        assert_eq!(
            outcomes,
            [
                ("applied".into(), None),
                skipped("braked"),
                skipped("braked")
            ]
        );
        let brake = brake.unwrap();
        assert_eq!((brake.contained, brake.braked), (1.0, Some(2.0)));
        let braked = audits(&f, "threat:response-braked").await;
        assert_eq!(braked.len(), 1, "audited once per brake");
        assert_eq!(braked[0]["actorId"], json!("threat-detection"));
        assert_eq!(
            braked[0]["resourceId"],
            json!("threats/playbooks/playbook-1")
        );
        assert_eq!(
            braked[0]["metadata"],
            json!({ "threshold": 1, "identityId": people[1], "detectionId": "detection-1", "playbookId": "playbook-1" })
        );
        assert_eq!(status_of(&f, &people[1]).await, json!("active"));
        let contain_event = &audits(&f, "threat:contain").await[0];
        assert_eq!(contain_event["actorId"], json!("threat-detection"));
        assert_eq!(contain_event["metadata"]["reason"], json!("test"));
    });
}

#[test]
fn revokes_sessions_and_forgets_devices() {
    run(|| async {
        let f = organization(|_| {}).await;
        let owner = person(&f, &f.owner_credential.clone()).await;
        let alice = f.member("alice").await;
        let first = f.sign_in(&alice).await;
        f.sign_in(&alice).await;
        f.insert(
            "sessions",
            json!({ "id": "key-1", "tenantId": f.tenant_id, "identityId": alice, "kind": "api-key" }),
        )
        .await;
        let mut revoke = request("revoke-sessions", subject("identity", &alice), &owner);
        revoke.reason = "   ".into();
        let response = applied(respond(&f, revoke).await);
        assert_eq!(
            response.details.clone().map(|details| json!(details)),
            Some(json!({ "revoked": 2, "keptApiKeys": true }))
        );
        assert!(f.iam.auth.get_session(&first).await.is_err());
        assert!(f.store().get("sessions", "key-1").await.unwrap().is_some());
        let events = audits(&f, "threat:revoke-sessions").await;
        assert_eq!(
            events[0]["metadata"],
            json!({ "revoked": 2, "keptApiKeys": true, "reason": "Threat response" })
        );

        // keepApiKeys: false ends the keys too; a person revoking their own sessions keeps the one they use.
        let own_credential = f.sign_in(&alice).await;
        let alice_actor = person(&f, &own_credential).await;
        f.sign_in(&alice).await;
        let mut own = request("revoke-sessions", subject("identity", &alice), &alice_actor);
        own.action.keep_api_keys = Some(false);
        let response = applied(respond(&f, own).await);
        assert_eq!(
            response.details.clone().map(|details| json!(details)),
            Some(json!({ "revoked": 2, "keptApiKeys": false }))
        );
        assert!(f.iam.auth.get_session(&own_credential).await.is_ok());
        assert!(f.store().get("sessions", "key-1").await.unwrap().is_none());

        let root_owner = person(&f, &f.owner_credential.clone()).await;
        let denied = refused(
            respond_with(
                &f,
                &f.root_tenant.clone(),
                request(
                    "revoke-sessions",
                    subject("identity", &f.root_id),
                    &root_owner,
                ),
                &defaults(),
                &mut None,
            )
            .await,
        );
        // A root administrator's sessions are ended by root (or by themselves), never by a permission alone.
        assert_eq!(denied.error.message, "Root capability is protected");
        assert!(denied.denied);

        for id in ["device-1", "device-2"] {
            f.insert(
                "authDevices",
                json!({ "id": id, "tenantId": f.tenant_id, "identityId": alice }),
            )
            .await;
        }
        let forgot = applied(
            respond(
                &f,
                request("forget-devices", subject("identity", &alice), &owner),
            )
            .await,
        );
        assert_eq!(forgot.details.as_ref().unwrap()["removed"], json!(2));
        assert!(
            f.find("authDevices", Filter::new().eq("identityId", alice.clone()))
                .await
                .is_empty()
        );
        // An identity action needs an identity.
        let none = applied(
            respond(
                &f,
                request("forget-devices", subject("network", "203.0.113.9"), &owner),
            )
            .await,
        );
        assert_eq!(outcome(&none), skipped("not-identity"));
        let by_member = {
            let mut fallback = request("forget-devices", subject("network", "203.0.113.9"), &owner);
            fallback.identity_id = Some(alice.clone());
            applied(respond(&f, fallback).await)
        };
        assert_eq!(by_member.subject.id, alice);
    });
}

#[test]
fn blocks_networks() {
    run(|| async {
        let f = organization(|_| {}).await;
        let tenant_id = f.tenant_id.clone();
        let owner = person(&f, &f.owner_credential.clone()).await;
        let automatic = ResponseActor::Automatic;
        let network = |id: &str| subject("network", id);

        let no_network = applied(
            respond(
                &f,
                request("block-network", subject("identity", "x"), &owner),
            )
            .await,
        );
        assert_eq!(outcome(&no_network), skipped("no-network"));
        let invalid =
            refused(respond(&f, request("block-network", network("not an ip"), &owner)).await);
        assert_eq!(
            invalid.error.message,
            "network must be an IPv4/IPv6 address or CIDR block"
        );
        let invalid_auto = applied(
            respond(
                &f,
                request("block-network", network("not an ip"), &automatic),
            )
            .await,
        );
        assert_eq!(outcome(&invalid_auto), skipped("invalid-network"));

        let mut trusted = defaults();
        trusted.trusted_networks = vec!["10.0.0.0/8".into()];
        let inside = applied(
            respond_with(
                &f,
                &tenant_id,
                request("block-network", network("10.1.0.0/16"), &owner),
                &trusted,
                &mut None,
            )
            .await,
        );
        assert_eq!(outcome(&inside), skipped("trusted-network"));

        let mut short = request("block-network", network(" 198.51.100.0/24 "), &owner);
        short.action.duration_ms = Some(MINUTE);
        let now = f.now();
        let blocked = applied(respond(&f, short.clone()).await);
        assert_eq!(outcome(&blocked), ("applied".into(), None));
        let details = blocked.details.clone().unwrap();
        assert_eq!(details["network"], json!("198.51.100.0/24"));
        assert_eq!(details["renewed"], json!(false));
        assert_eq!(details["expiresAt"].as_f64(), Some(now + MINUTE));
        let block = f
            .store()
            .get("authBlocks", details["blockId"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_matches(
            &Value::Object(block),
            json!({ "tenantId": tenant_id, "network": "198.51.100.0/24", "reason": "threat: test", "createdBy": f.owner_id }),
        );
        let event = &audits(&f, "threat:block-network").await[0];
        assert_eq!(
            event["resourceId"],
            json!("threats/networks/198.51.100.0/24")
        );
        // Covered for at least as long: redundant. Longer: the block is renewed in place.
        let again = applied(respond(&f, short.clone()).await);
        assert_eq!(outcome(&again), skipped("already-applied"));
        let narrower = applied(
            respond(&f, {
                let mut inner = short.clone();
                inner.subject = network("198.51.100.7");
                inner
            })
            .await,
        );
        assert_eq!(outcome(&narrower), skipped("already-applied"));
        let mut longer = short.clone();
        longer.action.duration_ms = Some(DAY);
        let renewed = applied(respond(&f, longer).await);
        assert_eq!(renewed.details.as_ref().unwrap()["renewed"], json!(true));
        assert_eq!(
            renewed.details.as_ref().unwrap()["blockId"],
            details["blockId"]
        );
        assert_eq!(
            f.find(
                "authBlocks",
                Filter::new().eq("tenantId", tenant_id.clone())
            )
            .await
            .len(),
            1
        );

        // People are held to the duration bounds; playbooks are clamped into them.
        let mut too_short = request("block-network", network("192.0.2.0/24"), &owner);
        too_short.action.duration_ms = Some(30.0);
        let bounds = refused(respond(&f, too_short.clone()).await);
        assert_eq!(bounds.error.message, "Invalid durationMs");
        too_short.actor = automatic.clone();
        let clamped = applied(respond(&f, too_short).await);
        assert_eq!(
            clamped.details.as_ref().unwrap()["expiresAt"].as_f64(),
            Some(f.now() + MINUTE)
        );

        // Never the responder's own address.
        let from_office = session_from(&f, &f.owner_id.clone(), "203.0.113.50").await;
        let office = person(&f, &from_office).await;
        let own = refused(
            respond(
                &f,
                request("block-network", network("203.0.113.0/24"), &office),
            )
            .await,
        );
        assert_eq!(own.error.message, "That network includes your own address");

        // The root tenant's blocks are root's alone: playbooks skip them, other people are refused.
        let root_tenant = f.root_tenant.clone();
        let by_playbook = applied(
            respond_with(
                &f,
                &root_tenant,
                request("block-network", network("198.51.100.0/24"), &automatic),
                &defaults(),
                &mut None,
            )
            .await,
        );
        assert_eq!(outcome(&by_playbook), skipped("protected"));
        let by_owner = refused(
            respond_with(
                &f,
                &root_tenant,
                request("block-network", network("198.51.100.0/24"), &owner),
                &defaults(),
                &mut None,
            )
            .await,
        );
        assert_eq!(
            by_owner.error.message,
            "Blocks on the root tenant are set by root administrators"
        );
        assert!(by_owner.denied);
        let root = person(&f, &f.root_credential.clone()).await;
        let by_root = applied(
            respond_with(
                &f,
                &root_tenant,
                request("block-network", network("198.51.100.0/24"), &root),
                &defaults(),
                &mut None,
            )
            .await,
        );
        assert_eq!(outcome(&by_root), ("applied".into(), None));
    });
}

fn incident(f: &Org, id: &str, severity: &str) -> Value {
    json!({
        "id": id, "tenantId": f.tenant_id,
        "subject": { "type": "identity", "id": f.owner_id, "name": "Acme owner" },
        "identityId": f.owner_id,
        "severity": severity, "title": "Reported by the account holder", "status": "open",
        "detectionIds": ["detection-1"], "detectionCount": 1, "ruleIds": ["user-reported"],
        "firstDetectedAt": 1, "lastDetectedAt": 1, "createdAt": 1, "updatedAt": 1,
        "uniqueKey": format!("open:identity:{}", f.owner_id),
    })
}

#[test]
fn emails_incidents() {
    run(|| async {
        let inbox: Arc<Mutex<Vec<DeliveryMessage>>> = Arc::new(Mutex::new(Vec::new()));
        let mailbox = inbox.clone();
        let f = organization(move |options| {
            options.authentication.as_mut().unwrap().send_email =
                Some(delivery_fn(move |message| {
                    let mailbox = mailbox.clone();
                    async move {
                        mailbox.lock().unwrap().push(message);
                        Ok(())
                    }
                }));
        })
        .await;
        let tenant_id = f.tenant_id.clone();
        let owner = person(&f, &f.owner_credential.clone()).await;
        let automatic = ResponseActor::Automatic;
        let tenant_subject = subject("tenant", &tenant_id);
        let no_incident =
            applied(respond(&f, request("notify", tenant_subject.clone(), &owner)).await);
        assert_eq!(outcome(&no_incident), skipped("no-incident"));
        f.insert("threatIncidents", incident(&f, "incident-1", "high"))
            .await;
        f.insert(
            "threatDetections",
            json!({
                "id": "detection-1", "tenantId": tenant_id, "ruleId": "user-reported", "severity": "high",
                "title": "Reported by the account holder", "summary": "The owner reported a sign-in.",
                "subject": { "type": "identity", "id": f.owner_id }, "evidence": { "eventIds": [], "count": 1, "firstAt": 1, "lastAt": 1 },
                "status": "open", "incidentId": "incident-1", "occurredAt": 1, "detectedAt": 1,
            }),
        )
        .await;
        let notify = |actor: &ResponseActor| {
            let mut notify = request("notify", tenant_subject.clone(), actor);
            notify.incident_id = Some("incident-1".into());
            notify
        };
        let nobody = applied(respond(&f, notify(&owner)).await);
        assert_eq!(outcome(&nobody), skipped("no-recipients"));

        let mut settings = defaults();
        settings.notify =
            json!({ "owners": true, "emails": ["SOC@Example.test", "owner@acme.test"] });
        let sent =
            applied(respond_with(&f, &tenant_id, notify(&automatic), &settings, &mut None).await);
        assert_eq!(outcome(&sent), ("applied".into(), None));
        assert_eq!(
            json!(sent.details.clone().unwrap()),
            json!({ "recipients": 2, "severity": "high" })
        );
        let mut queued: Vec<(String, String)> = f
            .find("outbox", Filter::new().eq("template", "threat-alert"))
            .await
            .into_iter()
            .map(|message| {
                (
                    message["to"].as_str().unwrap().to_owned(),
                    message["template"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        queued.sort();
        assert_eq!(
            queued,
            [
                ("owner@acme.test".to_owned(), "threat-alert".to_owned()),
                ("soc@example.test".to_owned(), "threat-alert".to_owned())
            ]
        );
        f.iam.auth.dispatch_outbox(None).await.unwrap();
        let delivered = inbox.lock().unwrap().clone();
        let message = delivered
            .iter()
            .find(|message| message.to == "soc@example.test")
            .expect("delivered");
        assert_matches(
            &json!(message.payload),
            json!({
                "incidentId": "incident-1", "title": "Reported by the account holder", "severity": "high",
                "subject": "Acme owner", "subjectType": "identity", "detections": "1", "tenantName": "Acme",
                "summary": "The owner reported a sign-in.",
            }),
        );
        let event = &audits(&f, "threat:notify").await[0];
        assert_eq!(event["resourceId"], json!("threats/incidents/incident-1"));
        assert_eq!(
            event["metadata"],
            json!({ "recipients": 2, "severity": "high", "incidentId": "incident-1" })
        );

        // Playbooks email an incident once, and again when its severity rises; people always can.
        let repeat =
            applied(respond_with(&f, &tenant_id, notify(&automatic), &settings, &mut None).await);
        assert_eq!(outcome(&repeat), skipped("already-applied"));
        let by_person =
            applied(respond_with(&f, &tenant_id, notify(&owner), &settings, &mut None).await);
        assert_eq!(outcome(&by_person), ("applied".into(), None));
        let mut raised = f
            .store()
            .get("threatIncidents", "incident-1")
            .await
            .unwrap()
            .unwrap();
        raised.insert("severity".into(), json!("critical"));
        f.put("threatIncidents", raised.clone()).await;
        let escalated =
            applied(respond_with(&f, &tenant_id, notify(&automatic), &settings, &mut None).await);
        assert_eq!(outcome(&escalated), ("applied".into(), None));

        // notifyIncident: the same delivery without a response row.
        let ctx = f.iam.ctx.clone();
        let incident_record: ThreatIncident = better_iam_server::port::decode(raised).unwrap();
        let (tenant, settings_copy) = (tenant_id.clone(), settings.clone());
        let result = f
            .iam
            .store
            .transaction(|tx| async move {
                notify_incident(&ctx, &tx, &tenant, &incident_record, &settings_copy, None).await
            })
            .await
            .unwrap();
        assert_eq!(result, json!({ "sent": 2 }));
    });
}

#[test]
fn notifies_nothing_without_an_email_transport() {
    run(|| async {
        let f = organization(|_| {}).await;
        f.insert("threatIncidents", incident(&f, "incident-1", "high"))
            .await;
        let mut notify = request(
            "notify",
            subject("tenant", &f.tenant_id.clone()),
            &ResponseActor::Automatic,
        );
        notify.incident_id = Some("incident-1".into());
        let response = applied(respond(&f, notify).await);
        assert_eq!(outcome(&response), skipped("no-transport"));
        let unknown = refused(
            respond(
                &f,
                request("explode", subject("tenant", "x"), &ResponseActor::Automatic),
            )
            .await,
        );
        assert_eq!(
            (unknown.error.code.as_str(), unknown.error.message.as_str()),
            ("INVALID_INPUT", "Unknown response action")
        );
    });
}

#[test]
fn suspends_clearances_only_where_the_deployment_has_them() {
    run(|| async {
        let f = organization(|_| {}).await;
        let alice = f.member("alice").await;
        let owner = person(&f, &f.owner_credential.clone()).await;
        let automatic = applied(
            respond(
                &f,
                request(
                    "suspend-clearance",
                    subject("identity", &alice),
                    &ResponseActor::Automatic,
                ),
            )
            .await,
        );
        assert_eq!(outcome(&automatic), skipped("feature-disabled"));
        let manual = refused(
            respond(
                &f,
                request("suspend-clearance", subject("identity", &alice), &owner),
            )
            .await,
        );
        assert_eq!(
            (manual.error.code.as_str(), manual.error.status),
            ("FEATURE_DISABLED", 403)
        );
    });
    run(|| async {
        let f = organization(|options| {
            options.clearances = Some(ClearanceOptions::default());
        })
        .await;
        let alice = f.member("alice").await;
        let owner = person(&f, &f.owner_credential.clone()).await;
        let automatic = ResponseActor::Automatic;
        let protected = applied(
            respond(
                &f,
                request(
                    "suspend-clearance",
                    subject("identity", &f.owner_id.clone()),
                    &automatic,
                ),
            )
            .await,
        );
        assert_eq!(outcome(&protected), skipped("protected"));
        let none = applied(
            respond(
                &f,
                request("suspend-clearance", subject("identity", &alice), &automatic),
            )
            .await,
        );
        assert_eq!(outcome(&none), skipped("no-clearance"));
        let by_owner = applied(
            respond(
                &f,
                request("suspend-clearance", subject("identity", &alice), &owner),
            )
            .await,
        );
        assert_eq!(outcome(&by_owner), skipped("no-clearance"));
        // A person without iam:clearances:suspend is refused before anything about the clearance is read.
        let bob = f.member("bob").await;
        let bob_credential = f.sign_in(&bob).await;
        let bob = person(&f, &bob_credential).await;
        let denied = refused(
            respond(
                &f,
                request("suspend-clearance", subject("identity", &alice), &bob),
            )
            .await,
        );
        assert_eq!(
            denied.error.message,
            "Suspending a clearance requires iam:clearances:suspend"
        );
        assert!(denied.denied);
    });
}

#[test]
fn never_releases_what_another_path_changed() {
    run(|| async {
        let f = organization(|_| {}).await;
        let owner = person(&f, &f.owner_credential.clone()).await;
        let contain =
            |identity_id: String| request("contain", subject("identity", &identity_id), &owner);

        // Never contained.
        let alice = f.member("alice").await;
        let never = refused(release(&f, &alice, &owner, None).await);
        assert_eq!(never.error.message, "The identity is not contained");

        // Another path ended the containment (identities.setStatus and friends call endContainment).
        applied(respond(&f, contain(alice.clone())).await);
        let id = alice.clone();
        f.iam
            .store
            .transaction(|tx| async move { end_containment(&tx, &id, 1.0).await })
            .await
            .unwrap();
        let ended = refused(release(&f, &alice, &owner, None).await);
        assert_eq!(ended.error.code, "INVALID_TRANSITION");
        assert_eq!(status_of(&f, &alice).await, json!("disabled"));

        // Re-enabled behind the module's back.
        let carol = f.member("carol").await;
        applied(respond(&f, contain(carol.clone())).await);
        let mut record = f.store().get("identities", &carol).await.unwrap().unwrap();
        record.insert("status".into(), json!("active"));
        f.put("identities", record).await;
        assert_eq!(
            refused(release(&f, &carol, &owner, None).await).error.code,
            "INVALID_TRANSITION"
        );

        // A suspended agent stays held by its kill switch.
        let agent = f.member("agent").await;
        applied(respond(&f, contain(agent.clone())).await);
        let mut record = f.store().get("identities", &agent).await.unwrap().unwrap();
        record.insert(
            "agent".into(),
            json!({ "sponsorId": f.owner_id, "suspended": { "at": 1, "by": f.owner_id, "reason": "prompt injection" } }),
        );
        f.put("identities", record).await;
        assert_eq!(
            refused(release(&f, &agent, &owner, None).await).error.code,
            "INVALID_TRANSITION"
        );

        // Expired since: extend or clear expiresAt first.
        let dave = f.member("dave").await;
        applied(respond(&f, contain(dave.clone())).await);
        let mut record = f.store().get("identities", &dave).await.unwrap().unwrap();
        record.insert("expiresAt".into(), json!(f.now() - 1.0));
        f.put("identities", record.clone()).await;
        let expired = refused(release(&f, &dave, &owner, None).await);
        assert_eq!(
            (
                expired.error.code.as_str(),
                expired.error.message.as_str(),
                expired.error.status
            ),
            (
                "INVALID_TRANSITION",
                "Extend or clear expiresAt before releasing an expired identity",
                409
            )
        );
        record.shift_remove("expiresAt");
        f.put("identities", record).await;

        // A containment nothing else touched is still released, by the automatic actor too.
        let released = applied(release(&f, &dave, &ResponseActor::Automatic, Some("   ")).await);
        assert_eq!(released.actor_id, "threat-detection");
        assert!(released.details.is_none());
        assert_eq!(status_of(&f, &dave).await, json!("active"));
        let event = audits(&f, "threat:release").await;
        assert_eq!(event[0]["actorId"], json!("threat-detection"));
        assert!(
            !event[0]["metadata"]
                .as_object()
                .unwrap()
                .contains_key("note")
        );
    });
}

#[test]
fn follow_up_clears_block_caches_without_identity_changes() {
    run(|| async {
        let f = organization(|_| {}).await;
        let owner = person(&f, &f.owner_credential.clone()).await;
        let mut block = request("block-network", subject("network", "192.0.2.0/24"), &owner);
        block.action.duration_ms = Some(MINUTE);
        let blocked = applied(respond(&f, block).await);
        let skipped_contain = applied(
            respond(
                &f,
                request(
                    "contain",
                    subject("identity", &f.owner_id.clone()),
                    &ResponseActor::Automatic,
                ),
            )
            .await,
        );
        after_threat_responses(&f.iam.ctx, &f.tenant_id, &[blocked, skipped_contain])
            .await
            .unwrap();
        after_threat_responses(&f.iam.ctx, &f.tenant_id, &[])
            .await
            .unwrap();
    });
}
