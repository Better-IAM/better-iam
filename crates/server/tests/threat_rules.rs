//! Rule coverage for identity threat detection (threat-rules.ts, threat-engine.ts): every scenario is produced
//! through the public API (sign-ins from simulated client addresses, administration calls) and judged by
//! `iam.detectThreats()`, so what is asserted is what a scheduled run would record. Ported from
//! tests/threat-rules.test.ts.
//!
//! Running detection needs `resolveThreatSettings`, `threatRule` and the other helpers of threats.ts and
//! `threatAudit` of threat-response.ts (other port units), so these scenarios are ignored until those land. Steps
//! that go through the `threats` API group (another unit) are tolerated while it answers NOT_IMPLEMENTED: settings
//! are then written to the store as `threats.configure` writes them, and assertions about what only that API does
//! (the guardrail detections it raises itself, risk recomputed on resolution) run once it is ported. Sign-in
//! baseline learning runs today, with every rule turned off.

mod organization_fixture;
mod threat_support;

use better_iam_auth::service::mfa::ConfirmMfaInput;
use better_iam_auth::{MfaCredential, totp};
use better_iam_core::{CredentialInput, Filter, IamResult, IamStoreExt, Identity, Record};
use better_iam_server::api::Reply;
use better_iam_server::http::AuthArgs;
use better_iam_server::options::{AuthorizationRequest, ResourceTarget};
use better_iam_server::threat_rules::{RuleFacts, RuleInput, RuleState, evaluate_threat_rules};
use better_iam_server::threats::ResolvedThreatSettings;
use indexmap::IndexMap;
use serde_json::{Map, Value, json};
use threat_support::{
    DAY, MINUTE, Threats, assert_matches, bearer, body, fixture, number, ok, run, sorted,
};

/// Whether an answer is another unit's NOT_IMPLEMENTED stub.
fn unported<T>(result: &IamResult<T>) -> bool {
    matches!(result, Err(error) if error.code == "NOT_IMPLEMENTED")
}

/// The result of an API call whose post-commit package automation (`afterIdentityChange`, another unit) may still
/// answer NOT_IMPLEMENTED: None then (the change itself was committed).
fn committed<O: serde::Serialize>(result: IamResult<Reply<O>>) -> Option<Value> {
    match result {
        Err(error)
            if error.code == "NOT_IMPLEMENTED" && error.message.contains("afterIdentityChange") =>
        {
            None
        }
        result => Some(ok(result)),
    }
}

impl Threats {
    /// `threats.configure` as `credential`. While the threats API group is another unit's stub, the settings record
    /// it would write is written directly; returns whether the API ran.
    async fn configure(&self, credential: &CredentialInput, input: Value) -> bool {
        let mut input = input;
        input["tenantId"] = json!(self.tenant_id);
        let result = self
            .iam
            .api
            .threats
            .configure(credential, body(input.clone()))
            .await;
        if !unported(&result) {
            ok(result);
            return true;
        }
        let mut settings: Record = match self.get("threatSettings", &self.tenant_id).await {
            Some(Value::Object(settings)) => settings,
            _ => json!({
                "id": self.tenant_id,
                "tenantId": self.tenant_id,
                "rules": {},
                "trustedNetworks": [],
                "dormantDays": 90,
                "riskHalfLifeHours": 24,
                "notify": { "owners": false, "emails": [] },
                "maxAutomaticContainments": 3,
            })
            .as_object()
            .unwrap()
            .clone(),
        };
        if let Some(rules) = input.get("rules").and_then(Value::as_object) {
            let mut stored = settings["rules"].as_object().cloned().unwrap_or_default();
            for (rule_id, patch) in rules {
                match patch {
                    Value::Null => {
                        stored.remove(rule_id);
                    }
                    Value::Object(patch) => {
                        let mut merged = stored
                            .get(rule_id)
                            .and_then(Value::as_object)
                            .cloned()
                            .unwrap_or_default();
                        for (key, value) in patch {
                            merged.insert(key.clone(), value.clone());
                        }
                        stored.insert(rule_id.clone(), Value::Object(merged));
                    }
                    _ => {}
                }
            }
            settings.insert("rules".into(), Value::Object(stored));
        }
        for name in [
            "trustedNetworks",
            "dormantDays",
            "riskHalfLifeHours",
            "notify",
            "maxAutomaticContainments",
        ] {
            if let Some(value) = input.get(name) {
                settings.insert(name.into(), value.clone());
            }
        }
        settings.insert("updatedAt".into(), json!(self.now()));
        settings.insert("updatedBy".into(), json!(self.owner_id));
        self.overwrite("threatSettings", settings).await;
        false
    }

    /// `threats.getRisk`; while that API is another unit's stub, the stored record's level and score (`none`/0
    /// without one).
    async fn risk_of(&self, credential: &CredentialInput, identity_id: &str) -> Value {
        let result = self
            .iam
            .api
            .threats
            .get_risk(
                credential,
                body(json!({ "tenantId": self.tenant_id, "identityId": identity_id })),
            )
            .await;
        if !unported(&result) {
            return ok(result);
        }
        match self.get("identityRisk", identity_id).await {
            Some(risk) => json!({ "level": risk["level"], "score": risk["score"] }),
            None => json!({ "level": "none", "score": 0 }),
        }
    }

    async fn change_password(&self, token: &str, current: &str, password: &str) {
        self.iam
            .api
            .auth
            .call(
                "changePassword",
                AuthArgs::Authenticated(
                    bearer(token),
                    json!({ "currentPassword": current, "password": password }),
                ),
            )
            .await
            .expect("change password");
    }

    async fn get_session(&self, credential: &CredentialInput) -> IamResult<Value> {
        self.iam
            .api
            .auth
            .call(
                "getSession",
                AuthArgs::Authenticated(credential.clone(), json!({})),
            )
            .await
    }

    async fn set_auth_policy(&self, credential: &CredentialInput, policy: Value) {
        ok(self
            .iam
            .api
            .tenants
            .set_auth_policy(
                credential,
                body(json!({ "tenantId": self.tenant_id, "authPolicy": policy })),
            )
            .await);
    }

    async fn reads_document(&self, token: &str) -> bool {
        self.iam
            .authorize(&AuthorizationRequest {
                credential: bearer(token),
                tenant_id: self.tenant_id.clone(),
                action: "documents:read".into(),
                resource: ResourceTarget {
                    kind: "document".into(),
                    id: "d1".into(),
                },
            })
            .await
            .expect("authorize")
            .allowed
    }

    /// Enrolls an authenticator app for the session's person; returns its secret.
    async fn enroll_authenticator(&self, token: &str) -> String {
        let credential = MfaCredential::Credential(bearer(token));
        let enrollment = self.iam.auth.begin_mfa(&credential).await.unwrap();
        self.iam
            .auth
            .confirm_mfa(&ConfirmMfaInput {
                credential,
                code: totp::generate(&enrollment.secret, self.now()).unwrap(),
                remember_device: false,
            })
            .await
            .unwrap();
        enrollment.secret
    }
}

fn detections_of(run: &Value) -> f64 {
    number(run, "detections")
}

fn ids(values: &[(String, String)]) -> Vec<String> {
    let mut ids: Vec<String> = values.iter().map(|(_, id)| id.clone()).collect();
    ids.sort();
    ids
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule and threat-response.ts threatAudit (other port units)"]
fn password_spray_one_network_failing_for_ten_people_one_detection_per_burst() {
    run(|| async {
        let f = fixture().await;
        let people = f.members("spray", 10).await;
        f.detect().await;

        for (name, _) in &people[..9] {
            f.fail_password(name, "203.0.113.50", 1).await;
        }
        assert_eq!(detections_of(&f.detect().await), 0.0);

        // The tenth account completes the burst; the nine before it are read back from the lookback window.
        f.fail_password(&people[9].0, "203.0.113.50", 1).await;
        let detected = f.detect().await;
        assert_eq!(detections_of(&detected), 1.0);
        assert_eq!(number(&detected, "incidentsOpened"), 1.0);
        let all = f.detections(None).await;
        assert_eq!(all.len(), 1);
        let spray = &all[0];
        assert_matches(
            spray,
            json!({
                "ruleId": "password-spray",
                "severity": "high",
                "subject": { "type": "network", "id": "203.0.113.50" },
                "network": "203.0.113.50",
                "status": "open",
                "metadata": { "peak": 10, "threshold": 10, "accounts": 10 },
            }),
        );
        assert!(spray.get("identityId").is_none());
        assert_eq!(sorted(&spray["evidence"]["identityIds"]), ids(&people));
        assert_matches(
            &spray["evidence"],
            json!({ "count": 10, "networks": ["203.0.113.50"] }),
        );
        // A network is nobody's risk.
        assert!(f.tenant_records("identityRisk").await.is_empty());

        // The burst goes on in the next run: it keeps its dedupe key, so nothing new is recorded.
        f.fail_password(&people[0].0, "203.0.113.50", 1).await;
        f.fail_password(&people[1].0, "203.0.113.50", 1).await;
        assert_eq!(detections_of(&f.detect().await), 0.0);
        assert_eq!(f.detections(Some("password-spray")).await.len(), 1);
    });
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule and threat-response.ts threatAudit (other port units)"]
fn password_spray_trusted_networks_and_a_disabled_rule_report_nothing() {
    run(|| async {
        let f = fixture().await;
        let people = f.members("trusted", 10).await;
        let owner = f.owner_sign_in().await;
        let through_api = f
            .configure(&owner, json!({ "trustedNetworks": ["203.0.113.0/24"] }))
            .await;
        f.detect().await;

        for (name, _) in &people {
            f.fail_password(name, "203.0.113.60", 1).await;
        }
        assert_eq!(detections_of(&f.detect().await), 0.0);

        f.configure(
            &owner,
            json!({ "rules": { "password-spray": { "enabled": false } } }),
        )
        .await;
        for (name, _) in &people {
            f.fail_password(name, "198.51.100.60", 1).await;
        }
        f.detect().await;
        assert!(f.detections(Some("password-spray")).await.is_empty());
        // Trusting a network and turning a rule off are each a weakened guardrail (raised by the settings API, not
        // the engine).
        if through_api {
            let guardrails: Vec<Value> = f
                .detections(Some("guardrail-weakened"))
                .await
                .into_iter()
                .map(|detection| detection["metadata"].clone())
                .collect();
            assert_eq!(guardrails.len(), 2);
            assert!(guardrails.iter().any(|metadata| threat_support::matches(
                metadata,
                &json!({ "disabledRules": [], "weakened": ["trustedNetworks"] })
            )));
            assert!(guardrails.iter().any(|metadata| threat_support::matches(
                metadata,
                &json!({ "disabledRules": ["password-spray"], "weakened": [] })
            )));
        }

        // Enabled again, the next failure from the untrusted network judges the window it closes.
        f.configure(&owner, json!({ "rules": { "password-spray": null } }))
            .await;
        f.fail_password(&people[0].0, "198.51.100.60", 1).await;
        assert_eq!(detections_of(&f.detect().await), 1.0);
        let sprays = f.detections(Some("password-spray")).await;
        let networks: Vec<&Value> = sprays.iter().map(|d| &d["network"]).collect();
        assert_eq!(networks, vec![&json!("198.51.100.60")]);
        assert_eq!(sprays[0]["evidence"]["networks"], json!(["198.51.100.60"]));
    });
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule and threat-response.ts threatAudit (other port units)"]
fn brute_force_success_high_from_the_failing_network_lower_from_another() {
    run(|| async {
        let f = fixture().await;
        let alice = f.member("alice").await;
        let bob = f.member("bob").await;
        let carol = f.member("carol").await;
        // Alice was signed in before the attack began.
        f.from("192.0.2.10", f.sign_in_as("alice")).await;
        f.detect().await;

        f.fail_password("alice", "198.51.100.7", 5).await;
        f.from("198.51.100.7", f.sign_in_as("alice")).await;
        f.fail_password("bob", "198.51.100.8", 5).await;
        f.from("192.0.2.44", f.sign_in_as("bob")).await;
        // Four failures stay below the threshold.
        f.fail_password("carol", "198.51.100.9", 4).await;
        f.from("198.51.100.9", f.sign_in_as("carol")).await;
        let detected = f.detect().await;
        assert_eq!(detections_of(&detected), 2.0);

        let found = f.detections(Some("brute-force-success")).await;
        let of = |id: &str| found.iter().find(|d| d["identityId"] == id).cloned();
        assert_matches(
            &of(&alice).unwrap(),
            json!({
                "severity": "high",
                "network": "198.51.100.7",
                "subject": { "type": "identity", "id": alice },
                "metadata": { "failures": 5, "threshold": 5, "fromFailingNetwork": true },
                "evidence": { "count": 6 },
            }),
        );
        assert_matches(
            &of(&bob).unwrap(),
            json!({
                "severity": "medium",
                "network": "192.0.2.44",
                "metadata": { "failures": 5, "fromFailingNetwork": false },
            }),
        );
        assert!(of(&carol).is_none());
        // Five failures are not password guessing (ten are).
        assert!(f.detections(Some("brute-force")).await.is_empty());

        // The flagged sign-in opens the account-takeover window on the baseline.
        let baseline = f.get("threatBaselines", &alice).await.unwrap();
        assert_matches(
            &baseline["riskySignIn"],
            json!({ "ruleId": "brute-force-success", "detectionId": of(&alice).unwrap()["id"] }),
        );

        // The sign-in ended the streak: signing in again raises nothing.
        f.from("198.51.100.7", f.sign_in_as("alice")).await;
        assert_eq!(detections_of(&f.detect().await), 0.0);
    });
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule and threat-response.ts threatAudit (other port units)"]
fn mfa_bombardment_wrong_second_factor_codes_after_a_correct_password() {
    run(|| async {
        let f = fixture().await;
        let frank = f.member("frank").await;
        let session = f.sign_in_as("frank").await;
        let secret = f
            .enroll_authenticator(session["token"].as_str().unwrap())
            .await;
        f.detect().await;

        let ip = "203.0.113.70";
        let challenge = f
            .from(
                ip,
                f.password_sign_in("frank@acme.test", "a strong frank password"),
            )
            .await
            .unwrap();
        assert_eq!(challenge["mfaRequired"], true, "expected an MFA challenge");
        let current = totp::generate(&secret, f.now()).unwrap();
        let wrong = if current == "000000" {
            "111111"
        } else {
            "000000"
        };
        for _ in 0..5 {
            let error = f
                .from(
                    ip,
                    f.iam.api.auth.call(
                        "verifyMfa",
                        AuthArgs::Public(json!({
                            "tenantId": f.tenant_id,
                            "challenge": challenge["challenge"],
                            "code": wrong,
                        })),
                    ),
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, "INVALID_MFA");
        }
        assert_eq!(detections_of(&f.detect().await), 1.0);
        let bombardment = &f.detections(Some("mfa-bombardment")).await[0];
        assert_matches(
            bombardment,
            json!({
                "severity": "high",
                "identityId": frank,
                "network": ip,
                "metadata": { "peak": 5, "threshold": 5, "networks": 1 },
            }),
        );
        // Wrong codes are not wrong passwords.
        assert!(f.detections(Some("brute-force")).await.is_empty());
    });
}

fn network_keys(baseline: &Value) -> Vec<Value> {
    baseline["networks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|network| network["key"].clone())
        .collect()
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule and threat-response.ts threatAudit (other port units)"]
fn new_network_learns_the_first_network_then_reports_a_new_one_for_the_owner() {
    run(|| async {
        let f = fixture().await;
        f.member("alice").await;
        // The fixture's own sign-ins carry no address: the owner's baseline starts without networks.
        f.detect().await;
        let initial = f.get("threatBaselines", &f.owner_id).await.unwrap();
        assert_eq!(initial["networks"], json!([]));

        f.from("198.51.100.20", f.owner_sign_in()).await;
        assert_eq!(detections_of(&f.detect().await), 0.0);
        let learned = f.get("threatBaselines", &f.owner_id).await.unwrap();
        assert_eq!(network_keys(&learned), vec![json!("198.51.100.20")]);
        let agents: Vec<&Value> = learned["userAgents"]
            .as_array()
            .unwrap()
            .iter()
            .map(|agent| &agent["value"])
            .collect();
        assert_eq!(agents, vec![&json!("threat-rules-test")]);

        f.from("198.51.100.20", f.owner_sign_in()).await;
        f.from("203.0.113.21", f.owner_sign_in()).await;
        let detected = f.detect().await;
        assert_eq!(detections_of(&detected), 1.0);
        let unfamiliar = &f.detections(Some("new-network")).await[0];
        assert_matches(
            unfamiliar,
            json!({
                "severity": "medium",
                "identityId": f.owner_id,
                "network": "203.0.113.21",
                "subject": { "type": "identity", "id": f.owner_id },
                "metadata": { "privileged": true, "knownNetworks": 1 },
            }),
        );
        // Once seen, the network is familiar.
        f.from("203.0.113.21", f.owner_sign_in()).await;
        assert_eq!(detections_of(&f.detect().await), 0.0);
        // A trusted network is never reported, though it is learned.
        let owner = f.owner_sign_in().await;
        f.configure(&owner, json!({ "trustedNetworks": ["192.0.2.0/24"] }))
            .await;
        f.from("192.0.2.5", f.owner_sign_in()).await;
        assert_eq!(detections_of(&f.detect().await), 0.0);
        assert_eq!(
            network_keys(&f.get("threatBaselines", &f.owner_id).await.unwrap()),
            vec![
                json!("198.51.100.20"),
                json!("203.0.113.21"),
                json!("192.0.2.5")
            ]
        );

        // A person without administrator access is reported only when the tenant asks for everyone (at low
        // severity).
        f.from("198.51.100.22", f.sign_in_as("alice")).await;
        f.detect().await;
        f.from("198.51.100.23", f.sign_in_as("alice")).await;
        assert_eq!(detections_of(&f.detect().await), 0.0);
        let owner = f.owner_sign_in().await;
        f.configure(
            &owner,
            json!({ "rules": { "new-network": { "everyone": true } } }),
        )
        .await;
        f.from("198.51.100.24", f.sign_in_as("alice")).await;
        assert_eq!(detections_of(&f.detect().await), 1.0);
        let everyone = f
            .detections(Some("new-network"))
            .await
            .into_iter()
            .find(|detection| detection["identityId"] != json!(f.owner_id))
            .unwrap();
        assert_matches(
            &everyone,
            json!({
                "severity": "low",
                "network": "198.51.100.24",
                "metadata": { "privileged": false, "knownNetworks": 2 },
            }),
        );
    });
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule and threat-response.ts threatAudit (other port units)"]
fn session_hijack_a_bound_session_presented_from_another_network_once_per_session() {
    run(|| async {
        let f = fixture().await;
        let alice = f.member("alice").await;
        let owner = f.owner_sign_in().await;
        f.set_auth_policy(&owner, json!({ "bindSessionsToIp": true }))
            .await;
        f.detect().await;

        let signed_in = f.from("198.51.100.30", f.sign_in_as("alice")).await;
        let credential = bearer(signed_in["token"].as_str().unwrap());
        f.from("198.51.100.30", f.get_session(&credential))
            .await
            .unwrap();
        assert_eq!(detections_of(&f.detect().await), 0.0);

        for _ in 0..2 {
            let error = f
                .from("203.0.113.31", f.get_session(&credential))
                .await
                .unwrap_err();
            assert_eq!(error.code, "SESSION_NETWORK_MISMATCH");
        }
        let detected = f.detect().await;
        assert_eq!(detections_of(&detected), 1.0);
        let hijack = &f.detections(Some("session-hijack")).await[0];
        assert_matches(
            hijack,
            json!({
                "severity": "high",
                "identityId": alice,
                "network": "203.0.113.31",
                "metadata": {
                    "sessionId": signed_in["session"]["id"],
                    "sessionIp": "198.51.100.30",
                    "ip": "203.0.113.31",
                },
            }),
        );
        assert_eq!(
            sorted(&hijack["evidence"]["networks"]),
            vec!["198.51.100.30", "203.0.113.31"]
        );

        // The same stolen session presented again later is the same detection.
        let error = f
            .from("203.0.113.32", f.get_session(&credential))
            .await
            .unwrap_err();
        assert_eq!(error.code, "SESSION_NETWORK_MISMATCH");
        assert_eq!(detections_of(&f.detect().await), 0.0);
    });
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule and threat-response.ts threatAudit (other port units)"]
fn account_takeover_persistence_a_password_change_after_a_risky_sign_in_within_the_window() {
    run(|| async {
        let f = fixture().await;
        let alice = f.member("alice").await;
        let bob = f.member("bob").await;
        f.member("carol").await;
        f.member("dave").await;
        f.detect().await;

        // Alice: the risky sign-in and the change are read in the same run.
        f.fail_password("alice", "198.51.100.40", 5).await;
        let alice_session = f.from("198.51.100.40", f.sign_in_as("alice")).await;
        f.change_password(
            alice_session["token"].as_str().unwrap(),
            "a strong alice password",
            "a brand new alice password",
        )
        .await;
        // Bob: the risky sign-in now, the change in a later run.
        f.fail_password("bob", "198.51.100.41", 5).await;
        let bob_session = f.from("198.51.100.41", f.sign_in_as("bob")).await;
        // Dave changes his password without any risky sign-in.
        let dave_session = f.sign_in_as("dave").await;
        f.change_password(
            dave_session["token"].as_str().unwrap(),
            "a strong dave password",
            "a brand new dave password",
        )
        .await;
        f.detect().await;
        let first = f.detections(Some("account-takeover-persistence")).await;
        assert_eq!(first.len(), 1);
        let alice_success = f
            .detections(Some("brute-force-success"))
            .await
            .into_iter()
            .find(|detection| detection["identityId"] == json!(alice))
            .unwrap();
        assert_matches(
            &first[0],
            json!({
                "identityId": alice,
                "severity": "high",
                "metadata": {
                    "changedAction": "auth:password:change",
                    "riskySignInRuleId": "brute-force-success",
                    "riskySignInKey": alice_success["uniqueKey"],
                },
            }),
        );
        assert_eq!(
            first[0]["evidence"]["actions"],
            json!(["auth:session:create", "auth:password:change"])
        );
        // Same person, same incident.
        assert_eq!(first[0]["incidentId"], alice_success["incidentId"]);

        f.advance(2.0 * MINUTE);
        f.change_password(
            bob_session["token"].as_str().unwrap(),
            "a strong bob password",
            "a brand new bob password",
        )
        .await;
        assert_eq!(detections_of(&f.detect().await), 1.0);
        let bob_success = f
            .detections(Some("brute-force-success"))
            .await
            .into_iter()
            .find(|detection| detection["identityId"] == json!(bob))
            .unwrap();
        let bob_change = f
            .detections(Some("account-takeover-persistence"))
            .await
            .into_iter()
            .find(|detection| detection["identityId"] == json!(bob))
            .unwrap();
        assert_matches(
            &bob_change["metadata"],
            json!({
                "changedAction": "auth:password:change",
                "riskySignInDetectionId": bob_success["id"],
            }),
        );

        // Carol: the change comes more than an hour after the risky sign-in.
        f.fail_password("carol", "198.51.100.42", 5).await;
        f.from("198.51.100.42", f.sign_in_as("carol")).await;
        assert_eq!(detections_of(&f.detect().await), 1.0);
        f.advance(61.0 * MINUTE);
        let carol_later = f.from("198.51.100.42", f.sign_in_as("carol")).await;
        f.change_password(
            carol_later["token"].as_str().unwrap(),
            "a strong carol password",
            "a brand new carol password",
        )
        .await;
        assert_eq!(detections_of(&f.detect().await), 0.0);
        assert_eq!(
            f.detections(Some("account-takeover-persistence"))
                .await
                .len(),
            2
        );
    });
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule and threat-response.ts threatAudit (other port units)"]
fn account_takeover_persistence_enrolling_an_authenticator_after_a_risky_sign_in() {
    run(|| async {
        let f = fixture().await;
        let erin = f.member("erin").await;
        f.detect().await;

        f.fail_password("erin", "198.51.100.43", 5).await;
        let session = f.from("198.51.100.43", f.sign_in_as("erin")).await;
        f.enroll_authenticator(session["token"].as_str().unwrap())
            .await;
        f.detect().await;
        let persistence = &f.detections(Some("account-takeover-persistence")).await[0];
        assert_matches(
            persistence,
            json!({
                "identityId": erin,
                "severity": "high",
                "metadata": {
                    "changedAction": "auth:mfa:enable",
                    "riskySignInRuleId": "brute-force-success",
                },
            }),
        );
        assert!(
            persistence["summary"]
                .as_str()
                .unwrap()
                .contains("enrolled an authenticator app")
        );
    });
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule and threat-response.ts threatAudit (other port units)"]
fn counting_rules_hold_the_administrator_behind_a_view_as_session_responsible() {
    run(|| async {
        let f = fixture().await;
        let alice = f.member("alice").await;
        let owner = f.owner_sign_in().await;
        f.set_auth_policy(&owner, json!({ "allowImpersonation": true }))
            .await;
        f.detect().await;

        // Support staff checking what a member cannot do produce the member's refusals, not the member.
        let viewing = ok(f
            .iam
            .api
            .identities
            .impersonate(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "identityId": alice,
                    "reason": "why can alice not read documents?",
                })),
            )
            .await);
        for _ in 0..30 {
            assert!(!f.reads_document(viewing["token"].as_str().unwrap()).await);
        }
        assert_eq!(detections_of(&f.detect().await), 1.0);
        let denials = &f.detections(Some("denial-burst")).await[0];
        assert_matches(
            denials,
            json!({
                "identityId": f.owner_id,
                "subject": { "type": "identity", "id": f.owner_id },
                "metadata": { "peak": 30, "viewedAs": [alice] },
            }),
        );
        assert!(
            denials["summary"]
                .as_str()
                .unwrap()
                .contains("while viewing as someone else")
        );
        assert_matches(
            &f.risk_of(&owner, &alice).await,
            json!({ "level": "none", "score": 0 }),
        );
    });
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule, threat-response.ts threatAudit and privacy.ts assertNoLegalHold (identities.delete) (other port units)"]
fn mass_deletion_twenty_identities_and_roles_removed_by_one_person() {
    run(|| async {
        let f = fixture().await;
        let owner = f.owner_sign_in().await;
        let mut roles = Vec::new();
        for index in 0..15 {
            let role = ok(f
                .iam
                .api
                .roles
                .create(
                    &owner,
                    body(json!({
                        "tenantId": f.tenant_id,
                        "name": format!("Disposable {index}"),
                        "document": {
                            "version": 1,
                            "statements": [{ "effect": "allow", "actions": ["documents:read"], "resources": ["*"] }],
                        },
                    })),
                )
                .await);
            roles.push(role["id"].as_str().unwrap().to_owned());
        }
        let mut people = Vec::new();
        for index in 0..5 {
            let email = format!("leaver{index}@acme.test");
            let created = committed(
                f.iam
                    .api
                    .identities
                    .create(
                        &owner,
                        body(json!({
                            "tenantId": f.tenant_id,
                            "email": email,
                            "name": format!("Leaver {index}"),
                        })),
                    )
                    .await,
            );
            let id = match created {
                Some(created) => created["id"].as_str().unwrap().to_owned(),
                None => f
                    .find(
                        "identities",
                        Filter::new()
                            .eq("tenantId", f.tenant_id.clone())
                            .eq("email", email),
                    )
                    .await[0]["id"]
                    .as_str()
                    .unwrap()
                    .to_owned(),
            };
            people.push(id);
        }
        f.detect().await;

        for role_id in &roles {
            ok(f.iam
                .api
                .roles
                .delete(
                    &owner,
                    body(json!({ "tenantId": f.tenant_id, "roleId": role_id })),
                )
                .await);
        }
        for identity_id in &people[..4] {
            committed(
                f.iam
                    .api
                    .identities
                    .delete(
                        &owner,
                        body(json!({ "tenantId": f.tenant_id, "identityId": identity_id })),
                    )
                    .await,
            );
        }
        // Nineteen: below the threshold. Identity deletion counts once, not also as its operation envelope.
        assert_eq!(detections_of(&f.detect().await), 0.0);

        committed(
            f.iam
                .api
                .identities
                .delete(
                    &owner,
                    body(json!({ "tenantId": f.tenant_id, "identityId": people[4] })),
                )
                .await,
        );
        assert_eq!(detections_of(&f.detect().await), 1.0);
        let deletion = &f.detections(Some("mass-deletion")).await[0];
        assert_matches(
            deletion,
            json!({
                "severity": "high",
                "identityId": f.owner_id,
                "subject": { "type": "identity", "id": f.owner_id },
                "metadata": { "peak": 20, "threshold": 20, "identities": 5 },
            }),
        );
        let mut expected = people.clone();
        expected.sort();
        assert_eq!(sorted(&deletion["evidence"]["identityIds"]), expected);
        assert_eq!(
            sorted(&deletion["evidence"]["actions"]),
            vec!["iam:roles:delete", "identity:delete"]
        );
        assert_eq!(
            deletion["evidence"]["eventIds"].as_array().unwrap().len(),
            20
        );
    });
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule and threat-response.ts threatAudit (other port units)"]
fn impersonation_burst_five_view_as_sessions_in_a_day_impersonated_sign_ins_teach_nothing() {
    run(|| async {
        let f = fixture().await;
        let people = f.members("viewed", 5).await;
        let owner = f.owner_sign_in().await;
        f.set_auth_policy(&owner, json!({ "allowImpersonation": true }))
            .await;
        f.detect().await;

        let impersonate = |identity_id: String| {
            let owner = owner.clone();
            let f = &f;
            async move {
                ok(f.from(
                    "198.51.100.50",
                    f.iam.api.identities.impersonate(
                        &owner,
                        body(json!({
                            "tenantId": f.tenant_id,
                            "identityId": identity_id,
                            "reason": "support ticket",
                        })),
                    ),
                )
                .await)
            }
        };
        for (_, id) in &people[..4] {
            impersonate(id.clone()).await;
        }
        assert_eq!(detections_of(&f.detect().await), 0.0);
        impersonate(people[4].1.clone()).await;
        assert_eq!(detections_of(&f.detect().await), 1.0);
        let burst = &f.detections(Some("impersonation-burst")).await[0];
        assert_matches(
            burst,
            json!({
                "severity": "medium",
                "identityId": f.owner_id,
                "metadata": { "peak": 5, "threshold": 5, "targets": 5 },
            }),
        );
        assert_eq!(sorted(&burst["evidence"]["identityIds"]), ids(&people));
        // Sessions opened by an administrator are not the members' own sign-ins.
        for (_, id) in &people {
            assert!(f.get("threatBaselines", id).await.is_none());
        }
    });
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule and threat-response.ts threatAudit (other port units)"]
fn denial_burst_thirty_refusals_of_one_person_in_ten_minutes() {
    run(|| async {
        let f = fixture().await;
        let alice = f.member("alice").await;
        let session = f.sign_in_as("alice").await;
        let token = session["token"].as_str().unwrap().to_owned();
        f.detect().await;
        for _ in 0..29 {
            assert!(!f.reads_document(&token).await);
        }
        assert_eq!(detections_of(&f.detect().await), 0.0);
        assert!(!f.reads_document(&token).await);
        assert_eq!(detections_of(&f.detect().await), 1.0);
        let denials = &f.detections(Some("denial-burst")).await[0];
        assert_matches(
            denials,
            json!({
                "severity": "medium",
                "identityId": alice,
                "metadata": { "peak": 30, "threshold": 30, "agent": false },
                "evidence": { "actions": ["documents:read"] },
            }),
        );
    });
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule and threat-response.ts threatAudit (other port units)"]
fn recon_burst_administrative_reads_over_a_lowered_threshold_the_threats_console_is_not_counted() {
    run(|| async {
        let f = fixture().await;
        let alice = f.member("alice").await;
        let owner = f.owner_sign_in().await;
        f.configure(
            &owner,
            json!({ "rules": { "recon-burst": { "threshold": 20 } } }),
        )
        .await;
        f.detect().await;

        for _ in 0..25 {
            let result = f
                .iam
                .api
                .threats
                .rules(&owner, body(json!({ "tenantId": f.tenant_id })))
                .await;
            if !unported(&result) {
                ok(result);
            }
        }
        let read = || {
            f.iam.api.identities.get(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "identityId": alice })),
            )
        };
        for _ in 0..19 {
            ok(read().await);
        }
        assert_eq!(detections_of(&f.detect().await), 0.0);

        ok(read().await);
        assert_eq!(detections_of(&f.detect().await), 1.0);
        let recon = &f.detections(Some("recon-burst")).await[0];
        assert_matches(
            recon,
            json!({
                "severity": "low",
                "identityId": f.owner_id,
                "metadata": { "kind": "reads", "peak": 20, "threshold": 20 },
                "evidence": { "actions": ["iam:identities:read"] },
            }),
        );
    });
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule and threat-response.ts threatAudit (other port units)"]
fn guardrail_weakened_the_tenant_sign_in_policy_loses_a_protection() {
    run(|| async {
        let f = fixture().await;
        f.detect().await;

        // Tightening is not reported. Root sets it: an owner without a second factor would lock themselves out.
        f.set_auth_policy(
            &f.root_credential,
            json!({ "requireMfa": true, "notifyNewSignIn": true }),
        )
        .await;
        assert_eq!(detections_of(&f.detect().await), 0.0);

        f.set_auth_policy(&f.root_credential, json!({ "notifyNewSignIn": true }))
            .await;
        assert_eq!(detections_of(&f.detect().await), 1.0);
        let dropped = &f.detections(Some("guardrail-weakened")).await[0];
        assert_matches(
            dropped,
            json!({
                "severity": "medium",
                "subject": { "type": "tenant", "id": f.tenant_id },
                "metadata": { "change": "auth-policy", "weakened": ["requireMfa"] },
            }),
        );
        // A root administrator is not an identity of this tenant: nobody's risk here.
        assert!(dropped.get("identityId").is_none());

        // Set and dropped again within one run, by the owner: judged in chain order.
        let owner = f.owner_sign_in().await;
        f.set_auth_policy(
            &owner,
            json!({ "notifyNewSignIn": true, "bindSessionsToIp": true }),
        )
        .await;
        f.set_auth_policy(&owner, Value::Null).await;
        assert_eq!(detections_of(&f.detect().await), 1.0);
        let latest = f
            .detections(Some("guardrail-weakened"))
            .await
            .pop()
            .unwrap();
        assert_matches(
            &latest,
            json!({
                "identityId": f.owner_id,
                "metadata": { "weakened": ["bindSessionsToIp", "notifyNewSignIn"] },
            }),
        );
    });
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule and threat-response.ts threatAudit (other port units)"]
fn dormant_reactivated_a_sign_in_after_the_dormancy_period() {
    run(|| async {
        let f = fixture().await;
        let alice = f.member("alice").await;
        f.member("bob").await;
        f.from("198.51.100.70", f.sign_in_as("alice")).await;
        f.from("198.51.100.71", f.sign_in_as("bob")).await;
        f.detect().await;

        f.advance(60.0 * DAY);
        f.from("198.51.100.71", f.sign_in_as("bob")).await;
        assert_eq!(detections_of(&f.detect().await), 0.0);

        f.advance(31.0 * DAY);
        f.from("198.51.100.70", f.sign_in_as("alice")).await;
        f.from("198.51.100.71", f.sign_in_as("bob")).await;
        assert_eq!(detections_of(&f.detect().await), 1.0);
        let dormant = &f.detections(Some("dormant-reactivated")).await[0];
        assert_matches(
            dormant,
            json!({
                "severity": "medium",
                "identityId": alice,
                "network": "198.51.100.70",
                "metadata": { "idleDays": 91, "dormantDays": 90 },
            }),
        );
        assert_matches(
            &f.get("threatBaselines", &alice).await.unwrap()["riskySignIn"],
            json!({ "ruleId": "dormant-reactivated", "detectionId": dormant["id"] }),
        );
    });
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule and threat-response.ts threatAudit (other port units)"]
fn is_idempotent_across_runs_including_a_full_re_read_of_the_trail() {
    run(|| async {
        let f = fixture().await;
        let carol = f.member("carol").await;
        f.detect().await;

        f.fail_password("carol", "198.51.100.80", 10).await;
        assert_eq!(detections_of(&f.detect().await), 1.0);
        // Past the sign-in rate limit window, still inside the brute-force-success window.
        f.advance(16.0 * MINUTE);
        let session = f.from("198.51.100.80", f.sign_in_as("carol")).await;
        f.change_password(
            session["token"].as_str().unwrap(),
            "a strong carol password",
            "a brand new carol password",
        )
        .await;
        assert_eq!(detections_of(&f.detect().await), 2.0);
        assert_eq!(detections_of(&f.detect().await), 0.0);

        let snapshot = || async {
            let mut detections: Vec<String> = f
                .detections(None)
                .await
                .iter()
                .map(|detection| detection["uniqueKey"].as_str().unwrap().to_owned())
                .collect();
            detections.sort();
            let incidents: Vec<Value> = f
                .tenant_records("threatIncidents")
                .await
                .iter()
                .map(|incident| json!([incident["id"], incident["detectionCount"]]))
                .collect();
            let risk = f
                .get("identityRisk", &carol)
                .await
                .map(|risk| risk["contributions"].clone());
            (detections, incidents, risk)
        };
        let before = snapshot().await;
        assert_eq!(before.0.len(), 3);
        // Forget how far the engine read: the next run starts a day back and reads everything again.
        let tenant_id = f.tenant_id.clone();
        f.store()
            .transaction(|tx| async move { tx.delete("threatCursors", &tenant_id).await })
            .await
            .unwrap();
        let reread = f.detect().await;
        assert!(number(&reread, "eventsScanned") > 20.0);
        assert_eq!(detections_of(&reread), 0.0);
        assert_eq!(snapshot().await, before);
    });
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule/effectiveRisk/riskContext and threat-response.ts threatAudit (other port units)"]
fn principal_risk_level_flips_a_policy_once_detections_make_the_person_high_risk() {
    run(|| async {
        let f = fixture().await;
        let mallory = f.member("mallory").await;
        let owner = f.owner_sign_in().await;
        let role = ok(f
            .iam
            .api
            .roles
            .create(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Readers unless risky",
                    "document": {
                        "version": 1,
                        "statements": [
                            { "effect": "allow", "actions": ["documents:read"], "resources": ["*"] },
                            {
                                "effect": "deny",
                                "actions": ["documents:read"],
                                "resources": ["*"],
                                "conditions": { "StringEquals": { "principal.riskLevel": "high" } },
                            },
                        ],
                    },
                })),
            )
            .await);
        committed(
            f.iam
                .api
                .bindings
                .create(
                    &owner,
                    body(json!({
                        "tenantId": f.tenant_id,
                        "roleId": role["id"],
                        "subjectType": "identity",
                        "subjectId": mallory,
                    })),
                )
                .await,
        );
        let through_api = f
            .configure(
                &owner,
                json!({ "rules": { "brute-force": { "threshold": 5 } } }),
            )
            .await;
        f.detect().await;

        f.fail_password("mallory", "198.51.100.90", 5).await;
        let session = f.from("198.51.100.90", f.sign_in_as("mallory")).await;
        let token = session["token"].as_str().unwrap().to_owned();
        assert!(f.reads_document(&token).await);

        // Password guessing (medium, 25) and the sign-in that followed (high, 50): 75 points, high risk.
        assert_eq!(detections_of(&f.detect().await), 2.0);
        assert_matches(
            &f.risk_of(&owner, &mallory).await,
            json!({ "level": "high", "score": 75 }),
        );
        assert!(!f.reads_document(&token).await);
        let mut changes = f
            .find(
                "audit",
                Filter::new()
                    .eq("tenantId", f.tenant_id.clone())
                    .eq("action", "threat:risk-change")
                    .eq("resourceId", mallory.clone()),
            )
            .await;
        changes.sort_by(|a, b| {
            a["sequence"]
                .as_f64()
                .unwrap()
                .total_cmp(&b["sequence"].as_f64().unwrap())
        });
        assert_matches(
            &changes.last().unwrap()["metadata"],
            json!({ "to": "high", "score": 75 }),
        );

        // Closing the incident as a false positive takes the points back.
        if !through_api {
            return;
        }
        let guessing = &f.detections(Some("brute-force")).await[0];
        ok(f.iam
            .api
            .threats
            .resolve_incident(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "incidentId": guessing["incidentId"],
                    "resolution": "false-positive",
                })),
            )
            .await);
        assert!(f.reads_document(&token).await);
    });
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule and threat-response.ts threatAudit (other port units)"]
fn account_takeover_persistence_a_risky_sign_in_judged_harmless_opens_no_window() {
    run(|| async {
        let f = fixture().await;
        f.member("bob").await;
        f.detect().await;
        f.fail_password("bob", "198.51.100.43", 5).await;
        let bob_session = f.from("198.51.100.43", f.sign_in_as("bob")).await;
        assert_eq!(detections_of(&f.detect().await), 1.0);
        let risky = f.detections(Some("brute-force-success")).await.remove(0);
        let owner = f.owner_sign_in().await;
        let dismissed = f
            .iam
            .api
            .threats
            .dismiss_detection(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "detectionId": risky["id"],
                    "reason": "Bob mistyped his new password",
                })),
            )
            .await;
        if unported(&dismissed) {
            // `threats.dismissDetection` is another unit's stub: the dismissal it records is written directly.
            let mut detection = risky.as_object().unwrap().clone();
            detection.insert("status".into(), json!("dismissed"));
            f.overwrite("threatDetections", detection).await;
        } else {
            ok(dismissed);
        }
        f.advance(2.0 * MINUTE);
        f.change_password(
            bob_session["token"].as_str().unwrap(),
            "a strong bob password",
            "a brand new bob password",
        )
        .await;
        assert_eq!(detections_of(&f.detect().await), 0.0);
        assert!(
            f.detections(Some("account-takeover-persistence"))
                .await
                .is_empty()
        );
    });
}

/// Facts about a tenant nobody in it is known to (`identity` undefined, nothing privileged).
struct NoFacts;

#[async_trait::async_trait]
impl RuleFacts for NoFacts {
    async fn identity(&self, _id: &str) -> IamResult<Option<Identity>> {
        Ok(None)
    }
    async fn is_privileged(&self, _identity_id: &str) -> IamResult<bool> {
        Ok(false)
    }
    async fn is_admin_role(&self, _role_id: &str) -> IamResult<bool> {
        Ok(false)
    }
    async fn holds_role(&self, _identity_id: &str, _role_id: &str) -> IamResult<bool> {
        Ok(false)
    }
}

fn empty_state() -> RuleState {
    RuleState {
        auth_policy: None,
        extra: Map::new(),
    }
}

#[test]
#[ignore = "needs threats.ts resolveThreatSettings/threatRule (another port unit)"]
fn counting_rules_keep_a_bursts_dedupe_key_when_the_lookback_is_cut_short() {
    run(|| async {
        let tenant_id = "tenant-cut";
        // 2026-09-24T00:00:00Z.
        let midnight = 1_790_208_000_000.0;
        // An integration denied every 12 seconds since midnight: a burst that never pauses.
        let events: Vec<Record> = (0..3600)
            .map(|index| {
                json!({
                    "id": format!("deny-{index}"),
                    "tenantId": tenant_id,
                    "actorId": "integration-7",
                    "action": "documents:read",
                    "resourceId": "d1",
                    "timestamp": midnight + f64::from(index) * 12_000.0,
                    "sequence": index + 1,
                    "outcome": "deny",
                })
                .as_object()
                .unwrap()
                .clone()
            })
            .collect();
        let at = |event: &Record| event["timestamp"].as_f64().unwrap();
        let settings: ResolvedThreatSettings =
            better_iam_server::threats::resolve_threat_settings(None).unwrap();
        // One run over [from, to) whose lookback the engine's cap cut at `historyFrom`.
        let evaluate = |from: f64, to: f64, history_from: f64| {
            let fresh: Vec<Record> = events
                .iter()
                .filter(|event| at(event) >= from && at(event) < to)
                .cloned()
                .collect();
            let history: Vec<Record> = events
                .iter()
                .filter(|event| at(event) >= history_from && at(event) < from)
                .cloned()
                .collect();
            let settings = settings.clone();
            async move {
                let facts = NoFacts;
                let mut input = RuleInput {
                    tenant_id: tenant_id.to_owned(),
                    events: &fresh,
                    history: &history,
                    history_from: Some(history_from),
                    settings,
                    baselines: IndexMap::new(),
                    state: empty_state(),
                    facts: &facts,
                    now: to,
                };
                evaluate_threat_rules(&mut input)
                    .await
                    .unwrap()
                    .candidates
                    .into_iter()
                    .filter(|candidate| candidate.rule_id == json!("denial-burst"))
                    .map(|candidate| candidate.dedupe_key)
                    .collect::<Vec<_>>()
            }
        };
        // Two runs five minutes apart near noon; the cut moves with the newest events, two hours behind them.
        let noon = midnight + 12.0 * 60.0 * MINUTE - MINUTE;
        let first = evaluate(
            noon - 10.0 * MINUTE,
            noon - 5.0 * MINUTE,
            noon - 130.0 * MINUTE,
        )
        .await;
        let second = evaluate(noon - 5.0 * MINUTE, noon, noon - 125.0 * MINUTE).await;
        assert_eq!(first.len(), 1);
        assert_eq!(second, first);
    });
}

/// Every rule turned off: evaluation reads no rule definition (threats.ts), only learns sign-ins.
fn rules_off() -> ResolvedThreatSettings {
    let mut rules = Map::new();
    for rule_id in [
        "password-spray",
        "brute-force",
        "brute-force-success",
        "mfa-bombardment",
        "session-hijack",
        "new-network",
        "dormant-reactivated",
        "account-takeover-persistence",
        "privilege-escalation",
        "root-admin-granted",
        "mass-deletion",
        "directory-mass-change",
        "impersonation-burst",
        "denial-burst",
        "classified-access-attempts",
        "recon-burst",
        "guardrail-weakened",
        "token-replay",
        "audit-tampering",
        "invariant-broken",
        "user-reported",
        "upstream-signal",
    ] {
        rules.insert(
            rule_id.into(),
            json!({ "enabled": false, "severity": "low" }),
        );
    }
    ResolvedThreatSettings {
        rules: Value::Object(rules),
        trusted_networks: Vec::new(),
        dormant_days: 90.0,
        risk_half_life_hours: 24.0,
        notify: json!({ "owners": false, "emails": [] }),
        max_automatic_containments: 3.0,
        extra: Map::new(),
    }
}

fn sign_in_event(id: &str, actor: &str, at: f64, metadata: Value) -> Record {
    json!({
        "id": id,
        "tenantId": "t1",
        "actorId": actor,
        "action": "auth:session:create",
        "resourceId": actor,
        "timestamp": at,
        "outcome": "allow",
        "metadata": metadata,
    })
    .as_object()
    .unwrap()
    .clone()
}

#[test]
fn learns_sign_ins_into_baselines_whatever_rules_are_enabled() {
    run(|| async {
        let mut events = vec![
            sign_in_event(
                "e1",
                "alice",
                1000.0,
                json!({ "ip": "198.51.100.1", "userAgent": "agent\u{7}one" }),
            ),
            sign_in_event(
                "e2",
                "alice",
                2000.0,
                json!({ "ip": "198.51.100.2", "userAgent": "agent two" }),
            ),
            sign_in_event("e3", "alice", 3000.0, json!({ "ip": "198.51.100.1" })),
            sign_in_event("e4", "bob", 1500.0, json!({ "ip": "not an address" })),
        ];
        // Sessions an administrator opened through "view as" are not the person's own sign-ins.
        let mut viewed = sign_in_event("e5", "carol", 1200.0, json!({ "ip": "198.51.100.9" }));
        viewed.insert("impersonatorId".into(), json!("owner"));
        events.push(viewed);
        // The threats module's own events are never read.
        let mut own = sign_in_event("e6", "dave", 1300.0, json!({}));
        own.insert("action".into(), json!("threat:detection"));
        events.push(own);
        let mut stored = IndexMap::new();
        stored.insert(
            "bob".to_owned(),
            json!({
                "id": "bob", "tenantId": "t1", "identityId": "bob", "networks": [{ "key": "192.0.2.1", "lastAt": 10 }],
                "userAgents": [], "lastSignInAt": 5000, "firstSeenAt": 10, "updatedAt": 10, "custom": true,
            })
            .as_object()
            .unwrap()
            .clone(),
        );
        let facts = NoFacts;
        let mut input = RuleInput {
            tenant_id: "t1".into(),
            events: &events,
            history: &[],
            history_from: None,
            settings: rules_off(),
            baselines: stored,
            state: empty_state(),
            facts: &facts,
            now: 9000.0,
        };
        let evaluated = evaluate_threat_rules(&mut input).await.unwrap();
        assert!(evaluated.candidates.is_empty());
        assert_eq!(
            evaluated.touched_baselines.iter().collect::<Vec<_>>(),
            vec!["alice", "bob"]
        );
        let alice = Value::Object(input.baselines["alice"].clone());
        assert_eq!(
            alice,
            json!({
                "id": "alice",
                "tenantId": "t1",
                "identityId": "alice",
                "networks": [
                    { "key": "198.51.100.2", "lastAt": 2000 },
                    { "key": "198.51.100.1", "lastAt": 3000 },
                ],
                "userAgents": [
                    { "value": "agentone", "lastAt": 1000 },
                    { "value": "agent two", "lastAt": 2000 },
                ],
                "firstSeenAt": 1000,
                "updatedAt": 9000,
                "lastSignInAt": 3000,
            })
        );
        // A stored baseline keeps its members and its later sign-in; an address that is not one is not learned.
        let bob = Value::Object(input.baselines["bob"].clone());
        assert_eq!(
            bob,
            json!({
                "id": "bob", "tenantId": "t1", "identityId": "bob", "networks": [{ "key": "192.0.2.1", "lastAt": 10 }],
                "userAgents": [], "lastSignInAt": 5000, "firstSeenAt": 10, "updatedAt": 9000, "custom": true,
            })
        );
        assert!(!input.baselines.contains_key("carol"));
        assert!(!input.baselines.contains_key("dave"));
    });
}

#[test]
fn considers_well_formed_events_that_are_not_the_threat_modules_own() {
    use better_iam_server::threat_rules::{baseline_identity_ids, considered, identity_label};
    let event =
        |value: Value| -> better_iam_core::AuditEvent { serde_json::from_value(value).unwrap() };
    let base = json!({
        "id": "e1", "tenantId": "t1", "actorId": "alice", "action": "auth:password:change",
        "resourceId": "alice", "timestamp": 1, "outcome": "allow",
    });
    assert!(considered(&event(base.clone())).unwrap());
    let mut by_engine = base.clone();
    by_engine["actorId"] = json!("threat-detection");
    assert!(!considered(&event(by_engine)).unwrap());
    let mut own = base.clone();
    own["action"] = json!("threat:contain");
    assert!(!considered(&event(own)).unwrap());

    // Own sign-ins and own sign-in method changes; not sessions opened through "view as", nor changes to others.
    let mut viewed = base.clone();
    viewed["id"] = json!("e2");
    viewed["action"] = json!("auth:session:create");
    viewed["actorId"] = json!("carol");
    viewed["impersonatorId"] = json!("owner");
    let mut other = base.clone();
    other["id"] = json!("e3");
    other["resourceId"] = json!("bob");
    other["actorId"] = json!("dave");
    let mut signed_in = base.clone();
    signed_in["id"] = json!("e4");
    signed_in["action"] = json!("auth:session:create");
    signed_in["actorId"] = json!("erin");
    assert_eq!(
        baseline_identity_ids(&[event(base), event(viewed), event(other), event(signed_in)])
            .unwrap(),
        vec!["alice", "erin"]
    );

    let identity = |name: &str, email: Option<&str>| -> Identity {
        serde_json::from_value(json!({
            "id": "i1", "tenantId": "t1", "kind": "user", "name": name, "email": email, "status": "active",
            "emailVerified": true, "rootAdmin": false, "owner": false, "createdAt": 1,
        }))
        .unwrap()
    };
    assert_eq!(identity_label(None, "gone\u{1b}[1m").unwrap(), "gone[1m");
    assert_eq!(
        identity_label(Some(&identity("Alice", Some("alice@acme.test"))), "i1").unwrap(),
        "Alice (alice@acme.test)"
    );
    assert_eq!(
        identity_label(Some(&identity("  ", Some("alice@acme.test"))), "i1").unwrap(),
        "alice@acme.test"
    );
    assert_eq!(
        identity_label(Some(&identity("Alice", None)), "i1").unwrap(),
        "Alice"
    );
    assert_eq!(
        identity_label(Some(&identity("", None)), "i1").unwrap(),
        "i1"
    );
}
