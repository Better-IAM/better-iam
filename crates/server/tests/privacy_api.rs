//! Port of tests/privacy.test.ts through the `privacy` API group and the credential-free runtime (api/privacy.ts):
//! purposes and consent, data-subject requests, public intake, deadline reminders, the review fixes, and legal holds
//! on organizations. The "privacy emails" suite renders auth templates and belongs to the auth crate's tests.
//!
//! The two erasure suites delete an account, which reaches guests.ts revokeGuestInvitationsBy (guests unit); until it
//! lands they are `#[ignore]`d with that reason. Everything here needs the privacy.ts helpers (port/rust/privacy).

mod organization_fixture;

use std::sync::{Arc, Mutex};

use better_iam_auth::{DeliveryMessage, delivery_fn};
use better_iam_core::CredentialInput;
use better_iam_server::options::{AuthorizationRequest, ResourceTarget};
use organization_fixture::{Org, assert_matches, body, code, fails, ok, organization, run};
use serde_json::{Value, json};

const DAY: f64 = 86_400_000.0;

struct Scenario {
    f: Org,
    tenant_id: String,
    owner: CredentialInput,
    marketing: Value,
    analytics: Value,
    alice: String,
    alice_token: CredentialInput,
    inbox: Arc<Mutex<Vec<DeliveryMessage>>>,
}

macro_rules! call {
    ($s:expr, $method:ident, $credential:expr, $input:expr) => {
        $s.f.iam
            .api
            .privacy
            .$method($credential, body($input))
            .await
    };
}

impl Scenario {
    fn sent(&self, template: &str) -> Vec<DeliveryMessage> {
        self.inbox
            .lock()
            .unwrap()
            .iter()
            .filter(|message| message.template == template)
            .cloned()
            .collect()
    }

    async fn dispatch(&self) {
        self.f.iam.auth.dispatch_outbox(None).await.unwrap();
    }

    async fn owner_sign_in(&self) -> CredentialInput {
        self.f.sign_in(&self.f.owner_id.clone()).await
    }

    async fn decide(&self, key: &str, version: u32, granted: bool) -> Value {
        ok(call!(
            self,
            decide,
            &self.alice_token,
            json!({
                "tenantId": self.tenant_id,
                "purposeKey": key,
                "version": version,
                "granted": granted,
            })
        ))
    }

    async fn check(&self, credential: &CredentialInput, subject: Value, key: &str) -> Value {
        ok(call!(
            self,
            check,
            credential,
            json!({ "tenantId": self.tenant_id, "subject": subject, "purposeKey": key })
        ))
    }

    async fn submit(&self, input: Value) -> Value {
        let mut input = input.as_object().cloned().unwrap();
        input.insert("tenantId".into(), json!(self.tenant_id));
        ok(call!(
            self,
            submit_request,
            &self.alice_token,
            Value::Object(input)
        ))
    }

    async fn fulfil(&self, credential: &CredentialInput, request_id: &Value) -> Value {
        ok(call!(
            self,
            fulfil_request,
            credential,
            json!({ "tenantId": self.tenant_id, "requestId": request_id })
        ))
    }

    async fn audit_events(&self, credential: &CredentialInput) -> Vec<Value> {
        let audit = ok(self
            .f
            .iam
            .api
            .audit
            .list(credential, body(json!({ "tenantId": self.tenant_id })))
            .await);
        match audit {
            Value::Array(events) => events,
            other => other["events"].as_array().cloned().unwrap_or_default(),
        }
    }

    async fn role(&self, name: &str, actions: Value) -> Value {
        ok(self
            .f
            .iam
            .api
            .roles
            .create(
                &self.owner,
                body(json!({
                    "tenantId": self.tenant_id,
                    "name": name,
                    "document": {
                        "version": 1,
                        "statements": [{ "effect": "allow", "actions": actions, "resources": ["*"] }],
                    },
                })),
            )
            .await)
    }

    async fn bind(&self, role: &Value, identity_id: &str) {
        ok(self
            .f
            .iam
            .api
            .bindings
            .create(
                &self.owner,
                body(json!({
                    "tenantId": self.tenant_id,
                    "roleId": role["id"],
                    "subjectType": "identity",
                    "subjectId": identity_id,
                })),
            )
            .await);
    }
}

async fn scenario() -> Scenario {
    let inbox: Arc<Mutex<Vec<DeliveryMessage>>> = Arc::default();
    let sink = inbox.clone();
    let f = organization(move |options| {
        if let Some(authentication) = options.authentication.as_mut() {
            authentication.send_email = Some(delivery_fn(move |message| {
                sink.lock().unwrap().push(message);
                async { Ok(()) }
            }));
        }
    })
    .await;
    let tenant_id = f.tenant_id.clone();
    let owner = f.owner_credential.clone();
    let create = |input: Value| {
        let mut input = input.as_object().cloned().unwrap();
        input.insert("tenantId".into(), json!(tenant_id));
        let (iam, owner) = (&f.iam, owner.clone());
        async move {
            ok(iam
                .api
                .privacy
                .create_purpose(&owner, body(Value::Object(input)))
                .await)
        }
    };
    let marketing = create(json!({
        "key": "marketing-email",
        "name": "Marketing email",
        "description": "Product news and offers by email.",
        "legalBasis": "consent",
        "dataCategories": ["contact"],
    }))
    .await;
    let analytics = create(json!({
        "key": "product-analytics",
        "name": "Product analytics",
        "description": "How features are used, to improve them.",
        "legalBasis": "legitimate-interests",
        "dataCategories": ["usage"],
    }))
    .await;
    create(json!({
        "key": "data-sharing",
        "name": "Sharing with partners",
        "description": "Sharing contact data with advertising partners.",
        "legalBasis": "consent",
        "mode": "opt-out",
    }))
    .await;
    create(json!({
        "key": "billing",
        "name": "Billing",
        "description": "Invoices and payments for your plan.",
        "legalBasis": "contract",
    }))
    .await;
    let alice = f.member("alice").await;
    let alice_token = f.sign_in(&alice).await;
    Scenario {
        f,
        tenant_id,
        owner,
        marketing,
        analytics,
        alice,
        alice_token,
        inbox,
    }
}

fn purpose<'a>(mine: &'a Value, key: &str) -> &'a Value {
    mine["purposes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|purpose| purpose["key"] == key)
        .unwrap()
}

// ── privacy purposes and consent ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn validates_purposes_and_refuses_duplicate_keys() {
    run(|| async {
        let s = scenario().await;
        let error = fails(call!(
            s,
            create_purpose,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "key": "marketing-email",
                "name": "Again",
                "description": "x",
                "legalBasis": "consent",
            })
        ));
        assert_eq!(code(&error), "CONFLICT");
        let error = fails(call!(
            s,
            create_purpose,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "key": "Bad Key",
                "name": "Bad",
                "description": "x",
                "legalBasis": "consent",
            })
        ));
        assert_eq!(code(&error), "INVALID_INPUT");
        let error = fails(call!(
            s,
            create_purpose,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "key": "fraud",
                "name": "Fraud",
                "description": "x",
                "legalBasis": "legal-obligation",
                "mode": "opt-out",
            })
        ));
        assert_eq!(code(&error), "INVALID_INPUT");
        // Changing the legal basis is material and needs a new version.
        let error = fails(call!(
            s,
            update_purpose,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "purposeId": s.analytics["id"],
                "legalBasis": "consent",
            })
        ));
        assert_eq!(code(&error), "INVALID_INPUT");
        // A member without permissions cannot manage purposes.
        let error = fails(call!(
            s,
            list_purposes,
            &s.alice_token,
            json!({ "tenantId": s.tenant_id })
        ));
        assert_eq!(code(&error), "ACCESS_DENIED");
    });
}

#[test]
fn lets_people_decide_with_receipts_versions_and_the_effect_of_each_basis() {
    run(|| async {
        let s = scenario().await;
        let mine = ok(call!(
            s,
            mine,
            &s.alice_token,
            json!({ "tenantId": s.tenant_id })
        ));
        assert_eq!(
            purpose(&mine, "marketing-email")["state"],
            json!({ "allowed": false, "reason": "NO_CONSENT" })
        );
        assert_eq!(
            purpose(&mine, "product-analytics")["state"],
            json!({ "allowed": true, "reason": "LEGITIMATE_INTERESTS" })
        );
        assert_eq!(
            purpose(&mine, "data-sharing")["state"],
            json!({ "allowed": true, "reason": "NOT_OPTED_OUT" })
        );
        assert_eq!(
            purpose(&mine, "billing")["state"],
            json!({ "allowed": true, "reason": "LEGAL_BASIS" })
        );
        assert_eq!(purpose(&mine, "billing")["decidable"], json!(false));

        let receipt = ok(call!(
            s,
            decide,
            &s.alice_token,
            json!({
                "tenantId": s.tenant_id,
                "purposeKey": "marketing-email",
                "version": 1,
                "granted": true,
                "evidence": "Signup form v3",
            })
        ));
        assert_matches(
            &receipt,
            json!({
                "tenantId": s.tenant_id,
                "subject": format!("identity:{}", s.alice),
                "granted": true,
                "purpose": { "key": "marketing-email", "version": 1, "legalBasis": "consent" },
                "source": "self",
            }),
        );
        let alice_subject = json!({ "identityId": s.alice });
        assert_matches(
            &s.check(&s.owner, alice_subject.clone(), "marketing-email")
                .await,
            json!({ "allowed": true, "reason": "CONSENT_GIVEN" }),
        );
        // Opting out and objecting.
        s.decide("data-sharing", 1, false).await;
        s.decide("product-analytics", 1, false).await;
        let after = ok(call!(
            s,
            mine,
            &s.alice_token,
            json!({ "tenantId": s.tenant_id })
        ));
        assert_eq!(
            purpose(&after, "data-sharing")["state"]["reason"],
            "CONSENT_WITHDRAWN"
        );
        assert_eq!(
            purpose(&after, "product-analytics")["state"]["reason"],
            "OBJECTED"
        );
        // Contract purposes are not a matter of consent.
        let error = fails(call!(
            s,
            decide,
            &s.alice_token,
            json!({ "tenantId": s.tenant_id, "purposeKey": "billing", "version": 1, "granted": false })
        ));
        assert_eq!(code(&error), "INVALID_INPUT");

        // A new version asks again: the old grant no longer counts, and deciding on the old text is refused.
        ok(call!(
            s,
            update_purpose,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "purposeId": s.marketing["id"],
                "description": "Product news, offers and partner offers by email.",
                "newVersion": true,
            })
        ));
        assert_matches(
            &s.check(&s.owner, alice_subject.clone(), "marketing-email")
                .await,
            json!({ "allowed": false, "reason": "CONSENT_OUTDATED" }),
        );
        let error = fails(call!(
            s,
            decide,
            &s.alice_token,
            json!({ "tenantId": s.tenant_id, "purposeKey": "marketing-email", "version": 1, "granted": true })
        ));
        assert_eq!(code(&error), "VERSION_CONFLICT");

        // The receipt verifies; a tampered copy does not; a later decision makes it historical.
        assert_eq!(
            ok(call!(
                s,
                verify_receipt,
                &s.owner,
                json!({ "tenantId": s.tenant_id, "receipt": receipt })
            )),
            json!({ "valid": true, "current": true })
        );
        let mut tampered = receipt.clone();
        tampered["granted"] = json!(false);
        assert_matches(
            &ok(call!(
                s,
                verify_receipt,
                &s.owner,
                json!({ "tenantId": s.tenant_id, "receipt": tampered })
            )),
            json!({ "valid": false, "reason": "SIGNATURE_INVALID" }),
        );
        // History is newest first by decision time; decisions at the same instant have no defined order.
        s.f.advance(1_000.0);
        s.decide("marketing-email", 2, true).await;
        assert_eq!(
            ok(call!(
                s,
                verify_receipt,
                &s.owner,
                json!({ "tenantId": s.tenant_id, "receipt": receipt })
            )),
            json!({ "valid": true, "current": false })
        );
        let mine_receipt = ok(call!(
            s,
            my_receipt,
            &s.alice_token,
            json!({ "tenantId": s.tenant_id, "receiptId": receipt["receiptId"] })
        ));
        assert!(organization_fixture::matches(&mine_receipt, &receipt));
        assert!(organization_fixture::matches(&receipt, &mine_receipt));
        let history = ok(call!(
            s,
            my_history,
            &s.alice_token,
            json!({ "tenantId": s.tenant_id, "purposeKey": "marketing-email" })
        ));
        let versions: Vec<f64> = history
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["purposeVersion"].as_f64().unwrap())
            .collect();
        assert_eq!(versions, vec![2.0, 1.0]);
        assert_eq!(history[1]["evidence"], "Signup form v3");
    });
}

#[test]
fn lets_grants_lapse_after_the_consent_lifetime() {
    run(|| async {
        let s = scenario().await;
        let cookies = ok(call!(
            s,
            create_purpose,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "key": "cookies.ads",
                "name": "Advertising cookies",
                "description": "Cookies that measure ads.",
                "legalBasis": "consent",
                "consentLifetimeDays": 30,
            })
        ));
        let key = cookies["key"].as_str().unwrap().to_owned();
        s.decide(&key, 1, true).await;
        let alice_subject = json!({ "identityId": s.alice });
        assert_eq!(
            s.check(&s.owner, alice_subject.clone(), &key).await["allowed"],
            json!(true)
        );
        s.f.advance(31.0 * DAY);
        let owner = s.owner_sign_in().await;
        assert_matches(
            &s.check(&owner, alice_subject, &key).await,
            json!({ "allowed": false, "reason": "CONSENT_EXPIRED" }),
        );
    });
}

#[test]
fn exposes_principal_consents_to_policies() {
    run(|| async {
        let s = scenario().await;
        let role = ok(s
            .f
            .iam
            .api
            .roles
            .create(
                &s.owner,
                body(json!({
                    "tenantId": s.tenant_id,
                    "name": "Newsletter reader",
                    "document": {
                        "version": 1,
                        "statements": [{
                            "effect": "allow",
                            "actions": ["documents:read"],
                            "resources": ["*"],
                            "conditions": { "ArrayContains": { "principal.consents": ["marketing-email"] } },
                        }],
                    },
                })),
            )
            .await);
        s.bind(&role, &s.alice).await;
        let can_read = || async {
            s.f.iam
                .authorize(&AuthorizationRequest {
                    credential: s.alice_token.clone(),
                    tenant_id: s.tenant_id.clone(),
                    action: "documents:read".into(),
                    resource: ResourceTarget {
                        kind: "document".into(),
                        id: "d1".into(),
                    },
                })
                .await
                .unwrap()
                .allowed
        };
        assert!(!can_read().await);
        s.decide("marketing-email", 1, true).await;
        assert!(can_read().await);
        s.decide("marketing-email", 1, false).await;
        assert!(!can_read().await);
    });
}

#[test]
fn records_imports_checks_and_lists_decisions_for_application_subjects() {
    run(|| async {
        let s = scenario().await;
        let recorded = ok(call!(
            s,
            record,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "subject": { "externalId": "cus_100" },
                "purposeKey": "marketing-email",
                "granted": true,
                "method": "banner",
                "ip": "203.0.113.9",
            })
        ));
        assert_matches(
            &recorded,
            json!({ "subject": "external:cus_100", "granted": true, "current": true }),
        );
        // An older imported decision is kept in the history but does not replace the newer one.
        let imported = ok(call!(
            s,
            import_decisions,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "decisions": [
                    {
                        "subject": { "externalId": "cus_100" },
                        "purposeKey": "marketing-email",
                        "granted": false,
                        "version": 1,
                        "recordedAt": s.f.now() - 10.0 * DAY,
                    },
                    {
                        "subject": { "externalId": "cus_200" },
                        "purposeKey": "marketing-email",
                        "granted": false,
                        "version": 1,
                        "recordedAt": s.f.now() - DAY,
                    },
                ],
            })
        ));
        assert_eq!(imported, json!({ "imported": 2, "current": 1 }));
        let filtered = ok(call!(
            s,
            filter_subjects,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "purposeKey": "marketing-email",
                "subjects": [
                    { "externalId": "cus_100" },
                    { "externalId": "cus_200" },
                    { "externalId": "cus_300" },
                    { "identityId": "missing" },
                ],
            })
        ));
        assert_eq!(filtered["allowed"], json!([{ "externalId": "cus_100" }]));
        let reasons: Vec<&Value> = filtered["refused"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| &item["reason"])
            .collect();
        assert_eq!(
            reasons,
            vec![
                &json!("CONSENT_WITHDRAWN"),
                &json!("NO_CONSENT"),
                &json!("UNKNOWN_SUBJECT")
            ]
        );
        // The opt-out purpose's audience is every active person (owner and alice) until they opt out.
        let audience = ok(call!(
            s,
            audience,
            &s.owner,
            json!({ "tenantId": s.tenant_id, "purposeKey": "data-sharing" })
        ));
        assert_eq!(audience["total"], json!(2));
        let consents = ok(call!(
            s,
            list_consents,
            &s.owner,
            json!({ "tenantId": s.tenant_id, "purposeKey": "marketing-email" })
        ));
        assert_eq!(consents["total"], json!(2));
        let history = ok(call!(
            s,
            history,
            &s.owner,
            json!({ "tenantId": s.tenant_id, "subject": { "externalId": "cus_100" } })
        ));
        assert_eq!(history.as_array().unwrap().len(), 2);
        assert_matches(
            &history[0],
            json!({ "granted": true, "ip": "203.0.113.9", "method": "banner" }),
        );
        // The deployment's own code can check without a credential.
        assert_matches(
            &s.f.iam
                .privacy
                .check(&json!({
                    "tenantId": s.tenant_id,
                    "subject": { "externalId": "cus_100" },
                    "purposeKey": "marketing-email",
                }))
                .await
                .unwrap(),
            json!({ "allowed": true }),
        );
        let summary = ok(call!(
            s,
            summary,
            &s.owner,
            json!({ "tenantId": s.tenant_id })
        ));
        let marketing = summary["purposes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|purpose| purpose["key"] == "marketing-email")
            .unwrap();
        assert_matches(marketing, json!({ "granted": 1, "withdrawn": 1 }));
    });
}

// ── data-subject requests ────────────────────────────────────────────────────────────────────────────────────────

#[test]
fn answers_an_access_request_with_an_export_only_the_subject_or_a_handler_downloads() {
    run(|| async {
        let s = scenario().await;
        s.decide("marketing-email", 1, true).await;
        ok(call!(
            s,
            update_settings,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "contactEmail": "dpo@acme.test",
                "responseDays": { "gdpr": 20 },
            })
        ));
        let request = s.submit(json!({ "type": "access" })).await;
        assert_matches(
            &request,
            json!({
                "status": "open",
                "regulation": "gdpr",
                "verification": { "status": "verified", "method": "authenticated-session" },
            }),
        );
        assert_eq!(
            request["dueAt"].as_f64().unwrap() - request["receivedAt"].as_f64().unwrap(),
            20.0 * DAY
        );
        let error = fails(call!(
            s,
            submit_request,
            &s.alice_token,
            json!({ "tenantId": s.tenant_id, "type": "access" })
        ));
        assert_eq!(code(&error), "CONFLICT");
        s.dispatch().await;
        assert!(
            s.sent("privacy-request-received")
                .iter()
                .any(|message| message.to == "dpo@acme.test")
        );

        let done = s.fulfil(&s.owner, &request["id"]).await;
        assert_matches(
            &done,
            json!({ "status": "completed", "actions": ["export:full"] }),
        );
        let download = ok(call!(
            s,
            download_export,
            &s.alice_token,
            json!({ "tenantId": s.tenant_id, "requestId": request["id"] })
        ));
        let data = &download["data"];
        assert_eq!(data["profile"]["email"], "alice@acme.test");
        let consents = data["consents"].as_array().unwrap();
        assert_eq!(consents.len(), 1);
        assert_matches(
            &consents[0],
            json!({ "purpose": "marketing-email", "granted": true }),
        );
        assert!(data["profile"].get("passwordHash").is_none());
        // Another member cannot download it.
        let bob = s.f.member("bob").await;
        let bob = s.f.sign_in(&bob).await;
        let error = fails(call!(
            s,
            download_export,
            &bob,
            json!({ "tenantId": s.tenant_id, "requestId": request["id"] })
        ));
        assert_eq!(code(&error), "ACCESS_DENIED");
        // The subject hears back; staff notes stay internal.
        s.dispatch().await;
        let update = s
            .sent("privacy-request-update")
            .into_iter()
            .find(|message| message.to == "alice@acme.test")
            .expect("update email");
        assert_matches(
            &Value::Object(update.payload),
            json!({ "event": "completed", "exportReady": "true" }),
        );
    });
}

#[test]
#[ignore = "identity deletion reaches guests.ts revokeGuestInvitationsBy (guests unit), still a stub"]
fn erases_a_person_after_the_legal_hold_is_released_and_says_so_to_downstream_systems() {
    run(|| async {
        let s = scenario().await;
        ok(call!(
            s,
            decide,
            &s.alice_token,
            json!({
                "tenantId": s.tenant_id,
                "purposeKey": "marketing-email",
                "version": 1,
                "granted": true,
                "evidence": "Signed up at the conference booth",
            })
        ));
        let hold = ok(call!(
            s,
            place_hold,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "subject": { "identityId": s.alice },
                "reason": "Litigation 2026-17",
            })
        ));
        // No path deletes a held person.
        let owner = s.owner_sign_in().await;
        let error = fails(
            s.f.iam
                .api
                .identities
                .delete(
                    &owner,
                    body(json!({ "tenantId": s.tenant_id, "identityId": s.alice })),
                )
                .await,
        );
        assert_eq!(code(&error), "LEGAL_HOLD");
        let request = s
            .submit(json!({ "type": "erasure", "details": "Please delete my account." }))
            .await;
        let error = fails(call!(
            s,
            fulfil_request,
            &owner,
            json!({ "tenantId": s.tenant_id, "requestId": request["id"] })
        ));
        assert_eq!(code(&error), "LEGAL_HOLD");
        ok(call!(
            s,
            release_hold,
            &owner,
            json!({ "tenantId": s.tenant_id, "holdId": hold["id"] })
        ));
        let done = s.fulfil(&owner, &request["id"]).await;
        assert_eq!(done["status"], "completed");
        let actions = done["actions"].as_array().unwrap();
        // Deleting the account already removed the current decision; erasure redacts its history.
        for action in [
            "account-deleted",
            "account-details-erased",
            "history-redacted:1",
        ] {
            assert!(actions.contains(&json!(action)), "{action} in {actions:?}");
        }
        assert!(done.get("details").is_none());
        assert_eq!(done["redacted"], json!(true));
        let tombstone =
            s.f.store()
                .get("identities", &s.alice)
                .await
                .unwrap()
                .unwrap();
        assert_eq!(tombstone["status"], "deleted");
        assert_eq!(tombstone["name"], "Erased person");
        assert!(tombstone.get("deletedEmail").is_none());
        let history = ok(call!(
            s,
            history,
            &owner,
            json!({ "tenantId": s.tenant_id, "subject": { "identityId": s.alice } })
        ));
        assert_eq!(history.as_array().unwrap().len(), 1);
        assert_eq!(history[0]["redacted"], json!(true));
        assert!(history[0].get("evidence").is_none());
        let events = s.audit_events(&owner).await;
        assert!(Value::Array(events).to_string().contains("privacy:erasure"));
        // The person heard back at their old address before it was erased.
        s.dispatch().await;
        assert!(s.sent("privacy-request-update").iter().any(|message| {
            message.to == "alice@acme.test"
                && message.payload.get("type") == Some(&json!("erasure"))
        }));
    });
}

#[test]
fn restricts_processing_withdraws_on_objection_and_extends_by_the_regulation() {
    run(|| async {
        let s = scenario().await;
        s.decide("marketing-email", 1, true).await;
        let restriction = s.submit(json!({ "type": "restriction" })).await;
        s.fulfil(&s.owner, &restriction["id"]).await;
        let alice = json!({ "identityId": s.alice });
        assert_matches(
            &s.check(&s.owner, alice.clone(), "marketing-email").await,
            json!({ "allowed": false, "reason": "RESTRICTED" }),
        );
        assert_matches(
            &s.check(&s.owner, alice.clone(), "billing").await,
            json!({ "allowed": false, "reason": "RESTRICTED" }),
        );
        ok(call!(
            s,
            lift_restriction,
            &s.owner,
            json!({ "tenantId": s.tenant_id, "subject": alice })
        ));
        assert_eq!(
            s.check(&s.owner, alice.clone(), "marketing-email").await["allowed"],
            json!(true)
        );

        let objection = s
            .submit(json!({ "type": "objection", "regulation": "lgpd" }))
            .await;
        // LGPD allows no extension; GDPR adds two months once.
        let error = fails(call!(
            s,
            extend_request,
            &s.owner,
            json!({ "tenantId": s.tenant_id, "requestId": objection["id"], "reason": "Complex" })
        ));
        assert_eq!(code(&error), "CONFLICT");
        let done = s.fulfil(&s.owner, &objection["id"]).await;
        assert_eq!(done["actions"], json!(["consents-withdrawn:3"]));
        assert_matches(
            &s.check(&s.owner, alice.clone(), "marketing-email").await,
            json!({ "reason": "CONSENT_WITHDRAWN" }),
        );
        assert_matches(
            &s.check(&s.owner, alice.clone(), "product-analytics").await,
            json!({ "reason": "OBJECTED" }),
        );
        assert_matches(
            &s.check(&s.owner, alice.clone(), "billing").await,
            json!({ "allowed": true }),
        );

        let access = s.submit(json!({ "type": "portability" })).await;
        let extended = ok(call!(
            s,
            extend_request,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "requestId": access["id"],
                "reason": "Data spread over several systems",
            })
        ));
        assert_eq!(
            extended["dueAt"].as_f64().unwrap() - access["dueAt"].as_f64().unwrap(),
            60.0 * DAY
        );
        let error = fails(call!(
            s,
            extend_request,
            &s.owner,
            json!({ "tenantId": s.tenant_id, "requestId": access["id"], "reason": "Again" })
        ));
        assert_eq!(code(&error), "CONFLICT");
        // Rectification needs a note saying what changed.
        let fix = s
            .submit(json!({ "type": "rectification", "details": "My name is spelled wrong." }))
            .await;
        ok(call!(
            s,
            add_note,
            &s.owner,
            json!({ "tenantId": s.tenant_id, "requestId": fix["id"], "note": "internal" })
        ));
        let error = fails(call!(
            s,
            fulfil_request,
            &s.owner,
            json!({ "tenantId": s.tenant_id, "requestId": fix["id"] })
        ));
        assert_eq!(code(&error), "INVALID_INPUT");
        let mine = ok(call!(
            s,
            mine,
            &s.alice_token,
            json!({ "tenantId": s.tenant_id })
        ));
        let view = mine["requests"]
            .as_array()
            .unwrap()
            .iter()
            .find(|request| request["id"] == fix["id"])
            .unwrap();
        assert!(
            !view["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["what"] == "note")
        );
    });
}

#[test]
fn takes_public_requests_only_when_enabled_confirmed_by_email_and_lapses_unconfirmed_ones() {
    run(|| async {
        let s = scenario().await;
        let error = fails(
            s.f.iam
                .api
                .privacy
                .submit_public(body(json!({
                    "tenantId": s.tenant_id,
                    "type": "access",
                    "email": "alice@acme.test",
                })))
                .await,
        );
        assert_eq!(code(&error), "NOT_FOUND");
        ok(call!(
            s,
            update_settings,
            &s.owner,
            json!({ "tenantId": s.tenant_id, "publicIntake": true, "contactEmail": "dpo@acme.test" })
        ));
        // Alice's address is verified, so a confirmed public request links to her account.
        let mut alice =
            s.f.store()
                .get("identities", &s.alice)
                .await
                .unwrap()
                .unwrap();
        alice.insert("emailVerified".into(), json!(true));
        s.f.put("identities", alice).await;
        let submitted = ok(s
            .f
            .iam
            .api
            .privacy
            .submit_public(body(json!({
                "tenantId": s.tenant_id,
                "type": "access",
                "email": "Alice@Acme.test",
                "name": "Alice",
            })))
            .await);
        assert_eq!(submitted["status"], "pending-verification");
        s.dispatch().await;
        let verify = s
            .sent("privacy-request-verify")
            .into_iter()
            .next()
            .expect("verification email");
        assert_eq!(verify.to, "alice@acme.test");
        let request_id = verify.payload["requestId"].clone();
        let token = verify.payload["token"].clone();
        let confirm = |token: Value| {
            let input = json!({ "tenantId": s.tenant_id, "requestId": request_id, "token": token });
            async { s.f.iam.api.privacy.confirm_public(body(input)).await }
        };
        assert_eq!(
            code(&fails(confirm(json!("wrong")).await)),
            "CONFIRMATION_INVALID"
        );
        let confirmed = ok(confirm(token.clone()).await);
        assert_eq!(confirmed["status"], "open");
        let listed = ok(call!(
            s,
            get_request,
            &s.owner,
            json!({ "tenantId": s.tenant_id, "requestId": request_id })
        ));
        assert_matches(
            &listed,
            json!({
                "identityId": s.alice,
                "subject": format!("identity:{}", s.alice),
                "channel": "public",
                "verification": { "status": "verified", "method": "email-link" },
            }),
        );
        // The token is single-use.
        assert_eq!(code(&fails(confirm(token).await)), "CONFIRMATION_INVALID");

        // An unconfirmed request lapses after seven days.
        ok(s.f
            .iam
            .api
            .privacy
            .submit_public(body(json!({
                "tenantId": s.tenant_id,
                "type": "opt-out",
                "email": "stranger@example.test",
            })))
            .await);
        s.f.advance(8.0 * DAY);
        let run =
            s.f.iam
                .privacy
                .send_deadline_reminders(Some(&json!({ "tenantId": s.tenant_id })))
                .await
                .unwrap();
        assert_eq!(run["lapsed"], json!(1));
        let owner = s.owner_sign_in().await;
        let cancelled = ok(call!(
            s,
            list_requests,
            &owner,
            json!({ "tenantId": s.tenant_id, "status": "cancelled" })
        ));
        assert_eq!(cancelled["total"], json!(1));
    });
}

#[test]
fn reminds_handlers_once_before_the_deadline_and_once_when_overdue() {
    run(|| async {
        let s = scenario().await;
        ok(call!(
            s,
            update_settings,
            &s.owner,
            json!({ "tenantId": s.tenant_id, "contactEmail": "dpo@acme.test" })
        ));
        let request = s.submit(json!({ "type": "access" })).await;
        let job = || async {
            s.f.iam
                .privacy
                .send_deadline_reminders(Some(&json!({ "tenantId": s.tenant_id })))
                .await
                .unwrap()
        };
        assert_eq!(job().await["reminded"], json!([]));
        s.f.advance(24.0 * DAY);
        assert_eq!(
            job().await["reminded"],
            json!([{ "tenantId": s.tenant_id, "requestId": request["id"], "kind": "due-soon" }])
        );
        assert_eq!(job().await["reminded"], json!([]));
        s.f.advance(7.0 * DAY);
        assert_eq!(
            job().await["reminded"],
            json!([{ "tenantId": s.tenant_id, "requestId": request["id"], "kind": "overdue" }])
        );
        let owner = s.owner_sign_in().await;
        let overdue = ok(call!(
            s,
            list_requests,
            &owner,
            json!({ "tenantId": s.tenant_id, "overdue": true })
        ));
        let ids: Vec<&Value> = overdue["requests"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| &item["id"])
            .collect();
        assert_eq!(ids, vec![&request["id"]]);
        let summary = ok(call!(
            s,
            summary,
            &owner,
            json!({ "tenantId": s.tenant_id })
        ));
        assert_matches(&summary["requests"], json!({ "open": 1, "overdue": 1 }));
        s.dispatch().await;
        let flags: Vec<Value> = s
            .sent("privacy-request-due")
            .iter()
            .map(|message| message.payload["overdue"].clone())
            .collect();
        assert_eq!(flags, vec![json!("false"), json!("true")]);
    });
}

// ── privacy review fixes ─────────────────────────────────────────────────────────────────────────────────────────

/// Bob handles privacy requests but may not read the directory or the audit log.
async fn handler(s: &Scenario) -> (String, CredentialInput) {
    let bob = s.f.member("bob").await;
    let role = s
        .role(
            "Privacy handler",
            json!(["iam:privacy:read", "iam:privacy:handle"]),
        )
        .await;
    s.bind(&role, &bob).await;
    let token = s.f.sign_in(&bob).await;
    (bob, token)
}

#[test]
fn keeps_public_requests_naming_an_application_identifier_unverified_after_the_email_is_confirmed()
{
    run(|| async {
        let s = scenario().await;
        ok(call!(
            s,
            update_settings,
            &s.owner,
            json!({ "tenantId": s.tenant_id, "publicIntake": true })
        ));
        ok(s.f
            .iam
            .api
            .privacy
            .submit_public(body(json!({
                "tenantId": s.tenant_id,
                "type": "erasure",
                "email": "attacker@example.test",
                "externalId": "cus_42",
            })))
            .await);
        s.dispatch().await;
        let verify = s
            .sent("privacy-request-verify")
            .into_iter()
            .next()
            .expect("verification email");
        let confirmed = ok(s
            .f
            .iam
            .api
            .privacy
            .confirm_public(body(json!({
                "tenantId": s.tenant_id,
                "requestId": verify.payload["requestId"],
                "token": verify.payload["token"],
            })))
            .await);
        assert_eq!(confirmed["status"], "pending-verification");
        let error = fails(call!(
            s,
            fulfil_request,
            &s.owner,
            json!({ "tenantId": s.tenant_id, "requestId": verify.payload["requestId"] })
        ));
        assert_eq!(code(&error), "INVALID_TRANSITION");
        // A confirmed address does not lapse as unconfirmed.
        s.f.advance(8.0 * DAY);
        let run =
            s.f.iam
                .privacy
                .send_deadline_reminders(Some(&json!({ "tenantId": s.tenant_id })))
                .await
                .unwrap();
        assert_eq!(run["lapsed"], json!(0));
    });
}

#[test]
fn keeps_an_erased_application_subject_suppressed_instead_of_opted_back_in() {
    run(|| async {
        let s = scenario().await;
        ok(call!(
            s,
            record,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "subject": { "externalId": "cus_7" },
                "purposeKey": "data-sharing",
                "granted": false,
            })
        ));
        let request = ok(call!(
            s,
            create_request,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "type": "erasure",
                "subject": { "externalId": "cus_7" },
                "verified": { "method": "Signed-in customer portal" },
            })
        ));
        s.fulfil(&s.owner, &request["id"]).await;
        assert_matches(
            &s.check(&s.owner, json!({ "externalId": "cus_7" }), "data-sharing")
                .await,
            json!({ "allowed": false, "reason": "ERASED" }),
        );
    });
}

#[test]
fn asks_handlers_for_directory_rights_to_export_download_or_list_people_and_audits_refusals() {
    run(|| async {
        let s = scenario().await;
        let (_, token) = handler(&s).await;
        let request = s.submit(json!({ "type": "access" })).await;
        // Bob may handle requests but not read Alice's account.
        let error = fails(call!(
            s,
            fulfil_request,
            &token,
            json!({ "tenantId": s.tenant_id, "requestId": request["id"] })
        ));
        assert_eq!(code(&error), "ACCESS_DENIED");
        s.fulfil(&s.owner, &request["id"]).await;
        let error = fails(call!(
            s,
            download_export,
            &token,
            json!({ "tenantId": s.tenant_id, "requestId": request["id"] })
        ));
        assert_eq!(code(&error), "ACCESS_DENIED");
        let events = s.audit_events(&s.owner).await;
        assert!(events.iter().any(|event| {
            event["action"] == "iam:identities:read" && event["outcome"] == "deny"
        }));
        // Audiences list people by ID only without directory rights.
        let audience = ok(call!(
            s,
            audience,
            &token,
            json!({ "tenantId": s.tenant_id, "purposeKey": "data-sharing" })
        ));
        let subjects = audience["subjects"].as_array().unwrap();
        assert!(!subjects.is_empty());
        assert!(
            subjects
                .iter()
                .all(|subject| subject.get("email").is_none())
        );
    });
}

#[test]
fn leaves_audit_activity_out_of_exports_made_without_audit_rights() {
    run(|| async {
        let s = scenario().await;
        let (bob, token) = handler(&s).await;
        // Bob may also read people, but still not the audit log.
        let reader = s
            .role("Directory reader", json!(["iam:identities:read"]))
            .await;
        s.bind(&reader, &bob).await;
        let request = s.submit(json!({ "type": "access" })).await;
        s.fulfil(&token, &request["id"]).await;
        let download = ok(call!(
            s,
            download_export,
            &s.alice_token,
            json!({ "tenantId": s.tenant_id, "requestId": request["id"] })
        ));
        assert!(download["data"].get("activity").is_none());
        assert_eq!(download["data"]["activityOmitted"], json!(true));
    });
}

#[test]
#[ignore = "identity deletion reaches guests.ts revokeGuestInvitationsBy (guests unit), still a stub"]
fn needs_a_linked_subject_for_requests_that_arrived_by_email_and_records_identity_delete_on_erasure()
 {
    run(|| async {
        let s = scenario().await;
        let request = ok(call!(
            s,
            create_request,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "type": "erasure",
                "requesterEmail": "alice.personal@example.test",
            })
        ));
        ok(call!(
            s,
            verify_request,
            &s.owner,
            json!({ "tenantId": s.tenant_id, "requestId": request["id"], "method": "Video call" })
        ));
        let error = fails(call!(
            s,
            fulfil_request,
            &s.owner,
            json!({ "tenantId": s.tenant_id, "requestId": request["id"] })
        ));
        assert_eq!(code(&error), "INVALID_INPUT");
        let linked = ok(call!(
            s,
            link_request,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "requestId": request["id"],
                "subject": { "identityId": s.alice },
                "note": "Same person, second address",
            })
        ));
        assert_matches(
            &linked,
            json!({ "identityId": s.alice, "subject": format!("identity:{}", s.alice) }),
        );
        s.fulfil(&s.owner, &request["id"]).await;
        let events = s.audit_events(&s.owner).await;
        let deletion = events
            .iter()
            .find(|event| {
                event["action"] == "identity:delete" && event["resourceId"] == s.alice.as_str()
            })
            .expect("identity:delete event");
        assert_eq!(
            deletion["metadata"],
            json!({ "kind": "user", "erasure": true })
        );
        // Another email-only request can be declined as holding no data.
        let other = ok(call!(
            s,
            create_request,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "type": "access",
                "requesterEmail": "stranger@example.test",
            })
        ));
        let rejected = ok(call!(
            s,
            reject_request,
            &s.owner,
            json!({ "tenantId": s.tenant_id, "requestId": other["id"], "reason": "no-data" })
        ));
        assert_eq!(rejected["status"], "rejected");
    });
}

#[test]
fn requires_versions_on_imports_and_a_new_version_for_a_mode_change() {
    run(|| async {
        let s = scenario().await;
        let error = fails(call!(
            s,
            record,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "subject": { "externalId": "cus_1" },
                "purposeKey": "marketing-email",
                "granted": true,
                "source": "import",
                "recordedAt": s.f.now() - DAY,
            })
        ));
        assert_eq!(code(&error), "INVALID_INPUT");
        let error = fails(call!(
            s,
            update_purpose,
            &s.owner,
            json!({ "tenantId": s.tenant_id, "purposeId": s.marketing["id"], "mode": "opt-out" })
        ));
        assert_eq!(code(&error), "INVALID_INPUT");
        let changed = ok(call!(
            s,
            update_purpose,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "purposeId": s.marketing["id"],
                "mode": "opt-out",
                "newVersion": true,
            })
        ));
        assert_matches(&changed, json!({ "mode": "opt-out", "version": 2 }));
    });
}

// ── legal holds and organizations ────────────────────────────────────────────────────────────────────────────────

#[test]
fn refuses_to_delete_an_organization_while_someone_in_it_is_under_a_legal_hold() {
    run(|| async {
        let s = scenario().await;
        let hold = ok(call!(
            s,
            place_hold,
            &s.owner,
            json!({
                "tenantId": s.tenant_id,
                "subject": { "identityId": s.alice },
                "reason": "Litigation",
            })
        ));
        let root = s.f.root_credential.clone();
        let set_deleted = || async {
            s.f.iam
                .api
                .tenants
                .set_status(
                    &root,
                    body(json!({ "tenantId": s.tenant_id, "status": "deleted" })),
                )
                .await
        };
        assert_eq!(code(&fails(set_deleted().await)), "LEGAL_HOLD");
        ok(call!(
            s,
            release_hold,
            &s.owner,
            json!({ "tenantId": s.tenant_id, "holdId": hold["id"] })
        ));
        assert_eq!(ok(set_deleted().await)["status"], "deleted");
    });
}

// ── input validation without the privacy records ─────────────────────────────────────────────────────────────────

#[test]
fn validates_self_service_input_before_authenticating() {
    run(|| async {
        let s = scenario().await;
        let nobody = CredentialInput::default();
        // `granted` and `version` are checked before the credential, as TypeScript does.
        let error = fails(call!(
            s,
            decide,
            &nobody,
            json!({ "tenantId": s.tenant_id, "purposeKey": "billing", "version": 1 })
        ));
        assert_eq!(error.message, "granted must be a boolean");
        let error = fails(call!(
            s,
            decide,
            &nobody,
            json!({ "tenantId": s.tenant_id, "purposeKey": "billing", "version": 0, "granted": true })
        ));
        assert_eq!(code(&error), "INVALID_INPUT");
        let error = fails(call!(
            s,
            submit_request,
            &nobody,
            json!({ "tenantId": s.tenant_id, "type": "nonsense" })
        ));
        assert_eq!(code(&error), "INVALID_INPUT");
        // Administrators acting for someone cannot use the self-service routes of another tenant.
        let error = fails(call!(
            s,
            mine,
            &s.f.root_credential,
            json!({ "tenantId": s.tenant_id })
        ));
        assert_eq!(code(&error), "ACCESS_DENIED");
    });
}
