//! Port of tests/sod.test.ts: separation-of-duties rules prevent conflicting grants on every granting path and
//! report conflicts that predate them.
//!
//! The TypeScript test also walks access packages (`packages.assign`) and the access analysis
//! (`analysis.findings`), group membership (`assertNotTeamGroup`, teams.ts) and invitation acceptance
//! (`acceptMemberInvitation`, flows.ts); those belong to other units and are still stubs, so their parts are split into
//! their own `#[ignore]`d tests, with the reason, until they land.

mod organization_fixture;

use std::sync::{Arc, Mutex};

use better_iam_auth::DeliveryMessage;
use better_iam_core::{CredentialInput, Filter};
use organization_fixture::{Org, assert_matches, body, code, fails, ok, organization, run};
use serde_json::{Value, json};

struct Scenario {
    f: Org,
    inbox: Arc<Mutex<Vec<DeliveryMessage>>>,
    owner: CredentialInput,
    tenant_id: String,
    requester: String,
    approver: String,
    auditor: String,
    alice: String,
    bob: String,
    carol: String,
}

impl Scenario {
    async fn role(&self, name: &str) -> String {
        let role = ok(self
            .f
            .iam
            .api
            .roles
            .create(
                &self.owner,
                body(json!({
                    "tenantId": self.tenant_id,
                    "name": name,
                    "permissions": ["documents:read"],
                })),
            )
            .await);
        role["id"].as_str().unwrap().to_owned()
    }

    async fn bind_as(
        &self,
        role_id: &str,
        subject_id: &str,
        subject_type: &str,
    ) -> better_iam_core::IamResult<Value> {
        self.f
            .iam
            .api
            .bindings
            .create(
                &self.owner,
                body(json!({
                    "tenantId": self.tenant_id,
                    "roleId": role_id,
                    "subjectType": subject_type,
                    "subjectId": subject_id,
                })),
            )
            .await
            .map(|reply| reply.into_value().unwrap())
    }

    async fn bind(&self, role_id: &str, subject_id: &str) -> better_iam_core::IamResult<Value> {
        self.bind_as(role_id, subject_id, "identity").await
    }

    async fn sod_create(&self, input: Value) -> better_iam_core::IamResult<Value> {
        let mut input = input.as_object().unwrap().clone();
        input.insert("tenantId".into(), json!(self.tenant_id));
        self.f
            .iam
            .api
            .sod
            .create(&self.owner, body(Value::Object(input)))
            .await
            .map(|reply| reply.into_value().unwrap())
    }

    async fn violations(&self) -> Vec<Value> {
        ok(self
            .f
            .iam
            .api
            .sod
            .violations(&self.owner, body(json!({ "tenantId": self.tenant_id })))
            .await)
        .as_array()
        .unwrap()
        .clone()
    }
}

/// The roles and people of the test, with Carol's conflict predating the rule and the `Payments` rule in place.
async fn scenario() -> (Scenario, String) {
    let inbox: Arc<Mutex<Vec<DeliveryMessage>>> = Arc::default();
    let sink = inbox.clone();
    let f = organization(move |options| {
        if let Some(authentication) = options.authentication.as_mut() {
            authentication.send_email = Some(better_iam_auth::delivery_fn(move |message| {
                let sink = sink.clone();
                async move {
                    sink.lock().unwrap().push(message);
                    Ok(())
                }
            }));
        }
    })
    .await;
    let owner = f.owner_credential.clone();
    let tenant_id = f.tenant_id.clone();
    let mut s = Scenario {
        f,
        inbox,
        owner,
        tenant_id,
        requester: String::new(),
        approver: String::new(),
        auditor: String::new(),
        alice: String::new(),
        bob: String::new(),
        carol: String::new(),
    };
    s.requester = s.role("Payment requester").await;
    s.approver = s.role("Payment approver").await;
    s.auditor = s.role("Auditor").await;
    s.alice = s.f.member("alice").await;
    s.bob = s.f.member("bob").await;
    s.carol = s.f.member("carol").await;
    s.bind(&s.requester, &s.alice).await.unwrap();
    // Carol's conflict predates the rule.
    s.bind(&s.requester, &s.carol).await.unwrap();
    s.bind(&s.approver, &s.carol).await.unwrap();

    for input in [
        json!({ "name": "One role", "roleIds": [s.requester] }),
        json!({ "name": "Unknown", "roleIds": [s.requester, "missing"] }),
        json!({ "name": "Bad mode", "roleIds": [s.requester, s.approver], "mode": "maybe" }),
    ] {
        let error = s.sod_create(input).await.unwrap_err();
        assert!(error.status >= 400);
    }
    let owner_role =
        s.f.find("roles", Filter::new().eq("tenantId", s.tenant_id.as_str()))
            .await
            .into_iter()
            .find(|role| role["protected"] == json!(true))
            .unwrap();
    let error = s
        .sod_create(json!({ "name": "Owners", "roleIds": [owner_role["id"], s.auditor] }))
        .await
        .unwrap_err();
    assert_eq!(code(&error), "INVALID_INPUT");

    let rule = s
        .sod_create(json!({ "name": "Payments", "roleIds": [s.requester, s.approver] }))
        .await
        .unwrap();
    assert_matches(&rule, json!({ "mode": "prevent", "existingViolations": 1 }));
    let rule_id = rule["id"].as_str().unwrap().to_owned();
    (s, rule_id)
}

#[test]
fn prevents_conflicting_grants_on_every_granting_path_and_reports_existing_conflicts() {
    run(|| async {
        let (s, rule_id) = scenario().await;
        let api = &s.f.iam.api;
        let tenant_id = s.tenant_id.as_str();

        // Direct binding.
        let error = s.bind(&s.approver, &s.alice).await.unwrap_err();
        assert_eq!(code(&error), "SOD_CONFLICT");
        assert_eq!(error.status, 409);
        assert_eq!(
            error.message,
            "Separation of duties (Payments): one person cannot hold Payment requester and Payment approver"
        );
        assert_eq!(
            s.f.find(
                "bindings",
                Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("subjectId", s.alice.as_str())
            )
            .await
            .len(),
            1
        );
        // A future-dated grant counts too: the conflict would begin when it starts.
        let error = fails(
            api.bindings
                .create(
                    &s.owner,
                    body(json!({
                        "tenantId": tenant_id,
                        "roleId": s.approver,
                        "subjectType": "identity",
                        "subjectId": s.alice,
                        "startsAt": s.f.now() + 86_400_000.0,
                    })),
                )
                .await,
        );
        assert_eq!(code(&error), "SOD_CONFLICT");
        // Bulk onboarding with both roles at once.
        let error = fails(
            api.identities
                .create_many(
                    &s.owner,
                    body(json!({
                        "tenantId": tenant_id,
                        "identities": [{
                            "email": "dave@acme.test",
                            "name": "Dave",
                            "roleIds": [s.requester, s.approver],
                        }],
                    })),
                )
                .await,
        );
        assert_eq!(code(&error), "SOD_CONFLICT");
        assert!(
            s.f.find("identities", Filter::new().eq("email", "dave@acme.test"))
                .await
                .is_empty()
        );

        // The pre-existing conflict never blocks unrelated grants, and it is reported.
        s.bind(&s.auditor, &s.carol).await.unwrap();
        let violations = s.violations().await;
        assert_eq!(violations.len(), 1);
        assert_matches(
            &violations[0],
            json!({
                "ruleName": "Payments",
                "identityId": s.carol,
                "identityName": "carol@acme.test",
                "roleNames": ["Payment requester", "Payment approver"],
            }),
        );

        // Detect mode reports without blocking; switching modes and deleting take effect immediately.
        let updated = ok(api
            .sod
            .update(
                &s.owner,
                body(json!({ "tenantId": tenant_id, "ruleId": rule_id, "mode": "detect" })),
            )
            .await);
        assert_eq!(updated["mode"], "detect");
        s.bind(&s.approver, &s.alice).await.unwrap();
        let mut flagged: Vec<String> = s
            .violations()
            .await
            .iter()
            .map(|violation| violation["identityId"].as_str().unwrap().to_owned())
            .collect();
        flagged.sort();
        let mut expected = vec![s.alice.clone(), s.carol.clone()];
        expected.sort();
        assert_eq!(flagged, expected);
        let listed = ok(api
            .sod
            .list(&s.owner, body(json!({ "tenantId": tenant_id })))
            .await);
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert_eq!(
            ok(api
                .sod
                .delete(
                    &s.owner,
                    body(json!({ "tenantId": tenant_id, "ruleId": rule_id })),
                )
                .await),
            json!({ "deleted": true })
        );
        assert!(s.violations().await.is_empty());
        assert_eq!(
            ok(api
                .sod
                .list(&s.owner, body(json!({ "tenantId": tenant_id })))
                .await),
            json!([])
        );
    });
}

#[test]
#[ignore = "needs packages.create and packages.assign (api/packages.ts, another unit)"]
fn access_packages_cannot_create_a_conflict() {
    run(|| async {
        let (s, _) = scenario().await;
        let api = &s.f.iam.api;
        let tenant_id = s.tenant_id.as_str();
        // Access packages materialize bindings too.
        let kit = ok(api
            .packages
            .create(
                &s.owner,
                body(json!({ "tenantId": tenant_id, "name": "Approver kit", "roleIds": [s.approver] })),
            )
            .await);
        let error = fails(
            api.packages
                .assign(
                    &s.owner,
                    body(json!({ "tenantId": tenant_id, "packageId": kit["id"], "identityId": s.alice })),
                )
                .await,
        );
        assert_eq!(code(&error), "SOD_CONFLICT");
        assert!(
            s.f.find(
                "packageAssignments",
                Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("identityId", s.alice.as_str())
            )
            .await
            .is_empty()
        );
    });
}

#[test]
#[ignore = "needs analysis.findings (api/analysis.ts, another unit)"]
fn the_access_analysis_reports_conflicts_that_predate_a_rule() {
    run(|| async {
        let (s, _) = scenario().await;
        let api = &s.f.iam.api;
        s.bind(&s.auditor, &s.carol).await.unwrap();
        let report = ok(api
            .analysis
            .findings(&s.owner, body(json!({ "tenantId": s.tenant_id })))
            .await);
        let findings: Vec<&Value> = report["findings"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|finding| finding["kind"] == "separation-of-duties")
            .collect();
        assert_eq!(findings.len(), 1);
        assert_matches(
            findings[0],
            json!({ "severity": "high", "subject": { "id": s.carol } }),
        );
    });
}

#[test]
fn requires_sod_permissions() {
    run(|| async {
        let f = organization(|_| {}).await;
        let mallory = f.member("mallory").await;
        let session = f.sign_in(&mallory).await;
        let error = fails(
            f.iam
                .api
                .sod
                .list(&session, body(json!({ "tenantId": f.tenant_id })))
                .await,
        );
        assert_eq!(error.status, 403);
    });
}

#[test]
fn validates_rules_and_names_violations_for_review() {
    run(|| async {
        let (s, rule_id) = scenario().await;
        let api = &s.f.iam.api;
        let tenant_id = s.tenant_id.as_str();
        // A rule names 2 to 20 distinct roles; duplicates collapse before the count.
        let error = s
            .sod_create(json!({ "name": "Twice", "roleIds": [s.requester, s.requester] }))
            .await
            .unwrap_err();
        assert_eq!(code(&error), "INVALID_INPUT");
        assert_eq!(error.message, "A rule names 2 to 20 conflicting roles");
        let error = s
            .sod_create(json!({ "roleIds": [s.requester, s.auditor] }))
            .await
            .unwrap_err();
        assert_eq!(error.message, "name and roleIds are required");
        let error = s
            .sod_create(
                json!({ "name": "Bad", "roleIds": [s.requester, s.auditor], "mode": "maybe" }),
            )
            .await
            .unwrap_err();
        assert_eq!(error.message, "mode must be prevent or detect");
        // Unknown rules are NOT_FOUND; a missing ruleId is refused before anything else.
        let error = fails(
            api.sod
                .update(
                    &s.owner,
                    body(json!({ "tenantId": tenant_id, "ruleId": "missing", "name": "x" })),
                )
                .await,
        );
        assert_eq!(error.status, 404);
        let error = fails(
            api.sod
                .delete(&s.owner, body(json!({ "tenantId": tenant_id })))
                .await,
        );
        assert_eq!(error.message, "Invalid ruleId");
        // A detect rule with a description, trimmed; violations filter by rule.
        s.f.advance(1000.0);
        let detect = s
            .sod_create(json!({
                "name": "  Audit  ",
                "description": " Auditors never approve ",
                "roleIds": [s.auditor, s.approver],
                "mode": "detect",
            }))
            .await
            .unwrap();
        assert_matches(
            &detect,
            json!({
                "name": "Audit",
                "description": "Auditors never approve",
                "mode": "detect",
                "existingViolations": 0,
                "createdBy": s.f.owner_id,
            }),
        );
        let only = ok(api
            .sod
            .violations(
                &s.owner,
                body(json!({ "tenantId": tenant_id, "ruleId": rule_id })),
            )
            .await);
        assert_eq!(only.as_array().unwrap().len(), 1);
        assert_eq!(only[0]["ruleId"], rule_id.as_str());
        assert_eq!(only[0]["mode"], "prevent");
        assert_eq!(only[0]["roleIds"], json!([s.requester, s.approver]));
        // Newest first.
        let listed = ok(api
            .sod
            .list(&s.owner, body(json!({ "tenantId": tenant_id })))
            .await);
        let names: Vec<&str> = listed
            .as_array()
            .unwrap()
            .iter()
            .map(|rule| rule["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["Audit", "Payments"]);
        // Role inheritance counts: a role inheriting the approver holds it.
        let senior = s.role("Senior approver").await;
        ok(api
            .roles
            .update(
                &s.owner,
                body(json!({ "tenantId": tenant_id, "roleId": senior, "inherits": [s.approver] })),
            )
            .await);
        let error = s.bind(&senior, &s.alice).await.unwrap_err();
        assert_eq!(code(&error), "SOD_CONFLICT");
    });
}

#[test]
#[ignore = "needs assertNotTeamGroup (teams.ts) and acceptMemberInvitation (flows.ts), other units"]
fn group_membership_bulk_onboarding_and_invitations_through_a_group_cannot_create_a_conflict() {
    run(|| async {
        let (s, _) = scenario().await;
        let api = &s.f.iam.api;
        let tenant_id = s.tenant_id.as_str();
        // Group membership that would confer the conflicting role.
        let approvers = ok(api
            .groups
            .create(
                &s.owner,
                body(json!({ "tenantId": tenant_id, "name": "Approvers" })),
            )
            .await);
        let approvers_id = approvers["id"].as_str().unwrap().to_owned();
        s.bind_as(&s.approver, &approvers_id, "group")
            .await
            .unwrap();
        let error = fails(
            api.groups
                .add_member(
                    &s.owner,
                    body(json!({ "tenantId": tenant_id, "groupId": approvers_id, "identityId": s.alice })),
                )
                .await,
        );
        assert_eq!(code(&error), "SOD_CONFLICT");
        ok(api
            .groups
            .add_member(
                &s.owner,
                body(
                    json!({ "tenantId": tenant_id, "groupId": approvers_id, "identityId": s.bob }),
                ),
            )
            .await);
        // Bulk onboarding.
        let error = fails(
            api.identities
                .create_many(
                    &s.owner,
                    body(json!({
                        "tenantId": tenant_id,
                        "identities": [{
                            "email": "dave@acme.test",
                            "name": "Dave",
                            "roleIds": [s.requester],
                            "groupIds": [approvers_id],
                        }],
                    })),
                )
                .await,
        );
        assert_eq!(code(&error), "SOD_CONFLICT");
        assert!(
            s.f.find("identities", Filter::new().eq("email", "dave@acme.test"))
                .await
                .is_empty()
        );
        // Invitation acceptance runs outside the operation envelope and is checked too.
        ok(api
            .identities
            .invite(
                &s.owner,
                body(json!({
                    "tenantId": tenant_id,
                    "email": "erin@acme.test",
                    "roleIds": [s.requester],
                    "groupIds": [approvers_id],
                })),
            )
            .await);
        s.f.iam.auth.dispatch_outbox(None).await.unwrap();
        let token = s
            .inbox
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|message| message.template == "member-invitation")
            .map(|message| message.payload["token"].clone())
            .expect("invitation");
        let error = fails(
            api.identities
                .accept_invitation(body(json!({
                    "tenantId": tenant_id,
                    "token": token,
                    "name": "Erin",
                    "password": "a strong erin password",
                })))
                .await,
        );
        assert_eq!(code(&error), "SOD_CONFLICT");
    });
}

#[test]
#[ignore = "needs acceptMemberInvitation (flows.ts, another unit)"]
fn invitation_acceptance_cannot_create_a_conflict() {
    run(|| async {
        let (s, _) = scenario().await;
        let api = &s.f.iam.api;
        let tenant_id = s.tenant_id.as_str();
        // Invitation acceptance runs outside the operation envelope and is checked too.
        ok(api
            .identities
            .invite(
                &s.owner,
                body(json!({
                    "tenantId": tenant_id,
                    "email": "erin@acme.test",
                    "roleIds": [s.requester, s.approver],
                })),
            )
            .await);
        s.f.iam.auth.dispatch_outbox(None).await.unwrap();
        let token = s
            .inbox
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|message| message.template == "member-invitation")
            .map(|message| message.payload["token"].clone())
            .expect("invitation");
        let error = fails(
            api.identities
                .accept_invitation(body(json!({
                    "tenantId": tenant_id,
                    "token": token,
                    "name": "Erin",
                    "password": "a strong erin password",
                })))
                .await,
        );
        assert_eq!(code(&error), "SOD_CONFLICT");
    });
}
