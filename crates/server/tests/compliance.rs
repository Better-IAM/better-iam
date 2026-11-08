//! Port of tests/compliance.test.ts: the compliance center adopts frameworks, evaluates controls, takes exceptions
//! that a second person approves, counts every path to full administration, ignores reviews nobody decided, exports
//! signed evidence, verifies the audit chain from a checkpoint, and runs from the scheduler job.

mod organization_fixture;

use better_iam_core::{CredentialInput, Filter};
use better_iam_server::api::compliance::verify_evidence_pack;
use organization_fixture::{Org, assert_matches, body, code, fails, ok, organization, run};
use serde_json::{Value, json};

const DAY: f64 = 86_400_000.0;
const MINUTE: f64 = 60_000.0;

struct Scenario {
    f: Org,
    tenant_id: String,
    owner: CredentialInput,
}

async fn scenario() -> Scenario {
    let f = organization(|_| {}).await;
    Scenario {
        tenant_id: f.tenant_id.clone(),
        owner: f.owner_credential.clone(),
        f,
    }
}

impl Scenario {
    fn input(&self, extra: Value) -> Value {
        let mut input = json!({ "tenantId": self.tenant_id });
        if let (Some(target), Value::Object(extra)) = (input.as_object_mut(), extra) {
            target.extend(extra);
        }
        input
    }

    async fn owner_sign_in(&self) -> CredentialInput {
        self.f.session(&self.f.owner_id, false).await
    }

    async fn root_sign_in(&self) -> CredentialInput {
        self.f.session(&self.f.root_id, true).await
    }

    async fn adopt(&self, credential: &CredentialInput, framework: &str) -> Value {
        ok(self
            .f
            .iam
            .api
            .compliance
            .adopt_framework(
                credential,
                body(self.input(json!({ "framework": framework }))),
            )
            .await)
    }

    async fn create_control(&self, credential: &CredentialInput, input: Value) -> Value {
        ok(self
            .f
            .iam
            .api
            .compliance
            .create_control(credential, body(self.input(input)))
            .await)
    }

    async fn evaluate(&self, credential: &CredentialInput, input: Value) -> Value {
        ok(self
            .f
            .iam
            .api
            .compliance
            .evaluate(credential, body(self.input(input)))
            .await)
    }

    async fn list_results(&self, credential: &CredentialInput, control_key: &str) -> Vec<Value> {
        ok(self
            .f
            .iam
            .api
            .compliance
            .list_results(
                credential,
                body(self.input(json!({ "controlKey": control_key }))),
            )
            .await)
        .as_array()
        .cloned()
        .unwrap()
    }

    async fn status(&self, credential: &CredentialInput, framework: &str) -> Value {
        ok(self
            .f
            .iam
            .api
            .compliance
            .status(
                credential,
                body(self.input(json!({ "framework": framework }))),
            )
            .await)[0]
            .clone()
    }

    async fn audit_text(&self, credential: &CredentialInput) -> String {
        ok(self
            .f
            .iam
            .api
            .audit
            .list(credential, body(self.input(json!({}))))
            .await)
        .to_string()
    }

    async fn role(&self, input: Value) -> String {
        ok(self
            .f
            .iam
            .api
            .roles
            .create(&self.owner, body(self.input(input)))
            .await)["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    async fn bind(&self, input: Value) {
        ok(self
            .f
            .iam
            .api
            .bindings
            .create(&self.owner, body(self.input(input)))
            .await);
    }
}

fn requirement<'a>(status: &'a Value, id: &str) -> &'a Value {
    status["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == id)
        .unwrap()
}

fn by_key<'a>(results: &'a Value, key: &str) -> &'a Value {
    results["results"]
        .as_array()
        .unwrap()
        .iter()
        .find(|result| result["controlKey"] == key)
        .unwrap()
}

#[test]
fn adopts_a_framework_evaluates_its_controls_and_reports_requirement_status() {
    run(|| async {
        let s = scenario().await;
        let adopted = s.adopt(&s.owner, "soc2").await;
        assert!(
            adopted["controls"]
                .as_array()
                .unwrap()
                .iter()
                .any(|control| control["key"] == "mfa-coverage")
        );
        // Adopting a second framework reuses the controls and adds its mappings.
        s.adopt(&s.owner, "iso27001").await;
        let controls = ok(s
            .f
            .iam
            .api
            .compliance
            .list_controls(&s.owner, body(s.input(json!({}))))
            .await);
        let coverage = controls
            .as_array()
            .unwrap()
            .iter()
            .find(|control| control["key"] == "mfa-coverage")
            .unwrap();
        let mappings = coverage["mappings"].as_array().unwrap();
        assert!(mappings.contains(&json!("soc2:CC6.1")));
        assert!(mappings.contains(&json!("iso27001:8.5")));

        s.f.member("alice").await;
        let evaluated = s.evaluate(&s.owner, json!({})).await;
        // Nobody enrolled a second factor and the policy does not require one.
        assert_eq!(by_key(&evaluated, "mfa-coverage")["status"], "fail");
        assert_eq!(by_key(&evaluated, "mfa-enforced")["status"], "fail");
        assert_eq!(by_key(&evaluated, "audit-integrity")["status"], "pass");
        assert_eq!(by_key(&evaluated, "owner-redundancy")["status"], "warn");
        // Frameworks expect duties to be separated: no rule at all is not a pass.
        assert_eq!(by_key(&evaluated, "separation-of-duties")["status"], "warn");
        assert_eq!(by_key(&evaluated, "access-reviews")["status"], "fail");
        assert!(evaluated["run"]["counts"]["fail"].as_f64().unwrap() > 0.0);
        let digest = evaluated["run"]["digest"].as_str().unwrap();
        assert!(
            digest.len() == 64
                && digest
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
        // The evaluation returns counts; findings are read separately.
        assert!(by_key(&evaluated, "mfa-coverage").get("findings").is_none());

        let soc2 = s.status(&s.owner, "soc2").await;
        assert_eq!(soc2["framework"]["id"], "soc2");
        assert_eq!(requirement(&soc2, "CC7.2")["status"], "pass");
        assert_eq!(requirement(&soc2, "CC6.1")["status"], "fail");
        assert_eq!(
            soc2["covered"].as_u64().unwrap() as usize,
            soc2["requirements"].as_array().unwrap().len()
        );
        let error = fails(
            s.f.iam
                .api
                .compliance
                .status(&s.owner, body(s.input(json!({ "framework": "nope" }))))
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");

        // Manual evaluations are limited to one a minute per tenant.
        let error = fails(
            s.f.iam
                .api
                .compliance
                .evaluate(&s.owner, body(s.input(json!({}))))
                .await,
        );
        assert_eq!(code(&error), "RATE_LIMITED");
        s.f.advance(MINUTE + 1.0);

        // Requiring MFA fixes the policy control; the next evaluation records the recovery.
        let owner = s.owner_sign_in().await;
        ok(s.f
            .iam
            .api
            .tenants
            .set_auth_policy(
                &owner,
                body(s.input(json!({ "authPolicy": { "requireMfa": true } }))),
            )
            .await);
        // Owners without a second factor are now refused; the (MFA) root administrator carries on.
        let root = s.f.root_credential.clone();
        let second = s
            .evaluate(&root, json!({ "controlKeys": ["mfa-enforced"] }))
            .await;
        let results = second["results"].as_array().unwrap();
        assert_eq!(results.len(), 1);
        assert_matches(
            &results[0],
            json!({ "controlKey": "mfa-enforced", "status": "pass" }),
        );
        let events = s.audit_text(&root).await;
        assert!(events.contains("compliance:control:recover"));
        // A control failing on its first run is recorded too.
        assert!(events.contains("compliance:control:fail"));

        // Disabling a mapped control keeps its requirements from passing; old results turn stale after three days.
        let controls = ok(s
            .f
            .iam
            .api
            .compliance
            .list_controls(&root, body(s.input(json!({}))))
            .await);
        let audit_control = controls
            .as_array()
            .unwrap()
            .iter()
            .find(|control| control["key"] == "audit-integrity")
            .unwrap();
        ok(s.f
            .iam
            .api
            .compliance
            .update_control(
                &root,
                body(s.input(json!({ "controlId": audit_control["id"], "enabled": false }))),
            )
            .await);
        let after = s.status(&root, "soc2").await;
        assert_eq!(requirement(&after, "CC7.2")["status"], "disabled");
        s.f.advance(4.0 * DAY);
        let stale = s.status(&root, "soc2").await;
        assert_eq!(requirement(&stale, "CC6.1")["status"], "not-evaluated");
    });
}

#[test]
fn needs_a_second_person_to_approve_an_exception_which_then_covers_the_finding_until_it_expires() {
    run(|| async {
        let s = scenario().await;
        s.create_control(
            &s.owner,
            json!({
                "key": "inactive-90",
                "name": "Inactive accounts",
                "checkId": "inactive-accounts",
                "params": { "days": 30 },
                "mappings": ["internal:POL-7"],
            }),
        )
        .await;
        let alice = s.f.member("alice").await;
        s.f.advance(40.0 * DAY);
        let owner = s.owner_sign_in().await;
        let first = s.evaluate(&owner, json!({})).await;
        assert_eq!(first["results"][0]["status"], "fail");
        // The owner signed in just now; Alice never did. Stored findings carry IDs; directory readers see names.
        let results = s.list_results(&owner, "inactive-90").await;
        assert_eq!(
            results[0]["findings"],
            json!([{
                "subject": format!("identity:{alice}"),
                "detail": "Has never signed in",
                "name": "alice@acme.test",
            }])
        );
        let exception = ok(s
            .f
            .iam
            .api
            .compliance
            .create_exception(
                &owner,
                body(s.input(json!({
                    "controlKey": "inactive-90",
                    "subject": format!("identity:{alice}"),
                    "reason": "On parental leave until December",
                    "expiresAt": s.f.now() + 10.0 * DAY,
                }))),
            )
            .await);
        assert_eq!(exception["status"], "pending");
        let exception_id = exception["id"].clone();
        // Pending exceptions cover nothing, and their author cannot approve them.
        s.f.advance(MINUTE + 1.0);
        let pending = s.owner_sign_in().await;
        assert_eq!(
            s.evaluate(&pending, json!({})).await["results"][0]["status"],
            "fail"
        );
        let error = fails(
            s.f.iam
                .api
                .compliance
                .approve_exception(
                    &pending,
                    body(s.input(json!({ "exceptionId": exception_id }))),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        // The root session from the fixture's start has expired by now.
        let root = s.root_sign_in().await;
        ok(s.f
            .iam
            .api
            .compliance
            .approve_exception(&root, body(s.input(json!({ "exceptionId": exception_id }))))
            .await);
        s.f.advance(MINUTE + 1.0);
        let excepted = s.evaluate(&root, json!({})).await;
        assert_matches(
            &excepted["results"][0],
            json!({ "status": "pass", "rawStatus": "fail", "excepted": 1 }),
        );
        s.f.advance(11.0 * DAY);
        let later = s.owner_sign_in().await;
        assert_eq!(
            s.evaluate(&later, json!({})).await["results"][0]["status"],
            "fail"
        );
        // Revoking keeps the record as history.
        ok(s.f
            .iam
            .api
            .compliance
            .revoke_exception(
                &later,
                body(s.input(json!({ "exceptionId": exception_id }))),
            )
            .await);
        let exceptions = ok(s
            .f
            .iam
            .api
            .compliance
            .list_exceptions(&later, body(s.input(json!({}))))
            .await);
        assert_eq!(exceptions.as_array().unwrap().len(), 1);
        assert_matches(
            &exceptions[0],
            json!({ "id": exception_id, "status": "revoked", "active": false }),
        );
        // Nobody excepts their own finding, and audit-chain breaks are never excepted.
        let error = fails(
            s.f.iam
                .api
                .compliance
                .create_exception(
                    &later,
                    body(s.input(json!({
                        "controlKey": "inactive-90",
                        "subject": format!("identity:{}", s.f.owner_id),
                        "reason": "Me",
                        "expiresAt": s.f.now() + DAY,
                    }))),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        s.create_control(
            &later,
            json!({ "key": "audit", "name": "Audit", "checkId": "audit-integrity" }),
        )
        .await;
        let error = fails(
            s.f.iam
                .api
                .compliance
                .create_exception(
                    &later,
                    body(s.input(json!({
                        "controlKey": "audit",
                        "subject": format!("tenant:{}:audit-chain", s.tenant_id),
                        "reason": "Known",
                        "expiresAt": s.f.now() + DAY,
                    }))),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let error = fails(
            s.f.iam
                .api
                .compliance
                .create_control(
                    &later,
                    body(s.input(json!({
                        "key": "bad",
                        "name": "Bad",
                        "checkId": "inactive-accounts",
                        "params": { "days": 1 },
                    }))),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
    });
}

#[test]
fn counts_every_path_to_full_administration() {
    run(|| async {
        let s = scenario().await;
        s.create_control(
            &s.owner,
            json!({
                "key": "admins",
                "name": "Admins",
                "checkId": "privileged-access",
                "params": { "maxHolders": 1 },
            }),
        )
        .await;
        // Full access to the iam service on iam/* (not the literal `*`), behind an MFA condition, inherited by "Ops".
        let admin = s
            .role(json!({
                "name": "Admin",
                "document": {
                    "version": 1,
                    "statements": [{
                        "effect": "allow",
                        "actions": ["iam:*"],
                        "resources": ["iam/*"],
                        "conditions": { "Bool": { "principal.mfa": true } },
                    }],
                },
            }))
            .await;
        let ops = s
            .role(json!({ "name": "Ops", "permissions": ["iam:audit:read"], "inherits": [admin] }))
            .await;
        let reader = s
            .role(json!({ "name": "Reader", "permissions": ["iam:identities:read"] }))
            .await;
        let alice = s.f.member("alice").await;
        let bob = s.f.member("bob").await;
        let carol = s.f.member("carol").await;
        let dave = s.f.member("dave").await;
        s.bind(json!({ "roleId": ops, "subjectType": "identity", "subjectId": alice }))
            .await;
        s.bind(json!({
            "roleId": admin,
            "subjectType": "identity",
            "subjectId": bob,
            "eligible": true,
        }))
        .await;
        s.bind(json!({
            "roleId": admin,
            "subjectType": "identity",
            "subjectId": carol,
            "eligible": true,
            "requireApproval": true,
        }))
        .await;
        s.bind(json!({ "roleId": reader, "subjectType": "identity", "subjectId": dave }))
            .await;
        s.evaluate(&s.owner, json!({})).await;
        let results = s.list_results(&s.owner, "admins").await;
        let result = &results[0];
        let subjects: Vec<&str> = result["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|finding| finding["subject"].as_str().unwrap())
            .collect();
        // The owner, Alice (through the inherited role) and Bob (eligible without approval); not Carol or Dave.
        assert!(subjects.contains(&format!("identity:{alice}").as_str()));
        assert!(subjects.contains(&format!("identity:{bob}").as_str()));
        assert!(!subjects.contains(&format!("identity:{carol}").as_str()));
        assert!(!subjects.contains(&format!("identity:{dave}").as_str()));
        assert_matches(
            &result["metrics"],
            json!({ "holders": 3, "eligibleWithApproval": 1 }),
        );
        assert_eq!(result["status"], "fail");
    });
}

#[test]
fn does_not_count_reviews_nobody_decided() {
    run(|| async {
        let s = scenario().await;
        s.create_control(
            &s.owner,
            json!({ "key": "reviews", "name": "Reviews", "checkId": "access-reviews" }),
        )
        .await;
        let reader = s
            .role(json!({ "name": "Reader", "permissions": ["iam:identities:read"] }))
            .await;
        let alice = s.f.member("alice").await;
        s.bind(json!({ "roleId": reader, "subjectType": "identity", "subjectId": alice }))
            .await;
        let campaign = ok(s
            .f
            .iam
            .api
            .certifications
            .create(&s.owner, body(s.input(json!({ "name": "Q3" }))))
            .await);
        ok(s.f
            .iam
            .api
            .certifications
            .close(
                &s.owner,
                body(s.input(json!({ "campaignId": campaign["id"] }))),
            )
            .await);
        s.evaluate(&s.owner, json!({})).await;
        let results = s.list_results(&s.owner, "reviews").await;
        assert_matches(
            &results[0],
            json!({ "status": "fail", "metrics": { "qualifying": 0, "lastDecidedPercent": 0 } }),
        );
        assert_eq!(
            results[0]["findings"][0]["subject"],
            format!("tenant:{}:no-review", s.tenant_id)
        );
    });
}

#[test]
fn exports_signed_evidence_that_auditors_verify_offline_and_that_detects_edits() {
    run(|| async {
        let s = scenario().await;
        s.adopt(&s.owner, "nist-800-53").await;
        s.evaluate(&s.owner, json!({})).await;
        let pack = ok(s
            .f
            .iam
            .api
            .compliance
            .export_evidence(
                &s.owner,
                body(s.input(json!({ "framework": "nist-800-53" }))),
            )
            .await);
        assert_eq!(
            pack["framework"],
            json!({ "id": "nist-800-53", "name": "NIST SP 800-53 Rev. 5" })
        );
        assert!(
            pack["controls"]
                .as_array()
                .unwrap()
                .iter()
                .all(|control| control.get("result").is_some())
        );
        assert!(pack["auditHead"]["sequence"].as_f64().unwrap() > 0.0);
        let verify = |input: Value| {
            let api = s.f.iam.api.clone();
            let owner = s.owner.clone();
            let input = s.input(input);
            async move { ok(api.compliance.verify_evidence(&owner, body(input)).await) }
        };
        assert_eq!(
            verify(json!({ "pack": pack })).await,
            json!({ "valid": true })
        );
        // Large packs: the digest and signature alone.
        assert_eq!(
            verify(json!({ "digest": pack["digest"], "signature": pack["signature"] })).await,
            json!({ "valid": true })
        );
        let keys = ok(s
            .f
            .iam
            .api
            .compliance
            .evidence_keys(&s.owner, body(s.input(json!({}))))
            .await);
        assert_matches(
            &verify_evidence_pack(&pack, &keys),
            json!({ "valid": true, "kid": pack["signature"]["kid"] }),
        );
        let mut edited = pack.clone();
        edited["controls"][0]["result"]["summary"] = json!("Edited after export");
        assert_eq!(
            verify(json!({ "pack": edited })).await,
            json!({ "valid": false })
        );
        assert_matches(
            &verify_evidence_pack(&edited, &keys),
            json!({ "valid": false, "reason": "digest mismatch" }),
        );
        // The export is anchored in the audit chain with its digest.
        let audit = s.audit_text(&s.owner).await;
        assert!(audit.contains(pack["digest"].as_str().unwrap()));
    });
}

#[test]
fn verifies_the_audit_chain_incrementally_from_a_checkpoint() {
    run(|| async {
        let s = scenario().await;
        s.create_control(
            &s.owner,
            json!({ "key": "audit", "name": "Audit", "checkId": "audit-integrity" }),
        )
        .await;
        s.evaluate(&s.owner, json!({})).await;
        let first = s.list_results(&s.owner, "audit").await;
        assert_eq!(first[0]["status"], "pass");
        let verified = first[0]["metrics"]["verifiedThrough"].as_f64().unwrap();
        s.f.member("erin").await;
        s.f.advance(MINUTE + 1.0);
        s.evaluate(&s.owner, json!({})).await;
        let second = s.list_results(&s.owner, "audit").await;
        assert_eq!(second[0]["status"], "pass");
        // Only the events since the checkpoint were read.
        let through = second[0]["metrics"]["verifiedThrough"].as_f64().unwrap();
        assert_eq!(
            second[0]["metrics"]["checked"].as_f64().unwrap(),
            through - verified
        );
        // Tampering after the checkpoint is found.
        let events =
            s.f.find("audit", Filter::new().eq("tenantId", s.tenant_id.clone()))
                .await;
        let mut target = events
            .into_iter()
            .find(|event| event.get("sequence").and_then(Value::as_f64).unwrap_or(0.0) > through)
            .unwrap();
        target.insert("action".into(), json!("edited"));
        s.f.put("audit", target).await;
        s.f.advance(MINUTE + 1.0);
        s.evaluate(&s.owner, json!({})).await;
        let third = s.list_results(&s.owner, "audit").await;
        assert_eq!(third[0]["status"], "fail");
    });
}

#[test]
fn evaluates_every_tenant_with_controls_from_the_scheduler_job_and_needs_permissions() {
    run(|| async {
        let s = scenario().await;
        s.adopt(&s.owner, "gdpr").await;
        let job = s.f.iam.compliance.evaluate_all(None).await.unwrap();
        assert_eq!(
            job["evaluated"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item["tenantId"].clone())
                .collect::<Vec<_>>(),
            vec![json!(s.tenant_id)]
        );
        assert_eq!(job["failed"], json!([]));
        let bob = s.f.member("bob").await;
        let bob = s.f.sign_in(&bob).await;
        let error = fails(
            s.f.iam
                .api
                .compliance
                .evaluate(&bob, body(s.input(json!({}))))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            s.f.iam
                .api
                .compliance
                .list_controls(&bob, body(s.input(json!({}))))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
    });
}

#[test]
fn validates_inputs_and_lists_the_catalog() {
    run(|| async {
        let s = scenario().await;
        let catalog = ok(s
            .f
            .iam
            .api
            .compliance
            .catalog(&s.owner, body(s.input(json!({}))))
            .await);
        let checks = catalog["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 14);
        let audit = checks
            .iter()
            .find(|check| check["id"] == "audit-integrity")
            .unwrap();
        assert_eq!(audit["noExceptions"], true);
        assert!(
            checks
                .iter()
                .filter(|check| check["id"] != "audit-integrity")
                .all(|check| check.get("noExceptions").is_none())
        );
        assert_eq!(
            checks[1]["params"],
            json!([{
                "name": "minimumPercent",
                "description": "Share of people that must be enrolled",
                "default": 100,
                "min": 50,
                "max": 100,
            }])
        );
        assert_eq!(catalog["frameworks"].as_array().unwrap().len(), 4);
        let error = fails(
            s.f.iam
                .api
                .compliance
                .adopt_framework(&s.owner, body(s.input(json!({ "framework": "pci" }))))
                .await,
        );
        assert_eq!(
            error.message,
            "framework must be one of soc2, iso27001, nist-800-53, gdpr"
        );
        let error = fails(
            s.f.iam
                .api
                .compliance
                .create_control(
                    &s.owner,
                    body(s.input(
                        json!({ "key": "Bad Key", "name": "x", "checkId": "mfa-enforced" }),
                    )),
                )
                .await,
        );
        assert_eq!(
            error.message,
            "Control keys use lowercase letters, digits, dots, underscores or hyphens"
        );
        let error = fails(
            s.f.iam
                .api
                .compliance
                .create_control(
                    &s.owner,
                    body(s.input(json!({
                        "key": "x",
                        "name": "x",
                        "checkId": "mfa-coverage",
                        "params": { "nope": 1 },
                    }))),
                )
                .await,
        );
        assert_eq!(error.message, "mfa-coverage has no parameter nope");
        let control = s
            .create_control(
                &s.owner,
                json!({ "key": "mfa", "name": " MFA ", "checkId": "mfa-coverage", "mappings": ["b", " a ", "b"] }),
            )
            .await;
        assert_eq!(control["name"], "MFA");
        assert_eq!(control["params"], json!({ "minimumPercent": 100 }));
        assert_eq!(control["mappings"], json!(["a", "b"]));
        let error = fails(
            s.f.iam
                .api
                .compliance
                .create_control(
                    &s.owner,
                    body(s.input(json!({ "key": "mfa", "name": "x", "checkId": "mfa-coverage" }))),
                )
                .await,
        );
        assert_eq!(code(&error), "CONFLICT");
        let deleted = ok(s
            .f
            .iam
            .api
            .compliance
            .delete_control(
                &s.owner,
                body(s.input(json!({ "controlId": control["id"] }))),
            )
            .await);
        assert_eq!(deleted, json!({ "deleted": true }));
        let error = fails(
            s.f.iam
                .api
                .compliance
                .list_runs(&s.owner, body(s.input(json!({ "limit": 0 }))))
                .await,
        );
        assert_eq!(error.message, "Invalid limit");
    });
}
