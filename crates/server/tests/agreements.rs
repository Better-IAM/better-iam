//! Terms of use: the port of tests/agreements.test.ts.
//!
//! Roles and bindings are written to the store directly (see `governance`). The TypeScript test's
//! `policies.simulate` and `analysis.lintPolicy` steps belong to other API groups and are left to their suites.

mod governance;

use better_iam_core::CredentialInput;
use better_iam_server::options::{AuthorizationRequest, ResourceTarget};
use governance::{DAY, Fixture, FixtureOptions, body, err, ok, organization, run};
use serde_json::{Value, json};

struct Scenario {
    f: Fixture,
    tenant_id: String,
    owner: CredentialInput,
    alice: String,
    alice_token: CredentialInput,
}

async fn scenario() -> Scenario {
    let f = organization(FixtureOptions::default()).await;
    let tenant_id = f.tenant_id.clone();
    let owner = f.owner.clone();
    let alice = f.member("alice").await;
    let reader = f
        .role_with(
            "Reader",
            json!([
                { "effect": "allow", "actions": ["documents:read"], "resources": ["*"] },
                // No document access until every required agreement is accepted.
                {
                    "effect": "deny",
                    "actions": ["documents:*"],
                    "resources": ["*"],
                    "conditions": { "NumericGreaterThan": { "principal.pendingAgreements": 0 } },
                },
            ]),
        )
        .await;
    f.bind(&reader, "identity", &alice).await;
    let alice_token = f.sign_in("alice").await;
    Scenario {
        f,
        tenant_id,
        owner,
        alice,
        alice_token,
    }
}

async fn allowed(s: &Scenario, credential: &CredentialInput, action: &str) -> bool {
    s.f.iam
        .authorize(&AuthorizationRequest {
            credential: credential.clone(),
            tenant_id: s.tenant_id.clone(),
            action: action.into(),
            resource: ResourceTarget {
                kind: "document".into(),
                id: "d1".into(),
            },
        })
        .await
        .unwrap()
        .allowed
}

#[test]
fn holds_back_access_until_required_agreements_are_accepted_and_again_after_a_new_version() {
    run(|| async {
        let s = scenario().await;
        let api = &s.f.iam.api.agreements;
        let tenant_id = s.tenant_id.clone();
        assert!(allowed(&s, &s.alice_token, "documents:read").await);
        let content = "Be nice.\n\n1. Report incidents.\r\n2.\tLock your screen.";
        let agreement = ok(api
            .create(
                &s.owner,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "Acceptable use",
                    "content": content,
                    "url": "https://acme.test/aup",
                })),
            )
            .await);
        assert_eq!(agreement["version"], json!(1));
        assert_eq!(agreement["required"], json!(true));
        assert_eq!(agreement["uniqueKey"], json!("name:acceptable use"));
        assert_eq!(agreement["url"], json!("https://acme.test/aup"));
        let agreement_id = agreement["id"].as_str().unwrap().to_owned();
        assert!(!allowed(&s, &s.alice_token, "documents:read").await);

        let mine = ok(api
            .list_mine(&s.alice_token, body(json!({ "tenantId": tenant_id })))
            .await);
        assert_eq!(mine.as_array().unwrap().len(), 1);
        assert_eq!(mine[0]["id"], json!(agreement_id));
        assert_eq!(mine[0]["accepted"], json!(false));
        assert_eq!(mine[0]["version"], json!(1));
        assert_eq!(mine[0]["content"], json!(content));
        assert!(mine[0].get("acceptedAt").is_none());
        // Accepting an outdated version is refused.
        let refused = err(api
            .accept(
                &s.alice_token,
                body(json!({ "tenantId": tenant_id, "agreementId": agreement_id, "version": 2 })),
            )
            .await);
        assert_eq!(refused.code, "VERSION_CONFLICT");
        let accepted = ok(api
            .accept(
                &s.alice_token,
                body(json!({ "tenantId": tenant_id, "agreementId": agreement_id, "version": 1 })),
            )
            .await);
        assert_eq!(accepted["accepted"], json!(true));
        assert_eq!(accepted["version"], json!(1));
        assert!(allowed(&s, &s.alice_token, "documents:read").await);
        let mine = ok(api
            .list_mine(&s.alice_token, body(json!({ "tenantId": tenant_id })))
            .await);
        assert_eq!(mine[0]["accepted"], json!(true));
        assert_eq!(mine[0]["acceptedVersion"], json!(1));

        // A typo fix keeps acceptances; a new version asks again.
        let fixed = ok(api
            .update(
                &s.owner,
                body(json!({ "tenantId": tenant_id, "agreementId": agreement_id, "content": "Be kind." })),
            )
            .await);
        assert_eq!(fixed["version"], json!(1));
        assert_eq!(fixed["url"], json!("https://acme.test/aup"));
        assert!(allowed(&s, &s.alice_token, "documents:read").await);
        let v2 = ok(api
            .update(
                &s.owner,
                body(json!({
                    "tenantId": tenant_id,
                    "agreementId": agreement_id,
                    "content": "Be kind and careful.",
                    "newVersion": true,
                })),
            )
            .await);
        assert_eq!(v2["version"], json!(2));
        assert!(!allowed(&s, &s.alice_token, "documents:read").await);
        let status = ok(api
            .status(
                &s.owner,
                body(json!({ "tenantId": tenant_id, "agreementId": agreement_id })),
            )
            .await);
        assert_eq!(status["accepted"], json!([]));
        assert_eq!(
            status["agreement"],
            json!({ "id": agreement_id, "name": "Acceptable use", "version": 2, "required": true })
        );
        assert!(
            status["pending"]
                .as_array()
                .unwrap()
                .contains(&json!({ "identity": { "id": s.alice, "name": "alice@acme.test" }, "acceptedVersion": 1 }))
        );
        // People are listed by email: alice before the owner, who never accepted.
        assert_eq!(
            status["pending"][1],
            json!({ "identity": { "id": s.f.owner_id, "name": "owner@acme.test" } })
        );
        ok(api
            .accept(
                &s.alice_token,
                body(json!({ "tenantId": tenant_id, "agreementId": agreement_id, "version": 2 })),
            )
            .await);
        assert!(allowed(&s, &s.alice_token, "documents:read").await);
        let after = ok(api
            .status(
                &s.owner,
                body(json!({ "tenantId": tenant_id, "agreementId": agreement_id })),
            )
            .await);
        assert_eq!(
            after["accepted"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| entry["identity"]["id"].clone())
                .collect::<Vec<_>>(),
            vec![json!(s.alice)]
        );
        assert_eq!(after["accepted"][0]["version"], json!(2));

        // Annual re-acceptance: acceptance lapses.
        let annual = ok(api
            .update(
                &s.owner,
                body(json!({ "tenantId": tenant_id, "agreementId": agreement_id, "reacceptAfterDays": 365 })),
            )
            .await);
        assert_eq!(annual["reacceptAfterDays"], json!(365));
        s.f.advance(366.0 * DAY);
        let fresh = s.f.sign_in("alice").await;
        assert!(!allowed(&s, &fresh, "documents:read").await);
        let events =
            s.f.find(
                "audit",
                &[
                    ("tenantId", json!(tenant_id)),
                    ("action", json!("agreement:accept")),
                ],
            )
            .await;
        assert_eq!(events.len(), 2);
        // The store returns records in no particular order: check both acceptances.
        let mut versions = events
            .iter()
            .map(|event| {
                assert_eq!(event["actorId"], json!(s.alice));
                assert_eq!(event["resourceId"], json!(agreement_id));
                assert_eq!(event["metadata"]["name"], json!("Acceptable use"));
                event["metadata"]["version"].as_i64().expect("a version")
            })
            .collect::<Vec<_>>();
        versions.sort_unstable();
        assert_eq!(versions, vec![1, 2]);
        // `reacceptAfterDays: null` removes the period; an empty url removes the link. The owner's session from
        // before the year passed has expired, so the owner signs in again.
        let owner =
            s.f.sign_in_with("owner@acme.test", "a strong tenant owner password")
                .await;
        let cleared = ok(api
            .update(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "agreementId": agreement_id,
                    "reacceptAfterDays": null,
                    "url": "",
                })),
            )
            .await);
        assert!(cleared.get("reacceptAfterDays").is_none());
        assert!(cleared.get("url").is_none());
        assert!(allowed(&s, &fresh, "documents:read").await);
    });
}

#[test]
fn exposes_accepted_names_to_policies_skips_optional_agreements_and_guards_self_service() {
    run(|| async {
        let s = scenario().await;
        let api = &s.f.iam.api.agreements;
        let tenant_id = s.tenant_id.clone();
        let optional = ok(api
            .create(
                &s.owner,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "Beta program",
                    "content": "Features may change.",
                    "required": false,
                })),
            )
            .await);
        let optional_id = optional["id"].as_str().unwrap().to_owned();
        // Optional agreements never hold anything back.
        assert!(allowed(&s, &s.alice_token, "documents:read").await);
        let beta =
            s.f.role_with(
                "Beta writer",
                json!([{
                    "effect": "allow",
                    "actions": ["documents:write"],
                    "resources": ["*"],
                    "conditions": { "ArrayContains": { "principal.agreements": ["Beta program"] } },
                }]),
            )
            .await;
        s.f.bind(&beta, "identity", &s.alice).await;
        assert!(!allowed(&s, &s.alice_token, "documents:write").await);
        ok(api
            .accept(
                &s.alice_token,
                body(json!({ "tenantId": tenant_id, "agreementId": optional_id, "version": 1 })),
            )
            .await);
        assert!(allowed(&s, &s.alice_token, "documents:write").await);
        // Accepting again replaces the acceptance.
        s.f.advance(1000.0);
        let again = ok(api
            .accept(
                &s.alice_token,
                body(json!({ "tenantId": tenant_id, "agreementId": optional_id, "version": 1 })),
            )
            .await);
        assert_eq!(
            s.f.find("agreementAcceptances", &[("tenantId", json!(tenant_id))])
                .await
                .iter()
                .map(|acceptance| acceptance["acceptedAt"].clone())
                .collect::<Vec<_>>(),
            vec![again["acceptedAt"].clone()]
        );

        // Management needs permissions; names are unique; members only accept for themselves.
        let refused = err(api
            .create(
                &s.alice_token,
                body(json!({ "tenantId": tenant_id, "name": "Mine", "content": "x" })),
            )
            .await);
        assert_eq!(refused.code, "ACCESS_DENIED");
        let refused = err(api
            .create(
                &s.owner,
                body(json!({ "tenantId": tenant_id, "name": "beta PROGRAM", "content": "x" })),
            )
            .await);
        assert_eq!(refused.code, "CONFLICT");
        let invalid: [(Value, &str); 6] = [
            (
                json!({ "name": "Linked", "content": "x", "url": "javascript:alert(1)" }),
                "url must be an http(s) URL",
            ),
            (
                json!({ "name": "Controls", "content": "bell \u{0007}" }),
                "Invalid content",
            ),
            (
                json!({ "name": "Blank", "content": "  \n " }),
                "Invalid content",
            ),
            (json!({ "name": "  ", "content": "x" }), "Invalid name"),
            (
                json!({ "name": "Flag", "content": "x", "required": "yes" }),
                "required must be a boolean",
            ),
            (
                json!({ "name": "Period", "content": "x", "reacceptAfterDays": 0 }),
                "Invalid reacceptAfterDays",
            ),
        ];
        for (input, message) in invalid {
            let mut request = input.as_object().unwrap().clone();
            request.insert("tenantId".into(), json!(tenant_id));
            let refused = err(api.create(&s.owner, body(Value::Object(request))).await);
            assert_eq!(
                (refused.code.as_str(), refused.message.as_str()),
                ("INVALID_INPUT", message)
            );
        }
        // Self-service needs an ordinary session of the tenant itself.
        let refused = err(api
            .list_mine(&s.owner, body(json!({ "tenantId": s.f.root_tenant_id })))
            .await);
        assert_eq!(refused.code, "ACCESS_DENIED");
        let refused = err(api
            .accept(
                &s.owner,
                body(json!({ "tenantId": s.f.root_tenant_id, "agreementId": optional_id, "version": 1 })),
            )
            .await);
        assert_eq!(refused.code, "ACCESS_DENIED");
        let refused = err(api
            .accept(
                &s.alice_token,
                body(json!({ "tenantId": tenant_id, "agreementId": optional_id, "version": 0 })),
            )
            .await);
        assert_eq!(refused.message, "Invalid version");
        let refused = err(api
            .update(
                &s.owner,
                body(json!({ "tenantId": tenant_id, "agreementId": 3 })),
            )
            .await);
        assert_eq!(refused.message, "Invalid agreementId");
        let mine = ok(api
            .list_mine(&s.alice_token, body(json!({ "tenantId": tenant_id })))
            .await);
        assert_eq!(mine[0]["name"], json!("Beta program"));
        assert_eq!(mine[0]["required"], json!(false));
        assert_eq!(
            ok(api
                .list(&s.owner, body(json!({ "tenantId": tenant_id })))
                .await)
            .as_array()
            .unwrap()
            .len(),
            1
        );
        ok(api
            .delete(
                &s.owner,
                body(json!({ "tenantId": tenant_id, "agreementId": optional_id })),
            )
            .await);
        assert!(!allowed(&s, &s.alice_token, "documents:write").await);
        assert_eq!(
            ok(api
                .list(&s.owner, body(json!({ "tenantId": tenant_id })))
                .await),
            json!([])
        );
        assert!(
            s.f.find("agreementAcceptances", &[("tenantId", json!(tenant_id))])
                .await
                .is_empty()
        );
    });
}

#[test]
fn lists_agreements_by_name_and_orders_the_personal_list() {
    run(|| async {
        let s = scenario().await;
        let api = &s.f.iam.api.agreements;
        let tenant_id = s.tenant_id.clone();
        for (name, required) in [("Zeta", true), ("alpha", false), ("Beta", true)] {
            ok(api
                .create(
                    &s.owner,
                    body(json!({ "tenantId": tenant_id, "name": name, "content": "x", "required": required })),
                )
                .await);
        }
        let names = |value: &Value| -> Vec<String> {
            value
                .as_array()
                .unwrap()
                .iter()
                .map(|agreement| agreement["name"].as_str().unwrap().to_owned())
                .collect()
        };
        assert_eq!(
            names(&ok(api
                .list(&s.owner, body(json!({ "tenantId": tenant_id })))
                .await)),
            vec!["alpha", "Beta", "Zeta"]
        );
        let zeta = ok(api
            .list(&s.owner, body(json!({ "tenantId": tenant_id })))
            .await)[2]["id"]
            .clone();
        ok(api
            .accept(
                &s.alice_token,
                body(json!({ "tenantId": tenant_id, "agreementId": zeta, "version": 1 })),
            )
            .await);
        // Unaccepted first, required before optional, then by name.
        assert_eq!(
            names(&ok(api
                .list_mine(&s.alice_token, body(json!({ "tenantId": tenant_id })))
                .await)),
            vec!["Beta", "alpha", "Zeta"]
        );
    });
}
