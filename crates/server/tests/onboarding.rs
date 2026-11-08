//! Onboarding: ported from tests/onboarding.test.ts and the onboarding block of tests/security-org.test.ts. Tenants,
//! members, sessions and grants come from the organization fixture (written as `tenants.create` with `activate`,
//! `identities.create`, `roles.create` and `bindings.create` write them, so these suites do not depend on the
//! invitation ceremony). Tests that reach another unit's stub (package-rules, teams, packages, sod,
//! package-automation, invariants) are `#[ignore]`d with that reason; the parts of them that need none of those run
//! as separate tests.

mod organization_fixture;

use better_iam_core::{AttributeType, CredentialInput, Filter};
use better_iam_server::options::{AuthorizationRequest, BetterIamOptions, ResourceTarget};
use indexmap::IndexMap;
use organization_fixture::{Org, assert_matches, body, code, fails, ok, organization, run};
use serde_json::{Value, json};

/// `permissions` with documents actions and two declared identity attributes.
fn attributes(options: &mut BetterIamOptions) {
    let mut declared = IndexMap::new();
    declared.insert("department".to_owned(), AttributeType::String);
    declared.insert("title".to_owned(), AttributeType::String);
    if let Some(permissions) = options.permissions.as_mut() {
        permissions.identity_attributes = Some(declared);
    }
}

/// A project under Acme whose owner is active.
async fn project(f: &Org, name: &str) -> (String, CredentialInput) {
    let (tenant_id, _, credential) = f
        .activate(
            &f.tenant_id,
            name,
            "project",
            &format!("{}@acme.test", name.to_lowercase()),
        )
        .await;
    (tenant_id, credential)
}

/// A role that reads documents only once every required onboarding flow is complete.
async fn gated_reader(f: &Org, identity_id: &str) {
    f.grant(
        identity_id,
        json!([
            { "effect": "allow", "actions": ["documents:read"], "resources": ["*"] },
            {
                "effect": "deny",
                "actions": ["documents:*"],
                "resources": ["*"],
                "conditions": { "NumericGreaterThan": { "principal.pendingOnboarding": 0 } },
            },
        ]),
    )
    .await;
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

fn names(flows: &Value) -> Vec<String> {
    flows
        .as_array()
        .unwrap()
        .iter()
        .map(|flow| {
            flow.get("name")
                .or_else(|| flow.pointer("/flow/name"))
                .and_then(Value::as_str)
                .unwrap()
                .to_owned()
        })
        .collect()
}

fn token(credential: &CredentialInput) -> String {
    credential.token.clone().unwrap()
}

#[test]
#[ignore = "needs ruleDocument/ruleMatch/parseAutoAssign (package-rules unit), assertNotTeamGroup/teamsSyncingFrom (teams unit), allow (packages unit), sodAssertIdentity (sod unit) and afterIdentityChange (package-automation unit)"]
fn inherits_platform_flows_lets_the_organization_customize_them_and_gates_access_until_done() {
    run(|| async {
        let f = organization(attributes).await;
        let api = &f.iam.api.onboarding;
        let root_id = f.root_tenant.clone();
        let owner = f.owner_credential.clone();
        // The owner joined before any flow existed; flows ask newcomers only unless includeExisting.
        f.advance(1_000.0);

        let department_field = json!({
            "name": "department",
            "label": "Department",
            "type": "select",
            "options": ["Engineering", "Sales"],
            "required": true,
        });
        let mut mapped_field = department_field.clone();
        mapped_field["attribute"] = json!("department");
        // A flow that reaches only the tenants below may not write their people's attributes.
        let error = fails(
            api.create_flow(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id,
                    "name": "Platform profile",
                    "audience": "member",
                    "steps": [{ "id": "profile", "kind": "form", "title": "About you", "fields": [mapped_field] }],
                })),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let essentials = ok(api
            .create_flow(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id,
                    "name": "Platform essentials",
                    "audience": "member",
                    "locked": true,
                    "steps": [
                        { "id": "conduct", "kind": "acknowledge", "title": "Code of conduct", "content": "Be kind.\n\n1. Report incidents." },
                        { "id": "profile", "kind": "form", "title": "About you", "fields": [department_field, { "name": "phone", "label": "Desk phone", "type": "text" }] },
                    ],
                })),
            )
            .await);
        // Flows at the platform root reach the tenants below it by default.
        assert_matches(
            &essentials,
            json!({ "appliesTo": "descendants", "version": 1, "locked": true }),
        );
        f.advance(1.0);
        let tour = ok(api
            .create_flow(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id,
                    "name": "Product tour",
                    "audience": "member",
                    "required": false,
                    "steps": [{ "id": "tour", "kind": "task", "title": "Take the tour", "url": "https://example.test/tour" }],
                })),
            )
            .await);
        ok(api
            .set_settings(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id,
                    "welcomeTitle": "Welcome to Example Cloud",
                    "welcomeMessage": "Platform message",
                    "supportEmail": "help@example.test",
                })),
            )
            .await);

        // The organization sees both, may switch off only the unlocked one, and adds its own.
        let effective = ok(api
            .effective(&owner, body(json!({ "tenantId": f.tenant_id })))
            .await);
        let levels: Vec<&str> = effective["levels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|level| level["type"].as_str().unwrap())
            .collect();
        assert_eq!(levels, ["root", "organization"]);
        let member_flows: Vec<Value> = effective["memberFlows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| json!([item["flow"]["name"], item["inherited"], item["canDisable"]]))
            .collect();
        assert_eq!(
            member_flows,
            vec![
                json!(["Platform essentials", true, false]),
                json!(["Product tour", true, true])
            ]
        );
        assert!(
            effective["memberFlows"][0]["flow"]
                .get("authorId")
                .is_none()
        );
        let error = fails(
            api.set_settings(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "disabledFlowIds": [essentials["id"]] })),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        ok(api
            .set_settings(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "welcomeMessage": "Welcome to Acme!",
                    "disabledFlowIds": [tour["id"]],
                })),
            )
            .await);
        let engineers = ok(f
            .iam
            .api
            .groups
            .create(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "name": "Engineers" })),
            )
            .await);
        // Acme's own flow may fill its people's department.
        let team = ok(api
            .create_flow(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Acme profile",
                    "audience": "member",
                    "steps": [{ "id": "team", "kind": "form", "title": "Your team", "fields": [mapped_field] }],
                })),
            )
            .await);
        f.advance(1.0);
        let engineering = ok(api
            .create_flow(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Engineering onboarding",
                    "audience": "member",
                    "rule": { "include": [{ "StringEquals": { "principal.department": "Engineering" } }] },
                    "completionGroupIds": [engineers["id"]],
                    "steps": [{ "id": "laptop", "kind": "task", "title": "Collect your laptop", "verification": "admin" }],
                })),
            )
            .await);
        assert_eq!(engineering["appliesTo"], "tenant");

        let alice = f.member("alice").await;
        gated_reader(&f, &alice).await;
        let alice_token = f.sign_in(&alice).await;

        let mut mine = ok(api
            .mine(&alice_token, body(json!({ "tenantId": f.tenant_id })))
            .await);
        assert_eq!(
            names(&mine["flows"]),
            ["Platform essentials", "Acme profile"]
        );
        assert_matches(&mine, json!({ "pending": 2, "complete": false }));
        assert_matches(
            &mine["welcome"],
            json!({
                "welcomeTitle": "Welcome to Example Cloud",
                "welcomeMessage": "Welcome to Acme!",
                "supportEmail": "help@example.test",
                "sources": {
                    "welcomeTitle": { "type": "root" },
                    "welcomeMessage": { "tenantId": f.tenant_id },
                },
            }),
        );
        // The owner predates the flows.
        let owner_mine = ok(api
            .mine(&owner, body(json!({ "tenantId": f.tenant_id })))
            .await);
        assert_eq!(owner_mine["flows"], json!([]));
        assert!(!can_read(&f, &alice_token).await);

        let error = fails(
            api.submit_step(
                &alice_token,
                body(json!({ "tenantId": f.tenant_id, "flowId": essentials["id"], "stepId": "conduct" })),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        ok(api
            .submit_step(
                &alice_token,
                body(json!({
                    "tenantId": f.tenant_id, "flowId": essentials["id"], "stepId": "conduct", "acknowledged": true,
                })),
            )
            .await);
        let error = fails(
            api.submit_step(
                &alice_token,
                body(json!({
                    "tenantId": f.tenant_id, "flowId": essentials["id"], "stepId": "profile",
                    "answers": { "department": "Marketing" },
                })),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        // The platform's answers stay answers; they never write Acme's identities.
        let profile = ok(api
            .submit_step(
                &alice_token,
                body(json!({
                    "tenantId": f.tenant_id, "flowId": essentials["id"], "stepId": "profile",
                    "answers": { "department": "Engineering", "phone": " 555-0100 " },
                })),
            )
            .await);
        assert_eq!(profile["attributesFilled"], json!([]));
        assert_matches(
            &profile["flow"],
            json!({ "complete": true, "done": 2, "total": 2 }),
        );
        assert_eq!(
            profile["flow"]["steps"][1]["answers"],
            json!({ "department": "Engineering", "phone": "555-0100" })
        );
        let filled = ok(api
            .submit_step(
                &alice_token,
                body(json!({
                    "tenantId": f.tenant_id, "flowId": team["id"], "stepId": "team",
                    "answers": { "department": "Engineering" },
                })),
            )
            .await);
        assert_eq!(filled["attributesFilled"], json!(["department"]));

        // The answer filled her department, so the engineering flow now applies to her.
        mine = ok(api
            .mine(&alice_token, body(json!({ "tenantId": f.tenant_id })))
            .await);
        let states: Vec<Value> = mine["flows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|flow| json!([flow["name"], flow["complete"]]))
            .collect();
        assert_eq!(
            states,
            vec![
                json!(["Platform essentials", true]),
                json!(["Acme profile", true]),
                json!(["Engineering onboarding", false])
            ]
        );
        assert!(!can_read(&f, &alice_token).await);

        // Onboarding only fills empty attributes.
        let again = ok(api
            .submit_step(
                &alice_token,
                body(json!({
                    "tenantId": f.tenant_id, "flowId": team["id"], "stepId": "team",
                    "answers": { "department": "Sales" },
                })),
            )
            .await);
        assert_eq!(again["attributesFilled"], json!([]));
        let identity = ok(f
            .iam
            .api
            .identities
            .get(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "identityId": alice })),
            )
            .await);
        assert_eq!(
            identity["attributes"],
            json!({ "department": "Engineering" })
        );

        // An administrator-verified task waits for the owner.
        let laptop = ok(api
            .submit_step(
                &alice_token,
                body(json!({ "tenantId": f.tenant_id, "flowId": engineering["id"], "stepId": "laptop" })),
            )
            .await);
        assert_matches(&laptop["flow"]["steps"][0], json!({ "state": "submitted" }));
        let error = fails(
            api.verify_step(
                &alice_token,
                body(json!({
                    "tenantId": f.tenant_id, "flowId": engineering["id"], "subjectId": alice, "stepId": "laptop",
                })),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let report = ok(api
            .progress(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "flowId": engineering["id"] })),
            )
            .await);
        assert_eq!(report["members"].as_array().unwrap().len(), 1);
        assert_matches(
            &report["members"][0],
            json!({ "identity": { "id": alice }, "complete": false, "awaiting": ["laptop"] }),
        );
        let verified = ok(api
            .verify_step(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id, "flowId": engineering["id"], "subjectId": alice, "stepId": "laptop",
                })),
            )
            .await);
        assert_eq!(verified["flow"]["complete"], true);
        assert!(can_read(&f, &alice_token).await);

        // Completion groups are applied when she next reads her onboarding.
        mine = ok(api
            .mine(&alice_token, body(json!({ "tenantId": f.tenant_id })))
            .await);
        assert_matches(&mine, json!({ "pending": 0, "complete": true }));
        let members = ok(f
            .iam
            .api
            .groups
            .list_members(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "groupId": engineers["id"] })),
            )
            .await);
        let member_ids: Vec<&Value> = members
            .as_array()
            .unwrap()
            .iter()
            .map(|member| &member["id"])
            .collect();
        assert_eq!(member_ids, vec![&json!(alice)]);
        let audit = ok(f
            .iam
            .api
            .audit
            .list(&owner, body(json!({ "tenantId": f.tenant_id })))
            .await);
        let actions: Vec<&str> = audit
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["action"].as_str().unwrap())
            .collect();
        for action in [
            "onboarding:step",
            "onboarding:complete",
            "onboarding:verify",
            "onboarding:groups",
        ] {
            assert!(
                actions.contains(&action),
                "{action} missing from {actions:?}"
            );
        }

        // The platform's report counts Acme's people without naming them.
        let platform_report = ok(api
            .progress(
                &f.root_credential,
                body(json!({ "tenantId": root_id, "flowId": essentials["id"] })),
            )
            .await);
        assert_eq!(platform_report["members"], json!([]));
        assert_eq!(
            platform_report["descendants"],
            json!([{
                "tenant": { "tenantId": f.tenant_id, "name": "Acme", "type": "organization" },
                "people": 1,
                "complete": 1,
            }])
        );

        // Resetting one step reopens the flow for her.
        ok(api
            .reset_progress(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id, "flowId": engineering["id"], "subjectId": alice, "stepId": "laptop",
                })),
            )
            .await);
        assert!(!can_read(&f, &alice_token).await);
    });
}

/// The parts of the platform/organization test that need no other unit: inherited flows, switching off unlocked
/// ones, welcome settings resolved level by level, gating access through `principal.pendingOnboarding`, forms,
/// acknowledgements, admin-verified tasks, the reports and resetting one step.
#[test]
fn inherited_flows_settings_gating_and_verified_tasks_without_rules_or_groups() {
    run(|| async {
        let f = organization(attributes).await;
        let api = &f.iam.api.onboarding;
        let root_id = f.root_tenant.clone();
        let owner = f.owner_credential.clone();
        f.advance(1_000.0);
        let department_field = json!({
            "name": "department", "label": "Department", "type": "select",
            "options": ["Engineering", "Sales"], "required": true,
        });
        let mut mapped_field = department_field.clone();
        mapped_field["attribute"] = json!("department");
        let error = fails(
            api.create_flow(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id, "name": "Platform profile", "audience": "member",
                    "steps": [{ "id": "profile", "kind": "form", "title": "About you", "fields": [mapped_field] }],
                })),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        assert_eq!(
            error.message,
            "Answers fill identity attributes only for the defining tenant\u{2019}s own people; a flow that reaches only tenants below cannot map fields to attributes"
        );
        let essentials = ok(api
            .create_flow(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id, "name": "Platform essentials", "audience": "member", "locked": true,
                    "steps": [
                        { "id": "conduct", "kind": "acknowledge", "title": "Code of conduct", "content": "Be kind.\n\n1. Report incidents." },
                        { "id": "profile", "kind": "form", "title": "About you", "fields": [department_field, { "name": "phone", "label": "Desk phone", "type": "text" }] },
                    ],
                })),
            )
            .await);
        assert_matches(
            &essentials,
            json!({ "appliesTo": "descendants", "version": 1, "locked": true, "required": true, "enabled": true }),
        );
        f.advance(1.0);
        let tour = ok(api
            .create_flow(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id, "name": "Product tour", "audience": "member", "required": false,
                    "steps": [{ "id": "tour", "kind": "task", "title": "Take the tour", "url": "https://example.test/tour" }],
                })),
            )
            .await);
        ok(api
            .set_settings(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id, "welcomeTitle": "Welcome to Example Cloud",
                    "welcomeMessage": "Platform message", "supportEmail": "help@example.test",
                })),
            )
            .await);
        let effective = ok(api
            .effective(&owner, body(json!({ "tenantId": f.tenant_id })))
            .await);
        let member_flows: Vec<Value> = effective["memberFlows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| json!([item["flow"]["name"], item["inherited"], item["canDisable"]]))
            .collect();
        assert_eq!(
            member_flows,
            vec![
                json!(["Platform essentials", true, false]),
                json!(["Product tour", true, true])
            ]
        );
        assert!(
            effective["memberFlows"][0]["flow"]
                .get("authorId")
                .is_none()
        );
        assert_eq!(effective["descendantTypes"], json!(["project"]));
        assert_eq!(
            effective["identityAttributes"],
            json!({ "department": "string", "title": "string" })
        );
        let error = fails(
            api.set_settings(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "disabledFlowIds": [essentials["id"]] })),
            )
            .await,
        );
        assert_eq!(
            error.message,
            "disabledFlowIds: Platform essentials is locked by the tenant that defines it"
        );
        let saved = ok(api
            .set_settings(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id, "welcomeMessage": "Welcome to Acme!", "disabledFlowIds": [tour["id"]],
                })),
            )
            .await);
        assert_eq!(saved["disabledFlowIds"], json!([tour["id"]]));
        let laptop_flow = ok(api
            .create_flow(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id, "name": "Engineering onboarding", "audience": "member",
                    "steps": [{ "id": "laptop", "kind": "task", "title": "Collect your laptop", "verification": "admin" }],
                })),
            )
            .await);
        assert_eq!(laptop_flow["appliesTo"], "tenant");

        let alice = f.member("alice").await;
        gated_reader(&f, &alice).await;
        let alice_token = f.sign_in(&alice).await;
        let mine = ok(api
            .mine(&alice_token, body(json!({ "tenantId": f.tenant_id })))
            .await);
        assert_eq!(
            names(&mine["flows"]),
            ["Platform essentials", "Engineering onboarding"]
        );
        assert_matches(&mine, json!({ "pending": 2, "complete": false }));
        assert_matches(
            &mine["welcome"],
            json!({
                "welcomeTitle": "Welcome to Example Cloud",
                "welcomeMessage": "Welcome to Acme!",
                "supportEmail": "help@example.test",
                "sources": {
                    "welcomeTitle": { "type": "root" },
                    "welcomeMessage": { "tenantId": f.tenant_id },
                },
            }),
        );
        let owner_mine = ok(api
            .mine(&owner, body(json!({ "tenantId": f.tenant_id })))
            .await);
        assert_eq!(owner_mine["flows"], json!([]));
        assert!(!can_read(&f, &alice_token).await);

        let error = fails(
            api.submit_step(
                &alice_token,
                body(json!({ "tenantId": f.tenant_id, "flowId": essentials["id"], "stepId": "conduct" })),
            )
            .await,
        );
        assert_eq!(
            error.message,
            "Confirm that you have read this (acknowledged: true)"
        );
        ok(api
            .submit_step(
                &alice_token,
                body(json!({
                    "tenantId": f.tenant_id, "flowId": essentials["id"], "stepId": "conduct", "acknowledged": true,
                })),
            )
            .await);
        let error = fails(
            api.submit_step(
                &alice_token,
                body(json!({
                    "tenantId": f.tenant_id, "flowId": essentials["id"], "stepId": "profile",
                    "answers": { "department": "Marketing" },
                })),
            )
            .await,
        );
        assert_eq!(error.message, "Department is not valid");
        let profile = ok(api
            .submit_step(
                &alice_token,
                body(json!({
                    "tenantId": f.tenant_id, "flowId": essentials["id"], "stepId": "profile",
                    "answers": { "department": "Engineering", "phone": " 555-0100 " },
                })),
            )
            .await);
        assert_eq!(profile["attributesFilled"], json!([]));
        assert_matches(
            &profile["flow"],
            json!({ "complete": true, "done": 2, "total": 2 }),
        );
        assert_eq!(
            profile["flow"]["steps"][1]["answers"],
            json!({ "department": "Engineering", "phone": "555-0100" })
        );
        assert!(!can_read(&f, &alice_token).await);

        let laptop = ok(api
            .submit_step(
                &alice_token,
                body(json!({ "tenantId": f.tenant_id, "flowId": laptop_flow["id"], "stepId": "laptop" })),
            )
            .await);
        assert_matches(&laptop["flow"]["steps"][0], json!({ "state": "submitted" }));
        let error = fails(
            api.verify_step(
                &alice_token,
                body(json!({
                    "tenantId": f.tenant_id, "flowId": laptop_flow["id"], "subjectId": alice, "stepId": "laptop",
                })),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let report = ok(api
            .progress(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "flowId": laptop_flow["id"] })),
            )
            .await);
        assert_eq!(report["members"].as_array().unwrap().len(), 1);
        assert_matches(
            &report["members"][0],
            json!({ "identity": { "id": alice }, "complete": false, "awaiting": ["laptop"] }),
        );
        assert_eq!(report["summary"], json!({ "subjects": 1, "complete": 0 }));
        let verified = ok(api
            .verify_step(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id, "flowId": laptop_flow["id"], "subjectId": alice, "stepId": "laptop",
                })),
            )
            .await);
        assert_eq!(verified["flow"]["complete"], true);
        assert!(can_read(&f, &alice_token).await);
        let mine = ok(api
            .mine(&alice_token, body(json!({ "tenantId": f.tenant_id })))
            .await);
        assert_matches(&mine, json!({ "pending": 0, "complete": true }));
        let audit = ok(f
            .iam
            .api
            .audit
            .list(&owner, body(json!({ "tenantId": f.tenant_id })))
            .await);
        let actions: Vec<&str> = audit
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["action"].as_str().unwrap())
            .collect();
        for action in [
            "onboarding:step",
            "onboarding:complete",
            "onboarding:verify",
        ] {
            assert!(
                actions.contains(&action),
                "{action} missing from {actions:?}"
            );
        }

        let platform_report = ok(api
            .progress(
                &f.root_credential,
                body(json!({ "tenantId": root_id, "flowId": essentials["id"] })),
            )
            .await);
        assert_eq!(platform_report["members"], json!([]));
        assert_eq!(
            platform_report["descendants"],
            json!([{
                "tenant": { "tenantId": f.tenant_id, "name": "Acme", "type": "organization" },
                "people": 1,
                "complete": 1,
            }])
        );

        let member = ok(api
            .member_progress(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "identityId": alice })),
            )
            .await);
        assert_matches(
            &member,
            json!({ "identity": { "id": alice, "name": "alice", "email": "alice@acme.test" }, "pending": 0 }),
        );

        let reset = ok(api
            .reset_progress(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id, "flowId": laptop_flow["id"], "subjectId": alice, "stepId": "laptop",
                })),
            )
            .await);
        assert_eq!(reset, json!({ "reset": 1 }));
        assert!(!can_read(&f, &alice_token).await);
    });
}

#[test]
#[ignore = "needs allow (packages unit) for flows whose answers fill identity attributes"]
fn reaches_projects_through_the_subtree_with_project_level_flows_and_settings() {
    run(|| async {
        let f = organization(attributes).await;
        subtree_scenario(&f).await;
        let api = &f.iam.api.onboarding;
        let owner = f.owner_credential.clone();
        // An organization's subtree flow fills its own people's attributes, never a project member's.
        let (project_id, bob_token, bob, project_credential) =
            SUBTREE.with(|cell| cell.borrow().clone().unwrap());
        let directory = ok(api
            .create_flow(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id, "name": "Directory profile", "audience": "member", "appliesTo": "subtree",
                    "steps": [{
                        "id": "title", "kind": "form", "title": "Your title",
                        "fields": [{ "name": "title", "label": "Title", "type": "text", "attribute": "title" }],
                    }],
                })),
            )
            .await);
        let answered = ok(api
            .submit_step(
                &bob_token,
                body(json!({
                    "tenantId": project_id, "flowId": directory["id"], "stepId": "title",
                    "answers": { "title": "Engineer" },
                })),
            )
            .await);
        assert_matches(
            &answered,
            json!({ "attributesFilled": [], "flow": { "complete": true } }),
        );
        let identity = ok(f
            .iam
            .api
            .identities
            .get(
                &project_credential,
                body(json!({ "tenantId": project_id, "identityId": bob })),
            )
            .await);
        assert_eq!(
            identity.get("attributes").cloned().unwrap_or(json!({})),
            json!({})
        );
    });
}

thread_local! {
    /// What [`subtree_scenario`] set up: the project, Bob's session, Bob, and the project owner's session.
    static SUBTREE: std::cell::RefCell<Option<(String, CredentialInput, String, CredentialInput)>> =
        const { std::cell::RefCell::new(None) };
}

/// The project half of tests/onboarding.test.ts "reaches projects through the subtree", up to the reports.
async fn subtree_scenario(f: &Org) {
    let api = &f.iam.api.onboarding;
    let root_id = f.root_tenant.clone();
    let owner = f.owner_credential.clone();
    let step = |id: &str| json!([{ "id": id, "kind": "acknowledge", "title": id, "content": format!("Read {id}.") }]);
    ok(api
        .create_flow(
            &f.root_credential,
            body(json!({
                "tenantId": root_id, "name": "Organizations only", "audience": "member",
                "tenantTypes": ["organization"], "steps": step("org-only"),
            })),
        )
        .await);
    f.advance(1.0);
    ok(api
        .create_flow(
            &f.root_credential,
            body(json!({ "tenantId": root_id, "name": "Everyone", "audience": "member", "steps": step("everyone") })),
        )
        .await);
    ok(api
        .set_settings(
            &f.root_credential,
            body(json!({
                "tenantId": root_id, "welcomeTitle": "Platform title", "supportUrl": "https://help.example.test",
            })),
        )
        .await);
    let basics = ok(api
        .create_flow(
            &owner,
            body(json!({
                "tenantId": f.tenant_id, "name": "Acme basics", "audience": "member", "appliesTo": "subtree",
                "steps": step("basics"),
            })),
        )
        .await);
    let (apollo, apollo_credential) = project(f, "Apollo").await;
    let error = fails(
        api.create_flow(
            &apollo_credential,
            body(json!({
                "tenantId": apollo, "name": "Below projects", "audience": "member", "appliesTo": "descendants",
                "steps": step("nothing"),
            })),
        )
        .await,
    );
    assert_eq!(code(&error), "INVALID_INPUT");
    assert_eq!(
        error.message,
        "project tenants have no descendants; use appliesTo: tenant"
    );
    ok(api
        .create_flow(
            &apollo_credential,
            body(json!({ "tenantId": apollo, "name": "Project kickoff", "audience": "member", "steps": step("kickoff") })),
        )
        .await);
    ok(api
        .set_settings(
            &apollo_credential,
            body(json!({ "tenantId": apollo, "welcomeTitle": "Welcome to Apollo" })),
        )
        .await);
    let bob = f.member_in(&apollo, "bob").await;
    let bob_token = f.sign_in(&bob).await;

    let mine = ok(api
        .mine(&bob_token, body(json!({ "tenantId": apollo })))
        .await);
    let sources: Vec<Value> = mine["flows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|flow| json!([flow["name"], flow["source"]["type"]]))
        .collect();
    assert_eq!(
        sources,
        vec![
            json!(["Everyone", "root"]),
            json!(["Acme basics", "organization"]),
            json!(["Project kickoff", "project"])
        ]
    );
    assert_matches(
        &mine["welcome"],
        json!({ "welcomeTitle": "Welcome to Apollo", "supportUrl": "https://help.example.test" }),
    );
    assert_eq!(mine["pending"], 3);

    // The project switches off the organization's unlocked flow for itself...
    ok(api
        .set_settings(
            &apollo_credential,
            body(json!({ "tenantId": apollo, "welcomeTitle": "Welcome to Apollo", "disabledFlowIds": [basics["id"]] })),
        )
        .await);
    let mine = ok(api
        .mine(&bob_token, body(json!({ "tenantId": apollo })))
        .await);
    assert_eq!(names(&mine["flows"]), ["Everyone", "Project kickoff"]);
    let effective = ok(api
        .effective(&apollo_credential, body(json!({ "tenantId": apollo })))
        .await);
    let switched = effective["memberFlows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["flow"]["id"] == basics["id"])
        .unwrap();
    assert_matches(
        switched,
        json!({ "disabledBy": { "tenantId": apollo }, "canDisable": true }),
    );
    // ...until the organization locks it.
    ok(api
        .update_flow(
            &owner,
            body(json!({ "tenantId": f.tenant_id, "flowId": basics["id"], "locked": true })),
        )
        .await);
    let mine = ok(api
        .mine(&bob_token, body(json!({ "tenantId": apollo })))
        .await);
    assert_eq!(
        names(&mine["flows"]),
        ["Everyone", "Acme basics", "Project kickoff"]
    );
    // Re-saving the project's settings quietly drops the switch that no longer applies.
    let saved = ok(api
        .set_settings(
            &apollo_credential,
            body(json!({ "tenantId": apollo, "welcomeTitle": "Welcome to Apollo", "disabledFlowIds": [basics["id"]] })),
        )
        .await);
    assert_eq!(saved["disabledFlowIds"], json!([]));

    ok(api
        .submit_step(
            &bob_token,
            body(json!({ "tenantId": apollo, "flowId": basics["id"], "stepId": "basics", "acknowledged": true })),
        )
        .await);
    let report = ok(api
        .progress(
            &owner,
            body(json!({ "tenantId": f.tenant_id, "flowId": basics["id"] })),
        )
        .await);
    assert_eq!(
        report["descendants"],
        json!([{
            "tenant": { "tenantId": apollo, "name": "Apollo", "type": "project" },
            "people": 2,
            "complete": 1,
        }])
    );
    // A flow inherited from above is reported at the project for its own people.
    let project_report = ok(api
        .progress(
            &apollo_credential,
            body(json!({ "tenantId": apollo, "flowId": basics["id"] })),
        )
        .await);
    assert_matches(
        &project_report["flow"],
        json!({ "inherited": true, "source": { "type": "organization" } }),
    );
    let rows: Vec<Value> = project_report["members"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| json!([row["identity"]["id"] == json!(bob), row["complete"]]))
        .collect();
    assert!(rows.contains(&json!([true, true])), "{rows:?}");
    SUBTREE.with(|cell| {
        *cell.borrow_mut() = Some((
            apollo.clone(),
            bob_token.clone(),
            bob.clone(),
            apollo_credential.clone(),
        ))
    });
}

/// The parts of "reaches projects through the subtree" that need no other unit (everything before the flow whose
/// answers fill identity attributes).
#[test]
fn reaches_projects_through_the_subtree_without_attribute_answers() {
    run(|| async {
        let f = organization(attributes).await;
        subtree_scenario(&f).await;
    });
}

#[test]
fn walks_a_new_organization_through_setup_checks_forms_and_verified_tasks() {
    run(|| async {
        let f = organization(|_| {}).await;
        let api = &f.iam.api.onboarding;
        let root_id = f.root_tenant.clone();
        let owner = f.owner_credential.clone();
        // Tenants record creation on the wall clock; move the test clock past Acme's creation.
        f.advance(60_000.0);
        let setup = ok(api
            .create_flow(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id, "name": "Organization setup", "audience": "tenant",
                    "tenantTypes": ["organization"], "includeExisting": true,
                    "steps": [
                        { "id": "team", "kind": "check", "title": "Invite your team", "check": "members", "minimum": 2 },
                        { "id": "alias", "kind": "check", "title": "Choose a sign-in alias", "check": "slug" },
                        {
                            "id": "company", "kind": "form", "title": "About your company",
                            "fields": [{ "name": "size", "label": "Company size", "type": "select", "options": ["1-10", "11-50", "51+"], "required": true }],
                        },
                        { "id": "kyc", "kind": "task", "title": "Business verification", "verification": "admin" },
                        { "id": "sso", "kind": "check", "title": "Connect SSO", "check": "sso", "optional": true },
                    ],
                })),
            )
            .await);
        // Flows for projects, and flows that ask only organizations created from now on, leave Acme alone.
        ok(api
            .create_flow(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id, "name": "Project setup", "audience": "tenant", "tenantTypes": ["project"],
                    "includeExisting": true, "steps": [{ "id": "p", "kind": "task", "title": "Project task" }],
                })),
            )
            .await);
        ok(api
            .create_flow(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id, "name": "New organizations", "audience": "tenant",
                    "steps": [{ "id": "n", "kind": "task", "title": "New task" }],
                })),
            )
            .await);

        let state = ok(api
            .setup(&owner, body(json!({ "tenantId": f.tenant_id })))
            .await);
        assert_eq!(names(&state["flows"]), ["Organization setup"]);
        let steps: Vec<Value> = state["flows"][0]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|step| json!([step["id"], step["state"], step.get("detail")]))
            .collect();
        assert_eq!(
            steps,
            vec![
                json!(["team", "pending", "1 of 2 members"]),
                json!(["alias", "pending", "No sign-in alias yet"]),
                json!(["company", "pending", null]),
                json!(["kyc", "pending", null]),
                json!(["sso", "pending", "0 of 1 SSO connection"]),
            ]
        );
        assert_matches(&state, json!({ "pending": 1, "complete": false }));

        // Checks follow the organization's real state.
        let alice = f.member("alice").await;
        ok(f.iam
            .api
            .tenants
            .set_slug(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "slug": "acme" })),
            )
            .await);
        let error = fails(
            api.submit_setup_step(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "flowId": setup["id"], "stepId": "team" })),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        assert_eq!(
            error.message,
            "This step completes when the organization\u{2019}s setup meets it"
        );
        ok(api
            .submit_setup_step(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id, "flowId": setup["id"], "stepId": "company", "answers": { "size": "11-50" },
                })),
            )
            .await);
        ok(api
            .submit_setup_step(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "flowId": setup["id"], "stepId": "kyc" })),
            )
            .await);
        // People without iam:onboarding:manage cannot complete setup.
        let alice_token = f.sign_in(&alice).await;
        let error = fails(
            api.submit_setup_step(
                &alice_token,
                body(json!({
                    "tenantId": f.tenant_id, "flowId": setup["id"], "stepId": "company", "answers": { "size": "1-10" },
                })),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");

        // The platform sees every organization's setup, with its answers, and verifies the task.
        let report = ok(api
            .progress(
                &f.root_credential,
                body(json!({ "tenantId": root_id, "flowId": setup["id"] })),
            )
            .await);
        assert_eq!(report["tenants"].as_array().unwrap().len(), 1);
        assert_matches(
            &report["tenants"][0],
            json!({
                "tenant": { "tenantId": f.tenant_id, "name": "Acme", "status": "active" },
                "complete": false,
                "done": 3,
                "total": 4,
                "awaiting": ["kyc"],
                "answers": { "company": { "size": "11-50" } },
            }),
        );
        ok(api
            .verify_step(
                &f.root_credential,
                body(json!({
                    "tenantId": root_id, "flowId": setup["id"], "subjectId": f.tenant_id, "stepId": "kyc",
                    "approve": false, "note": "Upload the registration certificate",
                })),
            )
            .await);
        let state = ok(api
            .setup(&owner, body(json!({ "tenantId": f.tenant_id })))
            .await);
        let kyc = state["flows"][0]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .find(|step| step["id"] == "kyc")
            .unwrap();
        assert_matches(
            kyc,
            json!({ "state": "rejected", "note": "Upload the registration certificate" }),
        );
        ok(api
            .submit_setup_step(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "flowId": setup["id"], "stepId": "kyc" })),
            )
            .await);
        let verified = ok(api
            .verify_step(
                &f.root_credential,
                body(json!({ "tenantId": root_id, "flowId": setup["id"], "subjectId": f.tenant_id, "stepId": "kyc" })),
            )
            .await);
        assert_matches(
            &verified["flow"],
            json!({ "complete": true, "done": 4, "total": 4 }),
        );
        let state = ok(api
            .setup(&owner, body(json!({ "tenantId": f.tenant_id })))
            .await);
        assert_matches(&state, json!({ "pending": 0, "complete": true }));
        let audit = ok(f
            .iam
            .api
            .audit
            .list(&owner, body(json!({ "tenantId": f.tenant_id })))
            .await);
        assert!(
            audit
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["action"] == "onboarding:complete")
        );

        // The organization cannot verify its own setup task: the flow belongs to the platform.
        let error = fails(
            api.verify_step(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "flowId": setup["id"], "subjectId": f.tenant_id, "stepId": "kyc" })),
            )
            .await,
        );
        assert_eq!(code(&error), "NOT_FOUND");
    });
}

/// The invalid flows of "validates flows, versions steps, and cleans up progress" that need no other unit.
async fn invalid_flows(f: &Org, alice_token: &CredentialInput) {
    let api = &f.iam.api.onboarding;
    let owner = f.owner_credential.clone();
    let task = json!([{ "id": "hello", "kind": "task", "title": "Say hello" }]);
    let error = fails(
        api.create_flow(
            alice_token,
            body(json!({ "tenantId": f.tenant_id, "name": "Mine", "audience": "member", "steps": task })),
        )
        .await,
    );
    assert_eq!(code(&error), "ACCESS_DENIED");
    let invalid = |input: Value, credential: CredentialInput, at: String| {
        let mut request =
            json!({ "tenantId": at, "name": "Invalid", "audience": "member", "steps": task });
        for (key, value) in input.as_object().unwrap() {
            request[key] = value.clone();
        }
        async move {
            let error = fails(api.create_flow(&credential, body(request.clone())).await);
            assert_eq!(code(&error), "INVALID_INPUT", "{request}: {error:?}");
            error.message
        }
    };
    let here = f.tenant_id.clone();
    assert_eq!(
        invalid(
            json!({ "steps": [{ "id": "c", "kind": "check", "title": "Check", "check": "slug" }] }),
            owner.clone(),
            here.clone()
        )
        .await,
        "steps[0].kind must be one of form, acknowledge, task, agreement, verify-email, mfa, passkey in a member flow"
    );
    assert_eq!(
        invalid(
            json!({ "steps": [{ "id": "f", "kind": "form", "title": "Form", "fields": [{ "name": "x", "label": "X", "type": "text", "attribute": "favouriteColour" }] }] }),
            owner.clone(),
            here.clone()
        )
        .await,
        "steps[0].fields[0].attribute favouriteColour is not a declared identity attribute"
    );
    assert_eq!(
        invalid(
            json!({ "steps": [{ "id": "f", "kind": "form", "title": "Form", "fields": [{ "name": "x", "label": "X", "type": "number", "attribute": "department" }] }] }),
            owner.clone(),
            here.clone()
        )
        .await,
        "steps[0].fields[0].attribute department holds a string; a number field cannot fill it"
    );
    assert_eq!(
        invalid(
            json!({ "steps": [{ "id": "f", "kind": "form", "title": "Form", "fields": [{ "name": "x", "label": "X", "type": "textarea", "attribute": "department" }] }] }),
            owner.clone(),
            here.clone()
        )
        .await,
        "steps[0].fields[0].attribute: a textarea answer cannot fill an attribute"
    );
    assert_eq!(
        invalid(
            json!({ "steps": [{ "id": "Bad Id", "kind": "task", "title": "Task" }] }),
            owner.clone(),
            here.clone()
        )
        .await,
        "steps[0].id must use lowercase letters, digits and dashes (at most 40)"
    );
    assert_eq!(
        invalid(
            json!({ "steps": [task[0], task[0]] }),
            owner.clone(),
            here.clone()
        )
        .await,
        "steps must have distinct IDs"
    );
    assert_eq!(
        invalid(
            json!({ "audience": "tenant", "appliesTo": "tenant" }),
            owner.clone(),
            here.clone()
        )
        .await,
        "Tenant setup flows apply to descendant tenants"
    );
    assert_eq!(
        invalid(
            json!({ "tenantTypes": ["project"] }),
            owner.clone(),
            here.clone()
        )
        .await,
        "tenantTypes applies to flows that reach descendants"
    );
    assert_eq!(
        invalid(
            json!({ "appliesTo": "descendants", "tenantTypes": ["organization"] }),
            owner.clone(),
            here.clone()
        )
        .await,
        "tenantTypes: organization tenants cannot exist below a organization tenant"
    );
    assert_eq!(
        invalid(
            json!({ "appliesTo": "descendants", "completionGroupIds": ["group"] }),
            f.root_credential.clone(),
            f.root_tenant.clone()
        )
        .await,
        "completionGroupIds apply to member flows that reach the defining tenant\u{2019}s own people"
    );
}

#[test]
#[ignore = "needs parseAutoAssign (package-rules unit) to refuse identity.groups on a flow that reaches only descendants, and assertNoLegalHold (privacy unit) for identities.delete"]
fn validates_flows_versions_steps_and_cleans_up_progress() {
    run(|| async {
        let f = organization(attributes).await;
        let api = &f.iam.api.onboarding;
        let owner = f.owner_credential.clone();
        let alice = f.member("alice").await;
        let alice_token = f.sign_in(&alice).await;
        invalid_flows(&f, &alice_token).await;
        let group = ok(f
            .iam
            .api
            .groups
            .create(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "name": "Staff" })),
            )
            .await);
        let error = fails(
            api.create_flow(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id, "name": "Invalid", "audience": "member", "appliesTo": "descendants",
                    "steps": [{ "id": "hello", "kind": "task", "title": "Say hello" }],
                    "rule": { "include": [{ "ArrayContains": { "identity.groups": group["id"] } }] },
                })),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let flow = versions(&f, &alice_token).await;
        cleanup(&f, &alice, &flow).await;
    });
}

/// The middle of "validates flows, versions steps, and cleans up progress": names, versions and completion.
async fn versions(f: &Org, alice_token: &CredentialInput) -> Value {
    let api = &f.iam.api.onboarding;
    let owner = f.owner_credential.clone();
    let tenant_id = f.tenant_id.clone();
    let task = json!([{ "id": "hello", "kind": "task", "title": "Say hello" }]);
    let flow = ok(api
        .create_flow(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "Welcome", "audience": "member", "steps": task })),
        )
        .await);
    let error = fails(
        api.create_flow(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "welcome", "audience": "member", "steps": task })),
        )
        .await,
    );
    assert_eq!(code(&error), "CONFLICT");
    let renamed = ok(api
        .update_flow(
            &owner,
            body(json!({ "tenantId": tenant_id, "flowId": flow["id"], "name": "Welcome aboard" })),
        )
        .await);
    assert_eq!(renamed["version"], 1);
    ok(api
        .submit_step(
            alice_token,
            body(json!({ "tenantId": tenant_id, "flowId": flow["id"], "stepId": "hello" })),
        )
        .await);
    let extended = ok(api
        .update_flow(
            &owner,
            body(json!({
                "tenantId": tenant_id, "flowId": flow["id"],
                "steps": [task[0], { "id": "coffee", "kind": "task", "title": "Get coffee", "optional": true }],
            })),
        )
        .await);
    assert_eq!(extended["version"], 2);
    // Finished steps stay finished; the new step is optional, so the flow stays complete.
    let mine = ok(api
        .mine(alice_token, body(json!({ "tenantId": tenant_id })))
        .await);
    assert_matches(
        &mine["flows"][0],
        json!({ "complete": true, "done": 1, "total": 1 }),
    );
    flow
}

/// The end of "validates flows, versions steps, and cleans up progress": deleting a person, then the flow.
async fn cleanup(f: &Org, alice: &str, flow: &Value) {
    let api = &f.iam.api.onboarding;
    let owner = f.owner_credential.clone();
    let tenant_id = f.tenant_id.clone();
    // Deleting a person removes their progress, which holds their answers.
    let records = || {
        f.find(
            "onboardingProgress",
            Filter::new().eq("tenantId", tenant_id.clone()),
        )
    };
    assert_eq!(records().await.len(), 1);
    ok(f.iam
        .api
        .identities
        .delete(
            &owner,
            body(json!({ "tenantId": tenant_id, "identityId": alice })),
        )
        .await);
    assert!(records().await.is_empty());
    let second = ok(api
        .delete_flow(
            &owner,
            body(json!({ "tenantId": tenant_id, "flowId": flow["id"] })),
        )
        .await);
    assert_eq!(second, json!({ "deleted": true, "progressRemoved": 0 }));
}

/// "validates flows, versions steps, and cleans up progress" without the targeting-rule refusal (package-rules
/// unit) and the identity deletion (`identities.delete` needs assertNoLegalHold, privacy unit): deleting the flow
/// then removes Alice's progress with it.
#[test]
fn validates_flows_versions_steps_and_deletes_progress_with_the_flow() {
    run(|| async {
        let f = organization(attributes).await;
        let alice = f.member("alice").await;
        let alice_token = f.sign_in(&alice).await;
        invalid_flows(&f, &alice_token).await;
        let flow = versions(&f, &alice_token).await;
        let records = f
            .find(
                "onboardingProgress",
                Filter::new().eq("tenantId", f.tenant_id.clone()),
            )
            .await;
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0]["id"],
            json!(format!("{}:{alice}", flow["id"].as_str().unwrap()))
        );
        let deleted = ok(f
            .iam
            .api
            .onboarding
            .delete_flow(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "flowId": flow["id"] })),
            )
            .await);
        assert_eq!(deleted, json!({ "deleted": true, "progressRemoved": 1 }));
        let error = fails(
            f.iam
                .api
                .onboarding
                .get_flow(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "flowId": flow["id"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "NOT_FOUND");
    });
}

#[test]
fn serves_the_member_routes_over_http_and_refuses_role_sessions_and_impersonation() {
    run(|| async {
        let f = organization(|_| {}).await;
        let api = &f.iam.api.onboarding;
        let tenant_id = f.tenant_id.clone();
        let flow = ok(api
            .create_flow(
                &f.owner_credential,
                body(json!({
                    "tenantId": tenant_id, "name": "Hello", "audience": "member",
                    "steps": [{ "id": "hello", "kind": "acknowledge", "title": "Hello", "content": "Hi" }],
                })),
            )
            .await);
        let alice = f.member("alice").await;
        let alice_token = token(&f.sign_in(&alice).await);
        let (status, mine) = f
            .post(
                "onboarding/mine",
                &alice_token,
                json!({ "tenantId": tenant_id }),
            )
            .await;
        assert_eq!(status, 200, "{mine}");
        assert_eq!(names(&mine["data"]["flows"]), ["Hello"]);
        let (status, done) = f
            .post(
                "onboarding/submitStep",
                &alice_token,
                json!({ "tenantId": tenant_id, "flowId": flow["id"], "stepId": "hello", "acknowledged": true }),
            )
            .await;
        assert_eq!(status, 200, "{done}");
        assert_eq!(done["data"]["flow"]["complete"], true);

        ok(f.iam
            .api
            .tenants
            .set_auth_policy(
                &f.owner_credential,
                body(
                    json!({ "tenantId": tenant_id, "authPolicy": { "allowImpersonation": true } }),
                ),
            )
            .await);
        let owner_session = f.session(&f.owner_id, false).await;
        let view = ok(f
            .iam
            .api
            .identities
            .impersonate(
                &owner_session,
                body(json!({ "tenantId": tenant_id, "identityId": alice, "reason": "Support ticket 42" })),
            )
            .await);
        let view_credential = organization_fixture::bearer(view["token"].as_str().unwrap());
        let error = fails(
            api.submit_step(
                &view_credential,
                body(json!({ "tenantId": tenant_id, "flowId": flow["id"], "stepId": "hello", "acknowledged": true })),
            )
            .await,
        );
        assert_eq!(code(&error), "IMPERSONATION_RESTRICTED");
        // An administrator viewing as the member sees their checklist.
        let viewed = ok(api
            .mine(&view_credential, body(json!({ "tenantId": tenant_id })))
            .await);
        assert_eq!(viewed["flows"][0]["complete"], true);
    });
}

// ----- tests/security-org.test.ts: onboarding completion groups stand on grant authority -----

const ACKNOWLEDGE: &str =
    r#"[{ "id": "ok", "kind": "acknowledge", "title": "OK", "content": "Read this." }]"#;

fn acknowledge() -> Value {
    serde_json::from_str(ACKNOWLEDGE).unwrap()
}

/// A role with `permissions` bound to one person (as `roles.create` + `bindings.create`); returns the role.
async fn grant_permissions(f: &Org, identity_id: &str, permissions: &[&str]) -> String {
    f.grant(
        identity_id,
        json!([{ "effect": "allow", "actions": permissions, "resources": ["*"] }]),
    )
    .await
}

/// Binds a Writer role (documents:write) to a group under the owner's authority.
async fn allow_writes(f: &Org, group_id: &str) {
    let role = ok(f
        .iam
        .api
        .roles
        .create(
            &f.owner_credential,
            body(json!({ "tenantId": f.tenant_id, "name": format!("Writer {group_id}"), "permissions": ["documents:write"] })),
        )
        .await);
    ok(f.iam
        .api
        .bindings
        .create(
            &f.owner_credential,
            body(json!({ "tenantId": f.tenant_id, "roleId": role["id"], "subjectType": "group", "subjectId": group_id })),
        )
        .await);
}

async fn group_member_ids(f: &Org, group_id: &Value) -> Vec<Value> {
    ok(f.iam
        .api
        .groups
        .list_members(
            &f.owner_credential,
            body(json!({ "tenantId": f.tenant_id, "groupId": group_id })),
        )
        .await)
    .as_array()
    .unwrap()
    .iter()
    .map(|member| member["id"].clone())
    .collect()
}

#[test]
#[ignore = "needs assertNotTeamGroup/teamsSyncingFrom/teamChainBindings (teams unit), allow (packages unit) and parseAutoAssign (package-rules unit)"]
fn refuses_onboarding_manage_alone_changing_who_completes_a_flow_with_completion_groups() {
    run(|| async {
        let f = organization(|_| {}).await;
        let api = &f.iam.api.onboarding;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let mallory = f.member("mallory").await;
        grant_permissions(
            &f,
            &mallory,
            &["iam:onboarding:manage", "iam:onboarding:read"],
        )
        .await;
        let engineers = ok(f
            .iam
            .api
            .groups
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Engineers" })),
            )
            .await);
        allow_writes(&f, engineers["id"].as_str().unwrap()).await;
        f.advance(60_000.0); // Mallory predates the flow
        let flow = ok(api
            .create_flow(
                &owner,
                body(json!({
                    "tenantId": tenant_id, "name": "Engineering onboarding", "audience": "member",
                    "completionGroupIds": [engineers["id"]],
                    "steps": [{ "id": "laptop", "kind": "task", "title": "Collect your laptop", "verification": "admin" }],
                })),
            )
            .await);
        let m = f.sign_in(&mallory).await;
        let update = |changes: Value| {
            let mut request = json!({ "tenantId": tenant_id, "flowId": flow["id"] });
            for (key, value) in changes.as_object().unwrap() {
                request[key] = value.clone();
            }
            let m = m.clone();
            async move { api.update_flow(&m, body(request)).await }
        };
        for changes in [
            json!({ "includeExisting": true, "steps": acknowledge() }),
            json!({ "steps": acknowledge() }),
            json!({ "includeExisting": true }),
            json!({ "rule": { "include": [{ "StringEquals": { "principal.kind": "user" } }] } }),
            json!({ "appliesTo": "subtree" }),
        ] {
            assert_eq!(fails(update(changes).await).status, 403);
        }
        // Pausing hands nothing out; resuming does.
        ok(update(json!({ "enabled": false })).await);
        assert_eq!(fails(update(json!({ "enabled": true })).await).status, 403);
        ok(api
            .update_flow(
                &owner,
                body(json!({ "tenantId": tenant_id, "flowId": flow["id"], "enabled": true })),
            )
            .await);
        // Edits that leave who completes it alone still work, and the groups keep their owner.
        let renamed =
            ok(update(json!({ "name": "Engineering start", "description": "Day one" })).await);
        assert_matches(
            &renamed,
            json!({ "authorId": mallory, "groupsOwnerId": f.owner_id }),
        );
        // Naming the same groups again (as the console does) passes quietly without handing them over.
        let resaved =
            ok(update(json!({ "completionGroupIds": [engineers["id"]], "required": false })).await);
        assert_eq!(resaved["groupsOwnerId"], json!(f.owner_id));
        let mine = ok(api.mine(&m, body(json!({ "tenantId": tenant_id }))).await);
        assert_eq!(mine["flows"], json!([]));
        assert!(
            !group_member_ids(&f, &engineers["id"])
                .await
                .contains(&json!(mallory))
        );
        // The owner may widen the flow; the groups then stand on the owner's authority.
        let widened = ok(api
            .update_flow(
                &owner,
                body(
                    json!({ "tenantId": tenant_id, "flowId": flow["id"], "includeExisting": true }),
                ),
            )
            .await);
        assert_eq!(widened["groupsOwnerId"], json!(f.owner_id));
    });
}

#[test]
#[ignore = "needs assertNotTeamGroup/teamsSyncingFrom/teamChainBindings (teams unit), allow (packages unit), sodAssertIdentity (sod unit) and afterIdentityChange (package-automation unit)"]
fn applies_the_groups_under_the_owners_authority_and_skips_those_the_owner_lost() {
    run(|| async {
        let f = organization(|_| {}).await;
        let api = &f.iam.api.onboarding;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let ada = f.member("ada").await;
        let ada_role = grant_permissions(
            &f,
            &ada,
            &[
                "iam:onboarding:manage",
                "iam:onboarding:read",
                "iam:groups:update",
            ],
        )
        .await;
        let engineers = ok(f
            .iam
            .api
            .groups
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Engineers" })),
            )
            .await);
        let a = f.sign_in(&ada).await;
        let flow = ok(api
            .create_flow(
                &a,
                body(json!({
                    "tenantId": tenant_id, "name": "Welcome", "audience": "member",
                    "completionGroupIds": [engineers["id"]], "steps": acknowledge(),
                })),
            )
            .await);
        assert_eq!(flow["groupsOwnerId"], json!(ada));
        f.advance(1_000.0);
        let complete = |name: &'static str| {
            let f = &f;
            let flow_id = flow["id"].clone();
            let tenant_id = tenant_id.clone();
            async move {
                let id = f.member(name).await;
                let session = f.sign_in(&id).await;
                ok(f.iam
                    .api
                    .onboarding
                    .submit_step(
                        &session,
                        body(json!({ "tenantId": tenant_id, "flowId": flow_id, "stepId": "ok", "acknowledged": true })),
                    )
                    .await);
                session
            }
        };
        // While Ada may add people to the group, finishing the flow adds them.
        let bob = complete("bob").await;
        let mine = ok(api.mine(&bob, body(json!({ "tenantId": tenant_id }))).await);
        assert_eq!(mine["complete"], true);
        assert_eq!(group_member_ids(&f, &engineers["id"]).await.len(), 1);

        // Once she may not, the group is skipped, reported on the progress, and audited once.
        for binding in f
            .find("bindings", Filter::new().eq("roleId", ada_role.clone()))
            .await
        {
            ok(f.iam
                .api
                .bindings
                .delete(
                    &owner,
                    body(json!({ "tenantId": tenant_id, "bindingId": binding["id"] })),
                )
                .await);
        }
        let carol = complete("carol").await;
        ok(api
            .mine(&carol, body(json!({ "tenantId": tenant_id })))
            .await);
        assert_eq!(group_member_ids(&f, &engineers["id"]).await.len(), 1);
        let report = ok(api
            .progress(
                &owner,
                body(json!({ "tenantId": tenant_id, "flowId": flow["id"] })),
            )
            .await);
        let row = report["members"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["identity"]["name"] == "carol")
            .unwrap();
        assert_eq!(row["complete"], true);
        assert!(
            row["completionError"]
                .as_str()
                .unwrap()
                .contains("Completion groups skipped")
        );
        let skipped = ok(f
            .iam
            .api
            .audit
            .list(
                &owner,
                body(json!({ "tenantId": tenant_id, "action": "onboarding:groups-skipped" })),
            )
            .await);
        assert_eq!(skipped.as_array().unwrap().len(), 1);
        assert_matches(
            &skipped[0]["metadata"],
            json!({ "groupIds": [engineers["id"]], "ownerId": ada }),
        );
        // An administrator who may add people to it takes the groups over by naming them again.
        let retaken = ok(api
            .update_flow(
                &owner,
                body(json!({ "tenantId": tenant_id, "flowId": flow["id"], "completionGroupIds": [engineers["id"]] })),
            )
            .await);
        assert_eq!(retaken["groupsOwnerId"], json!(f.owner_id));
        ok(api
            .mine(&carol, body(json!({ "tenantId": tenant_id })))
            .await);
        assert_eq!(group_member_ids(&f, &engineers["id"]).await.len(), 2);
    });
}

#[test]
#[ignore = "needs assertNotTeamGroup/teamsSyncingFrom/teamChainBindings (teams unit), allow (packages unit), sodAssertIdentity (sod unit) and the invariants API (invariants unit)"]
fn keeps_enforced_access_invariants_for_completion_groups() {
    run(|| async {
        let f = organization(|_| {}).await;
        let api = &f.iam.api.onboarding;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let writers = ok(f
            .iam
            .api
            .groups
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Writers" })),
            )
            .await);
        allow_writes(&f, writers["id"].as_str().unwrap()).await;
        let flow = ok(api
            .create_flow(
                &owner,
                body(json!({
                    "tenantId": tenant_id, "name": "Welcome", "audience": "member",
                    "completionGroupIds": [writers["id"]], "steps": acknowledge(),
                })),
            )
            .await);
        f.advance(1_000.0);
        let bob = f.member("bob").await;
        ok(f.iam
            .api
            .invariants
            .create(
                &owner,
                body(json!({
                    "tenantId": tenant_id, "name": "Bob never writes", "subject": { "identityId": bob },
                    "action": "documents:write", "resource": { "type": "documents", "id": "a" },
                    "expect": "deny", "mode": "enforce",
                })),
            )
            .await);
        let b = f.sign_in(&bob).await;
        ok(api
            .submit_step(
                &b,
                body(json!({ "tenantId": tenant_id, "flowId": flow["id"], "stepId": "ok", "acknowledged": true })),
            )
            .await);
        assert!(group_member_ids(&f, &writers["id"]).await.is_empty());
        let report = ok(api
            .progress(
                &owner,
                body(json!({ "tenantId": tenant_id, "flowId": flow["id"] })),
            )
            .await);
        assert_eq!(report["members"][0]["complete"], true);
        assert!(
            report["members"][0]["completionError"]
                .as_str()
                .unwrap()
                .contains("Bob never writes")
        );
    });
}

#[test]
#[ignore = "needs assertNotTeamGroup/teamsSyncingFrom/teamChainBindings (teams unit), allow (packages unit), sodAssertIdentity (sod unit) and afterIdentityChange (package-automation unit)"]
fn refuses_resetting_ones_own_progress_to_rejoin_a_completion_group() {
    run(|| async {
        let f = organization(|_| {}).await;
        let api = &f.iam.api.onboarding;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let writers = ok(f
            .iam
            .api
            .groups
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Writers" })),
            )
            .await);
        allow_writes(&f, writers["id"].as_str().unwrap()).await;
        let flow = ok(api
            .create_flow(
                &owner,
                body(json!({
                    "tenantId": tenant_id, "name": "Welcome", "audience": "member",
                    "completionGroupIds": [writers["id"]], "steps": acknowledge(),
                })),
            )
            .await);
        f.advance(1_000.0);
        let mallory = f.member("mallory").await;
        grant_permissions(
            &f,
            &mallory,
            &["iam:onboarding:manage", "iam:onboarding:read"],
        )
        .await;
        let m = f.sign_in(&mallory).await;
        ok(api
            .submit_step(
                &m,
                body(json!({ "tenantId": tenant_id, "flowId": flow["id"], "stepId": "ok", "acknowledged": true })),
            )
            .await);
        assert_eq!(
            group_member_ids(&f, &writers["id"]).await,
            vec![json!(mallory)]
        );
        // An administrator takes her out of the group again.
        ok(f.iam
            .api
            .groups
            .remove_member(
                &owner,
                body(json!({ "tenantId": tenant_id, "groupId": writers["id"], "identityId": mallory })),
            )
            .await);
        let error = fails(
            api.reset_progress(
                &m,
                body(json!({ "tenantId": tenant_id, "flowId": flow["id"], "subjectId": mallory })),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            api.reset_progress(
                &m,
                body(json!({ "tenantId": tenant_id, "flowId": flow["id"] })),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        ok(api.mine(&m, body(json!({ "tenantId": tenant_id }))).await);
        assert!(group_member_ids(&f, &writers["id"]).await.is_empty());
        // Administrators still reset anyone.
        let reset = ok(api
            .reset_progress(
                &owner,
                body(json!({ "tenantId": tenant_id, "flowId": flow["id"], "subjectId": mallory })),
            )
            .await);
        assert_eq!(reset, json!({ "reset": 1 }));
    });
}
