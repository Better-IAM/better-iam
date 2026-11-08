//! Configuration as code (`config.export`, `config.plan`, `config.apply`). Ported from tests/config-sync.test.ts,
//! tests/config-governance.test.ts, tests/security-sync.test.ts and the configuration parts of
//! tests/config-review.test.ts.

mod organization_fixture;

use better_iam_core::{
    CredentialInput, Filter, IamResult, PermissionsConfig, PermissionsMode, js as core_js,
};
use better_iam_server::api::Reply;
use organization_fixture::{Org, assert_matches, body, fails, ok, organization, run};
use serde_json::{Value, json};

async fn plan(f: &Org, credential: &CredentialInput, input: Value) -> IamResult<Value> {
    f.iam
        .api
        .config
        .plan(credential, body(input))
        .await
        .and_then(Reply::into_value)
}

async fn apply(f: &Org, credential: &CredentialInput, input: Value) -> IamResult<Value> {
    f.iam
        .api
        .config
        .apply(credential, body(input))
        .await
        .and_then(Reply::into_value)
}

async fn export(f: &Org, credential: &CredentialInput, tenant_id: &str) -> Value {
    ok(f.iam
        .api
        .config
        .export(credential, body(json!({ "tenantId": tenant_id })))
        .await)
}

/// `${change.action} ${change.kind} ${change.name}` for every change of a plan.
fn change_lines(plan: &Value) -> Vec<String> {
    plan["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|change| {
            format!(
                "{} {} {}",
                change["action"].as_str().unwrap(),
                change["kind"].as_str().unwrap(),
                change["name"].as_str().unwrap()
            )
        })
        .collect()
}

fn changes_of<'a>(plan: &'a Value, kind: &str) -> Vec<&'a Value> {
    plan["changes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|change| change["kind"] == kind)
        .collect()
}

fn summary(create: u32, update: u32, delete: u32, unchanged: u32) -> Value {
    json!({ "create": create, "update": update, "delete": delete, "unchanged": unchanged })
}

fn names(list: &Value) -> Vec<String> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|item| item["name"].as_str().unwrap().to_owned())
        .collect()
}

fn sorted(mut items: Vec<String>) -> Vec<String> {
    items.sort();
    items
}

fn assert_same(actual: &Value, expected: &Value) {
    assert!(
        core_js::deep_equal(actual, expected),
        "\n  actual:   {}\n  expected: {}",
        core_js::stringify(actual),
        core_js::stringify(expected)
    );
}

fn desired() -> Value {
    json!({
        "version": 1,
        "resourceTypes": [
            {
                "name": "project",
                "description": "A project",
                "actions": ["read", "write"],
                "attributes": { "archived": "boolean" },
                "relations": ["viewer"],
            },
        ],
        "policies": [
            {
                "name": "Readers",
                "document": {
                    "version": 1,
                    "statements": [
                        { "effect": "allow", "actions": ["documents:read", "project:read"], "resources": ["*"] },
                    ],
                },
            },
        ],
        "roles": [
            { "name": "Reader", "description": "Reads", "policies": ["Readers"] },
            { "name": "Editor", "permissions": ["documents:write", "project:write"] },
        ],
        "groups": [{ "name": "Engineering", "members": ["alice@acme.test"] }],
        "bindings": [
            { "group": "Engineering", "role": "Reader" },
            {
                "group": "Engineering",
                "role": "Editor",
                "eligible": true,
                "maxActivationMs": 600_000,
                "requireJustification": true,
            },
        ],
    })
}

async fn tenant_defined_fixture() -> Org {
    let f = organization(|options| {
        options.permissions = Some(PermissionsConfig {
            mode: Some(PermissionsMode::TenantDefined),
            actions: Some(vec!["documents:read".into(), "documents:write".into()]),
            ..PermissionsConfig::default()
        });
    })
    .await;
    f.member("alice").await;
    f.member("bob").await;
    f
}

async fn list(f: &Org, group: &str, input: Value) -> Value {
    let owner = &f.owner_credential;
    let api = &f.iam.api;
    match group {
        "roles" => ok(api.roles.list(owner, body(input)).await),
        "policies" => ok(api.policies.list(owner, body(input)).await),
        "groups" => ok(api.groups.list(owner, body(input)).await),
        "groupMembers" => ok(api.groups.list_members(owner, body(input)).await),
        "bindings" => ok(api.bindings.list(owner, body(input)).await),
        "audit" => ok(api.audit.list(owner, body(input)).await),
        "invariants" => ok(api.invariants.list(owner, body(input)).await),
        "agreements" => ok(api.agreements.list(owner, body(input)).await),
        "packages" => ok(api.packages.list(owner, body(input)).await),
        _ => unreachable!("{group}"),
    }
}

#[test]
fn plans_applies_exports_and_converges_a_tenant_configuration() {
    run(|| async {
        let f = tenant_defined_fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let planned = plan(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": desired() }),
        )
        .await
        .unwrap();
        assert_same(&planned["summary"], &summary(7, 0, 0, 0));
        assert_eq!(
            change_lines(&planned),
            [
                "create resourceType project",
                "create policy Readers",
                "create role Editor",
                "create role Reader",
                "create group Engineering",
                "create binding Engineering -> Editor",
                "create binding Engineering -> Reader",
            ]
        );
        // A plan writes nothing.
        assert_eq!(
            names(&list(&f, "roles", json!({ "tenantId": tenant_id })).await),
            ["Owner"]
        );
        let applied = apply(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": desired() }),
        )
        .await
        .unwrap();
        assert_eq!(applied["applied"], true);
        assert_same(&applied["summary"], &planned["summary"]);
        let roles = list(&f, "roles", json!({ "tenantId": tenant_id })).await;
        assert_eq!(sorted(names(&roles)), ["Editor", "Owner", "Reader"]);
        let reader = roles
            .as_array()
            .unwrap()
            .iter()
            .find(|role| role["name"] == "Reader")
            .unwrap()
            .clone();
        let policies = list(&f, "policies", json!({ "tenantId": tenant_id })).await;
        let readers = policies
            .as_array()
            .unwrap()
            .iter()
            .find(|policy| policy["name"] == "Readers")
            .unwrap()
            .clone();
        assert_eq!(reader["policyIds"], json!([readers["id"]]));
        let groups = list(&f, "groups", json!({ "tenantId": tenant_id })).await;
        let engineering = groups[0].clone();
        let members = list(
            &f,
            "groupMembers",
            json!({ "tenantId": tenant_id, "groupId": engineering["id"] }),
        )
        .await;
        let emails: Vec<&str> = members
            .as_array()
            .unwrap()
            .iter()
            .map(|member| member["email"].as_str().unwrap())
            .collect();
        assert_eq!(emails, ["alice@acme.test"]);
        let eligible = list(
            &f,
            "bindings",
            json!({ "tenantId": tenant_id, "eligible": true }),
        )
        .await;
        assert_eq!(eligible.as_array().unwrap().len(), 1);
        assert_matches(
            &eligible[0],
            json!({ "subjectId": engineering["id"], "maxActivationMs": 600_000, "requireJustification": true }),
        );
        let project = ok(f
            .iam
            .api
            .resource_types
            .get(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "project" })),
            )
            .await);
        let mut actions: Vec<String> = project["actions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|action| action.as_str().unwrap().to_owned())
            .collect();
        actions.sort();
        assert_eq!(actions, ["project:read", "project:write"]);
        // The trail records the apply with its summary.
        let trail = list(
            &f,
            "audit",
            json!({ "tenantId": tenant_id, "action": "config:apply" }),
        )
        .await;
        assert_matches(
            &trail[0]["metadata"],
            json!({ "create": 7, "prune": false }),
        );
        // Export round-trips, and applying the export changes nothing.
        let exported = export(&f, &owner, &tenant_id).await;
        assert_same(
            &exported,
            &json!({
                "version": 1,
                "resourceTypes": [
                    {
                        "name": "project",
                        "description": "A project",
                        "actions": ["read", "write"],
                        "attributes": { "archived": "boolean" },
                        "relations": ["viewer"],
                    },
                ],
                "policies": [{ "name": "Readers", "document": desired()["policies"][0]["document"] }],
                "roles": [
                    { "name": "Editor", "policies": [], "permissions": ["documents:write", "project:write"] },
                    { "name": "Reader", "description": "Reads", "policies": ["Readers"] },
                ],
                "groups": [{ "name": "Engineering", "members": ["alice@acme.test"] }],
                "bindings": [
                    {
                        "group": "Engineering",
                        "role": "Editor",
                        "eligible": true,
                        "maxActivationMs": 600_000,
                        "requireJustification": true,
                    },
                    { "group": "Engineering", "role": "Reader" },
                ],
                "packages": [],
            }),
        );
        let again = apply(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": exported }),
        )
        .await
        .unwrap();
        assert_same(&again["summary"], &summary(0, 0, 0, 7));
        // Drift: change permissions and membership, drop the Reader role; prune decides about deletions.
        let next = json!({
            "version": 1,
            "roles": [
                { "name": "Editor", "permissions": ["documents:read", "documents:write", "project:write"] },
            ],
            "groups": [{ "name": "Engineering", "members": ["alice@acme.test", "bob@acme.test"] }],
            "bindings": [{ "group": "Engineering", "role": "Editor" }],
        });
        let keep = plan(&f, &owner, json!({ "tenantId": tenant_id, "config": next }))
            .await
            .unwrap();
        assert_same(&keep["summary"], &summary(0, 3, 0, 0));
        assert_matches(
            changes_of(&keep, "role")[0],
            json!({ "action": "update", "fields": ["document"] }),
        );
        assert_matches(
            changes_of(&keep, "group")[0],
            json!({ "action": "update", "fields": ["members"] }),
        );
        assert_matches(
            changes_of(&keep, "binding")[0],
            json!({ "action": "update", "fields": ["eligible", "maxActivationMs", "requireJustification"] }),
        );
        let pruned = plan(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": next, "prune": true }),
        )
        .await
        .unwrap();
        assert_same(&pruned["summary"], &summary(0, 3, 2, 0));
        let deletions: Vec<String> = pruned["changes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|change| change["action"] == "delete")
            .map(|change| {
                format!(
                    "{} {}",
                    change["kind"].as_str().unwrap(),
                    change["name"].as_str().unwrap()
                )
            })
            .collect();
        assert_eq!(deletions, ["role Reader", "binding Engineering -> Reader"]);
        let result = apply(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": next, "prune": true }),
        )
        .await
        .unwrap();
        assert_same(&result["summary"], &pruned["summary"]);
        assert_eq!(
            sorted(names(
                &list(&f, "roles", json!({ "tenantId": tenant_id })).await
            )),
            ["Editor", "Owner"]
        );
        let members = list(
            &f,
            "groupMembers",
            json!({ "tenantId": tenant_id, "groupId": engineering["id"] }),
        )
        .await;
        let emails: Vec<String> = sorted(
            members
                .as_array()
                .unwrap()
                .iter()
                .map(|member| member["email"].as_str().unwrap().to_owned())
                .collect(),
        );
        assert_eq!(emails, ["alice@acme.test", "bob@acme.test"]);
        assert_eq!(
            list(
                &f,
                "bindings",
                json!({ "tenantId": tenant_id, "eligible": true })
            )
            .await,
            json!([])
        );
        // Policies were not listed, so the policy survived; a later prune with policies: [] removes it.
        assert!(
            names(&list(&f, "policies", json!({ "tenantId": tenant_id })).await)
                .contains(&"Readers".to_owned())
        );
        let cleared = apply(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": { "version": 1, "policies": [] }, "prune": true }),
        )
        .await
        .unwrap();
        assert_same(&cleared["summary"], &summary(0, 0, 1, 0));
        assert_eq!(
            names(&list(&f, "policies", json!({ "tenantId": tenant_id })).await),
            ["Owner"]
        );
        // A resource type whose actions a role still names cannot be pruned; nothing else is touched.
        let error = apply(
            &f,
            &owner,
            json!({
                "tenantId": tenant_id,
                "config": { "version": 1, "resourceTypes": [], "groups": [] },
                "prune": true,
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "RESOURCE_IN_USE", "{error:?}");
        assert_eq!(
            names(&list(&f, "groups", json!({ "tenantId": tenant_id })).await),
            ["Engineering"]
        );
    });
}

#[test]
fn rejects_malformed_or_dangling_configurations_and_applies_atomically_under_authorization() {
    run(|| async {
        let f = tenant_defined_fixture().await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        for config in [
            json!({ "version": 2 }),
            json!({ "version": 1, "roles": [{ "name": "A" }, { "name": "A" }] }),
            json!({ "version": 1, "roles": [{ "name": "A", "policies": ["Missing"] }] }),
            json!({ "version": 1, "groups": [{ "name": "G", "members": ["nobody@acme.test"] }] }),
            json!({ "version": 1, "bindings": [{ "group": "G", "role": "R" }] }),
            json!({
                "version": 1,
                "roles": [{ "name": "A", "permissions": ["x"], "document": { "version": 1, "statements": [] } }],
            }),
        ] {
            let error = plan(
                &f,
                &owner,
                json!({ "tenantId": tenant_id, "config": config }),
            )
            .await
            .unwrap_err();
            assert_eq!(error.code, "INVALID_INPUT", "{config}: {error:?}");
        }
        // Unknown actions are refused by the catalog, like a direct create.
        let error = apply(
            &f,
            &owner,
            json!({
                "tenantId": tenant_id,
                "config": { "version": 1, "roles": [{ "name": "A", "permissions": ["nope:read"] }] },
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "INVALID_ACTION", "{error:?}");
        // Members without the config permissions are refused at the door.
        let identities = ok(f
            .iam
            .api
            .identities
            .list(
                &owner,
                body(json!({ "tenantId": tenant_id, "query": "alice" })),
            )
            .await);
        let alice_id = identities[0]["id"].as_str().unwrap().to_owned();
        let as_alice = f.sign_in(&alice_id).await;
        let error = plan(
            &f,
            &as_alice,
            json!({ "tenantId": tenant_id, "config": { "version": 1 } }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "ACCESS_DENIED");
        // Holding iam:config:apply is not enough: each change needs the equivalent direct permission, and one refusal
        // rolls the whole apply back.
        let operator = ok(f
            .iam
            .api
            .roles
            .create(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "Config operator",
                    "permissions": ["iam:config:read", "iam:config:apply", "iam:groups:create"],
                })),
            )
            .await);
        ok(f.iam
            .api
            .bindings
            .create(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "roleId": operator["id"],
                    "subjectType": "identity",
                    "subjectId": alice_id,
                })),
            )
            .await);
        let config = json!({
            "version": 1,
            "groups": [{ "name": "Ops" }],
            "roles": [{ "name": "X", "permissions": ["documents:read"] }],
        });
        let planned = plan(
            &f,
            &as_alice,
            json!({ "tenantId": tenant_id, "config": config }),
        )
        .await
        .unwrap();
        assert_eq!(planned["summary"]["create"], 2);
        let error = apply(
            &f,
            &as_alice,
            json!({ "tenantId": tenant_id, "config": config }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "ACCESS_DENIED");
        assert_eq!(
            list(&f, "groups", json!({ "tenantId": tenant_id })).await,
            json!([])
        );
        // The HTTP route serves the group like any other.
        let (status, response) = f
            .post(
                "config/plan",
                owner.token.as_deref().unwrap(),
                json!({ "tenantId": tenant_id, "config": { "version": 1, "groups": [{ "name": "Ops" }] } }),
            )
            .await;
        assert_eq!(status, 200, "{response}");
        assert_eq!(response["data"]["summary"]["create"], 1);
    });
}

#[test]
fn exports_plans_applies_and_prunes_invariants_and_agreements_by_name() {
    run(|| async {
        let f = organization(|_| {}).await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let alice = f.member("alice").await;
        // A tenant without either kind exports neither key.
        let empty = export(&f, &owner, &tenant_id).await;
        assert!(empty.get("invariants").is_none());
        assert!(empty.get("agreements").is_none());

        let contractors = json!({
            "name": "Contractors never write d1",
            "subject": { "group": "Contractors" },
            "action": "documents:write",
            "resource": { "type": "document", "id": "d1" },
            "expect": "deny",
            "mode": "enforce",
        });
        let reads_nothing = json!({
            "name": "Alice reads nothing",
            "subject": { "identity": "ALICE@acme.test" },
            "action": "documents:read",
            "resource": { "type": "document", "id": "d1" },
            "expect": "deny",
        });
        let document = json!({
            "version": 1,
            "groups": [{ "name": "Contractors", "members": ["alice@acme.test"] }],
            "agreements": [{ "name": "Acceptable use", "content": "Be nice.\nReally." }],
            "invariants": [contractors, reads_nothing],
        });
        let planned = plan(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": document }),
        )
        .await
        .unwrap();
        assert_eq!(
            change_lines(&planned),
            [
                "create group Contractors",
                "create agreement Acceptable use",
                "create invariant Alice reads nothing",
                "create invariant Contractors never write d1",
            ]
        );
        apply(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": document }),
        )
        .await
        .unwrap();
        let invariants = list(&f, "invariants", json!({ "tenantId": tenant_id })).await;
        let modes: Vec<(String, String)> = invariants
            .as_array()
            .unwrap()
            .iter()
            .map(|invariant| {
                (
                    invariant["name"].as_str().unwrap().to_owned(),
                    invariant["mode"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert_eq!(
            modes,
            [
                ("Alice reads nothing".to_owned(), "monitor".to_owned()),
                (
                    "Contractors never write d1".to_owned(),
                    "enforce".to_owned()
                ),
            ]
        );
        assert_eq!(invariants[0]["subject"], json!({ "identityId": alice }));
        // The applied invariant is enforced right away.
        let writer = ok(f
            .iam
            .api
            .roles
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Writer", "permissions": ["documents:write"] })),
            )
            .await);
        let error = fails(
            f.iam
                .api
                .bindings
                .create(
                    &owner,
                    body(json!({
                        "tenantId": tenant_id,
                        "roleId": writer["id"],
                        "subjectType": "identity",
                        "subjectId": alice,
                    })),
                )
                .await,
        );
        assert_eq!(error.code, "INVARIANT_VIOLATION");

        // Round trip: the export applies with no changes.
        let exported = export(&f, &owner, &tenant_id).await;
        assert!(
            exported["invariants"]
                .as_array()
                .unwrap()
                .iter()
                .any(|invariant| core_js::deep_equal(
                    invariant,
                    &json!({
                        "name": "Contractors never write d1",
                        "subject": { "group": "Contractors" },
                        "action": "documents:write",
                        "resource": { "type": "document", "id": "d1" },
                        "expect": "deny",
                        "mode": "enforce",
                        "assumeMfa": true,
                    })
                )),
            "{}",
            exported["invariants"]
        );
        assert_same(
            &exported["agreements"],
            &json!([{ "name": "Acceptable use", "content": "Be nice.\nReally.", "required": true }]),
        );
        let again = plan(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": exported }),
        )
        .await
        .unwrap();
        assert_matches(
            &again["summary"],
            json!({ "create": 0, "update": 0, "delete": 0 }),
        );

        // A content change publishes a new version; a URL change does not.
        let agreement = list(&f, "agreements", json!({ "tenantId": tenant_id })).await[0].clone();
        apply(
            &f,
            &owner,
            json!({
                "tenantId": tenant_id,
                "config": {
                    "version": 1,
                    "agreements": [
                        { "name": "Acceptable use", "content": "Be nice.\nReally.", "url": "https://acme.test/aup" },
                    ],
                },
            }),
        )
        .await
        .unwrap();
        assert_eq!(
            list(&f, "agreements", json!({ "tenantId": tenant_id })).await[0]["version"],
            agreement["version"]
        );
        let edited_config = json!({
            "version": 1,
            "agreements": [{ "name": "Acceptable use", "content": "Be kind." }],
        });
        let edited = plan(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": edited_config }),
        )
        .await
        .unwrap();
        assert_matches(
            &edited["changes"][0],
            json!({ "kind": "agreement", "action": "update", "fields": ["content", "url"] }),
        );
        apply(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": edited_config }),
        )
        .await
        .unwrap();
        let current = list(&f, "agreements", json!({ "tenantId": tenant_id })).await[0].clone();
        assert_matches(
            &current,
            json!({ "version": agreement["version"].as_f64().unwrap() + 1.0, "content": "Be kind." }),
        );
        assert!(current.get("url").is_none());

        // Invariant updates and pruning.
        let mut monitored = contractors.clone();
        monitored["mode"] = json!("monitor");
        apply(
            &f,
            &owner,
            json!({
                "tenantId": tenant_id,
                "prune": true,
                "config": { "version": 1, "invariants": [monitored], "agreements": [] },
            }),
        )
        .await
        .unwrap();
        let invariants = list(&f, "invariants", json!({ "tenantId": tenant_id })).await;
        assert_eq!(invariants.as_array().unwrap().len(), 1);
        assert_matches(
            &invariants[0],
            json!({ "name": "Contractors never write d1", "mode": "monitor" }),
        );
        assert_eq!(
            list(&f, "agreements", json!({ "tenantId": tenant_id })).await,
            json!([])
        );

        // References are checked while planning.
        let mut nobody = contractors.clone();
        nobody["subject"] = json!({ "group": "Nobody" });
        let mut ghost = reads_nothing.clone();
        ghost["subject"] = json!({ "identity": "ghost@acme.test" });
        for config in [
            json!({ "version": 1, "invariants": [nobody] }),
            json!({ "version": 1, "invariants": [ghost] }),
            json!({
                "version": 1,
                "agreements": [{ "name": "A", "content": "x" }, { "name": "a", "content": "y" }],
            }),
        ] {
            let error = plan(
                &f,
                &owner,
                json!({ "tenantId": tenant_id, "config": config }),
            )
            .await
            .unwrap_err();
            assert_eq!(error.code, "INVALID_INPUT", "{error:?}");
        }
    });
}

async fn security_setup() -> (Org, CredentialInput, Value) {
    let f = organization(|_| {}).await;
    let owner = f.sign_in(&f.owner_id.clone()).await;
    let writer = ok(f
        .iam
        .api
        .roles
        .create(
            &owner,
            body(json!({ "tenantId": f.tenant_id, "name": "Writer", "permissions": ["documents:write"] })),
        )
        .await);
    (f, owner, writer)
}

#[test]
fn binds_the_administrators_group_never_a_directory_group_that_took_its_name() {
    run(|| async {
        let (f, owner, _writer) = security_setup().await;
        let tenant_id = f.tenant_id.clone();
        let admins = ok(f
            .iam
            .api
            .groups
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Admins" })),
            )
            .await);
        // An identity provider pushes its own "Admins" group through SCIM.
        let planted = better_iam_server::utils::id();
        f.insert(
            "groups",
            json!({ "id": planted, "tenantId": tenant_id, "name": "Admins", "createdAt": 1 }),
        )
        .await;
        f.insert(
            "scimGroups",
            json!({
                "id": better_iam_server::utils::id(),
                "tenantId": tenant_id,
                "connectionId": "idp",
                "groupId": planted,
                "displayName": "Admins",
                "members": [],
                "version": 1,
                "createdAt": 1,
                "updatedAt": 1,
            }),
        )
        .await;
        apply(
            &f,
            &owner,
            json!({
                "tenantId": tenant_id,
                "config": {
                    "version": 1,
                    "roles": [{ "name": "Writer", "permissions": ["documents:write"] }],
                    "groups": [{ "name": "Admins" }],
                    "bindings": [{ "group": "Admins", "role": "Writer" }],
                },
            }),
        )
        .await
        .unwrap();
        let bound = f
            .find(
                "bindings",
                Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq("subjectType", "group"),
            )
            .await;
        let subjects: Vec<&Value> = bound.iter().map(|binding| &binding["subjectId"]).collect();
        assert_eq!(subjects, [&admins["id"]]);
    });
}

#[test]
fn keeps_a_team_approver_group_and_the_dates_of_a_temporary_grant_when_it_replaces_a_binding() {
    run(|| async {
        let (f, owner, writer) = security_setup().await;
        let tenant_id = f.tenant_id.clone();
        let oncall = ok(f
            .iam
            .api
            .groups
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "On-call" })),
            )
            .await);
        // A team's backing group, which configuration never exports or manages.
        let team_group = better_iam_server::utils::id();
        f.insert(
            "groups",
            json!({
                "id": team_group,
                "tenantId": tenant_id,
                "name": "Team: Payments",
                "teamId": "team-payments",
                "createdAt": 1,
            }),
        )
        .await;
        let expires_at = f.now() + 30.0 * 86_400_000.0;
        let original = ok(f
            .iam
            .api
            .bindings
            .create(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "roleId": writer["id"],
                    "subjectType": "group",
                    "subjectId": oncall["id"],
                    "eligible": true,
                    "requireApproval": true,
                    "approverGroupId": team_group,
                    "expiresAt": expires_at,
                })),
            )
            .await);
        apply(
            &f,
            &owner,
            json!({
                "tenantId": tenant_id,
                "config": {
                    "version": 1,
                    "roles": [{ "name": "Writer", "permissions": ["documents:write"] }],
                    "groups": [{ "name": "On-call" }],
                    "bindings": [
                        {
                            "group": "On-call",
                            "role": "Writer",
                            "eligible": true,
                            "requireApproval": true,
                            "requireJustification": true,
                        },
                    ],
                },
            }),
        )
        .await
        .unwrap();
        let replaced = f
            .find(
                "bindings",
                Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq("subjectType", "group")
                    .eq("subjectId", oncall["id"].clone()),
            )
            .await;
        let replaced = Value::Object(replaced[0].clone());
        assert_ne!(replaced["id"], original["id"]);
        assert_matches(
            &replaced,
            json!({ "requireJustification": true, "approverGroupId": team_group, "expiresAt": expires_at }),
        );
    });
}

async fn review_setup() -> (Org, String, CredentialInput, Value) {
    let f = organization(|_| {}).await;
    let tenant_id = f.tenant_id.clone();
    let owner = f.owner_credential.clone();
    let reader = ok(f
        .iam
        .api
        .roles
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "Reader", "permissions": ["documents:read"] })),
        )
        .await);
    (f, tenant_id, owner, reader)
}

async fn create_package(f: &Org, owner: &CredentialInput, input: Value) -> Value {
    ok(f.iam.api.packages.create(owner, body(input)).await)
}

#[test]
fn treats_a_null_package_max_duration_as_no_cap_and_converges() {
    run(|| async {
        let (f, tenant_id, owner, reader) = review_setup().await;
        let kit = create_package(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "name": "Kit", "roleIds": [reader["id"]] }),
        )
        .await;
        let capped = create_package(
            &f,
            &owner,
            json!({
                "tenantId": tenant_id,
                "name": "Capped",
                "roleIds": [reader["id"]],
                "maxDurationMs": 30.0 * 86_400_000.0,
            }),
        )
        .await;
        let config = json!({
            "version": 1,
            "packages": [
                { "name": "Capped", "roles": ["Reader"], "maxDurationMs": null },
                { "name": "Fresh", "roles": ["Reader"], "maxDurationMs": null },
                { "name": "Kit", "roles": ["Reader"], "maxDurationMs": null },
            ],
        });
        // An uncapped package is unchanged; a capped one loses its cap; a new one is created uncapped.
        let planned = plan(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": config }),
        )
        .await
        .unwrap();
        assert_same(&planned["summary"], &summary(1, 1, 0, 1));
        let packages = changes_of(&planned, "package");
        assert_matches(
            packages[0],
            json!({ "name": "Capped", "action": "update", "fields": ["maxDurationMs"] }),
        );
        assert_matches(packages[1], json!({ "name": "Fresh", "action": "create" }));
        assert_same(
            packages[2],
            &json!({ "kind": "package", "name": "Kit", "action": "unchanged" }),
        );
        f.advance(1000.0);
        let applied = apply(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": config }),
        )
        .await
        .unwrap();
        assert_same(&applied["summary"], &planned["summary"]);
        let listed = list(&f, "packages", json!({ "tenantId": tenant_id })).await;
        assert_eq!(names(&listed), ["Capped", "Fresh", "Kit"]);
        for pkg in listed.as_array().unwrap() {
            assert!(pkg.get("maxDurationMs").is_none());
        }
        // The unchanged package was not rewritten.
        let kit_now = ok(f
            .iam
            .api
            .packages
            .get(
                &owner,
                body(json!({ "tenantId": tenant_id, "packageId": kit["id"] })),
            )
            .await);
        assert_eq!(kit_now["updatedAt"], kit["updatedAt"]);
        let capped_now = ok(f
            .iam
            .api
            .packages
            .get(
                &owner,
                body(json!({ "tenantId": tenant_id, "packageId": capped["id"] })),
            )
            .await);
        assert!(capped_now.get("maxDurationMs").is_none());
        // Repeated applies are no-ops.
        for _ in 0..2 {
            f.advance(1000.0);
            let again = apply(
                &f,
                &owner,
                json!({ "tenantId": tenant_id, "config": config }),
            )
            .await
            .unwrap();
            assert_same(&again["summary"], &summary(0, 0, 0, 3));
        }
        let trail = list(
            &f,
            "audit",
            json!({ "tenantId": tenant_id, "action": "config:apply" }),
        )
        .await;
        assert_eq!(trail.as_array().unwrap().len(), 3);
        // The first apply changed two packages; the repeats changed nothing.
        let mut changed: Vec<usize> = trail
            .as_array()
            .unwrap()
            .iter()
            .map(|event| event["metadata"]["changed"].as_array().unwrap().len())
            .collect();
        changed.sort();
        assert_eq!(changed, [0, 0, 2]);
        let last = plan(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": config }),
        )
        .await
        .unwrap();
        assert_same(&last["summary"], &summary(0, 0, 0, 3));
    });
}

#[test]
fn rejects_a_string_or_out_of_range_package_max_duration_at_plan_time() {
    run(|| async {
        let (f, tenant_id, owner, reader) = review_setup().await;
        create_package(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "name": "Kit", "roleIds": [reader["id"]] }),
        )
        .await;
        for max_duration in [
            json!("2592000000"),
            json!(59_999),
            json!(0),
            json!(-1),
            json!(1.5),
            json!(315_360_000_001_i64),
            json!(9_007_199_254_740_993_f64),
            json!(true),
            json!({}),
        ] {
            for name in ["Kit", "New"] {
                let config = json!({
                    "version": 1,
                    "packages": [{ "name": name, "roles": ["Reader"], "maxDurationMs": max_duration }],
                });
                let error = plan(
                    &f,
                    &owner,
                    json!({ "tenantId": tenant_id, "config": config }),
                )
                .await
                .unwrap_err();
                assert_eq!(error.code, "INVALID_INPUT", "plan {name} {max_duration}");
                assert!(error.message.contains("maxDurationMs"), "{}", error.message);
                let error = apply(
                    &f,
                    &owner,
                    json!({ "tenantId": tenant_id, "config": config }),
                )
                .await
                .unwrap_err();
                assert_eq!(error.code, "INVALID_INPUT", "apply {name} {max_duration}");
            }
        }
        // The bounds themselves are accepted.
        for max_duration in [60_000.0, 315_360_000_000.0] {
            let planned = plan(
                &f,
                &owner,
                json!({
                    "tenantId": tenant_id,
                    "config": {
                        "version": 1,
                        "packages": [{ "name": "Kit", "roles": ["Reader"], "maxDurationMs": max_duration }],
                    },
                }),
            )
            .await
            .unwrap();
            assert_eq!(planned["summary"]["update"], 1);
        }
        let listed = list(&f, "packages", json!({ "tenantId": tenant_id })).await;
        assert_eq!(names(&listed), ["Kit"]);
        assert!(listed[0].get("maxDurationMs").is_none());
    });
}

#[test]
fn treats_a_null_binding_max_activation_as_no_cap_and_rejects_bad_values_at_plan_time() {
    run(|| async {
        let (f, tenant_id, owner, reader) = review_setup().await;
        ok(f.iam
            .api
            .groups
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Engineering" })),
            )
            .await);
        let ops = ok(f
            .iam
            .api
            .groups
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Ops" })),
            )
            .await);
        ok(f.iam
            .api
            .bindings
            .create(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "roleId": reader["id"],
                    "subjectType": "group",
                    "subjectId": ops["id"],
                    "eligible": true,
                    "maxActivationMs": 600_000,
                })),
            )
            .await);
        let config = json!({
            "version": 1,
            "bindings": [
                { "group": "Engineering", "role": "Reader", "eligible": true, "maxActivationMs": null },
                { "group": "Ops", "role": "Reader", "eligible": true, "maxActivationMs": null },
            ],
        });
        let planned = plan(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": config }),
        )
        .await
        .unwrap();
        assert_same(&planned["summary"], &summary(1, 1, 0, 0));
        let bindings = changes_of(&planned, "binding");
        assert_matches(
            bindings[0],
            json!({ "name": "Engineering -> Reader", "action": "create" }),
        );
        assert_matches(
            bindings[1],
            json!({ "name": "Ops -> Reader", "action": "update", "fields": ["maxActivationMs"] }),
        );
        apply(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": config }),
        )
        .await
        .unwrap();
        let group_bindings = || {
            Filter::new()
                .eq("tenantId", tenant_id.clone())
                .eq("subjectType", "group")
        };
        let stored = f.find("bindings", group_bindings()).await;
        assert_eq!(stored.len(), 2);
        for binding in &stored {
            assert_eq!(binding["eligible"], true);
            assert!(binding.get("maxActivationMs").is_none());
        }
        // Repeated applies are no-ops: the bindings are not replaced.
        for _ in 0..2 {
            let again = apply(
                &f,
                &owner,
                json!({ "tenantId": tenant_id, "config": config }),
            )
            .await
            .unwrap();
            assert_same(&again["summary"], &summary(0, 0, 0, 2));
        }
        let ids = |records: &[better_iam_core::Record]| {
            let mut ids: Vec<String> = records
                .iter()
                .map(|record| record["id"].as_str().unwrap().to_owned())
                .collect();
            ids.sort();
            ids
        };
        assert_eq!(
            ids(&f.find("bindings", group_bindings()).await),
            ids(&stored)
        );
        // Strings and out-of-range values are refused before anything is planned.
        for max_activation in [
            json!("600000"),
            json!(59_999),
            json!(0),
            json!(1.5),
            json!(7 * 86_400_000 + 1),
            json!(false),
            json!([]),
        ] {
            let bad = json!({
                "version": 1,
                "bindings": [{ "group": "Ops", "role": "Reader", "eligible": true, "maxActivationMs": max_activation }],
            });
            let error = plan(&f, &owner, json!({ "tenantId": tenant_id, "config": bad }))
                .await
                .unwrap_err();
            assert_eq!(error.code, "INVALID_INPUT", "plan {max_activation}");
            assert!(
                error.message.contains("maxActivationMs"),
                "{}",
                error.message
            );
            let error = apply(&f, &owner, json!({ "tenantId": tenant_id, "config": bad }))
                .await
                .unwrap_err();
            assert_eq!(error.code, "INVALID_INPUT", "apply {max_activation}");
        }
        let planned = plan(
            &f,
            &owner,
            json!({
                "tenantId": tenant_id,
                "config": {
                    "version": 1,
                    "bindings": [{ "group": "Ops", "role": "Reader", "eligible": true, "maxActivationMs": 7 * 86_400_000 }],
                },
            }),
        )
        .await
        .unwrap();
        assert_eq!(planned["summary"]["update"], 1);
    });
}

#[test]
fn matches_package_names_regardless_of_case_and_renames_in_place() {
    run(|| async {
        let (f, tenant_id, owner, reader) = review_setup().await;
        let alice = f.member("alice").await;
        let kit = create_package(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "name": "Engineer Kit", "roleIds": [reader["id"]] }),
        )
        .await;
        ok(f.iam
            .api
            .packages
            .assign(
                &owner,
                body(json!({ "tenantId": tenant_id, "packageId": kit["id"], "identityId": alice })),
            )
            .await);
        let config =
            json!({ "version": 1, "packages": [{ "name": "Engineer kit", "roles": ["Reader"] }] });
        for prune in [false, true] {
            let planned = plan(
                &f,
                &owner,
                json!({ "tenantId": tenant_id, "config": config, "prune": prune }),
            )
            .await
            .unwrap();
            assert_same(&planned["summary"], &summary(0, 1, 0, 0));
            assert_eq!(planned["changes"].as_array().unwrap().len(), 1);
            assert_matches(
                &planned["changes"][0],
                json!({
                    "kind": "package",
                    "name": "Engineer kit",
                    "action": "update",
                    "fields": ["name"],
                    "before": { "name": "Engineer Kit" },
                    "after": { "name": "Engineer kit" },
                }),
            );
        }
        // With prune, a create+delete would fail on the held package; a rename keeps it and its holder.
        let applied = apply(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": config, "prune": true }),
        )
        .await
        .unwrap();
        assert_same(&applied["summary"], &summary(0, 1, 0, 0));
        let listed = list(&f, "packages", json!({ "tenantId": tenant_id })).await;
        assert_same(
            &json!(
                listed
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|pkg| json!([pkg["id"], pkg["name"], pkg["assignments"]]))
                    .collect::<Vec<_>>()
            ),
            &json!([[kit["id"], "Engineer kit", 1]]),
        );
        let assignments = ok(f
            .iam
            .api
            .packages
            .list_assignments(
                &owner,
                body(json!({ "tenantId": tenant_id, "packageId": kit["id"] })),
            )
            .await);
        assert_same(
            &json!(
                assignments
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|assignment| json!([assignment["identityId"], assignment["packageName"]]))
                    .collect::<Vec<_>>()
            ),
            &json!([[alice, "Engineer kit"]]),
        );
        assert_same(
            &export(&f, &owner, &tenant_id).await["packages"],
            &json!([{ "name": "Engineer kit", "roles": ["Reader"], "groups": [] }]),
        );
        let last = plan(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": config, "prune": true }),
        )
        .await
        .unwrap();
        assert_same(&last["summary"], &summary(0, 0, 0, 1));
    });
}

#[test]
fn renames_on_a_case_only_difference_without_prune_instead_of_creating_a_second_package() {
    run(|| async {
        let (f, tenant_id, owner, reader) = review_setup().await;
        let kit = create_package(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "name": "Engineer Kit", "roleIds": [reader["id"]] }),
        )
        .await;
        let config =
            json!({ "version": 1, "packages": [{ "name": "Engineer kit", "roles": ["Reader"] }] });
        let applied = apply(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": config }),
        )
        .await
        .unwrap();
        assert_same(&applied["summary"], &summary(0, 1, 0, 0));
        let packages = changes_of(&applied, "package");
        assert_eq!(packages.len(), 1);
        assert_matches(
            packages[0],
            json!({ "name": "Engineer kit", "action": "update", "fields": ["name"] }),
        );
        let listed = list(&f, "packages", json!({ "tenantId": tenant_id })).await;
        assert_eq!(listed.as_array().unwrap().len(), 1);
        assert_eq!(listed[0]["id"], kit["id"]);
        assert_eq!(listed[0]["name"], "Engineer kit");
        // The renamed package still owns its name: a direct create with the old casing conflicts.
        let error = fails(
            f.iam
                .api
                .packages
                .create(
                    &owner,
                    body(json!({ "tenantId": tenant_id, "name": "Engineer Kit", "roleIds": [reader["id"]] })),
                )
                .await,
        );
        assert_eq!(error.code, "CONFLICT");
        let last = plan(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": config }),
        )
        .await
        .unwrap();
        assert_same(&last["summary"], &summary(0, 0, 0, 1));
    });
}

#[test]
fn rejects_package_names_that_differ_only_by_case_as_duplicates_at_plan_time() {
    run(|| async {
        let (f, tenant_id, owner, reader) = review_setup().await;
        create_package(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "name": "Kit", "roleIds": [reader["id"]] }),
        )
        .await;
        let config = json!({
            "version": 1,
            "packages": [
                { "name": "Vendor", "roles": ["Reader"] },
                { "name": "vendor", "roles": ["Reader"] },
            ],
        });
        let error = plan(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": config }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "INVALID_INPUT");
        assert!(
            error.message.to_lowercase().contains("duplicate package"),
            "{}",
            error.message
        );
        let error = plan(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": config, "prune": true }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "INVALID_INPUT");
        let error = apply(
            &f,
            &owner,
            json!({ "tenantId": tenant_id, "config": config }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "INVALID_INPUT");
        assert_eq!(
            names(&list(&f, "packages", json!({ "tenantId": tenant_id })).await),
            ["Kit"]
        );
    });
}
