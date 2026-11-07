//! Port of tests/departments.test.ts: the department tree, placements, policy context, attribute import, manager
//! sync, deletion and offboarding, `mine`, and permissions.
//!
//! The `departments` API group is ported, but every method reads the department records through departments.ts
//! (`tenantDepartments`, `loadDepartment`, `departmentChain`, ...) and re-evaluates birthright rules through
//! package-automation.ts (`afterIdentityChange`); both belong to other units and are still stubs, so these tests are
//! `#[ignore]`d with that reason until they land. The deletion test also needs the `teams` API group.

mod organization_fixture;

use std::sync::Arc;

use better_iam_core::{
    AttributeType, CredentialInput, IamStoreExt, PermissionsConfig, ResourceRef,
};
use better_iam_server::departments::{department_heads, department_of, department_path};
use better_iam_server::options::{AuthorizationRequest, ResolvedResource, ResourceTarget};
use organization_fixture::{Org, assert_matches, body, code, fails, ok, organization, run};
use serde_json::{Map, Value, json};

struct Scenario {
    f: Org,
    tenant_id: String,
    owner: CredentialInput,
    alice: String,
    bob: String,
    carol: String,
    dave: String,
    engineering: Value,
    platform: Value,
}

impl Scenario {
    fn engineering_id(&self) -> String {
        self.engineering["id"].as_str().unwrap().to_owned()
    }

    fn platform_id(&self) -> String {
        self.platform["id"].as_str().unwrap().to_owned()
    }

    fn input(&self, members: Value) -> Value {
        let mut input = Map::new();
        input.insert("tenantId".into(), json!(self.tenant_id));
        for (key, value) in members.as_object().unwrap() {
            input.insert(key.clone(), value.clone());
        }
        Value::Object(input)
    }

    async fn assign(
        &self,
        department_id: &str,
        identity_ids: &[&str],
        title: Option<&str>,
    ) -> Value {
        let mut members = json!({ "departmentId": department_id, "identityIds": identity_ids });
        if let Some(title) = title {
            members["title"] = json!(title);
        }
        ok(self
            .f
            .iam
            .api
            .departments
            .assign(&self.owner, body(self.input(members)))
            .await)
    }

    async fn of_identity(&self, identity_id: &str) -> Value {
        ok(self
            .f
            .iam
            .api
            .departments
            .of_identity(
                &self.owner,
                body(self.input(json!({ "identityId": identity_id }))),
            )
            .await)
    }
}

fn names(steps: &Value, key: &str) -> Vec<String> {
    steps
        .as_array()
        .unwrap()
        .iter()
        .map(|step| step[key].as_str().unwrap_or_default().to_owned())
        .collect()
}

async fn scenario() -> Scenario {
    let f = organization(|options| {
        let mut attributes = indexmap::IndexMap::new();
        attributes.insert("department".to_owned(), AttributeType::String);
        options.permissions = Some(PermissionsConfig {
            actions: Some(vec!["documents:read".into(), "documents:write".into()]),
            identity_attributes: Some(attributes),
            ..PermissionsConfig::default()
        });
        // Documents named `doc-{departmentId}` belong to that department.
        options.resolve_resource = Some(Arc::new(|reference: ResourceRef| {
            Box::pin(async move {
                let mut resolved = ResolvedResource::of(&reference);
                let department_id = reference
                    .id
                    .strip_prefix("doc-")
                    .unwrap_or(&reference.id)
                    .to_owned();
                let mut attributes = Map::new();
                attributes.insert("departmentId".into(), Value::String(department_id));
                resolved.attributes = Some(attributes);
                Ok(resolved)
            })
        }));
    })
    .await;
    let tenant_id = f.tenant_id.clone();
    let owner = f.owner_credential.clone();
    let alice = f.member("alice").await;
    let bob = f.member("bob").await;
    let carol = f.member("carol").await;
    let dave = f.member("dave").await;
    let engineering = ok(f
        .iam
        .api
        .departments
        .create(
            &owner,
            body(json!({
                "tenantId": tenant_id,
                "name": "Engineering",
                "code": "ENG",
                "headId": alice,
                "costCenter": "CC-100",
            })),
        )
        .await);
    let platform = ok(f
        .iam
        .api
        .departments
        .create(
            &owner,
            body(json!({
                "tenantId": tenant_id,
                "name": "Platform",
                "code": "ENG-PLT",
                "parentId": engineering["id"],
                "headId": bob,
            })),
        )
        .await);
    Scenario {
        f,
        tenant_id,
        owner,
        alice,
        bob,
        carol,
        dave,
        engineering,
        platform,
    }
}

#[test]
#[ignore = "needs departments.ts (tenantDepartments, loadDepartment, departmentChain, departmentDescendants, departmentCode) and afterIdentityChange (api/package-automation.ts), other units"]
fn builds_a_department_tree_with_heads_codes_and_unique_names() {
    run(|| async {
        let s = scenario().await;
        let api = &s.f.iam.api.departments;
        assert_matches(
            &s.engineering,
            json!({
                "name": "Engineering",
                "code": "ENG",
                "costCenter": "CC-100",
                "head": { "id": s.alice },
                "path": [],
            }),
        );
        assert_eq!(names(&s.platform["path"], "code"), ["ENG"]);
        let error = fails(
            api.create(&s.owner, body(s.input(json!({ "name": "engineering" }))))
                .await,
        );
        assert_eq!(code(&error), "CONFLICT");
        let error = fails(
            api.create(
                &s.owner,
                body(s.input(json!({ "name": "Eng 2", "code": "eng" }))),
            )
            .await,
        );
        assert_eq!(code(&error), "CONFLICT");
        let error = fails(
            api.update(
                &s.owner,
                body(s.input(
                    json!({ "departmentId": s.engineering_id(), "parentId": s.platform_id() }),
                )),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let service = ok(s
            .f
            .iam
            .api
            .service_accounts
            .create(&s.owner, body(s.input(json!({ "name": "ci" }))))
            .await);
        let error = fails(
            api.update(
                &s.owner,
                body(s.input(json!({ "departmentId": s.platform_id(), "headId": service["id"] }))),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let cleared = ok(api
            .update(
                &s.owner,
                body(s.input(json!({
                    "departmentId": s.platform_id(),
                    "code": null,
                    "description": "Runs shared infrastructure",
                }))),
            )
            .await);
        assert!(cleared.get("code").is_none());
        assert_eq!(cleared["description"], "Runs shared infrastructure");
    });
}

#[test]
#[ignore = "needs departments.ts (tenantDepartments, departmentMembership, departmentOf, departmentPath, departmentHeads, ...) and afterIdentityChange (api/package-automation.ts), other units"]
fn places_people_one_department_each_and_rolls_counts_up_the_tree() {
    run(|| async {
        let s = scenario().await;
        let api = &s.f.iam.api.departments;
        let (engineering, platform) = (s.engineering_id(), s.platform_id());
        s.assign(&engineering, &[&s.alice, &s.carol], None).await;
        let moved = s
            .assign(&platform, &[&s.bob, &s.carol], Some("Engineer"))
            .await;
        assert_eq!(moved, json!({ "assigned": 2, "unchanged": 0 }));
        let tree = ok(api.tree(&s.owner, body(s.input(json!({})))).await);
        let tree = tree.as_array().unwrap();
        assert_eq!(tree.len(), 1);
        assert_matches(
            &tree[0],
            json!({ "name": "Engineering", "memberCount": 1, "totalMemberCount": 3 }),
        );
        assert_matches(
            &tree[0]["children"][0],
            json!({ "name": "Platform", "memberCount": 2, "head": { "id": s.bob } }),
        );
        let everyone = ok(api
            .list_members(
                &s.owner,
                body(
                    s.input(json!({ "departmentId": engineering, "includeSubdepartments": true })),
                ),
            )
            .await);
        let rows: Vec<(String, String, bool)> = everyone
            .as_array()
            .unwrap()
            .iter()
            .map(|member| {
                (
                    member["name"].as_str().unwrap().to_owned(),
                    member["department"]["name"].as_str().unwrap().to_owned(),
                    member["head"].as_bool().unwrap_or(false),
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                ("alice".to_owned(), "Engineering".to_owned(), true),
                ("bob".to_owned(), "Platform".to_owned(), true),
                ("carol".to_owned(), "Platform".to_owned(), false),
            ]
        );
        let carol = s.of_identity(&s.carol).await;
        assert_matches(
            &carol,
            json!({
                "department": { "name": "Platform" },
                "title": "Engineer",
                "head": { "id": s.bob },
            }),
        );
        assert_eq!(names(&carol["path"], "name"), ["Engineering", "Platform"]);

        let (tenant_id, carol_id) = (s.tenant_id.clone(), s.carol.clone());
        let (engineering_id, platform_id) = (engineering.clone(), platform.clone());
        let (alice_id, bob_id) = (s.alice.clone(), s.bob.clone());
        s.f.iam
            .store
            .transaction(|tx| async move {
                assert_eq!(
                    department_of(&tx, &tenant_id, &carol_id).await?,
                    Some(platform_id.clone())
                );
                assert_eq!(
                    department_path(&tx, &tenant_id, &platform_id).await?,
                    [engineering_id.clone(), platform_id.clone()]
                );
                assert_eq!(
                    department_heads(&tx, &tenant_id, &platform_id, None).await?,
                    [bob_id.as_str()]
                );
                assert_eq!(
                    department_heads(
                        &tx,
                        &tenant_id,
                        &platform_id,
                        Some(&json!({ "includeAncestors": true }))
                    )
                    .await?,
                    [bob_id.clone(), alice_id.clone()]
                );
                Ok(())
            })
            .await
            .unwrap();

        ok(api
            .unassign(&s.owner, body(s.input(json!({ "identityId": s.carol }))))
            .await);
        assert_eq!(s.of_identity(&s.carol).await, Value::Null);
    });
}

#[test]
#[ignore = "needs departments.ts (departmentContext, tenantDepartments, ...) and afterIdentityChange (api/package-automation.ts), other units"]
fn exposes_principal_departments_and_principal_department_id_to_policies() {
    run(|| async {
        let s = scenario().await;
        let role = ok(s
            .f
            .iam
            .api
            .roles
            .create(
                &s.owner,
                body(s.input(json!({
                    "name": "Engineering documents",
                    "document": {
                        "version": 1,
                        "statements": [
                            {
                                "effect": "allow",
                                "actions": ["documents:read"],
                                "resources": ["*"],
                                "conditions": {
                                    "ArrayContains": { "principal.departments": [s.engineering_id()] },
                                },
                            },
                            {
                                "effect": "allow",
                                "actions": ["documents:write"],
                                "resources": ["*"],
                                "conditions": {
                                    "StringEquals": { "principal.departmentId": "${resource.departmentId}" },
                                },
                            },
                        ],
                    },
                }))),
            )
            .await);
        ok(s.f
            .iam
            .api
            .bindings
            .create(
                &s.owner,
                body(s.input(json!({
                    "roleId": role["id"],
                    "subjectType": "identity",
                    "subjectId": s.carol,
                }))),
            )
            .await);
        let carol = s.f.sign_in(&s.carol).await;
        let check = |action: &'static str, department_id: String| {
            let carol = carol.clone();
            let iam = &s.f.iam;
            let tenant_id = s.tenant_id.clone();
            async move {
                iam.authorize(&AuthorizationRequest {
                    credential: carol,
                    tenant_id,
                    action: action.into(),
                    resource: ResourceTarget {
                        kind: "documents".into(),
                        id: format!("doc-{department_id}"),
                    },
                })
                .await
                .unwrap()
                .allowed
            }
        };
        assert!(!check("documents:read", "x".into()).await);
        s.assign(&s.platform_id(), &[&s.carol], None).await;
        // Platform sits under Engineering.
        assert!(check("documents:read", "x".into()).await);
        // A policy variable compares the person's own department with the resource's.
        assert!(check("documents:write", s.platform_id()).await);
        assert!(!check("documents:write", s.engineering_id()).await);
    });
}

#[test]
#[ignore = "needs departments.ts (tenantDepartments, departmentMembership, ...) and afterIdentityChange (api/package-automation.ts), other units"]
fn imports_departments_from_an_identity_attribute() {
    run(|| async {
        let s = scenario().await;
        let api = &s.f.iam.api.departments;
        for (person, value) in [(&s.carol, "eng"), (&s.dave, "Sales"), (&s.bob, "Platform")] {
            ok(s.f
                .iam
                .api
                .identities
                .update(
                    &s.owner,
                    body(s.input(
                        json!({ "identityId": person, "attributes": { "department": value } }),
                    )),
                )
                .await);
        }
        let preview = ok(api
            .import_from_attribute(
                &s.owner,
                body(s.input(json!({ "attribute": "department", "dryRun": true }))),
            )
            .await);
        assert_matches(
            &preview,
            json!({ "dryRun": true, "created": [], "assigned": 2, "unmatched": ["Sales"] }),
        );
        assert_eq!(s.of_identity(&s.carol).await, Value::Null);
        let applied = ok(api
            .import_from_attribute(
                &s.owner,
                body(s.input(json!({ "attribute": "department", "createMissing": true }))),
            )
            .await);
        assert_matches(
            &applied,
            json!({ "created": ["Sales"], "assigned": 3, "unmatched": [] }),
        );
        let again = ok(api
            .import_from_attribute(
                &s.owner,
                body(s.input(json!({ "attribute": "department" }))),
            )
            .await);
        assert_matches(&again, json!({ "assigned": 0, "unchanged": 3 }));
        let error = fails(
            api.import_from_attribute(&s.owner, body(s.input(json!({ "attribute": "title" }))))
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
    });
}

#[test]
#[ignore = "needs departments.ts (tenantDepartments, departmentChain, ...) and afterIdentityChange (api/package-automation.ts), other units"]
fn turns_department_heads_into_managers_without_creating_cycles() {
    run(|| async {
        let s = scenario().await;
        let api = &s.f.iam.api.departments;
        s.assign(&s.engineering_id(), &[&s.alice], None).await;
        s.assign(&s.platform_id(), &[&s.bob, &s.carol, &s.dave], None)
            .await;
        // Dave already reports to Alice; without overwrite he keeps her.
        ok(s.f
            .iam
            .api
            .identities
            .update(
                &s.owner,
                body(s.input(json!({ "identityId": s.dave, "managerId": s.alice }))),
            )
            .await);
        let preview = ok(api
            .sync_managers(&s.owner, body(s.input(json!({ "dryRun": true }))))
            .await);
        assert_matches(&preview, json!({ "dryRun": true, "kept": 1, "noHead": 1 }));
        let mut pairs: Vec<String> = preview["updated"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| {
                format!(
                    "{} -> {}",
                    item["name"].as_str().unwrap(),
                    item["managerName"].as_str().unwrap()
                )
            })
            .collect();
        pairs.sort();
        assert_eq!(pairs, ["bob -> alice", "carol -> bob"]);
        let carol = preview["updated"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["name"] == "carol")
            .unwrap();
        assert_matches(carol, json!({ "identityId": s.carol, "managerId": s.bob }));
        ok(api.sync_managers(&s.owner, body(s.input(json!({})))).await);
        let reports = ok(s
            .f
            .iam
            .api
            .identities
            .list_reports(&s.owner, body(s.input(json!({ "identityId": s.bob }))))
            .await);
        assert_eq!(names(&reports, "id"), [s.carol.as_str()]);
        let forced = ok(api
            .sync_managers(&s.owner, body(s.input(json!({ "overwrite": true }))))
            .await);
        assert_eq!(
            forced["updated"],
            json!([{ "identityId": s.dave, "name": "dave", "managerId": s.bob, "managerName": "bob" }])
        );
    });
}

#[test]
#[ignore = "needs departments.ts (tenantDepartments, releaseDepartments, ...), afterIdentityChange (api/package-automation.ts), packagesNaming (org-rules.ts) and the teams API group, other units"]
fn deletes_departments_unassigning_people_and_unfiling_teams_and_hands_heads_over_on_offboarding() {
    run(|| async {
        let s = scenario().await;
        let api = &s.f.iam.api.departments;
        let error = fails(
            api.delete(
                &s.owner,
                body(s.input(json!({ "departmentId": s.engineering_id() }))),
            )
            .await,
        );
        assert_eq!(code(&error), "RESOURCE_IN_USE");
        s.assign(&s.platform_id(), &[&s.carol], None).await;
        let team = ok(s
            .f
            .iam
            .api
            .teams
            .create(
                &s.owner,
                body(s.input(json!({ "name": "Build", "departmentId": s.platform_id() }))),
            )
            .await);
        assert_matches(&team["department"], json!({ "name": "Platform" }));
        let platform = ok(api
            .get(
                &s.owner,
                body(s.input(json!({ "departmentId": s.platform_id() }))),
            )
            .await);
        assert_eq!(names(&platform["teams"], "slug"), ["build"]);

        let owner = s.f.session(&s.f.owner_id, true).await;
        let offboarded = ok(s
            .f
            .iam
            .api
            .identities
            .offboard(
                &owner,
                body(s.input(json!({
                    "identityId": s.bob,
                    "reason": "Moved on",
                    "successorId": s.dave,
                }))),
            )
            .await);
        assert_matches(&offboarded, json!({ "departmentsReassigned": 1 }));
        let platform = ok(api
            .get(
                &owner,
                body(s.input(json!({ "departmentId": s.platform_id() }))),
            )
            .await);
        assert_matches(&platform["head"], json!({ "id": s.dave }));

        let removed = ok(api
            .delete(
                &owner,
                body(s.input(json!({ "departmentId": s.platform_id() }))),
            )
            .await);
        assert_eq!(
            removed,
            json!({ "deleted": true, "unassigned": 1, "teams": 1 })
        );
        let build = ok(s
            .f
            .iam
            .api
            .teams
            .get(&owner, body(s.input(json!({ "teamId": team["id"] }))))
            .await);
        assert!(build.get("departmentId").is_none());
        ok(s.f
            .iam
            .api
            .identities
            .delete(&owner, body(s.input(json!({ "identityId": s.alice }))))
            .await);
        let engineering = ok(api
            .get(
                &owner,
                body(s.input(json!({ "departmentId": s.engineering_id() }))),
            )
            .await);
        assert!(engineering.get("head").is_none());
    });
}

#[test]
#[ignore = "needs departments.ts (tenantDepartments, departmentMembership, departmentChain, ...) and afterIdentityChange (api/package-automation.ts), other units"]
fn shows_people_their_own_department_and_heads_the_people_they_lead() {
    run(|| async {
        let s = scenario().await;
        let api = &s.f.iam.api.departments;
        s.assign(&s.engineering_id(), &[&s.alice], None).await;
        s.assign(&s.platform_id(), &[&s.bob, &s.carol], Some("Engineer"))
            .await;
        let carol = s.f.sign_in(&s.carol).await;
        let mine = ok(api.mine(&carol, body(s.input(json!({})))).await);
        assert_eq!(mine["leads"], json!([]));
        assert_matches(
            &mine["department"],
            json!({
                "department": { "name": "Platform" },
                "title": "Engineer",
                "head": { "id": s.bob },
            }),
        );
        assert_eq!(
            names(&mine["department"]["path"], "name"),
            ["Engineering", "Platform"]
        );
        // Alice heads Engineering, so she sees everyone in it and in Platform below it.
        let alice = s.f.sign_in(&s.alice).await;
        let leads = ok(api.mine(&alice, body(s.input(json!({})))).await)["leads"].clone();
        let leads = leads.as_array().unwrap();
        assert_eq!(
            leads
                .iter()
                .map(|lead| lead["department"]["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["Engineering"]
        );
        let people: Vec<String> = leads[0]["people"]
            .as_array()
            .unwrap()
            .iter()
            .map(|person| {
                format!(
                    "{}:{}",
                    person["name"].as_str().unwrap(),
                    person["department"]["name"].as_str().unwrap()
                )
            })
            .collect();
        assert_eq!(
            people,
            ["alice:Engineering", "bob:Platform", "carol:Platform"]
        );
        // Dave has no department and leads none.
        let dave = s.f.sign_in(&s.dave).await;
        assert_eq!(
            ok(api.mine(&dave, body(s.input(json!({})))).await),
            json!({ "department": null, "leads": [] })
        );
    });
}

#[test]
#[ignore = "needs departments.ts (tenantDepartments, ...) for the scenario's departments, another unit"]
fn keeps_reads_and_changes_behind_their_permissions() {
    run(|| async {
        let s = scenario().await;
        let api = &s.f.iam.api.departments;
        let carol = s.f.sign_in(&s.carol).await;
        let error = fails(api.list(&carol, body(s.input(json!({})))).await);
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            api.create(&carol, body(s.input(json!({ "name": "Shadow IT" }))))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
    });
}

#[test]
fn refuses_unauthorized_callers_and_malformed_identifiers_before_reading_departments() {
    run(|| async {
        let f = organization(|_| {}).await;
        let api = &f.iam.api.departments;
        let carol = f.member("carol").await;
        let carol = f.sign_in(&carol).await;
        let input = |members: Value| {
            let mut input = members.as_object().unwrap().clone();
            input.insert("tenantId".into(), json!(f.tenant_id));
            Value::Object(input)
        };
        let error = fails(api.list(&carol, body(input(json!({})))).await);
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            api.create(&carol, body(input(json!({ "name": "Shadow IT" }))))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(api.tree(&carol, body(input(json!({})))).await);
        assert_eq!(code(&error), "ACCESS_DENIED");
        // The resource identifier is validated before authentication.
        let error = fails(
            api.get(&carol, body(input(json!({ "departmentId": 7 }))))
                .await,
        );
        assert_eq!(
            (code(&error), error.message.as_str()),
            ("INVALID_INPUT", "Invalid departmentId")
        );
        let error = fails(api.unassign(&carol, body(input(json!({})))).await);
        assert_eq!(error.message, "Invalid identityId");
        // `mine` needs a person's own session in the organization.
        let root = f.root_credential.clone();
        let error = fails(api.mine(&root, body(input(json!({})))).await);
        assert_eq!(error.status, 403);
        let error = fails(api.mine(&root, body(json!({}))).await);
        assert_eq!(error.message, "Invalid tenantId");
    });
}
