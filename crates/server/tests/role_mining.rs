//! Role mining, access usage reports and certification review recommendations: ported from
//! tests/role-mining.test.ts, the `roleMining.usage` / `roleMining.rightSize` cases of tests/access-usage.test.ts,
//! and tests/review-recommendations.test.ts. Tenants, members and sessions come from the organization fixture; roles,
//! groups, bindings, identities and certifications are created through their API groups, while memberships and
//! account status are written the way `groups.addMembers` and `identities.setStatus` store them (their license, team,
//! guest and threat hooks belong to other port units).
//!
//! Mining reads whether a group is a team's backing group (`teams.ts isTeamGroup`), and setting identity attributes or
//! managers runs `api/package-automation.ts afterIdentityChange`; the suites that need those are ignored until the
//! units that own them land.

mod organization_fixture;

use better_iam_core::{AttributeType, CredentialInput, PermissionsConfig};
use better_iam_server::http::AuthArgs;
use better_iam_server::options::{
    AccessUsageOptions, AuthorizationCheck, AuthorizationRequest, BatchAuthorizationRequest,
    ResourceTarget, Toggle,
};
use indexmap::IndexMap;
use organization_fixture::{Org, assert_matches, body, code, fails, ok, organization, run};
use serde_json::{Value, json};

const DAY: f64 = 86_400_000.0;

/// Memberships as `groups.addMembers` stores them (its license and team hooks belong to other port units).
async fn add_members(f: &Org, group_id: &Value, identity_ids: &[&String]) {
    let group_id = group_id.as_str().unwrap();
    for identity_id in identity_ids {
        f.insert(
            "groupMembers",
            json!({
                "id": better_iam_server::utils::id(),
                "tenantId": f.tenant_id,
                "uniqueKey": format!("{group_id}:{identity_id}"),
                "groupId": group_id,
                "identityId": identity_id,
            }),
        )
        .await;
    }
}

/// An identity's status as `identities.setStatus` stores it (its guest and threat hooks belong to other port units).
async fn set_status(f: &Org, identity_id: &str, status: &str) {
    let mut record = f
        .store()
        .get("identities", identity_id)
        .await
        .unwrap()
        .expect("identity");
    record.insert("status".into(), json!(status));
    f.put("identities", record).await;
}

fn sorted(mut items: Vec<String>) -> Vec<String> {
    items.sort();
    items
}

fn strings(value: &Value, pointer: &str) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry.pointer(pointer).unwrap().as_str().unwrap().to_owned())
        .collect()
}

// --- tests/role-mining.test.ts ---------------------------------------------------------------------------------

struct Mining {
    f: Org,
    tenant_id: String,
    owner: CredentialInput,
    ana: String,
    ben: String,
    cai: String,
    dee: String,
    eve: String,
    reader: Value,
    deployer: Value,
    eng: Value,
    ops: Value,
    direct: Value,
}

async fn mining() -> Mining {
    let f = organization(|options| {
        let mut attributes = IndexMap::new();
        attributes.insert("department".to_owned(), AttributeType::String);
        options.permissions = Some(PermissionsConfig {
            actions: Some(vec!["documents:read".into(), "documents:write".into()]),
            identity_attributes: Some(attributes),
            ..PermissionsConfig::default()
        });
    })
    .await;
    let tenant_id = f.tenant_id.clone();
    let owner = f.owner_credential.clone();
    let api = &f.iam.api;
    let mut people = Vec::new();
    for (name, department) in [
        ("ana", "eng"),
        ("ben", "eng"),
        ("cai", "eng"),
        ("dee", "eng"),
        ("eve", "sales"),
    ] {
        let id = f.member(name).await;
        ok(api
            .identities
            .update(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "identityId": id,
                    "attributes": { "department": department },
                })),
            )
            .await);
        people.push(id);
    }
    let [ana, ben, cai, dee, eve] = <[String; 5]>::try_from(people).unwrap();
    let role = |name: &'static str, permissions: Value| {
        let (owner, tenant_id) = (owner.clone(), tenant_id.clone());
        async move {
            ok(api
                .roles
                .create(
                    &owner,
                    body(
                        json!({ "tenantId": tenant_id, "name": name, "permissions": permissions }),
                    ),
                )
                .await)
        }
    };
    let reader = role("Reader", json!(["documents:read"])).await;
    let writer = role("Writer", json!(["documents:write"])).await;
    role("Auditor", json!(["documents:read"])).await;
    let deployer = role("Deployer", json!(["documents:read", "documents:write"])).await;
    let bind = |role_id: Value, subject_type: &'static str, subject_id: Value| {
        let (owner, tenant_id) = (owner.clone(), tenant_id.clone());
        async move {
            ok(api
                .bindings
                .create(
                    &owner,
                    body(json!({
                        "tenantId": tenant_id,
                        "roleId": role_id,
                        "subjectType": subject_type,
                        "subjectId": subject_id,
                    })),
                )
                .await)
        }
    };
    for who in [&ana, &ben, &cai] {
        bind(reader["id"].clone(), "identity", json!(who)).await;
        bind(writer["id"].clone(), "identity", json!(who)).await;
    }
    let eng = ok(api
        .groups
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "Engineering" })),
        )
        .await);
    add_members(&f, &eng["id"], &[&ana, &ben, &cai]).await;
    let ops = ok(api
        .groups
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "Operations" })),
        )
        .await);
    add_members(&f, &ops["id"], &[&dee, &eve]).await;
    bind(deployer["id"].clone(), "group", ops["id"].clone()).await;
    let direct = bind(deployer["id"].clone(), "identity", json!(dee)).await;
    Mining {
        f,
        tenant_id,
        owner,
        ana,
        ben,
        cai,
        dee,
        eve,
        reader,
        deployer,
        eng,
        ops,
        direct,
    }
}

async fn suggest(s: &Mining, credential: &CredentialInput, input: Value) -> Result<Value, String> {
    let mut input = input;
    input["tenantId"] = json!(s.tenant_id);
    s.f.iam
        .api
        .role_mining
        .suggest(credential, body(input))
        .await
        .map(|reply| reply.into_value().unwrap())
        .map_err(|error| error.code)
}

async fn apply(
    s: &Mining,
    credential: &CredentialInput,
    suggestion_id: &Value,
) -> Result<Value, String> {
    s.f.iam
        .api
        .role_mining
        .apply(
            credential,
            body(json!({ "tenantId": s.tenant_id, "suggestionId": suggestion_id })),
        )
        .await
        .map(|reply| reply.into_value().unwrap())
        .map_err(|error| error.code)
}

fn of_kind<'a>(result: &'a Value, kind: &str) -> Vec<&'a Value> {
    result["suggestions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["kind"] == json!(kind))
        .collect()
}

#[test]
#[ignore = "needs teams.ts isTeamGroup and api/package-automation.ts afterIdentityChange (other port units)"]
fn suggests_bundles_group_bindings_redundant_bindings_and_duplicate_roles() {
    run(|| async {
        let s = mining().await;
        let result = suggest(&s, &s.owner, json!({})).await.unwrap();
        assert_eq!(
            result["summary"],
            json!({ "bundle": 1, "group-binding": 2, "redundant-binding": 1, "duplicate-roles": 1 })
        );
        assert_matches(
            &result["suggestions"][0],
            json!({
                "kind": "redundant-binding",
                "group": { "id": s.ops["id"], "name": "Operations" },
                "bindingIds": [s.direct["id"]],
                "identities": [{ "id": s.dee, "name": "dee@acme.test" }],
                "applicable": true,
            }),
        );
        let bundle = of_kind(&result, "bundle")[0];
        assert_eq!(
            sorted(strings(&bundle["roles"], "/name")),
            vec!["Reader", "Writer"]
        );
        assert_eq!(
            sorted(strings(&bundle["identities"], "/id")),
            sorted(vec![s.ana.clone(), s.ben.clone(), s.cai.clone()])
        );
        assert_eq!(bundle["savings"], json!(3));
        let duplicate = of_kind(&result, "duplicate-roles")[0];
        assert_eq!(
            sorted(strings(&duplicate["roles"], "/name")),
            vec!["Auditor", "Reader"]
        );
        let group_bindings = of_kind(&result, "group-binding");
        assert_eq!(
            sorted(
                group_bindings
                    .iter()
                    .map(|entry| entry["roles"][0]["name"].as_str().unwrap().to_owned())
                    .collect()
            ),
            vec!["Reader", "Writer"]
        );
        assert!(
            group_bindings
                .iter()
                .all(|entry| entry["group"]["id"] == s.eng["id"] && entry["savings"] == json!(2))
        );
        // Stable IDs across runs; kinds and thresholds filter.
        let again = suggest(&s, &s.owner, json!({})).await.unwrap();
        assert_eq!(
            strings(&again["suggestions"], "/id"),
            strings(&result["suggestions"], "/id")
        );
        let bundles = suggest(&s, &s.owner, json!({ "kinds": ["bundle"] }))
            .await
            .unwrap();
        assert_eq!(strings(&bundles["suggestions"], "/kind"), vec!["bundle"]);
        let strict = suggest(&s, &s.owner, json!({ "minIdentities": 4 }))
            .await
            .unwrap();
        assert_eq!(strict["summary"]["bundle"], json!(0));
        assert_eq!(strict["summary"]["group-binding"], json!(0));
        assert_eq!(
            suggest(&s, &s.owner, json!({ "minIdentities": 1 }))
                .await
                .unwrap_err(),
            "INVALID_INPUT"
        );
    });
}

#[test]
#[ignore = "needs teams.ts isTeamGroup, api/package-automation.ts afterIdentityChange and api/packages.ts allow (other port units)"]
fn applies_group_binding_and_redundant_binding_suggestions_without_changing_access() {
    run(|| async {
        let s = mining().await;
        let listed = suggest(&s, &s.owner, json!({})).await.unwrap();
        let reader_to_group = of_kind(&listed, "group-binding")
            .into_iter()
            .find(|entry| entry["roles"][0]["id"] == s.reader["id"])
            .unwrap()
            .clone();
        let applied = apply(&s, &s.owner, &reader_to_group["id"]).await.unwrap();
        assert_eq!(applied["applied"], json!("group-binding"));
        assert_eq!(applied["removedBindingIds"].as_array().unwrap().len(), 3);
        let api = &s.f.iam.api;
        let bindings = ok(api
            .bindings
            .list(&s.owner, body(json!({ "tenantId": s.tenant_id })))
            .await);
        let reader_bindings: Vec<&Value> = bindings
            .as_array()
            .unwrap()
            .iter()
            .filter(|binding| binding["roleId"] == s.reader["id"])
            .collect();
        assert_eq!(reader_bindings.len(), 1);
        assert_matches(
            reader_bindings[0],
            json!({
                "subjectType": "group",
                "subjectId": s.eng["id"],
                "id": applied["createdBindingId"],
            }),
        );
        // Same suggestion again: it no longer holds.
        assert_eq!(
            apply(&s, &s.owner, &reader_to_group["id"])
                .await
                .unwrap_err(),
            "NOT_FOUND"
        );

        let redundant = of_kind(&listed, "redundant-binding")[0].clone();
        apply(&s, &s.owner, &redundant["id"]).await.unwrap();
        let after = ok(api
            .bindings
            .list(&s.owner, body(json!({ "tenantId": s.tenant_id })))
            .await);
        let after = after.as_array().unwrap();
        assert!(!after.iter().any(|binding| binding["id"] == s.direct["id"]));
        assert!(after.iter().any(|binding| {
            binding["roleId"] == s.deployer["id"] && binding["subjectId"] == s.ops["id"]
        }));

        let bundle = of_kind(&listed, "bundle")[0].clone();
        assert_eq!(
            apply(&s, &s.owner, &bundle["id"]).await.unwrap_err(),
            "INVALID_INPUT"
        );
        let remaining = suggest(&s, &s.owner, json!({})).await.unwrap();
        assert_matches(
            &remaining["summary"],
            json!({ "group-binding": 1, "redundant-binding": 0, "bundle": 1 }),
        );
    });
}

#[test]
#[ignore = "needs api/package-automation.ts afterIdentityChange (another port unit)"]
fn finds_peer_outliers_by_attribute_and_by_manager() {
    run(|| async {
        let s = mining().await;
        let api = &s.f.iam.api;
        let outliers = |input: Value| {
            let mut input = input;
            input["tenantId"] = json!(s.tenant_id);
            let owner = s.owner.clone();
            async move {
                api.role_mining
                    .outliers(&owner, body(input))
                    .await
                    .map(|reply| reply.into_value().unwrap())
                    .map_err(|error| error.code)
            }
        };
        let by_department = outliers(json!({ "peerBy": "attribute:department" }))
            .await
            .unwrap();
        // Sales has one person, so only the four engineers are compared.
        assert_eq!(by_department["identitiesCompared"], json!(4));
        assert_eq!(by_department["outliers"].as_array().unwrap().len(), 1);
        let dee = &by_department["outliers"][0];
        assert_matches(
            dee,
            json!({ "identity": { "id": s.dee }, "peerValue": "eng", "peers": 3 }),
        );
        assert_eq!(dee["unusualRoles"].as_array().unwrap().len(), 1);
        assert_matches(
            &dee["unusualRoles"][0],
            json!({ "role": { "name": "Deployer" }, "peersHolding": 0, "share": 0 }),
        );
        assert_eq!(
            sorted(strings(&dee["missingRoles"], "/role/name")),
            vec!["Reader", "Writer"]
        );

        // Manager cohorts: everyone reporting to Eve.
        for who in [&s.ana, &s.ben, &s.cai, &s.dee] {
            ok(api
                .identities
                .update(
                    &s.owner,
                    body(json!({ "tenantId": s.tenant_id, "identityId": who, "managerId": s.eve })),
                )
                .await);
        }
        let by_manager = outliers(json!({})).await.unwrap();
        assert_eq!(by_manager["peerBy"], json!("manager"));
        assert_eq!(
            strings(&by_manager["outliers"], "/identity/id"),
            vec![s.dee.clone()]
        );
        assert_eq!(by_manager["outliers"][0]["peerValue"], json!(s.eve));

        assert_eq!(
            outliers(json!({ "peerBy": "attribute:shoe" }))
                .await
                .unwrap_err(),
            "INVALID_INPUT"
        );
        assert_eq!(
            outliers(json!({ "threshold": 2 })).await.unwrap_err(),
            "INVALID_INPUT"
        );
    });
}

#[test]
#[ignore = "needs teams.ts isTeamGroup, api/package-automation.ts afterIdentityChange and the packages API group (other port units)"]
fn does_not_rely_on_package_owned_memberships_or_groups_with_inactive_members() {
    run(|| async {
        let s = mining().await;
        let api = &s.f.iam.api;
        // Operations' Deployer binding reaches Dee only through a package-owned membership from now on.
        ok(api
            .groups
            .remove_member(
                &s.owner,
                body(
                    json!({ "tenantId": s.tenant_id, "groupId": s.ops["id"], "identityId": s.dee }),
                ),
            )
            .await);
        let pkg = ok(api
            .packages
            .create(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "name": "Ops kit", "groupIds": [s.ops["id"]] })),
            )
            .await);
        ok(api
            .packages
            .assign(
                &s.owner,
                body(
                    json!({ "tenantId": s.tenant_id, "packageId": pkg["id"], "identityId": s.dee }),
                ),
            )
            .await);
        // A disabled engineer makes "every member holds it directly" unsafe for Engineering.
        set_status(&s.f, &s.cai, "disabled").await;
        let result = suggest(&s, &s.owner, json!({ "minIdentities": 2 }))
            .await
            .unwrap();
        assert_eq!(result["summary"]["redundant-binding"], json!(0));
        assert_eq!(result["summary"]["group-binding"], json!(0));
    });
}

#[test]
#[ignore = "needs api/package-automation.ts afterIdentityChange (another port unit)"]
fn requires_analysis_permissions() {
    run(|| async {
        let s = mining().await;
        let eve = s.f.sign_in(&s.eve).await;
        assert_eq!(
            suggest(&s, &eve, json!({})).await.unwrap_err(),
            "ACCESS_DENIED"
        );
        let error = fails(
            s.f.iam
                .api
                .role_mining
                .outliers(&eve, body(json!({ "tenantId": s.tenant_id })))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        assert_eq!(
            apply(&s, &eve, &json!("a".repeat(24))).await.unwrap_err(),
            "ACCESS_DENIED"
        );
    });
}

/// The same checks as `requires_analysis_permissions` on a tenant without groups, which mining reads without the
/// teams helpers.
#[test]
fn requires_analysis_permissions_without_groups() {
    run(|| async {
        let f = organization(|_| {}).await;
        let eve = f.member("eve").await;
        let eve = f.sign_in(&eve).await;
        let api = &f.iam.api;
        let tenant_id = f.tenant_id.clone();
        let error = fails(
            api.role_mining
                .suggest(&eve, body(json!({ "tenantId": tenant_id })))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            api.role_mining
                .outliers(&eve, body(json!({ "tenantId": tenant_id })))
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            api.role_mining
                .apply(
                    &eve,
                    body(json!({ "tenantId": tenant_id, "suggestionId": "a".repeat(24) })),
                )
                .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
    });
}

/// Bundles and duplicate roles from direct bindings alone (no groups), with input validation.
#[test]
fn suggests_bundles_and_duplicate_roles_from_direct_bindings() {
    run(|| async {
        let f = organization(|_| {}).await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let api = &f.iam.api;
        let mut people = Vec::new();
        for name in ["ana", "ben", "cai"] {
            people.push(f.member(name).await);
        }
        let mut roles = Vec::new();
        for (name, permissions) in [
            ("Reader", json!(["documents:read"])),
            ("Writer", json!(["documents:write"])),
            ("Auditor", json!(["documents:read"])),
        ] {
            roles.push(ok(api
                .roles
                .create(
                    &owner,
                    body(
                        json!({ "tenantId": tenant_id, "name": name, "permissions": permissions }),
                    ),
                )
                .await));
        }
        for who in &people {
            for role in &roles[..2] {
                ok(api
                    .bindings
                    .create(
                        &owner,
                        body(json!({
                            "tenantId": tenant_id,
                            "roleId": role["id"],
                            "subjectType": "identity",
                            "subjectId": who,
                        })),
                    )
                    .await);
            }
        }
        let result = ok(api
            .role_mining
            .suggest(&owner, body(json!({ "tenantId": tenant_id })))
            .await);
        assert_eq!(
            result["summary"],
            json!({ "bundle": 1, "group-binding": 0, "redundant-binding": 0, "duplicate-roles": 1 })
        );
        assert_eq!(
            strings(&result["suggestions"], "/kind"),
            vec!["duplicate-roles", "bundle"]
        );
        let bundle = &result["suggestions"][1];
        assert_eq!(
            sorted(strings(&bundle["roles"], "/name")),
            vec!["Reader", "Writer"]
        );
        assert_eq!(
            bundle["title"],
            json!(format!(
                "3 people hold {} together",
                strings(&bundle["roles"], "/name").join(" + ")
            ))
        );
        assert_eq!(bundle["savings"], json!(3));
        assert_eq!(bundle["applicable"], json!(false));
        assert_eq!(bundle["id"].as_str().unwrap().len(), 24);
        let duplicate = &result["suggestions"][0];
        assert_eq!(
            sorted(strings(&duplicate["roles"], "/name")),
            vec!["Auditor", "Reader"]
        );
        assert_eq!(duplicate["identities"], json!([]));
        // A bundle cannot be applied; an unknown suggestion is gone.
        let error = fails(
            api.role_mining
                .apply(
                    &owner,
                    body(json!({ "tenantId": tenant_id, "suggestionId": bundle["id"] })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        assert_eq!(
            error.message,
            "Create an access package from a bundle with packages.create"
        );
        let error = fails(
            api.role_mining
                .apply(
                    &owner,
                    body(json!({ "tenantId": tenant_id, "suggestionId": "a".repeat(24) })),
                )
                .await,
        );
        assert_eq!(code(&error), "NOT_FOUND");
        // Kinds filter; unknown kinds are refused.
        let bundles = ok(api
            .role_mining
            .suggest(
                &owner,
                body(json!({ "tenantId": tenant_id, "kinds": ["bundle"] })),
            )
            .await);
        assert_eq!(strings(&bundles["suggestions"], "/kind"), vec!["bundle"]);
        let error = fails(
            api.role_mining
                .suggest(
                    &owner,
                    body(json!({ "tenantId": tenant_id, "kinds": ["shoes"] })),
                )
                .await,
        );
        assert_eq!(error.message, "Unknown suggestion kind");
        let error = fails(
            api.role_mining
                .suggest(&owner, body(json!({ "tenantId": tenant_id, "limit": 0 })))
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
    });
}

// --- tests/access-usage.test.ts (roleMining.usage and roleMining.rightSize) --------------------------------------

struct Usage {
    f: Org,
    tenant_id: String,
    owner: CredentialInput,
    alice: String,
    bob: String,
    carol: String,
    readers: Value,
}

async fn usage_scenario(access_usage: bool) -> Usage {
    let f = organization(|options| {
        options.access_usage = Some(Toggle::Flag(access_usage));
    })
    .await;
    let tenant_id = f.tenant_id.clone();
    let owner = f.owner_credential.clone();
    let api = &f.iam.api;
    let reader = ok(api
        .roles
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "Reader", "permissions": ["documents:read"] })),
        )
        .await);
    let editor = ok(api
        .roles
        .create(
            &owner,
            body(json!({
                "tenantId": tenant_id,
                "name": "Editor",
                "permissions": ["documents:read", "documents:write"],
            })),
        )
        .await);
    let alice = f.member("alice").await;
    let bob = f.member("bob").await;
    let carol = f.member("carol").await;
    let readers = ok(api
        .groups
        .create(
            &owner,
            body(json!({ "tenantId": tenant_id, "name": "Readers" })),
        )
        .await);
    add_members(&f, &readers["id"], &[&bob]).await;
    for (role_id, subject_type, subject_id) in [
        (&editor["id"], "identity", json!(alice)),
        (&reader["id"], "group", readers["id"].clone()),
        (&reader["id"], "identity", json!(carol)),
    ] {
        ok(api
            .bindings
            .create(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "roleId": role_id,
                    "subjectType": subject_type,
                    "subjectId": subject_id,
                })),
            )
            .await);
    }
    Usage {
        f,
        tenant_id,
        owner,
        alice,
        bob,
        carol,
        readers,
    }
}

async fn check(s: &Usage, identity_id: &str, action: &str) -> bool {
    let credential = s.f.sign_in(identity_id).await;
    s.f.iam
        .authorize(&AuthorizationRequest {
            credential,
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

async fn usage_of(s: &Usage, input: Value) -> Value {
    let mut input = input;
    input["tenantId"] = json!(s.tenant_id);
    ok(s.f.iam.api.role_mining.usage(&s.owner, body(input)).await)
}

#[test]
fn records_allowed_checks_and_right_sizes_bindings_against_them() {
    run(|| async {
        let s = usage_scenario(true).await;
        assert!(check(&s, &s.alice, "documents:read").await);
        assert!(check(&s, &s.alice, "documents:read").await);
        assert!(check(&s, &s.bob, "documents:read").await);
        // Denied checks are not usage.
        assert!(!check(&s, &s.carol, "documents:write").await);
        let bob_credential = s.f.sign_in(&s.bob).await;
        s.f.iam
            .authorize_many(&BatchAuthorizationRequest {
                credential: bob_credential,
                tenant_id: s.tenant_id.clone(),
                checks: vec![AuthorizationCheck {
                    action: "documents:read".into(),
                    resource: ResourceTarget {
                        kind: "document".into(),
                        id: "d2".into(),
                    },
                }],
            })
            .await
            .unwrap();

        let usage = usage_of(&s, json!({ "identityId": s.alice })).await;
        assert_eq!(usage["tracking"], json!(true));
        assert_eq!(usage["records"].as_array().unwrap().len(), 1);
        assert_matches(
            &usage["records"][0],
            json!({ "identityId": s.alice, "action": "documents:read", "count": 2 }),
        );
        let bob = usage_of(&s, json!({ "identityId": s.bob })).await;
        assert_matches(
            &bob["records"][0],
            json!({ "action": "documents:read", "count": 2 }),
        );
        assert_eq!(
            usage_of(&s, json!({ "identityId": s.carol })).await["records"],
            json!([])
        );
        // The owner's own provisioning operations count as usage too.
        let owner_usage = usage_of(&s, json!({ "identityId": s.f.owner_id })).await;
        assert!(
            strings(&owner_usage["records"], "/action").contains(&"iam:bindings:create".into())
        );

        let report = ok(s
            .f
            .iam
            .api
            .role_mining
            .right_size(&s.owner, body(json!({ "tenantId": s.tenant_id })))
            .await);
        assert_matches(
            &report,
            json!({ "tracking": true, "unusedDays": 90, "complete": false }),
        );
        assert!(report["trackingSince"].is_number());
        let entries: Vec<(String, String, String)> = report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| {
                (
                    entry["identity"]["id"].as_str().unwrap().to_owned(),
                    entry["role"]["name"].as_str().unwrap().to_owned(),
                    entry["status"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        assert_eq!(
            entries,
            vec![
                (s.carol.clone(), "Reader".into(), "unused".into()),
                (s.alice.clone(), "Editor".into(), "partial".into()),
            ]
        );
        let alice = report["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["identity"]["id"] == json!(s.alice))
            .unwrap();
        assert_matches(
            alice,
            json!({
                "via": { "type": "identity" },
                "grantedActions": 2,
                "usedActions": ["documents:read"],
                "unusedActions": ["documents:write"],
                "unusedCount": 1,
            }),
        );
        assert!(alice["lastUsedAt"].is_number());
        let role = |name: &str| {
            report["roles"]
                .as_array()
                .unwrap()
                .iter()
                .find(|role| role["role"]["name"] == json!(name))
                .unwrap()
                .clone()
        };
        assert_matches(
            &role("Editor"),
            json!({ "holders": 1, "neverUsed": ["documents:write"] }),
        );
        assert_matches(
            &role("Reader"),
            json!({ "holders": 2, "neverUsed": [], "usedActions": ["documents:read"] }),
        );

        // Once the window is covered, old use no longer counts.
        s.f.advance(2.0 * DAY);
        let owner = s.f.sign_in(&s.f.owner_id).await;
        let later = ok(s
            .f
            .iam
            .api
            .role_mining
            .right_size(
                &owner,
                body(json!({ "tenantId": s.tenant_id, "unusedDays": 1 })),
            )
            .await);
        assert_eq!(later["complete"], json!(true));
        assert!(
            later["entries"]
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| entry["status"] == json!("unused"))
        );
        let bob_entry = later["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["identity"]["id"] == json!(s.bob))
            .unwrap();
        assert_eq!(
            bob_entry["via"],
            json!({ "type": "group", "id": s.readers["id"], "name": "Readers" })
        );
    });
}

#[test]
fn merges_buffered_usage_into_stored_records_across_flushes() {
    run(|| async {
        let s = usage_scenario(true).await;
        check(&s, &s.alice, "documents:read").await;
        let written = s.f.iam.flush_access_usage().await.unwrap();
        assert!(written["written"].as_f64().unwrap() > 0.0);
        assert_eq!(
            s.f.iam.flush_access_usage().await.unwrap()["written"],
            json!(0)
        );
        s.f.advance(60_000.0);
        check(&s, &s.alice, "documents:read").await;
        s.f.iam.flush_access_usage().await.unwrap();
        let usage = usage_of(&s, json!({ "identityId": s.alice })).await;
        let record = &usage["records"][0];
        assert_eq!(record["count"], json!(2));
        assert_eq!(
            record["lastUsedAt"].as_f64().unwrap() - record["firstUsedAt"].as_f64().unwrap(),
            60_000.0
        );
    });
}

#[test]
fn records_nothing_when_tracking_is_off() {
    run(|| async {
        let s = usage_scenario(false).await;
        check(&s, &s.alice, "documents:read").await;
        assert_eq!(
            s.f.iam.flush_access_usage().await.unwrap(),
            json!({ "written": 0 })
        );
        let usage = usage_of(&s, json!({})).await;
        assert_matches(
            &usage,
            json!({ "tracking": false, "total": 0, "records": [] }),
        );
        let report = ok(s
            .f
            .iam
            .api
            .role_mining
            .right_size(&s.owner, body(json!({ "tenantId": s.tenant_id })))
            .await);
        assert_matches(&report, json!({ "tracking": false, "complete": false }));
        assert!(report.get("trackingSince").is_none());
        let error = fails(
            s.f.iam
                .api
                .role_mining
                .right_size(
                    &s.owner,
                    body(json!({ "tenantId": s.tenant_id, "unusedDays": 0 })),
                )
                .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
    });
}

/// Usage and right-sizing for direct bindings only (no groups), with tracking on and off.
#[test]
fn usage_and_right_sizing_without_groups() {
    run(|| async {
        for tracking in [true, false] {
            let f = organization(|options| {
                options.access_usage = Some(Toggle::Options(AccessUsageOptions::default()));
                if !tracking {
                    options.access_usage = Some(Toggle::Flag(false));
                }
            })
            .await;
            let tenant_id = f.tenant_id.clone();
            let owner = f.owner_credential.clone();
            let api = &f.iam.api;
            let editor = ok(api
                .roles
                .create(
                    &owner,
                    body(json!({
                        "tenantId": tenant_id,
                        "name": "Editor",
                        "permissions": ["documents:read", "documents:write"],
                    })),
                )
                .await);
            let alice = f.member("alice").await;
            ok(api
                .bindings
                .create(
                    &owner,
                    body(json!({
                        "tenantId": tenant_id,
                        "roleId": editor["id"],
                        "subjectType": "identity",
                        "subjectId": alice,
                    })),
                )
                .await);
            let credential = f.sign_in(&alice).await;
            for _ in 0..2 {
                assert!(
                    f.iam
                        .authorize(&AuthorizationRequest {
                            credential: credential.clone(),
                            tenant_id: tenant_id.clone(),
                            action: "documents:read".into(),
                            resource: ResourceTarget {
                                kind: "document".into(),
                                id: "d1".into(),
                            },
                        })
                        .await
                        .unwrap()
                        .allowed
                );
            }
            let usage = ok(api
                .role_mining
                .usage(
                    &owner,
                    body(json!({ "tenantId": tenant_id, "identityId": alice })),
                )
                .await);
            let report = ok(api
                .role_mining
                .right_size(&owner, body(json!({ "tenantId": tenant_id })))
                .await);
            if tracking {
                assert_eq!(usage["tracking"], json!(true));
                assert!(usage["trackingSince"].is_number());
                assert_eq!(usage["total"], json!(1));
                assert_matches(
                    &usage["records"][0],
                    json!({ "identityId": alice, "action": "documents:read", "count": 2 }),
                );
                assert_matches(
                    &report,
                    json!({ "tracking": true, "unusedDays": 90, "complete": false }),
                );
                assert_eq!(report["entries"].as_array().unwrap().len(), 1);
                assert_matches(
                    &report["entries"][0],
                    json!({
                        "identity": { "id": alice, "name": "alice@acme.test" },
                        "role": { "id": editor["id"], "name": "Editor" },
                        "via": { "type": "identity" },
                        "eligible": false,
                        "status": "partial",
                        "grantedActions": 2,
                        "usedActions": ["documents:read"],
                        "unusedActions": ["documents:write"],
                        "unusedCount": 1,
                    }),
                );
                assert!(report["entries"][0]["lastUsedAt"].is_number());
                assert_eq!(
                    report["roles"],
                    json!([{
                        "role": { "id": editor["id"], "name": "Editor" },
                        "holders": 1,
                        "grantedActions": 2,
                        "usedActions": ["documents:read"],
                        "neverUsed": ["documents:write"],
                        "neverUsedCount": 1,
                    }])
                );
            } else {
                assert_eq!(
                    usage,
                    json!({ "tracking": false, "total": 0, "records": [] })
                );
                assert_matches(&report, json!({ "tracking": false, "complete": false }));
                assert!(report.get("trackingSince").is_none());
                assert_eq!(report["entries"][0]["status"], json!("unused"));
            }
        }
    });
}

// --- tests/review-recommendations.test.ts --------------------------------------------------------------------------

#[test]
fn suggests_keep_or_revoke_from_account_status_sign_ins_and_recorded_usage() {
    run(|| async {
        let f = organization(|options| {
            options.access_usage = Some(Toggle::Flag(true));
        })
        .await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let api = &f.iam.api;
        let alice = f.member("alice").await;
        let bob = f.member("bob").await;
        let carol = f.member("carol").await;
        let dave = f.member("dave").await;
        let reader = ok(api
            .roles
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Reader", "permissions": ["documents:read"] })),
            )
            .await);
        let writer = ok(api
            .roles
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Writer", "permissions": ["documents:write"] })),
            )
            .await);
        let team = ok(api
            .groups
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Team" })),
            )
            .await);
        for (role_id, subject_type, subject_id) in [
            (&reader["id"], "identity", json!(alice)),
            (&writer["id"], "identity", json!(bob)),
            (&reader["id"], "identity", json!(carol)),
            (&reader["id"], "identity", json!(dave)),
            (&reader["id"], "group", team["id"].clone()),
        ] {
            ok(api
                .bindings
                .create(
                    &owner,
                    body(json!({
                        "tenantId": tenant_id,
                        "roleId": role_id,
                        "subjectType": subject_type,
                        "subjectId": subject_id,
                    })),
                )
                .await);
        }
        set_status(&f, &carol, "disabled").await;
        let use_role = |identity_id: String, action: &'static str| {
            let (f, tenant_id) = (&f, tenant_id.clone());
            async move {
                let credential = f.sign_in(&identity_id).await;
                f.iam
                    .authorize(&AuthorizationRequest {
                        credential,
                        tenant_id,
                        action: action.into(),
                        resource: ResourceTarget {
                            kind: "document".into(),
                            id: "d1".into(),
                        },
                    })
                    .await
                    .unwrap();
            }
        };
        password_sign_in(&f, "alice").await;
        use_role(alice.clone(), "documents:read").await;
        password_sign_in(&f, "bob").await;
        // Dave never signs in; support viewing the product as Dave is not Dave signing in.
        view_as(&f, &dave).await;

        let campaign = ok(api
            .certifications
            .create(&owner, body(json!({ "tenantId": tenant_id, "name": "Q3" })))
            .await);
        let owner_now = f.sign_in(&f.owner_id).await;
        let items = ok(api
            .certifications
            .get(
                &owner_now,
                body(json!({ "tenantId": tenant_id, "campaignId": campaign["id"] })),
            )
            .await)["items"]
            .clone();
        let item_for = |subject_id: &Value| -> Value {
            items
                .as_array()
                .unwrap()
                .iter()
                .find(|item| &item["subjectId"] == subject_id)
                .unwrap()["id"]
                .clone()
        };
        let by_item = |result: &Value| -> IndexMap<String, Value> {
            result["recommendations"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| (entry["itemId"].as_str().unwrap().to_owned(), entry.clone()))
                .collect()
        };
        let item = |subject: &str| item_for(&json!(subject)).as_str().unwrap().to_owned();

        // Usage only just started: sign-ins are the evidence.
        let early = ok(api
            .role_mining
            .review_recommendations(
                &owner,
                body(json!({ "tenantId": tenant_id, "campaignId": campaign["id"], "unusedDays": 30 })),
            )
            .await);
        assert_eq!(early["usageComplete"], json!(false));
        let first = by_item(&early);
        assert_matches(
            &first[&item(&alice)],
            json!({ "recommendation": "keep", "basis": "sign-in" }),
        );
        assert_matches(
            &first[&item(&bob)],
            json!({ "recommendation": "keep", "basis": "sign-in" }),
        );
        assert_matches(
            &first[&item(&carol)],
            json!({ "recommendation": "revoke", "basis": "status", "reason": "The account is disabled." }),
        );
        assert_matches(
            &first[&item(&dave)],
            json!({ "recommendation": "revoke", "basis": "sign-in", "reason": "Has never signed in." }),
        );
        assert_matches(
            &first[item_for(&team["id"]).as_str().unwrap()],
            json!({ "recommendation": "none" }),
        );

        // A month later usage covers the window: Alice used her role again, Bob signed in but never wrote.
        f.advance(31.0 * DAY);
        use_role(alice.clone(), "documents:read").await;
        password_sign_in(&f, "bob").await;
        let owner_now = f.sign_in(&f.owner_id).await;
        let later = by_item(&ok(api
            .role_mining
            .review_recommendations(
                &owner_now,
                body(json!({ "tenantId": tenant_id, "campaignId": campaign["id"], "unusedDays": 30 })),
            )
            .await));
        assert_matches(
            &later[&item(&alice)],
            json!({ "recommendation": "keep", "basis": "usage", "lastUsedAt": f.now() }),
        );
        assert_matches(
            &later[&item(&bob)],
            json!({
                "recommendation": "revoke",
                "basis": "usage",
                "reason": "None of the role's actions were used in the last 30 days.",
            }),
        );

        let owner_now = f.sign_in(&f.owner_id).await;
        let error = fails(
            api.role_mining
                .review_recommendations(
                    &owner_now,
                    body(json!({ "tenantId": tenant_id, "campaignId": "missing" })),
                )
                .await,
        );
        assert_eq!(code(&error), "NOT_FOUND");
    });
}

/// `auth.signIn` with the member's password (audited as `auth:session:create`).
async fn password_sign_in(f: &Org, name: &str) -> CredentialInput {
    let session = f
        .iam
        .api
        .auth
        .call(
            "signIn",
            AuthArgs::Public(json!({
                "tenantId": f.tenant_id,
                "email": format!("{name}@acme.test"),
                "password": format!("a strong {name} password"),
            })),
        )
        .await
        .expect("sign in");
    organization_fixture::bearer(session["token"].as_str().expect("no MFA"))
}

/// The owner views the product as a member ("view as"): allowed by the tenant's auth policy, then
/// `identities.impersonate`.
async fn view_as(f: &Org, identity_id: &str) {
    let api = &f.iam.api;
    ok(api
        .tenants
        .set_auth_policy(
            &f.owner_credential,
            body(json!({ "tenantId": f.tenant_id, "authPolicy": { "allowImpersonation": true } })),
        )
        .await);
    let owner = f.sign_in(&f.owner_id).await;
    ok(api
        .identities
        .impersonate(
            &owner,
            body(
                json!({ "tenantId": f.tenant_id, "identityId": identity_id, "reason": "Ticket 1" }),
            ),
        )
        .await);
}

/// Recommendations for direct bindings only (no groups): status, sign-ins and the missing campaign.
#[test]
fn recommends_from_status_and_sign_ins_without_groups() {
    run(|| async {
        let f = organization(|_| {}).await;
        let tenant_id = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let api = &f.iam.api;
        let alice = f.member("alice").await;
        let carol = f.member("carol").await;
        let dave = f.member("dave").await;
        let reader = ok(api
            .roles
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Reader", "permissions": ["documents:read"] })),
            )
            .await);
        for who in [&alice, &carol, &dave] {
            ok(api
                .bindings
                .create(
                    &owner,
                    body(json!({
                        "tenantId": tenant_id,
                        "roleId": reader["id"],
                        "subjectType": "identity",
                        "subjectId": who,
                    })),
                )
                .await);
        }
        set_status(&f, &carol, "disabled").await;
        password_sign_in(&f, "alice").await;
        view_as(&f, &dave).await;
        let campaign = ok(api
            .certifications
            .create(&owner, body(json!({ "tenantId": tenant_id, "name": "Q3" })))
            .await);
        let owner_now = f.sign_in(&f.owner_id).await;
        let result = ok(api
            .role_mining
            .review_recommendations(
                &owner_now,
                body(
                    json!({ "tenantId": tenant_id, "campaignId": campaign["id"], "unusedDays": 1 }),
                ),
            )
            .await);
        assert_eq!(result["campaignId"], campaign["id"]);
        assert_eq!(result["unusedDays"], json!(1));
        assert_eq!(result["usageComplete"], json!(false));
        let items = ok(api
            .certifications
            .get(
                &owner_now,
                body(json!({ "tenantId": tenant_id, "campaignId": campaign["id"] })),
            )
            .await)["items"]
            .clone();
        let item = |subject: &str| -> Value {
            let id = items
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["subjectId"] == json!(subject))
                .unwrap()["id"]
                .clone();
            result["recommendations"]
                .as_array()
                .unwrap()
                .iter()
                .find(|entry| entry["itemId"] == id)
                .unwrap()
                .clone()
        };
        let alice_entry = item(&alice);
        assert_matches(
            &alice_entry,
            json!({
                "recommendation": "keep",
                "basis": "sign-in",
                "reason": "Signed in within the last 1 day.",
            }),
        );
        assert!(alice_entry["lastUsedAt"].is_number());
        assert_eq!(
            item(&carol),
            json!({
                "itemId": item(&carol)["itemId"],
                "recommendation": "revoke",
                "basis": "status",
                "reason": "The account is disabled.",
            })
        );
        assert_matches(
            &item(&dave),
            json!({ "recommendation": "revoke", "basis": "sign-in", "reason": "Has never signed in." }),
        );
        // A month on, Alice's sign-in is outside the window.
        f.advance(31.0 * DAY);
        let owner_now = f.sign_in(&f.owner_id).await;
        let later = ok(api
            .role_mining
            .review_recommendations(
                &owner_now,
                body(json!({ "tenantId": tenant_id, "campaignId": campaign["id"] })),
            )
            .await);
        let alice_later = later["recommendations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["itemId"] == alice_entry["itemId"])
            .unwrap()
            .clone();
        assert_eq!(
            alice_later,
            json!({
                "itemId": alice_entry["itemId"],
                "recommendation": "keep",
                "basis": "sign-in",
                "reason": "Signed in within the last 90 days.",
                "lastUsedAt": alice_entry["lastUsedAt"],
            })
        );
        let error = fails(
            api.role_mining
                .review_recommendations(
                    &owner_now,
                    body(json!({ "tenantId": tenant_id, "campaignId": "missing" })),
                )
                .await,
        );
        assert_eq!(code(&error), "NOT_FOUND");
    });
}
