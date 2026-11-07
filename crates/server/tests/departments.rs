//! Port of the tests of `departments.ts`: tests/departments.test.ts (the department tree, codes, placements and the
//! helpers `departmentOf`, `departmentPath`, `departmentHeads`; principal.departments and principal.departmentId in
//! policies; heads handed over on offboarding). Departments and placements are written as the departments API group
//! (another port unit) stores them, and the module functions are called directly.

#![allow(clippy::cloned_ref_to_slice_refs)]

mod org_fixture;
mod teams_fixture;

use std::sync::Arc;

use better_iam_core::{IamStoreExt, Record};
use better_iam_server::departments::{
    MAX_DEPARTMENT_DEPTH, department_chain, department_code, department_context,
    department_descendants, department_heads, department_membership, department_of,
    department_path, load_department, release_departments, remove_from_department,
    tenant_departments,
};
use better_iam_server::options::{AuthorizationRequest, ResolvedResource, ResourceTarget};
use org_fixture::{Org, run};
use serde_json::{Map, Value, json};
use teams_fixture::{bind, create_department, place, role};

struct Scenario {
    org: Org,
    alice: String,
    bob: String,
    carol: String,
    dave: String,
    engineering: String,
    platform: String,
}

async fn scenario() -> Scenario {
    let org = Org::new(|options| {
        // Documents named `doc-{departmentId}` belong to that department.
        options.resolve_resource = Some(Arc::new(|reference| {
            Box::pin(async move {
                let mut resource = ResolvedResource::of(&reference);
                let mut attributes = Map::new();
                attributes.insert(
                    "departmentId".into(),
                    json!(reference.id.strip_prefix("doc-").unwrap_or(&reference.id)),
                );
                resource.attributes = Some(attributes);
                Ok(resource)
            })
        }));
    })
    .await;
    let alice = org.member("alice").await.id;
    let bob = org.member("bob").await.id;
    let carol = org.member("carol").await.id;
    let dave = org.member("dave").await.id;
    let engineering = create_department(&org, "Engineering", None).await;
    org.patch(
        "departments",
        &engineering,
        json!({ "code": "ENG", "headId": alice, "costCenter": "CC-100" }),
    )
    .await;
    let platform = create_department(&org, "Platform", Some(&engineering)).await;
    org.patch(
        "departments",
        &platform,
        json!({ "code": "ENG-PLT", "headId": bob }),
    )
    .await;
    Scenario {
        org,
        alice,
        bob,
        carol,
        dave,
        engineering,
        platform,
    }
}

fn department(id: &str, parent: Option<&str>) -> better_iam_server::departments::Department {
    let mut record =
        json!({ "id": id, "tenantId": "t", "name": id, "createdAt": 1, "updatedAt": 1 });
    if let Some(parent) = parent {
        record["parentId"] = json!(parent);
    }
    serde_json::from_value(record).unwrap()
}

#[test]
fn validates_codes_and_walks_the_tree() {
    assert_eq!(department_code(Some(&json!("FIN-AP"))).unwrap(), "FIN-AP");
    assert_eq!(department_code(Some(&json!("a.b_c"))).unwrap(), "a.b_c");
    for bad in [
        json!("-ENG"),
        json!(""),
        json!("x".repeat(33)),
        json!("A B"),
        json!(1),
    ] {
        let error = department_code(Some(&bad)).unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "INVALID_INPUT",
                "code must use 1-32 letters, digits, dots, underscores, or hyphens"
            )
        );
    }
    let departments: indexmap::IndexMap<String, _> = [
        department("company", None),
        department("eng", Some("company")),
        department("platform", Some("eng")),
        department("loop-a", Some("loop-b")),
        department("loop-b", Some("loop-a")),
    ]
    .into_iter()
    .map(|department| (department.id.clone(), department))
    .collect();
    let ids = |list: Vec<better_iam_server::departments::Department>| {
        list.into_iter()
            .map(|department| department.id)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        ids(department_chain(&departments, "platform").unwrap()),
        ["platform", "eng", "company"]
    );
    assert_eq!(
        ids(department_chain(&departments, "loop-b").unwrap()),
        ["loop-b", "loop-a"]
    );
    let list = json!(departments.values().collect::<Vec<_>>());
    assert_eq!(
        ids(department_descendants(&list, "company").unwrap()),
        ["eng", "platform"]
    );
    let mut deep = indexmap::IndexMap::new();
    for level in 0..30 {
        let parent = (level > 0).then(|| format!("d{}", level - 1));
        let department = department(&format!("d{level}"), parent.as_deref());
        deep.insert(department.id.clone(), department);
    }
    assert_eq!(
        department_chain(&deep, "d29").unwrap().len(),
        MAX_DEPARTMENT_DEPTH as usize + 1
    );
}

#[test]
fn places_people_and_answers_the_helpers() {
    run(|| async {
        let s = scenario().await;
        let org = &s.org;
        let tx = org.iam.store.clone();
        let loaded = load_department(&tx, &org.tenant_id, Some(&json!(s.platform)))
            .await
            .unwrap();
        assert_eq!(loaded.code.as_deref(), Some("ENG-PLT"));
        assert_eq!(loaded.parent_id.as_deref(), Some(s.engineering.as_str()));
        let missing = load_department(&tx, &org.tenant_id, Some(&json!("nope")))
            .await
            .unwrap_err();
        assert_eq!(
            (
                missing.code.as_str(),
                missing.message.as_str(),
                missing.status
            ),
            ("NOT_FOUND", "Department not found", 404)
        );
        let invalid = load_department(&tx, &org.tenant_id, Some(&json!("")))
            .await
            .unwrap_err();
        assert_eq!(
            (invalid.code.as_str(), invalid.message.as_str()),
            ("INVALID_INPUT", "Invalid departmentId")
        );
        assert_eq!(
            load_department(&tx, &org.root_tenant_id, Some(&json!(s.platform)))
                .await
                .unwrap_err()
                .code,
            "NOT_FOUND"
        );
        assert_eq!(
            tenant_departments(&tx, &org.tenant_id).await.unwrap().len(),
            2
        );

        assert_eq!(
            department_of(&tx, &org.tenant_id, &s.carol).await.unwrap(),
            None
        );
        place(org, &s.platform, &s.carol).await;
        assert_eq!(
            department_of(&tx, &org.tenant_id, &s.carol).await.unwrap(),
            Some(s.platform.clone())
        );
        let membership = department_membership(&tx, &org.tenant_id, &s.carol)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(membership.department_id, s.platform);
        assert_eq!(
            department_path(&tx, &org.tenant_id, &s.platform)
                .await
                .unwrap(),
            [s.engineering.clone(), s.platform.clone()]
        );
        assert!(
            department_path(&tx, &org.tenant_id, "unknown")
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            department_heads(&tx, &org.tenant_id, &s.platform, None)
                .await
                .unwrap(),
            [s.bob.clone()]
        );
        assert_eq!(
            department_heads(
                &tx,
                &org.tenant_id,
                &s.platform,
                Some(&json!({ "includeAncestors": true }))
            )
            .await
            .unwrap(),
            [s.bob.clone(), s.alice.clone()]
        );
        // The same head twice counts once.
        org.patch("departments", &s.platform, json!({ "headId": s.alice }))
            .await;
        assert_eq!(
            department_heads(
                &tx,
                &org.tenant_id,
                &s.platform,
                Some(&json!({ "includeAncestors": true }))
            )
            .await
            .unwrap(),
            [s.alice.clone()]
        );

        let tenant_id = org.tenant_id.clone();
        let carol = s.carol.clone();
        let removed = org
            .iam
            .store
            .transaction(|tx| async move {
                let first = remove_from_department(&tx, &tenant_id, &carol).await?;
                let second = remove_from_department(&tx, &tenant_id, &carol).await?;
                Ok((first, second))
            })
            .await
            .unwrap();
        assert_eq!(removed, (true, false));
        assert_eq!(
            department_of(&tx, &org.tenant_id, &s.carol).await.unwrap(),
            None
        );
    });
}

#[test]
fn exposes_principal_departments_and_principal_department_id_to_policies() {
    run(|| async {
        let s = scenario().await;
        let org = &s.org;
        let documents = role(
            org,
            "Engineering documents",
            json!([
                {
                    "effect": "allow",
                    "actions": ["documents:read"],
                    "resources": ["*"],
                    "conditions": { "ArrayContains": { "principal.departments": [s.engineering] } },
                },
                {
                    "effect": "allow",
                    "actions": ["documents:write"],
                    "resources": ["*"],
                    "conditions": { "StringEquals": { "principal.departmentId": "${resource.departmentId}" } },
                },
            ]),
        )
        .await;
        bind(org, "identity", &s.carol, &documents).await;
        let carol = org.sign_in("carol").await;
        let check = |action: &'static str, department_id: String| {
            let carol = carol.clone();
            async move {
                org.iam
                    .authorize(&AuthorizationRequest {
                        credential: carol,
                        tenant_id: org.tenant_id.clone(),
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
        place(org, &s.platform, &s.carol).await;
        // Platform sits under Engineering.
        assert!(check("documents:read", "x".into()).await);
        // A policy variable compares the person's own department with the resource's.
        assert!(check("documents:write", s.platform.clone()).await);
        assert!(!check("documents:write", s.engineering.clone()).await);

        let context = department_context(&org.iam.store, &org.tenant_id, &s.carol)
            .await
            .unwrap();
        let mut path = vec![s.engineering.clone(), s.platform.clone()];
        path.sort();
        assert_eq!(
            Value::Object(context),
            json!({ "principal.departmentId": s.platform, "principal.departments": path })
        );
        let none = department_context(&org.iam.store, &org.tenant_id, &s.dave)
            .await
            .unwrap();
        assert_eq!(Value::Object(none), json!({ "principal.departments": [] }));
    });
}

#[test]
fn hands_heads_over_on_offboarding() {
    run(|| async {
        let s = scenario().await;
        let org = &s.org;
        place(org, &s.platform, &s.bob).await;
        org.advance(60_000.0);
        let tenant_id = org.tenant_id.clone();
        let bob = s.bob.clone();
        let dave = s.dave.clone();
        let now = org.now();
        let released = org
            .iam
            .store
            .transaction(|tx| async move {
                release_departments(&tx, &tenant_id, &bob, now, Some(&dave)).await
            })
            .await
            .unwrap();
        assert_eq!(
            released,
            json!({ "left": true, "headsReassigned": 1, "headsCleared": 0 })
        );
        let platform: Record = org.get("departments", &s.platform).await.unwrap();
        assert_eq!(platform["headId"], json!(s.dave));
        assert_eq!(
            platform["updatedAt"],
            better_iam_server::js::number(org.now())
        );
        // Member order survives: headId moves to the end, updatedAt keeps its place.
        let keys: Vec<&str> = platform.keys().map(String::as_str).collect();
        assert_eq!(keys.last(), Some(&"headId"));

        let tenant_id = org.tenant_id.clone();
        let alice = s.alice.clone();
        let released = org
            .iam
            .store
            .transaction(|tx| async move {
                release_departments(&tx, &tenant_id, &alice, now, None).await
            })
            .await
            .unwrap();
        assert_eq!(
            released,
            json!({ "left": false, "headsReassigned": 0, "headsCleared": 1 })
        );
        let engineering = org.get("departments", &s.engineering).await.unwrap();
        assert!(engineering.get("headId").is_none());
        assert_eq!(
            department_of(&org.iam.store, &org.tenant_id, &s.bob)
                .await
                .unwrap(),
            None
        );
    });
}
