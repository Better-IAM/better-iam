//! Managed resources (tests/access.test.ts, tests/security-engine.test.ts, tests/limits.test.ts). Members, roles and
//! bindings are written to the store directly where the TypeScript tests use the `identities`, `roles` and
//! `bindings` groups.

mod directory_support;

use better_iam_core::{AttributeType, PermissionsConfig, PermissionsMode, ResourceTypeDefinition};
use better_iam_server::options::{AuthorizationRequest, ResourceTarget};
use directory_support::{Fixture, Member, Org, body, err, fixture, ok, run};
use serde_json::{Value, json};

fn managed(actions: &[&str], parent: Option<&str>, relations: &[&str]) -> ResourceTypeDefinition {
    ResourceTypeDefinition {
        managed: Some(true),
        parent: parent.map(str::to_owned),
        actions: Some(actions.iter().map(|action| (*action).to_owned()).collect()),
        relations: (!relations.is_empty()).then(|| {
            relations
                .iter()
                .map(|relation| (*relation).to_owned())
                .collect()
        }),
        ..ResourceTypeDefinition::default()
    }
}

async fn setup() -> (Fixture, Org) {
    let f = fixture(
        "access-test-secret-with-at-least-32-characters",
        |options| {
            let mut types = indexmap::IndexMap::new();
            let mut document = managed(&["documents:read", "documents:write"], None, &["viewer"]);
            let mut attributes = indexmap::IndexMap::new();
            attributes.insert("classification".to_owned(), AttributeType::String);
            document.attributes = Some(attributes);
            types.insert("document".to_owned(), document);
            types.insert("folder".to_owned(), managed(&["folders:read"], None, &[]));
            types.insert(
                "page".to_owned(),
                managed(&["pages:read"], Some("folder"), &[]),
            );
            options.permissions = Some(PermissionsConfig {
                mode: Some(PermissionsMode::TenantDefined),
                resource_types: Some(types),
                ..PermissionsConfig::default()
            });
        },
    )
    .await;
    let org = f.organization("Acme", "owner@acme.test").await;
    (f, org)
}

async fn allowed(f: &Fixture, org: &Org, who: &Member, action: &str, kind: &str, id: &str) -> bool {
    f.iam
        .authorize(&AuthorizationRequest {
            credential: who.credential.clone(),
            tenant_id: org.tenant_id.clone(),
            action: action.into(),
            resource: ResourceTarget {
                kind: kind.into(),
                id: id.into(),
            },
        })
        .await
        .expect("decision")
        .allowed
}

fn resource_ids(list: &Value) -> Vec<Value> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|record| record["resourceId"].clone())
        .collect()
}

#[test]
fn lets_a_role_grant_access_to_the_resources_a_principal_owns_without_an_application_resolver() {
    run(|| async {
        let (f, org) = setup().await;
        let api = &f.iam.api.resources;
        let alice = f.member(&org, "alice").await;
        let bob = f.member(&org, "bob").await;
        let owners = f
            .role(
                &org,
                json!([
                    {
                        "effect": "allow",
                        "actions": ["documents:read", "documents:write"],
                        "resources": ["document/*"],
                        "conditions": { "StringEquals": { "resource.ownerId": "${principal.id}" } },
                    },
                    { "effect": "allow", "actions": ["folders:read"], "resources": ["folder/home-${principal.id}"] },
                ]),
            )
            .await;
        for person in [&alice, &bob] {
            f.bind(&org, &owners, "identity", &person.id, json!({}))
                .await;
        }
        let notes = ok(api
            .register(
                &org.owner,
                body(json!({
                    "tenantId": org.tenant_id,
                    "type": "document",
                    "id": "alice-notes",
                    "ownerId": alice.id,
                    "attributes": { "classification": "internal" },
                })),
            )
            .await);
        assert_eq!(notes["uniqueKey"], json!("document/alice-notes"));
        assert_eq!(notes["attributes"], json!({ "classification": "internal" }));
        assert_eq!(notes["ownerId"], json!(alice.id));
        assert_eq!(notes["createdAt"], notes["updatedAt"]);
        ok(api
            .register(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "type": "document", "id": "bob-notes", "ownerId": bob.id })),
            )
            .await);
        ok(api
            .register(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "type": "folder", "id": format!("home-{}", alice.id) })),
            )
            .await);
        // An id holding a wildcard would read as a pattern in iam/{type}/{id}: registration refuses it.
        for id in ["home-*", "home-?"] {
            let error = err(api
                .register(
                    &org.owner,
                    body(json!({ "tenantId": org.tenant_id, "type": "folder", "id": id })),
                )
                .await);
            assert_eq!(
                (error.code.as_str(), error.message.as_str()),
                ("INVALID_INPUT", "A resource ID cannot contain * or ?")
            );
        }
        assert!(
            allowed(
                &f,
                &org,
                &alice,
                "documents:write",
                "document",
                "alice-notes"
            )
            .await
        );
        assert!(!allowed(&f, &org, &alice, "documents:read", "document", "bob-notes").await);
        assert!(allowed(&f, &org, &bob, "documents:write", "document", "bob-notes").await);
        let home = format!("home-{}", alice.id);
        assert!(allowed(&f, &org, &alice, "folders:read", "folder", &home).await);
        // Ownership moves with an update, and `ownerId: null` clears it.
        let moved = ok(api
            .update(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "type": "document", "id": "bob-notes", "ownerId": alice.id })),
            )
            .await);
        assert_eq!(moved["ownerId"], json!(alice.id));
        assert!(allowed(&f, &org, &alice, "documents:read", "document", "bob-notes").await);
        assert!(!allowed(&f, &org, &bob, "documents:read", "document", "bob-notes").await);
        let cleared = ok(api
            .update(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "type": "document", "id": "bob-notes", "ownerId": null })),
            )
            .await);
        assert!(cleared.get("ownerId").is_none());
        assert!(!allowed(&f, &org, &alice, "documents:read", "document", "bob-notes").await);
    });
}

#[test]
fn authorizes_every_item_of_a_batch_before_writing_and_rolls_back_on_conflict() {
    run(|| async {
        let (f, org) = setup().await;
        let api = &f.iam.api.resources;
        let limited = f.member(&org, "limited").await;
        f.grant(
            &org,
            &limited.id,
            json!([{ "effect": "allow", "actions": ["iam:resources:create"], "resources": ["iam/folder/*"] }]),
        )
        .await;
        let denied = err(api
            .register_many(
                &limited.credential,
                body(json!({
                    "tenantId": org.tenant_id,
                    "resources": [{ "type": "folder", "id": "ok" }, { "type": "document", "id": "nope" }],
                })),
            )
            .await);
        assert_eq!(
            (denied.code.as_str(), denied.message.as_str(), denied.status),
            ("ACCESS_DENIED", "Access denied for document/nope", 403)
        );
        let list = || api.list(&org.owner, body(json!({ "tenantId": org.tenant_id })));
        assert_eq!(ok(list().await), json!([]));
        let result = ok(api
            .register_many(
                &limited.credential,
                body(json!({
                    "tenantId": org.tenant_id,
                    "resources": [{ "type": "folder", "id": "one" }, { "type": "folder", "id": "two" }],
                })),
            )
            .await);
        assert_eq!(
            resource_ids(&result["resources"]),
            vec![json!("one"), json!("two")]
        );
        let conflict = err(api
            .register_many(
                &limited.credential,
                body(json!({
                    "tenantId": org.tenant_id,
                    "resources": [{ "type": "folder", "id": "three" }, { "type": "folder", "id": "one" }],
                })),
            )
            .await);
        assert_eq!(conflict.code, "CONFLICT");
        assert_eq!(
            resource_ids(&ok(list().await)),
            vec![json!("one"), json!("two")]
        );
        for input in [
            json!({ "tenantId": org.tenant_id, "resources": [] }),
            json!({ "tenantId": org.tenant_id, "resources": "folder/one" }),
            json!({ "tenantId": org.tenant_id, "resources": (0..101).map(|i| json!({ "type": "folder", "id": format!("f{i}") })).collect::<Vec<_>>() }),
        ] {
            let error = err(api.register_many(&org.owner, body(input)).await);
            assert_eq!(
                (error.code.as_str(), error.message.as_str()),
                ("INVALID_INPUT", "Provide 1-100 resources")
            );
        }
        let item = err(api
            .register_many(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "resources": [{ "type": "folder" }] })),
            )
            .await);
        assert_eq!(item.message, "Invalid resource id");
        // The refusal is the only audit record of the denied batch; the allowed batch audits each item.
        let events = f.audit(&org.tenant_id, "iam:resources:create").await;
        let denied: Vec<&Value> = events
            .iter()
            .filter(|event| event["outcome"] == json!("deny"))
            .map(|event| &event["resourceId"])
            .collect();
        assert_eq!(denied, vec![&json!("document/nope")]);
        let mut allowed: Vec<&str> = events
            .iter()
            .filter(|event| event["outcome"] == json!("allow"))
            .map(|event| event["resourceId"].as_str().unwrap())
            .collect();
        allowed.sort();
        assert_eq!(allowed, vec!["folder/one", "folder/two"]);
    });
}

#[test]
fn leaves_out_records_a_policy_keeps_from_the_caller_and_refuses_wildcard_ids() {
    run(|| async {
        let (f, org) = setup().await;
        let api = &f.iam.api.resources;
        for id in ["handbook", "payroll"] {
            ok(api
                .register(
                    &org.owner,
                    body(json!({ "tenantId": org.tenant_id, "type": "document", "id": id })),
                )
                .await);
        }
        let wildcard = err(api
            .register(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "type": "document", "id": "*" })),
            )
            .await);
        assert_eq!(wildcard.code, "INVALID_INPUT");
        let bob = f.member(&org, "bob").await;
        f.grant(
            &org,
            &bob.id,
            json!([
                { "effect": "allow", "actions": ["iam:resources:read", "iam:relationships:read"], "resources": ["*"] },
                { "effect": "deny", "actions": ["iam:resources:read", "iam:relationships:read"], "resources": ["iam/document/payroll"] },
            ]),
        )
        .await;
        let denied = err(api
            .get(
                &bob.credential,
                body(json!({ "tenantId": org.tenant_id, "type": "document", "id": "payroll" })),
            )
            .await);
        assert_eq!(denied.code, "ACCESS_DENIED");
        let fetched = ok(api
            .get(
                &bob.credential,
                body(json!({ "tenantId": org.tenant_id, "type": "document", "id": "handbook" })),
            )
            .await);
        assert_eq!(fetched["resourceId"], json!("handbook"));
        let listed = ok(api
            .list(
                &bob.credential,
                body(json!({ "tenantId": org.tenant_id, "type": "document" })),
            )
            .await);
        assert_eq!(resource_ids(&listed), vec![json!("handbook")]);
        let everything = ok(api
            .list(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "type": "document" })),
            )
            .await);
        assert_eq!(everything.as_array().unwrap().len(), 2);
        // Relationship tuples of a resource the caller may not read are left out the same way.
        let alice = f.member(&org, "alice").await;
        for id in ["handbook", "payroll"] {
            ok(f.iam
                .api
                .relationships
                .create(
                    &org.owner,
                    body(json!({
                        "tenantId": org.tenant_id,
                        "type": "document",
                        "id": id,
                        "relation": "viewer",
                        "subjectType": "identity",
                        "subjectId": alice.id,
                    })),
                )
                .await);
        }
        let tuples = ok(f
            .iam
            .api
            .relationships
            .list(
                &bob.credential,
                body(json!({ "tenantId": org.tenant_id, "type": "document" })),
            )
            .await);
        assert_eq!(resource_ids(&tuples), vec![json!("handbook")]);
        let all = ok(f
            .iam
            .api
            .relationships
            .list(&org.owner, body(json!({ "tenantId": org.tenant_id })))
            .await);
        assert_eq!(all.as_array().unwrap().len(), 2);
    });
}

#[test]
fn enforces_the_tenant_plan_limits_for_resources_and_webhooks() {
    run(|| async {
        let (f, org) = setup().await;
        f.update(
            "tenants",
            &org.tenant_id,
            json!({ "limits": { "resources": 2, "webhooks": 1 } }),
        )
        .await;
        let api = &f.iam.api.resources;
        let folder = |id: &str| json!({ "tenantId": org.tenant_id, "type": "folder", "id": id });
        ok(api.register(&org.owner, body(folder("one"))).await);
        let batch = err(api
            .register_many(
                &org.owner,
                body(json!({
                    "tenantId": org.tenant_id,
                    "resources": [{ "type": "folder", "id": "two" }, { "type": "folder", "id": "three" }],
                })),
            )
            .await);
        assert_eq!(batch.code, "LIMIT_EXCEEDED");
        ok(api.register(&org.owner, body(folder("two"))).await);
        let single = err(api.register(&org.owner, body(folder("three"))).await);
        assert_eq!(
            (single.code.as_str(), single.message.as_str(), single.status),
            (
                "LIMIT_EXCEEDED",
                "This tenant has reached its resource limit (2)",
                409
            )
        );
        let hook = |url: &str| json!({ "tenantId": org.tenant_id, "url": url, "events": ["*"] });
        ok(f.iam
            .api
            .webhooks
            .create(&org.owner, body(hook("https://hooks.example.test/a")))
            .await);
        let second = err(f
            .iam
            .api
            .webhooks
            .create(&org.owner, body(hook("https://hooks.example.test/b")))
            .await);
        assert_eq!(second.code, "LIMIT_EXCEEDED");
    });
}

#[test]
fn validates_parents_attributes_and_deletion_order() {
    run(|| async {
        let (f, org) = setup().await;
        let api = &f.iam.api.resources;
        let register = |input: Value| {
            let mut input = input;
            input["tenantId"] = json!(org.tenant_id);
            api.register(&org.owner, body(input))
        };
        let orphan = err(register(json!({ "type": "page", "id": "intro" })).await);
        assert_eq!(
            orphan.message,
            "Resources of type page require a folder parent"
        );
        let missing =
            err(register(json!({ "type": "page", "id": "intro", "parentId": "nowhere" })).await);
        assert_eq!((missing.code.as_str(), missing.status), ("NOT_FOUND", 404));
        let parentless =
            err(register(json!({ "type": "folder", "id": "docs", "parentId": "x" })).await);
        assert_eq!(parentless.message, "This resource type has no parent");
        let unknown = err(register(json!({ "type": "galaxy", "id": "x" })).await);
        assert_eq!(unknown.code, "INVALID_RESOURCE_TYPE");
        let owner =
            err(register(json!({ "type": "folder", "id": "docs", "ownerId": "nobody" })).await);
        assert_eq!(owner.status, 404);
        ok(register(json!({ "type": "folder", "id": "docs" })).await);
        let duplicate = err(register(json!({ "type": "folder", "id": "docs" })).await);
        assert_eq!(duplicate.code, "CONFLICT");
        let page = ok(register(json!({ "type": "page", "id": "intro", "parentId": "docs" })).await);
        assert_eq!(page["parentType"], json!("folder"));
        assert_eq!(page["parentId"], json!("docs"));
        ok(register(json!({ "type": "page", "id": "faq", "parentId": "docs" })).await);
        let wrong = err(register(
            json!({ "type": "document", "id": "memo", "attributes": { "classification": 3 } }),
        )
        .await);
        assert_eq!(wrong.code, "INVALID_INPUT");
        let undeclared = err(register(
            json!({ "type": "document", "id": "memo", "attributes": { "color": "red" } }),
        )
        .await);
        assert_eq!(undeclared.code, "INVALID_INPUT");
        ok(register(json!({ "type": "document", "id": "memo", "attributes": { "classification": "secret" } })).await);
        let updated = ok(api
            .update(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "type": "document", "id": "memo", "attributes": { "classification": "public" } })),
            )
            .await);
        assert_eq!(updated["attributes"], json!({ "classification": "public" }));
        let absent = err(api
            .update(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "type": "document", "id": "none", "attributes": {} })),
            )
            .await);
        assert_eq!(absent.message, "Resource is not registered");
        // Listing orders by type/id and pages through `limit` and `offset`.
        let page_of = |input: Value| {
            let mut input = input;
            input["tenantId"] = json!(org.tenant_id);
            api.list(&org.owner, body(input))
        };
        let keys = |list: &Value| -> Vec<String> {
            list.as_array()
                .unwrap()
                .iter()
                .map(|record| record["uniqueKey"].as_str().unwrap().to_owned())
                .collect()
        };
        assert_eq!(
            keys(&ok(page_of(json!({})).await)),
            vec!["document/memo", "folder/docs", "page/faq", "page/intro"]
        );
        assert_eq!(
            keys(&ok(page_of(json!({ "limit": 2, "offset": 1 })).await)),
            vec!["folder/docs", "page/faq"]
        );
        assert_eq!(
            keys(&ok(page_of(json!({ "parentId": "docs" })).await)),
            vec!["page/faq", "page/intro"]
        );
        let limit = err(page_of(json!({ "limit": 0 })).await);
        assert_eq!(limit.message, "Invalid limit");
        // A parent with children cannot be deleted; deleting the children first frees it.
        let delete = |kind: &str, id: &str| {
            api.delete(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "type": kind, "id": id })),
            )
        };
        let in_use = err(delete("folder", "docs").await);
        assert_eq!(
            (in_use.code.as_str(), in_use.message.as_str()),
            ("RESOURCE_IN_USE", "Delete child resources first")
        );
        ok(delete("page", "intro").await);
        ok(delete("page", "faq").await);
        assert_eq!(
            ok(delete("folder", "docs").await),
            json!({ "deleted": true })
        );
        let gone = err(api
            .get(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "type": "folder", "id": "docs" })),
            )
            .await);
        assert_eq!((gone.code.as_str(), gone.status), ("NOT_FOUND", 404));
        assert_eq!(err(delete("folder", "docs").await).status, 404);
    });
}
