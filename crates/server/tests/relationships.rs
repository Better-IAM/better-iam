//! Relationship tuples (tests/relationships.test.ts). Members, groups, roles and bindings are written to the store
//! directly where the TypeScript test uses the `identities`, `groups`, `roles` and `bindings` groups.

mod directory_support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use better_iam_core::{
    CredentialInput, Filter, FindOptions, IamError, IamStoreExt, PermissionsConfig,
    PermissionsMode, ResourceTypeDefinition,
};
use better_iam_server::options::{
    AccessibleResourcesRequest, AuthorizationRequest, ResolvedResource, ResourceTarget,
};
use directory_support::{Fixture, Member, Org, body, err, fixture, ok, run};
use serde_json::{Map, Value, json};

type Documents = Arc<Mutex<HashMap<String, String>>>;

fn definition(
    actions: &[&str],
    relations: &[&str],
    parent: Option<&str>,
    managed: bool,
) -> ResourceTypeDefinition {
    ResourceTypeDefinition {
        managed: managed.then_some(true),
        parent: parent.map(str::to_owned),
        actions: Some(actions.iter().map(|action| (*action).to_owned()).collect()),
        relations: Some(
            relations
                .iter()
                .map(|relation| (*relation).to_owned())
                .collect(),
        ),
        ..ResourceTypeDefinition::default()
    }
}

async fn setup() -> (Fixture, Org, Documents) {
    let documents: Documents = Arc::default();
    let notes = documents.clone();
    let f = fixture(
        "relationships-test-secret-with-at-least-32-chars",
        move |options| {
            let mut types = indexmap::IndexMap::new();
            types.insert(
                "folder".to_owned(),
                definition(
                    &["folders:read", "folders:share"],
                    &["viewer", "editor", "owner"],
                    None,
                    true,
                ),
            );
            types.insert(
                "file".to_owned(),
                definition(
                    &["files:read", "files:write"],
                    &["viewer", "editor"],
                    Some("folder"),
                    true,
                ),
            );
            types.insert(
                "note".to_owned(),
                definition(&["notes:read"], &["reader"], None, false),
            );
            options.permissions = Some(PermissionsConfig {
                mode: Some(PermissionsMode::TenantDefined),
                resource_types: Some(types),
                ..PermissionsConfig::default()
            });
            options.resolve_resource = Some(Arc::new(move |reference| {
                let title = notes.lock().unwrap().get(&reference.id).cloned();
                Box::pin(async move {
                    match title {
                        Some(title) if reference.kind == "note" => {
                            let mut resource = ResolvedResource::of(&reference);
                            let mut attributes = Map::new();
                            attributes.insert("title".into(), Value::String(title));
                            resource.attributes = Some(attributes);
                            Ok(resource)
                        }
                        _ => Err(IamError::new("INTERNAL_ERROR", "unknown")),
                    }
                })
            }));
        },
    )
    .await;
    let org = f.organization("Acme", "owner@acme.test").await;
    (f, org, documents)
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

fn tuple(org: &Org, kind: &str, id: &str, relation: &str, subject: (&str, &str)) -> Value {
    json!({
        "tenantId": org.tenant_id,
        "type": kind,
        "id": id,
        "relation": relation,
        "subjectType": subject.0,
        "subjectId": subject.1,
    })
}

#[test]
fn grants_access_through_held_relations_on_the_resource_or_its_parent_for_identities_and_groups_with_expiry()
 {
    run(|| async {
        let (f, org, documents) = setup().await;
        let api = &f.iam.api.relationships;
        let owner = &org.owner;
        let alice = f.member(&org, "alice").await;
        let bob = f.member(&org, "bob").await;
        let team = f.group(&org, "Team").await;
        f.add_member(&org, &team, &bob.id, None).await;
        let sharing = f
            .role(
                &org,
                json!([
                    {
                        "effect": "allow",
                        "actions": ["folders:read", "files:read"],
                        "resources": ["*"],
                        "conditions": { "ArrayContains": { "resource.relations": ["viewer", "editor", "owner"] } },
                    },
                    {
                        "effect": "allow",
                        "actions": ["files:read"],
                        "resources": ["file/*"],
                        "conditions": { "ArrayContains": { "resource.parentRelations": ["viewer", "editor", "owner"] } },
                    },
                    {
                        "effect": "allow",
                        "actions": ["files:write"],
                        "resources": ["file/*"],
                        "conditions": { "ArrayContains": { "resource.relations": ["editor"] } },
                    },
                    {
                        "effect": "allow",
                        "actions": ["folders:share", "iam:relationships:create", "iam:relationships:read"],
                        "resources": ["*"],
                        "conditions": { "ArrayContains": { "resource.relations": ["owner"] } },
                    },
                    {
                        "effect": "allow",
                        "actions": ["iam:relationships:create"],
                        "resources": ["iam/file/*"],
                        "conditions": { "ArrayContains": { "resource.parentRelations": ["owner"] } },
                    },
                    {
                        "effect": "allow",
                        "actions": ["notes:read"],
                        "resources": ["note/*"],
                        "conditions": { "ArrayContains": { "resource.relations": ["reader"] } },
                    },
                ]),
            )
            .await;
        for person in [&alice, &bob] {
            f.bind(&org, &sharing, "identity", &person.id, json!({}))
                .await;
        }
        ok(f.iam
            .api
            .resources
            .register_many(
                owner,
                body(json!({
                    "tenantId": org.tenant_id,
                    "resources": [
                        { "type": "folder", "id": "plans" },
                        { "type": "file", "id": "roadmap", "parentId": "plans" },
                        { "type": "folder", "id": "private" },
                        { "type": "file", "id": "diary", "parentId": "private" },
                    ],
                })),
            )
            .await);
        assert!(!allowed(&f, &org, &alice, "folders:read", "folder", "plans").await);
        // Validation: undeclared relations, unknown types, unregistered managed resources, and wrong subjects.
        for (input, code) in [
            (
                tuple(&org, "folder", "plans", "admin", ("identity", &alice.id)),
                "INVALID_INPUT",
            ),
            (
                tuple(&org, "nothing", "x", "viewer", ("identity", &alice.id)),
                "INVALID_RESOURCE_TYPE",
            ),
            (
                tuple(&org, "folder", "missing", "viewer", ("identity", &alice.id)),
                "NOT_FOUND",
            ),
            (
                tuple(&org, "folder", "plans", "viewer", ("identity", "nobody")),
                "NOT_FOUND",
            ),
            (
                tuple(&org, "folder", "plans", "viewer", ("robot", &alice.id)),
                "INVALID_INPUT",
            ),
        ] {
            assert_eq!(
                err(api.create(owner, body(input.clone())).await).code,
                code,
                "{input}"
            );
        }
        // Alice owns the folder; the team can view it. Relations flow to files through the parent.
        let owner_tuple = ok(api
            .create(
                owner,
                body(tuple(
                    &org,
                    "folder",
                    "plans",
                    "owner",
                    ("identity", &alice.id),
                )),
            )
            .await);
        assert_eq!(
            owner_tuple["uniqueKey"],
            json!(format!("folder/plans#owner@identity:{}", alice.id))
        );
        assert_eq!(owner_tuple["createdBy"], json!(org.owner_id));
        // Creating the same tuple again keeps its ID.
        let again = ok(api
            .create(
                owner,
                body(tuple(
                    &org,
                    "folder",
                    "plans",
                    "owner",
                    ("identity", &alice.id),
                )),
            )
            .await);
        assert_eq!(again["id"], owner_tuple["id"]);
        ok(api
            .create(
                owner,
                body(tuple(&org, "folder", "plans", "viewer", ("group", &team))),
            )
            .await);
        assert!(allowed(&f, &org, &alice, "folders:read", "folder", "plans").await);
        assert!(allowed(&f, &org, &alice, "files:read", "file", "roadmap").await);
        assert!(!allowed(&f, &org, &alice, "files:write", "file", "roadmap").await);
        assert!(allowed(&f, &org, &bob, "folders:read", "folder", "plans").await);
        assert!(allowed(&f, &org, &bob, "files:read", "file", "roadmap").await);
        assert!(!allowed(&f, &org, &bob, "files:read", "file", "diary").await);
        assert!(!allowed(&f, &org, &alice, "folders:read", "folder", "private").await);
        // The owner relation lets Alice share the folder herself; Bob cannot.
        ok(api
            .create(
                &alice.credential,
                body(tuple(
                    &org,
                    "file",
                    "roadmap",
                    "editor",
                    ("identity", &bob.id),
                )),
            )
            .await);
        let denied = err(api
            .create(
                &bob.credential,
                body(tuple(
                    &org,
                    "folder",
                    "private",
                    "viewer",
                    ("identity", &bob.id),
                )),
            )
            .await);
        assert_eq!(denied.code, "ACCESS_DENIED");
        assert!(allowed(&f, &org, &bob, "files:write", "file", "roadmap").await);
        // Reverse queries and listings see relationships.
        let accessible = f
            .iam
            .list_accessible(&AccessibleResourcesRequest {
                credential: bob.credential.clone(),
                tenant_id: org.tenant_id.clone(),
                action: "files:read".into(),
                kind: "file".into(),
                limit: None,
                offset: None,
            })
            .await
            .unwrap();
        let ids: Vec<&Value> = accessible
            .resources
            .iter()
            .map(|resource| &resource["resourceId"])
            .collect();
        assert_eq!(ids, vec![&json!("roadmap")]);
        let on_folder = ok(api
            .list(
                &alice.credential,
                body(json!({ "tenantId": org.tenant_id, "type": "folder", "id": "plans" })),
            )
            .await);
        let mut kinds: Vec<String> = on_folder
            .as_array()
            .unwrap()
            .iter()
            .map(|tuple| {
                format!(
                    "{}:{}",
                    tuple["relation"].as_str().unwrap(),
                    tuple["subjectType"].as_str().unwrap()
                )
            })
            .collect();
        kinds.sort();
        assert_eq!(kinds, vec!["owner:identity", "viewer:group"]);
        assert_eq!(
            err(api
                .list(&bob.credential, body(json!({ "tenantId": org.tenant_id })))
                .await)
            .code,
            "ACCESS_DENIED"
        );
        let held = ok(api
            .list(
                owner,
                body(json!({ "tenantId": org.tenant_id, "subjectType": "identity", "subjectId": bob.id })),
            )
            .await);
        let relations: Vec<&Value> = held
            .as_array()
            .unwrap()
            .iter()
            .map(|tuple| &tuple["relation"])
            .collect();
        assert_eq!(relations, vec![&json!("editor")]);
        // Application-owned resources can carry relations too.
        documents
            .lock()
            .unwrap()
            .insert("memo".into(), "Memo".into());
        assert!(!allowed(&f, &org, &alice, "notes:read", "note", "memo").await);
        let mut expiring = tuple(&org, "note", "memo", "reader", ("identity", &alice.id));
        expiring["expiresAt"] = json!(f.now() + 60_000.0);
        ok(api.create(owner, body(expiring)).await);
        assert!(allowed(&f, &org, &alice, "notes:read", "note", "memo").await);
        f.advance(61_000.0);
        assert!(!allowed(&f, &org, &alice, "notes:read", "note", "memo").await);
        // Expired tuples are listed only on request.
        let notes = |include: bool| {
            api.list(
                owner,
                body(
                    json!({ "tenantId": org.tenant_id, "type": "note", "includeExpired": include }),
                ),
            )
        };
        assert_eq!(ok(notes(false).await), json!([]));
        assert_eq!(ok(notes(true).await).as_array().unwrap().len(), 1);
        // Deleting a tuple, a group, or a resource removes the access it carried.
        let denied = err(api
            .delete(
                &bob.credential,
                body(json!({ "tenantId": org.tenant_id, "relationshipId": owner_tuple["id"] })),
            )
            .await);
        assert_eq!(denied.code, "ACCESS_DENIED");
        ok(api
            .delete(
                owner,
                body(json!({ "tenantId": org.tenant_id, "relationshipId": owner_tuple["id"] })),
            )
            .await);
        assert!(!allowed(&f, &org, &alice, "folders:read", "folder", "plans").await);
        delete_group(&f, &org, &team).await;
        assert!(!allowed(&f, &org, &bob, "folders:read", "folder", "plans").await);
        assert!(allowed(&f, &org, &bob, "files:write", "file", "roadmap").await);
        ok(f.iam
            .api
            .resources
            .delete(
                owner,
                body(json!({ "tenantId": org.tenant_id, "type": "file", "id": "roadmap" })),
            )
            .await);
        let remaining = f
            .iam
            .store
            .find(
                "relationships",
                &Filter::new()
                    .eq("tenantId", org.tenant_id.clone())
                    .eq("type", "file"),
                &FindOptions::default(),
            )
            .await
            .unwrap();
        assert!(remaining.is_empty());
        // Tenant-defined types declare relations too, and a relation in use cannot be dropped.
        let ticket = ok(f
            .iam
            .api
            .resource_types
            .register(
                owner,
                body(json!({ "tenantId": org.tenant_id, "name": "ticket", "actions": ["read"], "relations": ["assignee"] })),
            )
            .await);
        assert_eq!(ticket["relations"], json!(["assignee"]));
        ok(f.iam
            .api
            .resources
            .register(
                owner,
                body(json!({ "tenantId": org.tenant_id, "type": "ticket", "id": "t1" })),
            )
            .await);
        ok(api
            .create(
                owner,
                body(tuple(
                    &org,
                    "ticket",
                    "t1",
                    "assignee",
                    ("identity", &alice.id),
                )),
            )
            .await);
        let in_use = err(f
            .iam
            .api
            .resource_types
            .update(
                owner,
                body(json!({ "tenantId": org.tenant_id, "name": "ticket", "relations": [] })),
            )
            .await);
        assert_eq!(in_use.code, "RESOURCE_IN_USE");
        let updated = ok(f
            .iam
            .api
            .resource_types
            .update(
                owner,
                body(json!({ "tenantId": org.tenant_id, "name": "ticket", "relations": ["assignee", "watcher"] })),
            )
            .await);
        assert_eq!(updated["relations"], json!(["assignee", "watcher"]));
        let invalid = err(f
            .iam
            .api
            .resource_types
            .register(
                owner,
                body(
                    json!({ "tenantId": org.tenant_id, "name": "bad", "relations": ["Not Valid"] }),
                ),
            )
            .await);
        assert_eq!(invalid.code, "INVALID_INPUT");
    });
}

#[test]
fn audits_relationship_changes_on_the_resource_and_validates_before_authenticating() {
    run(|| async {
        let (f, org, _) = setup().await;
        let api = &f.iam.api.relationships;
        let alice = f.member(&org, "alice").await;
        ok(f.iam
            .api
            .resources
            .register(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "type": "folder", "id": "plans" })),
            )
            .await);
        let created = ok(api
            .create(
                &org.owner,
                body(tuple(
                    &org,
                    "folder",
                    "plans",
                    "viewer",
                    ("identity", &alice.id),
                )),
            )
            .await);
        let events = f.audit(&org.tenant_id, "iam:relationships:create").await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["resourceId"], json!("folder/plans"));
        assert_eq!(events[0]["outcome"], json!("allow"));
        ok(api
            .delete(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "relationshipId": created["id"] })),
            )
            .await);
        let events = f.audit(&org.tenant_id, "iam:relationships:delete").await;
        assert_eq!(events[0]["resourceId"], json!("folder/plans"));
        // An unknown tuple is not found before any operation runs.
        let missing = err(api
            .delete(
                &org.owner,
                body(json!({ "tenantId": org.tenant_id, "relationshipId": "missing" })),
            )
            .await);
        assert_eq!((missing.code.as_str(), missing.status), ("NOT_FOUND", 404));
        // Inputs are validated before the credential is looked at.
        let anonymous = CredentialInput::default();
        let invalid = err(api
            .create(
                &anonymous,
                body(json!({ "tenantId": org.tenant_id, "type": "folder", "id": 7 })),
            )
            .await);
        assert_eq!(
            (invalid.code.as_str(), invalid.message.as_str()),
            ("INVALID_INPUT", "Invalid resource id")
        );
        let unauthenticated = err(api
            .list(&anonymous, body(json!({ "tenantId": org.tenant_id })))
            .await);
        assert_eq!(unauthenticated.status, 401);
    });
}

/// `groups.delete`: the group, its memberships, and the relationship tuples it holds.
async fn delete_group(f: &Fixture, org: &Org, group_id: &str) {
    let (tenant_id, group_id) = (org.tenant_id.clone(), group_id.to_owned());
    f.iam
        .store
        .transaction(|tx| async move {
            for (collection, filter) in [
                (
                    "groupMembers",
                    Filter::new()
                        .eq("tenantId", tenant_id.clone())
                        .eq("groupId", group_id.clone()),
                ),
                (
                    "relationships",
                    Filter::new()
                        .eq("tenantId", tenant_id.clone())
                        .eq("subjectType", "group")
                        .eq("subjectId", group_id.clone()),
                ),
            ] {
                for record in tx
                    .find(collection, &filter, &FindOptions::default())
                    .await?
                {
                    tx.delete(collection, record["id"].as_str().unwrap())
                        .await?;
                }
            }
            tx.delete("groups", &group_id).await
        })
        .await
        .unwrap();
}
