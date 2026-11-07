//! The `roles` API group: tests/role-inheritance.test.ts (the parts that do not need the bindings and config API
//! groups, whose bindings are written to the store here), the role cases of tests/server-security.test.ts, and the
//! rules of api/roles.ts (validation, protected roles, the denies other administrators rely on, binding listings).

mod grants;

use better_iam_core::Filter;
use grants::{
    bind, body, can, code, find, fixture, identity, insert_all, refused, run, session, value,
};
use serde_json::{Value, json};

#[test]
fn includes_inherited_grants_validates_the_hierarchy_and_protects_inherited_roles() {
    run(|| async {
        let f = fixture().await;
        let api = &f.iam.api;
        let user = &f.credential;
        let viewer = value(
            api.roles
                .create(
                    user,
                    body(json!({ "tenantId": "a", "name": "Viewer", "permissions": ["documents:read"] })),
                )
                .await,
        )
        .unwrap();
        let viewer_id = viewer["id"].as_str().unwrap().to_owned();
        assert_eq!(
            viewer["document"],
            json!({
                "version": 1,
                "statements": [{ "sid": "RolePermissions", "effect": "allow", "actions": ["documents:read"], "resources": ["*"] }],
            })
        );
        assert_eq!(viewer["authorityId"], json!("user-authority"));
        let editor = value(
            api.roles
                .create(
                    user,
                    body(json!({
                        "tenantId": "a",
                        "name": "Editor",
                        "permissions": ["documents:write"],
                        "inherits": [viewer_id],
                    })),
                )
                .await,
        )
        .unwrap();
        let editor_id = editor["id"].as_str().unwrap().to_owned();
        assert_eq!(editor["inherits"], json!([viewer_id]));
        // Cycles, self-inheritance, protected roles, and unknown roles are refused.
        assert_eq!(
            code(value(
                api.roles
                    .update(
                        user,
                        body(
                            json!({ "tenantId": "a", "roleId": viewer_id, "inherits": [editor_id] })
                        )
                    )
                    .await
            )),
            "INVALID_INPUT"
        );
        assert_eq!(
            code(value(
                api.roles
                    .update(
                        user,
                        body(
                            json!({ "tenantId": "a", "roleId": viewer_id, "inherits": [viewer_id] })
                        )
                    )
                    .await
            )),
            "INVALID_INPUT"
        );
        insert_all(
            &f.iam,
            vec![(
                "roles",
                json!({ "id": "owner-role", "tenantId": "a", "name": "Owner", "uniqueKey": "system:owner", "policyIds": [], "protected": true }),
            )],
        )
        .await;
        let roles = value(api.roles.list(user, body(json!({ "tenantId": "a" }))).await).unwrap();
        let owner_role = roles
            .as_array()
            .unwrap()
            .iter()
            .find(|role| role["protected"] == json!(true))
            .unwrap()["id"]
            .clone();
        assert_eq!(
            code(value(
                api.roles
                    .update(
                        user,
                        body(json!({ "tenantId": "a", "roleId": editor_id, "inherits": [owner_role] }))
                    )
                    .await
            )),
            "PROTECTED_RESOURCE"
        );
        assert_eq!(
            code(value(
                api.roles
                    .create(
                        user,
                        body(json!({ "tenantId": "a", "name": "Broken", "inherits": ["missing"] }))
                    )
                    .await
            )),
            "NOT_FOUND"
        );
        // Editors read through Viewer; viewers cannot write.
        let alice = identity(&f.iam, "a", "alice@example.com", "Alice").await;
        let bob = identity(&f.iam, "a", "bob@example.com", "Bob").await;
        bind(&f.iam, &editor_id, &alice.id, "user-authority").await;
        bind(&f.iam, &viewer_id, &bob.id, "user-authority").await;
        let as_alice = session(&f.iam, &alice, false).await;
        let as_bob = session(&f.iam, &bob, false).await;
        assert!(can(&f.iam, &as_alice, "documents:read", "a").await);
        assert!(can(&f.iam, &as_alice, "documents:write", "a").await);
        assert!(can(&f.iam, &as_bob, "documents:read", "a").await);
        assert!(!can(&f.iam, &as_bob, "documents:write", "a").await);
        let review = value(
            api.policies
                .effective_actions(
                    user,
                    body(json!({
                        "tenantId": "a",
                        "identityId": alice.id,
                        "resource": { "type": "document", "id": "a" },
                        "actions": ["documents:write", "documents:read"],
                    })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(
            review["allowed"],
            json!(["documents:read", "documents:write"])
        );
        // An inherited role cannot be deleted; clearing the inheritance removes the inherited grant.
        assert_eq!(
            refused(value(
                api.roles
                    .delete(user, body(json!({ "tenantId": "a", "roleId": viewer_id })))
                    .await
            )),
            ("RESOURCE_IN_USE".to_owned(), 409)
        );
        let cleared = value(
            api.roles
                .update(
                    user,
                    body(json!({ "tenantId": "a", "roleId": editor_id, "inherits": [] })),
                )
                .await,
        )
        .unwrap();
        assert!(cleared.get("inherits").is_none());
        assert!(!can(&f.iam, &as_alice, "documents:read", "a").await);
        assert_eq!(
            value(
                api.roles
                    .delete(user, body(json!({ "tenantId": "a", "roleId": viewer_id })))
                    .await
            )
            .unwrap(),
            json!({ "deleted": true })
        );
        // The role's bindings went with it.
        assert!(
            find(
                &f.iam,
                "bindings",
                Filter::new().eq("roleId", viewer_id.clone())
            )
            .await
            .is_empty()
        );
    });
}

#[test]
fn bounds_inherited_grants_by_the_inheriting_roles_own_authority_ceiling() {
    run(|| async {
        let f = fixture().await;
        let api = &f.iam.api;
        let user = &f.credential;
        let full_role = value(
            api.roles
                .create(
                    user,
                    body(json!({ "tenantId": "a", "name": "Full", "permissions": ["documents:read", "documents:write"] })),
                )
                .await,
        )
        .unwrap();
        // Bob administers under a ceiling that only allows reads, plus the permissions to create roles.
        let bob = identity(&f.iam, "a", "bob@example.com", "Bob").await;
        let carol = identity(&f.iam, "a", "carol@example.com", "Carol").await;
        let admin = value(
            api.roles
                .create(
                    user,
                    body(json!({
                        "tenantId": "a",
                        "name": "Delegated admin",
                        "permissions": ["iam:roles:create", "iam:roles:read", "iam:roles:update", "iam:bindings:create"],
                    })),
                )
                .await,
        )
        .unwrap();
        bind(
            &f.iam,
            admin["id"].as_str().unwrap(),
            &bob.id,
            "user-authority",
        )
        .await;
        let authority = value(
            api.authorities
                .create(
                    user,
                    body(json!({
                        "tenantId": "a",
                        "identityId": bob.id,
                        "ceiling": { "version": 1, "statements": [{ "effect": "allow", "actions": ["documents:read"], "resources": ["*"] }] },
                    })),
                )
                .await,
        )
        .unwrap();
        let as_bob = session(&f.iam, &bob, false).await;
        let narrow = value(
            api.roles
                .create(
                    &as_bob,
                    body(
                        json!({ "tenantId": "a", "name": "Narrow", "inherits": [full_role["id"]] }),
                    ),
                )
                .await,
        )
        .unwrap();
        assert_eq!(narrow["authorityId"], authority["id"]);
        bind(
            &f.iam,
            narrow["id"].as_str().unwrap(),
            &carol.id,
            authority["id"].as_str().unwrap(),
        )
        .await;
        let as_carol = session(&f.iam, &carol, false).await;
        assert!(can(&f.iam, &as_carol, "documents:read", "a").await);
        assert!(!can(&f.iam, &as_carol, "documents:write", "a").await);
        // A role created under Bob's authority is not the user's to edit.
        assert_eq!(
            code(value(
                api.roles
                    .update(
                        user,
                        body(json!({ "tenantId": "a", "roleId": narrow["id"], "inherits": [] }))
                    )
                    .await
            )),
            "ACCESS_DENIED"
        );
        let cleared = value(
            api.roles
                .update(
                    &as_bob,
                    body(json!({ "tenantId": "a", "roleId": narrow["id"], "inherits": [] })),
                )
                .await,
        )
        .unwrap();
        assert!(cleared.get("inherits").is_none());
        assert!(!can(&f.iam, &as_carol, "documents:read", "a").await);
    });
}

#[test]
fn enforces_explicit_deny_attachments_when_lower_authorities_delete_roles() {
    run(|| async {
        let f = fixture().await;
        insert_all(
            &f.iam,
            vec![
                ("groups", json!({ "id": "restricted-group", "tenantId": "a", "name": "Restricted" })),
                (
                    "groupMembers",
                    json!({ "id": "member", "tenantId": "a", "groupId": "restricted-group", "identityId": f.user.id }),
                ),
                (
                    "policies",
                    json!({
                        "id": "deny-policy",
                        "tenantId": "a",
                        "name": "Deny reads",
                        "version": 1,
                        "authorityId": "higher-authority",
                        "document": { "version": 1, "statements": [{ "effect": "deny", "actions": ["documents:read"], "resources": ["*"] }] },
                    }),
                ),
                (
                    "roles",
                    json!({ "id": "deny-role", "tenantId": "a", "name": "Deny role", "policyIds": ["deny-policy"], "protected": false, "authorityId": "higher-authority" }),
                ),
                (
                    "bindings",
                    json!({ "id": "deny-binding", "tenantId": "a", "subjectType": "group", "subjectId": "restricted-group", "roleId": "deny-role", "authorityId": "higher-authority" }),
                ),
            ],
        )
        .await;
        assert!(!can(&f.iam, &f.credential, "documents:read", "a-doc").await);
        assert_eq!(
            code(value(
                f.iam
                    .api
                    .roles
                    .delete(
                        &f.credential,
                        body(json!({ "tenantId": "a", "roleId": "deny-role" }))
                    )
                    .await
            )),
            "ACCESS_DENIED"
        );
        // A policy another authority issued is not the user's to change either.
        assert_eq!(
            code(value(
                f.iam
                    .api
                    .policies
                    .update(
                        &f.credential,
                        body(json!({ "tenantId": "a", "policyId": "deny-policy", "version": 1, "name": "Renamed" }))
                    )
                    .await
            )),
            "ACCESS_DENIED"
        );
        assert!(!can(&f.iam, &f.credential, "documents:read", "a-doc").await);
    });
}

#[test]
fn keeps_the_denies_another_authority_relies_on() {
    run(|| async {
        let f = fixture().await;
        let api = &f.iam.api;
        let user = &f.credential;
        let deny = json!({ "effect": "deny", "actions": ["documents:write"], "resources": ["document/secret"] });
        let allow = json!({ "effect": "allow", "actions": ["documents:read"], "resources": ["*"] });
        let role = value(
            api.roles
                .create(
                    user,
                    body(json!({
                        "tenantId": "a",
                        "name": "Guarded",
                        "document": { "version": 1, "statements": [allow, deny] },
                    })),
                )
                .await,
        )
        .unwrap();
        let role_id = role["id"].as_str().unwrap().to_owned();
        // Nobody else relies on the role yet: its editor may still drop the deny.
        let relaxed = value(
            api.roles
                .update(
                    user,
                    body(json!({
                        "tenantId": "a",
                        "roleId": role_id,
                        "document": { "version": 1, "statements": [allow] },
                    })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(relaxed["document"]["statements"], json!([allow]));
        value(
            api.roles
                .update(
                    user,
                    body(json!({
                        "tenantId": "a",
                        "roleId": role_id,
                        "document": { "version": 1, "statements": [allow, deny] },
                    })),
                )
                .await,
        )
        .unwrap();
        // Another administrator binds it: from now on its denies restrict what they granted.
        bind(&f.iam, &role_id, &f.other.id, "higher-authority").await;
        let removed = api
            .roles
            .update(
                user,
                body(json!({
                    "tenantId": "a",
                    "roleId": role_id,
                    "document": { "version": 1, "statements": [allow] },
                })),
            )
            .await;
        let error = removed.expect_err("refused");
        assert_eq!(
            (error.code.as_str(), error.status),
            ("PROTECTED_RESOURCE", 403)
        );
        assert!(
            error
                .message
                .starts_with("Other administrators rely on its deny statements")
        );
        // Adding a deny is always allowed; deleting the role would drop its denies with its bindings.
        let more = json!({ "effect": "deny", "actions": ["documents:read"], "resources": ["document/secret"] });
        value(
            api.roles
                .update(
                    user,
                    body(json!({
                        "tenantId": "a",
                        "roleId": role_id,
                        "document": { "version": 1, "statements": [allow, deny, more] },
                    })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(
            code(value(
                api.roles
                    .delete(user, body(json!({ "tenantId": "a", "roleId": role_id })))
                    .await
            )),
            "PROTECTED_RESOURCE"
        );
        // Root may.
        let restored = value(
            api.roles
                .update(
                    &f.root,
                    body(json!({
                        "tenantId": "a",
                        "roleId": role_id,
                        "document": { "version": 1, "statements": [allow] },
                    })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(restored["document"]["statements"], json!([allow]));

        // A policy attached to a role another authority bound carries the same protection.
        let policy = value(
            api.policies
                .create(
                    user,
                    body(json!({
                        "tenantId": "a",
                        "name": "Guarded policy",
                        "document": { "version": 1, "statements": [allow, deny] },
                    })),
                )
                .await,
        )
        .unwrap();
        let attached = value(
            api.roles
                .create(
                    user,
                    body(
                        json!({ "tenantId": "a", "name": "Attached", "policyIds": [policy["id"]] }),
                    ),
                )
                .await,
        )
        .unwrap();
        bind(
            &f.iam,
            attached["id"].as_str().unwrap(),
            &f.other.id,
            "higher-authority",
        )
        .await;
        assert_eq!(
            code(value(
                api.policies
                    .update(
                        user,
                        body(json!({
                            "tenantId": "a",
                            "policyId": policy["id"],
                            "version": 1,
                            "document": { "version": 1, "statements": [allow] },
                        }))
                    )
                    .await
            )),
            "PROTECTED_RESOURCE"
        );
    });
}

#[test]
fn validates_role_input_and_protects_system_roles() {
    run(|| async {
        let f = fixture().await;
        let api = &f.iam.api;
        let user = &f.credential;
        let create = |input: Value| async move { value(api.roles.create(user, body(input)).await) };
        assert_eq!(
            refused(
                create(json!({
                    "tenantId": "a",
                    "name": "Both",
                    "permissions": ["documents:read"],
                    "document": { "version": 1, "statements": [] },
                }))
                .await
            ),
            ("INVALID_INPUT".to_owned(), 400)
        );
        let empty = create(json!({ "tenantId": "a", "name": "Empty", "permissions": [] }))
            .await
            .err()
            .unwrap();
        assert_eq!(empty.message, "permissions must name at least one action");
        let unknown =
            create(json!({ "tenantId": "a", "name": "Burn", "permissions": ["documents:burn"] }))
                .await
                .err()
                .unwrap();
        assert_eq!(
            (unknown.code.as_str(), unknown.message.as_str()),
            ("INVALID_ACTION", "Unknown action documents:burn")
        );
        let nameless = create(json!({ "tenantId": "a", "permissions": ["documents:read"] }))
            .await
            .err()
            .unwrap();
        assert_eq!(nameless.message, "Invalid name");
        let missing_policy = create(json!({ "tenantId": "a", "name": "X", "policyIds": ["nope"] }))
            .await
            .err()
            .unwrap();
        assert_eq!(missing_policy.code, "NOT_FOUND");
        let described = create(json!({
            "tenantId": "a",
            "name": "Described",
            "description": "Reads documents",
            "policyIds": ["user-policy"],
        }))
        .await
        .unwrap();
        assert_eq!(described["description"], json!("Reads documents"));
        assert_eq!(described["policyIds"], json!(["user-policy"]));
        assert_eq!(described["protected"], json!(false));
        assert!(described.get("document").is_none());
        // A null document removes the inline document; updating a protected role is refused.
        let updated = value(
            api.roles
                .update(
                    user,
                    body(json!({
                        "tenantId": "a",
                        "roleId": described["id"],
                        "permissions": ["documents:write"],
                        "name": "Writers",
                    })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(updated["name"], json!("Writers"));
        assert_eq!(
            updated["document"]["statements"][0]["actions"],
            json!(["documents:write"])
        );
        let removed = value(
            api.roles
                .update(
                    user,
                    body(json!({ "tenantId": "a", "roleId": described["id"], "document": null })),
                )
                .await,
        )
        .unwrap();
        assert!(removed.get("document").is_none());
        insert_all(
            &f.iam,
            vec![(
                "roles",
                json!({ "id": "owner-role", "tenantId": "a", "name": "Owner", "uniqueKey": "system:owner", "policyIds": [], "protected": true }),
            )],
        )
        .await;
        for result in [
            value(
                api.roles
                    .update(
                        user,
                        body(json!({ "tenantId": "a", "roleId": "owner-role", "name": "Mine" })),
                    )
                    .await,
            ),
            value(
                api.roles
                    .delete(
                        user,
                        body(json!({ "tenantId": "a", "roleId": "owner-role" })),
                    )
                    .await,
            ),
        ] {
            let error = result.err().unwrap();
            assert_eq!(
                (error.code.as_str(), error.message.as_str(), error.status),
                ("PROTECTED_RESOURCE", "Role is protected", 403)
            );
        }
        // Roles of another tenant are not found; reads answer the stored record.
        assert_eq!(
            code(value(
                api.roles
                    .get(user, body(json!({ "tenantId": "a", "roleId": "missing" })))
                    .await
            )),
            "NOT_FOUND"
        );
        let read = value(
            api.roles
                .get(
                    user,
                    body(json!({ "tenantId": "a", "roleId": "user-role" })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(read["name"], json!("User role"));
        // A package that includes the role keeps it.
        insert_all(
            &f.iam,
            vec![(
                "accessPackages",
                json!({ "id": "pkg", "tenantId": "a", "name": "Starter", "roleIds": [updated["id"]], "groupIds": [], "createdAt": 1, "updatedAt": 1 }),
            )],
        )
        .await;
        let error = value(
            api.roles
                .delete(
                    user,
                    body(json!({ "tenantId": "a", "roleId": updated["id"] })),
                )
                .await,
        )
        .err()
        .unwrap();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "RESOURCE_IN_USE",
                "Access packages still include it: Starter"
            )
        );
    });
}

#[test]
fn lists_live_bindings_with_their_subjects() {
    run(|| async {
        let f = fixture().await;
        let api = &f.iam.api;
        let now = better_iam_server::utils::date_now();
        insert_all(
            &f.iam,
            vec![
                ("groups", json!({ "id": "g1", "tenantId": "a", "name": "Writers" })),
                ("groups", json!({ "id": "g2", "tenantId": "b", "name": "Elsewhere" })),
                (
                    "bindings",
                    json!({ "id": "b-group", "tenantId": "a", "subjectType": "group", "subjectId": "g1", "roleId": "user-role", "authorityId": "user-authority" }),
                ),
                (
                    "bindings",
                    json!({ "id": "b-foreign", "tenantId": "a", "subjectType": "group", "subjectId": "g2", "roleId": "user-role", "authorityId": "user-authority" }),
                ),
                (
                    "bindings",
                    json!({ "id": "b-expired", "tenantId": "a", "subjectType": "identity", "subjectId": f.other.id, "roleId": "user-role", "authorityId": "user-authority", "expiresAt": now - 1000.0 }),
                ),
            ],
        )
        .await;
        let listed = value(
            api.roles
                .list_bindings(
                    &f.credential,
                    body(json!({ "tenantId": "a", "roleId": "user-role" })),
                )
                .await,
        )
        .unwrap();
        let listed = listed.as_array().unwrap();
        assert_eq!(listed.len(), 3);
        let by_id = |id: &str| {
            listed
                .iter()
                .find(|binding| binding["id"] == json!(id))
                .unwrap()
                .clone()
        };
        assert_eq!(
            by_id("user-binding")["subject"],
            json!({ "id": f.user.id, "name": "User", "email": "user@example.com", "kind": "user" })
        );
        assert_eq!(
            by_id("b-group")["subject"],
            json!({ "id": "g1", "name": "Writers" })
        );
        assert!(by_id("b-foreign").get("subject").is_none());
        assert_eq!(
            code(value(
                api.roles
                    .list_bindings(
                        &f.credential,
                        body(json!({ "tenantId": "a", "roleId": "missing" }))
                    )
                    .await
            )),
            "NOT_FOUND"
        );
    });
}
