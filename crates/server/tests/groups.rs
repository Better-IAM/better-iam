//! The `groups` API group: creating, reading, renaming and listing groups and their current members (rules of
//! api/groups.ts). Membership changes go through team sync (teams.ts) and license checks (licenses.ts), which other
//! suites cover once those modules are ported.

mod grants;

use better_iam_core::TenantLimits;
use grants::{body, code, fixture, insert_all, refused, run, value};
use serde_json::json;

#[test]
fn creates_reads_renames_and_lists_groups() {
    run(|| async {
        let f = fixture().await;
        let api = &f.iam.api;
        let user = &f.credential;
        let group = value(
            api.groups
                .create(
                    user,
                    body(json!({ "tenantId": "a", "name": "Writers", "description": "People who write" })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(group["tenantId"], json!("a"));
        assert_eq!(group["name"], json!("Writers"));
        assert_eq!(group["description"], json!("People who write"));
        let keys: Vec<&String> = group.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["id", "tenantId", "name", "description"]);
        assert_eq!(
            code(value(
                api.groups
                    .create(user, body(json!({ "tenantId": "a", "name": " " })))
                    .await
            )),
            "INVALID_INPUT"
        );
        let long = "x".repeat(513);
        let error = value(
            api.groups
                .create(
                    user,
                    body(json!({ "tenantId": "a", "name": "Long", "description": long })),
                )
                .await,
        )
        .err()
        .unwrap();
        assert_eq!(error.message, "Invalid description");
        let group_id = group["id"].clone();
        assert_eq!(
            value(
                api.groups
                    .get(user, body(json!({ "tenantId": "a", "groupId": group_id })))
                    .await
            )
            .unwrap(),
            group
        );
        assert_eq!(
            refused(value(
                api.groups
                    .get(user, body(json!({ "tenantId": "b", "groupId": group_id })))
                    .await
            ))
            .1,
            403
        );
        let error = value(
            api.groups
                .update(user, body(json!({ "tenantId": "a", "groupId": group_id })))
                .await,
        )
        .err()
        .unwrap();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            ("INVALID_INPUT", "Nothing to update")
        );
        let renamed = value(
            api.groups
                .update(
                    user,
                    body(json!({ "tenantId": "a", "groupId": group_id, "name": "Authors" })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(renamed["name"], json!("Authors"));
        assert_eq!(renamed["description"], json!("People who write"));
        let listed = value(
            api.groups
                .list(user, body(json!({ "tenantId": "a" })))
                .await,
        )
        .unwrap();
        assert_eq!(listed, json!([renamed]));
        assert_eq!(
            code(value(
                api.groups
                    .get(user, body(json!({ "tenantId": "a", "groupId": "missing" })))
                    .await
            )),
            "NOT_FOUND"
        );
    });
}

#[test]
fn lists_current_members_with_their_membership_expiry() {
    run(|| async {
        let f = fixture().await;
        let api = &f.iam.api;
        let now = better_iam_server::utils::date_now();
        let outsider = grants::identity(&f.iam, "b", "outsider@example.com", "Outsider").await;
        insert_all(
            &f.iam,
            vec![
                ("groups", json!({ "id": "g", "tenantId": "a", "name": "Team" })),
                (
                    "groupMembers",
                    json!({ "id": "m1", "tenantId": "a", "uniqueKey": format!("g:{}", f.user.id), "groupId": "g", "identityId": f.user.id }),
                ),
                (
                    "groupMembers",
                    json!({ "id": "m2", "tenantId": "a", "uniqueKey": format!("g:{}", f.other.id), "groupId": "g", "identityId": f.other.id, "expiresAt": now + 3_600_000.0 }),
                ),
                (
                    "groupMembers",
                    json!({ "id": "m3", "tenantId": "a", "uniqueKey": "g:gone", "groupId": "g", "identityId": "gone", "expiresAt": now - 1000.0 }),
                ),
                (
                    "groupMembers",
                    json!({ "id": "m4", "tenantId": "a", "uniqueKey": format!("g:{}", outsider.id), "groupId": "g", "identityId": outsider.id }),
                ),
            ],
        )
        .await;
        let members = value(
            api.groups
                .list_members(
                    &f.credential,
                    body(json!({ "tenantId": "a", "groupId": "g" })),
                )
                .await,
        )
        .unwrap();
        let members = members.as_array().unwrap();
        assert_eq!(members.len(), 2);
        let user = members
            .iter()
            .find(|member| member["id"] == json!(f.user.id))
            .unwrap();
        assert_eq!(user["email"], json!("user@example.com"));
        assert!(user.get("membershipExpiresAt").is_none());
        assert!(user.get("passwordHash").is_none());
        let other = members
            .iter()
            .find(|member| member["id"] == json!(f.other.id))
            .unwrap();
        assert_eq!(
            other["membershipExpiresAt"].as_f64(),
            Some(now + 3_600_000.0)
        );
    });
}

#[test]
fn enforces_the_group_limit_and_validates_member_batches() {
    run(|| async {
        let f = fixture().await;
        let mut tenant = grants::get(&f.iam, "tenants", "a").await.unwrap();
        tenant.insert(
            "limits".into(),
            serde_json::to_value(TenantLimits {
                groups: Some(1.0),
                ..TenantLimits::default()
            })
            .unwrap(),
        );
        let store = f.iam.store.clone();
        better_iam_core::IamStoreExt::transaction(store.as_ref(), |tx| async move {
            tx.put("tenants", &tenant).await
        })
        .await
        .unwrap();
        let api = &f.iam.api;
        value(
            api.groups
                .create(
                    &f.credential,
                    body(json!({ "tenantId": "a", "name": "One" })),
                )
                .await,
        )
        .unwrap();
        assert_eq!(
            refused(value(
                api.groups
                    .create(
                        &f.credential,
                        body(json!({ "tenantId": "a", "name": "Two" }))
                    )
                    .await
            )),
            ("LIMIT_EXCEEDED".to_owned(), 409)
        );
        let group = value(
            api.groups
                .list(&f.credential, body(json!({ "tenantId": "a" })))
                .await,
        )
        .unwrap()[0]
            .clone();
        let error = value(
            api.groups
                .add_members(
                    &f.credential,
                    body(json!({ "tenantId": "a", "groupId": group["id"], "identityIds": [] })),
                )
                .await,
        )
        .err()
        .unwrap();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            ("INVALID_INPUT", "Provide 1-100 identityIds")
        );
    });
}
