//! Port of tests/scim.test.ts: SCIM tenant isolation and provisioning.

mod support;

use std::sync::Arc;

use better_iam_core::{Filter, IamError, IamStoreExt};
use better_iam_scim::{ScimConfig, ScimService, parse_scim_filter};
use serde_json::{Value, json};
use support::*;

const ENTERPRISE: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const PATCH: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

struct Fixture {
    store: Store,
    service: ScimService,
    a: Value,
    b: Value,
}

async fn fixture() -> Fixture {
    let store = memory_store().await;
    tenants(&store, &["root", "a", "b"]).await;
    let (authorize, authenticate) = admin_callbacks();
    let mut config = ScimConfig::new(store.clone(), authorize, authenticate);
    config.map_attributes = Some(Arc::new(|user| {
        let mut attributes = serde_json::Map::new();
        if let Some(title) = &user.title {
            attributes.insert("title".into(), json!(title));
        }
        if let Some(Value::String(department)) =
            user.enterprise.as_ref().and_then(|e| e.get("department"))
        {
            attributes.insert("department".into(), json!(department));
        }
        Ok((!attributes.is_empty()).then_some(attributes))
    }));
    config.validate_identity_attributes = Some(Arc::new(|attributes| {
        for key in attributes.keys() {
            if key != "title" && key != "department" {
                return Err(IamError::new(
                    "INVALID_INPUT",
                    format!("Attribute {key} is not declared"),
                ));
            }
        }
        Ok(attributes.clone())
    }));
    let service = ScimService::new(config).expect("service");
    let a = service
        .create_connection(&token("admin"), &json!({ "tenantId": "a", "name": "A" }))
        .await
        .expect("connection a");
    let b = service
        .create_connection(&token("admin"), &json!({ "tenantId": "b", "name": "B" }))
        .await
        .expect("connection b");
    Fixture {
        store,
        service,
        a,
        b,
    }
}

impl Fixture {
    async fn request(
        &self,
        connection: &Value,
        resource: &str,
        method: &str,
        body: Option<Value>,
        extra: &[(&str, &str)],
    ) -> Answer {
        let url = format!(
            "https://iam.test{}/{resource}",
            connection["path"].as_str().unwrap()
        );
        let bearer = format!("Bearer {}", connection["token"].as_str().unwrap());
        let mut headers = vec![
            ("authorization", bearer.as_str()),
            ("content-type", "application/scim+json"),
        ];
        headers.extend_from_slice(extra);
        let request = request(method, &url, &headers, body.map(|body| body.to_string()));
        answer(self.service.handler(&request).await.expect("a SCIM answer"))
    }
}

fn patch(operations: Value) -> Value {
    json!({ "schemas": [PATCH], "Operations": operations })
}

#[test]
fn scopes_tokens_resources_and_same_email_accounts_to_the_connection_tenant() {
    run(|| async {
        let f = fixture().await;
        let create_a = f
            .request(
                &f.a,
                "Users",
                "POST",
                Some(json!({ "userName": "same@example.test", "active": true })),
                &[],
            )
            .await;
        assert_eq!(create_a.status, 201);
        let user_a = create_a.body;
        let create_b = f
            .request(
                &f.b,
                "Users",
                "POST",
                Some(json!({ "userName": "same@example.test", "active": true })),
                &[],
            )
            .await;
        assert_eq!(create_b.status, 201);
        assert_ne!(create_b.body["id"], user_a["id"]);
        let id_a = user_a["id"].as_str().unwrap();
        assert_eq!(
            f.request(&f.b, &format!("Users/{id_a}"), "GET", None, &[])
                .await
                .status,
            404
        );
        let mut forged = f.a.clone();
        forged["token"] = f.b["token"].clone();
        assert_eq!(
            f.request(&forged, "Users", "GET", None, &[]).await.status,
            401
        );
        assert_eq!(
            find(
                &f.store,
                "identities",
                Filter::new().eq("email", "same@example.test")
            )
            .await
            .len(),
            2
        );
        let token_a = f.a["token"].as_str().unwrap();
        assert!(
            !find(&f.store, "scimConnections", Filter::new())
                .await
                .iter()
                .any(|row| Value::Object(row.clone()).to_string().contains(token_a))
        );
    });
}

#[test]
fn maps_the_title_and_enterprise_extension_to_declared_identity_attributes() {
    run(|| async {
        let f = fixture().await;
        let created = f
            .request(
                &f.a,
                "Users",
                "POST",
                Some(json!({
                    "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", ENTERPRISE],
                    "userName": "mapped@example.test",
                    "title": "Engineer",
                    ENTERPRISE: { "department": "Platform", "manager": { "value": "boss", "displayName": "Boss" } },
                })),
                &[],
            )
            .await;
        assert_eq!(created.status, 201);
        let user = created.body;
        assert_eq!(user["title"], json!("Engineer"));
        assert_eq!(
            user[ENTERPRISE],
            json!({ "department": "Platform", "manager": { "value": "boss", "displayName": "Boss" } })
        );
        assert!(
            user["schemas"]
                .as_array()
                .unwrap()
                .contains(&json!(ENTERPRISE))
        );
        let id = user["id"].as_str().unwrap();
        let link = get(&f.store, "scimUsers", id).await.unwrap();
        let identity_id = link["identityId"].as_str().unwrap();
        let identity = get(&f.store, "identities", identity_id).await.unwrap();
        assert_eq!(
            identity["attributes"],
            json!({ "title": "Engineer", "department": "Platform" })
        );
        // PUT replaces the mapping; unsupported enterprise fields are rejected.
        let replaced = f
            .request(
                &f.a,
                &format!("Users/{id}"),
                "PUT",
                Some(json!({ "userName": "mapped@example.test", "title": "Lead" })),
                &[],
            )
            .await;
        assert_eq!(replaced.status, 200);
        assert_eq!(
            get(&f.store, "identities", identity_id).await.unwrap()["attributes"],
            json!({ "title": "Lead" })
        );
        let rejected = f
            .request(
                &f.a,
                &format!("Users/{id}"),
                "PUT",
                Some(json!({ "userName": "mapped@example.test", ENTERPRISE: { "badge": "gold" } })),
                &[],
            )
            .await;
        assert_eq!(rejected.status, 400);
    });
}

#[test]
fn deactivation_revokes_local_and_assumed_sessions_while_preserving_another_tenant() {
    run(|| async {
        let f = fixture().await;
        let user = f
            .request(
                &f.a,
                "Users",
                "POST",
                Some(json!({ "userName": "user@example.test" })),
                &[],
            )
            .await
            .body;
        let id = user["id"].as_str().unwrap();
        let link = get(&f.store, "scimUsers", id).await.unwrap();
        let identity_id = link["identityId"].as_str().unwrap().to_owned();
        insert(
            &f.store,
            "sessions",
            record(json!({ "id": "local", "tenantId": "a", "identityId": identity_id })),
        )
        .await;
        insert(
            &f.store,
            "sessions",
            record(json!({
                "id": "assumed",
                "tenantId": "b",
                "identityId": "role-user",
                "originalIdentityId": identity_id,
            })),
        )
        .await;
        insert(
            &f.store,
            "sessions",
            record(json!({ "id": "other", "tenantId": "b", "identityId": "other-user" })),
        )
        .await;
        let patched = f
            .request(
                &f.a,
                &format!("Users/{id}"),
                "PATCH",
                Some(patch(
                    json!([{ "op": "replace", "path": "active", "value": false }]),
                )),
                &[],
            )
            .await;
        assert_eq!(patched.status, 200);
        assert_eq!(patched.body["active"], json!(false));
        assert!(get(&f.store, "sessions", "local").await.is_none());
        assert!(get(&f.store, "sessions", "assumed").await.is_none());
        assert!(get(&f.store, "sessions", "other").await.is_some());
        assert_eq!(
            get(&f.store, "identities", &identity_id).await.unwrap()["status"],
            json!("disabled")
        );
    });
}

#[test]
fn supports_group_patch_and_rejects_nested_or_foreign_members_atomically() {
    run(|| async {
        let f = fixture().await;
        let first = f
            .request(
                &f.a,
                "Users",
                "POST",
                Some(json!({ "userName": "one@example.test" })),
                &[],
            )
            .await
            .body;
        let second = f
            .request(
                &f.a,
                "Users",
                "POST",
                Some(json!({ "userName": "two@example.test" })),
                &[],
            )
            .await
            .body;
        let foreign = f
            .request(
                &f.b,
                "Users",
                "POST",
                Some(json!({ "userName": "foreign@example.test" })),
                &[],
            )
            .await
            .body;
        let group = f
            .request(
                &f.a,
                "Groups",
                "POST",
                Some(json!({ "displayName": "Engineers", "members": [{ "value": first["id"] }] })),
                &[],
            )
            .await
            .body;
        let path = format!("Groups/{}", group["id"].as_str().unwrap());
        let status = |operations: Value| {
            let path = path.clone();
            let f = &f;
            async move {
                f.request(&f.a, &path, "PATCH", Some(patch(operations)), &[])
                    .await
                    .status
            }
        };
        assert_eq!(
            status(
                json!([{ "op": "add", "path": "members", "value": [{ "value": second["id"] }] }])
            )
            .await,
            200
        );
        assert_eq!(
            status(
                json!([{ "op": "add", "path": "members", "value": [{ "value": foreign["id"] }] }])
            )
            .await,
            400
        );
        assert_eq!(
            status(json!([{ "op": "add", "path": "members", "value": [{ "value": group["id"], "type": "Group" }] }]))
                .await,
            400
        );
        let current = f.request(&f.a, &path, "GET", None, &[]).await.body;
        assert_eq!(current["members"].as_array().unwrap().len(), 2);
        let filter = format!("members[value eq \"{}\"]", first["id"].as_str().unwrap());
        assert_eq!(
            status(json!([{ "op": "remove", "path": filter }])).await,
            200
        );
        assert_eq!(find(&f.store, "groupMembers", Filter::new()).await.len(), 1);
    });
}

#[test]
fn rejects_owner_changes_stale_etags_and_email_based_account_takeover() {
    run(|| async {
        let f = fixture().await;
        let user = f
            .request(
                &f.a,
                "Users",
                "POST",
                Some(json!({ "userName": "owner@example.test" })),
                &[],
            )
            .await
            .body;
        let id = user["id"].as_str().unwrap();
        assert_eq!(
            f.request(
                &f.a,
                &format!("Users/{id}"),
                "PUT",
                Some(json!({ "userName": "owner@example.test" })),
                &[("if-match", "W/\"0\"")],
            )
            .await
            .status,
            412
        );
        let link = get(&f.store, "scimUsers", id).await.unwrap();
        let mut identity = get(&f.store, "identities", link["identityId"].as_str().unwrap())
            .await
            .unwrap();
        identity.insert("owner".into(), json!(true));
        put(&f.store, "identities", identity).await;
        assert_eq!(
            f.request(&f.a, &format!("Users/{id}"), "DELETE", None, &[])
                .await
                .status,
            403
        );
        let second = f
            .service
            .create_connection(
                &token("admin"),
                &json!({ "tenantId": "a", "name": "another" }),
            )
            .await
            .unwrap();
        assert_eq!(
            f.request(
                &second,
                "Users",
                "POST",
                Some(json!({ "userName": "owner@example.test" })),
                &[]
            )
            .await
            .status,
            409
        );
    });
}

#[test]
fn filters_and_pages_honestly_and_immediately_rejects_revoked_or_suspended_connections() {
    run(|| async {
        let f = fixture().await;
        for user_name in ["a@example.test", "b@example.test"] {
            assert_eq!(
                f.request(
                    &f.a,
                    "Users",
                    "POST",
                    Some(json!({ "userName": user_name })),
                    &[]
                )
                .await
                .status,
                201
            );
        }
        let filtered = f
            .request(
                &f.a,
                &format!("Users?filter={}", encode("userName eq \"A@example.test\"")),
                "GET",
                None,
                &[],
            )
            .await
            .body;
        assert_eq!(filtered["totalResults"], json!(1));
        let page = f
            .request(&f.a, "Users?startIndex=1&count=1", "GET", None, &[])
            .await
            .body;
        assert_eq!(page["itemsPerPage"], json!(1));
        assert_eq!(page["totalResults"], json!(2));
        assert_eq!(
            f.request(
                &f.a,
                &format!("Users?filter={}", encode("userName eq \"a\" or bogus(")),
                "GET",
                None,
                &[]
            )
            .await
            .status,
            400
        );
        let discovery = f
            .request(&f.a, "ServiceProviderConfig", "GET", None, &[])
            .await
            .body;
        assert_matches(
            &discovery["bulk"],
            json!({ "supported": true, "maxOperations": 100 }),
        );
        assert_eq!(discovery["sort"]["supported"], json!(true));
        f.service
            .revoke_connection(
                &token("admin"),
                &json!({ "tenantId": "a", "connectionId": f.a["id"] }),
            )
            .await
            .unwrap();
        assert_eq!(f.request(&f.a, "Users", "GET", None, &[]).await.status, 401);
        let mut root = get(&f.store, "tenants", "root").await.unwrap();
        root.insert("status".into(), json!("suspended"));
        put(&f.store, "tenants", root).await;
        assert_eq!(f.request(&f.b, "Users", "GET", None, &[]).await.status, 401);
    });
}

#[test]
fn requires_administrator_credentials_to_provision_connections() {
    run(|| async {
        let f = fixture().await;
        let error = f
            .service
            .create_connection(
                &token("forged"),
                &json!({ "tenantId": "a", "name": "forged" }),
            )
            .await
            .unwrap_err();
        assert_eq!(error.status, 403);
        assert!(parse_scim_filter(Some("active eq \"false\"")).is_err());
        let _ = f.store.transaction(|_| async { Ok(()) }).await;
    });
}

#[test]
fn roundtrips_supported_profile_attributes_and_treats_external_ids_as_case_exact() {
    run(|| async {
        let f = fixture().await;
        let input = json!({
            "userName": "profile",
            "externalId": "CaseSensitiveID",
            "name": { "givenName": "Ada", "familyName": "Lovelace" },
            "emails": [{ "value": "ada@example.test", "primary": true, "type": "work" }],
        });
        let created = f
            .request(&f.a, "Users", "POST", Some(input.clone()), &[])
            .await;
        assert_eq!(created.status, 201);
        let user = created.body;
        assert_eq!(user["name"], input["name"]);
        assert_eq!(user["emails"], input["emails"]);
        let wrong_case = f
            .request(
                &f.a,
                &format!(
                    "Users?filter={}",
                    encode("externalId eq \"casesensitiveid\"")
                ),
                "GET",
                None,
                &[],
            )
            .await
            .body;
        assert_eq!(wrong_case["totalResults"], json!(0));
        let patched = f
            .request(
                &f.a,
                &format!("Users/{}", user["id"].as_str().unwrap()),
                "PATCH",
                Some(patch(
                    json!([{ "op": "replace", "path": "displayName", "value": "Ada" }]),
                )),
                &[],
            )
            .await;
        assert_eq!(patched.body["emails"], input["emails"]);
    });
}
