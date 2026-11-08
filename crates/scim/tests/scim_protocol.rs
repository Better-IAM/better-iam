//! Port of tests/scim-protocol.test.ts: SCIM protocol coverage (filters, sorting, projection, `/.search`, PATCH
//! paths with Entra and Okta conventions, group member removal, If-None-Match, Bulk, connection listing and
//! rotation).

mod support;

use better_iam_core::Filter;
use better_iam_scim::{ScimConfig, ScimService, parse_scim_filter};
use serde_json::{Value, json};
use support::*;

const ENTERPRISE: &str = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User";
const PATCH: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
const BULK: &str = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
const SEARCH: &str = "urn:ietf:params:scim:api:messages:2.0:SearchRequest";

struct Fixture {
    store: Store,
    service: ScimService,
    connection: Value,
}

async fn fixture() -> Fixture {
    let store = memory_store().await;
    tenants(&store, &["a"]).await;
    let (authorize, authenticate) = admin_callbacks();
    let service =
        ScimService::new(ScimConfig::new(store.clone(), authorize, authenticate)).expect("service");
    let connection = service
        .create_connection(&token("admin"), &json!({ "tenantId": "a", "name": "A" }))
        .await
        .expect("connection");
    Fixture {
        store,
        service,
        connection,
    }
}

impl Fixture {
    fn token(&self) -> String {
        self.connection["token"].as_str().unwrap().to_owned()
    }

    async fn send(
        &self,
        resource: &str,
        method: &str,
        body: Option<Value>,
        headers: &[(&str, &str)],
        token: &str,
    ) -> Answer {
        let url = format!(
            "https://iam.test{}/{resource}",
            self.connection["path"].as_str().unwrap()
        );
        let bearer = format!("Bearer {token}");
        let mut all = vec![
            ("authorization", bearer.as_str()),
            ("content-type", "application/scim+json"),
        ];
        all.extend_from_slice(headers);
        let request = request(method, &url, &all, body.map(|body| body.to_string()));
        answer(self.service.handler(&request).await.expect("a SCIM answer"))
    }

    async fn request(&self, resource: &str, method: &str, body: Option<Value>) -> Answer {
        self.send(resource, method, body, &[], &self.token()).await
    }

    async fn get(&self, resource: &str) -> Answer {
        self.request(resource, "GET", None).await
    }

    async fn create(&self, user: Value) -> Value {
        let created = self.request("Users", "POST", Some(user)).await;
        assert_eq!(created.status, 201, "{}", created.body);
        created.body
    }

    async fn filter(&self, expression: &str, extra: &str) -> Value {
        self.get(&format!("Users?filter={}{extra}", encode(expression)))
            .await
            .body
    }

    async fn total(&self, expression: &str) -> i64 {
        self.filter(expression, "").await["totalResults"]
            .as_i64()
            .unwrap()
    }

    async fn patch(&self, id: &str, operations: Value, kind: &str) -> Answer {
        self.request(
            &format!("{kind}/{id}"),
            "PATCH",
            Some(json!({ "schemas": [PATCH], "Operations": operations })),
        )
        .await
    }
}

fn id(value: &Value) -> String {
    value["id"].as_str().unwrap().to_owned()
}

#[test]
fn evaluates_logical_grouped_value_path_sub_attribute_and_schema_qualified_filters() {
    run(|| async {
        let f = fixture().await;
        f.create(json!({
            "userName": "ada",
            "name": { "givenName": "Ada", "familyName": "Lovelace" },
            "emails": [
                { "value": "ada@work.test", "type": "work", "primary": true },
                { "value": "ada@home.test", "type": "home" },
            ],
            ENTERPRISE: { "department": "Research" },
        }))
        .await;
        f.create(json!({
            "userName": "grace",
            "active": false,
            "name": { "givenName": "Grace", "familyName": "Hopper" },
            "emails": [{ "value": "grace@home.test", "type": "home" }],
            ENTERPRISE: { "department": "Navy" },
        }))
        .await;
        f.create(json!({ "userName": "linus" })).await;

        assert_eq!(
            f.total("userName eq \"ada\" or userName eq \"grace\"")
                .await,
            2
        );
        assert_eq!(
            f.total("active eq true and not (userName sw \"l\")").await,
            1
        );
        assert_eq!(
            f.total("emails[type eq \"work\" and value co \"@work\"]")
                .await,
            1
        );
        assert_eq!(f.total("emails.type eq \"home\"").await, 2);
        assert_eq!(f.total("emails co \"home.test\"").await, 2);
        assert_eq!(f.total("name.familyName sw \"HOP\"").await, 1);
        assert_eq!(
            f.total(&format!("{ENTERPRISE}:department eq \"research\""))
                .await,
            1
        );
        assert_eq!(
            f.total("urn:ietf:params:scim:schemas:core:2.0:User:userName eq \"linus\"")
                .await,
            1
        );
        assert_eq!(f.total("emails pr").await, 2);
        assert_eq!(f.total("not (emails pr)").await, 1);
        assert_eq!(
            f.total("meta.lastModified gt \"2000-01-01T00:00:00Z\"")
                .await,
            3
        );
        assert_eq!(
            f.total("(userName eq \"ada\" or userName eq \"grace\") and active eq false")
                .await,
            1
        );
        // Malformed, unbounded or type-confused filters fail loudly instead of broadening the result.
        let long = (0..70)
            .map(|i| format!("userName eq \"{i}\""))
            .collect::<Vec<_>>()
            .join(" or ");
        for bad in [
            "userName eq",
            "userName xx \"a\"",
            "(userName eq \"a\"",
            "active gt true",
            "userName co 5",
            "urn:example:custom:attr eq \"x\"",
            long.as_str(),
        ] {
            assert_eq!(
                f.get(&format!("Users?filter={}", encode(bad))).await.status,
                400,
                "{bad}"
            );
        }
        assert!(parse_scim_filter(Some("primary eq \"true\"")).is_err());
    });
}

#[test]
fn sorts_projects_attributes_and_serves_post_search() {
    run(|| async {
        let f = fixture().await;
        for user_name in ["bravo", "alpha", "charlie"] {
            f.create(
                json!({ "userName": user_name, "name": { "givenName": user_name.to_uppercase() } }),
            )
            .await;
        }
        let sorted = f
            .get("Users?sortBy=userName&sortOrder=descending")
            .await
            .body;
        let names: Vec<&str> = sorted["Resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|user| user["userName"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["charlie", "bravo", "alpha"]);
        let projected = f
            .get("Users?sortBy=userName&attributes=userName,name.givenName&count=1")
            .await
            .body;
        assert_eq!(projected["totalResults"], json!(3));
        let mut keys: Vec<&String> = projected["Resources"][0]
            .as_object()
            .unwrap()
            .keys()
            .collect();
        keys.sort();
        assert_eq!(keys, ["id", "name", "schemas", "userName"]);
        assert_eq!(
            projected["Resources"][0]["name"],
            json!({ "givenName": "ALPHA" })
        );
        let excluded = f.get("Users?excludedAttributes=meta,name,id").await.body;
        assert!(excluded["Resources"][0].get("meta").is_none());
        assert!(excluded["Resources"][0].get("name").is_none());
        assert!(excluded["Resources"][0].get("id").is_some());
        assert_eq!(
            f.get("Users?attributes=userName&excludedAttributes=name")
                .await
                .status,
            400
        );
        assert_eq!(
            f.get("Users?sortOrder=sideways&sortBy=userName")
                .await
                .status,
            400
        );

        let searched = f
            .request(
                "Users/.search",
                "POST",
                Some(json!({
                    "schemas": [SEARCH],
                    "filter": "userName sw \"b\" or userName sw \"c\"",
                    "sortBy": "userName",
                    "startIndex": 2,
                    "count": 5,
                    "attributes": ["userName"],
                })),
            )
            .await;
        assert_eq!(searched.status, 200);
        let page = searched.body;
        assert_eq!(page["totalResults"], json!(2));
        assert_eq!(page["startIndex"], json!(2));
        let resources = page["Resources"].as_array().unwrap();
        assert_eq!(resources.len(), 1);
        assert_eq!(
            resources[0].as_object().unwrap().keys().collect::<Vec<_>>(),
            ["schemas", "id", "userName"]
        );
        assert!(resources[0]["schemas"].is_array());
        assert!(resources[0]["id"].is_string());
        assert_eq!(resources[0]["userName"], json!("charlie"));
        assert_eq!(
            f.request(
                "Users/.search",
                "POST",
                Some(json!({ "filter": "userName pr" }))
            )
            .await
            .status,
            400
        );
        assert_eq!(f.get("Users/.search").await.status, 405);
    });
}

#[test]
fn applies_value_path_sub_attribute_and_extension_patch_paths_with_entra_and_okta_conventions() {
    run(|| async {
        let f = fixture().await;
        let user = f
            .create(json!({
                "userName": "patchy",
                "title": "Engineer",
                "emails": [{ "value": "p@home.test", "type": "home" }],
                ENTERPRISE: { "department": "Platform", "costCenter": "42" },
            }))
            .await;
        let user_id = id(&user);
        // Seeding: add to a value path that matches nothing creates the entry with the filter's attribute.
        let response = f
            .patch(
                &user_id,
                json!([
                    { "op": "add", "path": "emails[type eq \"work\"].value", "value": "p@work.test" },
                    { "op": "Replace", "path": "name.givenName", "value": "Pat" },
                    { "op": "replace", "path": format!("{ENTERPRISE}:department"), "value": "Security" },
                    { "op": "replace", "path": format!("{ENTERPRISE}:manager.value"), "value": "boss-id" },
                    { "op": "Replace", "path": "active", "value": "False" },
                ]),
                "Users",
            )
            .await;
        assert_eq!(response.status, 200, "{}", response.body);
        let body = response.body;
        assert_eq!(
            body["emails"],
            json!([{ "value": "p@home.test", "type": "home" }, { "type": "work", "value": "p@work.test" }])
        );
        assert_eq!(body["name"], json!({ "givenName": "Pat" }));
        assert_eq!(body["active"], json!(false));
        assert_eq!(body["title"], json!("Engineer"));
        assert_eq!(
            body[ENTERPRISE],
            json!({ "department": "Security", "costCenter": "42", "manager": { "value": "boss-id" } })
        );

        // Okta-style pathless replace with schema-qualified keys and a whole extension object.
        let response = f
            .patch(
                &user_id,
                json!([
                    {
                        "op": "replace",
                        "value": {
                            "active": true,
                            format!("{ENTERPRISE}:division"): "R&D",
                            ENTERPRISE: { "costCenter": "7" },
                        },
                    },
                    { "op": "remove", "path": "emails[type eq \"home\"]" },
                    { "op": "replace", "path": "emails[type eq \"work\"].primary", "value": "True" },
                ]),
                "Users",
            )
            .await;
        let body = response.body;
        assert_eq!(response.status, 200);
        assert_eq!(body["active"], json!(true));
        assert_eq!(
            body["emails"],
            json!([{ "type": "work", "value": "p@work.test", "primary": true }])
        );
        assert_matches(
            &body[ENTERPRISE],
            json!({ "division": "R&D", "costCenter": "7", "department": "Security" }),
        );

        // Removing the last extension attribute drops the extension schema.
        let body = f
            .patch(
                &user_id,
                json!([{ "op": "remove", "path": ENTERPRISE }]),
                "Users",
            )
            .await
            .body;
        assert!(body.get(ENTERPRISE).is_none());
        assert_eq!(
            body["schemas"],
            json!(["urn:ietf:params:scim:schemas:core:2.0:User"])
        );

        // replace with an unmatched filter, required-attribute removal and immutable paths are rejected atomically.
        let before = f.get(&format!("Users/{user_id}")).await.body;
        for operations in [
            json!([{ "op": "replace", "path": "emails[type eq \"other\"].value", "value": "x@y.test" }]),
            json!([{ "op": "remove", "path": "userName" }]),
            json!([{ "op": "replace", "path": "meta.created", "value": "x" }]),
            json!([{ "op": "replace", "path": "name[givenName eq \"x\"]", "value": {} }]),
            json!([
                { "op": "replace", "path": "displayName", "value": "Changed" },
                { "op": "replace", "path": "id", "value": "x" },
            ]),
        ] {
            let rejected = f.patch(&user_id, operations.clone(), "Users").await;
            assert_eq!(rejected.status, 400, "{operations}");
        }
        assert_eq!(
            f.get(&format!("Users/{user_id}")).await.body["meta"]["version"],
            before["meta"]["version"]
        );
    });
}

#[test]
fn removes_listed_group_members_entra_and_filtered_members_and_answers_if_none_match() {
    run(|| async {
        let f = fixture().await;
        let mut users = Vec::new();
        for user_name in ["m1", "m2", "m3"] {
            users.push(f.create(json!({ "userName": user_name })).await);
        }
        let group = f
            .request(
                "Groups",
                "POST",
                Some(json!({
                    "displayName": "Team",
                    "members": users.iter().map(|user| json!({ "value": user["id"] })).collect::<Vec<_>>(),
                })),
            )
            .await
            .body;
        let group_id = id(&group);
        let response = f
            .patch(
                &group_id,
                json!([{ "op": "remove", "path": "members", "value": [{ "value": users[0]["id"] }] }]),
                "Groups",
            )
            .await;
        let values: Vec<Value> = response.body["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|member| member["value"].clone())
            .collect();
        assert_eq!(values, vec![users[1]["id"].clone(), users[2]["id"].clone()]);
        let filter = format!(
            "members[value eq \"{}\" or value eq \"{}\"]",
            id(&users[1]),
            id(&users[2])
        );
        let response = f
            .patch(
                &group_id,
                json!([{ "op": "remove", "path": filter }]),
                "Groups",
            )
            .await;
        assert_eq!(response.body["members"], json!([]));
        assert!(
            find(&f.store, "groupMembers", Filter::new())
                .await
                .is_empty()
        );
        let etag = response.header("etag").unwrap();
        let token = f.token();
        assert_eq!(
            f.send(
                &format!("Groups/{group_id}"),
                "GET",
                None,
                &[("if-none-match", &etag)],
                &token
            )
            .await
            .status,
            304
        );
        assert_eq!(
            f.send(
                &format!("Groups/{group_id}"),
                "GET",
                None,
                &[("if-none-match", "W/\"0\"")],
                &token
            )
            .await
            .status,
            200
        );
        let members = f
            .get(&format!(
                "Groups?filter={}&attributes=displayName",
                encode("displayName eq \"team\"")
            ))
            .await
            .body;
        assert_eq!(
            members["Resources"][0],
            json!({
                "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
                "id": group_id,
                "displayName": "Team",
            })
        );
    });
}

#[test]
fn processes_bulk_requests_with_forward_bulk_id_references_isolation_and_fail_on_errors() {
    run(|| async {
        let f = fixture().await;
        let response = f
            .request(
                "Bulk",
                "POST",
                Some(json!({
                    "schemas": [BULK],
                    "Operations": [
                        // The group references a user declared later in the request.
                        {
                            "method": "POST",
                            "bulkId": "g1",
                            "path": "/Groups",
                            "data": { "displayName": "Bulk Group", "members": [{ "value": "bulkId:u1" }] },
                        },
                        { "method": "POST", "bulkId": "u1", "path": "/Users", "data": { "userName": "bulk-one" } },
                        { "method": "POST", "bulkId": "dup", "path": "/Users", "data": { "userName": "bulk-one" } },
                        {
                            "method": "PATCH",
                            "path": "/Users/bulkId:u1",
                            "data": {
                                "schemas": [PATCH],
                                "Operations": [{ "op": "replace", "path": "displayName", "value": "One" }],
                            },
                        },
                        {
                            "method": "POST",
                            "bulkId": "orphan",
                            "path": "/Groups",
                            "data": { "displayName": "X", "members": [{ "value": "bulkId:dup" }] },
                        },
                        {
                            "method": "POST",
                            "bulkId": "ghost",
                            "path": "/Groups",
                            "data": { "displayName": "Y", "members": [{ "value": "bulkId:nope" }] },
                        },
                        { "method": "DELETE", "path": "/Users/missing" },
                    ],
                })),
            )
            .await;
        assert_eq!(response.status, 200);
        let operations = response.body["Operations"].as_array().unwrap().clone();
        let by_bulk_id = |bulk_id: &str| {
            operations
                .iter()
                .find(|op| op["bulkId"] == json!(bulk_id))
                .cloned()
                .unwrap()
        };
        assert_eq!(by_bulk_id("u1")["status"], json!("201"));
        assert_eq!(by_bulk_id("g1")["status"], json!("201"));
        assert_eq!(by_bulk_id("dup")["status"], json!("409"));
        assert_eq!(by_bulk_id("orphan")["status"], json!("409"));
        assert_eq!(by_bulk_id("ghost")["status"], json!("400"));
        let by_method = |method: &str| {
            operations
                .iter()
                .find(|op| op["method"] == json!(method))
                .cloned()
                .unwrap()
        };
        assert_eq!(by_method("DELETE")["status"], json!("404"));
        assert_eq!(by_method("PATCH")["status"], json!("200"));
        let location = by_bulk_id("g1")["location"].as_str().unwrap().to_owned();
        let group_path = format!("Groups/{}", location.rsplit("/Groups/").next().unwrap());
        let group = f.get(&group_path).await.body;
        let user_id = by_bulk_id("u1")["location"]
            .as_str()
            .unwrap()
            .rsplit('/')
            .next()
            .unwrap()
            .to_owned();
        let members: Vec<Value> = group["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|member| member["value"].clone())
            .collect();
        assert_eq!(members, vec![json!(user_id)]);
        assert_eq!(
            f.get(&format!("Users/{user_id}")).await.body["displayName"],
            json!("One")
        );
        // Failed operations leave nothing behind.
        assert_eq!(find(&f.store, "scimGroups", Filter::new()).await.len(), 1);

        let stopped = f
            .request(
                "Bulk",
                "POST",
                Some(json!({
                    "schemas": [BULK],
                    "failOnErrors": 1,
                    "Operations": [
                        { "method": "POST", "bulkId": "bad", "path": "/Users", "data": { "userName": "" } },
                        { "method": "POST", "bulkId": "never", "path": "/Users", "data": { "userName": "never" } },
                    ],
                })),
            )
            .await
            .body;
        assert_eq!(stopped["Operations"].as_array().unwrap().len(), 1);
        assert_eq!(f.total("userName eq \"never\"").await, 0);

        let cycle = f
            .request(
                "Bulk",
                "POST",
                Some(json!({
                    "schemas": [BULK],
                    "Operations": [
                        {
                            "method": "POST",
                            "bulkId": "x",
                            "path": "/Groups",
                            "data": { "displayName": "X", "members": [{ "value": "bulkId:y" }] },
                        },
                        {
                            "method": "POST",
                            "bulkId": "y",
                            "path": "/Groups",
                            "data": { "displayName": "Y", "members": [{ "value": "bulkId:x" }] },
                        },
                    ],
                })),
            )
            .await
            .body;
        let statuses: Vec<Value> = cycle["Operations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|op| op["status"].clone())
            .collect();
        assert_eq!(statuses, vec![json!("409"), json!("409")]);

        let version = f
            .request(
                "Bulk",
                "POST",
                Some(json!({
                    "schemas": [BULK],
                    "Operations": [{
                        "method": "PUT",
                        "path": format!("/Users/{user_id}"),
                        "version": "W/\"999\"",
                        "data": { "userName": "bulk-one" },
                    }],
                })),
            )
            .await
            .body;
        assert_eq!(version["Operations"][0]["status"], json!("412"));

        assert_eq!(
            f.request(
                "Bulk",
                "POST",
                Some(json!({ "schemas": [BULK], "Operations": [] }))
            )
            .await
            .status,
            400
        );
        let many: Vec<Value> = (0..101)
            .map(|i| json!({ "method": "DELETE", "path": format!("/Users/{i}") }))
            .collect();
        assert_eq!(
            f.request(
                "Bulk",
                "POST",
                Some(json!({ "schemas": [BULK], "Operations": many }))
            )
            .await
            .status,
            413
        );
        assert_eq!(
            f.send(
                "Bulk",
                "POST",
                Some(json!({ "schemas": [BULK], "Operations": [{ "method": "DELETE", "path": "/Users/x" }] })),
                &[],
                "forged",
            )
            .await
            .status,
            401
        );
    });
}

#[test]
fn lists_connections_with_usage_and_rotates_tokens_without_losing_provisioned_state() {
    run(|| async {
        let f = fixture().await;
        f.create(json!({ "userName": "kept" })).await;
        let listed = f
            .service
            .list_connections(&token("admin"), &json!({ "tenantId": "a" }))
            .await
            .unwrap();
        let listed = &listed[0];
        assert_matches(
            listed,
            json!({ "id": f.connection["id"], "name": "A", "users": 1, "groups": 0, "revoked": false }),
        );
        assert!(listed["lastUsedAt"].is_number());
        assert!(!listed.to_string().contains(&f.token()));
        let error = f
            .service
            .list_connections(&token("forged"), &json!({ "tenantId": "a" }))
            .await
            .unwrap_err();
        assert_eq!(error.status, 403);

        let rotated = f
            .service
            .rotate_token(
                &token("admin"),
                &json!({ "tenantId": "a", "connectionId": f.connection["id"], "expiresIn": 3600 }),
            )
            .await
            .unwrap();
        assert_ne!(rotated["token"], f.connection["token"]);
        assert_eq!(f.get("Users").await.status, 401);
        let users = f
            .send(
                "Users",
                "GET",
                None,
                &[],
                rotated["token"].as_str().unwrap(),
            )
            .await
            .body;
        assert_eq!(users["totalResults"], json!(1));
        assert_eq!(
            find(
                &f.store,
                "audit",
                Filter::new().eq("action", "iam:scim:RotateToken")
            )
            .await
            .len(),
            1
        );

        f.service
            .revoke_connection(
                &token("admin"),
                &json!({ "tenantId": "a", "connectionId": f.connection["id"] }),
            )
            .await
            .unwrap();
        let error = f
            .service
            .rotate_token(
                &token("admin"),
                &json!({ "tenantId": "a", "connectionId": f.connection["id"] }),
            )
            .await
            .unwrap_err();
        assert_eq!(error.status, 409);
    });
}
