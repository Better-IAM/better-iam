//! Port of tests/scim-admin.test.ts: the SCIM connection administration routes mounted on a Better IAM server.

#[path = "../../server/tests/organization_fixture/mod.rs"]
mod organization_fixture;

use std::sync::Arc;

use better_iam_core::IamError;
use better_iam_scim::host::scim_config;
use better_iam_scim::{HttpResponse, ScimService, authorize_fn};
use bytes::Bytes;
use organization_fixture::{ORIGIN, Org, body, ok, organization, run};
use serde_json::{Value, json};

struct Reply {
    status: u16,
    cache_control: Option<String>,
    body: Value,
}

fn parse(response: HttpResponse) -> Reply {
    Reply {
        status: response.status().as_u16(),
        cache_control: response
            .headers()
            .get("cache-control")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        body: serde_json::from_slice(response.body()).unwrap_or(Value::Null),
    }
}

struct Mounted {
    f: Org,
}

async fn mounted() -> Mounted {
    let f = organization(|_| {}).await;
    let mut config = scim_config(&f.iam).expect("protocol host");
    config.base_path = Some("/api/iam/scim/v2".into());
    config.admin_base_path = Some("/api/iam/scim-admin".into());
    let service = ScimService::new(config).expect("service");
    f.iam.use_protocol(Arc::new(service));
    Mounted { f }
}

#[derive(Default)]
struct Options<'a> {
    token: Option<&'a str>,
    headers: Vec<(&'a str, &'a str)>,
    method: Option<&'a str>,
}

impl Mounted {
    fn owner_token(&self) -> String {
        self.f.owner_credential.token.clone().unwrap()
    }

    /// A console-style JSON call to the administration API through the IAM handler.
    async fn call(
        &self,
        route: &str,
        payload: Option<Value>,
        raw: Option<&str>,
        options: Options<'_>,
    ) -> Reply {
        let method = options.method.unwrap_or("POST");
        let owner = self.owner_token();
        let token = options.token.unwrap_or(&owner);
        let mut headers: Vec<(String, String)> = vec![
            ("content-type".into(), "application/json".into()),
            ("x-better-iam".into(), "1".into()),
            ("authorization".into(), format!("Bearer {token}")),
        ];
        for (name, value) in options.headers {
            match headers.iter_mut().find(|(key, _)| key == name) {
                Some(entry) => entry.1 = value.to_owned(),
                None => headers.push((name.to_owned(), value.to_owned())),
            }
        }
        let mut builder = http::Request::builder()
            .method(method)
            .uri(format!("{ORIGIN}/api/iam/scim-admin/{route}"));
        for (name, value) in &headers {
            builder = builder.header(name, value);
        }
        let content = if method == "GET" {
            Bytes::new()
        } else if let Some(raw) = raw {
            Bytes::from(raw.to_owned())
        } else {
            Bytes::from(
                payload
                    .map(|payload| payload.to_string())
                    .unwrap_or_default(),
            )
        };
        parse(self.f.iam.handler(builder.body(content).unwrap()).await)
    }

    async fn post(&self, route: &str, payload: Value) -> Reply {
        self.call(route, Some(payload), None, Options::default())
            .await
    }

    /// An IdP request to the SCIM protocol endpoint, authenticated with the connection token.
    async fn scim(
        &self,
        path: &str,
        token: &str,
        resource: &str,
        method: &str,
        payload: Option<Value>,
    ) -> Reply {
        let request = http::Request::builder()
            .method(method)
            .uri(format!("{ORIGIN}{path}/{resource}"))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/scim+json")
            .body(
                payload
                    .map(|payload| Bytes::from(payload.to_string()))
                    .unwrap_or_default(),
            )
            .unwrap();
        parse(self.f.iam.handler(request).await)
    }
}

#[test]
fn creates_lists_maps_rotates_and_revokes_connections_while_the_protocol_keeps_working() {
    run(|| async {
        let m = mounted().await;
        let tenant_id = m.f.tenant_id.clone();
        let created = m
            .post(
                "connections/create",
                json!({ "tenantId": tenant_id, "name": "Okta" }),
            )
            .await;
        assert_eq!(created.status, 200);
        assert_eq!(created.cache_control.as_deref(), Some("no-store"));
        let connection = created.body["data"].clone();
        let connection_id = connection["id"].as_str().unwrap().to_owned();
        let path = connection["path"].as_str().unwrap().to_owned();
        let scim_token = connection["token"].as_str().unwrap().to_owned();
        assert_eq!(connection["tenantId"], json!(tenant_id));
        assert_eq!(path, format!("/api/iam/scim/v2/{connection_id}"));
        let listed = m
            .post("connections/list", json!({ "tenantId": tenant_id }))
            .await;
        let data = listed.body["data"].as_array().unwrap();
        assert_eq!(data.len(), 1);
        organization_fixture::assert_matches(
            &data[0],
            json!({ "id": connection_id, "name": "Okta", "users": 0, "groups": 0, "revoked": false }),
        );
        assert!(!listed.body.to_string().contains(&scim_token));
        assert!(data[0].get("tokenHash").is_none());

        // The IdP provisions through the protocol endpoint mounted on the same handler.
        let pushed = m
            .scim(
                &path,
                &scim_token,
                "Users",
                "POST",
                Some(json!({ "userName": "dev@acme.test" })),
            )
            .await;
        assert_eq!(pushed.status, 201);
        let user = pushed.body;
        let engineering = m
            .scim(
                &path,
                &scim_token,
                "Groups",
                "POST",
                Some(json!({ "displayName": "Engineering", "externalId": "eng", "members": [{ "value": user["id"] }] })),
            )
            .await
            .body;
        let admins = m
            .scim(
                &path,
                &scim_token,
                "Groups",
                "POST",
                Some(json!({ "displayName": "Admins" })),
            )
            .await
            .body;
        let users = m.scim(&path, &scim_token, "Users", "GET", None).await.body;
        assert_eq!(users["totalResults"], json!(1));

        let groups = m
            .post(
                "connections/groups",
                json!({ "tenantId": tenant_id, "connectionId": connection_id }),
            )
            .await
            .body["data"]
            .clone();
        let groups = groups.as_array().unwrap();
        assert_eq!(groups.len(), 2);
        assert_eq!(
            groups[0],
            json!({
                "id": admins["id"],
                "groupId": groups[0]["groupId"],
                "displayName": "Admins",
                "members": 0,
                "roleIds": [],
            })
        );
        assert!(groups[0]["groupId"].is_string());
        assert_eq!(
            groups[1],
            json!({
                "id": engineering["id"],
                "groupId": groups[1]["groupId"],
                "displayName": "Engineering",
                "externalId": "eng",
                "members": 1,
                "roleIds": [],
            })
        );
        let local_group_id = groups[1]["groupId"].as_str().unwrap().to_owned();

        let readers = ok(m
            .f
            .iam
            .api
            .roles
            .create(
                &m.f.owner_credential,
                body(json!({ "tenantId": tenant_id, "name": "Readers", "permissions": ["documents:read"] })),
            )
            .await);
        let readers_id = readers["id"].as_str().unwrap().to_owned();
        let mapped = m
            .post(
                "connections/mappings",
                json!({
                    "tenantId": tenant_id,
                    "connectionId": connection_id,
                    "groupId": engineering["id"],
                    "roleIds": [readers_id],
                }),
            )
            .await;
        assert_eq!(mapped.status, 200, "{}", mapped.body);
        assert_eq!(mapped.body, json!({ "data": null }));
        assert_eq!(
            m.post(
                "connections/groups",
                json!({ "tenantId": tenant_id, "connectionId": connection_id })
            )
            .await
            .body["data"][1]["roleIds"],
            json!([readers_id])
        );
        let link =
            m.f.store()
                .get("scimUsers", user["id"].as_str().unwrap())
                .await
                .unwrap()
                .unwrap();
        let identity_id = link["identityId"].as_str().unwrap().to_owned();
        let effective = || async {
            ok(m.f
                .iam
                .api
                .identities
                .list_bindings(
                    &m.f.owner_credential,
                    body(json!({ "tenantId": tenant_id, "identityId": identity_id })),
                )
                .await)
        };
        let bindings = effective().await;
        let bindings = bindings.as_array().unwrap();
        assert_eq!(bindings.len(), 1);
        organization_fixture::assert_matches(
            &bindings[0],
            json!({ "roleId": readers_id, "via": { "groupId": local_group_id } }),
        );
        assert_eq!(
            m.post(
                "connections/mappings",
                json!({
                    "tenantId": tenant_id,
                    "connectionId": connection_id,
                    "groupId": engineering["id"],
                    "roleIds": "everything",
                }),
            )
            .await
            .status,
            400
        );

        let rotated = m
            .post(
                "connections/rotate",
                json!({ "tenantId": tenant_id, "connectionId": connection_id, "expiresIn": 3600 }),
            )
            .await;
        assert_eq!(rotated.status, 200);
        let token = rotated.body["data"]["token"].as_str().unwrap().to_owned();
        assert_ne!(token, scim_token);
        assert_eq!(
            m.scim(&path, &scim_token, "Users", "GET", None)
                .await
                .status,
            401
        );
        assert_eq!(
            m.scim(&path, &token, "Users", "GET", None).await.status,
            200
        );

        let revoked = m
            .post(
                "connections/revoke",
                json!({ "tenantId": tenant_id, "connectionId": connection_id }),
            )
            .await;
        assert_eq!(revoked.status, 200);
        assert_eq!(revoked.body, json!({ "data": null }));
        assert_eq!(
            m.scim(&path, &token, "Users", "GET", None).await.status,
            401
        );
        assert_eq!(
            m.post("connections/list", json!({ "tenantId": tenant_id }))
                .await
                .body["data"][0]["revoked"],
            json!(true)
        );
        assert_eq!(effective().await, json!([]));
    });
}

#[test]
fn refuses_cross_site_malformed_unknown_and_unauthorized_requests() {
    run(|| async {
        let m = mounted().await;
        let tenant_id = m.f.tenant_id.clone();
        let owner = m.owner_token();
        let missing_header = parse(
            m.f.iam
                .handler(
                    http::Request::builder()
                        .method("POST")
                        .uri(format!("{ORIGIN}/api/iam/scim-admin/connections/list"))
                        .header("content-type", "application/json")
                        .header("authorization", format!("Bearer {owner}"))
                        .body(Bytes::from(json!({ "tenantId": tenant_id }).to_string()))
                        .unwrap(),
                )
                .await,
        );
        assert_eq!(missing_header.status, 403);
        assert_eq!(missing_header.body["error"]["code"], json!("CSRF_REJECTED"));
        let text_plain = m
            .call(
                "connections/list",
                Some(json!({ "tenantId": tenant_id })),
                None,
                Options {
                    headers: vec![("content-type", "text/plain")],
                    ..Options::default()
                },
            )
            .await;
        assert_eq!(text_plain.body["error"]["code"], json!("CSRF_REJECTED"));
        let cross_site = m
            .call(
                "connections/create",
                Some(json!({ "tenantId": tenant_id, "name": "Evil" })),
                None,
                Options {
                    headers: vec![("origin", "https://evil.test")],
                    ..Options::default()
                },
            )
            .await;
        assert_eq!(cross_site.status, 403);
        assert_eq!(cross_site.body["error"]["code"], json!("CSRF_REJECTED"));
        assert_eq!(
            m.call(
                "connections/list",
                Some(json!({ "tenantId": tenant_id })),
                None,
                Options {
                    headers: vec![("origin", ORIGIN)],
                    ..Options::default()
                },
            )
            .await
            .status,
            200
        );

        let get = m
            .call(
                "connections/list",
                None,
                None,
                Options {
                    method: Some("GET"),
                    ..Options::default()
                },
            )
            .await;
        assert_eq!(get.status, 405);
        assert_eq!(get.body["error"]["code"], json!("METHOD_NOT_ALLOWED"));
        for route in ["connections/nope", "constructor", "connections"] {
            let reply = m.post(route, json!({ "tenantId": tenant_id })).await;
            assert_eq!(reply.status, 404, "{route}");
            assert_eq!(reply.cache_control.as_deref(), Some("no-store"));
            assert_eq!(reply.body["error"]["code"], json!("NOT_FOUND"));
        }
        assert_eq!(
            m.call("connections/list", None, Some("[1]"), Options::default())
                .await
                .status,
            400
        );
        assert_eq!(
            m.call("connections/list", None, Some("{nope"), Options::default())
                .await
                .status,
            400
        );
        assert_eq!(m.post("connections/list", json!({})).await.status, 400);
        assert_eq!(
            m.post(
                "connections/create",
                json!({ "tenantId": tenant_id, "name": "x".repeat(70 * 1024) })
            )
            .await
            .status,
            413
        );
        assert_eq!(
            m.post(
                "connections/groups",
                json!({ "tenantId": tenant_id, "connectionId": "missing" })
            )
            .await
            .status,
            404
        );

        // A member without SCIM permissions is denied, and nothing was created on their behalf.
        let alice = m.f.member("alice").await;
        let alice = m.f.sign_in(&alice).await;
        let alice_token = alice.token.unwrap();
        for (route, payload) in [
            ("connections/list", json!({ "tenantId": tenant_id })),
            (
                "connections/create",
                json!({ "tenantId": tenant_id, "name": "Shadow" }),
            ),
        ] {
            let reply = m
                .call(
                    route,
                    Some(payload),
                    None,
                    Options {
                        token: Some(&alice_token),
                        ..Options::default()
                    },
                )
                .await;
            assert_eq!(reply.status, 403, "{route}");
        }
        assert_eq!(
            m.post("connections/list", json!({ "tenantId": tenant_id }))
                .await
                .body["data"],
            json!([])
        );
    });
}

#[test]
fn hides_unexpected_failures_and_validates_its_paths() {
    run(|| async {
        let m = mounted().await;
        let mut config = scim_config(&m.f.iam).unwrap();
        // A callback that fails with something other than an IamError (`throw new Error('database exploded')`).
        config.authorize = authorize_fn(|_, _, _| async {
            Err(IamError::with_status(
                "INTERNAL_ERROR",
                "database exploded",
                500,
            ))
        });
        let failing = ScimService::new(config).unwrap();
        let response = failing
            .handler(
                &http::Request::builder()
                    .method("POST")
                    .uri(format!("{ORIGIN}/scim/admin/connections/list"))
                    .header("content-type", "application/json")
                    .header("x-better-iam", "1")
                    .body(Bytes::from(
                        json!({ "tenantId": m.f.tenant_id }).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let reply = parse(response);
        assert_eq!(reply.status, 500);
        assert_eq!(reply.body["error"]["code"], json!("INTERNAL_ERROR"));
        assert!(
            !reply.body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("exploded")
        );
        assert!(
            failing
                .handler(
                    &http::Request::builder()
                        .uri(format!("{ORIGIN}/elsewhere"))
                        .body(Bytes::new())
                        .unwrap()
                )
                .await
                .is_none()
        );

        for (base, admin) in [
            ("/scim/v2", "/scim/v2"),
            ("/scim/v2", "/scim/v2/admin"),
            ("/scim/admin/v2", "/scim/admin"),
            ("/scim/v2", "scim/admin"),
        ] {
            let mut config = scim_config(&m.f.iam).unwrap();
            config.base_path = Some(base.into());
            config.admin_base_path = Some(admin.into());
            let error = ScimService::new(config)
                .err()
                .expect("a configuration error");
            assert_eq!(error.code, "configuration", "{base} {admin}");
        }
        let mut config = scim_config(&m.f.iam).unwrap();
        config.base_path = Some("/scim".into());
        config.admin_base_path = Some("/scim-admin".into());
        assert_eq!(
            ScimService::new(config).unwrap().admin_base_path(),
            "/scim-admin"
        );
    });
}
