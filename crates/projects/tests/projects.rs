//! The projects plugin (tests/projects.test.ts, and the projects suite of tests/security-integrations.test.ts).
//! Tenants and their owners come from the organization fixture (the way `tenants.create` with `activate` writes
//! them) instead of the invitation round trip; everything else goes through the server's API.

#[path = "../../server/tests/organization_fixture/mod.rs"]
mod organization_fixture;

use better_iam_core::{CredentialInput, Filter, IamError};
use better_iam_server::contracts::PluginCall;
use better_iam_server::options::OnboardingOptions;
use bytes::Bytes;
use organization_fixture::{Org, assert_matches, body, ok, run};
use serde_json::{Value, json};

async fn fixture() -> Org {
    organization_fixture::organization(|options| {
        options.onboarding = Some(OnboardingOptions {
            mode: Some("linked".into()),
            ..OnboardingOptions::default()
        });
        options.plugins = Some(vec![better_iam_projects::create_projects_plugin()]);
    })
    .await
}

async fn call(
    f: &Org,
    path: &str,
    who: &CredentialInput,
    tenant_id: &str,
    input: Value,
) -> Result<Value, IamError> {
    f.iam
        .call_plugin(
            who,
            PluginCall {
                plugin_id: Some(json!("projects")),
                path: Some(json!(path)),
                tenant_id: Some(json!(tenant_id)),
                input: Some(input),
            },
        )
        .await
}

#[track_caller]
fn code(result: Result<Value, IamError>) -> String {
    match result {
        Ok(value) => panic!("expected an error, got {value}"),
        Err(error) => error.code,
    }
}

/// A tenant with an active owner: `(tenant id, owner id, owner credential)`.
async fn create_tenant(
    f: &Org,
    name: &str,
    parent: Option<&str>,
    kind: &str,
) -> (String, String, CredentialInput) {
    let parent = parent.map_or_else(|| f.root_tenant.clone(), str::to_owned);
    f.activate(&parent, name, kind, &format!("{name}@example.test"))
        .await
}

fn id(value: &Value) -> String {
    value["id"].as_str().unwrap().to_owned()
}

fn ids(value: &Value) -> Vec<String> {
    value.as_array().unwrap().iter().map(id).collect()
}

#[test]
fn manages_the_project_lifecycle_in_the_root_tenant_and_organization_tenants() {
    run(|| async {
        let f = fixture().await;
        let root = f.root_credential.clone();
        let platform = call(
            &f,
            "create",
            &root,
            &f.root_tenant,
            json!({ "name": "Platform", "description": "Deployment-level project" }),
        )
        .await
        .unwrap();
        assert_matches(
            &platform,
            json!({ "name": "Platform", "status": "active", "tenantId": f.root_tenant, "createdBy": f.root_id }),
        );
        assert_eq!(
            code(
                call(
                    &f,
                    "create",
                    &root,
                    &f.root_tenant,
                    json!({ "name": "Platform" })
                )
                .await
            ),
            "CONFLICT"
        );
        assert_eq!(
            code(
                call(
                    &f,
                    "create",
                    &root,
                    &f.root_tenant,
                    json!({ "name": "   " })
                )
                .await
            ),
            "INVALID_INPUT"
        );
        assert_eq!(
            code(
                call(
                    &f,
                    "create",
                    &root,
                    &f.root_tenant,
                    json!({ "name": "x".repeat(101) })
                )
                .await
            ),
            "INVALID_INPUT"
        );
        assert_eq!(
            code(
                call(
                    &f,
                    "create",
                    &root,
                    &f.root_tenant,
                    json!({ "name": "Fields", "owner": "forged" })
                )
                .await
            ),
            "INVALID_INPUT"
        );
        let (a, a_owner, a_credential) = create_tenant(&f, "acme", None, "organization").await;
        assert_eq!(
            code(
                call(
                    &f,
                    "create",
                    &a_credential,
                    &a,
                    json!({ "tenantId": f.root_tenant, "name": "Forged scope" })
                )
                .await
            ),
            "INVALID_INPUT"
        );
        // The same name is available in another tenant.
        let first = call(
            &f,
            "create",
            &a_credential,
            &a,
            json!({ "name": "Platform" }),
        )
        .await
        .unwrap();
        assert_matches(
            &first,
            json!({ "tenantId": a, "createdBy": a_owner, "status": "active" }),
        );
        assert_eq!(
            code(
                call(
                    &f,
                    "update",
                    &a_credential,
                    &a,
                    json!({ "projectId": id(&first) })
                )
                .await
            ),
            "INVALID_INPUT"
        );
        let renamed = call(
            &f,
            "update",
            &a_credential,
            &a,
            json!({ "projectId": id(&first), "name": "Platform Core" }),
        )
        .await
        .unwrap();
        assert_eq!(renamed["name"], json!("Platform Core"));
        let described = call(
            &f,
            "update",
            &a_credential,
            &a,
            json!({ "projectId": id(&first), "description": "Owned by acme" }),
        )
        .await
        .unwrap();
        assert_eq!(described["description"], json!("Owned by acme"));
        let cleared = call(
            &f,
            "update",
            &a_credential,
            &a,
            json!({ "projectId": id(&first), "description": "" }),
        )
        .await
        .unwrap();
        assert!(cleared.get("description").is_none());
        let second = call(&f, "create", &a_credential, &a, json!({ "name": "Second" }))
            .await
            .unwrap();
        assert_eq!(
            code(
                call(
                    &f,
                    "update",
                    &a_credential,
                    &a,
                    json!({ "projectId": id(&second), "name": "Platform Core" })
                )
                .await
            ),
            "CONFLICT"
        );
        let archived = call(
            &f,
            "archive",
            &a_credential,
            &a,
            json!({ "projectId": id(&second) }),
        )
        .await
        .unwrap();
        assert_eq!(archived["status"], json!("archived"));
        assert_eq!(
            code(
                call(
                    &f,
                    "archive",
                    &a_credential,
                    &a,
                    json!({ "projectId": id(&second) })
                )
                .await
            ),
            "INVALID_TRANSITION"
        );
        let listed = call(
            &f,
            "list",
            &a_credential,
            &a,
            json!({ "status": "archived" }),
        )
        .await
        .unwrap();
        assert_eq!(ids(&listed), vec![id(&second)]);
        let listed = call(&f, "list", &a_credential, &a, json!({ "status": "active" }))
            .await
            .unwrap();
        assert_eq!(ids(&listed), vec![id(&first)]);
        let listed = call(&f, "list", &a_credential, &a, json!({}))
            .await
            .unwrap();
        let mut names: Vec<&str> = listed
            .as_array()
            .unwrap()
            .iter()
            .map(|project| project["name"].as_str().unwrap())
            .collect();
        names.sort_unstable();
        assert_eq!(names, vec!["Platform Core", "Second"]);
        let restored = call(
            &f,
            "restore",
            &a_credential,
            &a,
            json!({ "projectId": id(&second) }),
        )
        .await
        .unwrap();
        assert_eq!(restored["status"], json!("active"));
        assert_eq!(
            code(
                call(
                    &f,
                    "restore",
                    &a_credential,
                    &a,
                    json!({ "projectId": id(&second) })
                )
                .await
            ),
            "INVALID_TRANSITION"
        );
        let got = call(
            &f,
            "get",
            &a_credential,
            &a,
            json!({ "projectId": id(&second) }),
        )
        .await
        .unwrap();
        assert_eq!(got["name"], json!("Second"));
        assert_eq!(
            code(
                call(
                    &f,
                    "get",
                    &a_credential,
                    &a,
                    json!({ "projectId": id(&platform) })
                )
                .await
            ),
            "NOT_FOUND"
        );
        // Records keep the TypeScript member order.
        let keys: Vec<&String> = got.as_object().unwrap().keys().collect();
        assert_eq!(
            keys,
            vec![
                "id",
                "tenantId",
                "name",
                "status",
                "createdBy",
                "createdAt",
                "updatedAt"
            ]
        );
    });
}

#[test]
fn isolates_tenants_and_enforces_policies_for_project_access() {
    run(|| async {
        let f = fixture().await;
        let (a, _, a_credential) = create_tenant(&f, "alpha", None, "organization").await;
        let (b, _, b_credential) = create_tenant(&f, "beta", None, "organization").await;
        let project = call(
            &f,
            "create",
            &a_credential,
            &a,
            json!({ "name": "Alpha project" }),
        )
        .await
        .unwrap();
        assert_eq!(
            code(
                call(
                    &f,
                    "create",
                    &b_credential,
                    &a,
                    json!({ "name": "Intrusion" })
                )
                .await
            ),
            "ACCESS_DENIED"
        );
        assert_eq!(
            code(call(&f, "list", &b_credential, &a, json!({})).await),
            "ACCESS_DENIED"
        );
        assert_eq!(
            code(
                call(
                    &f,
                    "get",
                    &b_credential,
                    &a,
                    json!({ "projectId": id(&project) })
                )
                .await
            ),
            "ACCESS_DENIED"
        );
        assert_eq!(
            call(&f, "list", &b_credential, &b, json!({}))
                .await
                .unwrap(),
            json!([])
        );
        let reader = f.member_in(&a, "reader").await;
        let policy = ok(f
            .iam
            .api
            .policies
            .create(
                &a_credential,
                body(json!({
                    "tenantId": a,
                    "name": "Project reader",
                    "document": {
                        "version": 1,
                        "statements": [{ "effect": "allow", "actions": ["projects:read"], "resources": ["iam/*"] }],
                    },
                })),
            )
            .await);
        let role = ok(f
            .iam
            .api
            .roles
            .create(
                &a_credential,
                body(json!({ "tenantId": a, "name": "Reader", "policyIds": [policy["id"]] })),
            )
            .await);
        ok(f.iam
            .api
            .bindings
            .create(
                &a_credential,
                body(json!({
                    "tenantId": a,
                    "roleId": role["id"],
                    "subjectType": "identity",
                    "subjectId": reader,
                })),
            )
            .await);
        let reader_credential = f.sign_in(&reader).await;
        let got = call(
            &f,
            "get",
            &reader_credential,
            &a,
            json!({ "projectId": id(&project) }),
        )
        .await
        .unwrap();
        assert_eq!(got["name"], json!("Alpha project"));
        assert_eq!(
            code(
                call(
                    &f,
                    "create",
                    &reader_credential,
                    &a,
                    json!({ "name": "Nope" })
                )
                .await
            ),
            "ACCESS_DENIED"
        );
        let listed = call(&f, "list", &f.root_credential, &a, json!({}))
            .await
            .unwrap();
        assert_eq!(ids(&listed), vec![id(&project)]);
    });
}

#[test]
fn applies_ancestor_tenant_boundaries_to_plugin_actions() {
    run(|| async {
        let f = fixture().await;
        let (a, _, a_credential) = create_tenant(&f, "bounded", None, "organization").await;
        let project = call(
            &f,
            "create",
            &a_credential,
            &a,
            json!({ "name": "Bounded project" }),
        )
        .await
        .unwrap();
        ok(f.iam
            .api
            .tenants
            .set_boundary(
                &f.root_credential,
                body(json!({
                    "tenantId": a,
                    "boundary": {
                        "version": 1,
                        "statements": [{ "effect": "allow", "actions": ["iam:*"], "resources": ["*"] }],
                    },
                })),
            )
            .await);
        assert_eq!(
            code(
                call(
                    &f,
                    "create",
                    &a_credential,
                    &a,
                    json!({ "name": "Blocked" })
                )
                .await
            ),
            "ACCESS_DENIED"
        );
        assert_eq!(
            code(call(&f, "list", &a_credential, &a, json!({})).await),
            "ACCESS_DENIED"
        );
        assert_eq!(
            code(
                call(
                    &f,
                    "archive",
                    &a_credential,
                    &a,
                    json!({ "projectId": id(&project) })
                )
                .await
            ),
            "ACCESS_DENIED"
        );
        let listed = call(&f, "list", &f.root_credential, &a, json!({}))
            .await
            .unwrap();
        assert_eq!(ids(&listed), vec![id(&project)]);
    });
}

#[test]
fn removes_purged_tenants_project_records_through_the_plugin_purge_callback() {
    run(|| async {
        let f = fixture().await;
        let (a, _, a_credential) = create_tenant(&f, "alpha", None, "organization").await;
        let (b, _, b_credential) = create_tenant(&f, "beta", None, "organization").await;
        let in_a = call(
            &f,
            "create",
            &a_credential,
            &a,
            json!({ "name": "Alpha one" }),
        )
        .await
        .unwrap();
        let (child, _, child_credential) =
            create_tenant(&f, "alpha-web", Some(&a), "project").await;
        let in_child = call(
            &f,
            "create",
            &child_credential,
            &child,
            json!({ "name": "Alpha web" }),
        )
        .await
        .unwrap();
        let in_b = call(
            &f,
            "create",
            &b_credential,
            &b,
            json!({ "name": "Beta one" }),
        )
        .await
        .unwrap();
        ok(f.iam
            .api
            .tenants
            .set_status(
                &f.root_credential,
                body(json!({ "tenantId": a, "status": "deleted" })),
            )
            .await);
        let purge = f
            .iam
            .purge_deleted(Some(&json!({ "retentionMs": 0 })))
            .await
            .unwrap();
        let mut expected = vec![a.clone(), child.clone()];
        expected.sort();
        assert_eq!(purge["purgedTenants"], json!(expected));
        let projects = |tenant: &str| Filter::new().eq("tenantId", tenant.to_owned());
        assert!(f.find("projects", projects(&a)).await.is_empty());
        assert!(f.find("projects", projects(&child)).await.is_empty());
        let left: Vec<String> = f
            .find("projects", projects(&b))
            .await
            .iter()
            .map(|project| project["id"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(left, vec![id(&in_b)]);
        assert_ne!(id(&in_a), id(&in_child));
        let purged = f
            .find(
                "audit",
                Filter::new()
                    .eq("tenantId", a.clone())
                    .eq("action", "tenants:purge"),
            )
            .await;
        assert_eq!(purged.len(), 1);
    });
}

#[test]
fn serves_the_plugin_over_http_with_the_same_authorization_boundary() {
    run(|| async {
        let f = fixture().await;
        let (a, a_owner, a_credential) = create_tenant(&f, "http", None, "organization").await;
        let token = a_credential.token.clone().unwrap();
        let post = |path: &str, input: Value, headers: Vec<(&str, String)>| {
            let mut builder = http::Request::builder().method("POST").uri(format!(
                "http://localhost:3000/api/iam/plugins/projects/{path}"
            ));
            let mut all = vec![
                ("content-type", "application/json".to_owned()),
                ("x-better-iam", "1".to_owned()),
                ("authorization", format!("Bearer {token}")),
            ];
            for (name, value) in headers {
                all.retain(|(existing, _)| *existing != name);
                all.push((name, value));
            }
            for (name, value) in all {
                builder = builder.header(name, value);
            }
            let request = builder.body(Bytes::from(input.to_string())).unwrap();
            let http = f.iam.http.clone();
            async move { http.handler(request).await }
        };
        let json_of = |response: &http::Response<Bytes>| -> Value {
            serde_json::from_slice(response.body()).unwrap()
        };
        let response = post(
            "create",
            json!({ "tenantId": a, "name": "HTTP project" }),
            vec![],
        )
        .await;
        assert_eq!(response.status(), 200);
        let created = json_of(&response)["data"].clone();
        assert_matches(
            &created,
            json!({ "name": "HTTP project", "tenantId": a, "createdBy": a_owner, "status": "active" }),
        );
        let listed = post("list", json!({ "tenantId": a }), vec![]).await;
        assert_eq!(ids(&json_of(&listed)["data"]), vec![id(&created)]);
        let got = post(
            "get",
            json!({ "tenantId": a, "projectId": id(&created) }),
            vec![],
        )
        .await;
        assert_eq!(got.status(), 200);
        let forged = post(
            "list",
            json!({ "tenantId": a }),
            vec![("x-better-iam", "0".to_owned())],
        )
        .await;
        assert_eq!(forged.status(), 403);
        let (other, _, _) = create_tenant(&f, "other", None, "organization").await;
        assert_eq!(
            post("list", json!({ "tenantId": other }), vec![])
                .await
                .status(),
            403
        );
        let missing = post(
            "destroy",
            json!({ "tenantId": a, "projectId": id(&created) }),
            vec![],
        )
        .await;
        assert_eq!(missing.status(), 404);
        let anonymous = post(
            "create",
            json!({ "tenantId": a, "name": "No owner" }),
            vec![("authorization", String::new())],
        )
        .await;
        assert_eq!(anonymous.status(), 401);
    });
}

#[test]
fn authorizes_endpoints_on_one_project_against_that_project_so_a_deny_on_it_applies() {
    run(|| async {
        let f = organization_fixture::organization(|options| {
            options.plugins = Some(vec![better_iam_projects::create_projects_plugin()]);
        })
        .await;
        let owner = f.owner_credential.clone();
        let tenant = f.tenant_id.clone();
        let secret = call(&f, "create", &owner, &tenant, json!({ "name": "Secret" }))
            .await
            .unwrap();
        let open = call(&f, "create", &owner, &tenant, json!({ "name": "Open" }))
            .await
            .unwrap();
        let policy = ok(f
            .iam
            .api
            .policies
            .create(
                &owner,
                body(json!({
                    "tenantId": tenant,
                    "name": "Projects except Secret",
                    "document": {
                        "version": 1,
                        "statements": [
                            { "effect": "allow", "actions": ["projects:*"], "resources": ["*"] },
                            { "effect": "deny", "actions": ["projects:*"], "resources": [format!("iam/project/{}", id(&secret))] },
                        ],
                    },
                })),
            )
            .await);
        let role = ok(f
            .iam
            .api
            .roles
            .create(
                &owner,
                body(json!({ "tenantId": tenant, "name": "Project editor", "policyIds": [policy["id"]] })),
            )
            .await);
        let bob = f.member("bob").await;
        ok(f.iam
            .api
            .bindings
            .create(
                &owner,
                body(json!({ "tenantId": tenant, "roleId": role["id"], "subjectType": "identity", "subjectId": bob })),
            )
            .await);
        let session = f.sign_in(&bob).await;
        for (path, extra) in [
            ("get", json!({})),
            ("update", json!({ "name": "Renamed" })),
            ("archive", json!({})),
        ] {
            let mut input = extra.as_object().unwrap().clone();
            input.insert("projectId".into(), json!(id(&secret)));
            assert_eq!(
                code(call(&f, path, &session, &tenant, Value::Object(input)).await),
                "ACCESS_DENIED"
            );
        }
        let renamed = call(
            &f,
            "update",
            &session,
            &tenant,
            json!({ "projectId": id(&open), "name": "Open, renamed" }),
        )
        .await
        .unwrap();
        assert_eq!(renamed["name"], json!("Open, renamed"));
        // A wildcard never stands in for a project ID.
        assert_eq!(
            code(call(&f, "get", &session, &tenant, json!({ "projectId": "*" })).await),
            "INVALID_INPUT"
        );
    });
}
