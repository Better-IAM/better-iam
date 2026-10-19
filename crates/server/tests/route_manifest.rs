//! The route manifest (spec/api/routes.json): the Rust router answers exactly that set of routes, no missing and no
//! extra ones, and dispatches every route to its method (a stub answers NOT_IMPLEMENTED, never NOT_FOUND).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_core::IamStore;
use better_iam_server::api::dispatch::ROUTE_PATHS;
use better_iam_server::http::{
    AUTH_METHODS, AUTHENTICATED_AUTH_METHODS, PUBLIC_API_METHODS, PUBLIC_AUTH_METHODS,
    ROUTE_GROUPS, SESSION_COOKIE_ROUTES, TENANT_BOUND_PUBLIC_METHODS,
};
use better_iam_server::options::BetterIamOptions;
use bytes::Bytes;
use serde_json::Value;

fn routes() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/api/routes.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("routes.json")).expect("JSON")
}

fn strings(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .expect("array")
        .iter()
        .map(|item| item.as_str().expect("string").to_owned())
        .collect()
}

fn set(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

#[test]
fn the_route_table_is_exactly_routes_json() {
    let routes = routes();
    let rpc = routes["rpc"].as_array().unwrap();
    let group_routes: BTreeSet<String> = rpc
        .iter()
        .filter(|route| route["group"] != "auth")
        .map(|route| route["path"].as_str().unwrap().to_owned())
        .collect();
    let table: BTreeSet<String> = ROUTE_PATHS.iter().map(|path| (*path).to_owned()).collect();
    let missing: Vec<_> = group_routes.difference(&table).collect();
    let extra: Vec<_> = table.difference(&group_routes).collect();
    assert!(
        missing.is_empty(),
        "routes the Rust router lacks: {missing:?}"
    );
    assert!(
        extra.is_empty(),
        "routes the Rust router has beyond routes.json: {extra:?}"
    );
    let auth_routes: BTreeSet<String> = rpc
        .iter()
        .filter(|route| route["group"] == "auth")
        .map(|route| route["method"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(set(AUTH_METHODS), auth_routes);
    let sets = &routes["sets"];
    assert_eq!(
        set(PUBLIC_AUTH_METHODS),
        strings(&sets["publicAuthMethods"])
    );
    assert_eq!(
        set(AUTHENTICATED_AUTH_METHODS),
        strings(&sets["authenticatedAuthMethods"])
    );
    assert_eq!(set(ROUTE_GROUPS), strings(&sets["routeGroups"]));
    assert_eq!(set(PUBLIC_API_METHODS), strings(&sets["publicApiMethods"]));
    assert_eq!(
        set(TENANT_BOUND_PUBLIC_METHODS),
        strings(&sets["tenantBoundPublicMethods"])
    );
    assert_eq!(
        set(SESSION_COOKIE_ROUTES),
        strings(&sets["sessionCookieRoutes"])
    );
    assert_eq!(
        strings(&sets["deviceTokenRoutes"]),
        set(&["auth/signIn", "auth/finishPasswordless"])
    );
    // Every routed group is a group of the table, and the table has no group outside routeGroups.
    let groups: BTreeSet<String> = rpc
        .iter()
        .map(|route| route["group"].as_str().unwrap().to_owned())
        .filter(|group| group != "auth")
        .collect();
    assert_eq!(groups, set(ROUTE_GROUPS));
    // The types crate's table agrees with routes.json as well.
    assert_eq!(
        better_iam_types::routes::ROUTES.len(),
        rpc.len() + 3,
        "the generated route table covers every RPC route and the three special routes"
    );
}

#[test]
fn every_route_reaches_its_method() {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let store: Arc<dyn IamStore> =
                        sqlite_adapter(SqliteAdapterOptions::new(":memory:")).unwrap();
                    let iam = better_iam_server::better_iam(BetterIamOptions::new(
                        store,
                        "route-manifest-test-secret-with-32-chars",
                        "http://localhost:3000",
                    ))
                    .unwrap();
                    iam.initialize().await.unwrap();
                    let routes = routes();
                    let mut paths: Vec<String> = routes["rpc"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|route| route["path"].as_str().unwrap().to_owned())
                        .collect();
                    paths.extend(
                        ["authorize", "authorizeMany", "listAccessible"].map(str::to_owned),
                    );
                    for path in paths {
                        let request = http::Request::builder()
                            .method("POST")
                            .uri(format!("http://localhost:3000/api/iam/{path}"))
                            .header("content-type", "application/json")
                            .header("x-better-iam", "1")
                            .body(Bytes::from_static(b"{}"))
                            .unwrap();
                        let response = iam.handler(request).await;
                        let body: Value =
                            serde_json::from_slice(response.body()).unwrap_or(Value::Null);
                        assert!(
                            !(response.status() == 404
                                && body["error"]["message"] == "Endpoint not found"),
                            "{path} is not routed"
                        );
                    }
                    // Paths outside the table are not routed.
                    for path in [
                        "tenants/nope",
                        "nope/list",
                        "auth/authenticate",
                        "tenants",
                        "plugins/none/x",
                    ] {
                        let request = http::Request::builder()
                            .method("POST")
                            .uri(format!("http://localhost:3000/api/iam/{path}"))
                            .header("content-type", "application/json")
                            .header("x-better-iam", "1")
                            .body(Bytes::from_static(b"{\"tenantId\":\"t\"}"))
                            .unwrap();
                        let response = iam.handler(request).await;
                        let body: Value = serde_json::from_slice(response.body()).unwrap();
                        assert_eq!(
                            (
                                response.status().as_u16(),
                                body["error"]["message"].as_str()
                            ),
                            (404, Some("Endpoint not found")),
                            "{path}"
                        );
                    }
                });
        })
        .unwrap()
        .join()
        .unwrap();
}
