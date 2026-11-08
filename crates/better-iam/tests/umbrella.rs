//! The umbrella re-exports work together: the server with the SQLite adapter and the projects plugin, the core
//! policy helpers, and the typed client over the server's handler.

use std::sync::Arc;

use better_iam::adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam::client::{BoxError, ClientOptions, FetchRequest, FetchResponse, create_iam_client};
use better_iam::{
    BetterIamOptions, IamStore, better_iam, canonical_json, define_policy, validate_policy,
};
use serde_json::json;

fn run<F: std::future::Future<Output = ()> + 'static>(body: impl FnOnce() -> F + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(body());
        })
        .expect("thread")
        .join()
        .expect("test body");
}

#[test]
fn re_exports_the_server_core_client_and_plugin() {
    run(|| async {
        let policy = json!({
            "version": 1,
            "statements": [{ "effect": "allow", "actions": ["projects:read"], "resources": ["*"] }],
        });
        assert!(validate_policy(&policy).is_ok());
        assert!(define_policy(&policy).is_ok());
        assert_eq!(
            canonical_json(&json!({ "b": 1, "a": [true] })),
            r#"{"a":[true],"b":1}"#
        );

        let store: Arc<dyn IamStore> =
            sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
        let mut options = BetterIamOptions::new(
            store,
            "umbrella-test-secret-with-at-least-32-characters",
            "http://localhost:3000",
        );
        options.plugins = Some(vec![better_iam::projects::create_projects_plugin()]);
        let iam = better_iam(options).expect("valid options");
        iam.initialize().await.expect("initialize");
        let root = iam
            .bootstrap(&json!({ "email": "root@example.test", "name": "Root", "password": "a strong root test password" }))
            .await
            .expect("bootstrap");
        let http = iam.http.clone();
        let client = create_iam_client(ClientOptions::new("http://localhost:3000").fetch_fn(
            move |request: FetchRequest| {
                let http = http.clone();
                async move {
                    let request = request
                        .into_http()
                        .map_err(|error| Arc::new(error) as BoxError)?;
                    Ok::<_, BoxError>(FetchResponse::from_http(http.handler(request).await))
                }
            },
        ))
        .expect("client");
        let discovery = client
            .tenants()
            .lookup(better_iam::types::api::tenants::LookupInput::default())
            .await;
        // A lookup without a slug or host is refused by the server, through the typed client.
        let error = discovery.unwrap_err();
        assert_eq!(error.status(), Some(400));
        // The projects plugin is mounted: an anonymous call is refused as unauthenticated, not as unknown.
        let refused = client
            .request::<serde_json::Value>(
                "plugins/projects/list",
                &json!({ "tenantId": root["tenant"]["id"] }),
            )
            .await
            .unwrap_err();
        assert_eq!(refused.status(), Some(401));
    });
}
