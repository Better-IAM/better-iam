//! Shared test helpers: fixture loading, JSON comparison, and a server context over an in-memory SQLite store.

#![allow(dead_code)]

use std::path::PathBuf;
use std::sync::Arc;

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::{AuthOptions, create_auth};
use better_iam_core::{IamError, IamStore, js};
use better_iam_server::catalog::Catalog;
use better_iam_server::context::{ContextBase, ServerContext, create_context};
use better_iam_server::events::create_events;
use better_iam_server::observe::create_observer;
use better_iam_server::options::{BetterIamOptions, resolve_config};
use serde_json::{Value, json};

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn read_json(relative: &str) -> Value {
    let path = repo_root().join(relative);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("read {}", path.display()));
    js::parse(&text).expect("valid JSON")
}

pub fn fixture(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("read {}", path.display()));
    js::parse(&text).expect("valid JSON")
}

pub fn memory_store() -> Arc<dyn IamStore> {
    sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite")
}

pub fn error_value(error: &IamError) -> Value {
    json!({ "code": error.code, "status": error.status, "message": error.message })
}

/// Asserts two JSON values are equal as JavaScript sees them (numbers as doubles, member order ignored).
pub fn assert_same(name: &str, actual: &Value, expected: &Value) {
    assert!(
        js::deep_equal(actual, expected),
        "{name}\n  actual:   {}\n  expected: {}",
        js::stringify(actual),
        js::stringify(expected)
    );
}

/// Compares an outcome with a fixture case that has either `result` or `error`.
pub fn assert_outcome(name: &str, actual: Result<Value, IamError>, case: &Value) {
    match (actual, case.get("error")) {
        (Err(error), Some(expected)) => {
            let mut expected = expected.clone();
            if let Value::Object(map) = &mut expected {
                map.remove("thrown");
            }
            assert_same(name, &error_value(&error), &expected);
        }
        (Ok(value), None) => assert_same(name, &value, case.get("result").unwrap_or(&Value::Null)),
        (Ok(value), Some(expected)) => panic!(
            "{name}: expected error {}, got {}",
            js::stringify(expected),
            js::stringify(&value)
        ),
        (Err(error), None) => panic!(
            "{name}: expected {}, got error {}",
            js::stringify(case.get("result").unwrap_or(&Value::Null)),
            js::stringify(&error_value(&error))
        ),
    }
}

/// A server context for these options (no service modules attached besides events).
pub fn context(options: BetterIamOptions, now: f64) -> Arc<ServerContext> {
    let config = resolve_config(&options).expect("valid options");
    let store = options.database.clone().expect("database");
    // As the composition root does: webhook outbox messages go to the event service of this context.
    let slot: Arc<std::sync::OnceLock<std::sync::Weak<ServerContext>>> = Arc::default();
    let mut auth_options = AuthOptions::new(
        store.clone(),
        options.secret.clone(),
        options.base_url.clone(),
    );
    auth_options.previous_secrets = options.previous_secrets.clone();
    auth_options.now = Some(Arc::new(move || now));
    let webhook_slot = slot.clone();
    auth_options.deliver_webhook = Some(better_iam_auth::delivery_fn(move |message| {
        let ctx = webhook_slot.get().and_then(std::sync::Weak::upgrade);
        async move {
            match ctx {
                Some(ctx) => ctx.events()?.deliver_webhook_message(message).await,
                None => Ok(()),
            }
        }
    }));
    let auth = create_auth(auth_options).expect("auth");
    let catalog = Catalog::new(&options, &[], &config).expect("catalog");
    let ctx = create_context(ContextBase {
        options: Arc::new(options),
        config: Arc::new(config),
        store,
        auth,
        plugins: Vec::new(),
        catalog: Arc::new(catalog),
        now: Arc::new(move || now),
        observe: create_observer(None),
    });
    ctx.attach_events(create_events(&ctx));
    let _ = slot.set(Arc::downgrade(&ctx));
    ctx
}
