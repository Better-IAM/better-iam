//! The adapter conformance suite against PostgreSQL, one fresh schema per case. Runs only when
//! `BETTER_IAM_POSTGRES_URL` is set (CI); `BETTER_IAM_POSTGRES_POOL_SIZE` sets the pool size (default 3).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use better_iam_adapter_postgres::{PostgresAdapterOptions, postgres_adapter};
use better_iam_core::IamStore;
use better_iam_core::conformance::adapter_conformance_cases;

fn url() -> Option<String> {
    std::env::var("BETTER_IAM_POSTGRES_URL")
        .ok()
        .filter(|url| !url.is_empty())
}

async fn admin(url: &str, statement: &str) {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect");
    let task = tokio::spawn(connection);
    client.batch_execute(statement).await.expect(statement);
    drop(client);
    let _ = task.await;
}

fn with_search_path(url: &str, schema: &str) -> String {
    let separator = if url.contains('?') { '&' } else { '?' };
    format!("{url}{separator}options=-c%20search_path%3D{schema}")
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_conforms() {
    let Some(url) = url() else {
        println!("SKIPPED: set BETTER_IAM_POSTGRES_URL to run the PostgreSQL conformance suite");
        return;
    };
    let pool_size = std::env::var("BETTER_IAM_POSTGRES_POOL_SIZE")
        .ok()
        .and_then(|size| size.parse().ok())
        .unwrap_or(3);
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let mut failures = Vec::new();
    for case in adapter_conformance_cases() {
        let schema = format!(
            "conformance_rs_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        admin(&url, &format!("CREATE SCHEMA {schema}")).await;
        let options = PostgresAdapterOptions {
            pool_size: Some(pool_size),
            ..PostgresAdapterOptions::new(with_search_path(&url, &schema))
        };
        let store: Arc<dyn IamStore> = postgres_adapter(options).expect("store");
        let outcome = match store.migrate().await {
            Ok(()) => (case.run)(store.clone()).await,
            Err(error) => Err(error.into()),
        };
        let _ = store.close().await;
        admin(&url, &format!("DROP SCHEMA {schema} CASCADE")).await;
        if let Err(failure) = outcome {
            failures.push(format!("{}: {failure}", case.name));
        }
    }
    assert!(
        failures.is_empty(),
        "PostgreSQL conformance failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn validates_options_like_the_typescript_adapter() {
    let invalid = |options: PostgresAdapterOptions| {
        postgres_adapter(options)
            .err()
            .map(|error| (error.code, error.message))
    };
    assert_eq!(
        invalid(PostgresAdapterOptions::new("mysql://localhost/iam")),
        Some((
            "INVALID_CONFIG".into(),
            "A PostgreSQL connection string is required".into()
        ))
    );
    assert_eq!(
        invalid(PostgresAdapterOptions {
            pool_size: Some(0),
            ..PostgresAdapterOptions::new("postgres://localhost/iam")
        }),
        Some((
            "INVALID_CONFIG".into(),
            "Invalid PostgreSQL pool size or lock timeout".into()
        ))
    );
    assert_eq!(
        invalid(PostgresAdapterOptions {
            lock_timeout_ms: Some(60_001),
            ..PostgresAdapterOptions::new("postgres://localhost/iam")
        }),
        Some((
            "INVALID_CONFIG".into(),
            "Invalid PostgreSQL pool size or lock timeout".into()
        ))
    );
}
