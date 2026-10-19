//! The adapter conformance suite against libSQL local databases (`:memory:` and files). Remote databases run when
//! `BETTER_IAM_LIBSQL_URL` (and `BETTER_IAM_LIBSQL_AUTH_TOKEN`) point at a sqld or Turso database used only for tests.

use std::sync::Arc;

use better_iam_adapter_libsql::{LibsqlAdapterOptions, libsql_adapter};
use better_iam_core::IamStore;
use better_iam_core::conformance::{
    ConformanceReport, adapter_conformance_cases, run_adapter_conformance,
};

fn report(name: &str, report: ConformanceReport) {
    for (case, failure) in &report.failed {
        eprintln!("{name}: FAILED {case}: {failure}");
    }
    println!(
        "{name}: {} passed, {} failed",
        report.passed.len(),
        report.failed.len()
    );
    assert!(
        report.failed.is_empty(),
        "{name}: {} conformance failures",
        report.failed.len()
    );
    assert_eq!(report.passed.len(), adapter_conformance_cases().len());
}

#[tokio::test(flavor = "multi_thread")]
async fn libsql_memory_conforms() {
    report(
        "libSQL (memory)",
        run_adapter_conformance(|| async { libsql_adapter(LibsqlAdapterOptions::new(":memory:")) })
            .await,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn libsql_file_conforms() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut counter = 0;
    let outcome = run_adapter_conformance(|| {
        counter += 1;
        let url = format!(
            "file:{}",
            directory
                .path()
                .join(format!("conformance-{counter}.db"))
                .to_string_lossy()
        );
        async move {
            let store: Arc<dyn IamStore> = libsql_adapter(LibsqlAdapterOptions::new(url))?;
            Ok(store)
        }
    })
    .await;
    report("libSQL (file)", outcome);
}

#[test]
fn validates_options_like_the_typescript_adapter() {
    let invalid = |options: LibsqlAdapterOptions| {
        libsql_adapter(options)
            .err()
            .map(|error| (error.code, error.message))
    };
    assert_eq!(
        invalid(LibsqlAdapterOptions::new("")),
        Some((
            "INVALID_CONFIG".into(),
            "libSQL requires a url: :memory:, file:, libsql:, https:, or wss:".into()
        ))
    );
    assert_eq!(
        invalid(LibsqlAdapterOptions::new("mysql://x")),
        Some((
            "INVALID_CONFIG".into(),
            "Unsupported libSQL URL scheme".into()
        ))
    );
    assert_eq!(
        invalid(LibsqlAdapterOptions {
            busy_timeout_ms: Some(-1),
            ..LibsqlAdapterOptions::new(":memory:")
        }),
        Some((
            "INVALID_CONFIG".into(),
            "busyTimeoutMs must be between 0 and 60000".into()
        ))
    );
    assert_eq!(
        invalid(LibsqlAdapterOptions {
            sync_url: Some("libsql://x".into()),
            ..LibsqlAdapterOptions::new("file:replica.db")
        })
        .map(|(code, _)| code),
        Some("NOT_IMPLEMENTED".into())
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn libsql_remote_conforms() {
    let Some(url) = std::env::var("BETTER_IAM_LIBSQL_URL")
        .ok()
        .filter(|url| !url.is_empty())
    else {
        println!("SKIPPED: set BETTER_IAM_LIBSQL_URL to run the remote libSQL conformance suite");
        return;
    };
    let token = std::env::var("BETTER_IAM_LIBSQL_AUTH_TOKEN").ok();
    let outcome = run_adapter_conformance(|| {
        let options = LibsqlAdapterOptions {
            auth_token: token.clone(),
            ..LibsqlAdapterOptions::new(url.clone())
        };
        async move {
            let store = libsql_adapter(options)?;
            // Each case starts from an empty database.
            store.migrate().await?;
            let collections = store.collections().await?;
            better_iam_core::IamStoreExt::transaction(store.as_ref(), move |tx| async move {
                for collection in collections {
                    for record in tx
                        .find(
                            &collection,
                            &better_iam_core::Filter::new(),
                            &Default::default(),
                        )
                        .await?
                    {
                        tx.delete(&collection, better_iam_core::record_id(&record))
                            .await?;
                    }
                }
                Ok(())
            })
            .await?;
            Ok(store)
        }
    })
    .await;
    report("libSQL (remote)", outcome);
}
