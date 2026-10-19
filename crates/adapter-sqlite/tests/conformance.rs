//! The adapter conformance suite (`@better-iam/core/conformance`) against SQLite in memory and on disk.

use std::sync::Arc;

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_core::IamStore;
use better_iam_core::conformance::{adapter_conformance_cases, run_adapter_conformance};

fn report(name: &str, report: better_iam_core::conformance::ConformanceReport) {
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
async fn sqlite_memory_conforms() {
    let outcome =
        run_adapter_conformance(|| async { sqlite_adapter(SqliteAdapterOptions::new(":memory:")) })
            .await;
    report("SQLite (memory)", outcome);
}

#[tokio::test(flavor = "multi_thread")]
async fn sqlite_file_conforms() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let mut counter = 0;
    let outcome = run_adapter_conformance(|| {
        counter += 1;
        let path = directory
            .path()
            .join(format!("conformance-{counter}.sqlite"));
        async move {
            let store: Arc<dyn IamStore> =
                sqlite_adapter(SqliteAdapterOptions::new(path.to_string_lossy()))?;
            Ok(store)
        }
    })
    .await;
    report("SQLite (file)", outcome);
}
