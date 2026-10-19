//! The adapter conformance suite against the in-memory test store, which exercises the shared `record_store` logic
//! (the driver without SQL queries, so `find` takes the select-and-filter path).

mod common;

use better_iam_core::conformance::run_adapter_conformance;
use common::memory::MemoryStore;

#[tokio::test]
async fn memory_store_conforms() {
    let report = run_adapter_conformance(|| async { Ok(MemoryStore::open()) }).await;
    for (name, failure) in &report.failed {
        eprintln!("FAILED {name}: {failure}");
    }
    assert!(
        report.failed.is_empty(),
        "{} conformance failures",
        report.failed.len()
    );
    assert_eq!(
        report.passed.len(),
        better_iam_core::conformance::adapter_conformance_cases().len()
    );
}
