//! Mixed fleet: one libSQL local file written and read by both the TypeScript libSQL adapter (through
//! `scripts/conformance/fleet/sqlite-fleet.mjs`) and this crate. Records written by either side read back identically
//! on the other, the stored text is exactly `JSON.stringify` output, lookups agree, and one audit hash chain extended
//! alternately by both writers verifies everywhere.
//!
//! Needs Node with the workspace's TypeScript packages built (`pnpm build`) and a `better-sqlite3` build matching the
//! Node version. Set `BETTER_IAM_NODE` to that Node binary when `node` on PATH is another version; without a working
//! Node the test reports itself skipped.

use std::path::{Path, PathBuf};
use std::process::Command;

use better_iam_adapter_libsql::{LibsqlAdapterOptions, libsql_adapter};
use better_iam_core::{
    ChainHead, Filter, FindOptions, IamStoreExt, OrderOptions, Record, VerifyAuditChainOptions,
    append_audit_event, js, record, storage::find_ordered, verify_audit_chain,
};
use serde_json::{Value, json};

const TENANT: &str = "fleet-tenant";

fn script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../scripts/conformance/fleet/sqlite-fleet.mjs")
}

fn node() -> String {
    std::env::var("BETTER_IAM_NODE").unwrap_or_else(|_| "node".to_owned())
}

fn run_node(arguments: &[&str]) -> Option<Value> {
    let output = Command::new(node())
        .env("FLEET_ADAPTER", "libsql")
        .arg(script())
        .args(arguments)
        .output()
        .ok()?;
    if !output.status.success() {
        eprintln!(
            "node {arguments:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }
    serde_json::from_slice(&output.stdout).ok()
}

fn rust_records(prefix: &str) -> Vec<Record> {
    vec![
        record(json!({
            "id": format!("{prefix}-plain"),
            "tenantId": TENANT,
            "uniqueKey": format!("{prefix}@example.com"),
            "name": "Ada",
            "tokenHash": format!("{prefix}-hash"),
            "createdAt": 1_767_225_600_000u64,
        })),
        record(json!({
            "id": format!("{prefix}-numbers"),
            "tenantId": TENANT,
            "sum": js::number(0.1 + 0.2),
            "large": js::number(2f64.powi(60)),
            "exponent": js::number(1e21),
            "tiny": js::number(5e-324),
            "negative": -1.5,
            "max": js::number(f64::MAX),
            "expiresAt": 1_767_229_200_000u64,
        })),
        record(json!({
            "id": format!("{prefix}-unicode-\u{e9}\u{1f600}"),
            "tenantId": TENANT,
            "text": "\u{e9} \u{1f600} \u{4e2d}\u{6587} \u{2028} \u{1} \"quoted\" \\ back",
            "nested": { "list": [1, "two", true, null, { "deep": [] }], "2": "index key", "10": "ten", "b": 1, "a": 2 },
            "nul": "a\u{0}b",
        })),
    ]
}

fn event(id: &str, n: u64) -> Record {
    record(json!({
        "id": id,
        "tenantId": TENANT,
        "actorId": "idn_fleet",
        "action": "iam:groups:create",
        "resourceId": format!("grp_rust_{n}"),
        "timestamp": 1_767_225_700_000u64 + n,
        "outcome": "allow",
        "rootOverride": false,
        "metadata": { "writer": "rust", "n": n },
    }))
}

async fn chain_of(file: &Path) -> (usize, better_iam_core::AuditChainVerification) {
    let store = libsql_adapter(LibsqlAdapterOptions::new(format!(
        "file:{}",
        file.to_string_lossy()
    )))
    .expect("store");
    let events = find_ordered(
        store.as_ref(),
        "audit",
        &Filter::new().eq("tenantId", TENANT),
        &OrderOptions::by("sequence"),
        None,
    )
    .await
    .expect("audit");
    let head = store
        .get("auditChains", TENANT)
        .await
        .expect("head")
        .expect("chain head");
    let options = VerifyAuditChainOptions {
        previous_hash: None,
        head: Some(ChainHead {
            sequence: head["sequence"].as_f64().expect("sequence"),
            hash: head["hash"].as_str().expect("hash").to_owned(),
        }),
    };
    let verification = verify_audit_chain(&events, &options);
    store.close().await.expect("close");
    (events.len(), verification)
}

#[tokio::test(flavor = "multi_thread")]
async fn typescript_and_rust_share_one_libsql_database() {
    if run_node(&["probe"]).and_then(|probe| probe["ok"].as_bool()) != Some(true) {
        println!(
            "SKIPPED: no Node that can load the TypeScript libSQL adapter (set BETTER_IAM_NODE)"
        );
        return;
    }
    let directory = tempfile::tempdir().expect("temporary directory");
    let file = directory.path().join("fleet.sqlite");
    let path = file.to_string_lossy().into_owned();

    // 1. TypeScript creates and migrates the database, writes records and starts the audit chain.
    let written = run_node(&["write", &path, "ts"]).expect("TypeScript write");
    let ts_records: Vec<Value> = written["records"].as_array().expect("records").clone();

    // 2. Rust reads them back exactly, finds them through the lookup indexes, and verifies the chain.
    let store = libsql_adapter(LibsqlAdapterOptions::new(format!("file:{path}"))).expect("store");
    store
        .migrate()
        .await
        .expect("migrate an up-to-date database");
    for expected in &ts_records {
        let id = expected["id"].as_str().expect("id");
        let read = store
            .get("fleet", id)
            .await
            .expect("get")
            .expect("TypeScript record");
        assert_eq!(
            js::stringify_object(&read),
            js::stringify(expected),
            "Rust reads {id} as TypeScript wrote it"
        );
    }
    let found = store
        .find(
            "fleet",
            &Filter::new().eq("tokenHash", "ts-hash"),
            &FindOptions::default(),
        )
        .await
        .expect("find");
    assert_eq!(found.len(), 1);
    let numbers = store
        .find(
            "fleet",
            &Filter::new().eq("large", js::number(2f64.powi(60)).expect("number")),
            &FindOptions::default(),
        )
        .await
        .expect("find by number");
    assert_eq!(
        numbers.len(),
        1,
        "a number TypeScript wrote matches a Rust filter in SQL"
    );
    let ordered = find_ordered(
        store.as_ref(),
        "fleet",
        &Filter::new(),
        &OrderOptions::by("expiresAt"),
        None,
    )
    .await
    .expect("ordered");
    assert_eq!(ordered.len(), 1);

    // 3. Rust writes its own records, extends the same audit chain, updates one TypeScript record and deletes another.
    let mine = rust_records("rs");
    let mut updated = store.get("fleet", "ts-plain").await.unwrap().unwrap();
    updated.insert("name".into(), json!("Ada Lovelace"));
    updated.insert("updatedBy".into(), json!("rust"));
    {
        let (mine, updated) = (mine.clone(), updated.clone());
        store
            .transaction(move |tx| async move {
                for record in &mine {
                    tx.insert("fleet", record).await?;
                }
                for n in 1..=3 {
                    append_audit_event(tx.as_ref(), &event(&format!("rs-evt-{n}"), n)).await?;
                }
                tx.put("fleet", &updated).await?;
                tx.delete("fleet", "ts-numbers").await
            })
            .await
            .expect("Rust writes");
    }
    store.close().await.expect("close");
    let (count, verification) = chain_of(&file).await;
    assert_eq!(count, 6);
    assert!(
        verification.valid,
        "chain after the Rust writer: {verification:?}"
    );

    // 4. TypeScript reads the Rust records exactly, sees the update and the delete, and verifies the chain.
    let mut expected_records: Vec<Value> = mine
        .iter()
        .map(|record| Value::Object(record.clone()))
        .collect();
    expected_records.push(Value::Object(updated));
    expected_records.push(ts_records[2].clone());
    let expected = json!({
        "records": expected_records,
        "deleted": ["ts-numbers"],
        "lookups": [["tokenHash", "rs-hash", ["rs-plain"]], ["tokenHash", "ts-hash", ["ts-plain"]], ["updatedBy", "rust", ["ts-plain"]]],
        "auditEvents": 6,
    });
    let expected_path = directory.path().join("expected.json");
    std::fs::write(&expected_path, js::stringify(&expected)).expect("expected file");
    let verified =
        run_node(&["verify", &path, &expected_path.to_string_lossy()]).expect("TypeScript verify");
    assert_eq!(
        verified["ok"],
        json!(true),
        "TypeScript verification problems: {}",
        verified["problems"]
    );

    // 5. TypeScript extends the chain after the Rust events; Rust verifies all nine.
    run_node(&["write", &path, "ts2"]).expect("second TypeScript write");
    let (count, verification) = chain_of(&file).await;
    assert_eq!(count, 9);
    assert!(
        verification.valid,
        "chain after the second TypeScript writer: {verification:?}"
    );
    assert_eq!(verification.checked, 9);
    println!(
        "mixed fleet (libSQL): TypeScript and Rust records round-trip, 9 audit events verify across 3 writer turns"
    );
}
