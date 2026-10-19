# better-iam-core

The core of [Better IAM](https://github.com/Better-IAM/better-iam) for Rust, the counterpart of the
`@better-iam/core` npm package. It holds the pieces every other crate and every storage adapter share:

- the storage contract (`IamStore`, `IamStoreExt::transaction`) and the record-store logic adapters build on
  (`storage::record_store`, `RecordDriver`, `RecordAccess`), with the exact SQL, schema migrations and PostgreSQL
  value encoding of the TypeScript adapters, so TypeScript and Rust servers can share one database;
- policy validation and evaluation (`validate_policy`, `evaluate_policy`, glob and variable matching, IP ranges);
- query planning (`plan_resources`) and filter compilers for SQL, Prisma-style and MongoDB queries;
- the tamper-evident audit hash chain (`append_audit_event`, `verify_audit_chain`) and JSON canonicalization
  (`canonicalize_json`, RFC 8785);
- store snapshots (`export_store`, `import_store`, `copy_store`), security classification labels, Shared Signals
  (SSF/CAEP/RISC) claims and delegation token claims;
- with the `conformance` feature, the adapter conformance suite (`conformance::adapter_conformance_cases`).

Module and function names mirror the TypeScript sources (`policy.ts` → `policy`, `evaluatePolicy` →
`evaluate_policy`). Every behavior is checked against the vectors in the repository's `spec/vectors/`, produced by
the TypeScript implementation.

```rust,ignore
use better_iam_core::{evaluate_policy_json, Decision};
use serde_json::json;

let decision: Decision = evaluate_policy_json(&json!({
    "action": "docs:read",
    "resource": "doc/1",
    "grants": [{ "version": 1, "statements": [{ "effect": "allow", "actions": ["docs:*"], "resources": ["doc/*"] }] }]
}))?;
assert!(decision.allowed);
```

Records are `serde_json` objects; numbers are JavaScript doubles and JSON is written exactly as `JSON.stringify`
writes it. Rust strings cannot hold unpaired UTF-16 surrogates, so values that only JavaScript can produce read as
U+FFFD here.
