# better-iam-adapter-libsql

libSQL storage for [Better IAM](https://github.com/Better-IAM/better-iam) in Rust, the counterpart of
`@better-iam/adapter-libsql`: local files and remote Turso or sqld databases through one adapter, with the same schema,
migrations and SQL as the TypeScript adapter.

```rust,ignore
use better_iam_adapter_libsql::{libsql_adapter, LibsqlAdapterOptions};

let store = libsql_adapter(LibsqlAdapterOptions {
    auth_token: Some(std::env::var("TURSO_AUTH_TOKEN")?),
    ..LibsqlAdapterOptions::new("libsql://my-db.turso.io")
})?;
store.migrate().await?;
```

Local databases (`:memory:`, `file:` URLs and plain paths) run on bundled SQLite (`rusqlite`); remote databases speak
Hrana over HTTP with the `libsql` crate (`wss:`/`ws:` URLs are sent to the same server over `https:`/`http:`). The
libSQL C core is not linked, because it defines the same C symbols as bundled SQLite and would conflict with
`better-iam-adapter-sqlite`; embedded replicas (`sync_url`) and encrypted files (`encryption_key`) therefore return
`NOT_IMPLEMENTED`.
