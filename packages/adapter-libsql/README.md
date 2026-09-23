# @better-iam/adapter-libsql

libSQL persistence for Better IAM through `@libsql/client`: local files (plain or encrypted), embedded replicas, and remote Turso or sqld databases. Requires Node.js 22.12 or later. Install `better-iam` to receive this adapter with the complete distribution, or install this package directly.

```ts
import { libsqlAdapter } from '@better-iam/adapter-libsql';

const database = libsqlAdapter({ url: 'file:./iam.db' });
// const database = libsqlAdapter({ url: 'libsql://name-org.turso.io', authToken: process.env.TURSO_AUTH_TOKEN });
await database.migrate();
// Pass database to betterIam({ database, ... }).
```

`url` accepts `:memory:` for tests, `file:` URLs or plain paths, and remote `libsql:`, `https:`, or `wss:` URLs; `authToken`, `encryptionKey`, `syncUrl`, and `syncInterval` are passed to the client. `busyTimeoutMs` (default 5000, 0–60000) bounds how long local file operations wait for another connection's lock.

All writes require `database.transaction(async tx => ...)`. Read/modify/write sequences must run inside this callback, including all reads used to make a write decision. Nested transactions on the same adapter join the outer transaction; a failed nested operation marks the entire transaction for rollback. Retaining a transaction handle after its callback completes is unsupported and rejected.

Every transaction is a `write` interactive transaction (`BEGIN IMMEDIATE`), so the writer lock is held before application reads. Adapters addressing the same local file serialize through a shared process mutex; reads outside a transaction wait for the current transaction, which also keeps single-connection databases (`:memory:`, embedded replicas) usable. Remote servers queue write transactions themselves, and every request to them is a network round trip: keep transactions short and never perform network requests or long work inside them.

Records use the same schema and strict JSON filter semantics as the SQLite and PostgreSQL adapters. Natural keys are unique within collection and tenant. `put` updates existing records and cannot change tenant ownership. Filter results sort by record ID before pagination. Tenant and record ID predicates use database indexes; remaining JSON filters execute in application code.

Prefer one adapter instance per process and database: two instances on the same local file coordinate through SQLite's file lock, whose retry delays are coarse, so hand-offs between them are slow. On Windows the native driver releases a database file handle when its connection object is garbage-collected, so deleting a file immediately after `close()` can fail with `EBUSY`; retry or leave the file to the operating system.

`migrate()` is idempotent and checks the persisted schema version. `close()` releases the client. Never call `close()` from inside a transaction. Uniqueness errors expose `IamError` code `CONFLICT`; lock timeouts expose `STORAGE_BUSY`. Retry the entire operation after a busy response, not an isolated write.

License: MIT.
