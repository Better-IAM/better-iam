# @better-iam/adapter-sqlite

SQLite persistence for Better IAM, using Kysely and better-sqlite3. Requires Node.js 22.12 or later. Install `better-iam` to receive this adapter with the complete distribution, or install this package directly.

```ts
import { sqliteAdapter } from '@better-iam/adapter-sqlite';

const database = sqliteAdapter({ filename: './iam.sqlite' });
await database.migrate();
// Pass database to betterIam({ database, ... }).
```

`filename` accepts a filesystem path or `:memory:` for tests. URI filenames are unsupported. The containing directory must already exist. `busyTimeoutMs` defaults to 5000 and can be set between 0 and 60000.

All writes require `database.transaction(async tx => ...)`. Read/modify/write sequences must run inside this callback, including all reads used to make a write decision. Nested transactions on the same adapter join the outer transaction; a failed nested operation marks the entire transaction for rollback. Retaining a transaction handle after its callback completes is unsupported and rejected. Do not start a second adapter's transaction from inside the first adapter's transaction on the same database.

The adapter acquires `BEGIN IMMEDIATE` before application reads and retains one connection across `await`. Operations on adapters addressing the same canonical filename serialize through a shared process mutex. SQLite's database locks coordinate other processes, with a bounded busy timeout. Use one canonical path per database; aliases through filesystem hard links or independently loaded worker runtimes cannot share the process mutex. Do not perform network requests or long work inside database transactions.

Records use the same schema and strict JSON filter semantics as the PostgreSQL adapter. Natural keys are unique within collection and tenant. `put` updates existing records and cannot change tenant ownership. Filter results sort by record ID before pagination, independent of database collation. Tenant and record ID predicates use database indexes; remaining JSON filters execute in application code. This initial adapter favors consistency over high-volume analytical query performance.

`migrate()` is idempotent and checks the persisted schema version. Back up the database before upgrades. `close()` releases the database handle. Never call `close()` from inside a transaction. Database uniqueness errors expose `IamError` code `CONFLICT`; lock timeouts expose `STORAGE_BUSY`. Retry the entire operation after a busy response, not an isolated write.

The shared generic record schema intentionally has no application-level foreign keys. Better IAM services validate tenant hierarchy, identity ownership, and references within transactions. Writing database records directly bypasses service-level authorization and referential checks.

License: MIT.
