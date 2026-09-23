# Adapters and plugins

## Adapter contract

Implement `IamStore` from `better-iam/core`: `get`, `find`, `insert`, `put`, `delete`, `transaction`, `migrate`, and `close`.

- Records have `id`, `tenantId`, optional `uniqueKey`, and JSON-compatible fields. Field values may hold any string. Identifiers (collection, `id`, `tenantId`, `uniqueKey`) containing an unpaired surrogate are refused with `INVALID_RECORD`, because drivers encode text as UTF-8 and would store U+FFFD instead, so two ids would share a row. Reads and deletes treat such identifiers as absent.
- `uniqueKey` is unique within collection and tenant. Enforce this in the database.
- `put` updates an existing record; it is not an upsert. Tenant ownership is immutable.
- Filters use strict, typed equality on top-level fields. The string `"1"` never matches the number `1`, `null` matches only a stored `null`, `undefined` matches only an absent field, and objects compare deeply with key order ignored and array order kept.
- Results are ordered by `id` in code-point order, which is the order of SQLite's `BINARY` and PostgreSQL's `"C"` collation. Pagination uses `limit`/`offset` over that order. `after` is a keyset cursor: only records whose id sorts after it. Each page then costs the same however deep it is, and `offset` applies after the cursor. `RecordStore` passes the cursor to drivers as `RecordQuery.after`, which SQL drivers evaluate as `id > ?`. When a driver ignores it, the extra rows are caught and the query is repeated without paging, so the result stays correct.
- All writes require `transaction()`. Nested transactions join the current transaction and propagate rollback. Do not expose transaction handles after completion.
- Concurrent check-and-write operations must serialize before reading mutable authorization state. Token consumption and last-owner protection depend on this guarantee.
- Map errors to `IamError` without exposing SQL or serialized credentials.

The PostgreSQL, SQLite, and libSQL adapters are reference implementations. All three share the `RecordStore` base from `better-iam/core`, so a new adapter only implements a row driver, transaction boundaries, migration, and close. A driver that also implements the optional `query(RecordQuery)` method receives each filter as typed field conditions and evaluates it in SQL. `RecordStore` then pages in SQL whenever the whole filter could be expressed there, and filters the rest in memory. Values a database cannot compare exactly stay in memory: strings with U+0000 or unpaired surrogates, sparse arrays, and filters beyond `MAX_QUERY_CONDITIONS` keys. If a driver returns a row the filter rejects, `find` repeats the query without paging and filters in memory, so a lenient driver is slow but never wrong. A driver that drops matching rows cannot be corrected this way, and the conformance suite is designed to catch it. Drivers without `query` stay correct and read by collection, id, and tenant only. `planQuery`, `sqliteSelect`, `postgresSelect`, and `applyMigrations` are exported for SQL adapters, and `applyMigrations` records named schema steps in an `iam_migrations` table.

Three store methods are optional, and callers fall back when a store lacks them:

- **`findOrdered(collection, filter, { field, direction, from, to, offset, limit })`** returns records whose field holds a number, ordered by that field and then by id, within the inclusive `from` and `to` bounds. Records without a numeric value are left out. The audit log reads through it. A driver opts in with `queryCapabilities: { order: true }`. Callers use the exported `findOrdered(store, …)` helper, which sorts in memory for stores without the method and accepts an extra `where` predicate that it applies page by page.
- **`collections()`** lists the collections that hold records. Snapshots (`exportStore`, `importStore`, `copyStore`) rely on it, and a driver provides it with `collections()` returning the distinct collection names.
- **`describe()`** returns a `StoreDescription` for `doctor`: adapter name, schema version, applied migrations, record counts per collection, and adapter settings. `describeRecords` builds one from any SQL executor.

`instrumentStore(store, onCall)` wraps any store and reports each call, which helps verify that a new adapter's lookups stay selective. It forwards the optional methods only when the wrapped store has them.

### Conformance suite

`@better-iam/core/conformance` exports the behavioral contract as framework-agnostic cases. Every reference adapter runs it in `tests/adapter-conformance.test.ts`. Give each case a fresh, migrated store:

```ts
import { adapterConformanceCases } from '@better-iam/core/conformance';

for (const test of adapterConformanceCases())
  it(test.name, async () => {
    const store = myAdapter(options);
    await store.migrate();
    try {
      await test.run(store);
    } finally {
      await store.close();
    }
  });
```

`runAdapterConformance(createStore)` runs every case and returns `{ passed, failed }` for runners without per-case reporting. The cases cover typed filters (including integers above 2^53 and extreme exponents), strings with U+0000 and unpaired surrogates, code-point ordering, selective pagination over hundreds of rows, ordered and bounded reads, reads of uncommitted writes, natural-key uniqueness, transaction rollback and nesting, serialization of concurrent read-modify-write, record validation, and error hygiene. Run the service security tests against a new adapter as well.

## Plugin contract

An `IamPlugin` has a unique `id`, optional action names, validated endpoints, configuration validation, an optional migration callback, an optional post-commit audit callback, and an optional purge callback that removes plugin-owned records when a retention purge deletes a tenant.

```ts
const labels = {
  id: 'labels',
  actions: ['labels:create'],
  endpoints: [
    {
      method: 'POST',
      path: 'create',
      action: 'labels:create',
      validate(value) {
        if (!value || typeof value.tenantId !== 'string' || typeof value.name !== 'string') {
          throw new IamError('INVALID_INPUT', 'tenantId and name required');
        }
        return { tenantId: value.tenantId, name: value.name };
      },
      async handler({ store, tenantId }, input) {
        return store.insert('labels', { id: crypto.randomUUID(), tenantId, name: input.name });
      },
    },
  ],
};
```

Mount at `POST /api/iam/plugins/labels/create`. Plugin validation and registered action authorization run before the handler; the handler receives a transaction and verified principal. Use the SDK's `$request` for plugin routes. Trusted plugins must not bypass scope checks by accessing another collection/tenant arbitrarily.

The `@better-iam/projects` package is a complete reference plugin built on these contracts. Registering `createProjectsPlugin()` adds the `projects:read` and `projects:write` actions and mounts `create`, `list`, `get`, `update`, `archive`, and `restore` endpoints for tenant-scoped project records; its purge callback removes a purged tenant's project records in the same transaction as the tenant purge.

Plugin migrations should be idempotent and use the provided transaction. Version migration records explicitly in the plugin's namespace. `afterAudit` executes from the audit dispatcher after commit and must tolerate at-least-once invocation. `purge` runs inside the tenant purge transaction before the server deletes the purged tenants' own records. Plugins cannot register reserved `iam:` or tenant action namespaces.
