// Mixed-fleet check for SQLite (and libSQL local files with FLEET_ADAPTER=libsql): the TypeScript adapter writes and
// verifies a database file that the Rust (and Go) adapters also read and write. Used by crates/adapter-sqlite and
// crates/adapter-libsql tests/fleet.rs; runnable by hand:
//
//   node scripts/conformance/fleet/sqlite-fleet.mjs write  <file> <prefix>     writes records and audit events
//   node scripts/conformance/fleet/sqlite-fleet.mjs verify <file> <expected>   checks another writer's records
//
// Every command prints one JSON object on stdout. Run it with the Node version better-sqlite3 was built for.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { libsqlAdapter } from '../../../packages/adapter-libsql/dist/index.js';
import { sqliteAdapter } from '../../../packages/adapter-sqlite/dist/index.js';
import {
  appendAuditEvent,
  findOrdered,
  verifyAuditChain,
} from '../../../packages/core/dist/index.js';

const require = createRequire(
  new URL('../../../packages/adapter-sqlite/package.json', import.meta.url),
);
const Database = require('better-sqlite3');

const TENANT = 'fleet-tenant';

/** FLEET_ADAPTER=libsql runs the same checks through the TypeScript libSQL adapter (local file mode). */
const open = (file) =>
  process.env.FLEET_ADAPTER === 'libsql'
    ? libsqlAdapter({ url: pathToFileURL(file).href })
    : sqliteAdapter({ filename: file });

/** Records with the values most likely to differ between implementations' JSON encoders. */
export function fleetRecords(prefix) {
  return [
    {
      id: `${prefix}-plain`,
      tenantId: TENANT,
      uniqueKey: `${prefix}@example.com`,
      name: 'Ada',
      tokenHash: `${prefix}-hash`,
      createdAt: 1767225600000,
    },
    {
      id: `${prefix}-numbers`,
      tenantId: TENANT,
      sum: 0.1 + 0.2,
      large: 2 ** 60,
      exponent: 1e21,
      tiny: 5e-324,
      negative: -1.5,
      max: Number.MAX_VALUE,
      expiresAt: 1767225600000 + 3600000,
    },
    {
      id: `${prefix}-unicode-é😀`,
      tenantId: TENANT,
      text: 'é 😀 中文    "quoted" \x5c back',
      nested: { list: [1, 'two', true, null, { deep: [] }], 2: 'index key', 10: 'ten', b: 1, a: 2 },
      nul: 'a\u0000b',
    },
  ];
}

function event(id, sequenceHint) {
  return {
    id,
    tenantId: TENANT,
    actorId: 'idn_fleet',
    action: 'iam:groups:create',
    resourceId: `grp_${sequenceHint}`,
    timestamp: 1767225600000 + sequenceHint,
    outcome: 'allow',
    rootOverride: false,
    metadata: { writer: 'typescript', n: sequenceHint },
  };
}

async function write(file, prefix) {
  const store = open(file);
  await store.migrate();
  const records = fleetRecords(prefix);
  const events = await store.transaction(async (tx) => {
    for (const record of records) await tx.insert('fleet', record);
    const appended = [];
    for (let n = 1; n <= 3; n++)
      appended.push(await appendAuditEvent(tx, event(`${prefix}-evt-${n}`, n)));
    return appended;
  });
  await store.close();
  return { records, events };
}

async function verify(file, expectedPath) {
  const expected = JSON.parse(readFileSync(expectedPath, 'utf8'));
  const store = open(file);
  const problems = [];
  try {
    await store.migrate();
    for (const record of expected.records) {
      const read = await store.get('fleet', record.id);
      if (JSON.stringify(read) !== JSON.stringify(record))
        problems.push(
          `record ${record.id}: expected ${JSON.stringify(record)}, read ${JSON.stringify(read)}`,
        );
    }
    for (const id of expected.deleted ?? [])
      if (await store.get('fleet', id)) problems.push(`record ${id} should be deleted`);
    for (const [field, value, ids] of expected.lookups ?? []) {
      const found = (await store.find('fleet', { [field]: value })).map((record) => record.id);
      if (JSON.stringify(found) !== JSON.stringify(ids))
        problems.push(
          `find ${field}=${JSON.stringify(value)}: expected ${JSON.stringify(ids)}, got ${JSON.stringify(found)}`,
        );
    }
    const audit = await findOrdered(store, 'audit', { tenantId: TENANT }, { field: 'sequence' });
    const head = await store.get('auditChains', TENANT);
    const chain = await verifyAuditChain(audit, {
      head: head && { sequence: head.sequence, hash: head.hash },
    });
    if (!chain.valid) problems.push(`audit chain: ${JSON.stringify(chain)}`);
    if (audit.length !== expected.auditEvents)
      problems.push(`audit events: expected ${expected.auditEvents}, found ${audit.length}`);
  } finally {
    await store.close();
  }
  // The stored text must be exactly what JSON.stringify writes for the parsed record.
  const raw = new Database(file, { readonly: true });
  try {
    for (const row of raw.prepare('SELECT id, data FROM iam_records').all()) {
      const canonical = JSON.stringify(JSON.parse(row.data));
      if (canonical !== row.data)
        problems.push(`row ${row.id}: stored text is not JSON.stringify output`);
    }
  } finally {
    raw.close();
  }
  return { ok: problems.length === 0, problems };
}

const [command, file, argument] = process.argv.slice(2);
const result =
  command === 'write'
    ? await write(file, argument ?? 'ts')
    : command === 'verify'
      ? await verify(file, argument)
      : command === 'probe'
        ? { ok: typeof Database === 'function' }
        : { error: `unknown command ${command}` };
process.stdout.write(`${JSON.stringify(result)}\n`);
