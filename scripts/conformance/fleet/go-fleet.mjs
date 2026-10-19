#!/usr/bin/env node
// Mixed-fleet check for the Go port, TypeScript side: one SQLite (or libSQL) database file shared by the TypeScript
// adapter and a Go adapter. The Go tests (go/adapters/internal/fleettest, run from go/adapters/sqlite and
// go/adapters/libsql) drive it:
//
//   node scripts/conformance/fleet/go-fleet.mjs create <file> [sqlite|libsql]   write the TypeScript fixture
//   node scripts/conformance/fleet/go-fleet.mjs check  <file> [sqlite|libsql]   read what Go wrote, then add more
//
// Each command prints one JSON object on stdout: the store snapshot (exportStore lines, the header without its
// createdAt), the audit chain verification of every tenant, and the results of a few pushed-down queries, so the Go
// side can compare them with its own reading byte for byte. `check` also reports the snapshot from before its writes.
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const load = (pkg) => import(pathToFileURL(join(root, 'packages', pkg, 'dist', 'index.js')).href);
const core = await load('core');

const [command, file, kind = 'sqlite'] = process.argv.slice(2);
if (!command || !file) {
  console.error('usage: go-fleet.mjs create|check <file> [sqlite|libsql]');
  process.exit(2);
}

async function openStore() {
  if (kind === 'libsql') {
    const { libsqlAdapter } = await load('adapter-libsql');
    return libsqlAdapter({ url: `file:${file}` });
  }
  const { sqliteAdapter } = await load('adapter-sqlite');
  return sqliteAdapter({ filename: file });
}

const NOW = 1767225600000;
const event = (tenantId, n, extra = {}) => ({
  id: `evt_ts_${tenantId}_${n}`,
  tenantId,
  actorId: 'idn_ts',
  action: 'iam:groups:create',
  resourceId: `grp_${n}`,
  outcome: 'allow',
  rootOverride: false,
  timestamp: NOW + n,
  ...extra,
});

/** Records exercising every serialization rule a port must share with JSON.stringify. */
function fixture() {
  return {
    tenants: [
      { id: 'tnt_a', tenantId: 'tnt_a', name: 'A', type: 'org', parentId: null, status: 'active', createdAt: NOW },
      {
        id: 'tnt_b',
        tenantId: 'tnt_b',
        name: 'B ü \u{1F600}',
        type: 'org',
        parentId: 'tnt_a',
        status: 'active',
        createdAt: NOW,
        slug: 'b',
        uniqueKey: 'slug:b',
      },
    ],
    identities: [
      {
        id: 'idn_ts',
        tenantId: 'tnt_a',
        kind: 'user',
        email: 'ada@example.com',
        uniqueKey: 'ada@example.com',
        name: 'Ada "quoted" \\ back\nline',
        status: 'active',
        emailVerified: true,
        rootAdmin: false,
        owner: true,
        createdAt: NOW,
        attributes: { 10: 'ten', 2: 'two', team: 'eng', level: 3, '': 'empty key' },
      },
    ],
    oddities: [
      {
        id: 'odd_1',
        tenantId: 'tnt_a',
        lone: 'x\ud800y',
        nul: 'a\u0000b',
        separators: '  ',
        control: '\u0001\u001f\u007f',
        html: '<script>&amp;</script>',
        numbers: [0, -0, 1e21, 1e-7, 0.1 + 0.2, 2 ** 53 + 2, 5e-324, 1.7976931348623157e308, -1.5, 123456789012345680000],
        nested: { deep: { list: [true, false, null, { k: 'v' }] } },
        timestamp: 5,
      },
    ],
  };
}

async function snapshot(store) {
  const lines = [];
  await core.exportStore(store, (line) => lines.push(line));
  const header = JSON.parse(lines[0]);
  delete header.createdAt;
  lines[0] = JSON.stringify(header);
  return lines;
}

async function chains(store) {
  const out = {};
  for (const tenantId of ['tnt_a', 'tnt_b']) {
    const events = await store.find('audit', { tenantId });
    const head = await store.get('auditChains', tenantId);
    out[tenantId] = await core.verifyAuditChain(
      events,
      head ? { head: { sequence: head.sequence, hash: head.hash } } : {},
    );
  }
  return out;
}

async function queries(store) {
  const ids = (records) => records.map((record) => record.id);
  return {
    byEmail: ids(await store.find('identities', { email: 'go@example.com' })),
    byNumber: ids(await store.find('oddities', { timestamp: 5 })),
    byLargeNumber: ids(await store.find('oddities', { big: 2 ** 60 })),
    byBoolean: ids(await store.find('identities', { owner: true })),
    byLone: ids(await store.find('oddities', { lone: 'x\ud800y' })),
    ordered: ids(
      await core.findOrdered(store, 'audit', { tenantId: 'tnt_a' }, { field: 'sequence', direction: 'desc' }),
    ),
    goRecord: (await store.get('fromGo', 'go_1')) ?? null,
  };
}

const store = await openStore();
let before;
try {
  if (command === 'create') {
    await store.migrate();
    const records = fixture();
    await store.transaction(async (tx) => {
      for (const [collection, list] of Object.entries(records))
        for (const record of list) await tx.insert(collection, record);
      for (let n = 1; n <= 3; n++) await core.appendAuditEvent(tx, event('tnt_a', n));
      await core.appendAuditEvent(
        tx,
        event('tnt_b', 1, { metadata: { z: 1, a: [2, 1], name: 'Ünïcödé \u{1F600}' } }),
      );
    });
  } else if (command === 'check') {
    before = await snapshot(store);
    // Write after Go: the chain continues from Go's head, and a record Go wrote is replaced.
    await store.transaction(async (tx) => {
      await core.appendAuditEvent(tx, event('tnt_a', 100, { metadata: { after: 'go' } }));
      const fromGo = await tx.get('fromGo', 'go_1');
      if (fromGo) await tx.put('fromGo', { ...fromGo, touchedByTs: true });
    });
  } else throw new Error(`unknown command ${command}`);
  const output = {
    before,
    snapshot: await snapshot(store),
    chains: await chains(store),
    queries: await queries(store),
  };
  process.stdout.write(`${JSON.stringify(output)}\n`);
} finally {
  await store.close();
}
