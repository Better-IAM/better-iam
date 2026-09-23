/**
 * Scale benchmark: one large organization, then the hot paths measured with store instrumentation.
 * `BENCH_IDENTITIES` (default 5000) sets the size; results print as a table and are written to
 * `work/bench-scale.json` so rounds can be compared. Run with `pnpm bench:scale`.
 */
import { randomUUID } from 'node:crypto';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, it } from 'vitest';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import {
  instrumentStore,
  summarizeStoreCalls,
  type IamStore,
  type StoreCall,
} from '@better-iam/core';
import { closeFixtures, organizationFixture } from '../support/organization.js';

const identities = Number(process.env.BENCH_IDENTITIES ?? 5000);
const iterations = Number(process.env.BENCH_ITERATIONS ?? 40);
let directory: string;
let raw: IamStore | undefined;
afterAll(async () => {
  await closeFixtures();
  // The fixture closes only its own store; the file database must close before its folder goes.
  await raw?.close();
  if (directory) await rm(directory, { recursive: true, force: true, maxRetries: 5 });
});

interface Measurement {
  operation: string;
  meanMs: number;
  p95Ms: number;
  storeCalls: number;
  recordsRead: number;
  heaviest: string;
}

describe('scale benchmark', () => {
  it(`measures hot paths with ${identities} identities`, async () => {
    directory = await mkdtemp(join(tmpdir(), 'better-iam-bench-'));
    const calls: StoreCall[] = [];
    let recording = false;
    raw = sqliteAdapter({ filename: join(directory, 'bench.sqlite') });
    const database: IamStore = instrumentStore(raw, (call) => {
      if (recording) calls.push(call);
    });
    const f = await organizationFixture({ database });
    const { iam, tenantId, ownerCredential } = f;
    const owner = await f.ownerSignIn();

    // --- seed ----------------------------------------------------------------------------
    const seedStarted = performance.now();
    const roles = [];
    for (let index = 0; index < 20; index++)
      roles.push(
        await iam.api.roles.create(owner, {
          tenantId,
          name: `Role ${index}`,
          document: {
            version: 1,
            statements: [
              {
                effect: 'allow',
                actions: [index % 2 ? 'documents:write' : 'documents:read'],
                resources: [`document/${index}-*`, 'document/shared-*'],
              },
            ],
          },
        }),
      );
    const template = await iam.api.bindings.create(owner, {
      tenantId,
      roleId: roles[0]!.id,
      subjectType: 'identity',
      subjectId: f.ownerId,
    });
    const groups = Math.max(10, Math.floor(identities / 25));
    const people: string[] = [];
    const tokens: string[] = [];
    const batch = 250;
    for (let start = 0; start < identities; start += batch)
      await database.transaction(async (tx) => {
        for (let index = start; index < Math.min(identities, start + batch); index++) {
          const person = await iam.auth.createIdentity(tx, {
            tenantId,
            email: `person${index}@acme.test`,
            name: `Person ${index}`,
            emailVerified: true,
          });
          people.push(person.id);
          const role = roles[index % roles.length]!;
          await tx.insert('bindings', {
            ...template,
            id: randomUUID(),
            subjectId: person.id,
            roleId: role.id,
            uniqueKey: `identity:${person.id}:${role.id}:${template.authorityId}`,
          });
          for (const offset of [0, 7])
            await tx.insert('groupMembers', {
              id: randomUUID(),
              tenantId,
              groupId: `group-${(index + offset) % groups}`,
              identityId: person.id,
              uniqueKey: `group-${(index + offset) % groups}:${person.id}`,
            });
          if (index % 5 === 0) tokens.push((await iam.auth.issueSession(tx, person)).token);
        }
      });
    await database.transaction(async (tx) => {
      for (let index = 0; index < groups; index++) {
        await tx.insert('groups', { id: `group-${index}`, tenantId, name: `Group ${index}` });
        const role = roles[(index * 3) % roles.length]!;
        await tx.insert('bindings', {
          ...template,
          id: randomUUID(),
          subjectType: 'group',
          subjectId: `group-${index}`,
          roleId: role.id,
          uniqueKey: `group:group-${index}:${role.id}:${template.authorityId}`,
        });
      }
    });
    const seedSeconds = (performance.now() - seedStarted) / 1000;

    // --- measure -------------------------------------------------------------------------
    const results: Measurement[] = [];
    const measure = async (operation: string, run: (index: number) => Promise<unknown>) => {
      await run(0); // warm up statement caches and JIT
      const durations: number[] = [];
      calls.length = 0;
      recording = true;
      for (let index = 1; index <= iterations; index++) {
        const started = performance.now();
        await run(index);
        durations.push(performance.now() - started);
      }
      recording = false;
      durations.sort((a, b) => a - b);
      const summary = Object.entries(summarizeStoreCalls(calls)).sort(
        (a, b) => b[1].records - a[1].records,
      );
      results.push({
        operation,
        meanMs: durations.reduce((sum, value) => sum + value, 0) / durations.length,
        p95Ms: durations[Math.floor(durations.length * 0.95) - 1] ?? durations.at(-1)!,
        storeCalls: calls.length / iterations,
        recordsRead:
          calls
            .filter((call) => ['find', 'findOrdered', 'get'].includes(call.method))
            .reduce((sum, call) => sum + call.records, 0) / iterations,
        heaviest: summary
          .slice(0, 3)
          .map(
            ([key, value]) =>
              `${key} x${(value.calls / iterations).toFixed(1)} -> ${Math.round(value.records / iterations)}`,
          )
          .join(' '),
      });
    };
    const pick = <T>(items: T[], index: number) => items[(index * 7919) % items.length]!;
    await measure('authenticate (bearer)', (i) => iam.authenticate({ token: pick(tokens, i) }));
    await measure('auth.getSession', (i) => iam.api.auth.getSession({ token: pick(tokens, i) }));
    await measure('authorize (allowed)', (i) => {
      const index = (i * 7919) % tokens.length;
      return iam.authorize({
        token: tokens[index]!,
        tenantId,
        action: 'documents:read',
        resource: { type: 'document', id: 'shared-1' },
      });
    });
    await measure('authorize (denied)', (i) =>
      iam.authorize({
        token: pick(tokens, i),
        tenantId,
        action: 'documents:write',
        resource: { type: 'document', id: 'private-1' },
      }),
    );
    await measure('identities.list (50)', () =>
      iam.api.identities.list(ownerCredential, { tenantId, limit: 50 }),
    );
    await measure('identities.list (query)', (i) =>
      iam.api.identities.list(ownerCredential, { tenantId, query: `person${i}@`, limit: 20 }),
    );
    await measure('audit.list (50)', () =>
      iam.api.audit.list(ownerCredential, { tenantId, limit: 50 }),
    );
    await measure('groups.listMembers', (i) =>
      iam.api.groups.listMembers(ownerCredential, { tenantId, groupId: `group-${i % groups}` }),
    );
    await measure('bindings.list', () => iam.api.bindings.list(ownerCredential, { tenantId }));
    await measure('identities.listBindings', (i) =>
      iam.api.identities.listBindings(ownerCredential, {
        tenantId,
        identityId: pick(people, i),
      }),
    );

    // --- report --------------------------------------------------------------------------
    const lines = results.map(
      (r) =>
        `${r.operation.padEnd(30)} ${r.meanMs.toFixed(2).padStart(9)} ms  p95 ${r.p95Ms.toFixed(2).padStart(9)} ms  ${r.storeCalls.toFixed(1).padStart(6)} calls  ${Math.round(r.recordsRead).toString().padStart(7)} records  ${r.heaviest}`,
    );
    console.log(
      [
        `Scale benchmark: ${identities} identities, ${groups} groups, ${tokens.length} sessions (seeded in ${seedSeconds.toFixed(1)} s)`,
        ...lines,
      ].join('\n'),
    );
    await mkdir(join(process.cwd(), 'work'), { recursive: true });
    await writeFile(
      join(process.cwd(), 'work', 'bench-scale.json'),
      JSON.stringify({ identities, groups, iterations, results }, null, 2),
    );
  });
});
