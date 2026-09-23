import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam, verifyAuditChain } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import {
  appendAuditEvent,
  auditEventHash,
  auditGenesis,
  canonicalJson,
  type AuditChainHead,
  type AuditEvent,
  type IamStore,
} from '@better-iam/core';
import type { DeliveryMessage } from '@better-iam/auth';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

function build(database: IamStore, inbox: DeliveryMessage[]) {
  return betterIam({
    database,
    secret: 'audit-chain-test-secret-with-at-least-32-chars',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
    },
    permissions: { actions: ['documents:read'] },
    resolveResource: async (reference) => reference,
  });
}

async function fixture() {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  const iam = build(database, inbox);
  await iam.initialize();
  const root = await iam.bootstrap({
    email: 'root@example.test',
    name: 'Root',
    password: 'a strong root test password',
  });
  const challenge = await iam.api.auth.signIn({
    tenantId: root.tenant.id,
    email: 'root@example.test',
    password: 'a strong root test password',
  });
  if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
  const enrollment = await iam.api.auth.beginMfa({
    tenantId: root.tenant.id,
    challenge: challenge.challenge,
  });
  const session = await iam.api.auth.confirmMfa({
    credential: { tenantId: root.tenant.id, challenge: challenge.challenge },
    code: authenticator.generate(enrollment.secret),
  });
  const credential = { token: session.token };
  const created = await iam.api.tenants.create(credential, {
    parentId: root.tenant.id,
    name: 'Acme',
    type: 'organization',
    ownerEmail: 'owner@acme.test',
  });
  await iam.auth.dispatchOutbox();
  const invitation = inbox.find(
    (message) => message.tenantId === created.tenant.id && message.template === 'owner-invitation',
  )!;
  const owner = await iam.api.tenants.acceptInvitation({
    tenantId: created.tenant.id,
    token: invitation.payload.token!,
    name: 'Owner',
    password: 'a strong tenant owner password',
  });
  if (!('token' in owner)) throw new Error('Unexpected owner MFA');
  return {
    iam,
    database,
    inbox,
    root,
    credential,
    tenantId: created.tenant.id,
    ownerCredential: { token: owner.token },
  };
}

describe('audit hash chain', () => {
  it('chains every audit writer per tenant, verifies, exports, and detects tampering', async () => {
    const f = await fixture();
    // Provisioning, authentication, and denial events all land on the chain.
    const group = await f.iam.api.groups.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Team',
    });
    await f.iam.api.groups.update(f.ownerCredential, {
      tenantId: f.tenantId,
      groupId: group.id,
      name: 'Team A',
    });
    const alice = await f.iam.api.identities.create(f.ownerCredential, {
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      name: 'Alice',
      password: 'a strong alice password',
    });
    const login = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      password: 'a strong alice password',
    });
    if (!('token' in login)) throw new Error('Unexpected MFA');
    await expect(
      f.iam.api.groups.delete({ token: login.token }, { tenantId: f.tenantId, groupId: group.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const events = (await f.database.find<AuditEvent>('audit', { tenantId: f.tenantId })).sort(
      (a, b) => a.sequence! - b.sequence!,
    );
    expect(events.length).toBeGreaterThan(5);
    expect(events.map((event) => event.sequence)).toEqual(events.map((_e, index) => index + 1));
    expect(events[0]!.previousHash).toBe(auditGenesis);
    for (let index = 1; index < events.length; index++)
      expect(events[index]!.previousHash).toBe(events[index - 1]!.hash);
    expect(events.map((event) => event.action)).toEqual(
      expect.arrayContaining([
        'iam:groups:create',
        'auth:identity:create',
        'auth:session:create',
        'iam:groups:delete',
      ]),
    );
    expect(events.find((event) => event.action === 'iam:groups:delete')!.outcome).toBe('deny');
    const head = (await f.database.get<AuditChainHead>('auditChains', f.tenantId))!;
    expect(head).toMatchObject({ sequence: events.length, hash: events.at(-1)!.hash });
    // Root events form their own chain; the tenant's chain is independent of it.
    const rootEvents = await f.database.find<AuditEvent>('audit', { tenantId: f.root.tenant.id });
    expect(rootEvents.every((event) => typeof event.sequence === 'number')).toBe(true);
    expect(rootEvents.find((event) => event.sequence === 1)).toMatchObject({
      action: 'auth:identity:create',
      previousHash: auditGenesis,
    });
    expect(rootEvents.find((event) => event.action === 'root:bootstrap')).toMatchObject({
      sequence: 2,
      previousHash: rootEvents.find((event) => event.sequence === 1)!.hash,
    });
    // Server-side verification, windows, and export.
    const verified = await f.iam.api.audit.verify(f.ownerCredential, { tenantId: f.tenantId });
    expect(verified).toMatchObject({
      valid: true,
      checked: events.length,
      unchained: 0,
      first: 1,
      last: events.length,
      lastHash: events.at(-1)!.hash,
      head: { sequence: events.length, hash: events.at(-1)!.hash },
    });
    const window = await f.iam.api.audit.verify(f.ownerCredential, {
      tenantId: f.tenantId,
      fromSequence: 3,
      toSequence: 5,
    });
    expect(window).toMatchObject({ valid: true, checked: 3, first: 3, last: 5 });
    const exported = await f.iam.api.audit.export(f.ownerCredential, {
      tenantId: f.tenantId,
      limit: 4,
    });
    expect(exported).toMatchObject({
      format: 'jsonl',
      count: 4,
      firstSequence: 1,
      lastSequence: 4,
      nextSequence: 5,
    });
    const lines = exported.body.split('\n').map((line) => JSON.parse(line) as AuditEvent);
    expect(lines.map((event) => event.sequence)).toEqual([1, 2, 3, 4]);
    // An archive verifies offline, and the next page links to it through previousHash.
    expect(await verifyAuditChain(lines)).toMatchObject({ valid: true, checked: 4 });
    const rest = await f.iam.api.audit.export(f.ownerCredential, {
      tenantId: f.tenantId,
      fromSequence: exported.nextSequence,
    });
    const restLines = rest.body.split('\n').map((line) => JSON.parse(line) as AuditEvent);
    expect(rest.nextSequence).toBeUndefined();
    // The verify and export reads above were audited too, so the second page is longer than the snapshot.
    expect(restLines.length).toBeGreaterThan(events.length - 4);
    expect(await verifyAuditChain(restLines, { previousHash: lines.at(-1)!.hash })).toMatchObject({
      valid: true,
      checked: restLines.length,
      first: 5,
      last: rest.lastSequence,
    });
    expect(
      (await verifyAuditChain(restLines, { previousHash: 'f'.repeat(64) })).failure,
    ).toMatchObject({ sequence: 5, reason: 'previous-hash-mismatch' });
    expect((await verifyAuditChain([...lines, ...restLines.slice(1)])).failure).toMatchObject({
      sequence: 6,
      reason: 'sequence-gap',
    });
    // Tampering with a stored event is detected; so is a rewritten head.
    const target = events[2]!;
    await f.database.transaction((tx) =>
      tx.put('audit', { ...target, outcome: target.outcome === 'deny' ? 'allow' : 'deny' }),
    );
    expect(await f.iam.api.audit.verify(f.ownerCredential, { tenantId: f.tenantId })).toMatchObject(
      { valid: false, failure: { sequence: 3, id: target.id, reason: 'hash-mismatch' } },
    );
    await f.database.transaction((tx) => tx.put('audit', target));
    await f.database.transaction((tx) => tx.put('auditChains', { ...head, hash: 'a'.repeat(64) }));
    const broken = await f.iam.api.audit.verify(f.ownerCredential, { tenantId: f.tenantId });
    expect(broken.valid).toBe(false);
    expect(broken.failure?.reason).toBe('head-mismatch');
    await f.database.transaction((tx) => tx.put('auditChains', head));
    // Audit reads need iam:audit:read.
    await expect(
      f.iam.api.audit.export({ token: login.token }, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(alice.id).toBeTruthy();
  });

  it('hashes canonically and backfills unchained events at initialization', async () => {
    expect(canonicalJson({ b: [3, { z: 1, y: undefined }], a: 'x' })).toBe(
      '{"a":"x","b":[3,{"z":1}]}',
    );
    const event: AuditEvent = {
      id: 'e1',
      tenantId: 't1',
      actorId: 'a',
      action: 'x:y',
      resourceId: 'r',
      timestamp: 1,
      outcome: 'allow',
      sequence: 1,
      previousHash: auditGenesis,
    };
    expect(await auditEventHash(event)).toBe(await auditEventHash({ ...event, hash: 'ignored' }));
    expect(await auditEventHash(event)).not.toBe(await auditEventHash({ ...event, timestamp: 2 }));
    // Legacy events inserted before the chain existed get chained in timestamp order on initialize.
    const database = sqliteAdapter({ filename: ':memory:' });
    databases.push(database);
    await database.migrate();
    await database.transaction(async (tx) => {
      for (const [id, timestamp] of [
        ['legacy-b', 20],
        ['legacy-a', 10],
      ] as const)
        await tx.insert('audit', {
          ...event,
          id,
          tenantId: 'legacy',
          timestamp,
          sequence: undefined,
          previousHash: undefined,
        });
      await appendAuditEvent(tx, { ...event, id: 'chained-1', tenantId: 'other' });
    });
    const iam = build(database, []);
    await iam.initialize();
    const legacy = (await database.find<AuditEvent>('audit', { tenantId: 'legacy' })).sort(
      (a, b) => a.sequence! - b.sequence!,
    );
    expect(legacy.map((item) => [item.id, item.sequence])).toEqual([
      ['legacy-a', 1],
      ['legacy-b', 2],
    ]);
    expect(await verifyAuditChain(legacy)).toMatchObject({ valid: true, checked: 2 });
    expect(await database.get<AuditChainHead>('auditChains', 'legacy')).toMatchObject({
      sequence: 2,
      hash: legacy[1]!.hash,
    });
    expect(await database.get<AuditChainHead>('auditChains', 'other')).toMatchObject({
      sequence: 1,
    });
    // Initializing again is a no-op for chained events.
    await iam.initialize();
    expect(await database.get<AuditChainHead>('auditChains', 'legacy')).toMatchObject({
      sequence: 2,
    });
  });
});
