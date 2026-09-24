import { afterEach, describe, expect, it } from 'vitest';
import { verifyAuditChain, type AuditEvent } from '@better-iam/core';
import { closeFixtures, organizationFixture } from './support/organization';

afterEach(closeFixtures);

const byId = (events: AuditEvent[]) => events.map((event) => event.id);

describe('audit.verify covers the whole stored chain', () => {
  it('fails when every event of the tenant was deleted', async () => {
    const f = await organizationFixture();
    const events = await f.database.find<AuditEvent>('audit', { tenantId: f.tenantId });
    expect(events.length).toBeGreaterThan(0);
    await f.database.transaction(async (tx) => {
      for (const id of byId(events)) await tx.delete('audit', id);
    });
    const verified = await f.iam.api.audit.verify(f.rootCredential, { tenantId: f.tenantId });
    expect(verified).toMatchObject({ valid: false, failure: { reason: 'head-mismatch' } });
  });

  it('fails when the oldest events were deleted without a pruning checkpoint', async () => {
    const f = await organizationFixture();
    const events = (await f.database.find<AuditEvent>('audit', { tenantId: f.tenantId })).sort(
      (a, b) => a.sequence! - b.sequence!,
    );
    await f.database.transaction(async (tx) => {
      for (const event of events.slice(0, 2)) await tx.delete('audit', event.id);
    });
    const verified = await f.iam.api.audit.verify(f.ownerCredential, { tenantId: f.tenantId });
    expect(verified).toMatchObject({
      valid: false,
      failure: { reason: 'missing-prefix', sequence: 3 },
    });
  });

  it('still verifies after a legitimate prune, which records its checkpoint', async () => {
    const f = await organizationFixture();
    await new Promise((resolve) => setTimeout(resolve, 5));
    const pruned = await f.iam.pruneAudit({ tenantId: f.tenantId, retentionMs: 0 });
    expect(pruned.deleted).toBeGreaterThan(0);
    const verified = await f.iam.api.audit.verify(f.ownerCredential, { tenantId: f.tenantId });
    expect(verified).toMatchObject({ valid: true });
    expect(verified.first).toBe(pruned.prunedThroughSequence! + 1);
  });

  it('fails on an event inserted without chain fields, and does not fold it in on restart', async () => {
    const f = await organizationFixture();
    const forged: AuditEvent = {
      id: 'forged-event',
      tenantId: f.tenantId,
      actorId: f.ownerId,
      action: 'identity:delete',
      resourceId: 'someone',
      timestamp: 1,
      outcome: 'allow',
    };
    await f.database.transaction((tx) => tx.insert('audit', forged));
    const verify = () => f.iam.api.audit.verify(f.ownerCredential, { tenantId: f.tenantId });
    expect(await verify()).toMatchObject({
      valid: false,
      failure: { reason: 'unchained', id: 'forged-event' },
    });
    await f.iam.initialize();
    expect((await f.database.get<AuditEvent>('audit', 'forged-event'))?.sequence).toBeUndefined();
    expect((await verify()).valid).toBe(false);
  });

  it('keeps verifying runs of events (exports) without a head as before', async () => {
    const f = await organizationFixture();
    const events = (await f.database.find<AuditEvent>('audit', { tenantId: f.tenantId })).sort(
      (a, b) => a.sequence! - b.sequence!,
    );
    const tail = events.slice(2);
    expect(await verifyAuditChain(tail)).toMatchObject({ valid: true, first: 3 });
    expect(
      await verifyAuditChain([...tail, { ...tail[0]!, id: 'loose', sequence: undefined }]),
    ).toMatchObject({ valid: true, unchained: 1 });
  });
});
