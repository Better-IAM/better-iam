import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent } from '@better-iam/core';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

describe('network blocks', () => {
  it('lets root block a network platform-wide: sign-ins, counters, and live sessions from it stop until lifted or lapsed', async () => {
    const f = await organizationFixture();
    const from = <T>(ip: string, fn: () => Promise<T>) =>
      f.iam.auth.withClient({ ip, userAgent: 'test' }, fn);
    const alice = await f.member('alice');
    const early = await from('198.51.100.9', () => f.signIn('alice'));
    const rootTenant = f.root.tenant.id;
    const block = await f.iam.api.security.blockNetwork(f.rootCredential, {
      tenantId: rootTenant,
      network: '198.51.100.0/24',
      reason: 'credential stuffing',
      durationMs: 3_600_000,
      platform: true,
    });
    expect(block).toMatchObject({
      network: '198.51.100.0/24',
      platform: true,
      expiresAt: f.now() + 3_600_000,
      active: true,
    });
    // Refused before any credential or counter is examined, in every tenant and flow.
    await expect(from('198.51.100.9', () => f.signIn('alice'))).rejects.toMatchObject({
      code: 'IP_BLOCKED',
      status: 403,
    });
    await expect(
      from('198.51.100.200', () =>
        f.iam.api.auth.requestPasswordReset({ tenantId: f.tenantId, email: 'alice@acme.test' }),
      ),
    ).rejects.toMatchObject({ code: 'IP_BLOCKED' });
    await expect(
      from('198.51.100.200', () =>
        f.iam.api.auth.signIn({
          tenantId: rootTenant,
          email: 'root@example.test',
          password: 'a strong root test password',
        }),
      ),
    ).rejects.toMatchObject({ code: 'IP_BLOCKED' });
    const failures = (await f.iam.store.find<AuditEvent>('audit', { tenantId: f.tenantId })).filter(
      (event) => event.action === 'auth:signin:fail' && event.actorId === alice.id,
    );
    expect(failures).toHaveLength(0);
    // The session established from that network before the block stops working; others are untouched.
    await expect(f.iam.api.auth.getSession({ token: early.token })).rejects.toMatchObject({
      code: 'IP_BLOCKED',
    });
    const elsewhere = await from('203.0.113.7', () => f.signIn('alice'));
    expect('token' in elsewhere).toBe(true);
    // Root sees the block on the root tenant; an organization sees only its own.
    expect(
      await f.iam.api.security.listBlocks(f.rootCredential, { tenantId: rootTenant }),
    ).toMatchObject([{ id: block.id, active: true, reason: 'credential stuffing' }]);
    expect(
      await f.iam.api.security.listBlocks(f.ownerCredential, { tenantId: f.tenantId }),
    ).toEqual([]);
    // Lifting it restores the network at once.
    await f.iam.api.security.unblockNetwork(f.rootCredential, {
      tenantId: rootTenant,
      blockId: block.id,
    });
    expect('token' in (await from('198.51.100.9', () => f.signIn('alice')))).toBe(true);
    // A timed block lapses by itself.
    const short = await f.iam.api.security.blockNetwork(f.rootCredential, {
      tenantId: rootTenant,
      network: '198.51.100.9',
      reason: 'one minute',
      durationMs: 60_000,
      platform: true,
    });
    await expect(from('198.51.100.9', () => f.signIn('alice'))).rejects.toMatchObject({
      code: 'IP_BLOCKED',
    });
    f.advance(61_000);
    expect('token' in (await from('198.51.100.9', () => f.signIn('alice')))).toBe(true);
    expect(
      await f.iam.api.security.listBlocks(f.rootCredential, { tenantId: rootTenant }),
    ).toMatchObject([{ id: short.id, active: false }]);
    // Everything was audited with the network named.
    const events = (await f.iam.store.find<AuditEvent>('audit', { tenantId: rootTenant }))
      .filter((event) => event.action.startsWith('security:network-'))
      .map((event) => [event.action, event.metadata?.network]);
    expect(events).toEqual(
      expect.arrayContaining([
        ['security:network-block', '198.51.100.0/24'],
        ['security:network-unblock', '198.51.100.0/24'],
        ['security:network-block', '198.51.100.9'],
      ]),
    );
  });

  it('lets an organization block networks for itself only and validates the request', async () => {
    const f = await organizationFixture();
    const from = <T>(ip: string, fn: () => Promise<T>) =>
      f.iam.auth.withClient({ ip, userAgent: 'test' }, fn);
    await f.member('alice');
    const owner = await from('10.0.0.5', () => f.ownerSignIn());
    const block = await f.iam.api.security.blockNetwork(owner, {
      tenantId: f.tenantId,
      network: '192.0.2.0/24',
      reason: 'scanner',
    });
    expect(block).toMatchObject({ network: '192.0.2.0/24', active: true });
    expect(block.platform).toBeUndefined();
    expect(block.expiresAt).toBeUndefined();
    await expect(from('192.0.2.5', () => f.signIn('alice'))).rejects.toMatchObject({
      code: 'IP_BLOCKED',
    });
    // The block is the organization's: the root tenant still accepts that network.
    const rootAttempt = await from('192.0.2.5', () =>
      f.iam.api.auth.signIn({
        tenantId: f.root.tenant.id,
        email: 'root@example.test',
        password: 'a strong root test password',
      }),
    );
    expect('mfaRequired' in rootAttempt).toBe(true);
    // Renewing the same network updates the record instead of adding one.
    const renewed = await f.iam.api.security.blockNetwork(owner, {
      tenantId: f.tenantId,
      network: '192.0.2.0/24',
      reason: 'scanner, again',
      durationMs: 120_000,
    });
    expect(renewed.id).toBe(block.id);
    expect(await f.iam.api.security.listBlocks(owner, { tenantId: f.tenantId })).toHaveLength(1);
    // Validation: platform blocks are root's, networks must parse, and the caller cannot block themselves.
    await expect(
      f.iam.api.security.blockNetwork(owner, {
        tenantId: f.tenantId,
        network: '203.0.113.0/24',
        reason: 'x',
        platform: true,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.security.blockNetwork(owner, {
        tenantId: f.tenantId,
        network: 'not-a-network',
        reason: 'x',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.security.blockNetwork(owner, {
        tenantId: f.tenantId,
        network: '10.0.0.0/8',
        reason: 'would lock me out',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT', message: expect.stringContaining('own') });
    await expect(
      f.iam.api.security.blockNetwork(owner, {
        tenantId: f.tenantId,
        network: '203.0.113.1',
        reason: 'x',
        durationMs: 1_000,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // A member without the permission can neither read nor manage blocks.
    const alice = await from('203.0.113.9', () => f.signIn('alice'));
    await expect(
      f.iam.api.security.listBlocks({ token: alice.token }, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });
});
