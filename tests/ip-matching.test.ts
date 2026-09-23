import { afterEach, describe, expect, it } from 'vitest';
import {
  evaluatePolicy,
  ipCounterKey,
  ipMatches,
  type PolicyDocument,
  type Tenant,
} from '@better-iam/core';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

describe('IPv4-mapped IPv6 addresses', () => {
  it.each([
    ['::ffff:198.51.100.7', '198.51.100.0/24', true],
    ['::FFFF:c633:6407', '198.51.100.0/24', true],
    ['0:0:0:0:0:ffff:c633:6407', '198.51.100.7', true],
    ['::ffff:198.51.101.7', '198.51.100.0/24', false],
    ['198.51.100.7', '::ffff:198.51.100.0/120', true],
    ['198.51.100.7', '::ffff:198.51.100.7', true],
    ['198.51.100.7', '::ffff:0:0/96', true],
    ['198.51.101.7', '::ffff:198.51.100.0/120', false],
    // Unchanged: other IPv6 never matches IPv4, and plain IPv4 is not inside wider IPv6 blocks.
    ['2001:db8::c633:6407', '198.51.100.0/24', false],
    ['::198.51.100.7', '198.51.100.0/24', false],
    ['198.51.100.7', '::/0', false],
    ['198.51.100.7', '2001:db8::/32', false],
    ['::ffff:198.51.100.7', '::/0', true],
    ['::ffff:198.51.100.7', '::ffff:198.51.100.0/120', true],
  ])('%s in %s: %s', (address, network, expected) => {
    expect(ipMatches(address, network)).toBe(expected);
    // The policy operators share the matching.
    const grant: PolicyDocument = {
      version: 1,
      statements: [
        {
          effect: 'allow',
          actions: ['document:read'],
          resources: ['*'],
          conditions: { IpAddress: { ip: network } },
        },
      ],
    };
    expect(
      evaluatePolicy({
        action: 'document:read',
        resource: 'organization-a/document/1',
        grants: [grant],
        context: { ip: address },
      }).allowed,
    ).toBe(expected);
  });

  it('applies network blocks and allowlists to IPv4 clients reported in mapped form', async () => {
    const f = await organizationFixture();
    await f.member('alice');
    const from = <T>(ip: string, fn: () => Promise<T>) =>
      f.iam.auth.withClient({ ip, userAgent: 'test' }, fn);
    await f.iam.api.security.blockNetwork(f.rootCredential, {
      tenantId: f.root.tenant.id,
      network: '198.51.100.0/24',
      reason: 'credential stuffing',
      durationMs: 3_600_000,
      platform: true,
    });
    for (const ip of ['198.51.100.7', '::ffff:198.51.100.7', '::ffff:c633:6407'])
      await expect(from(ip, () => f.signIn('alice'))).rejects.toMatchObject({
        code: 'IP_BLOCKED',
      });
    await f.iam.store.transaction(async (tx) => {
      const tenant = (await tx.get<Tenant>('tenants', f.tenantId))!;
      await tx.put<Tenant>('tenants', {
        ...tenant,
        authPolicy: { ...tenant.authPolicy, allowedIpRanges: ['203.0.113.0/24'] },
      });
    });
    const office = await from('::ffff:203.0.113.9', () => f.signIn('alice'));
    expect(office.session.client?.ip).toBe('::ffff:203.0.113.9');
    expect((await f.iam.api.auth.getSession({ token: office.token })).identity.email).toBe(
      'alice@acme.test',
    );
    await expect(from('::ffff:192.0.2.9', () => f.signIn('alice'))).rejects.toMatchObject({
      code: 'IP_NOT_ALLOWED',
    });
  });
});

describe('per-address attempt counters', () => {
  it.each([
    ['198.51.100.7', '198.51.100.7'],
    ['::ffff:198.51.100.7', '198.51.100.7'],
    ['::FFFF:C633:6407', '198.51.100.7'],
    ['2001:db8:1:2::1', '2001:db8:1:2::/64'],
    ['2001:DB8:1:2:ffff:0:0:9', '2001:db8:1:2::/64'],
    ['2001:0db8:0001:0002:0000:0000:0000:0001', '2001:db8:1:2::/64'],
    ['2001:db8::1', '2001:db8:0:0::/64'],
    [' 2001:db8:1:2::1 ', '2001:db8:1:2::/64'],
    ['unknown', undefined],
    ['fe80::1%eth0', undefined],
  ])('keys %s as %s', (address, key) => {
    expect(ipCounterKey(address)).toBe(key);
  });

  it('counts an IPv6 /64 as one client, and an IPv4 client once however it is spelled', async () => {
    const f = await organizationFixture({ authentication: { rateLimits: { ipAttempts: 3 } } });
    const attempt = (ip: string, index: number) =>
      f.iam.auth.withClient({ ip }, () =>
        f.iam.api.auth.signIn({
          tenantId: f.tenantId,
          email: `nobody-${index}@acme.test`,
          password: 'not a password',
        }),
      );
    // Rotating interface identifiers within one /64 shares one counter.
    for (let index = 0; index < 3; index++)
      await expect(attempt(`2001:db8:1:2::${index + 1}`, index)).rejects.toMatchObject({
        code: 'INVALID_CREDENTIALS',
      });
    await expect(attempt('2001:DB8:1:2:abcd::99', 3)).rejects.toMatchObject({
      code: 'RATE_LIMITED',
    });
    // The neighbouring /64 is another client.
    await expect(attempt('2001:db8:1:3::1', 4)).rejects.toMatchObject({
      code: 'INVALID_CREDENTIALS',
    });
    // An IPv4 client and its IPv4-mapped spelling share one counter.
    for (let index = 5; index < 7; index++)
      await expect(attempt('203.0.113.5', index)).rejects.toMatchObject({
        code: 'INVALID_CREDENTIALS',
      });
    await expect(attempt('::ffff:203.0.113.5', 7)).rejects.toMatchObject({
      code: 'INVALID_CREDENTIALS',
    });
    await expect(attempt('::ffff:cb00:7105', 8)).rejects.toMatchObject({ code: 'RATE_LIMITED' });
    await expect(attempt('203.0.113.6', 9)).rejects.toMatchObject({
      code: 'INVALID_CREDENTIALS',
    });
  });
});
