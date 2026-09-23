import { afterEach, describe, expect, it, vi } from 'vitest';
import { ipMatches, verifyAuditChain, type AuditEvent, type Tenant } from '@better-iam/core';
import { tenantAuthPolicy } from '../packages/server/src/tenant-policy.js';
import {
  bodyFrom,
  selectDefault,
  textDefault,
  type FieldSpec,
  type FormValues,
} from '../apps/console/src/lib/form-body.js';
import {
  authPolicyFields,
  editedPolicyKeys,
  uneditedPolicyKeys,
} from '../apps/console/src/lib/auth-policy-form.js';
import {
  auditWindow,
  pageOf,
  platformBlockFor,
  recordsById,
} from '../apps/console/src/lib/admin-views.js';
import { auditChainExport } from '../apps/console/src/lib/audit-export.js';
import {
  createOptions,
  trustedProxyClientInfo,
  trustedProxyHops,
} from '../apps/console/better-iam.config.mjs';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

/** The form data a browser submits for a form rendered from `fields` and left untouched. */
function untouched(fields: FieldSpec[]): FormValues {
  const values = new Map<string, string[]>();
  for (const field of fields) {
    if (field.type === 'checkbox') values.set(field.name, field.defaultValue ? ['on'] : []);
    else if (field.type === 'multiselect' || field.type === 'select')
      values.set(field.name, [selectDefault(field)].flat());
    else values.set(field.name, [textDefault(field)]);
  }
  return {
    get: (name) => values.get(name)?.[0] ?? null,
    getAll: (name) => values.get(name) ?? [],
  };
}

/** What the console's ApiForm sends when the form is saved without changes. */
const submitDefaults = (fields: FieldSpec[]) => bodyFrom(untouched(fields), fields);

const everyField = {
  requireMfa: true,
  requireMfaForOwners: true,
  bindSessionsToIp: true,
  allowedMethods: ['password', 'passkey'],
  sessionLifetimeMs: 3_600_000,
  sessionIdleTimeoutMs: 1_800_000,
  maxAttempts: 7,
  minPasswordLength: 14,
  maxSessions: 3,
  allowImpersonation: true,
  trustedDeviceDays: 0,
  notifyNewSignIn: true,
  allowedIpRanges: ['203.0.113.0/24', '2001:db8::/32'],
  mfaEmailCodes: true,
  passwordMinClasses: 3,
  passwordHistory: 5,
  passwordMaxAgeDays: 90,
  passwordRejectPersonalInfo: true,
} as const;

describe('organization settings: authentication policy form', () => {
  it('carries every policy field, so saving the form unchanged keeps the policy exactly', () => {
    const policy = tenantAuthPolicy(everyField);
    expect(policy).toEqual(everyField);
    expect(uneditedPolicyKeys(policy)).toEqual([]);
    const fields = authPolicyFields(policy);
    expect(new Set(fields.map((field) => field.name))).toEqual(new Set(Object.keys(policy)));
    expect(new Set(editedPolicyKeys)).toEqual(new Set(Object.keys(policy)));
    expect(fields.every((field) => field.group === 'authPolicy')).toBe(true);
    // The method restriction is preselected; before, the multiselect rendered empty and a save dropped it.
    expect(fields.find((field) => field.name === 'allowedMethods')?.defaultValue).toEqual([
      'password',
      'passkey',
    ]);
    expect(tenantAuthPolicy(submitDefaults(fields).authPolicy)).toEqual(policy);
    // No policy: nothing is preselected, so the form does not invent a restriction.
    expect(submitDefaults(authPolicyFields(undefined)).authPolicy).not.toHaveProperty(
      'allowedMethods',
    );
  });

  it('flags stored fields the form cannot edit instead of dropping them silently', () => {
    expect(uneditedPolicyKeys({ requireMfa: true, futureControl: 1 } as never)).toEqual([
      'futureControl',
    ]);
    expect(uneditedPolicyKeys(undefined)).toEqual([]);
  });

  it('warns on the network controls when the deployment records no client addresses', () => {
    const help = (recordsAddresses: boolean, name: string) =>
      authPolicyFields(undefined, { recordsAddresses }).find((field) => field.name === name)?.help;
    expect(help(false, 'allowedIpRanges')).toMatch(/Not enforced/);
    expect(help(false, 'bindSessionsToIp')).toMatch(/Not enforced/);
    expect(help(true, 'allowedIpRanges')).not.toMatch(/Not enforced/);
  });

  it('keeps an allowed-methods restriction through a save of the whole form', async () => {
    const f = await organizationFixture();
    const initial = {
      allowedMethods: ['password', 'passkey'],
      sessionLifetimeMs: 86_400_000,
      maxAttempts: 7,
      minPasswordLength: 14,
      passwordHistory: 5,
      allowImpersonation: true,
      trustedDeviceDays: 0,
    };
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: initial as Tenant['authPolicy'] & object,
    });
    const stored = (await f.iam.api.tenants.get(f.ownerCredential, { tenantId: f.tenantId }))
      .authPolicy;
    // The administrator only changes the session lifetime and saves.
    const body = submitDefaults(authPolicyFields(stored)).authPolicy as Record<string, unknown>;
    body.sessionLifetimeMs = 43_200_000;
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: body as Tenant['authPolicy'] & object,
    });
    const saved = (await f.iam.api.tenants.get(f.ownerCredential, { tenantId: f.tenantId }))
      .authPolicy!;
    expect(saved).toMatchObject({ ...initial, sessionLifetimeMs: 43_200_000 });
  });

  it('shows the policy only to viewers who may read the tenant, and clears an alias with null', async () => {
    const f = await organizationFixture();
    await f.member('bob');
    const bob = await f.signIn('bob');
    // The settings page renders details and policy only when tenants.get succeeds for the viewer.
    await expect(
      f.iam.api.tenants.get({ token: bob.token }, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect((await f.iam.api.tenants.get(f.ownerCredential, { tenantId: f.tenantId })).id).toBe(
      f.tenantId,
    );
    // The alias field sends null when emptied: an omitted slug is invalid input, null removes the alias.
    await f.iam.api.tenants.setSlug(f.ownerCredential, { tenantId: f.tenantId, slug: 'acme-co' });
    await expect(
      f.iam.api.tenants.setSlug(f.ownerCredential, { tenantId: f.tenantId } as never),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await f.iam.api.tenants.setSlug(f.ownerCredential, { tenantId: f.tenantId, slug: null });
    expect(
      (await f.iam.api.tenants.get(f.ownerCredential, { tenantId: f.tenantId })).slug,
    ).toBeUndefined();
  });
});

describe('console client addresses (TRUSTED_PROXY_HOPS)', () => {
  const request = (headers: Record<string, string>) =>
    new Request('http://localhost:3000/api/iam/auth/signIn', { headers });

  it('reads the hop the trusted proxies appended, never the client-supplied part', () => {
    const one = trustedProxyClientInfo(1);
    expect(
      one(request({ 'x-forwarded-for': '203.0.113.9, 198.51.100.7', 'user-agent': 'UA/1' })),
    ).toEqual({ ip: '198.51.100.7', userAgent: 'UA/1' });
    expect(
      trustedProxyClientInfo(2)(request({ 'x-forwarded-for': '203.0.113.9, 198.51.100.7' })),
    ).toEqual({ ip: '203.0.113.9' });
    // Fewer entries than proxies: the request bypassed one, so no address is guessed.
    expect(
      trustedProxyClientInfo(2)(request({ 'x-forwarded-for': '198.51.100.7', 'user-agent': 'UA' })),
    ).toEqual({ userAgent: 'UA' });
    expect(one(request({}))).toBeUndefined();
    expect(one(request({ 'x-forwarded-for': '198.51.100.7:4711' }))).toEqual({
      ip: '198.51.100.7',
    });
    expect(one(request({ 'x-forwarded-for': '[2001:db8::7]:443' }))).toEqual({
      ip: '2001:db8::7',
    });
    expect(one(request({ 'x-forwarded-for': '::ffff:198.51.100.7' }))).toEqual({
      ip: '198.51.100.7',
    });
    expect(
      one(request({ 'x-forwarded-for': '198.51.100.7, unknown', 'user-agent': 'UA' })),
    ).toEqual({ userAgent: 'UA' });
  });

  it('is off unless TRUSTED_PROXY_HOPS is set, and rejects nonsense', async () => {
    expect(trustedProxyHops({})).toBe(0);
    expect(trustedProxyHops({ TRUSTED_PROXY_HOPS: '' })).toBe(0);
    expect(trustedProxyHops({ TRUSTED_PROXY_HOPS: '2' })).toBe(2);
    for (const value of ['yes', '-1', '1.5', '11'])
      expect(() => trustedProxyHops({ TRUSTED_PROXY_HOPS: value })).toThrow(/TRUSTED_PROXY_HOPS/);
    const saved = { ...process.env };
    try {
      process.env.BETTER_IAM_SECRET = 'console-pages-test-secret-with-32-characters';
      process.env.BETTER_IAM_DATABASE = ':memory:';
      delete process.env.DATABASE_URL;
      delete process.env.TRUSTED_PROXY_HOPS;
      const plain = await createOptions();
      expect(plain).not.toHaveProperty('http');
      await plain.database.close();
      process.env.TRUSTED_PROXY_HOPS = '1';
      const proxied = await createOptions();
      await proxied.database.close();
      expect(
        proxied.http?.clientInfo?.(request({ 'x-forwarded-for': '203.0.113.9, 198.51.100.7' })),
      ).toEqual({ ip: '198.51.100.7' });
    } finally {
      process.env = saved;
    }
  });

  it('lets allowed networks bite through the HTTP handler', async () => {
    const f = await organizationFixture({ http: { clientInfo: trustedProxyClientInfo(1) } });
    await f.iam.store.transaction(async (tx) => {
      const tenant = (await tx.get<Tenant>('tenants', f.tenantId))!;
      await tx.put('tenants', { ...tenant, authPolicy: { allowedIpRanges: ['203.0.113.0/24'] } });
    });
    const signIn = (forwardedFor: string) =>
      f.iam.handler(
        new Request('http://localhost:3000/api/iam/auth/signIn', {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-better-iam': '1',
            'x-forwarded-for': forwardedFor,
          },
          body: JSON.stringify({
            tenantId: f.tenantId,
            email: 'owner@acme.test',
            password: 'a strong tenant owner password',
          }),
        }),
      );
    // The client claims an allowed address; the proxy's own hop says otherwise.
    const refused = await signIn('203.0.113.9, 198.51.100.7');
    expect(refused.status).toBe(403);
    expect((await refused.json()).error.code).toBe('IP_NOT_ALLOWED');
    const accepted = await signIn('198.51.100.7, 203.0.113.9');
    expect(accepted.status).toBe(200);
    expect((await accepted.json()).data.session.client.ip).toBe('203.0.113.9');
  });
});

describe('admin pages: bounded reads and platform blocks', () => {
  const event = (tenantId: string, action: string, timestamp: number, actorId = 'usr_a') =>
    ({
      id: `evt_${tenantId}_${action}_${timestamp}`,
      tenantId,
      actorId,
      action,
      resourceId: tenantId,
      outcome: 'deny',
      timestamp,
    }) as AuditEvent;

  it('reads the audit once, narrowed to the organization, and keeps only the window', async () => {
    const events = [
      event('ten_a', 'auth:signin:fail', 1_000),
      event('ten_a', 'auth:signin:fail', 5_000),
      event('ten_a', 'auth:session:create', 6_000),
      event('ten_a', 'iam:roles:create', 7_000),
      event('ten_b', 'auth:signin:fail', 8_000),
    ];
    const store = {
      find: vi.fn(async (_collection: string, filter: Record<string, unknown> = {}) =>
        events.filter((item) => !filter.tenantId || item.tenantId === filter.tenantId),
      ),
    };
    const scoped = await auditWindow(store as never, {
      actions: ['auth:signin:fail', 'auth:session:create'],
      since: 2_000,
      tenantId: 'ten_a',
    });
    expect(store.find).toHaveBeenCalledTimes(1);
    expect(store.find).toHaveBeenCalledWith('audit', { tenantId: 'ten_a' });
    expect(scoped.get('auth:signin:fail')!.map((item) => item.timestamp)).toEqual([5_000]);
    expect(scoped.get('auth:session:create')!.map((item) => item.timestamp)).toEqual([6_000]);
    const everywhere = await auditWindow(store as never, {
      actions: ['auth:signin:fail'],
      since: 0,
    });
    expect(store.find).toHaveBeenLastCalledWith('audit', {});
    expect(everywhere.get('auth:signin:fail')!.map((item) => item.timestamp)).toEqual([
      8_000, 5_000, 1_000,
    ]);
  });

  it('finds sign-ins in the window against a real store and reads only the people it names', async () => {
    const f = await organizationFixture();
    await f.ownerSignIn();
    const since = f.now() - 3_600_000;
    const window = await auditWindow(f.iam.store, {
      actions: ['auth:session:create'],
      since,
      tenantId: f.tenantId,
    });
    expect(window.get('auth:session:create')!.some((item) => item.actorId === f.ownerId)).toBe(
      true,
    );
    expect(
      (
        await auditWindow(f.iam.store, {
          actions: ['auth:session:create'],
          since,
          tenantId: f.root.tenant.id,
        })
      )
        .get('auth:session:create')!
        .some((item) => item.actorId === f.ownerId),
    ).toBe(false);
    f.advance(2 * 3_600_000);
    expect(
      (
        await auditWindow(f.iam.store, {
          actions: ['auth:session:create'],
          since: f.now() - 3_600_000,
          tenantId: f.tenantId,
        })
      ).get('auth:session:create'),
    ).toEqual([]);
    const get = vi.spyOn(f.iam.store, 'get');
    const people = await recordsById(f.iam.store, 'identities', [f.ownerId, f.ownerId, 'usr_none']);
    expect(get).toHaveBeenCalledTimes(2);
    expect([...people.keys()]).toEqual([f.ownerId]);
  });

  it('treats only active platform blocks as covering an address everywhere', () => {
    const blocks = [
      { id: 'b1', network: '233.252.0.7', active: true },
      { id: 'b2', network: '198.51.100.0/24', active: true, platform: true },
      { id: 'b3', network: '192.0.2.0/24', active: false, platform: true },
    ];
    // A root-organization-only block leaves the one-click platform block available.
    expect(platformBlockFor(blocks, '233.252.0.7', ipMatches)).toBeUndefined();
    // A platform block covers every address in its range, not only an exact match.
    expect(platformBlockFor(blocks, '198.51.100.7', ipMatches)?.id).toBe('b2');
    expect(platformBlockFor(blocks, '192.0.2.5', ipMatches)).toBeUndefined();
  });

  it('pages rows and clamps the page number', () => {
    const rows = Array.from({ length: 5 }, (_, index) => index);
    expect(pageOf(rows, 1, 2)).toEqual({ rows: [0, 1], page: 1, pages: 3 });
    expect(pageOf(rows, 3, 2)).toEqual({ rows: [4], page: 3, pages: 3 });
    expect(pageOf(rows, 9, 2).page).toBe(3);
    expect(pageOf(rows, Number.NaN, 2).page).toBe(1);
    expect(pageOf([], 1, 2)).toEqual({ rows: [], page: 1, pages: 1 });
  });
});

describe('organization audit export', () => {
  it('streams the whole chain page by page, ending at the head as it stood when the export began', async () => {
    const f = await organizationFixture();
    for (const name of ['ann', 'ben', 'cat']) await f.member(name);
    const reads: number[] = [];
    let appended = false;
    const read = async (fromSequence: number) => {
      reads.push(fromSequence);
      const page = await f.iam.api.audit.export(f.ownerCredential, {
        tenantId: f.tenantId,
        fromSequence,
        limit: 2,
      });
      // Events recorded while the download runs belong to the next export.
      if (!appended) {
        appended = true;
        await f.member('late');
      }
      return page;
    };
    const chain = await auditChainExport(read);
    let text = '';
    for await (const chunk of chain.chunks) text += chunk;
    const lines = text
      .trimEnd()
      .split('\n')
      .map((line) => JSON.parse(line) as AuditEvent);
    expect(chain.firstSequence).toBe(1);
    expect(chain.through).toBeGreaterThan(4);
    expect(lines.map((line) => line.sequence)).toEqual(
      Array.from({ length: chain.through }, (_, index) => index + 1),
    );
    expect(lines.at(-1)!.hash).toBe(chain.head!.hash);
    expect((await verifyAuditChain(lines)).valid).toBe(true);
    expect(reads.length).toBeGreaterThan(2);
    const head = (await f.iam.api.audit.verify(f.ownerCredential, { tenantId: f.tenantId })).head!;
    expect(head.sequence).toBeGreaterThan(chain.through);
    // The next incremental export continues exactly where this one ended.
    const next = await auditChainExport(read, chain.through + 1);
    let rest = '';
    for await (const chunk of next.chunks) rest += chunk;
    const restLines = rest
      .trimEnd()
      .split('\n')
      .map((line) => JSON.parse(line) as AuditEvent);
    expect(restLines[0]!.sequence).toBe(chain.through + 1);
    expect(restLines[0]!.previousHash).toBe(chain.head!.hash);
    expect(next.through).toBeGreaterThanOrEqual(head.sequence);
    expect(restLines.at(-1)!.sequence).toBe(next.through);
    expect(restLines.at(-1)!.hash).toBe(next.head!.hash);
  });

  it('exports nothing past the head', async () => {
    const f = await organizationFixture();
    const chain = await auditChainExport(
      (fromSequence) =>
        f.iam.api.audit.export(f.ownerCredential, { tenantId: f.tenantId, fromSequence }),
      1_000_000,
    );
    let text = '';
    for await (const chunk of chain.chunks) text += chunk;
    expect(text).toBe('');
    expect(chain.firstSequence).toBeUndefined();
  });
});
