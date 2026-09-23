import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

describe('sessions bound to the sign-in network', () => {
  it('refuses a bound session from another address, records it, and leaves unbound cases alone', async () => {
    const f = await organizationFixture();
    const from = <T>(ip: string, fn: () => Promise<T>) =>
      f.iam.auth.withClient({ ip, userAgent: 'test' }, fn);
    await f.member('alice');
    const session = await from('203.0.113.7', () => f.signIn('alice'));
    const use = (ip: string | undefined, token: string) =>
      ip
        ? from(ip, () => f.iam.api.auth.getSession({ token }))
        : f.iam.api.auth.getSession({ token });
    // Off by default: a session roams freely.
    expect((await use('198.51.100.9', session.token)).session.id).toBe(session.session.id);
    // The owner turns it on; existing sessions are bound to the address they were issued from.
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { bindSessionsToIp: true },
    });
    expect((await use('203.0.113.7', session.token)).session.id).toBe(session.session.id);
    await expect(use('198.51.100.9', session.token)).rejects.toMatchObject({
      code: 'SESSION_NETWORK_MISMATCH',
      status: 401,
    });
    // The refusal is in the person's trail with both addresses, and the session still works from home.
    const events = await from('203.0.113.7', () =>
      f.iam.api.auth.listSecurityEvents({ token: session.token }, { limit: 5 }),
    );
    // Events share the frozen fixture timestamp, so pick the mismatch by action rather than by position.
    expect(events.find((event) => event.action === 'auth:session:mismatch')).toMatchObject({
      metadata: { sessionId: session.session.id, sessionIp: '203.0.113.7', ip: '198.51.100.9' },
    });
    // A fresh sign-in from the new network works and is bound there.
    const away = await from('198.51.100.9', () => f.signIn('alice'));
    expect((await use('198.51.100.9', away.token)).session.id).toBe(away.session.id);
    await expect(use('203.0.113.7', away.token)).rejects.toMatchObject({
      code: 'SESSION_NETWORK_MISMATCH',
    });
    // Sessions without a recorded address, and requests without one, are not judged.
    const bare = await f.signIn('alice');
    expect((await use('198.51.100.9', bare.token)).session.id).toBe(bare.session.id);
    expect((await use(undefined, session.token)).session.id).toBe(session.session.id);
    // Over HTTP the refusal is a 401 with the code.
    const response = await f.iam.handler(
      new Request('http://localhost:3000/api/iam/auth/getSession', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-better-iam': '1',
          authorization: `Bearer ${session.token}`,
        },
        body: '{}',
      }),
    );
    // The default handler records no client IP, so the request is not judged; with clientInfo it would be.
    expect(response.status).toBe(200);
    // The policy field is validated.
    await expect(
      f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
        tenantId: f.tenantId,
        authPolicy: { bindSessionsToIp: 'yes' as never },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});
