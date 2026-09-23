import { afterEach, describe, expect, it } from 'vitest';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { createRequire } from 'node:module';
import { createSharedSignalsTransmitter, sharedSignalEvents } from '@better-iam/oauth';
import { closeFixtures, organizationFixture } from './support/organization.js';

const { jwtVerify, importJWK } = createRequire(
  new URL('../packages/oauth/package.json', import.meta.url),
)('jose');
const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const privateJwk = { ...pair.privateKey.export({ format: 'jwk' }), kid: 'ssf-key', alg: 'RS256' };
const publicJwk = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'ssf-key', alg: 'RS256' };
const ISSUER = 'https://id.example.test/oidc';

/** A push receiver (RFC 8935) that records every SET and can be told to refuse. */
async function receiver() {
  const received: { authorization?: string; contentType?: string; set: string }[] = [];
  let status = 202;
  const server = createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += String(chunk);
    received.push({
      authorization: req.headers.authorization,
      contentType: req.headers['content-type'],
      set: body,
    });
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(status === 202 ? '' : JSON.stringify({ err: 'invalid_request', description: 'nope' }));
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    server,
    received,
    url: `http://127.0.0.1:${(server.address() as { port: number }).port}/events`,
    refuse(code: number) {
      status = code;
    },
  };
}

describe('Shared Signals Framework transmitter', () => {
  const servers: Server[] = [];
  afterEach(async () => {
    for (const server of servers.splice(0)) {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    await closeFixtures();
  });

  async function setup() {
    const fixture = await organizationFixture();
    const endpoint = await receiver();
    servers.push(endpoint.server);
    const transmitter = createSharedSignalsTransmitter({
      ...fixture.iam.protocolHost,
      issuer: ISSUER,
      jwks: { keys: [privateJwk] },
      encryptionKey: randomBytes(32).toString('base64'),
      allowInsecureLocalhost: true,
    });
    const key = await importJWK(publicJwk, 'RS256');
    const decode = async (set: string) => {
      const { payload, protectedHeader } = await jwtVerify(set, key, {
        issuer: ISSUER,
        typ: 'secevent+jwt',
      });
      return { payload, protectedHeader } as {
        payload: Record<string, unknown> & { events: Record<string, Record<string, unknown>> };
        protectedHeader: Record<string, unknown>;
      };
    };
    return { ...fixture, endpoint, transmitter, decode };
  }

  it('pushes signed CAEP and RISC events for IAM activity to each tenant stream', async () => {
    const { iam, tenantId, ownerCredential, endpoint, transmitter, decode, ...fixture } =
      await setup();
    const stream = await transmitter.createStream(ownerCredential, {
      tenantId,
      name: 'SIEM',
      endpointUrl: endpoint.url,
      authorization: 'Bearer receiver-secret',
    });
    expect(stream).toMatchObject({ hasAuthorization: true, subjectFormat: 'iss_sub', pending: 0 });
    expect(JSON.stringify(stream)).not.toContain('receiver-secret');

    // Verification event: delivered immediately with the chosen state.
    const verification = await transmitter.verifyStream(ownerCredential, {
      tenantId,
      streamId: stream.id,
      state: 'check-123',
    });
    expect(verification.delivered).toBe(true);
    expect(endpoint.received[0]).toMatchObject({
      authorization: 'Bearer receiver-secret',
      contentType: 'application/secevent+jwt',
    });
    const verified = await decode(endpoint.received[0]!.set);
    expect(verified.protectedHeader).toMatchObject({ typ: 'secevent+jwt', kid: 'ssf-key' });
    expect(verified.payload.aud).toBe(endpoint.url);
    expect(
      verified.payload.events['https://schemas.openid.net/secevent/ssf/event-type/verification'],
    ).toEqual({ state: 'check-123' });

    const unsubscribe = transmitter.subscribe(iam.events);
    const alice = await fixture.member('alice');
    const aliceSession = await fixture.signIn('alice');

    // An administrator revokes Alice's sessions: session-revoked, initiated by an admin.
    await iam.api.identities.revokeSessions(await fixture.ownerSignIn(), {
      tenantId,
      identityId: alice.id,
    });
    await iam.dispatchAuditHooks();
    const revoked = await decode(endpoint.received.at(-1)!.set);
    expect(revoked.payload.sub_id).toEqual({ format: 'iss_sub', iss: ISSUER, sub: alice.id });
    expect(revoked.payload.events[sharedSignalEvents.sessionRevoked]).toMatchObject({
      initiating_entity: 'admin',
    });
    expect(typeof revoked.payload.txn).toBe('string');
    expect(aliceSession.token).toBeTruthy();

    // Alice changes her password herself: credential-change, initiated by the user.
    const again = await fixture.signIn('alice');
    await iam.api.auth.changePassword(
      { token: again.token },
      { currentPassword: 'a strong alice password', password: 'an even stronger alice password' },
    );
    await iam.dispatchAuditHooks();
    const changed = await decode(endpoint.received.at(-1)!.set);
    expect(changed.payload.events[sharedSignalEvents.credentialChange]).toMatchObject({
      credential_type: 'password',
      change_type: 'update',
      initiating_entity: 'user',
    });

    // Delivery history, newest first; audit trail of management.
    const deliveries = await transmitter.listDeliveries(ownerCredential, {
      tenantId,
      streamId: stream.id,
    });
    expect(deliveries.every((delivery) => delivery.status === 'delivered')).toBe(true);
    expect(deliveries[0]!.eventType).toBe(sharedSignalEvents.credentialChange);
    unsubscribe();
    const actions = (await iam.store.find('audit', { tenantId })).map((event) => event.action);
    expect(actions).toContain('iam:ssf:CreateStream');
  });

  it('filters event types, identifies by email, retries failures, holds events while paused', async () => {
    const { iam, tenantId, ownerCredential, endpoint, transmitter, decode, ...fixture } =
      await setup();
    const stream = await transmitter.createStream(ownerCredential, {
      tenantId,
      name: 'Credentials only',
      endpointUrl: endpoint.url,
      audience: 'https://receiver.example.test',
      events: [sharedSignalEvents.credentialChange],
      subjectFormat: 'email',
    });
    transmitter.subscribe(iam.events);
    await fixture.member('bob');
    const bob = await fixture.signIn('bob');
    endpoint.refuse(500);
    await iam.api.auth.changePassword(
      { token: bob.token },
      { currentPassword: 'a strong bob password', password: 'an even stronger bob password' },
    );
    await iam.dispatchAuditHooks();
    // Only the credential change was queued; the receiver refused it, so it waits for a retry.
    let deliveries = await transmitter.listDeliveries(ownerCredential, {
      tenantId,
      streamId: stream.id,
    });
    expect(deliveries).toHaveLength(1);
    expect(deliveries[0]).toMatchObject({
      status: 'pending',
      attempts: 1,
      lastError: 'HTTP 500: invalid_request nope',
    });
    expect(
      (await transmitter.getStream(ownerCredential, { tenantId, streamId: stream.id })).lastError,
    ).toContain('HTTP 500');
    // Not due yet: nothing is resent.
    expect(await transmitter.dispatch()).toEqual({ delivered: 0, failed: 0 });

    // Due again after the backoff; the receiver recovered.
    endpoint.refuse(202);
    await iam.store.transaction(async (tx) => {
      const record = (await tx.find('ssfDeliveries', { streamId: stream.id }))[0]!;
      await tx.put('ssfDeliveries', { ...record, nextAttemptAt: 0 });
    });
    expect(await transmitter.dispatch()).toEqual({ delivered: 1, failed: 0 });
    const set = await decode(endpoint.received.at(-1)!.set);
    expect(set.payload.aud).toBe('https://receiver.example.test');
    expect(set.payload.sub_id).toEqual({ format: 'email', email: 'bob@acme.test' });

    // Paused streams keep events and deliver them after resuming.
    await transmitter.updateStream(ownerCredential, {
      tenantId,
      streamId: stream.id,
      enabled: false,
    });
    const before = endpoint.received.length;
    const bobAgain = await iam.api.auth.signIn({
      tenantId,
      email: 'bob@acme.test',
      password: 'an even stronger bob password',
    });
    if (!('token' in bobAgain)) throw new Error('Unexpected MFA');
    await iam.api.auth.changePassword(
      { token: bobAgain.token },
      { currentPassword: 'an even stronger bob password', password: 'the strongest bob password' },
    );
    await iam.dispatchAuditHooks();
    expect(endpoint.received.length).toBe(before);
    expect(
      (await transmitter.getStream(ownerCredential, { tenantId, streamId: stream.id })).pending,
    ).toBe(1);
    await transmitter.updateStream(ownerCredential, {
      tenantId,
      streamId: stream.id,
      enabled: true,
    });
    expect(await transmitter.dispatch()).toEqual({ delivered: 1, failed: 0 });
    expect(endpoint.received.length).toBe(before + 1);

    // Deleting the stream drops its queue.
    await transmitter.deleteStream(ownerCredential, { tenantId, streamId: stream.id });
    expect(await iam.store.find('ssfDeliveries', { streamId: stream.id })).toEqual([]);
  });

  it('guards management and validates streams; serves transmitter metadata', async () => {
    const { tenantId, ownerCredential, endpoint, transmitter, ...fixture } = await setup();
    await fixture.member('carol');
    const carol = await fixture.signIn('carol');
    await expect(
      transmitter.createStream(
        { token: carol.token },
        { tenantId, name: 'X', endpointUrl: endpoint.url },
      ),
    ).rejects.toMatchObject({ status: 403 });
    for (const input of [
      { endpointUrl: 'http://receiver.example.test/events' },
      { endpointUrl: 'not a url' },
      { events: ['https://example.test/unknown'] },
      { subjectFormat: 'phone' },
      { authorization: 'Bearer a\r\nx-injected: 1' },
      { name: '' },
    ])
      await expect(
        transmitter.createStream(ownerCredential, {
          tenantId,
          name: 'X',
          endpointUrl: endpoint.url,
          ...(input as object),
        }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const served = transmitter.handler(
      new Request('https://id.example.test/.well-known/ssf-configuration/oidc'),
    )!;
    expect(await served.json()).toMatchObject({
      spec_version: '1_0',
      issuer: ISSUER,
      jwks_uri: `${ISSUER}/jwks`,
      delivery_methods_supported: ['urn:ietf:rfc:8935'],
    });
    expect(transmitter.handler(new Request('https://id.example.test/other'))).toBeUndefined();
    expect(() =>
      createSharedSignalsTransmitter({
        ...fixture.iam.protocolHost,
        issuer: ISSUER,
        jwks: { keys: [publicJwk] },
        encryptionKey: randomBytes(32).toString('base64'),
      }),
    ).toThrow(/private signing key/);
  });
});
