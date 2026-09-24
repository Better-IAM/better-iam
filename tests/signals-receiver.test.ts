import { afterEach, describe, expect, it } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { AuditEvent } from '@better-iam/core';
import { createSharedSignalsTransmitter } from '@better-iam/oauth';
import { betterIam, type SignalSourceCreateInput } from '@better-iam/server';
import {
  generateTestKey,
  signTestJwt,
  tamperPayload,
  type SignTestJwtKey,
  type TestKey,
} from './support/jwt-keys.js';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

const CAEP = 'https://schemas.openid.net/secevent/caep/event-type/';
const RISC = 'https://schemas.openid.net/secevent/risc/event-type/';
const SSF = 'https://schemas.openid.net/secevent/ssf/event-type/';
const ISSUER = 'https://idp.example.test';
const AUDIENCE = 'https://rp.example.test/signals';
const FIXTURE_SECRET = 'organization-fixture-secret-with-32-characters';

type Subject = Record<string, unknown>;

const servers: Server[] = [];
afterEach(async () => {
  for (const server of servers.splice(0)) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  await closeFixtures();
});

/** A node HTTP server on 127.0.0.1 playing an upstream identity provider or an RFC 8936 poll endpoint. */
async function listen(
  handle: (request: IncomingMessage, body: string, response: ServerResponse) => void,
): Promise<string> {
  const server = createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += String(chunk);
    handle(request, body, response);
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${(server.address() as { port: number }).port}`;
}

function reply(response: ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { 'content-type': 'application/json' });
  response.end(JSON.stringify(body));
}

const seconds = (f: OrganizationFixture) => Math.floor(f.now() / 1000);
/** The credential of a sign-in result. */
const bearer = (result: { token: string }) => ({ token: result.token });

/** The `events` claim (one event) and, when given, the RFC 9493 `sub_id`. */
const event = (type: string, claims: Record<string, unknown> = {}, subject?: Subject) => ({
  events: { [type]: claims },
  ...(subject ? { sub_id: subject } : {}),
});

/** A compact SET for ISSUER and AUDIENCE, issued now with a fresh jti unless `claims` says otherwise. */
function securityEvent(
  f: OrganizationFixture,
  key: SignTestJwtKey,
  claims: Record<string, unknown>,
  header: Record<string, unknown> = {},
): string {
  return signTestJwt(
    key,
    { iss: ISSUER, aud: AUDIENCE, iat: seconds(f), jti: randomUUID(), ...claims },
    { typ: 'secevent+jwt', ...header },
  );
}

/** A push source of Acme for ISSUER with static keys, and helpers to sign and push SETs to it. */
async function pushSource(f: OrganizationFixture, input: Partial<SignalSourceCreateInput> = {}) {
  const key = generateTestKey('RS256', 'idp-1');
  const created = await f.iam.api.signals.createSource(await f.ownerSignIn(), {
    tenantId: f.tenantId,
    name: 'Upstream IdP',
    issuer: ISSUER,
    audiences: [AUDIENCE],
    jwks: { keys: [key.publicJwk as never] },
    delivery: 'push',
    ...input,
  });
  const sign = (
    claims: Record<string, unknown>,
    header: Record<string, unknown> = {},
    signer: SignTestJwtKey = key,
  ) => securityEvent(f, signer, claims, header);
  const push = (
    body: string,
    init: { token?: string | null; type?: string; url?: string; method?: string } = {},
  ) => {
    const pushToken = init.token === undefined ? created.pushToken : init.token;
    const method = init.method ?? 'POST';
    return f.iam.handler(
      new Request(init.url ?? created.pushUrl!, {
        method,
        headers: {
          'content-type': init.type ?? 'application/secevent+jwt',
          accept: 'application/json',
          ...(pushToken ? { authorization: `Bearer ${pushToken}` } : {}),
        },
        ...(method === 'GET' ? {} : { body }),
      }),
    );
  };
  return { key, created, sourceId: created.source.id, sign, push };
}

/** A federation link as federation.ts writes it on sign-in: natural key `[connectionId, issuer, subject]`. */
function link(
  f: OrganizationFixture,
  tenantId: string,
  connectionId: string,
  issuer: string,
  subject: string,
  identityId: string,
) {
  return f.iam.store.transaction((tx) =>
    tx.insert('externalIdentities', {
      id: randomUUID(),
      tenantId,
      uniqueKey: JSON.stringify([connectionId, issuer, subject]),
      identityId,
      providerId: connectionId,
      issuer,
      subject,
    }),
  );
}

/** A user provisioned through a SCIM connection (scim `UserLink`), the IdP's user id as `externalId`. */
function linkScim(
  f: OrganizationFixture,
  connectionId: string,
  identityId: string,
  externalId: string,
) {
  return f.iam.store.transaction((tx) =>
    tx.insert('scimUsers', {
      id: randomUUID(),
      tenantId: f.tenantId,
      connectionId,
      identityId,
      userName: `${externalId}@idp.example.test`,
      externalId,
      displayName: externalId,
      active: true,
      version: 1,
      createdAt: f.now(),
      updatedAt: f.now(),
    }),
  );
}

/** A second organization ("Beta") with an owner who accepted the invitation. */
async function secondOrganization(f: OrganizationFixture) {
  const created = await f.iam.api.tenants.create(f.rootCredential, {
    parentId: f.root.tenant.id,
    name: 'Beta',
    type: 'organization',
    ownerEmail: 'owner@beta.test',
  });
  await f.iam.auth.dispatchOutbox();
  const invitation = f.inbox.find(
    (message) => message.tenantId === created.tenant.id && message.template === 'owner-invitation',
  )!;
  await f.iam.api.tenants.acceptInvitation({
    tenantId: created.tenant.id,
    token: invitation.payload.token!,
    name: 'Beta owner',
    password: 'a strong beta owner password',
  });
  const tenantId = created.tenant.id;
  const signIn = async (email: string, password: string) => {
    const result = await f.iam.api.auth.signIn({ tenantId, email, password });
    if (!('token' in result)) throw new Error('Unexpected MFA');
    return { token: result.token };
  };
  return {
    tenantId,
    signIn,
    ownerSignIn: () => signIn('owner@beta.test', 'a strong beta owner password'),
  };
}

async function audit(f: OrganizationFixture, tenantId: string, action: string) {
  return (await f.iam.store.find<AuditEvent>('audit', { tenantId }))
    .filter((entry) => entry.action === action)
    .sort((a, b) => (a.sequence ?? 0) - (b.sequence ?? 0));
}

const listEvents = (
  f: OrganizationFixture,
  input: Omit<
    Parameters<OrganizationFixture['iam']['api']['signals']['listEvents']>[1],
    'tenantId'
  > = {},
) => f.iam.api.signals.listEvents(f.ownerCredential, { tenantId: f.tenantId, ...input });

describe('Shared Signals receiver', () => {
  it('receives what our own transmitter sends from another organization and ends the matched sessions', async () => {
    const f = await organizationFixture({ signals: { allowInsecureLocalhost: true } });
    const beta = await secondOrganization(f);
    const TRANSMITTER = 'https://id.acme.example.test/oidc';
    const BETA_AUDIENCE = 'https://beta.example.test/signals';
    const signing = generateTestKey('ES256', 'acme-ssf');
    // Acme's deployment transmits; its pushes reach this same deployment's receiver in process.
    const transmitter = createSharedSignalsTransmitter({
      ...f.iam.protocolHost,
      issuer: TRANSMITTER,
      jwks: { keys: [signing.privateJwk as never] },
      encryptionKey: randomBytes(32).toString('base64'),
      allowInsecureLocalhost: true,
      fetch: (url, init) => f.iam.handler(new Request(url, init)),
    });

    // Beta registers Acme's transmitter, mapping subjects through its Acme sign-in connection.
    const betaOwner = await beta.ownerSignIn();
    const created = await f.iam.api.signals.createSource(betaOwner, {
      tenantId: beta.tenantId,
      name: 'Acme identity provider',
      issuer: TRANSMITTER,
      audiences: [BETA_AUDIENCE],
      jwks: { keys: [signing.publicJwk as never] },
      delivery: 'push',
      subjects: { connectionIds: ['acme-oidc'] },
      actions: { 'session-revoked': 'revoke-sessions' },
    });
    const sourceId = created.source.id;
    expect(created.pushUrl).toBe(`http://localhost:3000/api/iam/signals/push/${sourceId}`);
    expect(created.pushToken).toMatch(/^[\w-]{43}$/);
    const stream = await transmitter.createStream(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Beta',
      endpointUrl: created.pushUrl!,
      audience: BETA_AUDIENCE,
      authorization: `Bearer ${created.pushToken}`,
    });

    // The stream's verification event is accepted and noted on the source.
    expect(
      await transmitter.verifyStream(f.ownerCredential, {
        tenantId: f.tenantId,
        streamId: stream.id,
        state: 'hello',
      }),
    ).toMatchObject({ delivered: true });
    expect(
      (await f.iam.api.signals.getSource(betaOwner, { tenantId: beta.tenantId, sourceId }))
        .lastVerifiedAt,
    ).toBe(f.now());
    f.advance(1000);

    // Alice works in both organizations; Beta's account is linked to Acme's through Beta's Acme connection.
    const aliceAtAcme = await f.member('alice');
    const aliceAtBeta = await f.iam.api.identities.create(betaOwner, {
      tenantId: beta.tenantId,
      email: 'alice@beta.test',
      name: 'Alice',
      password: 'a strong alice password',
    });
    await link(f, beta.tenantId, 'acme-oidc', TRANSMITTER, aliceAtAcme.id, aliceAtBeta.id);
    const betaSession = await beta.signIn('alice@beta.test', 'a strong alice password');
    // Beta transmits too: none of the receiver's own audit events may echo back upstream.
    const echo = await transmitter.createStream(betaOwner, {
      tenantId: beta.tenantId,
      name: 'Echo check',
      endpointUrl: 'http://localhost:3000/echo',
      audience: 'https://acme.example.test',
    });

    // An Acme administrator ends Alice's sessions: session-revoked reaches Beta.
    const unsubscribe = transmitter.subscribe(f.iam.events);
    await f.iam.api.identities.revokeSessions(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      identityId: aliceAtAcme.id,
    });
    await f.iam.dispatchAuditHooks();
    await f.iam.dispatchAuditHooks();
    unsubscribe();

    const deliveries = await transmitter.listDeliveries(f.ownerCredential, {
      tenantId: f.tenantId,
      streamId: stream.id,
    });
    expect(deliveries.length).toBeGreaterThanOrEqual(2);
    expect(deliveries.every((delivery) => delivery.status === 'delivered')).toBe(true);
    await expect(f.iam.api.auth.getSession(betaSession)).rejects.toMatchObject({ status: 401 });

    const page = await f.iam.api.signals.listEvents(betaOwner, { tenantId: beta.tenantId });
    expect(page.total).toBe(2);
    expect(page.events.map((entry) => [entry.eventType, entry.status])).toEqual([
      ['session-revoked', 'applied'],
      ['verification', 'recorded'],
    ]);
    const revocation = page.events[0]!;
    expect(revocation).toMatchObject({
      sourceId,
      identityId: aliceAtBeta.id,
      subject: { format: 'iss_sub', iss: TRANSMITTER, sub: aliceAtAcme.id },
      claims: { initiating_entity: 'admin' },
      txn: expect.any(String),
    });
    const [received] = (await audit(f, beta.tenantId, 'signal:received')).filter(
      (entry) => entry.metadata?.eventType === 'session-revoked',
    );
    expect(received).toMatchObject({
      actorId: `signal:${sourceId}`,
      resourceId: aliceAtBeta.id,
      outcome: 'allow',
      metadata: {
        sourceId,
        eventType: 'session-revoked',
        jti: revocation.jti,
        status: 'applied',
        identityId: aliceAtBeta.id,
      },
    });
    expect(
      (await audit(f, beta.tenantId, 'signal:revoke-sessions')).map((entry) => entry.metadata),
    ).toEqual([{ sourceId, eventType: 'session-revoked', jti: revocation.jti, revoked: 1 }]);
    expect(await audit(f, beta.tenantId, 'identity:revoke-sessions')).toEqual([]);
    expect(
      await transmitter.listDeliveries(betaOwner, { tenantId: beta.tenantId, streamId: echo.id }),
    ).toEqual([]);
  });

  it('refuses security event tokens that fail verification, with RFC 8935 answers', async () => {
    const f = await organizationFixture();
    const { key, sign, push, sourceId } = await pushSource(f);
    const disabled = event(`${RISC}account-disabled`, {}, { format: 'opaque', id: 'someone' });
    const now = seconds(f);
    const refused = async (response: Promise<Response>, status: number, err: string) => {
      const answer = await response;
      expect(answer.status).toBe(status);
      expect(answer.headers.get('cache-control')).toBe('no-store');
      expect(await answer.json()).toEqual({ err, description: expect.any(String) });
    };

    // Addressed elsewhere, or from someone else.
    await refused(
      push(sign({ ...disabled, aud: 'https://another.example.test' })),
      400,
      'invalid_audience',
    );
    await refused(push(sign({ ...disabled, aud: undefined })), 400, 'invalid_audience');
    await refused(
      push(sign({ ...disabled, iss: 'https://evil.example.test' })),
      400,
      'invalid_issuer',
    );
    // Keys and algorithms: only the source's keys, only its algorithms, never keys named by the token.
    await refused(push(sign(disabled, {}, generateTestKey('ES384', 'idp-1'))), 400, 'invalid_key');
    await refused(
      push(sign(disabled, {}, { alg: 'HS256', secret: 'shared-secret' })),
      400,
      'invalid_key',
    );
    await refused(push(sign(disabled, {}, generateTestKey('RS256', 'idp-1'))), 400, 'invalid_key');
    await refused(push(sign(disabled, {}, generateTestKey('RS256', 'idp-2'))), 400, 'invalid_key');
    await refused(push(tamperPayload(sign(disabled), { jti: 'forged' })), 400, 'invalid_key');
    await refused(push(sign(disabled, {}, { alg: 'none' })), 400, 'invalid_request');
    for (const header of [
      { jwk: key.publicJwk },
      { jku: 'https://idp.example.test/keys' },
      { x5u: 'https://idp.example.test/cert.pem' },
      { x5c: ['MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA'] },
      { crit: ['exp'], exp: now + 60 },
    ])
      await refused(push(sign(disabled, header)), 400, 'invalid_request');
    // The token type.
    await refused(push(sign(disabled, { typ: 'JWT' })), 400, 'invalid_request');
    await refused(push(sign(disabled, { typ: undefined })), 400, 'invalid_request');
    // Claims: no nonce (ID tokens), exactly one event, a readable subject, a sane age.
    await refused(push(sign({ ...disabled, nonce: 'n-0S6_WzA2Mj' })), 400, 'invalid_request');
    await refused(
      push(
        sign({
          ...disabled,
          events: { [`${RISC}account-disabled`]: {}, [`${RISC}account-purged`]: {} },
        }),
      ),
      400,
      'invalid_request',
    );
    await refused(push(sign({ ...disabled, events: {} })), 400, 'invalid_request');
    await refused(push(sign({ ...disabled, events: undefined })), 400, 'invalid_request');
    await refused(
      push(sign({ ...disabled, sub_id: { format: 'email', email: 'not-an-address' } })),
      400,
      'invalid_request',
    );
    await refused(
      push(
        sign({
          ...disabled,
          sub: 'someone-else',
          sub_id: { format: 'iss_sub', iss: ISSUER, sub: 'someone' },
        }),
      ),
      400,
      'invalid_request',
    );
    await refused(push(sign({ ...disabled, iat: now - 8 * 86_400 })), 400, 'invalid_request');
    await refused(push(sign({ ...disabled, iat: now + 600 })), 400, 'invalid_request');
    await refused(push(sign({ ...disabled, exp: now - 600 })), 400, 'invalid_request');
    await refused(push(sign({ ...disabled, nbf: now + 600 })), 400, 'invalid_request');
    await refused(push(`${'a'.repeat(17_000)}.b.c`), 400, 'invalid_request');
    await refused(push('not a token'), 400, 'invalid_request');

    // The transport: bearer token, media type, size, method, stream.
    await refused(push(sign(disabled), { token: 'not-the-token' }), 401, 'authentication_failed');
    const anonymous = await push(sign(disabled), { token: null });
    expect(anonymous.status).toBe(401);
    expect(anonymous.headers.get('www-authenticate')).toBe('Bearer');
    await refused(push(sign(disabled), { type: 'application/json' }), 415, 'invalid_request');
    await refused(push(sign(disabled), { type: 'application/jwt' }), 415, 'invalid_request');
    await refused(push('x'.repeat(70_000)), 413, 'invalid_request');
    await refused(
      push(sign(disabled), { url: `http://localhost:3000/api/iam/signals/push/${randomUUID()}` }),
      404,
      'invalid_request',
    );
    const get = await push('', { method: 'GET' });
    expect(get.status).toBe(405);
    expect(get.headers.get('allow')).toBe('POST');

    // Nothing refused was recorded; the latest refusal is noted on the source.
    expect((await listEvents(f)).total).toBe(0);
    expect(
      (await f.iam.api.signals.getSource(f.ownerCredential, { tenantId: f.tenantId, sourceId }))
        .lastError,
    ).toEqual({ at: f.now(), message: expect.stringMatching(/^Refused an event: /) });

    // Accepted: an audience list naming this receiver, the issuer with a trailing slash, the media type spelling of
    // typ, a token days old (a transmitter's queue) or a little ahead of this clock.
    for (const set of [
      sign({ ...disabled, aud: ['https://another.example.test', AUDIENCE] }),
      sign({ ...disabled, iss: `${ISSUER}/` }),
      sign(disabled, { typ: 'application/secevent+jwt' }),
      sign({ ...disabled, iat: now - 6 * 86_400 }),
      sign({ ...disabled, iat: now + 120 }),
    ]) {
      const answer = await push(set);
      expect(answer.status).toBe(202);
      expect(answer.headers.get('cache-control')).toBe('no-store');
      expect(await answer.text()).toBe('');
    }
    // An event type the receiver does not know is kept, and ignored.
    expect(
      (await push(sign(event('https://example.test/event-type/custom', { detail: 1 })))).status,
    ).toBe(202);
    const page = await listEvents(f);
    expect(page.total).toBe(6);
    expect(page.events.filter((entry) => entry.eventType === 'unknown')).toEqual([
      expect.objectContaining({
        status: 'ignored',
        reason: 'unsupported-event',
        eventUri: 'https://example.test/event-type/custom',
        claims: { detail: 1 },
      }),
    ]);
    expect(
      page.events
        .filter((entry) => entry.eventType === 'account-disabled')
        .every((entry) => entry.status === 'unmatched' && entry.reason === 'no-match'),
    ).toBe(true);
  });

  it('tries each key of a source that could have signed a token without a kid', async () => {
    const f = await organizationFixture();
    const retired = generateTestKey('RS256');
    const current = generateTestKey('RS256');
    const withoutKid = ({ kid: _kid, ...jwk }: TestKey['publicJwk']) => jwk;
    const { sign, push } = await pushSource(f, {
      jwks: { keys: [withoutKid(retired.publicJwk), withoutKid(current.publicJwk)] as never },
    });
    const verification = event(`${SSF}verification`, { state: 'no-kid' });
    expect((await push(sign(verification, { kid: undefined }, current))).status).toBe(202);
    expect((await push(sign(verification, { kid: undefined }, retired))).status).toBe(202);
    const stranger = await push(sign(verification, { kid: undefined }, generateTestKey('RS256')));
    expect(stranger.status).toBe(400);
    expect(await stranger.json()).toMatchObject({ err: 'invalid_key' });
    expect((await listEvents(f)).total).toBe(2);
  });

  it('ends sessions only for configured event types, once per event, never for a protected identity', async () => {
    const f = await organizationFixture();
    const { sign, push, sourceId } = await pushSource(f, {
      subjects: { scimConnectionIds: ['okta-scim'] },
      actions: { 'session-revoked': 'revoke-sessions', 'credential-compromise': 'record' },
    });
    const alice = await f.member('alice');
    await linkScim(f, 'okta-scim', alice.id, '00u-alice');
    const first = bearer(await f.signIn('alice'));
    const second = bearer(await f.signIn('alice'));
    const aliceSubject = { format: 'iss_sub', iss: ISSUER, sub: '00u-alice' };

    // Recorded only: the sessions stay.
    expect(
      (
        await push(
          sign(
            event(`${RISC}credential-compromise`, { credential_type: 'password' }, aliceSubject),
          ),
        )
      ).status,
    ).toBe(202);
    expect((await f.iam.api.auth.getSession(first)).identity.id).toBe(alice.id);

    const revocation = sign(
      event(
        `${CAEP}session-revoked`,
        { event_timestamp: seconds(f), initiating_entity: 'policy' },
        aliceSubject,
      ),
    );
    expect((await push(revocation)).status).toBe(202);
    for (const credential of [first, second])
      await expect(f.iam.api.auth.getSession(credential)).rejects.toMatchObject({ status: 401 });
    expect(
      (await audit(f, f.tenantId, 'signal:revoke-sessions')).map((entry) => entry.metadata),
    ).toEqual([{ sourceId, eventType: 'session-revoked', jti: expect.any(String), revoked: 2 }]);

    // The same event again (a transmitter retrying): accepted, nothing happens twice.
    const again = bearer(await f.signIn('alice'));
    expect((await push(revocation)).status).toBe(202);
    expect((await f.iam.api.auth.getSession(again)).identity.id).toBe(alice.id);
    expect(await f.iam.signals.receive(sourceId, revocation)).toMatchObject({
      duplicate: true,
      status: 'applied',
      identityId: alice.id,
    });
    expect(await audit(f, f.tenantId, 'signal:revoke-sessions')).toHaveLength(1);
    expect(await audit(f, f.tenantId, 'signal:received')).toHaveLength(2);
    const page = await listEvents(f);
    expect(page.events.map((entry) => entry.status).sort()).toEqual(['applied', 'recorded']);
    const applied = page.events.find((entry) => entry.status === 'applied')!;
    expect(applied).toMatchObject({
      eventType: 'session-revoked',
      identityId: alice.id,
      eventTimestamp: seconds(f) * 1000,
      claims: { initiating_entity: 'policy' },
    });

    // A root administrator is never signed out by an organization's source.
    const bob = await f.member('bob');
    await linkScim(f, 'okta-scim', bob.id, '00u-bob');
    await f.signIn('bob');
    await f.iam.store.transaction(async (tx) => {
      const record = (await tx.get('identities', bob.id))!;
      await tx.put('identities', { ...record, rootAdmin: true });
    });
    const protectedReceipt = await f.iam.signals.receive(
      sourceId,
      sign(event(`${CAEP}session-revoked`, {}, { format: 'opaque', id: '00u-bob' })),
    );
    expect(protectedReceipt).toMatchObject({
      status: 'ignored',
      identityId: bob.id,
      duplicate: false,
    });
    expect(
      await f.iam.api.signals.getEvent(f.ownerCredential, {
        tenantId: f.tenantId,
        eventId: protectedReceipt.eventId,
      }),
    ).toMatchObject({ status: 'ignored', reason: 'protected' });
    expect(await f.iam.store.find('sessions', { identityId: bob.id })).toHaveLength(1);

    // An event about someone not mapped yet can be reprocessed once the mapping exists; the action runs then.
    const dan = await f.member('dan');
    const danSession = bearer(await f.signIn('dan'));
    const early = await f.iam.signals.receive(
      sourceId,
      sign(event(`${CAEP}session-revoked`, {}, { format: 'opaque', id: '00u-dan' })),
    );
    expect(early).toMatchObject({ status: 'unmatched' });
    await linkScim(f, 'okta-scim', dan.id, '00u-dan');
    const owner = await f.ownerSignIn();
    expect(
      await f.iam.api.signals.reprocess(owner, { tenantId: f.tenantId, eventId: early.eventId }),
    ).toMatchObject({ status: 'applied', identityId: dan.id, reprocessedBy: f.ownerId });
    await expect(f.iam.api.auth.getSession(danSession)).rejects.toMatchObject({ status: 401 });
    expect((await audit(f, f.tenantId, 'signal:reprocess')).map((entry) => entry.metadata)).toEqual(
      [
        {
          sourceId,
          eventType: 'session-revoked',
          jti: expect.any(String),
          previousStatus: 'unmatched',
          status: 'applied',
          identityId: dan.id,
        },
      ],
    );
    // Threat detection sees it with the identity now.
    expect(
      (await audit(f, f.tenantId, 'signal:received')).filter(
        (entry) => entry.metadata?.identityId === dan.id,
      ),
    ).toHaveLength(1);
    await expect(
      f.iam.api.signals.reprocess(owner, { tenantId: f.tenantId, eventId: early.eventId }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
  });

  it('accepts legacy RISC events (Google) from a source that does not require the SET type', async () => {
    const f = await organizationFixture();
    const google = generateTestKey('RS256', 'google-2026');
    const GOOGLE = 'https://accounts.google.com/';
    const CLIENT = '1234-web.apps.googleusercontent.com';
    const PERSON = '110169484474386276334';
    const owner = await f.ownerSignIn();
    const created = await f.iam.api.signals.createSource(owner, {
      tenantId: f.tenantId,
      name: 'Google',
      issuer: GOOGLE,
      audiences: [CLIENT],
      jwks: { keys: [google.publicJwk as never] },
      delivery: 'push',
      pushToken: false,
      subjects: { connectionIds: ['google'] },
      actions: { 'sessions-revoked': 'revoke-sessions' },
    });
    expect(created.source).toMatchObject({
      issuer: 'https://accounts.google.com',
      requireTyp: true,
      hasPushToken: false,
    });
    expect(created.pushToken).toBeUndefined();
    const paula = await f.member('paula');
    // Google ID tokens name the issuer without the trailing slash its RISC events use.
    await link(f, f.tenantId, 'google', 'https://accounts.google.com', PERSON, paula.id);
    const session = bearer(await f.signIn('paula'));

    // Google's shape: no typ, OAuth client ids as audiences, the subject inside the event (`subject_type`).
    const risc = (type: string, claims: Record<string, unknown>, header = { typ: undefined }) =>
      signTestJwt(
        google,
        {
          iss: GOOGLE,
          aud: [CLIENT, '5678-android.apps.googleusercontent.com'],
          iat: seconds(f),
          jti: randomUUID(),
          events: { [`${RISC}${type}`]: claims },
        },
        header,
      );
    const post = (body: string) =>
      f.iam.handler(
        new Request(created.pushUrl!, {
          method: 'POST',
          headers: { 'content-type': 'application/secevent+jwt' },
          body,
        }),
      );
    const revoked = risc('sessions-revoked', {
      subject: { subject_type: 'iss-sub', iss: GOOGLE, sub: PERSON },
    });
    const strict = await post(revoked);
    expect(strict.status).toBe(400);
    expect(await strict.json()).toMatchObject({ err: 'invalid_request' });

    await f.iam.api.signals.updateSource(owner, {
      tenantId: f.tenantId,
      sourceId: created.source.id,
      requireTyp: false,
    });
    expect((await post(revoked)).status).toBe(202);
    await expect(f.iam.api.auth.getSession(session)).rejects.toMatchObject({ status: 401 });
    const [record] = (await listEvents(f, { eventType: 'sessions-revoked' })).events;
    expect(record).toMatchObject({
      status: 'applied',
      identityId: paula.id,
      subject: { format: 'iss_sub', iss: GOOGLE, sub: PERSON },
    });
    expect(record!.claims).toEqual({});

    // Google's verification event lives under the RISC namespace.
    expect((await post(risc('verification', { state: 'check-1' }))).status).toBe(202);
    expect(
      (
        await f.iam.api.signals.getSource(owner, {
          tenantId: f.tenantId,
          sourceId: created.source.id,
        })
      ).lastVerifiedAt,
    ).toBe(f.now());
    // A plain JWT typ passes; other token types (an access token) never do.
    expect(
      (await post(risc('account-credential-change-required', {}, { typ: 'JWT' } as never))).status,
    ).toBe(202);
    expect(
      (await post(risc('account-credential-change-required', {}, { typ: 'at+jwt' } as never)))
        .status,
    ).toBe(400);
  });

  it('maps subjects to people of the source organization only: verified email domains, links, SCIM ids', async () => {
    const txt = new Map<string, string[][]>();
    const f = await organizationFixture({
      domains: { resolveTxt: async (name: string) => txt.get(name) ?? [] },
    });
    const beta = await secondOrganization(f);
    const { sign, sourceId } = await pushSource(f, {
      issuer: `${ISSUER}/`,
      subjects: {
        matchEmail: true,
        connectionIds: ['okta-oidc'],
        scimConnectionIds: ['okta-scim'],
      },
    });
    const receive = (subject?: Subject) =>
      f.iam.signals.receive(sourceId, sign(event(`${RISC}account-disabled`, {}, subject)));
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const carol = await f.member('carol');
    const dave = await f.iam.api.identities.create(f.ownerCredential, {
      tenantId: f.tenantId,
      email: 'dave@other.test',
      name: 'Dave',
    });

    // Email: only at a domain the organization proved it controls.
    expect(await receive({ format: 'email', email: 'alice@acme.test' })).toMatchObject({
      status: 'unmatched',
    });
    const claim = await f.iam.api.domains.add(f.ownerCredential, {
      tenantId: f.tenantId,
      domain: 'acme.test',
    });
    txt.set(claim.dnsRecord.name, [[claim.dnsRecord.value]]);
    expect(
      await f.iam.api.domains.verify(f.ownerCredential, {
        tenantId: f.tenantId,
        domainId: claim.id,
      }),
    ).toMatchObject({ verified: true });
    expect(await receive({ format: 'email', email: 'Alice@ACME.test' })).toMatchObject({
      status: 'recorded',
      identityId: alice.id,
    });
    expect(await receive({ format: 'account', uri: 'acct:alice@acme.test' })).toMatchObject({
      identityId: alice.id,
    });
    expect(await receive({ format: 'email', email: 'dave@other.test' })).toMatchObject({
      status: 'unmatched',
    });
    // Someone of another organization with an address at the domain is never matched.
    await f.iam.api.identities.create(await beta.ownerSignIn(), {
      tenantId: beta.tenantId,
      email: 'erin@acme.test',
      name: 'Erin',
    });
    expect(await receive({ format: 'email', email: 'erin@acme.test' })).toMatchObject({
      status: 'unmatched',
    });

    // iss_sub: a federation link of a configured connection, for the source's issuer in either spelling.
    await link(f, f.tenantId, 'okta-oidc', ISSUER, '00u-bob', bob.id);
    for (const iss of [ISSUER, `${ISSUER}/`])
      expect(await receive({ format: 'iss_sub', iss, sub: '00u-bob' })).toMatchObject({
        status: 'recorded',
        identityId: bob.id,
      });
    // Not another issuer's subject, not a link of a connection the source does not name, not another
    // organization's link.
    await link(f, f.tenantId, 'okta-oidc', 'https://other-idp.example.test', '00u-bob', bob.id);
    expect(
      await receive({ format: 'iss_sub', iss: 'https://other-idp.example.test', sub: '00u-bob' }),
    ).toMatchObject({ status: 'unmatched' });
    await link(f, f.tenantId, 'saml-partner', ISSUER, '00u-dave', dave.id);
    expect(await receive({ format: 'iss_sub', iss: ISSUER, sub: '00u-dave' })).toMatchObject({
      status: 'unmatched',
    });
    const frank = await f.iam.api.identities.create(await beta.ownerSignIn(), {
      tenantId: beta.tenantId,
      email: 'frank@beta.test',
      name: 'Frank',
    });
    await link(f, beta.tenantId, 'okta-oidc', ISSUER, '00u-frank', frank.id);
    expect(await receive({ format: 'iss_sub', iss: ISSUER, sub: '00u-frank' })).toMatchObject({
      status: 'unmatched',
    });

    // SCIM externalId: as iss_sub, opaque, a complex subject's user, or one alias among others.
    await linkScim(f, 'okta-scim', carol.id, '00u-carol');
    for (const subject of [
      { format: 'iss_sub', iss: ISSUER, sub: '00u-carol' },
      { format: 'opaque', id: '00u-carol' },
      {
        format: 'complex',
        user: { format: 'opaque', id: '00u-carol' },
        session: { format: 'opaque', id: 'sid-1' },
      },
      {
        format: 'aliases',
        identifiers: [
          { format: 'phone_number', phone_number: '+15555550100' },
          { format: 'opaque', id: '00u-carol' },
        ],
      },
    ])
      expect(await receive(subject)).toMatchObject({ status: 'recorded', identityId: carol.id });
    await linkScim(f, 'other-scim', dave.id, '00u-dave-2');
    expect(await receive({ format: 'opaque', id: '00u-dave-2' })).toMatchObject({
      status: 'unmatched',
    });
    // Subjects that name no person, and no subject at all.
    expect(
      await receive({ format: 'complex', session: { format: 'opaque', id: 'sid-1' } }),
    ).toMatchObject({ status: 'unmatched' });
    const anonymous = await receive();
    expect(
      await f.iam.api.signals.getEvent(f.ownerCredential, {
        tenantId: f.tenantId,
        eventId: anonymous.eventId,
      }),
    ).toMatchObject({ status: 'unmatched', reason: 'no-subject' });

    // Turning email matching off stops email matches; the rest of the mapping stays.
    await f.iam.api.signals.updateSource(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      sourceId,
      subjects: { matchEmail: false },
    });
    expect(await receive({ format: 'email', email: 'alice@acme.test' })).toMatchObject({
      status: 'unmatched',
    });
    expect(await receive({ format: 'opaque', id: '00u-carol' })).toMatchObject({
      identityId: carol.id,
    });
    expect((await listEvents(f, { identityId: carol.id })).total).toBe(5);
  });

  it('audits every received event as signal:received with what threat detection needs', async () => {
    const f = await organizationFixture();
    const { sign, sourceId } = await pushSource(f, {
      subjects: { scimConnectionIds: ['okta-scim'] },
    });
    const alice = await f.member('alice');
    await linkScim(f, 'okta-scim', alice.id, '00u-alice');
    const subject = { format: 'opaque', id: '00u-alice' };
    const receive = (type: string, claims: Record<string, unknown>, about: Subject = subject) =>
      f.iam.signals.receive(sourceId, sign(event(type, claims, about)));
    const compromise = await receive(`${RISC}credential-compromise`, {
      credential_type: 'password',
      reason_admin: { de: 'In einem Datenleck gefunden', en: 'Found in a breach corpus' },
      reason_user: { en: 'Your password appeared in a breach' },
    });
    await receive(`${CAEP}risk-level-change`, {
      current_level: 'high',
      previous_level: 'low',
      risk_reason: 'PASSWORD_FOUND_IN_DATA_BREACH',
      principal: 'USER',
    });
    await receive(
      `${RISC}account-disabled`,
      { reason: 'hijacking', reason_admin: 'x'.repeat(300) },
      { format: 'opaque', id: 'nobody' },
    );
    const trail = await audit(f, f.tenantId, 'signal:received');
    expect(trail).toHaveLength(3);
    const about = (type: string) => trail.find((entry) => entry.metadata?.eventType === type)!;
    const { jti } = await f.iam.api.signals.getEvent(f.ownerCredential, {
      tenantId: f.tenantId,
      eventId: compromise.eventId,
    });
    expect(about('credential-compromise')).toMatchObject({
      actorId: `signal:${sourceId}`,
      resourceId: alice.id,
      outcome: 'allow',
    });
    expect(about('credential-compromise').metadata).toEqual({
      sourceId,
      eventType: 'credential-compromise',
      jti,
      status: 'recorded',
      identityId: alice.id,
      credentialType: 'password',
      reasonAdmin: 'Found in a breach corpus',
    });
    expect(about('risk-level-change').metadata).toEqual({
      sourceId,
      eventType: 'risk-level-change',
      jti: expect.any(String),
      status: 'recorded',
      identityId: alice.id,
      currentLevel: 'HIGH',
    });
    const unmatched = about('account-disabled');
    expect(unmatched.resourceId).toBe(`signals/sources/${sourceId}`);
    expect(unmatched.metadata).toEqual({
      sourceId,
      eventType: 'account-disabled',
      jti: expect.any(String),
      status: 'unmatched',
      reasonAdmin: 'x'.repeat(256),
    });
  });

  it("discovers a source's keys and answers 503 while they cannot be fetched", async () => {
    const f = await organizationFixture({ signals: { allowInsecureLocalhost: true } });
    const key = generateTestKey('EdDSA', 'edge-1');
    const idp = { keys: 500, discovery: 0 };
    const base = await listen((request, _body, response) => {
      if (request.url === '/.well-known/ssf-configuration/tenant') {
        idp.discovery++;
        return reply(response, 200, {
          spec_version: '1_0',
          issuer: `${base}/tenant`,
          jwks_uri: `${base}/keys`,
          delivery_methods_supported: ['urn:ietf:rfc:8935'],
        });
      }
      if (request.url === '/.well-known/ssf-configuration/impostor')
        return reply(response, 200, {
          issuer: 'https://someone-else.example.test',
          jwks_uri: `${base}/keys`,
        });
      if (request.url === '/keys')
        return idp.keys === 200
          ? reply(response, 200, { keys: [key.publicJwk] })
          : reply(response, idp.keys, { error: 'unavailable' });
      reply(response, 404, {});
    });
    const owner = await f.ownerSignIn();
    const create = (path: string) =>
      f.iam.api.signals.createSource(owner, {
        tenantId: f.tenantId,
        name: path,
        issuer: `${base}/${path}`,
        audiences: ['rp'],
        delivery: 'push',
        pushToken: false,
      });
    const post = (url: string, body: string) =>
      f.iam.handler(
        new Request(url, {
          method: 'POST',
          headers: { 'content-type': 'application/secevent+jwt' },
          body,
        }),
      );
    const verification = (issuer: string, signer: TestKey = key) =>
      signTestJwt(
        signer,
        {
          iss: issuer,
          aud: 'rp',
          iat: seconds(f),
          jti: randomUUID(),
          ...event(`${SSF}verification`),
        },
        { typ: 'secevent+jwt' },
      );
    const tenant = await create('tenant');

    // The key set answers 500: a temporary refusal, so the transmitter delivers again.
    const unavailable = await post(tenant.pushUrl!, verification(`${base}/tenant`));
    expect(unavailable.status).toBe(503);
    expect(unavailable.headers.get('retry-after')).toBe('30');
    expect(await unavailable.json()).toMatchObject({ err: 'invalid_key' });
    // Once it answers: accepted; the discovery document was read once.
    idp.keys = 200;
    expect((await post(tenant.pushUrl!, verification(`${base}/tenant`))).status).toBe(202);
    expect((await post(tenant.pushUrl!, verification(`${base}/tenant`))).status).toBe(202);
    expect(idp.discovery).toBe(1);
    // A key the fetched set does not have yet (a transmitter that just rotated) is retried later too.
    const rotated = await post(
      tenant.pushUrl!,
      verification(`${base}/tenant`, generateTestKey('EdDSA', 'edge-2')),
    );
    expect(rotated.status).toBe(503);
    expect(await rotated.json()).toMatchObject({ err: 'invalid_key' });

    // A discovery document naming another issuer is not trusted.
    const impostor = await create('impostor');
    expect((await post(impostor.pushUrl!, verification(`${base}/impostor`))).status).toBe(503);
    expect(
      (
        await f.iam.api.signals.getSource(owner, {
          tenantId: f.tenantId,
          sourceId: impostor.source.id,
        })
      ).lastError?.message,
    ).toContain('could not be obtained');

    // Key URLs on private addresses are refused at registration (only loopback is allowed here).
    for (const jwksUri of ['https://10.0.0.8/keys', 'https://169.254.169.254/latest/keys'])
      await expect(
        f.iam.api.signals.createSource(owner, {
          tenantId: f.tenantId,
          name: 'Internal',
          issuer: 'https://internal.example.test',
          audiences: ['rp'],
          jwksUri,
          delivery: 'push',
        }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(f.iam.signals.receive(randomUUID(), 'x.y.z')).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
  });

  it('polls an RFC 8936 transmitter, acknowledging committed events with the next request', async () => {
    const f = await organizationFixture({ signals: { allowInsecureLocalhost: true } });
    const key = generateTestKey('ES256', 'poll-1');
    const requests: { authorization?: string; type?: string; body: Record<string, unknown> }[] = [];
    const replies: { status?: number; body?: unknown }[] = [];
    const base = await listen((request, body, response) => {
      if (request.url !== '/poll' || request.method !== 'POST') return reply(response, 404, {});
      requests.push({
        authorization: request.headers.authorization,
        type: request.headers['content-type'],
        body: JSON.parse(body),
      });
      const next = replies.shift() ?? { body: { sets: {}, moreAvailable: false } };
      reply(response, next.status ?? 200, next.body ?? {});
    });
    const polled = (jti: string) =>
      securityEvent(f, key, {
        jti,
        ...event(`${RISC}account-disabled`, {}, { format: 'opaque', id: 'nobody' }),
      });
    const owner = await f.ownerSignIn();
    const created = await f.iam.api.signals.createSource(owner, {
      tenantId: f.tenantId,
      name: 'Poller',
      issuer: ISSUER,
      audiences: [AUDIENCE],
      jwks: { keys: [key.publicJwk as never] },
      delivery: 'poll',
      poll: { endpoint: `${base}/poll`, token: 'poll-secret-token', maxEvents: 10 },
    });
    const sourceId = created.source.id;
    const source = () =>
      f.iam.api.signals.getSource(f.ownerCredential, { tenantId: f.tenantId, sourceId });
    expect(created.pushUrl).toBeUndefined();
    expect(created.pushToken).toBeUndefined();
    expect(created.source.poll).toEqual({
      endpoint: `${base}/poll`,
      maxEvents: 10,
      pendingAcks: 0,
    });
    // The poll token is stored sealed and never shown.
    expect(JSON.stringify(created)).not.toContain('poll-secret-token');
    expect(JSON.stringify(await f.iam.store.get('signalSources', sourceId))).not.toContain(
      'poll-secret-token',
    );
    // A poll source takes no pushes.
    const pushed = await f.iam.handler(
      new Request(`http://localhost:3000/api/iam/signals/push/${sourceId}`, {
        method: 'POST',
        headers: { 'content-type': 'application/secevent+jwt' },
        body: polled('pushed'),
      }),
    );
    expect(pushed.status).toBe(404);

    // One run: two requests (moreAvailable), the second acknowledging what the first returned.
    replies.push(
      { body: { sets: { a: polled('a'), b: polled('b') }, moreAvailable: true } },
      { body: { sets: { c: polled('c'), bad: 'x.y.z', mismatched: polled('other') } } },
    );
    expect(await f.iam.signals.poll()).toEqual({
      sources: 1,
      received: 3,
      acknowledged: 2,
      errors: 0,
    });
    expect(requests[0]).toEqual({
      authorization: 'Bearer poll-secret-token',
      type: 'application/json',
      body: { maxEvents: 10, returnImmediately: true, ack: [] },
    });
    expect(requests[1]!.body).toEqual({ maxEvents: 10, returnImmediately: true, ack: ['a', 'b'] });
    expect((await source()).poll).toMatchObject({ pendingAcks: 1, lastPolledAt: f.now() });

    // The transmitter fails: acknowledgements and errors wait for the next run.
    const setErrs = {
      bad: { err: 'invalid_request', description: expect.any(String) },
      mismatched: { err: 'invalid_request', description: expect.any(String) },
    };
    replies.push({ status: 500, body: {} });
    expect(await f.iam.api.signals.poll(owner, { tenantId: f.tenantId, sourceId })).toEqual({
      sources: 1,
      received: 0,
      acknowledged: 0,
      errors: 1,
    });
    expect(requests[2]!.body).toEqual({
      maxEvents: 10,
      returnImmediately: true,
      ack: ['c'],
      setErrs,
    });
    expect(await source()).toMatchObject({
      lastError: { message: 'The poll endpoint answered 500' },
      poll: { pendingAcks: 1 },
    });

    // A redelivered event is acknowledged again but recorded once.
    replies.push({ body: { sets: { a: polled('a') }, moreAvailable: false } });
    expect(await f.iam.signals.poll({ sourceId })).toEqual({
      sources: 1,
      received: 0,
      acknowledged: 1,
      errors: 0,
    });
    expect(requests[3]!.body).toEqual({
      maxEvents: 10,
      returnImmediately: true,
      ack: ['c'],
      setErrs,
    });

    // More than a run's worth: at most five requests per source per run.
    for (let index = 0; index < 8; index++)
      replies.push({
        body: { sets: { [`e${index}`]: polled(`e${index}`) }, moreAvailable: true },
      });
    const before = requests.length;
    expect(await f.iam.signals.poll()).toEqual({
      sources: 1,
      received: 5,
      acknowledged: 5,
      errors: 0,
    });
    expect(requests.length - before).toBe(5);
    expect(requests[before]!.body.ack).toEqual(['a']);
    expect(requests.at(-1)!.body.ack).toEqual(['e3']);
    expect((await listEvents(f, { sourceId })).total).toBe(8);
    replies.length = 0;

    // Disabled sources are not polled; push sources cannot be.
    await f.iam.api.signals.updateSource(owner, {
      tenantId: f.tenantId,
      sourceId,
      status: 'disabled',
    });
    expect(await f.iam.signals.poll()).toEqual({
      sources: 0,
      received: 0,
      acknowledged: 0,
      errors: 0,
    });
    await expect(
      f.iam.api.signals.poll(owner, { tenantId: f.tenantId, sourceId }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    const push = await f.iam.api.signals.createSource(owner, {
      tenantId: f.tenantId,
      name: 'Pusher',
      issuer: 'https://push.example.test',
      audiences: [AUDIENCE],
      jwks: { keys: [key.publicJwk as never] },
      delivery: 'push',
    });
    await expect(
      f.iam.api.signals.poll(owner, { tenantId: f.tenantId, sourceId: push.source.id }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // A new poll endpoint needs its token again.
    await expect(
      f.iam.api.signals.updateSource(owner, {
        tenantId: f.tenantId,
        sourceId,
        poll: { endpoint: `${base}/poll/v2` },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(
      await f.iam.api.signals.updateSource(owner, {
        tenantId: f.tenantId,
        sourceId,
        poll: { endpoint: `${base}/poll/v2`, token: 'another-token' },
      }),
    ).toMatchObject({ poll: { endpoint: `${base}/poll/v2`, pendingAcks: 0 } });
  });

  it("leaves polled events unacknowledged while the source's keys cannot be fetched", async () => {
    const f = await organizationFixture({ signals: { allowInsecureLocalhost: true } });
    const key = generateTestKey('PS256', 'poll-2');
    const idp = { keys: 503 };
    const acks: unknown[] = [];
    const set = securityEvent(f, key, { jti: 'k1', ...event(`${RISC}account-enabled`) });
    const base = await listen((request, body, response) => {
      if (request.url === '/keys')
        return idp.keys === 200
          ? reply(response, 200, { keys: [key.publicJwk] })
          : reply(response, idp.keys, {});
      const { ack, setErrs } = JSON.parse(body) as { ack: string[]; setErrs?: unknown };
      acks.push({ ack, setErrs });
      // Unacknowledged events come back until acknowledged.
      reply(response, 200, { sets: ack.includes('k1') ? {} : { k1: set } });
    });
    const created = await f.iam.api.signals.createSource(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      name: 'Poller',
      issuer: ISSUER,
      audiences: [AUDIENCE],
      jwksUri: `${base}/keys`,
      algorithms: ['PS256'],
      delivery: 'poll',
      poll: { endpoint: `${base}/poll`, token: 'poll-token' },
    });
    expect(await f.iam.signals.poll()).toEqual({
      sources: 1,
      received: 0,
      acknowledged: 0,
      errors: 1,
    });
    idp.keys = 200;
    expect(await f.iam.signals.poll()).toEqual({
      sources: 1,
      received: 1,
      acknowledged: 0,
      errors: 0,
    });
    expect(await f.iam.signals.poll()).toMatchObject({ received: 0, acknowledged: 1 });
    // Neither acknowledged nor reported as an error while the keys were missing.
    expect(acks).toEqual([
      { ack: [], setErrs: undefined },
      { ack: [], setErrs: undefined },
      { ack: ['k1'], setErrs: undefined },
    ]);
    expect((await listEvents(f, { sourceId: created.source.id })).events).toEqual([
      expect.objectContaining({ jti: 'k1', eventType: 'account-enabled', status: 'unmatched' }),
    ]);
  });

  it('re-seals the poll token when the deployment secret rotates', async () => {
    const f = await organizationFixture({ signals: { allowInsecureLocalhost: true } });
    const key = generateTestKey('ES256', 'poll-3');
    const authorizations: (string | undefined)[] = [];
    const base = await listen((request, _body, response) => {
      authorizations.push(request.headers.authorization);
      if (request.headers.authorization !== 'Bearer rotating-poll-token')
        return reply(response, 401, {});
      reply(response, 200, { sets: {}, moreAvailable: false });
    });
    const created = await f.iam.api.signals.createSource(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      name: 'Poller',
      issuer: ISSUER,
      audiences: [AUDIENCE],
      jwks: { keys: [key.publicJwk as never] },
      delivery: 'poll',
      poll: { endpoint: `${base}/poll`, token: 'rotating-poll-token' },
    });
    const NEW_SECRET = 'a-new-deployment-secret-with-32-characters!!';
    const deployment = (secret: string, previousSecrets?: string[]) =>
      betterIam({
        database: f.database,
        secret,
        ...(previousSecrets ? { previousSecrets } : {}),
        baseURL: 'http://localhost:3000',
        signals: { allowInsecureLocalhost: true },
      });
    // During the rotation the token still opens with the previous secret, and is re-sealed.
    const during = deployment(NEW_SECRET, [FIXTURE_SECRET]);
    expect(await during.signals.poll()).toMatchObject({ sources: 1, errors: 0 });
    expect((await during.rotateSecrets()).resealed.signalSources).toBe(1);
    // The old deployment can no longer open it; the new secret alone can.
    expect(await f.iam.signals.poll()).toMatchObject({ sources: 1, errors: 1 });
    expect(
      (
        await f.iam.api.signals.getSource(f.ownerCredential, {
          tenantId: f.tenantId,
          sourceId: created.source.id,
        })
      ).lastError?.message,
    ).toContain('sealed with a secret that is gone');
    expect(await deployment(NEW_SECRET).signals.poll()).toMatchObject({ sources: 1, errors: 0 });
    expect(authorizations).toEqual(['Bearer rotating-poll-token', 'Bearer rotating-poll-token']);
  });

  it('guards and validates the signals API', async () => {
    const f = await organizationFixture({ signals: { allowInsecureLocalhost: true } });
    const beta = await secondOrganization(f);
    const key = generateTestKey('RS256', 'api-1');
    const owner = await f.ownerSignIn();
    const base: SignalSourceCreateInput = {
      tenantId: f.tenantId,
      name: 'IdP',
      issuer: ISSUER,
      audiences: [AUDIENCE],
      jwks: { keys: [key.publicJwk as never] },
      delivery: 'push',
    };
    const created = await f.iam.api.signals.createSource(owner, base);
    const sourceId = created.source.id;

    // The push token is shown once; views never carry it, its hash or a sealed token.
    const view = await f.iam.api.signals.getSource(f.ownerCredential, {
      tenantId: f.tenantId,
      sourceId,
    });
    expect(view).toMatchObject({
      hasPushToken: true,
      requireTyp: true,
      status: 'active',
      algorithms: ['RS256', 'ES256', 'PS256', 'EdDSA'],
      subjects: { connectionIds: [], matchEmail: false, scimConnectionIds: [] },
      actions: {},
      pushUrl: created.pushUrl,
      createdBy: f.ownerId,
    });
    expect(view).not.toHaveProperty('pushTokenHash');
    expect(JSON.stringify(view)).not.toContain(created.pushToken!);
    expect(
      await f.iam.api.signals.listSources(f.ownerCredential, { tenantId: f.tenantId }),
    ).toEqual([view]);

    // People without the permission, and other organizations, are refused.
    await f.member('eve');
    const eve = bearer(await f.signIn('eve'));
    await expect(
      f.iam.api.signals.listSources(eve, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(f.iam.api.signals.listEvents(eve, { tenantId: f.tenantId })).rejects.toMatchObject(
      { code: 'ACCESS_DENIED' },
    );
    await expect(
      f.iam.api.signals.createSource(eve, { ...base, issuer: 'https://eve.example.test' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const betaOwner = await beta.ownerSignIn();
    await expect(
      f.iam.api.signals.getSource(betaOwner, { tenantId: f.tenantId, sourceId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.signals.getSource(betaOwner, { tenantId: beta.tenantId, sourceId }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      f.iam.api.signals.deleteSource(betaOwner, { tenantId: beta.tenantId, sourceId }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });

    // Input validation.
    const poll = { endpoint: 'https://idp.example.test/poll', token: 'poll-token' };
    for (const input of [
      { issuer: 'http://idp.example.test' },
      { issuer: 'https://idp.example.test/?tenant=1' },
      { issuer: 'not a url' },
      { name: '' },
      { audiences: [] },
      { audiences: Array.from({ length: 11 }, (_, index) => `aud-${index}`) },
      { algorithms: ['HS256'] },
      { algorithms: ['none'] },
      { algorithms: [] },
      { jwks: { keys: [key.privateJwk] } },
      { jwks: { keys: [] } },
      { jwksUri: 'https://idp.example.test/keys' },
      { jwks: undefined, jwksUri: 'https://10.1.2.3/keys' },
      { jwks: undefined, jwksUri: 'http://keys.example.test/jwks' },
      { delivery: 'email' },
      { delivery: 'poll' },
      { delivery: 'poll', poll: { ...poll, token: 'has a space' } },
      { delivery: 'poll', poll: { ...poll, maxEvents: 0 } },
      { delivery: 'poll', poll: { ...poll, endpoint: 'https://192.168.1.10/poll' } },
      { delivery: 'poll', poll: { ...poll, extra: true } },
      { delivery: 'poll', poll, pushToken: true },
      { poll },
      { subjects: { emails: true } },
      { subjects: { matchEmail: 'yes' } },
      { subjects: { connectionIds: 'okta' } },
      { actions: { verification: 'revoke-sessions' } },
      { actions: { 'session-revoked': 'disable' } },
      { actions: { 'made-up': 'record' } },
      { requireTyp: 'no' },
      { issuerAliases: ['http://alias.example.test'] },
      {
        issuerAliases: Array.from(
          { length: 6 },
          (_, index) => `https://alias${index}.example.test`,
        ),
      },
    ])
      await expect(
        f.iam.api.signals.createSource(owner, {
          ...base,
          issuer: 'https://new.example.test',
          ...input,
        } as never),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    // One source per issuer (trailing slashes aside), twenty per organization; another organization has its own.
    await expect(
      f.iam.api.signals.createSource(owner, { ...base, issuer: `${ISSUER}/` }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    for (let index = 1; index < 20; index++)
      await f.iam.api.signals.createSource(owner, {
        ...base,
        issuer: `https://idp${index}.example.test`,
        pushToken: false,
      });
    await expect(
      f.iam.api.signals.createSource(owner, { ...base, issuer: 'https://idp20.example.test' }),
    ).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    await f.iam.api.signals.createSource(betaOwner, { ...base, tenantId: beta.tenantId });

    // Updates: the issuer, delivery and push token cannot change here; an update must change something.
    const update = (input: Record<string, unknown>, credential = owner) =>
      f.iam.api.signals.updateSource(credential, {
        tenantId: f.tenantId,
        sourceId,
        ...input,
      } as never);
    for (const input of [
      { issuer: 'https://other.example.test' },
      { delivery: 'poll' },
      { pushToken: true },
      {},
      { name: 'IdP' },
      { poll: { maxEvents: 5 } },
      { status: 'paused' },
      { jwksUri: 'https://idp.example.test/keys' },
    ])
      await expect(update(input)).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    // A session past its recent sign-in may read but not change.
    f.advance(6 * 60_000);
    await expect(update({ name: 'Renamed' })).rejects.toMatchObject({
      code: 'RECENT_AUTH_REQUIRED',
    });
    await expect(
      f.iam.api.signals.rotatePushToken(owner, { tenantId: f.tenantId, sourceId }),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
    expect(await f.iam.api.signals.listSources(owner, { tenantId: f.tenantId })).toHaveLength(20);
    const fresh = await f.ownerSignIn();

    // Rotating the push token: the old one stops working at once.
    const push = (secret: string | undefined) =>
      f.iam.handler(
        new Request(created.pushUrl!, {
          method: 'POST',
          headers: {
            'content-type': 'application/secevent+jwt',
            ...(secret ? { authorization: `Bearer ${secret}` } : {}),
          },
          body: securityEvent(f, key, event(`${SSF}verification`, { state: 'x' })),
        }),
      );
    expect((await push(created.pushToken)).status).toBe(202);
    const { pushToken } = await f.iam.api.signals.rotatePushToken(fresh, {
      tenantId: f.tenantId,
      sourceId,
    });
    expect(pushToken).not.toBe(created.pushToken);
    expect((await push(created.pushToken)).status).toBe(401);
    expect((await push(pushToken)).status).toBe(202);

    // Disabled, a source's pushes answer 404 until it is enabled again.
    expect(await update({ status: 'disabled' }, fresh)).toMatchObject({ status: 'disabled' });
    expect((await push(pushToken)).status).toBe(404);
    expect(
      await update(
        {
          status: 'active',
          name: 'Renamed IdP',
          audiences: [AUDIENCE, 'https://rp2.example.test'],
          subjects: { matchEmail: true },
          actions: { 'credential-compromise': 'revoke-sessions' },
        },
        fresh,
      ),
    ).toMatchObject({
      status: 'active',
      name: 'Renamed IdP',
      subjects: { matchEmail: true, connectionIds: [] },
      actions: { 'credential-compromise': 'revoke-sessions' },
      updatedBy: f.ownerId,
    });
    expect((await push(pushToken)).status).toBe(202);
    expect((await audit(f, f.tenantId, 'signal:source-update')).at(-1)!.metadata).toEqual({
      changed: ['name', 'audiences', 'subjects', 'actions', 'status'],
    });

    // Received events: paged, filtered, one at a time, not across organizations.
    const page = await f.iam.api.signals.listEvents(fresh, {
      tenantId: f.tenantId,
      sourceId,
      eventType: 'verification',
      limit: 2,
    });
    expect(page.total).toBe(3);
    expect(page.events).toHaveLength(2);
    const eventId = page.events[0]!.id;
    expect(await f.iam.api.signals.getEvent(fresh, { tenantId: f.tenantId, eventId })).toEqual(
      page.events[0],
    );
    await expect(
      f.iam.api.signals.getEvent(betaOwner, { tenantId: beta.tenantId, eventId }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    for (const input of [{ status: 'odd' }, { eventType: 'made-up' }, { limit: 0 }, { offset: -1 }])
      await expect(
        f.iam.api.signals.listEvents(fresh, { tenantId: f.tenantId, ...input } as never),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Only unmatched and failed events can be reprocessed.
    await expect(
      f.iam.api.signals.reprocess(fresh, { tenantId: f.tenantId, eventId }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });

    // Over HTTP as well.
    const http = await f.iam.handler(
      new Request('http://localhost:3000/api/iam/signals/listSources', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-better-iam': '1',
          authorization: `Bearer ${fresh.token}`,
        },
        body: JSON.stringify({ tenantId: f.tenantId }),
      }),
    );
    expect(http.status).toBe(200);
    const { data } = (await http.json()) as { data: unknown[] };
    expect(data).toHaveLength(20);
    expect(JSON.stringify(data)).not.toContain(pushToken);

    // Deleted: pushes answer 404; its events stay until the retention sweep.
    expect(await f.iam.api.signals.deleteSource(fresh, { tenantId: f.tenantId, sourceId })).toEqual(
      { deleted: true },
    );
    expect((await push(pushToken)).status).toBe(404);
    expect((await listEvents(f, { sourceId })).total).toBe(3);
    const actions = new Set(
      (await f.iam.store.find<AuditEvent>('audit', { tenantId: f.tenantId })).map(
        (entry) => entry.action,
      ),
    );
    for (const action of [
      'signal:source-create',
      'signal:source-update',
      'signal:source-rotate',
      'signal:source-delete',
    ])
      expect(actions.has(action)).toBe(true);
  });

  it('validates the signals deployment option and serves a custom push path', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    try {
      for (const signals of [
        { pushPath: 'signals/push' },
        { pushPath: '/signals/push/' },
        { pushPath: '/signals//push' },
        { pushPath: '/signals push' },
        { allowPrivateNetworks: 'yes' },
        { allowInsecureLocalhost: 1 },
        'on',
      ])
        expect(() =>
          betterIam({
            database,
            secret: FIXTURE_SECRET,
            baseURL: 'http://localhost:3000',
            signals,
          } as never),
        ).toThrowError(
          expect.objectContaining({
            code: 'INVALID_CONFIG',
            message: expect.stringMatching(/^signals/),
          }),
        );
    } finally {
      await database.close();
    }

    const f = await organizationFixture({ signals: { pushPath: '/ssf/push' } });
    const { created, sign, push } = await pushSource(f);
    expect(created.pushUrl).toBe(`http://localhost:3000/ssf/push/${created.source.id}`);
    expect((await push(sign(event(`${SSF}verification`)))).status).toBe(202);
    const moved = await push(sign(event(`${SSF}verification`)), {
      url: `http://localhost:3000/api/iam/signals/push/${created.source.id}`,
    });
    expect(moved.status).not.toBe(202);
    expect((await listEvents(f)).total).toBe(1);
  });

  it('turns upstream compromise and risk reports into threat detections for the matched person', async () => {
    const f = await organizationFixture();
    const { sign, push } = await pushSource(f, { subjects: { scimConnectionIds: ['okta-scim'] } });
    const alice = await f.member('alice');
    await linkScim(f, 'okta-scim', alice.id, '00u-alice');
    const aliceSubject = { format: 'iss_sub', iss: ISSUER, sub: '00u-alice' };
    await f.iam.detectThreats({ tenantId: f.tenantId });
    for (const signal of [
      event(`${RISC}credential-compromise`, { credential_type: 'password' }, aliceSubject),
      event(`${CAEP}risk-level-change`, { current_level: 'LOW' }, aliceSubject),
      event(`${CAEP}session-revoked`, { event_timestamp: seconds(f) }, aliceSubject),
      event(`${CAEP}risk-level-change`, { current_level: 'MEDIUM' }, aliceSubject),
    ])
      expect((await push(sign(signal))).status).toBe(202);
    await f.iam.detectThreats({ tenantId: f.tenantId });
    const detections = await f.iam.api.threats.listDetections(f.ownerCredential, {
      tenantId: f.tenantId,
      ruleId: 'upstream-signal',
    });
    // Low risk and session revocations raise nothing.
    expect(
      detections.detections
        .map((entry) => [entry.severity, entry.identityId, entry.metadata?.eventType])
        .sort(),
    ).toEqual([
      ['high', alice.id, 'credential-compromise'],
      ['medium', alice.id, 'risk-level-change'],
    ]);
    const risk = await f.iam.api.threats.getRisk(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.id,
    });
    expect(risk.level).toBe('high');
  });

  it('binds a source to one organization of a shared issuer through the tenant_id claim', async () => {
    const f = await organizationFixture();
    // A Better IAM transmitter signs every organization's events with one issuer and key.
    const { sign, push, sourceId } = await pushSource(f, { tenantClaim: 'org-acme' });
    const verification = (claims: Record<string, unknown> = {}) =>
      sign({ ...event(`${SSF}verification`), ...claims });
    expect((await push(verification({ tenant_id: 'org-acme' }))).status).toBe(202);
    for (const claims of [{ tenant_id: 'org-other' }, {}, { tenant_id: 42 }]) {
      const refused = await push(verification(claims));
      expect(refused.status).toBe(400);
      expect(await refused.json()).toMatchObject({ err: 'invalid_audience' });
    }
    expect((await listEvents(f)).total).toBe(1);
    const owner = await f.ownerSignIn();
    const view = await f.iam.api.signals.getSource(owner, { tenantId: f.tenantId, sourceId });
    expect(view.tenantClaim).toBe('org-acme');
    // Clearing the binding accepts SETs without the claim again.
    const cleared = await f.iam.api.signals.updateSource(owner, {
      tenantId: f.tenantId,
      sourceId,
      tenantClaim: null,
    });
    expect(cleared).not.toHaveProperty('tenantClaim');
    expect((await push(verification())).status).toBe(202);
  });
});
