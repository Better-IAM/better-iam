import { generateKeyPairSync } from 'node:crypto';
import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import type { JWK } from 'jose';
import { presentSdJwt, readDisclosure, readStatusList, splitSdJwt, statusAt } from '@better-iam/server';
import { closeFixtures, organizationFixture, type OrganizationFixture } from './support/organization.js';

// jose is a dependency of the server package, not of the workspace root.
const { SignJWT, decodeJwt, decodeProtectedHeader, exportJWK } = createRequire(
  new URL('../packages/server/package.json', import.meta.url),
)('jose') as typeof import('jose');

afterEach(closeFixtures);

const issuerOf = (f: OrganizationFixture) => `http://localhost:3000/api/iam/vc/${f.tenantId}`;

/** A wallet: a P-256 holder key that signs OpenID4VCI proofs and presentations. */
async function wallet() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const { kty, crv, x, y } = await exportJWK(publicKey);
  const jwk: JWK = { kty, crv, x, y };
  return {
    jwk,
    privateKey,
    proof: (audience: string, nonce: string, at: number) =>
      new SignJWT({ aud: audience, nonce, iat: Math.floor(at / 1000) })
        .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk })
        .sign(privateKey),
  };
}

/** Acme issuing an `employee` credential that alice may request for herself. */
async function setup() {
  const f = await organizationFixture({ verifiableCredentials: true });
  const type = await f.iam.api.verifiableCredentials.createType(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'employee',
    displayName: 'Acme employee',
    description: 'Works at Acme',
    claims: [
      { name: 'email', source: 'email', label: 'Email' },
      { name: 'name', source: 'name', selective: false },
      { name: 'organization', source: 'tenantName', selective: false },
      { name: 'employee_id', source: 'identityId' },
      { name: 'clearance', source: 'static', value: 'standard' },
      { name: 'team_names', source: 'teams' },
    ],
    lifetimeMs: 7 * 86_400_000,
    backgroundColor: '#112233',
  });
  const alice = await f.member('alice');
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Badge holders',
    document: {
      version: 1,
      statements: [{ effect: 'allow', actions: ['vc:request'], resources: ['credential-type/employee'] }],
    },
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: alice.id,
  });
  const aliceSession = { token: (await f.signIn('alice')).token };
  return { f, type, alice, aliceSession };
}

async function requestCredential(f: OrganizationFixture, session: { token: string }, holder: Awaited<ReturnType<typeof wallet>>) {
  const { nonce } = await f.iam.api.verifiableCredentials.nonce({ tenantId: f.tenantId });
  return f.iam.api.verifiableCredentials.request(session, {
    tenantId: f.tenantId,
    type: 'employee',
    proof: await holder.proof(issuerOf(f), nonce, f.now()),
  });
}

describe('verifiable credentials', () => {
  it('is off unless the option is set', async () => {
    const f = await organizationFixture();
    await expect(
      f.iam.api.verifiableCredentials.listTypes(f.ownerCredential, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({ code: 'FEATURE_DISABLED' });
  });

  it('issues holder-bound SD-JWT VCs that verify with selective disclosure', async () => {
    const { f, alice, aliceSession, type } = await setup();
    expect(type.vct).toBe(`${issuerOf(f)}/types/employee`);
    const holder = await wallet();
    const { credential, record } = await requestCredential(f, aliceSession, holder);
    expect(record).toMatchObject({ typeName: 'employee', identityId: alice.id, status: 'valid', via: 'request' });

    const { jwt, disclosures } = splitSdJwt(credential);
    expect(decodeProtectedHeader(jwt)).toMatchObject({ alg: 'ES256', typ: 'dc+sd-jwt' });
    const payload = decodeJwt(jwt) as Record<string, unknown>;
    expect(payload).toMatchObject({
      iss: issuerOf(f),
      vct: type.vct,
      cnf: { jwk: holder.jwk },
      name: 'alice',
      organization: 'Acme',
      status: { status_list: { idx: record.statusIndex, uri: `${issuerOf(f)}/status/${record.statusListId}` } },
    });
    expect(payload.exp! as number - (payload.iat as number)).toBe(7 * 86_400);
    expect(JSON.stringify(payload)).not.toContain('alice@acme.test');
    expect(disclosures.map((item) => readDisclosure(item).name).sort()).toEqual(['clearance', 'email', 'employee_id']);

    // The holder shows only the email to a verifier, bound to its nonce.
    const presentation = await presentSdJwt(credential, {
      disclose: ['email'],
      holderKey: holder.privateKey,
      alg: 'ES256',
      audience: 'https://verifier.example',
      nonce: 'n-1',
      issuedAt: f.now(),
    });
    const verified = await f.iam.verifiableCredentials.verify(presentation, {
      audience: 'https://verifier.example',
      nonce: 'n-1',
    });
    expect(verified).toMatchObject({
      tenantId: f.tenantId,
      type: 'employee',
      disclosed: ['email'],
      keyBound: true,
      claims: { email: 'alice@acme.test', name: 'alice', organization: 'Acme' },
    });
    expect(verified.claims).not.toHaveProperty('employee_id');
    // The public API reports instead of throwing.
    expect(
      await f.iam.api.verifiableCredentials.verify({ presentation, audience: 'https://other.example', nonce: 'n-1' }),
    ).toMatchObject({ valid: false, reason: 'wrong-audience' });

    // A proof nonce works once, and a proof for another issuer is refused.
    const { nonce } = await f.iam.api.verifiableCredentials.nonce({ tenantId: f.tenantId });
    const proof = await holder.proof(issuerOf(f), nonce, f.now());
    await f.iam.api.verifiableCredentials.request(aliceSession, { tenantId: f.tenantId, type: 'employee', proof });
    await expect(
      f.iam.api.verifiableCredentials.request(aliceSession, { tenantId: f.tenantId, type: 'employee', proof }),
    ).rejects.toMatchObject({ code: 'INVALID_NONCE' });
    const other = await f.iam.api.verifiableCredentials.nonce({ tenantId: f.tenantId });
    await expect(
      f.iam.api.verifiableCredentials.request(aliceSession, {
        tenantId: f.tenantId,
        type: 'employee',
        proof: await holder.proof('https://evil.example', other.nonce, f.now()),
      }),
    ).rejects.toMatchObject({ code: 'INVALID_PROOF' });
    expect((await f.iam.api.verifiableCredentials.mine(aliceSession, { tenantId: f.tenantId })).length).toBe(2);
  });

  it('decides self-service with policy and refuses people without vc:request', async () => {
    const { f } = await setup();
    await f.member('bob');
    const bobSession = { token: (await f.signIn('bob')).token };
    await expect(requestCredential(f, bobSession, await wallet())).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(await f.iam.api.verifiableCredentials.available(bobSession, { tenantId: f.tenantId })).toEqual([]);
    const events = await f.iam.api.audit.list(f.ownerCredential, { tenantId: f.tenantId, action: 'vc:request' });
    const list = (Array.isArray(events) ? events : (events as { events: typeof events }).events) as { outcome: string }[];
    expect(list.some((event) => event.outcome === 'deny')).toBe(true);
    // Types that require MFA refuse sessions without it (the owner signed in with a password only).
    await f.iam.api.verifiableCredentials.updateType(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'employee',
      requireMfa: true,
    });
    await expect(requestCredential(f, f.ownerCredential, await wallet())).rejects.toMatchObject({
      code: 'MFA_REQUIRED',
    });
  });

  it('revokes and suspends through the Token Status List', async () => {
    const { f, aliceSession } = await setup();
    const holder = await wallet();
    const { credential, record } = await requestCredential(f, aliceSession, holder);
    const present = () =>
      presentSdJwt(credential, {
        disclose: 'all',
        holderKey: holder.privateKey,
        alg: 'ES256',
        audience: 'https://verifier.example',
        nonce: 'n',
        issuedAt: f.now(),
      });
    const check = async () =>
      f.iam.api.verifiableCredentials.verify({ presentation: await present(), audience: 'https://verifier.example', nonce: 'n' });
    expect(await check()).toMatchObject({ valid: true });
    await f.iam.api.verifiableCredentials.suspend(f.ownerCredential, {
      tenantId: f.tenantId,
      credentialId: record.id,
      reason: 'Lost laptop',
    });
    expect(await check()).toMatchObject({ valid: false, reason: 'suspended' });

    // Verifiers read the same status from the public status list token, signed by the issuer.
    const statusUrl = `${issuerOf(f)}/status/${record.statusListId}`;
    const response = await f.iam.handler(new Request(statusUrl));
    expect(response.headers.get('content-type')).toBe('application/statuslist+jwt');
    const metadata = (await (
      await f.iam.handler(new Request(`http://localhost:3000/.well-known/jwt-vc-issuer/api/iam/vc/${f.tenantId}`))
    ).json()) as { issuer: string; jwks: { keys: JWK[] } };
    expect(metadata.issuer).toBe(issuerOf(f));
    const list = await readStatusList(await response.text(), metadata.jwks.keys[0]!, { uri: statusUrl, now: f.now() });
    expect(statusAt(list.bytes, record.statusIndex, 2)).toBe(2);

    await f.iam.api.verifiableCredentials.reinstate(f.ownerCredential, { tenantId: f.tenantId, credentialId: record.id });
    expect(await check()).toMatchObject({ valid: true });
    // The holder may revoke their own credential; revocation is final.
    await f.iam.api.verifiableCredentials.revoke(aliceSession, { tenantId: f.tenantId, credentialId: record.id });
    expect(await check()).toMatchObject({ valid: false, reason: 'revoked' });
    await expect(
      f.iam.api.verifiableCredentials.reinstate(f.ownerCredential, { tenantId: f.tenantId, credentialId: record.id }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
  });

  it('serves OpenID4VCI wallets: metadata, pre-authorized offers with a PIN, nonce and credential endpoints', async () => {
    const { f, aliceSession } = await setup();
    const issuer = issuerOf(f);
    const offer = await f.iam.api.verifiableCredentials.createOffer(aliceSession, {
      tenantId: f.tenantId,
      type: 'employee',
      txCode: true,
    });
    expect(offer.offerUri.startsWith('openid-credential-offer://?credential_offer=')).toBe(true);
    expect(offer.credentialOffer).toMatchObject({ credential_issuer: issuer, credential_configuration_ids: ['employee'] });
    const code = offer.credentialOffer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']!['pre-authorized_code'] as string;

    const get = (url: string) => f.iam.handler(new Request(url));
    const metadata = (await (
      await get(`http://localhost:3000/.well-known/openid-credential-issuer/api/iam/vc/${f.tenantId}`)
    ).json()) as Record<string, any>;
    expect(metadata).toMatchObject({
      credential_issuer: issuer,
      credential_endpoint: `${issuer}/credential`,
      nonce_endpoint: `${issuer}/nonce`,
      credential_configurations_supported: {
        employee: { format: 'dc+sd-jwt', vct: `${issuer}/types/employee`, cryptographic_binding_methods_supported: ['jwk'] },
      },
    });
    expect(metadata.credential_configurations_supported.employee.credential_metadata.display[0]).toMatchObject({
      name: 'Acme employee',
      background_color: '#112233',
    });
    expect(await (await get(`${issuer}/types/employee`)).json()).toMatchObject({ vct: `${issuer}/types/employee`, name: 'Acme employee' });

    const token = (body: Record<string, string>) =>
      f.iam.handler(
        new Request(`${issuer}/token`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams(body),
        }),
      );
    const grant = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
    const wrong = await token({ grant_type: grant, 'pre-authorized_code': code, tx_code: '000000' === offer.txCode ? '111111' : '000000' });
    expect(wrong.status).toBe(400);
    expect(await wrong.json()).toMatchObject({ error: 'invalid_grant' });
    const granted = await token({ grant_type: grant, 'pre-authorized_code': code, tx_code: offer.txCode! });
    expect(granted.status).toBe(200);
    const { access_token } = (await granted.json()) as { access_token: string };
    // The code works once.
    expect((await token({ grant_type: grant, 'pre-authorized_code': code, tx_code: offer.txCode! })).status).toBe(400);

    const { c_nonce } = (await (await f.iam.handler(new Request(`${issuer}/nonce`, { method: 'POST' }))).json()) as { c_nonce: string };
    const holder = await wallet();
    const credential = async (authorization: string) =>
      f.iam.handler(
        new Request(`${issuer}/credential`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', authorization },
          body: JSON.stringify({
            credential_configuration_id: 'employee',
            proofs: { jwt: [await holder.proof(issuer, c_nonce, f.now())] },
          }),
        }),
      );
    expect((await credential('Bearer biam_vcat.x.y')).status).toBe(401);
    const issued = await credential(`Bearer ${access_token}`);
    expect(issued.status).toBe(200);
    const body = (await issued.json()) as { credentials: { credential: string }[] };
    const payload = decodeJwt(splitSdJwt(body.credentials[0]!.credential).jwt);
    expect(payload).toMatchObject({ iss: issuer, cnf: { jwk: holder.jwk } });
    // One credential per offer.
    expect((await credential(`Bearer ${access_token}`)).status).toBe(401);
    const mine = await f.iam.api.verifiableCredentials.mine(aliceSession, { tenantId: f.tenantId });
    expect(mine.map((item) => item.via)).toEqual(['offer']);
  });

  it('lets administrators offer credentials to others and sweeps credentials of people who left', async () => {
    const { f, aliceSession } = await setup();
    const bob = await f.member('bob');
    const offer = await f.iam.api.verifiableCredentials.createOffer(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'employee',
      identityId: bob.id,
    });
    expect(offer.txCode).toBeUndefined();
    const { credential, record } = await requestCredential(f, aliceSession, await wallet());
    expect(credential).toBeTruthy();
    expect(await f.iam.verifiableCredentials.sweep()).toEqual({ examined: 1, revoked: 0 });
    await f.iam.api.identities.setStatus(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: record.identityId,
      status: 'disabled',
    });
    expect(await f.iam.verifiableCredentials.sweep({ tenantId: f.tenantId })).toEqual({ examined: 1, revoked: 1 });
    const issued = await f.iam.api.verifiableCredentials.listIssued(f.ownerCredential, { tenantId: f.tenantId });
    expect(issued.credentials[0]).toMatchObject({ status: 'revoked', reason: 'identity-inactive' });
  });

  it('caps credentials at the grants that allow them and revokes them when access goes away', async () => {
    const { f, type } = await setup();
    const carol = await f.member('carol');
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Visitors',
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['vc:request'], resources: ['credential-type/employee'] }],
      },
    });
    const binding = await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: carol.id,
      expiresAt: f.now() + 2 * 86_400_000,
    });
    const carolSession = { token: (await f.signIn('carol')).token };
    const { record } = await requestCredential(f, carolSession, await wallet());
    // A week-long type, but the grant ends in two days.
    expect(record.validUntil).toBe(f.now() + 2 * 86_400_000);
    expect(type.lifetimeMs).toBe(7 * 86_400_000);

    // A self-service offer is re-decided at redemption, and the refusal is audited.
    const offer = await f.iam.api.verifiableCredentials.createOffer(carolSession, { tenantId: f.tenantId, type: 'employee' });
    await f.iam.api.bindings.delete(f.ownerCredential, { tenantId: f.tenantId, bindingId: binding.id });
    const issuer = issuerOf(f);
    const code = offer.credentialOffer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']!['pre-authorized_code'] as string;
    const granted = await f.iam.handler(
      new Request(`${issuer}/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': code }),
      }),
    );
    const { access_token } = (await granted.json()) as { access_token: string };
    const { nonce } = await f.iam.api.verifiableCredentials.nonce({ tenantId: f.tenantId });
    const holder = await wallet();
    const refused = await f.iam.handler(
      new Request(`${issuer}/credential`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${access_token}` },
        body: JSON.stringify({ credential_configuration_id: 'employee', proofs: { jwt: [await holder.proof(issuer, nonce, f.now())] } }),
      }),
    );
    expect(refused.status).toBe(403);
    const denials = await f.iam.api.audit.list(f.ownerCredential, { tenantId: f.tenantId, action: 'vc:offer:redeem' });
    const events = (Array.isArray(denials) ? denials : (denials as { events: typeof denials }).events) as {
      outcome: string;
      metadata?: Record<string, unknown>;
    }[];
    expect(events.find((event) => event.outcome === 'deny')?.metadata).toMatchObject({ reason: 'access-changed' });

    // The sweep revokes what was issued once `vc:request` no longer allows it.
    expect(await f.iam.verifiableCredentials.sweep({ tenantId: f.tenantId })).toEqual({ examined: 1, revoked: 1 });
    const issued = await f.iam.api.verifiableCredentials.listIssued(f.ownerCredential, { tenantId: f.tenantId });
    expect(issued.credentials.find((item) => item.id === record.id)).toMatchObject({
      status: 'revoked',
      reason: 'access-changed',
    });
  });

  it('refuses replays, squatted types and PIN guessing', async () => {
    const { f, aliceSession } = await setup();
    const holder = await wallet();
    const { credential } = await requestCredential(f, aliceSession, holder);
    const presentation = await presentSdJwt(credential, {
      disclose: [],
      holderKey: holder.privateKey,
      alg: 'ES256',
      audience: 'a',
      nonce: 'n',
      issuedAt: f.now(),
    });
    // Without the verifier's audience and nonce, a captured presentation would verify for anyone.
    await expect(f.iam.api.verifiableCredentials.verify({ presentation })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const verified = await f.iam.verifiableCredentials.verify(presentation, { audience: 'a', nonce: 'n' });
    expect(verified.keyBinding).toMatchObject({ audience: 'a', nonce: 'n' });

    // Type identifiers under another organization's issuer are not this one's to claim.
    const base = 'http://localhost:3000/api/iam/vc/';
    await expect(
      f.iam.api.verifiableCredentials.createType(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'squat',
        displayName: 'Squat',
        vct: `${base}other-org/types/employee`,
        claims: [{ name: 'email', source: 'email' }],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const external = await f.iam.api.verifiableCredentials.createType(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'external',
      displayName: 'External schema',
      vct: 'https://schemas.example/employee',
      claims: [{ name: 'email', source: 'email' }],
    });
    expect(external.vct).toBe('https://schemas.example/employee');

    // A wallet that has not asked for the PIN yet has not guessed wrong; wrong guesses are audited and five end the offer.
    const offer = await f.iam.api.verifiableCredentials.createOffer(aliceSession, {
      tenantId: f.tenantId,
      type: 'employee',
      txCode: true,
    });
    const code = offer.credentialOffer.grants['urn:ietf:params:oauth:grant-type:pre-authorized_code']!['pre-authorized_code'] as string;
    const token = async (txCode?: string) => {
      const response = await f.iam.handler(
        new Request(`${issuerOf(f)}/token`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            'pre-authorized_code': code,
            ...(txCode !== undefined ? { tx_code: txCode } : {}),
          }),
        }),
      );
      return { status: response.status, body: (await response.json()) as { error: string } };
    };
    for (let i = 0; i < 6; i++) expect((await token()).body.error).toBe('invalid_request');
    const wrongPin = offer.txCode === '000000' ? '111111' : '000000';
    for (let i = 0; i < 5; i++) expect((await token(wrongPin)).body.error).toBe('invalid_grant');
    expect((await token(offer.txCode)).status).toBe(400);
    const listed = await f.iam.api.audit.list(f.ownerCredential, { tenantId: f.tenantId, action: 'vc:offer:redeem' });
    const events = (Array.isArray(listed) ? listed : (listed as { events: typeof listed }).events) as {
      outcome: string;
      metadata?: Record<string, unknown>;
    }[];
    expect(events.filter((event) => event.outcome === 'deny').map((event) => event.metadata?.reason).sort()).toEqual([
      'pin-locked',
      'wrong-pin',
      'wrong-pin',
      'wrong-pin',
      'wrong-pin',
    ]);
  });

  it('rotates issuer keys: old credentials keep verifying until the key is retired', async () => {
    const { f, aliceSession } = await setup();
    const holder = await wallet();
    const { credential } = await requestCredential(f, aliceSession, holder);
    const [first] = await f.iam.api.verifiableCredentials.listKeys(f.ownerCredential, { tenantId: f.tenantId });
    const next = await f.iam.api.verifiableCredentials.rotateKey(f.ownerCredential, { tenantId: f.tenantId });
    expect(next.kid).not.toBe(first!.kid);
    const presentation = await presentSdJwt(credential, {
      disclose: [],
      holderKey: holder.privateKey,
      alg: 'ES256',
      audience: 'a',
      nonce: 'n',
      issuedAt: f.now(),
    });
    expect(await f.iam.api.verifiableCredentials.verify({ presentation, audience: 'a', nonce: 'n' })).toMatchObject({ valid: true });
    const fresh = await requestCredential(f, aliceSession, holder);
    expect(decodeProtectedHeader(splitSdJwt(fresh.credential).jwt).kid).toBe(next.kid);
    await expect(
      f.iam.api.verifiableCredentials.retireKey(f.ownerCredential, { tenantId: f.tenantId, kid: first!.kid }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
    await f.iam.api.verifiableCredentials.retireKey(f.ownerCredential, { tenantId: f.tenantId, kid: first!.kid, force: true });
    expect(await f.iam.api.verifiableCredentials.verify({ presentation, audience: 'a', nonce: 'n' })).toMatchObject({
      valid: false,
      reason: 'unknown-issuer',
    });
  });
});
