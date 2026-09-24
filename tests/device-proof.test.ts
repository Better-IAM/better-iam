import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

// The root tests do not depend on jose; borrow the server package's copy.
const jose = createRequire(new URL('../packages/server/package.json', import.meta.url))(
  'jose',
) as typeof import('jose');

afterEach(closeFixtures);

async function keyPair(kind: 'EC' | 'OKP') {
  const pair =
    kind === 'EC'
      ? await jose.generateKeyPair('ES256', { extractable: true })
      : await jose.generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  const { d: _private, ...publicJwk } = await jose.exportJWK(pair.privateKey);
  const kid = await jose.calculateJwkThumbprint(publicJwk, 'sha256');
  return { pair, publicJwk, kid };
}

async function sign(
  privateKey: CryptoKey,
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
) {
  return new jose.CompactSign(new TextEncoder().encode(JSON.stringify(payload)))
    .setProtectedHeader(header as jose.CompactJWSHeaderParameters)
    .sign(privateKey);
}

/** Headers for `devices.enroll`: the session plus a proof signed with the key being enrolled (proof of possession). */
async function enrolling(
  token: string,
  sessionId: string,
  key: Awaited<ReturnType<typeof keyPair>>,
  alg: 'ES256' | 'EdDSA' = 'ES256',
) {
  const proof = await sign(
    key.pair.privateKey,
    { alg, typ: 'device-proof+jwt', kid: key.kid },
    { iat: Math.floor(Date.now() / 1000), sid: sessionId },
  );
  return { headers: { authorization: `Bearer ${token}`, 'x-better-iam-device': proof } };
}

describe('device proof verification', () => {
  it('accepts only well-formed proofs from enrolled keys, bound to the presenting session', async () => {
    const f = await organizationFixture();
    await f.member('alice');
    const signedIn = await f.signIn('alice');
    const sid = signedIn.session.id;
    const ec = await keyPair('EC');
    await f.iam.api.devices.enroll(await enrolling(signedIn.token, sid, ec), {
      tenantId: f.tenantId,
      name: 'Laptop',
      platform: 'linux',
      publicKey: ec.publicJwk,
    });
    const now = Math.floor(Date.now() / 1000);
    const check = async (proof: string) =>
      (
        await f.iam.api.devices.check(
          { headers: { authorization: `Bearer ${signedIn.token}`, 'x-better-iam-device': proof } },
          { tenantId: f.tenantId },
        )
      ).assurance;
    const good = { alg: 'ES256', typ: 'device-proof+jwt', kid: ec.kid };
    expect(await check(await sign(ec.pair.privateKey, good, { iat: now, sid }))).toBe('registered');

    // typ must be exact.
    expect(
      await check(await sign(ec.pair.privateKey, { ...good, typ: 'JWT' }, { iat: now, sid })),
    ).toBe('none');
    // Key material from the header is never used, even when it is the enrolled key.
    expect(
      await check(
        await sign(ec.pair.privateKey, { ...good, jwk: ec.publicJwk }, { iat: now, sid }),
      ),
    ).toBe('none');
    expect(
      await check(
        await sign(
          ec.pair.privateKey,
          { ...good, jku: 'https://attacker.example/jwks' },
          { iat: now, sid },
        ),
      ),
    ).toBe('none');
    // iat is bounded both ways.
    expect(await check(await sign(ec.pair.privateKey, good, { iat: now - 3600, sid }))).toBe(
      'none',
    );
    expect(await check(await sign(ec.pair.privateKey, good, { iat: now + 3600, sid }))).toBe(
      'none',
    );
    expect(await check(await sign(ec.pair.privateKey, good, { sid }))).toBe('none');
    // The session binding is the presenting session, not a caller-chosen id.
    expect(await check(await sign(ec.pair.privateKey, good, { iat: now, sid: 'ses_other' }))).toBe(
      'none',
    );
    // An unknown key id, or a signature by another key under the enrolled kid.
    const stranger = await keyPair('EC');
    expect(
      await check(
        await sign(stranger.pair.privateKey, { ...good, kid: stranger.kid }, { iat: now, sid }),
      ),
    ).toBe('none');
    expect(await check(await sign(stranger.pair.privateKey, good, { iat: now, sid }))).toBe('none');
    // The algorithm is pinned by the stored key type.
    const ed = await keyPair('OKP');
    await f.iam.api.devices.enroll(await enrolling(signedIn.token, sid, ed, 'EdDSA'), {
      tenantId: f.tenantId,
      name: 'Phone',
      platform: 'android',
      publicKey: ed.publicJwk,
    });
    expect(
      await check(
        await sign(
          ed.pair.privateKey,
          { alg: 'EdDSA', typ: 'device-proof+jwt', kid: ed.kid },
          { iat: now, sid },
        ),
      ),
    ).toBe('registered');
    expect(
      await check(
        await sign(
          ed.pair.privateKey,
          { alg: 'ES256', typ: 'device-proof+jwt', kid: ed.kid },
          { iat: now, sid },
        ).catch(() => 'unsignable'),
      ),
    ).toBe('none');
    // Oversized headers are ignored.
    expect(await check('a'.repeat(5000))).toBe('none');
  });

  it("does not let one person's device vouch for another person's session", async () => {
    const f = await organizationFixture();
    await f.member('alice');
    await f.member('bob');
    const alice = await f.signIn('alice');
    const bob = await f.signIn('bob');
    const ec = await keyPair('EC');
    await f.iam.api.devices.enroll(await enrolling(alice.token, alice.session.id, ec), {
      tenantId: f.tenantId,
      name: 'Alice laptop',
      platform: 'macos',
      publicKey: ec.publicJwk,
    });
    const proof = await sign(
      ec.pair.privateKey,
      { alg: 'ES256', typ: 'device-proof+jwt', kid: ec.kid },
      { iat: Math.floor(Date.now() / 1000), sid: bob.session.id },
    );
    const result = await f.iam.api.devices.check(
      { headers: { authorization: `Bearer ${bob.token}`, 'x-better-iam-device': proof } },
      { tenantId: f.tenantId },
    );
    expect(result.assurance).toBe('none');
  });
});
