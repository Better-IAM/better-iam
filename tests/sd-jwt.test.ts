import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { createRequire } from 'node:module';
import type { JWK } from 'jose';
import {
  STATUS_INVALID,
  STATUS_SUSPENDED,
  STATUS_VALID,
  issueSdJwt,
  presentSdJwt,
  readDisclosure,
  readStatusList,
  setStatusAt,
  signStatusList,
  splitSdJwt,
  statusAt,
  verifyHolderProof,
  verifySdJwt,
} from '@better-iam/server';

// jose is a dependency of the server package, not of the workspace root.
const { SignJWT, exportJWK } = createRequire(new URL('../packages/server/package.json', import.meta.url))(
  'jose',
) as typeof import('jose');
const issuerKeys = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const holder = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const holderJwk = async (): Promise<JWK> => {
  const { kty, crv, x, y } = await exportJWK(holder.publicKey);
  return { kty, crv, x, y };
};
const issuerKey = (kid: string, issuer: string) =>
  kid === 'k1' && issuer === 'https://issuer.example' ? issuerKeys.publicKey : undefined;

async function credential() {
  return issueSdJwt({
    alg: 'ES256',
    kid: 'k1',
    key: issuerKeys.privateKey,
    plain: {
      iss: 'https://issuer.example',
      vct: 'https://issuer.example/types/employee',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 3600,
      cnf: { jwk: await holderJwk() },
      status: { status_list: { idx: 7, uri: 'https://issuer.example/status/1' } },
    },
    disclosable: { email: 'alice@acme.test', department: 'Engineering', teams: ['Platform', 'SRE'] },
    decoys: 2,
  });
}

describe('SD-JWT VC', () => {
  it('issues, presents selected claims with key binding, and verifies', async () => {
    const issued = await credential();
    const { disclosures } = splitSdJwt(issued.sdJwt);
    expect(disclosures.map((item) => readDisclosure(item).name).sort()).toEqual(['department', 'email', 'teams']);
    // The signed payload holds digests (3 claims + 2 decoys), never the values.
    const payload = JSON.parse(Buffer.from(issued.jwt.split('.')[1]!, 'base64url').toString());
    expect(payload._sd).toHaveLength(5);
    expect(JSON.stringify(payload)).not.toContain('alice@acme.test');

    const presentation = await presentSdJwt(issued.sdJwt, {
      disclose: ['email'],
      holderKey: holder.privateKey,
      alg: 'ES256',
      audience: 'https://verifier.example',
      nonce: 'n-123',
    });
    const verified = await verifySdJwt(presentation, {
      issuerKey,
      audience: 'https://verifier.example',
      nonce: 'n-123',
    });
    expect(verified).toMatchObject({
      issuer: 'https://issuer.example',
      vct: 'https://issuer.example/types/employee',
      disclosed: ['email'],
      keyBound: true,
      status: { index: 7, uri: 'https://issuer.example/status/1' },
    });
    expect(verified.claims.email).toBe('alice@acme.test');
    expect(verified.claims).not.toHaveProperty('department');
    expect(verified.claims).not.toHaveProperty('_sd');

    // Wrong audience or nonce, a replayed KB over another selection, a forged disclosure, no key binding.
    await expect(
      verifySdJwt(presentation, { issuerKey, audience: 'https://other.example', nonce: 'n-123' }),
    ).rejects.toMatchObject({ reason: 'wrong-audience' });
    await expect(
      verifySdJwt(presentation, { issuerKey, audience: 'https://verifier.example', nonce: 'x' }),
    ).rejects.toMatchObject({ reason: 'wrong-nonce' });
    const [jwt, email, kb] = [presentation.split('~')[0], presentation.split('~')[1], presentation.split('~').at(-1)];
    const widened = `${jwt}~${email}~${disclosures.find((item) => readDisclosure(item).name === 'department')}~${kb}`;
    await expect(verifySdJwt(widened, { issuerKey })).rejects.toMatchObject({ reason: 'bad-key-binding' });
    const forged = Buffer.from(JSON.stringify(['salt', 'email', 'mallory@evil.test'])).toString('base64url');
    await expect(verifySdJwt(`${jwt}~${forged}~`, { issuerKey, requireKeyBinding: false })).rejects.toMatchObject({
      reason: 'bad-disclosure',
    });
    await expect(verifySdJwt(issued.sdJwt, { issuerKey })).rejects.toMatchObject({ reason: 'key-binding-required' });
    // A disclosure may not overwrite a signed claim.
    const iss = Buffer.from(JSON.stringify(['salt', 'iss', 'https://evil.test'])).toString('base64url');
    await expect(verifySdJwt(`${jwt}~${iss}~`, { issuerKey, requireKeyBinding: false })).rejects.toMatchObject({
      reason: 'bad-disclosure',
    });
    // Unknown issuers and expired credentials.
    await expect(
      verifySdJwt(presentation, { issuerKey: () => undefined, audience: 'https://verifier.example' }),
    ).rejects.toMatchObject({ reason: 'unknown-issuer' });
    await expect(
      verifySdJwt(presentation, { issuerKey, now: Date.now() + 7200_000, maxKeyBindingAgeSeconds: 10_000 }),
    ).rejects.toMatchObject({ reason: 'expired' });
    // The key-binding claims come back for the verifier's own replay bookkeeping.
    expect(verified.keyBinding).toMatchObject({ audience: 'https://verifier.example', nonce: 'n-123' });
  });

  it('refuses claim names that would reach the prototype or shadow SD-JWT structure', async () => {
    for (const name of ['__proto__', 'constructor', '_sd', '...', 'cnf'])
      await expect(
        issueSdJwt({
          alg: 'ES256',
          kid: 'k1',
          key: issuerKeys.privateKey,
          plain: { iss: 'https://issuer.example', vct: 'x' },
          disclosable: JSON.parse(`{${JSON.stringify(name)}: "value"}`) as Record<string, string>,
        }),
      ).rejects.toThrow();
    // A disclosure named like the prototype never verifies, even if its digest were signed.
    const salt = 'c2FsdA';
    const disclosure = Buffer.from(JSON.stringify([salt, '__proto__', { admin: true }])).toString('base64url');
    const { createHash } = await import('node:crypto');
    const digest = createHash('sha256').update(disclosure).digest('base64url');
    const jwt = await new SignJWT({ iss: 'https://issuer.example', vct: 'x', _sd_alg: 'sha-256', _sd: [digest] })
      .setProtectedHeader({ alg: 'ES256', kid: 'k1', typ: 'dc+sd-jwt' })
      .sign(issuerKeys.privateKey);
    await expect(verifySdJwt(`${jwt}~${disclosure}~`, { issuerKey, requireKeyBinding: false })).rejects.toMatchObject({
      reason: 'bad-disclosure',
    });
    // Nor does a digest listed twice.
    const email = Buffer.from(JSON.stringify([salt, 'email', 'a@b.test'])).toString('base64url');
    const twice = createHash('sha256').update(email).digest('base64url');
    const doubled = await new SignJWT({ iss: 'https://issuer.example', vct: 'x', _sd_alg: 'sha-256', _sd: [twice, twice] })
      .setProtectedHeader({ alg: 'ES256', kid: 'k1', typ: 'dc+sd-jwt' })
      .sign(issuerKeys.privateKey);
    await expect(verifySdJwt(`${doubled}~${email}~`, { issuerKey, requireKeyBinding: false })).rejects.toMatchObject({
      reason: 'bad-disclosure',
    });
  });

  it('encodes Token Status Lists and holder proofs', async () => {
    const bytes = Buffer.alloc(16);
    setStatusAt(bytes, 0, 2, STATUS_INVALID);
    setStatusAt(bytes, 5, 2, STATUS_SUSPENDED);
    expect(bytes[0]).toBe(0b01);
    expect(bytes[1]).toBe(0b1000);
    const token = await signStatusList({
      uri: 'https://issuer.example/status/1',
      bytes,
      bits: 2,
      alg: 'ES256',
      kid: 'k1',
      key: issuerKeys.privateKey,
      issuedAt: Date.now(),
      expiresAt: Date.now() + 3600_000,
      ttlSeconds: 300,
    });
    const read = await readStatusList(token, issuerKeys.publicKey, { uri: 'https://issuer.example/status/1' });
    expect([statusAt(read.bytes, 0, 2), statusAt(read.bytes, 5, 2), statusAt(read.bytes, 6, 2)]).toEqual([
      STATUS_INVALID,
      STATUS_SUSPENDED,
      STATUS_VALID,
    ]);
    await expect(readStatusList(token, issuerKeys.publicKey, { uri: 'https://issuer.example/status/2' })).rejects.toMatchObject({
      reason: 'status-unavailable',
    });

    const proof = await new SignJWT({ aud: 'https://issuer.example', nonce: 'c-1', iat: Math.floor(Date.now() / 1000) })
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk: await holderJwk() })
      .sign(holder.privateKey);
    const checked = await verifyHolderProof(proof, { audience: 'https://issuer.example' });
    expect(checked).toMatchObject({ nonce: 'c-1', jwk: await holderJwk() });
    expect(checked.thumbprint).toMatch(/^[A-Za-z0-9_-]{43}$/);
    await expect(verifyHolderProof(proof, { audience: 'https://other.example' })).rejects.toMatchObject({
      reason: 'bad-key-binding',
    });
  });
});
