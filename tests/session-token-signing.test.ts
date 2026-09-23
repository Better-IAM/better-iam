import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import {
  createSessionTokenVerifier,
  looksLikeJwt,
  SESSION_TOKEN_ALGORITHMS,
  SESSION_TOKEN_TYPE,
  SessionTokenError,
  type SessionTokenClaims,
  type SessionTokenErrorReason,
} from '@better-iam/server/session-tokens';
import { createSessionTokenSigner } from '../packages/server/src/token-signing.js';
import type { SessionTokenSigningOptions } from '../packages/server/src/options.js';
import { generateTestKey, signTestJwt, tamperPayload, decodeTestJwt } from './support/jwt-keys.js';

const issuer = 'http://localhost:3000/api/iam';
let clock = Date.UTC(2026, 8, 22, 12, 0, 0);
const now = () => clock;
const ed = generateTestKey('EdDSA', 'ed-1');
const ec = generateTestKey('ES256', 'ec-1');
const retiredEd = generateTestKey('EdDSA', 'ed-old');

function signer(options: Partial<SessionTokenSigningOptions> = {}) {
  const result = createSessionTokenSigner(
    { signingKeys: [ed.privateJwk, ec.privateJwk], ...options } as SessionTokenSigningOptions,
    { issuer, now },
  );
  if (!result) throw new Error('expected a signer');
  return result;
}

function claims(overrides: Partial<SessionTokenClaims> = {}): SessionTokenClaims {
  const iat = Math.floor(clock / 1000);
  return {
    iss: issuer,
    aud: issuer,
    sub: 'identity-1',
    tid: 'tenant-1',
    sid: 'session-1',
    jti: 'session-1',
    iat,
    nbf: iat,
    exp: iat + 900,
    auth_time: iat - 60,
    kind: 'role',
    mfa: true,
    role: 'role-1',
    trust: 'trust-1',
    ...overrides,
  };
}

async function reason(promise: Promise<unknown>): Promise<SessionTokenErrorReason> {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(SessionTokenError);
  return (error as SessionTokenError).reason;
}

const servers: Server[] = [];
afterEach(async () => {
  clock = Date.UTC(2026, 8, 22, 12, 0, 0);
  for (const server of servers.splice(0))
    await new Promise<void>((resolve) => server.close(() => resolve()));
});

async function serve(body: () => unknown): Promise<{ url: string; hits: () => number }> {
  let hits = 0;
  const server = createServer((_request, response) => {
    hits++;
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(body()));
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return { url: `http://127.0.0.1:${port}/api/iam/.well-known/jwks.json`, hits: () => hits };
}

describe('createSessionTokenSigner configuration', () => {
  const invalid = (options: unknown) => {
    try {
      createSessionTokenSigner(options as SessionTokenSigningOptions, { issuer, now });
    } catch (error) {
      return error as { code?: string; message: string };
    }
    throw new Error('expected INVALID_CONFIG');
  };

  it('returns undefined when sts.jwt is not configured', () => {
    expect(createSessionTokenSigner(undefined, { issuer, now })).toBeUndefined();
  });

  it.each([
    ['no signing keys', { signingKeys: [] }, 'sts.jwt.signingKeys'],
    [
      'more than ten signing keys',
      { signingKeys: Array.from({ length: 11 }, (_, i) => ({ ...ed.privateJwk, kid: `k${i}` })) },
      'sts.jwt.signingKeys',
    ],
    [
      'an RSA key',
      { signingKeys: [generateTestKey('RS256', 'rsa').privateJwk] },
      'sts.jwt.signingKeys',
    ],
    [
      'an ES384 key',
      { signingKeys: [generateTestKey('ES384', 'p384').privateJwk] },
      'sts.jwt.signingKeys',
    ],
    ['a key without alg', { signingKeys: [{ ...ed.privateJwk, alg: undefined }] }, 'signingKeys'],
    ['a public signing key', { signingKeys: [ed.publicJwk] }, 'must be private keys'],
    ['a bad kid', { signingKeys: [{ ...ed.privateJwk, kid: 'has space' }] }, 'kid'],
    ['a missing kid', { signingKeys: [{ ...ed.privateJwk, kid: undefined }] }, 'kid'],
    ['use enc', { signingKeys: [{ ...ed.privateJwk, use: 'enc' }] }, "use 'sig'"],
    [
      'key_ops without sign',
      { signingKeys: [{ ...ed.privateJwk, key_ops: ['verify'] }] },
      'key_ops',
    ],
    [
      'a key whose public part does not match',
      { signingKeys: [{ ...ed.privateJwk, x: retiredEd.publicJwk.x }] },
      'not a valid EdDSA key',
    ],
    [
      'duplicate kids',
      { signingKeys: [ed.privateJwk, { ...ec.privateJwk, kid: 'ed-1' }] },
      'more than once',
    ],
    [
      'a kid reused by a verification key',
      { signingKeys: [ed.privateJwk], verificationKeys: [{ ...retiredEd.publicJwk, kid: 'ed-1' }] },
      'more than once',
    ],
    [
      'a private verification key',
      { signingKeys: [ed.privateJwk], verificationKeys: [retiredEd.privateJwk] },
      'sts.jwt.verificationKeys must contain public keys only',
    ],
    [
      'more than ten verification keys',
      {
        signingKeys: [ed.privateJwk],
        verificationKeys: Array.from({ length: 11 }, (_, i) => ({
          ...retiredEd.publicJwk,
          kid: `v${i}`,
        })),
      },
      'sts.jwt.verificationKeys',
    ],
    [
      'an unknown activeKeyId',
      { signingKeys: [ed.privateJwk], activeKeyId: 'ed-old' },
      'sts.jwt.activeKeyId',
    ],
    [
      'maxLifetimeSeconds 299',
      { signingKeys: [ed.privateJwk], maxLifetimeSeconds: 299 },
      'maxLifetime',
    ],
    [
      'maxLifetimeSeconds 43201',
      { signingKeys: [ed.privateJwk], maxLifetimeSeconds: 43201 },
      'maxLifetime',
    ],
    ['a bad audience', { signingKeys: [ed.privateJwk], audiences: ['-bad'] }, 'sts.jwt.audiences'],
    [
      'an issuer with a query',
      { signingKeys: [ed.privateJwk], issuer: 'https://iam.example.com/?x=1' },
      'sts.jwt.issuer',
    ],
    ['a relative issuer', { signingKeys: [ed.privateJwk], issuer: '/api/iam' }, 'sts.jwt.issuer'],
  ])('refuses %s', (_name, options, message) => {
    const error = invalid(options);
    expect(error.code).toBe('INVALID_CONFIG');
    expect(error.message).toContain(message);
  });

  it('defaults the issuer, active key, audiences and lifetime', () => {
    const result = signer({ audiences: ['billing-api', issuer, 'billing-api'] });
    expect(result.issuer).toBe(issuer);
    expect(result.audiences).toEqual([issuer, 'billing-api']);
    expect(result.maxLifetimeSeconds).toBe(3600);
  });

  it('publishes only allowlisted public members for signing and verification keys', () => {
    const result = signer({ verificationKeys: [retiredEd.publicJwk] });
    const { keys } = result.publicJwks();
    expect(keys.map((key) => key.kid)).toEqual(['ed-1', 'ec-1', 'ed-old']);
    for (const key of keys) {
      expect(key.use).toBe('sig');
      for (const member of Object.keys(key))
        expect(['kty', 'crv', 'x', 'y', 'kid', 'alg', 'use']).toContain(member);
    }
    expect(keys[0]).toEqual({
      kty: 'OKP',
      crv: 'Ed25519',
      x: ed.publicJwk.x,
      kid: 'ed-1',
      alg: 'EdDSA',
      use: 'sig',
    });
    expect(keys[1]).toMatchObject({ kty: 'EC', crv: 'P-256', y: ec.publicJwk.y, alg: 'ES256' });
    expect(JSON.stringify(keys)).not.toContain(String(ed.privateJwk.d));
    // The returned set is a copy.
    keys[0]!.kid = 'changed';
    expect(result.publicJwks().keys[0]!.kid).toBe('ed-1');
  });
});

describe('signing and verification', () => {
  it.each([
    ['EdDSA', 'ed-1'],
    ['ES256', 'ec-1'],
  ] as const)('round-trips %s tokens', async (alg, kid) => {
    const result = signer({ activeKeyId: kid });
    const token = await result.sign(claims());
    expect(looksLikeJwt(token)).toBe(true);
    const { header, payload } = decodeTestJwt(token);
    expect(header).toEqual({ alg, kid, typ: SESSION_TOKEN_TYPE });
    expect(payload).toEqual(claims());
    await expect(result.verify(token)).resolves.toEqual(claims());
  });

  it.each([
    ['EdDSA', 'ed-1'],
    ['ES256', 'ec-1'],
  ] as const)(
    'signs with a %s key whose metadata lists sign and verify key_ops',
    async (alg, kid) => {
      const key = alg === 'EdDSA' ? ed : ec;
      const result = signer({
        signingKeys: [{ ...key.privateJwk, use: 'sig', key_ops: ['sign', 'verify'], ext: true }],
        activeKeyId: kid,
      });
      const token = await result.sign(claims());
      expect(decodeTestJwt(token).header).toEqual({ alg, kid, typ: SESSION_TOKEN_TYPE });
      await expect(result.verify(token)).resolves.toEqual(claims());
    },
  );

  it('checks the audience it is asked for', async () => {
    const result = signer({ audiences: ['billing-api'] });
    const token = await result.sign(claims({ aud: [issuer, 'billing-api'] }));
    await expect(result.verify(token, { audience: 'billing-api' })).resolves.toMatchObject({
      aud: [issuer, 'billing-api'],
    });
    const downstream = await result.sign(claims({ aud: 'billing-api' }));
    expect(await reason(result.verify(downstream))).toBe('audience');
    expect(await reason(result.verify(token, { audience: 'other-api' }))).toBe('audience');
  });

  it('drops unknown claims from the result', async () => {
    const result = signer();
    const token = await result.sign({ ...claims(), extra: 'x' } as SessionTokenClaims);
    expect(await result.verify(token)).not.toHaveProperty('extra');
  });

  it('refuses forged, confused and out-of-policy tokens with specific reasons', async () => {
    const result = signer({ maxLifetimeSeconds: 900 });
    const good = await result.sign(claims());
    const header = { typ: SESSION_TOKEN_TYPE };
    const cases: [string, string, SessionTokenErrorReason][] = [
      ['tampered payload', tamperPayload(good, { sub: 'identity-2' }), 'signature'],
      [
        'alg none without a signature',
        signTestJwt({ alg: 'none' }, claims() as never, { ...header, kid: 'ed-1' }),
        'malformed',
      ],
      [
        'alg none with a fake signature',
        `${signTestJwt({ alg: 'none' }, claims() as never, { ...header, kid: 'ed-1' })}AAAA`,
        'algorithm',
      ],
      [
        'HS256 keyed with the public x',
        signTestJwt({ alg: 'HS256', secret: String(ed.publicJwk.x) }, claims() as never, {
          ...header,
          kid: 'ed-1',
        }),
        'algorithm',
      ],
      [
        'the alg swapped on a kid',
        signTestJwt(ed, claims() as never, { ...header, alg: 'ES256' }),
        'algorithm',
      ],
      ['a JWT typ', signTestJwt(ed, claims() as never, { typ: 'JWT' }), 'type'],
      ['an at+jwt typ', signTestJwt(ed, claims() as never, { typ: 'at+jwt' }), 'type'],
      ['no typ', signTestJwt(ed, claims() as never, { typ: undefined }), 'type'],
      ['an unknown kid', signTestJwt(retiredEd, claims() as never, header), 'unknown-key'],
      ['no kid', signTestJwt(ed, claims() as never, { ...header, kid: undefined }), 'unknown-key'],
      ['a wrong issuer', await result.sign(claims({ iss: 'https://evil.example' })), 'issuer'],
      ['a wrong audience', await result.sign(claims({ aud: 'https://evil.example' })), 'audience'],
      [
        'an expired token',
        await result.sign(claims({ exp: Math.floor(clock / 1000) - 10 })),
        'expired',
      ],
      [
        'a future nbf',
        await result.sign(claims({ nbf: Math.floor(clock / 1000) + 60 })),
        'not-yet-valid',
      ],
      [
        'a lifetime over the cap',
        await result.sign(claims({ exp: Math.floor(clock / 1000) + 901 })),
        'lifetime',
      ],
      ['a user kind', await result.sign(claims({ kind: 'user' as never })), 'kind'],
      ['an api-key kind', await result.sign(claims({ kind: 'api-key' as never })), 'kind'],
      ['a missing tid', await result.sign(claims({ tid: undefined as never })), 'claims'],
      ['a jti that is not the sid', await result.sign(claims({ jti: 'other' })), 'claims'],
      ['a non-boolean mfa', await result.sign(claims({ mfa: 'yes' as never })), 'claims'],
      ['a numeric role', await result.sign(claims({ role: 7 as never })), 'claims'],
      ['a garbage string', 'not-a-jwt', 'malformed'],
      ['a header that is not JSON', 'aaaa.bbbb.cccc', 'malformed'],
      ['an oversized token', `${good}${'A'.repeat(4096)}`, 'too-large'],
    ];
    for (const [name, token, expected] of cases)
      expect([name, await reason(result.verify(token))]).toEqual([name, expected]);
  });

  it('tolerates five seconds of clock skew', async () => {
    const result = signer();
    const token = await result.sign(claims({ exp: Math.floor(clock / 1000) + 60 }));
    clock += 63_000;
    await expect(result.verify(token)).resolves.toBeDefined();
    clock += 3_000;
    expect(await reason(result.verify(token))).toBe('expired');
  });

  it('keeps verifying tokens of a retired key during rotation', async () => {
    const before = createSessionTokenSigner(
      { signingKeys: [retiredEd.privateJwk] },
      { issuer, now },
    )!;
    const token = await before.sign(claims());
    const during = signer({ verificationKeys: [retiredEd.publicJwk] });
    await expect(during.verify(token)).resolves.toMatchObject({ sid: 'session-1' });
    expect(decodeTestJwt(await during.sign(claims())).header.kid).toBe('ed-1');
    // Removing the kid from both lists revokes its tokens.
    expect(await reason(signer().verify(token))).toBe('unknown-key');
  });
});

describe('createSessionTokenVerifier', () => {
  it('verifies against a remote JWKS on 127.0.0.1 and refetches on an unknown kid', async () => {
    let keys = [ed.publicJwk];
    const jwks = await serve(() => ({ keys }));
    const verifier = createSessionTokenVerifier({
      issuer,
      audience: issuer,
      jwks: jwks.url,
      now,
      cooldownSeconds: 0,
    });
    const first = createSessionTokenSigner({ signingKeys: [ed.privateJwk] }, { issuer, now })!;
    await expect(verifier.verify(await first.sign(claims()))).resolves.toMatchObject({
      kind: 'role',
    });
    expect(jwks.hits()).toBe(1);
    await verifier.verify(await first.sign(claims()));
    expect(jwks.hits()).toBe(1);
    // A new kid appears at the JWKS route; the verifier refetches once.
    keys = [ed.publicJwk, ec.publicJwk];
    const second = createSessionTokenSigner({ signingKeys: [ec.privateJwk] }, { issuer, now })!;
    await expect(verifier.verify(await second.sign(claims()))).resolves.toBeDefined();
    expect(jwks.hits()).toBe(2);
  });

  it('reports an unreachable JWKS as reason jwks', async () => {
    const jwks = await serve(() => ({ keys: [] }));
    const url = jwks.url;
    for (const server of servers.splice(0))
      await new Promise<void>((resolve) => server.close(() => resolve()));
    const verifier = createSessionTokenVerifier({ issuer, audience: issuer, jwks: url, now });
    const token = await signer().sign(claims());
    expect(await reason(verifier.verify(token))).toBe('jwks');
  });

  it('refuses insecure remote JWKS URLs and bad options', () => {
    expect(() =>
      createSessionTokenVerifier({ issuer, audience: issuer, jwks: 'http://iam.example.com/jwks' }),
    ).toThrow(TypeError);
    expect(() =>
      createSessionTokenVerifier({ issuer, audience: [], jwks: signer().publicJwks() }),
    ).toThrow(TypeError);
    expect(() =>
      createSessionTokenVerifier({
        issuer,
        audience: issuer,
        jwks: signer().publicJwks(),
        clockToleranceSeconds: 61,
      }),
    ).toThrow(TypeError);
    expect(() =>
      createSessionTokenVerifier({
        issuer,
        audience: issuer,
        jwks: signer().publicJwks(),
        algorithms: ['RS256' as never],
      }),
    ).toThrow(TypeError);
  });

  it('accepts any configured audience and restricts algorithms and kinds', async () => {
    const result = signer({ audiences: ['billing-api'] });
    const verifier = createSessionTokenVerifier({
      issuer,
      audience: ['billing-api', 'reports-api'],
      jwks: result.publicJwks(),
      algorithms: ['ES256'],
      kinds: ['session-token'],
      now,
    });
    const ecSigner = signer({ activeKeyId: 'ec-1', audiences: ['billing-api'] });
    const token = await ecSigner.sign(claims({ aud: 'billing-api', kind: 'session-token' }));
    await expect(verifier.verify(token)).resolves.toMatchObject({ kind: 'session-token' });
    expect(await reason(verifier.verify(await result.sign(claims({ aud: 'billing-api' }))))).toBe(
      'algorithm',
    );
    expect(await reason(verifier.verify(await ecSigner.sign(claims({ aud: 'billing-api' }))))).toBe(
      'kind',
    );
  });

  it('verifyRequest takes a case-insensitive Bearer header', async () => {
    const result = signer();
    const verifier = createSessionTokenVerifier({
      issuer,
      audience: issuer,
      jwks: result.publicJwks(),
      now,
    });
    const token = await result.sign(claims());
    await expect(
      verifier.verifyRequest({ headers: { authorization: `bearer ${token}` } }),
    ).resolves.toMatchObject({ sid: 'session-1' });
    await expect(
      verifier.verifyRequest({ headers: new Headers({ Authorization: `BEARER ${token}` }) }),
    ).resolves.toMatchObject({ sid: 'session-1' });
    await expect(
      verifier.verifyRequest({ headers: [['authorization', `Bearer ${token}`]] }),
    ).resolves.toBeDefined();
    expect(await reason(verifier.verifyRequest({ headers: {} }))).toBe('malformed');
    expect(
      await reason(verifier.verifyRequest({ headers: { authorization: `Basic ${token}` } })),
    ).toBe('malformed');
    expect(
      await reason(verifier.verifyRequest({ headers: { authorization: `Bearer  ${token}` } })),
    ).toBe('malformed');
  });

  it('exposes a stable error shape', async () => {
    const error = await signer()
      .verify('not-a-jwt')
      .catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(SessionTokenError);
    expect(error).toMatchObject({
      code: 'INVALID_SESSION_TOKEN',
      status: 401,
      reason: 'malformed',
    });
    expect(SESSION_TOKEN_ALGORITHMS).toEqual(['EdDSA', 'ES256']);
    expect(looksLikeJwt('a.b')).toBe(false);
    expect(looksLikeJwt(42)).toBe(false);
    expect(looksLikeJwt('biam_ses_abc')).toBe(false);
  });
});
