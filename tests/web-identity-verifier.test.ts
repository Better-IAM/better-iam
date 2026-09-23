import {
  createHash,
  createPublicKey,
  generateKeyPairSync,
  verify as cryptoVerify,
} from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  createWebIdentityVerifier,
  flattenClaims,
  matchWebIdentityConditions,
  WEB_IDENTITY_ALGORITHMS,
  webIdentityAlgorithms,
  webIdentityAudiences,
  webIdentityClaimName,
  webIdentityConditions,
  webIdentityIssuer,
  webIdentityJwksUri,
  webIdentityKeys,
  webIdentityReplayId,
  WebIdentityFailure,
  type WebIdentityFailureReason,
  type WebIdentityProviderConfig,
  type WebIdentityVerifierOptions,
} from '../packages/server/src/web-identity.js';
import { generateTestKey, signTestJwt, tamperPayload, type TestKey } from './support/jwt-keys.js';

const issuer = 'https://token.actions.githubusercontent.com';
const audience = 'https://iam.example.com';
const rsa = generateTestKey('RS256', 'rsa-1');
const rsaPss = generateTestKey('PS256', 'pss-1');
const ec = generateTestKey('ES256', 'ec-1');
const ed = generateTestKey('EdDSA', 'ed-1');
const other = generateTestKey('RS256', 'rsa-2');

function setup(overrides: Partial<WebIdentityVerifierOptions> = {}) {
  const state = { clock: Date.UTC(2026, 8, 22, 12, 0, 0), fetched: [] as string[] };
  const documents = new Map<string, unknown>();
  const verifier = createWebIdentityVerifier({
    jwksCacheSeconds: 600,
    fetchTimeoutMs: 5000,
    maxJwksBytes: 65536,
    allowPrivateNetworks: false,
    allowInsecureLocalhost: false,
    now: () => state.clock,
    fetchJson: async (url) => {
      state.fetched.push(url.href);
      await new Promise((resolve) => setTimeout(resolve, 5));
      if (!documents.has(url.href)) throw new Error('not found');
      return structuredClone(documents.get(url.href));
    },
    ...overrides,
  });
  return { state, documents, verifier };
}

function provider(overrides: Partial<WebIdentityProviderConfig> = {}): WebIdentityProviderConfig {
  return {
    id: 'provider-1',
    issuer,
    audiences: [audience, 'sts.amazonaws.com'],
    jwks: { keys: [rsa.publicJwk, rsaPss.publicJwk, ec.publicJwk, ed.publicJwk] },
    algorithms: [...WEB_IDENTITY_ALGORITHMS],
    maxTokenLifetimeSeconds: 3600,
    clockToleranceSeconds: 30,
    updatedAt: 1,
    ...overrides,
  };
}

function payload(clock: number, overrides: Record<string, unknown> = {}) {
  const iat = Math.floor(clock / 1000);
  return {
    iss: issuer,
    sub: 'repo:acme/api:ref:refs/heads/main',
    aud: audience,
    iat,
    nbf: iat,
    exp: iat + 300,
    jti: 'jti-1',
    repository: 'acme/api',
    repository_owner: 'acme',
    ref: 'refs/heads/main',
    ...overrides,
  };
}

async function failure(promise: Promise<unknown>): Promise<WebIdentityFailureReason> {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(WebIdentityFailure);
  return (error as WebIdentityFailure).reason;
}

describe('web identity verification with static keys', () => {
  it.each([
    ['RS256', rsa],
    ['PS256', rsaPss],
    ['ES256', ec],
    ['EdDSA', ed],
  ] as [string, TestKey][])('accepts %s tokens', async (_alg, key) => {
    const { state, verifier } = setup();
    const token = signTestJwt(key, payload(state.clock));
    const verified = await verifier.verify(provider(), token);
    expect(verified).toMatchObject({
      issuer,
      subject: 'repo:acme/api:ref:refs/heads/main',
      audience,
      jti: 'jti-1',
      issuedAt: Math.floor(state.clock / 1000),
      expiresAt: Math.floor(state.clock / 1000) + 300,
    });
    expect(verified.context['token.sub']).toBe('repo:acme/api:ref:refs/heads/main');
    expect(verified.context['token.repository']).toBe('acme/api');
    expect(state.fetched).toEqual([]);
  });

  it('matches one of several audiences, from a token audience array', async () => {
    const { state, verifier } = setup();
    const token = signTestJwt(rsa, payload(state.clock, { aud: ['other', 'sts.amazonaws.com'] }));
    expect((await verifier.verify(provider(), token)).audience).toBe('sts.amazonaws.com');
  });

  it('accepts typ absent, JWT and application/jwt only', async () => {
    const { state, verifier } = setup();
    const body = payload(state.clock);
    for (const typ of [undefined, 'JWT', 'jwt', 'application/jwt'])
      await expect(
        verifier.verify(provider(), signTestJwt(rsa, body, { typ })),
      ).resolves.toBeDefined();
    for (const typ of ['biam-session+jwt', 'at+jwt', 'application/at+jwt', 'dpop+jwt', 7])
      expect(await failure(verifier.verify(provider(), signTestJwt(rsa, body, { typ })))).toBe(
        'type',
      );
  });

  it('refuses every class of bad token with a reason', async () => {
    const { state, verifier } = setup();
    const now = Math.floor(state.clock / 1000);
    const good = signTestJwt(rsa, payload(state.clock));
    const cases: [string, string, WebIdentityFailureReason, Partial<WebIdentityProviderConfig>?][] =
      [
        [
          'HS256',
          signTestJwt({ alg: 'HS256', secret: 'secret' }, payload(state.clock)),
          'algorithm',
        ],
        ['alg none', signTestJwt({ alg: 'none' }, payload(state.clock)), 'algorithm'],
        ['an alg the provider does not allow', good, 'algorithm', { algorithms: ['ES256'] }],
        ['an unknown kid', signTestJwt(other, payload(state.clock)), 'unknown-key'],
        ['a tampered payload', tamperPayload(good, { sub: 'repo:evil/api' }), 'signature'],
        [
          'a wrong issuer',
          signTestJwt(rsa, payload(state.clock, { iss: 'https://evil' })),
          'issuer',
        ],
        ['a wrong audience', signTestJwt(rsa, payload(state.clock, { aud: 'other' })), 'audience'],
        [
          'an expired token',
          signTestJwt(rsa, payload(state.clock, { iat: now - 400, exp: now - 60 })),
          'expired',
        ],
        [
          'a future nbf',
          signTestJwt(rsa, payload(state.clock, { nbf: now + 120 })),
          'not-yet-valid',
        ],
        [
          'a future iat',
          signTestJwt(rsa, payload(state.clock, { iat: now + 120, exp: now + 300 })),
          'not-yet-valid',
        ],
        [
          'a token older than the provider allows',
          signTestJwt(rsa, payload(state.clock, { iat: now - 3700, exp: now + 300 })),
          'too-old',
        ],
        [
          'a lifetime over the cap',
          signTestJwt(rsa, payload(state.clock, { exp: now + 3601 })),
          'lifetime',
        ],
        ['a missing sub', signTestJwt(rsa, payload(state.clock, { sub: undefined })), 'claims'],
        ['a missing exp', signTestJwt(rsa, payload(state.clock, { exp: undefined })), 'claims'],
        ['a long sub', signTestJwt(rsa, payload(state.clock, { sub: 'x'.repeat(513) })), 'claims'],
        ['a numeric sub', signTestJwt(rsa, payload(state.clock, { sub: 42 })), 'claims'],
        ['a numeric jti', signTestJwt(rsa, payload(state.clock, { jti: 42 })), 'claims'],
        ['garbage', 'not a token', 'malformed'],
        ['an oversized token', `${good}${'A'.repeat(8192)}`, 'malformed'],
        ['IAM’s own issuer', good, 'issuer', { issuer: 'http://localhost:3000/api/iam' }],
      ];
    const withSelf = setup({ selfIssuer: 'http://localhost:3000/api/iam' });
    for (const [name, token, expected, changes] of cases) {
      const target = changes?.issuer ? withSelf.verifier : verifier;
      expect([name, await failure(target.verify(provider(changes), token))]).toEqual([
        name,
        expected,
      ]);
    }
  });

  it('ignores unusable static keys', async () => {
    const { state, verifier } = setup();
    const weak = generateKeyPairSync('rsa', { modulusLength: 1024 });
    const weakJwk = { ...weak.publicKey.export({ format: 'jwk' }), kid: 'weak', alg: 'RS256' };
    const token = signTestJwt(
      { ...rsa, kid: 'weak', privateKey: weak.privateKey },
      payload(state.clock),
    );
    expect(
      await failure(verifier.verify(provider({ jwks: { keys: [weakJwk, ec.publicJwk] } }), token)),
    ).toBe('unknown-key');
  });
});

describe('web identity key fetching and caching', () => {
  const jwksUri = 'https://token.actions.githubusercontent.com/.well-known/jwks';
  const discovery = `${issuer}/.well-known/openid-configuration`;

  it('fetches keys from jwksUri once and caches them for jwksCacheSeconds', async () => {
    const { state, documents, verifier } = setup();
    documents.set(jwksUri, { keys: [rsa.publicJwk] });
    const config = provider({ jwks: undefined, jwksUri });
    await verifier.verify(config, signTestJwt(rsa, payload(state.clock)));
    await verifier.verify(config, signTestJwt(rsa, payload(state.clock, { jti: 'jti-2' })));
    expect(state.fetched).toEqual([jwksUri]);
    state.clock += 601_000;
    await verifier.verify(config, signTestJwt(rsa, payload(state.clock)));
    expect(state.fetched).toEqual([jwksUri, jwksUri]);
  });

  it('fetches single-flight for concurrent verifications', async () => {
    const { state, documents, verifier } = setup();
    documents.set(jwksUri, { keys: [rsa.publicJwk] });
    const config = provider({ jwks: undefined, jwksUri });
    const token = signTestJwt(rsa, payload(state.clock));
    await Promise.all([1, 2, 3, 4].map(() => verifier.verify(config, token)));
    expect(state.fetched).toEqual([jwksUri]);
  });

  it('uses OIDC discovery when the provider names no keys', async () => {
    const { state, documents, verifier } = setup();
    documents.set(discovery, { issuer, jwks_uri: jwksUri });
    documents.set(jwksUri, { keys: [ec.publicJwk] });
    const config = provider({ jwks: undefined });
    await expect(
      verifier.verify(config, signTestJwt(ec, payload(state.clock))),
    ).resolves.toMatchObject({ subject: 'repo:acme/api:ref:refs/heads/main' });
    expect(state.fetched).toEqual([discovery, jwksUri]);
  });

  it('refuses a discovery document for another issuer and caches the failure for 30 seconds', async () => {
    const { state, documents, verifier } = setup();
    documents.set(discovery, { issuer: 'https://evil.example', jwks_uri: jwksUri });
    documents.set(jwksUri, { keys: [ec.publicJwk] });
    const config = provider({ jwks: undefined });
    const token = signTestJwt(ec, payload(state.clock));
    expect(await failure(verifier.verify(config, token))).toBe('jwks-unavailable');
    expect(await failure(verifier.verify(config, token))).toBe('jwks-unavailable');
    expect(state.fetched).toEqual([discovery]);
    documents.set(discovery, { issuer, jwks_uri: jwksUri });
    state.clock += 31_000;
    await expect(
      verifier.verify(config, signTestJwt(ec, payload(state.clock))),
    ).resolves.toBeDefined();
    expect(state.fetched).toEqual([discovery, discovery, jwksUri]);
  });

  it('refuses a discovery jwks_uri that breaks the URL rules', async () => {
    const { state, documents, verifier } = setup();
    documents.set(discovery, {
      issuer,
      jwks_uri: 'http://token.actions.githubusercontent.com/jwks',
    });
    const token = signTestJwt(ec, payload(state.clock));
    expect(await failure(verifier.verify(provider({ jwks: undefined }), token))).toBe(
      'jwks-unavailable',
    );
    expect(state.fetched).toEqual([discovery]);
  });

  it('refetches on an unknown kid at most once per 30 second cooldown', async () => {
    const { state, documents, verifier } = setup();
    documents.set(jwksUri, { keys: [rsa.publicJwk] });
    const config = provider({ jwks: undefined, jwksUri });
    await verifier.verify(config, signTestJwt(rsa, payload(state.clock)));
    // The IdP rotates in a new key; within the cooldown the unknown kid is refused without a fetch.
    documents.set(jwksUri, { keys: [rsa.publicJwk, other.publicJwk] });
    state.clock += 10_000;
    expect(await failure(verifier.verify(config, signTestJwt(other, payload(state.clock))))).toBe(
      'unknown-key',
    );
    expect(state.fetched).toHaveLength(1);
    state.clock += 21_000;
    await expect(
      verifier.verify(config, signTestJwt(other, payload(state.clock))),
    ).resolves.toBeDefined();
    expect(state.fetched).toHaveLength(2);
    // A kid the IdP never published is refused, and the cooldown stops a refetch storm.
    const stranger = generateTestKey('RS256', 'stranger');
    for (let attempt = 0; attempt < 3; attempt++)
      expect(
        await failure(verifier.verify(config, signTestJwt(stranger, payload(state.clock)))),
      ).toBe('unknown-key');
    expect(state.fetched).toHaveLength(2);
  });

  it('keeps the unknown-kid cooldown while the IdP is failing', async () => {
    const { state, documents, verifier } = setup();
    documents.set(jwksUri, { keys: [rsa.publicJwk] });
    const config = provider({ jwks: undefined, jwksUri });
    await verifier.verify(config, signTestJwt(rsa, payload(state.clock)));
    expect(state.fetched).toHaveLength(1);
    // The JWKS endpoint goes down while the cached keys are still fresh but older than the cooldown.
    documents.delete(jwksUri);
    state.clock += 31_000;
    const stranger = generateTestKey('RS256', 'stranger');
    const reasons: WebIdentityFailureReason[] = [];
    for (let attempt = 0; attempt < 3; attempt++) {
      reasons.push(
        await failure(verifier.verify(config, signTestJwt(stranger, payload(state.clock)))),
      );
      state.clock += 5_000;
    }
    expect(reasons[0]).toBe('jwks-unavailable');
    expect(reasons.slice(1)).toEqual(['unknown-key', 'unknown-key']);
    // One refetch attempt, not one per token.
    expect(state.fetched).toHaveLength(2);
    // Tokens with a known kid keep verifying from the cache meanwhile.
    await expect(
      verifier.verify(config, signTestJwt(rsa, payload(state.clock))),
    ).resolves.toBeDefined();
    expect(state.fetched).toHaveLength(2);
    // Once the cooldown after the failed attempt has run out, an unknown kid may refetch again.
    documents.set(jwksUri, { keys: [rsa.publicJwk, stranger.publicJwk] });
    state.clock += 30_000;
    await expect(
      verifier.verify(config, signTestJwt(stranger, payload(state.clock))),
    ).resolves.toBeDefined();
    expect(state.fetched).toHaveLength(3);
  });

  it('drops cached keys when the provider changes or is forgotten', async () => {
    const { state, documents, verifier } = setup();
    documents.set(jwksUri, { keys: [rsa.publicJwk] });
    const config = provider({ jwks: undefined, jwksUri });
    const token = signTestJwt(rsa, payload(state.clock));
    await verifier.verify(config, token);
    await verifier.verify({ ...config, updatedAt: 2 }, token);
    expect(state.fetched).toHaveLength(2);
    verifier.forget(config.id);
    await verifier.verify({ ...config, updatedAt: 2 }, token);
    expect(state.fetched).toHaveLength(3);
  });

  it('filters fetched keys: private, weak and non-signature keys are not used', async () => {
    const { state, documents, verifier } = setup();
    documents.set(jwksUri, {
      keys: [
        { ...rsa.privateJwk },
        { ...ec.publicJwk, use: 'enc' },
        { kty: 'oct', k: 'c2VjcmV0', kid: 'hmac' },
      ],
    });
    const config = provider({ jwks: undefined, jwksUri });
    expect(await failure(verifier.verify(config, signTestJwt(rsa, payload(state.clock))))).toBe(
      'jwks-unavailable',
    );
  });

  it('reports a failing transport as jwks-unavailable', async () => {
    const { state, verifier } = setup();
    const config = provider({ jwks: undefined, jwksUri });
    expect(await failure(verifier.verify(config, signTestJwt(rsa, payload(state.clock))))).toBe(
      'jwks-unavailable',
    );
  });
});

describe('claim flattening', () => {
  it('flattens nested claims to token.* keys within the limits', () => {
    const flattened = flattenClaims({
      sub: 'system:serviceaccount:ci:deployer',
      aud: ['a', 'b'],
      exp: 1,
      admin: false,
      'kubernetes.io': {
        namespace: 'ci',
        serviceaccount: { name: 'deployer', uid: 'u-1', deeper: { tooDeep: true } },
        pod: null,
      },
      long: 'x'.repeat(1025),
      exactly: 'y'.repeat(1024),
      mixed: ['a', { b: 1 }],
      many: Array.from({ length: 65 }, (_, i) => i),
      'bad key': 'v',
      ['__proto__']: 'polluted',
      nan: Number.NaN,
    });
    expect(flattened).toEqual({
      'token.sub': 'system:serviceaccount:ci:deployer',
      'token.aud': ['a', 'b'],
      'token.exp': 1,
      'token.admin': false,
      'token.kubernetes.io.namespace': 'ci',
      'token.kubernetes.io.serviceaccount.name': 'deployer',
      'token.kubernetes.io.serviceaccount.uid': 'u-1',
      'token.exactly': 'y'.repeat(1024),
    });
    expect(Object.getPrototypeOf(flattened)).toBe(Object.prototype);
  });

  it('keeps at most 128 keys', () => {
    const wide = Object.fromEntries(Array.from({ length: 200 }, (_, i) => [`c${i}`, i]));
    const flattened = flattenClaims(wide);
    expect(Object.keys(flattened)).toHaveLength(128);
    expect(flattened['token.c127']).toBe(127);
    expect(flattened['token.c128']).toBeUndefined();
  });
});

describe('web identity trust conditions', () => {
  const pinned = { StringEquals: { 'token.sub': 'repo:acme/api:ref:refs/heads/main' } };

  it('accepts a subject pin and returns a copy', () => {
    const conditions = {
      StringLike: { 'token.sub': 'repo:acme/api:*' },
      StringEquals: { 'token.aud': 'https://iam.example.com', 'token.repository_owner': 'acme' },
    };
    const validated = webIdentityConditions(conditions);
    expect(validated).toEqual(conditions);
    expect(validated).not.toBe(conditions);
  });

  it.each([
    ['no subject condition', { StringEquals: { 'token.repository_owner': 'acme' } }],
    ['a leading * wildcard', { StringLike: { 'token.sub': '*' } }],
    ['a leading ? wildcard', { StringLike: { 'token.sub': '?repo:acme/api' } }],
    ['one wildcard among values', { StringLike: { 'token.sub': ['repo:acme/api:*', '*'] } }],
    ['an empty subject', { StringEquals: { 'token.sub': '' } }],
    ['a negated subject condition', { StringNotEquals: { 'token.sub': 'repo:evil/api' } }],
    ['a case-insensitive subject match', { StringEqualsIgnoreCase: { 'token.sub': 'repo:acme' } }],
  ])('refuses %s with WEAK_TRUST_CONDITIONS', (_name, conditions) => {
    expect(() => webIdentityConditions(conditions)).toThrow(
      expect.objectContaining({ code: 'WEAK_TRUST_CONDITIONS', status: 400 }),
    );
  });

  it.each([
    ['a non-token key', { StringEquals: { 'principal.id': 'x', 'token.sub': 'repo:a' } }],
    ['a policy variable', { StringEquals: { 'token.sub': 'repo:${principal.id}' } }],
    [
      'more than 20 entries',
      {
        StringEquals: {
          'token.sub': 'repo:a',
          ...Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`token.c${i}`, 'v'])),
        },
      },
    ],
    ['an array', [pinned]],
    ['a non-object operator entry', { StringEquals: 'token.sub' }],
  ])('refuses %s with INVALID_INPUT', (_name, conditions) => {
    expect(() => webIdentityConditions(conditions)).toThrow(
      expect.objectContaining({ code: 'INVALID_INPUT' }),
    );
  });

  it('refuses grammar errors with INVALID_POLICY', () => {
    expect(() => webIdentityConditions({ ...pinned, Regex: { 'token.sub': '.*' } })).toThrow(
      expect.objectContaining({ code: 'INVALID_POLICY' }),
    );
    expect(() =>
      webIdentityConditions({ ...pinned, NumericEquals: { 'token.run_number': 'one' } }),
    ).toThrow(expect.objectContaining({ code: 'INVALID_POLICY' }));
  });

  it('matches conditions against flattened claims and lists the failing entries', () => {
    const context = flattenClaims({
      sub: 'repo:acme/api:ref:refs/heads/main',
      repository_owner: 'acme',
      groups: ['deployers', 'ci'],
      run_number: 7,
    });
    const conditions = {
      StringLike: { 'token.sub': 'repo:acme/api:*' },
      StringEquals: { 'token.repository_owner': 'acme' },
      ArrayContains: { 'token.groups': 'deployers' },
      NumericGreaterThan: { 'token.run_number': 5 },
    };
    expect(matchWebIdentityConditions(conditions, context, 'trust-1')).toEqual({
      matched: true,
      failed: [],
    });
    expect(
      matchWebIdentityConditions(
        {
          ...conditions,
          StringEquals: { 'token.repository_owner': 'evil', 'token.environment': 'prod' },
          Exists: { 'token.environment': true },
        },
        context,
        'trust-1',
      ),
    ).toEqual({
      matched: false,
      failed: [
        'StringEquals:token.repository_owner',
        'StringEquals:token.environment',
        'Exists:token.environment',
      ],
    });
  });
});

describe('web identity validators', () => {
  const local = { allowInsecureLocalhost: false };

  it('validates issuers', () => {
    expect(webIdentityIssuer(issuer, local)).toBe(issuer);
    expect(webIdentityIssuer('https://gitlab.example.com/', local)).toBe(
      'https://gitlab.example.com/',
    );
    expect(webIdentityIssuer('http://localhost:9000', { allowInsecureLocalhost: true })).toBe(
      'http://localhost:9000',
    );
    for (const value of [
      'http://idp.example.com',
      'http://localhost:9000',
      'https://user:pass@idp.example.com',
      'https://idp.example.com/?tenant=1',
      'https://idp.example.com/#x',
      'idp.example.com',
      `https://idp.example.com/${'a'.repeat(512)}`,
      42,
    ])
      expect(() => webIdentityIssuer(value, local)).toThrow(
        expect.objectContaining({ code: 'INVALID_INPUT' }),
      );
    expect(() =>
      webIdentityIssuer('https://iam.example.com/api/iam/', {
        ...local,
        selfIssuer: 'https://iam.example.com/api/iam',
      }),
    ).toThrow(/own issuer/);
    expect(() =>
      webIdentityIssuer(issuer, { ...local, allowedIssuers: ['https://gitlab.com'] }),
    ).toThrow(/allowedIssuers/);
    expect(webIdentityIssuer(issuer, { ...local, allowedIssuers: [issuer] })).toBe(issuer);
  });

  it('validates JWKS URLs', () => {
    expect(webIdentityJwksUri('https://idp.example.com/jwks', local)).toBe(
      'https://idp.example.com/jwks',
    );
    expect(webIdentityJwksUri('https://idp.example.com:443/jwks', local)).toBe(
      'https://idp.example.com:443/jwks',
    );
    expect(webIdentityJwksUri('http://127.0.0.1:9000/jwks', { allowInsecureLocalhost: true })).toBe(
      'http://127.0.0.1:9000/jwks',
    );
    for (const value of [
      'http://idp.example.com/jwks',
      'https://idp.example.com:8443/jwks',
      'https://user@idp.example.com/jwks',
      'https://idp.example.com/jwks#k',
      'https://10.0.0.1/jwks',
      'https://[::1]/jwks',
      '/jwks',
    ])
      expect(() => webIdentityJwksUri(value, local)).toThrow(
        expect.objectContaining({ code: 'INVALID_INPUT' }),
      );
  });

  it('validates static keys', () => {
    const validated = webIdentityKeys({
      keys: [{ ...rsa.publicJwk, ext: true }, ec.publicJwk, ed.publicJwk],
    });
    expect(validated.keys).toHaveLength(3);
    expect(validated.keys[0]).toEqual({
      kty: 'RSA',
      kid: 'rsa-1',
      alg: 'RS256',
      use: 'sig',
      n: rsa.publicJwk.n,
      e: rsa.publicJwk.e,
    });
    const weak = generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({
      format: 'jwk',
    });
    const p256k = generateKeyPairSync('ec', { namedCurve: 'secp256k1' }).publicKey.export({
      format: 'jwk',
    });
    for (const value of [
      { keys: [] },
      { keys: Array.from({ length: 21 }, () => ec.publicJwk) },
      { keys: [rsa.privateJwk] },
      { keys: [weak] },
      { keys: [p256k] },
      { keys: [{ ...ec.publicJwk, use: 'enc' }] },
      { keys: [{ ...ec.publicJwk, alg: 'HS256' }] },
      { keys: [{ kty: 'oct', k: 'c2VjcmV0' }] },
      [ec.publicJwk],
      undefined,
    ])
      expect(() => webIdentityKeys(value)).toThrow(
        expect.objectContaining({ code: 'INVALID_INPUT' }),
      );
  });

  it('validates algorithms, audiences and claim names', () => {
    expect(webIdentityAlgorithms(undefined)).toEqual(['RS256', 'ES256']);
    expect(webIdentityAlgorithms(['EdDSA', 'EdDSA', 'PS256'])).toEqual(['EdDSA', 'PS256']);
    for (const value of [[], ['HS256'], ['none'], ['ES512'], 'RS256'])
      expect(() => webIdentityAlgorithms(value)).toThrow(
        expect.objectContaining({ code: 'INVALID_INPUT' }),
      );
    expect(webIdentityAudiences(['sts.amazonaws.com', 'sts.amazonaws.com', 'api'])).toEqual([
      'sts.amazonaws.com',
      'api',
    ]);
    for (const value of [
      [],
      [''],
      ['x'.repeat(257)],
      Array.from({ length: 11 }, (_, i) => `a${i}`),
    ])
      expect(() => webIdentityAudiences(value)).toThrow(
        expect.objectContaining({ code: 'INVALID_INPUT' }),
      );
    expect(webIdentityClaimName('token.repository_owner')).toBe('token.repository_owner');
    expect(webIdentityClaimName('token.kubernetes.io.namespace')).toBe(
      'token.kubernetes.io.namespace',
    );
    for (const value of ['repository_owner', 'token.', 'principal.id', 'token.a b', 42])
      expect(() => webIdentityClaimName(value)).toThrow(
        expect.objectContaining({ code: 'INVALID_INPUT' }),
      );
  });

  it('derives replay ids from the jti, or else from the signed content (header.payload)', () => {
    const byJti = webIdentityReplayId('provider-1', 'jti-1', 'h.p.sig-a');
    expect(byJti).toMatch(/^[0-9a-f]{64}$/);
    expect(webIdentityReplayId('provider-1', 'jti-1', 'h.q.sig-b')).toBe(byJti);
    expect(webIdentityReplayId('provider-2', 'jti-1', 'h.p.sig-a')).not.toBe(byJti);
    const byToken = webIdentityReplayId('provider-1', undefined, 'h.p.sig-a');
    expect(byToken).not.toBe(byJti);
    // A different spelling of the signature is the same token; different signed content is not.
    expect(webIdentityReplayId('provider-1', undefined, 'h.p.sig-other')).toBe(byToken);
    expect(webIdentityReplayId('provider-1', undefined, 'h.q.sig-a')).not.toBe(byToken);
    expect(byToken).not.toContain('h.p');
    // The formula: sha256('wi\n' + providerId + '\n' + (jti ? 'jti:' + jti : 'tok:' + sha256(header + '.' + payload))).
    const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');
    expect(byJti).toBe(sha256('wi\nprovider-1\njti:jti-1'));
    expect(byToken).toBe(sha256(`wi\nprovider-1\ntok:${sha256('h.p')}`));
    // An empty jti counts as absent.
    expect(webIdentityReplayId('provider-1', '', 'h.p.sig-a')).toBe(byToken);
  });

  it('gives malleated signatures of one token the same replay id', () => {
    const key = generateTestKey('ES256', 'malleable');
    const token = signTestJwt(key, {
      iss: 'https://idp.example.test',
      aud: 'better-iam',
      sub: 'repo:acme/app:ref:refs/heads/main',
      iat: 1_800_000_000,
      exp: 1_800_000_300,
    });
    const [header, payload, signature] = token.split('.') as [string, string, string];
    // (1) ECDSA malleability: (r, s) and (r, n - s) both verify.
    const raw = Buffer.from(signature, 'base64url');
    const n = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
    const s = BigInt(`0x${raw.subarray(32).toString('hex')}`);
    const flipped = Buffer.concat([
      raw.subarray(0, 32),
      Buffer.from((n - s).toString(16).padStart(64, '0'), 'hex'),
    ]).toString('base64url');
    const malleated = `${header}.${payload}.${flipped}`;
    expect(malleated).not.toBe(token);
    const publicKey = createPublicKey({ key: key.publicJwk as never, format: 'jwk' });
    const verifies = (value: string) => {
      const [h, p, sig] = value.split('.') as [string, string, string];
      return cryptoVerify(
        'sha256',
        Buffer.from(`${h}.${p}`),
        { key: publicKey, dsaEncoding: 'ieee-p1363' },
        Buffer.from(sig, 'base64url'),
      );
    };
    expect(verifies(token)).toBe(true);
    expect(verifies(malleated)).toBe(true);
    expect(webIdentityReplayId('p', undefined, malleated)).toBe(
      webIdentityReplayId('p', undefined, token),
    );
    // (2) Unused trailing base64url bits: a different spelling of the same signature bytes.
    const last = signature.slice(-1);
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const respelled = `${signature.slice(0, -1)}${alphabet[alphabet.indexOf(last) ^ 1]}`;
    if (Buffer.from(respelled, 'base64url').equals(raw)) {
      expect(webIdentityReplayId('p', undefined, `${header}.${payload}.${respelled}`)).toBe(
        webIdentityReplayId('p', undefined, token),
      );
    }
  });
});
