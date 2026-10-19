// Cryptographic and token vectors: sealing, key derivations, token formats, assertions, session JWTs, delegation
// tokens, password hashes, TOTP, webhook signatures, OAuth provider artifact sealing.
import crypto from 'node:crypto';
import { literal, location, packageNames, parse, sourceFiles, ts, unwrap, visit } from '../ts.mjs';
import { dist, fromPackage } from '../util.mjs';
import { previousCase, VectorFile } from './context.mjs';
import { ed25519Jwk, p256Jwk, publicJwk } from './keys.mjs';

const NOW = 1767225600000; // 2026-01-01T00:00:00.000Z
const sha256Hex = (value) => crypto.createHash('sha256').update(value).digest('hex');
const b64urlJson = (part) => JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
const decodeJwt = (token) => {
  const [header, payload, signature] = token.split('.');
  return { header: b64urlJson(header), payload: b64urlJson(payload), signature };
};

/** The encryption contexts (AES-GCM additional data) every encryptSecret/decryptSecret/openSecret call passes. */
async function sealingContexts() {
  const sites = [];
  for (const pkg of await packageNames())
    for (const file of await sourceFiles(pkg)) {
      const sourceFile = await parse(file);
      visit(sourceFile, (node) => {
        if (!ts.isCallExpression(node)) return;
        const name = node.expression.getText();
        if (!['encryptSecret', 'decryptSecret', 'openSecret'].includes(name)) return;
        if (pkg === 'auth' && file.endsWith('crypto.ts')) return;
        const context = node.arguments[2];
        const text = context
          ? (literal(unwrap(context)) ?? context.getText())
          : 'better-iam (default)';
        sites.push({ at: location(node), call: name, context: text });
      });
    }
  return sites;
}

async function secrets(output) {
  const authCrypto = await dist('auth', 'crypto.js');
  const file = new VectorFile('secrets', {
    description:
      'Sealed secrets (encryptSecret/openSecret/decryptSecret): AES-256-GCM with key = SHA-256(UTF-8 secret), a 12-byte random IV, additional data = UTF-8 context (default "better-iam"), 16-byte tag; sealed = base64url(iv) "." base64url(tag) "." base64url(ciphertext). open tries each secret of the keyring in order and reports the index of the one that authenticates; anything that is not exactly 3 parts with a 12-byte IV and 16-byte tag is refused.',
    source: 'packages/auth/src/crypto.ts#encryptSecret,openSecret,decryptSecret',
    notes: { contexts: await sealingContexts() },
  });
  const seal = ({ value, secret, context }) => {
    const sealed =
      context === undefined
        ? authCrypto.encryptSecret(value, secret)
        : authCrypto.encryptSecret(value, secret, context);
    const [iv, tag, ciphertext] = sealed.split('.');
    return { sealed, key: sha256Hex(secret), iv, tag, ciphertext, aad: context ?? 'better-iam' };
  };
  const secretA = 'deployment-secret-A-with-at-least-32-characters';
  const secretB = 'deployment-secret-B-with-at-least-32-characters';
  const sealedCases = [
    ['seal empty value', { value: '', secret: secretA }],
    ['seal ascii', { value: 'hello world', secret: secretA }],
    [
      'seal mfa secret with identity context',
      { value: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', secret: secretA, context: 'mfa:idn_01' },
    ],
    [
      'seal webhook secret',
      { value: 'whsec_0123456789abcdef', secret: secretB, context: 'webhook:hook_01' },
    ],
    ['seal unicode', { value: 'päss wörd ✓ 🔐', secret: secretA, context: 'better-iam' }],
    [
      'seal json payload',
      {
        value: JSON.stringify({ token: 'abc', nested: { n: 1 } }),
        secret: secretA,
        context: 'outbox',
      },
    ],
    ['seal long value', { value: 'x'.repeat(1000), secret: secretB }],
    ['seal with short secret', { value: 'v', secret: 's' }],
    ['seal with unicode secret', { value: 'v', secret: 'sécret-🔑' }],
    ['seal with empty context', { value: 'v', secret: secretA, context: '' }],
  ];
  const sealed = {};
  for (const [name, input] of sealedCases) sealed[name] = await file.add(name, input, seal);
  const open = ({ value, secrets: keyring, context }) =>
    context === undefined
      ? authCrypto.openSecret(value, keyring)
      : authCrypto.openSecret(value, keyring, context);
  const a = sealed['seal ascii'].sealed;
  const mfa = sealed['seal mfa secret with identity context'].sealed;
  const [iv, tag, ciphertext] = a.split('.');
  const flip = (part) => {
    const bytes = Buffer.from(part, 'base64url');
    bytes[0] ^= 1;
    return bytes.toString('base64url');
  };
  const openCases = [
    ['open with current secret', { value: a, secrets: [secretA] }],
    ['open with secret string', { value: a, secrets: secretA }],
    ['open during rotation (previous secret)', { value: a, secrets: [secretB, secretA] }],
    ['open with wrong secret', { value: a, secrets: [secretB] }],
    ['open with context', { value: mfa, secrets: [secretA], context: 'mfa:idn_01' }],
    ['open with wrong context', { value: mfa, secrets: [secretA], context: 'mfa:idn_02' }],
    ['open context-bound value with default context', { value: mfa, secrets: [secretA] }],
    ['open tampered ciphertext', { value: `${iv}.${tag}.${flip(ciphertext)}`, secrets: [secretA] }],
    ['open tampered tag', { value: `${iv}.${flip(tag)}.${ciphertext}`, secrets: [secretA] }],
    ['open tampered iv', { value: `${flip(iv)}.${tag}.${ciphertext}`, secrets: [secretA] }],
    [
      'open truncated tag (12 bytes)',
      {
        value: `${iv}.${Buffer.from(tag, 'base64url').subarray(0, 12).toString('base64url')}.${ciphertext}`,
        secrets: [secretA],
      },
    ],
    [
      'open 16-byte iv',
      {
        value: `${Buffer.alloc(16).toString('base64url')}.${tag}.${ciphertext}`,
        secrets: [secretA],
      },
    ],
    ['open two parts', { value: `${iv}.${tag}`, secrets: [secretA] }],
    ['open four parts', { value: `${a}.x`, secrets: [secretA] }],
    ['open empty string', { value: '', secrets: [secretA] }],
    ['open empty value sealed', { value: sealed['seal empty value'].sealed, secrets: [secretA] }],
    ['open non-string', { value: 42, secrets: [secretA] }],
    ['open empty keyring', { value: a, secrets: [] }],
  ];
  for (const [name, input] of openCases) await file.add(name, input, open);
  for (const [name, input] of [
    ['decrypt with current secret', { value: a, secrets: [secretA], context: 'better-iam' }],
    ['decrypt with wrong secret', { value: a, secrets: [secretB], context: 'better-iam' }],
    ['decrypt malformed', { value: 'not-sealed', secrets: [secretA], context: 'better-iam' }],
  ])
    await file.add(name, input, ({ value, secrets: keyring, context }) =>
      authCrypto.decryptSecret(value, keyring, context),
    );
  return file.write(output);
}

async function tokens(output) {
  const authCrypto = await dist('auth', 'crypto.js');
  const utils = await dist('server', 'utils.js');
  const vc = await dist('server', 'vc.js');
  const file = new VectorFile('tokens', {
    description:
      'Token formats and hashes. Credential tokens: "biam_" type "_" + 43 base64url characters (32 random bytes) + a 6-character check = base64url of the big-endian CRC-32 (IEEE) of everything before it; 58 characters. Stored token hashes are SHA-256 hex of the UTF-8 token. Random parts in these cases come from the seeded generator, so only their format (not their value) is meaningful for ports.',
    source:
      'packages/auth/src/crypto.ts#newCredentialToken,parseCredentialToken,hashToken,newToken,newId; packages/server/src/utils.ts; packages/server/src/vc.ts#offerToken,offerIdOf',
    notes: {
      credentialTokenKinds: { ...authCrypto.credentialTokenKinds },
      credentialTokenScanPattern: authCrypto.credentialTokenScanPattern,
      otherFormats: [
        {
          format: 'biam_sshj.{hostId}.{base64url(32 random bytes)}',
          use: 'SSH host join token',
          source: 'packages/server/src/api/ssh.ts',
        },
        {
          format: 'biam_sshr.{hostId}.{base64url(32 random bytes)}',
          use: 'SSH host renewal token',
          source: 'packages/server/src/api/ssh.ts',
        },
        {
          format: 'biam_gst_{base64url(32 random bytes)}',
          use: 'guest invitation token',
          source: 'packages/server/src/api/guests.ts',
        },
        {
          format: 'biam_denr_{base64url(32 random bytes)}',
          pattern: '^biam_denr_[A-Za-z0-9_-]{43}$',
          use: 'device enrollment code',
          source: 'packages/server/src/api/devices.ts',
        },
        {
          format: 'biam_vco.{offerId}.{base64url(32 random bytes)}',
          use: 'verifiable credential pre-authorized code',
          source: 'packages/server/src/vc.ts',
        },
        {
          format: 'biam_vcat.{offerId}.{base64url(32 random bytes)}',
          use: 'verifiable credential access token',
          source: 'packages/server/src/vc.ts',
        },
        {
          format: '{prefix}_{base64url(16 random bytes)}',
          use: 'auth record ids (newId)',
          source: 'packages/auth/src/crypto.ts',
        },
        {
          format: 'UUID v4 (crypto.randomUUID)',
          use: 'server record ids (utils.id)',
          source: 'packages/server/src/utils.ts',
        },
      ],
    },
  });
  for (const type of ['ses', 'key', 'rol', 'sts', 'dlg'])
    for (const n of [1, 2])
      await file.add(`new ${type} token ${n}`, { type }, ({ type: kind }) => {
        const token = authCrypto.newCredentialToken(kind);
        return {
          token,
          length: token.length,
          body: token.slice(0, -6),
          check: token.slice(-6),
          parsed: authCrypto.parseCredentialToken(token),
          hash: authCrypto.hashToken(token),
        };
      });
  await file.add('new token of unknown type', { type: 'xyz' }, ({ type }) =>
    authCrypto.newCredentialToken(type),
  );
  const valid = file.cases.find((item) => item.name === 'new ses token 1').output.token;
  const change = (token, index) =>
    token.slice(0, index) + (token[index] === 'A' ? 'B' : 'A') + token.slice(index + 1);
  for (const [name, value] of [
    ['parse valid session token', valid],
    ['parse with changed check character', change(valid, valid.length - 1)],
    ['parse with changed body character', change(valid, 20)],
    ['parse with unknown type', valid.replace('biam_ses_', 'biam_xyz_')],
    ['parse with upper-case prefix', valid.replace('biam_', 'BIAM_')],
    ['parse one character short', valid.slice(0, -1)],
    ['parse one character long', `${valid}A`],
    ['parse with surrounding space', ` ${valid}`],
    ['parse legacy opaque token', 'kZaf8-pvZ0eGfarZRTxLk-jeZdQ0XXEtDX9rTkHaX_k'],
    ['parse empty string', ''],
    ['parse non-string', 12345],
    ['parse fixed token', 'biam_key_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'],
  ])
    await file.add(name, { value }, ({ value: token }) => authCrypto.parseCredentialToken(token));
  // A credential token with a fixed body, so the checksum itself is pinned.
  for (const body of [
    'biam_ses_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    'biam_key_0123456789abcdefghijklmnopqrstuvwxyzABCDEFG',
    'biam_dlg_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-',
  ]) {
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE((await import('node:zlib')).crc32(body) >>> 0);
    const token = body + crc.toString('base64url');
    await file.add(`checksum of ${body.slice(0, 12)}...`, { token }, ({ token: value }) => ({
      check: value.slice(-6),
      parsed: authCrypto.parseCredentialToken(value),
    }));
  }
  for (const value of ['', 'token', 'biam_ses_x', 'päss', '🔐'])
    await file.add(`hashToken ${JSON.stringify(value)}`, { value }, ({ value: text }) => ({
      authHashToken: authCrypto.hashToken(text),
      serverHash: utils.hash(text),
    }));
  await file.add('newToken', {}, () => authCrypto.newToken());
  await file.add('newId default prefix', {}, () => authCrypto.newId());
  await file.add('newId with prefix', { prefix: 'pwh' }, ({ prefix }) => authCrypto.newId(prefix));
  await file.add('server id', {}, () => utils.id());
  await file.add('server token', {}, () => utils.token());
  for (const [a, b] of [
    [sha256Hex('a'), sha256Hex('a')],
    [sha256Hex('a'), sha256Hex('b')],
    [sha256Hex('a'), sha256Hex('a').slice(0, 63)],
  ])
    await file.add(
      `sameHash ${a.slice(0, 6)} ${b.slice(0, 6)} ${b.length}`,
      { a, b },
      ({ a: left, b: right }) => utils.sameHash(left, right),
    );
  await file.add(
    'offerToken biam_vco',
    { prefix: 'biam_vco', offerId: 'offer_01' },
    ({ prefix, offerId }) => vc.offerToken(prefix, offerId),
  );
  for (const [name, value, prefix] of [
    ['offerIdOf valid code', 'biam_vco.offer_01.secret', 'biam_vco'],
    ['offerIdOf access token as code', 'biam_vcat.offer_01.secret', 'biam_vco'],
    ['offerIdOf valid access token', 'biam_vcat.offer_01.secret', 'biam_vcat'],
    ['offerIdOf missing secret', 'biam_vco.offer_01.', 'biam_vco'],
    ['offerIdOf four parts', 'biam_vco.a.b.c', 'biam_vco'],
    ['offerIdOf too long', `biam_vco.offer.${'x'.repeat(250)}`, 'biam_vco'],
    ['offerIdOf non-string', 7, 'biam_vco'],
  ])
    await file.add(name, { value, prefix }, ({ value: v, prefix: p }) => vc.offerIdOf(v, p));
  return file.write(output);
}

async function derivations(output) {
  const assertions = await dist('server', 'assertions.js');
  const privacy = await dist('server', 'privacy.js');
  const tokenization = await dist('server', 'tokenization.js');
  const vc = await dist('server', 'vc.js');
  const { AuthBase } = await dist('auth', 'service/base.js');
  const oauthAdapter = await dist('oauth', 'adapter.js');
  const file = new VectorFile('derivations', {
    description:
      'Keys and MACs derived from the deployment secret: assertion keys (hex SHA-256 of "better-iam:assertion:" + secret), challenge digests (HMAC-SHA256(secret, tenantId ":" token) hex), privacy subjects and consent receipts, protection fingerprints, verifiable-credential proof nonces ("{base36 time}.{base64url 16 random bytes}.{base64url HMAC-SHA256(SHA-256(\'better-iam:vc-nonce:\' + secret), tenantId.time.random)}").',
    source:
      'packages/server/src/assertions.ts#assertionKey; packages/auth/src/service/base.ts#digestChallenge; packages/server/src/privacy.ts#emailSubject,signReceipt,receiptSignatureValid; packages/server/src/tokenization.ts#fingerprint; packages/server/src/vc.ts#createNonce; packages/oauth/src/adapter.ts#hash',
  });
  for (const secret of ['deployment-secret-A-with-at-least-32-characters', 's', 'sécret-🔑'])
    await file.add(`assertionKey ${secret.slice(0, 12)}`, { secret }, ({ secret: value }) =>
      assertions.assertionKey(value),
    );
  for (const [tenantId, token, secret] of [
    ['tnt_01', 'challenge-token', 'deployment-secret-A-with-at-least-32-characters'],
    ['tnt_02', 'challenge-token', 'deployment-secret-A-with-at-least-32-characters'],
    [
      'tnt_01',
      'kZaf8-pvZ0eGfarZRTxLk-jeZdQ0XXEtDX9rTkHaX_k',
      'deployment-secret-B-with-at-least-32-characters',
    ],
  ])
    await file.add(
      `digestChallenge ${tenantId} ${token.slice(0, 8)}`,
      { tenantId, token, secret },
      (input) =>
        AuthBase.prototype.digestChallenge.call(
          { options: { secret: input.secret } },
          input.tenantId,
          input.token,
        ),
    );
  for (const address of ['Person@Example.COM', 'person@example.com', 'ünï@exämple.de'])
    await file.add(
      `emailSubject ${address}`,
      { secret: 'deployment-secret-A-with-at-least-32-characters', address },
      (input) => privacy.emailSubject(input.secret, input.address),
    );
  const body = {
    version: 1,
    receiptId: 'rcpt_01',
    tenantId: 'tnt_01',
    subject: 'identity:idn_01',
    purpose: { key: 'marketing', name: 'Marketing email', version: 2, legalBasis: 'consent' },
    granted: true,
    recordedAt: NOW,
    source: 'api',
    method: 'checkbox',
  };
  const receipt = await file.add(
    'signReceipt',
    { secret: 'deployment-secret-A-with-at-least-32-characters', body },
    (input) => privacy.signReceipt(input.secret, input.body),
  );
  for (const [name, keyring, value] of [
    [
      'receiptSignatureValid current secret',
      ['deployment-secret-A-with-at-least-32-characters'],
      receipt,
    ],
    [
      'receiptSignatureValid previous secret',
      [
        'deployment-secret-B-with-at-least-32-characters',
        'deployment-secret-A-with-at-least-32-characters',
      ],
      receipt,
    ],
    [
      'receiptSignatureValid wrong secret',
      ['deployment-secret-B-with-at-least-32-characters'],
      receipt,
    ],
    [
      'receiptSignatureValid altered body',
      ['deployment-secret-A-with-at-least-32-characters'],
      { ...receipt, granted: false },
    ],
  ])
    await file.add(name, { secrets: keyring, receipt: value }, (input) =>
      privacy.receiptSignatureValid(input.secrets, input.receipt),
    );
  for (const value of ['4111111111111111', 'person@example.com', ''])
    await file.add(
      `fingerprint ${JSON.stringify(value)}`,
      { key: new Uint8Array(32).fill(7), value },
      (input) => tokenization.fingerprint(Buffer.from(input.key), input.value),
    );
  for (const tenantId of ['tnt_01', 'tnt_02'])
    await file.add(
      `vc nonce ${tenantId}`,
      { secret: 'deployment-secret-A-with-at-least-32-characters', tenantId, now: NOW },
      (input) =>
        vc.createNonce({ options: { secret: input.secret }, now: () => input.now }, input.tenantId),
    );
  for (const value of ['client_01', 'grant:abc'])
    await file.add(`oauth artifact id hash ${value}`, { value }, (input) =>
      oauthAdapter.hash(input.value),
    );
  return file.write(output);
}

async function oauthArtifacts(output) {
  const adapter = await dist('oauth', 'adapter.js');
  const file = new VectorFile('oauth-artifacts', {
    description:
      'OAuth provider artifact sealing (oidc-provider payloads at rest): AES-256-GCM with the 32-byte encryptionKey (base64), a 12-byte random IV, no additional data; sealed = base64(iv || ciphertext || tag) of JSON.stringify(payload). encryptionKey must decode to exactly 32 bytes.',
    source: 'packages/oauth/src/adapter.ts#cipher,encryptionKey',
  });
  const key = Buffer.alloc(32, 0x2a).toString('base64');
  for (const [name, value] of [
    [
      'seal object payload',
      { kind: 'AccessToken', jti: 'at_01', exp: 1767229200, scope: 'openid email' },
    ],
    ['seal string payload', 'plain'],
    ['seal nested payload', { a: [1, 2, { b: null }], c: 'ü' }],
  ]) {
    const sealed = await file.add(name, { key, value }, (input) => {
      const result = adapter.cipher(adapter.encryptionKey(input.key)).seal(input.value);
      const raw = Buffer.from(result, 'base64');
      return {
        sealed: result,
        iv: raw.subarray(0, 12).toString('base64'),
        tag: raw.subarray(-16).toString('base64'),
      };
    });
    await file.add(`open ${name.slice(5)}`, { key, sealed: sealed.sealed }, (input) =>
      adapter.cipher(adapter.encryptionKey(input.key)).open(input.sealed),
    );
  }
  const sample = file.cases[0].output.sealed;
  const raw = Buffer.from(sample, 'base64');
  raw[13] ^= 1;
  await file.add('open tampered', { key, sealed: raw.toString('base64') }, (input) =>
    adapter.cipher(adapter.encryptionKey(input.key)).open(input.sealed),
  );
  await file.add(
    'encryptionKey of 31 bytes',
    { key: Buffer.alloc(31).toString('base64') },
    (input) => adapter.encryptionKey(input.key).length,
  );
  await file.add(
    'encryptionKey of 32 bytes',
    { key },
    (input) => adapter.encryptionKey(input.key).length,
  );
  return file.write(output);
}

async function assertionsVectors(output) {
  const assertions = await dist('server', 'assertions.js');
  const secret = 'deployment-secret-A-with-at-least-32-characters';
  const file = new VectorFile('assertions', {
    description:
      'Stateless HS256 assertions. key = assertionKey(secret) (hex); token = base64url(JSON {"alg":"HS256","typ":"JWT"}) "." base64url(JSON.stringify(claims)) "." base64url(HMAC-SHA256(hex-decoded key, header.payload)). issue cases run the real assertions.issue with a stubbed operation envelope (principal, tenant, grant sources and clock given in the input). verifyAssertion accepts only the canonical header and signature spelling, checks the audience, optional issuer, exp + tolerance > now and iat - tolerance <= now (seconds, tolerance default 30).',
    source:
      'packages/server/src/assertions.ts#createAssertionsApi.issue,verifyAssertion,assertionKey',
  });
  const issue = async (input) => {
    const ctx = {
      config: { baseURL: new URL(input.baseURL) },
      options: { secret },
      now: () => input.now,
      operations: {
        operation: async (_credential, tenantId, _action, _resource, fn) =>
          fn({ tx: {}, principal: input.principal, tenant: { id: tenantId } }),
      },
      decisions: {
        grantSources: async () => ({
          groupIds: new Set(input.groupIds),
          bindings: input.roleIds.map((roleId) => ({ roleId })),
        }),
      },
    };
    return assertions.createAssertionsApi(ctx).issue({ token: 'caller' }, input.request);
  };
  const user = {
    identity: { id: 'idn_01', name: 'Ada Lovelace', email: 'ada@example.com' },
    session: { kind: 'user', mfa: true, method: 'password' },
  };
  const base = {
    baseURL: 'https://iam.example.com',
    now: NOW,
    principal: user,
    groupIds: ['grp_b', 'grp_a'],
    roleIds: ['role_x', 'role_a', 'role_x'],
  };
  const issued = {};
  for (const [name, input] of [
    [
      'issue user assertion',
      { ...base, request: { tenantId: 'tnt_01', audience: 'https://api.example.com' } },
    ],
    [
      'issue with ttl and claims',
      {
        ...base,
        request: {
          tenantId: 'tnt_01',
          audience: 'billing-service',
          ttlSeconds: 60,
          claims: { plan: 'pro', seats: 5 },
        },
      },
    ],
    [
      'issue for role session',
      {
        ...base,
        principal: {
          identity: { id: 'role_admin', name: 'Admin role' },
          session: { kind: 'role', mfa: false, roleId: 'role_admin' },
        },
        request: { tenantId: 'tnt_01', audience: 'svc' },
      },
    ],
    [
      'issue for impersonation',
      {
        ...base,
        principal: {
          identity: { id: 'idn_02', name: 'Member' },
          session: { kind: 'user', mfa: true, impersonatorId: 'idn_root' },
        },
        request: { tenantId: 'tnt_01', audience: 'svc' },
      },
    ],
    [
      'issue ttl below minimum',
      { ...base, request: { tenantId: 'tnt_01', audience: 'svc', ttlSeconds: 5 } },
    ],
    [
      'issue ttl above maximum',
      { ...base, request: { tenantId: 'tnt_01', audience: 'svc', ttlSeconds: 3601 } },
    ],
    ['issue invalid audience', { ...base, request: { tenantId: 'tnt_01', audience: 'has space' } }],
    [
      'issue claims redefining sub',
      { ...base, request: { tenantId: 'tnt_01', audience: 'svc', claims: { sub: 'x' } } },
    ],
    [
      'issue claims too large',
      {
        ...base,
        request: { tenantId: 'tnt_01', audience: 'svc', claims: { big: 'x'.repeat(5000) } },
      },
    ],
    [
      'issue scoped session token',
      {
        ...base,
        principal: {
          ...user,
          session: {
            ...user.session,
            kind: 'session-token',
            policy: { version: 1, statements: [] },
          },
        },
        request: { tenantId: 'tnt_01', audience: 'svc' },
      },
    ],
    [
      'issue delegated session',
      {
        ...base,
        principal: { ...user, session: { kind: 'delegated', mfa: false } },
        request: { tenantId: 'tnt_01', audience: 'svc' },
      },
    ],
  ])
    issued[name] = await file.add(name, input, issue);
  const key = assertions.assertionKey(secret);
  const otherKey = assertions.assertionKey('deployment-secret-B-with-at-least-32-characters');
  const token = issued['issue user assertion'].token;
  const [h, p, s] = token.split('.');
  const verify = (input) => assertions.verifyAssertion(input.token, input.options);
  const nowSeconds = NOW / 1000;
  for (const [name, input] of [
    ['verify valid', { token, options: { key, audience: 'https://api.example.com', now: NOW } }],
    [
      'verify with key list (rotation)',
      { token, options: { key: [otherKey, key], audience: 'https://api.example.com', now: NOW } },
    ],
    [
      'verify with issuer',
      {
        token,
        options: {
          key,
          audience: 'https://api.example.com',
          issuer: 'https://iam.example.com',
          now: NOW,
        },
      },
    ],
    [
      'verify wrong issuer',
      {
        token,
        options: {
          key,
          audience: 'https://api.example.com',
          issuer: 'https://other.example.com',
          now: NOW,
        },
      },
    ],
    ['verify wrong audience', { token, options: { key, audience: 'svc', now: NOW } }],
    [
      'verify wrong key',
      { token, options: { key: otherKey, audience: 'https://api.example.com', now: NOW } },
    ],
    [
      'verify malformed key',
      { token, options: { key: 'abc', audience: 'https://api.example.com', now: NOW } },
    ],
    [
      'verify empty key list',
      { token, options: { key: [], audience: 'https://api.example.com', now: NOW } },
    ],
    [
      'verify at expiry within tolerance',
      {
        token,
        options: { key, audience: 'https://api.example.com', now: (nowSeconds + 300 + 29) * 1000 },
      },
    ],
    [
      'verify expired',
      {
        token,
        options: { key, audience: 'https://api.example.com', now: (nowSeconds + 300 + 30) * 1000 },
      },
    ],
    [
      'verify expired with tolerance 0',
      {
        token,
        options: {
          key,
          audience: 'https://api.example.com',
          now: (nowSeconds + 300) * 1000,
          toleranceSeconds: 0,
        },
      },
    ],
    [
      'verify not yet valid',
      {
        token,
        options: { key, audience: 'https://api.example.com', now: (nowSeconds - 31) * 1000 },
      },
    ],
    [
      'verify tampered payload',
      {
        token: `${h}.${Buffer.from(JSON.stringify({ ...b64urlJson(p), sub: 'idn_99' })).toString('base64url')}.${s}`,
        options: { key, audience: 'https://api.example.com', now: NOW },
      },
    ],
    [
      'verify non-canonical signature spelling',
      { token: `${h}.${p}.${s}A`, options: { key, audience: 'https://api.example.com', now: NOW } },
    ],
    [
      'verify other header',
      {
        token: `${Buffer.from(JSON.stringify({ typ: 'JWT', alg: 'HS256' })).toString('base64url')}.${p}.${s}`,
        options: { key, audience: 'https://api.example.com', now: NOW },
      },
    ],
    [
      'verify two parts',
      { token: `${h}.${p}`, options: { key, audience: 'https://api.example.com', now: NOW } },
    ],
    [
      'verify too long',
      {
        token: `${h}.${'A'.repeat(16400)}.${s}`,
        options: { key, audience: 'https://api.example.com', now: NOW },
      },
    ],
  ])
    await file.add(name, input, verify);
  return file.write(output);
}

async function sessionJwt(output) {
  const signing = await dist('server', 'token-signing.js');
  const tokens = await dist('server', 'session-tokens.js');
  const jose = await fromPackage('server', 'jose');
  const ed = ed25519Jwk('session-ed25519', 'sess-ed-1');
  const ec = p256Jwk('session-p256', 'sess-ec-1');
  const retired = ed25519Jwk('session-ed25519-retired', 'sess-ed-0');
  const issuer = 'https://iam.example.com/api/iam';
  const file = new VectorFile('session-jwt', {
    description:
      'IAM session JWTs (sts.jwt): compact JWS with protected header {"alg","kid","typ":"biam-session+jwt"} (jose SignJWT member order), signed with Ed25519 (EdDSA, deterministic) or P-256 (ES256). Verification enforces typ, the alg allowlist pinned per kid, the exact issuer, one configured audience, exp/nbf with 5 s tolerance (signer) and the lifetime cap; failures are SessionTokenError (code INVALID_SESSION_TOKEN, status 401) with a reason. ES256 signatures are randomized: those cases keep the token from the previous generation as long as the TypeScript verifier still accepts it.',
    source:
      'packages/server/src/token-signing.ts#createSessionTokenSigner; packages/server/src/session-tokens.ts#createSessionTokenVerifier',
    notes: { keys: { ed25519: ed, p256: ec, retiredEd25519: retired } },
  });
  const options = {
    signingKeys: [ed, ec],
    verificationKeys: [publicJwk(retired)],
    audiences: ['https://api.example.com'],
    maxLifetimeSeconds: 3600,
  };
  const claims = (overrides = {}) => ({
    iss: issuer,
    aud: [issuer, 'https://api.example.com'],
    sub: 'idn_01',
    tid: 'tnt_01',
    sid: 'ses_01',
    jti: 'ses_01',
    iat: NOW / 1000,
    nbf: NOW / 1000,
    exp: NOW / 1000 + 900,
    auth_time: NOW / 1000 - 60,
    kind: 'session-token',
    mfa: true,
    ...overrides,
  });
  const signer = (input) =>
    signing.createSessionTokenSigner(input.options, { issuer: input.issuer, now: () => input.now });
  await file.add('signer public jwks and audiences', { options, issuer, now: NOW }, (input) => {
    const instance = signer(input);
    return {
      issuer: instance.issuer,
      audiences: [...instance.audiences],
      maxLifetimeSeconds: instance.maxLifetimeSeconds,
      jwks: instance.publicJwks(),
    };
  });
  const signed = {};
  for (const [name, input] of [
    ['sign session-token claims (EdDSA)', { options, issuer, now: NOW, claims: claims() }],
    [
      'sign role claims (EdDSA)',
      {
        options,
        issuer,
        now: NOW,
        claims: claims({
          kind: 'role',
          aud: issuer,
          role: 'role_admin',
          trust: 'trs_01',
          src_tid: 'tnt_00',
          session_name: 'deploy',
          source_identity: 'ci-bot',
        }),
      },
    ],
    [
      'sign web identity claims (EdDSA)',
      {
        options,
        issuer,
        now: NOW,
        claims: claims({
          kind: 'role',
          aud: issuer,
          role: 'role_ci',
          idp: 'oidc_gh',
          idp_sub: 'repo:org/app:ref:refs/heads/main',
          mfa: false,
        }),
      },
    ],
  ]) {
    signed[name] = await file.add(name, input, async (value) => {
      const token = await signer(value).sign(value.claims);
      return { token, ...decodeJwt(token) };
    });
  }
  // ES256: randomized signature, reused while it still verifies.
  {
    const name = 'sign session-token claims (ES256)';
    const input = {
      options: { ...options, activeKeyId: 'sess-ec-1' },
      issuer,
      now: NOW,
      claims: claims(),
    };
    const previous = await previousCase('session-jwt', name);
    let value;
    if (previous?.output?.token) {
      try {
        await signer(input).verify(previous.output.token, { audience: 'https://api.example.com' });
        const decoded = decodeJwt(previous.output.token);
        if (JSON.stringify(decoded.payload) === JSON.stringify(input.claims))
          value = previous.output;
      } catch {
        value = undefined;
      }
    }
    if (!value) {
      const token = await signer(input).sign(input.claims);
      value = { token, ...decodeJwt(token) };
    }
    file.push(name, input, value, { nondeterministic: 'ECDSA signature; verify, do not compare' });
    signed[name] = value;
  }
  const ok = signed['sign session-token claims (EdDSA)'].token;
  const role = signed['sign role claims (EdDSA)'].token;
  const es = signed['sign session-token claims (ES256)'].token;
  const verify = async (input) => {
    const instance = signer(input);
    return instance.verify(
      input.token,
      input.audience === undefined ? undefined : { audience: input.audience },
    );
  };
  const verifier = async (input) =>
    tokens
      .createSessionTokenVerifier({ ...input.verifier, now: () => input.now })
      .verify(input.token);
  const signRaw = async (header, payload, jwk = ed) =>
    new jose.SignJWT(payload).setProtectedHeader(header).sign(await jose.importJWK(jwk, jwk.alg));
  const [h, p, s] = ok.split('.');
  const publicSet = { keys: [publicJwk(ed), publicJwk(ec), publicJwk(retired)] };
  const signedByRetired = await signRaw(
    { alg: 'EdDSA', kid: 'sess-ed-0', typ: 'biam-session+jwt' },
    claims(),
    retired,
  );
  for (const [name, input, fn] of [
    ['verify EdDSA for issuer audience', { options, issuer, now: NOW, token: ok }, verify],
    [
      'verify EdDSA for configured audience',
      { options, issuer, now: NOW, token: ok, audience: 'https://api.example.com' },
      verify,
    ],
    [
      'verify ES256',
      { options, issuer, now: NOW, token: es, audience: 'https://api.example.com' },
      verify,
    ],
    ['verify role token for issuer', { options, issuer, now: NOW, token: role }, verify],
    [
      'verify role token for other audience',
      { options, issuer, now: NOW, token: role, audience: 'https://api.example.com' },
      verify,
    ],
    [
      'verify unconfigured audience',
      { options, issuer, now: NOW, token: ok, audience: 'https://unknown.example.com' },
      verify,
    ],
    ['verify token of retired key', { options, issuer, now: NOW, token: signedByRetired }, verify],
    [
      'verify expired (beyond tolerance)',
      { options, issuer, now: NOW + 906_000, token: ok },
      verify,
    ],
    ['verify expired within tolerance', { options, issuer, now: NOW + 904_000, token: ok }, verify],
    ['verify before nbf', { options, issuer, now: NOW - 6000, token: ok }, verify],
    [
      'verify tampered payload',
      {
        options,
        issuer,
        now: NOW,
        token: `${h}.${Buffer.from(JSON.stringify(claims({ sub: 'idn_99' }))).toString('base64url')}.${s}`,
      },
      verify,
    ],
    ['verify malformed', { options, issuer, now: NOW, token: 'abc.def' }, verify],
    [
      'verify too large',
      { options, issuer, now: NOW, token: `${h}.${'A'.repeat(5000)}.${s}` },
      verify,
    ],
    [
      'verify wrong typ',
      {
        options,
        issuer,
        now: NOW,
        token: await signRaw({ alg: 'EdDSA', kid: 'sess-ed-1', typ: 'JWT' }, claims()),
      },
      verify,
    ],
    [
      'verify unknown kid',
      {
        options,
        issuer,
        now: NOW,
        token: await signRaw({ alg: 'EdDSA', kid: 'nope', typ: 'biam-session+jwt' }, claims()),
      },
      verify,
    ],
    [
      'verify alg differs from key',
      {
        options,
        issuer,
        now: NOW,
        token: `${Buffer.from(JSON.stringify({ alg: 'ES256', kid: 'sess-ed-1', typ: 'biam-session+jwt' })).toString('base64url')}.${p}.${s}`,
      },
      verify,
    ],
    [
      'verify wrong issuer claim',
      {
        options,
        issuer,
        now: NOW,
        token: await signRaw(
          { alg: 'EdDSA', kid: 'sess-ed-1', typ: 'biam-session+jwt' },
          claims({ iss: 'https://evil.example.com' }),
        ),
      },
      verify,
    ],
    [
      'verify lifetime above cap',
      {
        options,
        issuer,
        now: NOW,
        token: await signRaw(
          { alg: 'EdDSA', kid: 'sess-ed-1', typ: 'biam-session+jwt' },
          claims({ exp: NOW / 1000 + 7200 }),
        ),
      },
      verify,
    ],
    [
      'verify unknown kind',
      {
        options,
        issuer,
        now: NOW,
        token: await signRaw(
          { alg: 'EdDSA', kid: 'sess-ed-1', typ: 'biam-session+jwt' },
          claims({ kind: 'user' }),
        ),
      },
      verify,
    ],
    [
      'verify jti differs from sid',
      {
        options,
        issuer,
        now: NOW,
        token: await signRaw(
          { alg: 'EdDSA', kid: 'sess-ed-1', typ: 'biam-session+jwt' },
          claims({ jti: 'other' }),
        ),
      },
      verify,
    ],
    [
      'verify mfa not boolean',
      {
        options,
        issuer,
        now: NOW,
        token: await signRaw(
          { alg: 'EdDSA', kid: 'sess-ed-1', typ: 'biam-session+jwt' },
          claims({ mfa: 'yes' }),
        ),
      },
      verify,
    ],
    [
      'verify missing tid',
      {
        options,
        issuer,
        now: NOW,
        token: await signRaw(
          { alg: 'EdDSA', kid: 'sess-ed-1', typ: 'biam-session+jwt' },
          { ...claims(), tid: undefined },
        ),
      },
      verify,
    ],
    [
      'verify empty optional claim',
      {
        options,
        issuer,
        now: NOW,
        token: await signRaw(
          { alg: 'EdDSA', kid: 'sess-ed-1', typ: 'biam-session+jwt' },
          claims({ role: '' }),
        ),
      },
      verify,
    ],
    [
      'offline verifier, kinds role only',
      {
        verifier: { issuer, audience: issuer, jwks: publicSet, kinds: ['role'] },
        now: NOW,
        token: ok,
      },
      verifier,
    ],
    [
      'offline verifier, algorithms ES256 only',
      {
        verifier: { issuer, audience: issuer, jwks: publicSet, algorithms: ['ES256'] },
        now: NOW,
        token: ok,
      },
      verifier,
    ],
    [
      'offline verifier default tolerance',
      {
        verifier: { issuer, audience: 'https://api.example.com', jwks: publicSet },
        now: NOW + 904_000,
        token: ok,
      },
      verifier,
    ],
    [
      'offline verifier tolerance 0',
      {
        verifier: {
          issuer,
          audience: 'https://api.example.com',
          jwks: publicSet,
          clockToleranceSeconds: 0,
        },
        now: NOW + 900_000,
        token: ok,
      },
      verifier,
    ],
  ])
    await file.add(name, input, fn);
  for (const [name, value] of [
    ['looksLikeJwt compact', ok],
    ['looksLikeJwt two segments', 'aa.bb'],
    ['looksLikeJwt short segment', 'a.bb.cc'],
    ['looksLikeJwt opaque token', 'biam_ses_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'],
  ])
    await file.add(name, { value }, (input) => tokens.looksLikeJwt(input.value));
  for (const [name, input] of [
    ['config: no signing keys', { options: { signingKeys: [] }, issuer, now: NOW }],
    ['config: public signing key', { options: { signingKeys: [publicJwk(ed)] }, issuer, now: NOW }],
    [
      'config: RSA key',
      {
        options: {
          signingKeys: [{ kty: 'RSA', n: 'x', e: 'AQAB', d: 'y', kid: 'r', alg: 'RS256' }],
        },
        issuer,
        now: NOW,
      },
    ],
    [
      'config: bad kid',
      { options: { signingKeys: [{ ...ed, kid: 'has space' }] }, issuer, now: NOW },
    ],
    [
      'config: duplicate kid',
      { options: { signingKeys: [ed, { ...ec, kid: ed.kid }] }, issuer, now: NOW },
    ],
    [
      'config: private verification key',
      { options: { signingKeys: [ed], verificationKeys: [retired] }, issuer, now: NOW },
    ],
    [
      'config: x does not match d',
      { options: { signingKeys: [{ ...ed, x: publicJwk(retired).x }] }, issuer, now: NOW },
    ],
    [
      'config: unknown active key',
      { options: { signingKeys: [ed], activeKeyId: 'other' }, issuer, now: NOW },
    ],
    [
      'config: lifetime below 300',
      { options: { signingKeys: [ed], maxLifetimeSeconds: 299 }, issuer, now: NOW },
    ],
    [
      'config: issuer with query',
      { options: { signingKeys: [ed], issuer: 'https://iam.example.com/?x=1' }, issuer, now: NOW },
    ],
    [
      'config: invalid audience',
      { options: { signingKeys: [ed], audiences: ['has space'] }, issuer, now: NOW },
    ],
    ['config: use enc', { options: { signingKeys: [{ ...ed, use: 'enc' }] }, issuer, now: NOW }],
    [
      'config: key_ops without sign',
      { options: { signingKeys: [{ ...ed, key_ops: ['verify'] }] }, issuer, now: NOW },
    ],
  ])
    await file.add(name, input, (value) => {
      const instance = signer(value);
      return { issuer: instance.issuer, audiences: [...instance.audiences] };
    });
  return file.write(output);
}

async function delegationTokens(output) {
  const core = await dist('core');
  const a2a = await dist('server', 'a2a.js');
  const verifier = await dist('a2a', 'delegation-tokens.js');
  const key = ed25519Jwk('a2a-card-ed25519', 'card-ed-1');
  const issuer = 'https://iam.example.com/api/iam';
  const file = new VectorFile('delegation-tokens', {
    description:
      'Delegation tokens (RFC 8693 act chains). readDelegationTokenClaims checks signature-verified claims; delegationActor builds act from the chain (person\'s own delegate first). Signed cases use the deployment card signer (compact JWS, header {"alg","kid","typ":"biam-delegation+jwt"}, payload JSON.stringify(claims) in insertion order) and the @better-iam/a2a verifier.',
    source:
      'packages/core/src/delegation-tokens.ts#readDelegationTokenClaims,delegationActor; packages/server/src/a2a.ts#cardSigner.signJwt,verifyJwt; packages/a2a/src/delegation-tokens.ts#verifyDelegationToken',
    notes: {
      key,
      limits: { ...core.delegationTokenLimits },
      scopePattern: core.delegationTokenScopePattern.source,
      tokenType: core.delegationTokenType,
    },
  });
  const iat = NOW / 1000;
  const claims = (overrides = {}) => ({
    iss: issuer,
    sub: 'idn_person',
    aud: 'https://agent-api.example.com',
    iat,
    nbf: iat,
    exp: iat + 300,
    jti: 'dtk_01',
    tenant_id: 'tnt_01',
    delegation_id: 'dlg_01',
    act: { sub: 'agt_01' },
    scope: 'documents:read billing:*',
    ...overrides,
  });
  const expected = { issuer, audience: 'https://agent-api.example.com', now: NOW };
  const read = (input) => core.readDelegationTokenClaims(input.claims, input.expected);
  for (const [name, input] of [
    ['read valid', { claims: claims(), expected }],
    [
      'read valid with issuer list and tenant',
      {
        claims: claims(),
        expected: { ...expected, issuer: ['https://x.example.com', issuer], tenantId: 'tnt_01' },
      },
    ],
    [
      'read hand-off chain',
      {
        claims: claims({ act: { sub: 'agt_03', act: { sub: 'agt_02', act: { sub: 'agt_01' } } } }),
        expected,
      },
    ],
    ['read without scope', { claims: claims({ scope: undefined }), expected }],
    ['read empty scope string', { claims: claims({ scope: '  ' }), expected }],
    ['read not an object', { claims: [1], expected }],
    ['read missing jti', { claims: claims({ jti: '' }), expected }],
    ['read invalid sub', { claims: claims({ sub: 'has space' }), expected }],
    ['read fractional iat', { claims: claims({ iat: iat + 0.5 }), expected }],
    ['read no actor', { claims: claims({ act: undefined }), expected }],
    ['read invalid actor', { claims: claims({ act: { sub: 7 } }), expected }],
    [
      'read five actors',
      {
        claims: claims({
          act: {
            sub: 'a1',
            act: { sub: 'a2', act: { sub: 'a3', act: { sub: 'a4', act: { sub: 'a5' } } } },
          },
        }),
        expected,
      },
    ],
    [
      'read repeated actor',
      { claims: claims({ act: { sub: 'agt_01', act: { sub: 'agt_01' } } }), expected },
    ],
    ['read actor equal to subject', { claims: claims({ act: { sub: 'idn_person' } }), expected }],
    ['read invalid scope', { claims: claims({ scope: 'bad scope!' }), expected }],
    ['read scope not string', { claims: claims({ scope: ['a'] }), expected }],
    ['read untrusted issuer', { claims: claims({ iss: 'https://evil.example.com' }), expected }],
    ['read other audience', { claims: claims({ aud: 'https://other.example.com' }), expected }],
    ['read other tenant', { claims: claims(), expected: { ...expected, tenantId: 'tnt_02' } }],
    ['read lifetime too long', { claims: claims({ exp: iat + 3601 }), expected }],
    ['read exp before iat', { claims: claims({ exp: iat }), expected }],
    ['read nbf before iat', { claims: claims({ nbf: iat - 1 }), expected }],
    ['read expired', { claims: claims(), expected: { ...expected, now: (iat + 330) * 1000 } }],
    [
      'read expired within tolerance',
      { claims: claims(), expected: { ...expected, now: (iat + 329) * 1000 } },
    ],
    ['read not yet valid', { claims: claims(), expected: { ...expected, now: (iat - 31) * 1000 } }],
    [
      'read tolerance 0',
      {
        claims: claims(),
        expected: { ...expected, now: (iat + 300) * 1000, clockToleranceSeconds: 0 },
      },
    ],
    [
      'read tolerance out of range',
      { claims: claims(), expected: { ...expected, clockToleranceSeconds: 301 } },
    ],
  ])
    await file.add(name, input, read);
  for (const chain of [
    ['agt_01'],
    ['agt_01', 'agt_02'],
    ['agt_01', 'agt_02', 'agt_03', 'agt_04'],
    [],
  ])
    await file.add(`delegationActor ${chain.join(',') || 'empty'}`, { chain }, (input) =>
      core.delegationActor(input.chain),
    );
  const ctx = {
    options: { a2a: { signingKeys: [key] } },
    config: { baseURL: new URL('https://iam.example.com'), basePath: '/api/iam' },
  };
  const signer = a2a.cardSigner(ctx);
  const jwks = { keys: signer.jwks.keys };
  const tokens = {};
  for (const [name, value] of [
    ['sign delegation token', claims()],
    [
      'sign hand-off delegation token',
      claims({ act: core.delegationActor(['agt_01', 'agt_02']), jti: 'dtk_02' }),
    ],
  ])
    tokens[name] = await file.add(name, { claims: value, key: 'notes.key' }, async (input) => {
      const token = await signer.signJwt({ ...input.claims }, core.delegationTokenType);
      return { token, ...decodeJwt(token) };
    });
  const token = tokens['sign delegation token'].token;
  const [h, p, s] = token.split('.');
  const verify = (input) =>
    verifier.verifyDelegationToken(input.token, {
      trustedIssuers: { [issuer]: jwks },
      audience: input.audience,
      now: () => input.now,
      ...(input.tenantId ? { tenantId: input.tenantId } : {}),
    });
  for (const [name, input] of [
    ['verify valid', { token, audience: 'https://agent-api.example.com', now: NOW }],
    [
      'verify hand-off',
      {
        token: tokens['sign hand-off delegation token'].token,
        audience: 'https://agent-api.example.com',
        now: NOW,
      },
    ],
    ['verify wrong audience', { token, audience: 'https://other.example.com', now: NOW }],
    ['verify expired', { token, audience: 'https://agent-api.example.com', now: NOW + 331_000 }],
    [
      'verify other tenant',
      { token, audience: 'https://agent-api.example.com', now: NOW, tenantId: 'tnt_02' },
    ],
    [
      'verify tampered payload',
      {
        token: `${h}.${Buffer.from(JSON.stringify(claims({ sub: 'idn_other' }))).toString('base64url')}.${s}`,
        audience: 'https://agent-api.example.com',
        now: NOW,
      },
    ],
    [
      'verify wrong typ',
      {
        token: `${Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: 'card-ed-1', typ: 'JWT' })).toString('base64url')}.${p}.${s}`,
        audience: 'https://agent-api.example.com',
        now: NOW,
      },
    ],
    [
      'verify unknown kid',
      {
        token: `${Buffer.from(JSON.stringify({ alg: 'EdDSA', kid: 'nope', typ: 'biam-delegation+jwt' })).toString('base64url')}.${p}.${s}`,
        audience: 'https://agent-api.example.com',
        now: NOW,
      },
    ],
    [
      'verify untrusted issuer',
      {
        token: `${h}.${Buffer.from(JSON.stringify(claims({ iss: 'https://evil.example.com' }))).toString('base64url')}.${s}`,
        audience: 'https://agent-api.example.com',
        now: NOW,
      },
    ],
    ['verify not compact', { token: 'abc', audience: 'https://agent-api.example.com', now: NOW }],
  ])
    await file.add(name, input, verify);
  for (const [name, input] of [
    ['server verifyJwt valid', { token, typ: core.delegationTokenType }],
    ['server verifyJwt wrong typ', { token, typ: 'biam-other+jwt' }],
    [
      'server verifyJwt tampered',
      { token: `${h}.${p}.${s.slice(0, -2)}AA`, typ: core.delegationTokenType },
    ],
  ])
    await file.add(name, input, (value) => signer.verifyJwt(value.token, value.typ));
  return file.write(output);
}

async function passwords(output) {
  const argon2 = (await fromPackage('auth', 'argon2')).default;
  const file = new VectorFile('passwords', {
    description:
      'Password hashes. The auth service hashes with argon2.hash(password, { type: argon2id }) of node-argon2 0.44: argon2id, version 19 (0x13), m=65536 KiB, t=3, p=4, 32-byte hash, 16-byte random salt, PHC string $argon2id$v=19$m=65536,t=3,p=4$<salt b64 unpadded>$<hash b64 unpadded>. verify reads the parameters from the PHC string. Salts here come from the seeded generator; ports must produce the same hash for the same salt and verify every case.',
    source:
      'packages/auth/src/service/base.ts#setPassword (argon2.hash), packages/auth/src/service/sessions.ts and account.ts (argon2.verify)',
  });
  const hashed = {};
  for (const password of [
    'correct horse battery staple',
    'Pässwörd-✓-🔐',
    'a strong root test password',
    ' ',
  ])
    hashed[password] = await file.add(
      `hash ${JSON.stringify(password)}`,
      { password },
      async (input) => {
        const phc = await argon2.hash(input.password, { type: argon2.argon2id });
        const [, type, version, params, salt, hash] = phc.split('$');
        return {
          phc,
          type,
          version,
          params,
          salt,
          hash,
          verify: await argon2.verify(phc, input.password),
        };
      },
    );
  // Older or different parameters must still verify (verify reads them from the string).
  const custom = await file.add(
    'hash with m=4096,t=2,p=1 (other parameters)',
    {
      password: 'legacy password',
      options: { type: 'argon2id', memoryCost: 4096, timeCost: 2, parallelism: 1 },
    },
    async (input) => argon2.hash(input.password, { ...input.options, type: argon2.argon2id }),
  );
  const argon2i = await file.add(
    'hash argon2i',
    { password: 'legacy password', options: { type: 'argon2i' } },
    async (input) => argon2.hash(input.password, { type: argon2.argon2i }),
  );
  const first = hashed['correct horse battery staple'].phc;
  for (const [name, phc, password] of [
    ['verify correct', first, 'correct horse battery staple'],
    ['verify wrong', first, 'correct horse battery stapler'],
    ['verify case differs', first, 'Correct horse battery staple'],
    ['verify unicode correct', hashed['Pässwörd-✓-🔐'].phc, 'Pässwörd-✓-🔐'],
    ['verify unicode normalization differs', hashed['Pässwörd-✓-🔐'].phc, 'Pässwörd-✓-🔐'],
    ['verify other parameters', custom, 'legacy password'],
    ['verify argon2i', argon2i, 'legacy password'],
    ['verify argon2i wrong', argon2i, 'legacy passwort'],
  ])
    await file.add(name, { phc, password }, (input) => argon2.verify(input.phc, input.password));
  return file.write(output);
}

async function totp(output) {
  const { authenticator } = await fromPackage('auth', 'otplib');
  const { MfaAuth } = await dist('auth', 'service/mfa.js');
  const authCrypto = await dist('auth', 'crypto.js');
  const file = new VectorFile('totp', {
    description:
      'TOTP (RFC 6238) as the auth service uses otplib\'s authenticator: base32 secrets of 20 random bytes (generateSecret(20)), HMAC-SHA1, 6 digits, 30-second steps, window 1 (the previous, current and next step are accepted). checkTotp accepts a code once per step: step = floor(now / 30000) + delta, and the step must be greater than the record\'s lastUsedStep; codes must match /^\\d{6}$/. keyuri: otpauth://totp/{issuer}:{account}?secret=...&period=30&digits=6&algorithm=SHA1&issuer={issuer} (appName default "Better IAM").',
    source: 'packages/auth/src/service/mfa.ts#beginMfa,checkTotp (otplib 12 authenticator)',
  });
  const secret = await file.add('generateSecret(20)', {}, () => authenticator.generateSecret(20));
  const fixed = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
  for (const epoch of [
    0,
    59_000,
    1_111_111_109_000,
    1_234_567_890_000,
    2_000_000_000_000,
    NOW,
    NOW + 29_999,
    NOW + 30_000,
  ])
    for (const value of [fixed, secret])
      await file.add(
        `generate ${value === fixed ? 'fixed' : 'generated'} secret at ${epoch}`,
        { secret: value, epoch },
        (input) => {
          const generator = authenticator.clone();
          generator.options = { epoch: input.epoch };
          return generator.generate(input.secret);
        },
      );
  const at = (epoch) => {
    const generator = authenticator.clone();
    generator.options = { epoch };
    return generator.generate(fixed);
  };
  for (const [name, code, epoch] of [
    ['checkDelta current step', at(NOW), NOW],
    ['checkDelta previous step', at(NOW - 30_000), NOW],
    ['checkDelta next step', at(NOW + 30_000), NOW],
    ['checkDelta two steps back', at(NOW - 60_000), NOW],
    ['checkDelta wrong code', '000000', NOW],
  ])
    await file.add(name, { secret: fixed, code, epoch }, (input) => {
      const generator = authenticator.clone();
      generator.options = { epoch: input.epoch, window: 1 };
      return generator.checkDelta(input.code, input.secret);
    });
  for (const [account, issuer] of [
    ['ada@example.com', 'Better IAM'],
    ['idn_01', 'Acme Identity'],
    ['ünï code@example.com', 'Better IAM'],
  ])
    await file.add(`keyuri ${account}`, { account, issuer, secret: fixed }, (input) =>
      authenticator.keyuri(input.account, input.issuer, input.secret),
    );
  const secretValue = 'deployment-secret-A-with-at-least-32-characters';
  const record = (lastUsedStep) => ({
    identityId: 'idn_01',
    encryptedSecret: authCrypto.encryptSecret(fixed, secretValue, 'mfa:idn_01'),
    lastUsedStep,
  });
  const step = Math.floor(NOW / 30_000);
  for (const [name, code, lastUsedStep] of [
    ['checkTotp current code', at(NOW), -1],
    ['checkTotp previous-step code', at(NOW - 30_000), -1],
    ['checkTotp next-step code', at(NOW + 30_000), -1],
    ['checkTotp replayed step', at(NOW), step],
    ['checkTotp older step after newer use', at(NOW - 30_000), step],
    ['checkTotp wrong code', '123456', -1],
    ['checkTotp five digits', '12345', -1],
    ['checkTotp letters', 'abcdef', -1],
  ])
    await file.add(name, { secret: fixed, code, now: NOW, lastUsedStep }, (input) =>
      MfaAuth.prototype.checkTotp.call(
        { now: () => input.now, secrets: [secretValue] },
        record(input.lastUsedStep),
        input.code,
      ),
    );
  return file.write(output);
}

async function webhooks(output) {
  const events = await dist('server', 'events.js');
  const authCrypto = await dist('auth', 'crypto.js');
  const file = new VectorFile('webhooks', {
    description:
      'Webhook deliveries: body = JSON.stringify(webhookBody(event)) (fixed member order: id, type, tenantId, actorId, resourceId, outcome, timestamp, then optional originalActorId, impersonatorId, rootOverride, metadata, sessionContext, sequence, hash); x-better-iam-timestamp = floor(now / 1000); x-better-iam-signature = "v1=" + hex HMAC-SHA256(webhook secret, timestamp "." body). The webhook secret is sealed with context "webhook:{hookId}". verifyWebhookSignature accepts any comma-separated v1= entry within the tolerance (default 300 s).',
    source:
      'packages/server/src/events.ts#webhookBody,createEvents.deliverWebhookMessage,verifyWebhookSignature',
  });
  const event = {
    id: 'evt_01',
    tenantId: 'tnt_01',
    actorId: 'idn_01',
    action: 'iam:groups:create',
    resourceId: 'grp_01',
    outcome: 'allow',
    rootOverride: false,
    timestamp: NOW,
  };
  const full = {
    ...event,
    originalActorId: 'idn_00',
    impersonatorId: 'idn_root',
    rootOverride: true,
    metadata: { name: 'Engineering', count: 3 },
    sessionContext: { kind: 'role', roleId: 'role_01' },
    sequence: 7,
    previousHash: 'a'.repeat(64),
    hash: 'b'.repeat(64),
  };
  for (const [name, value] of [
    ['webhookBody minimal', event],
    ['webhookBody full', full],
    [
      'webhookBody falsy optionals',
      { ...event, originalActorId: '', impersonatorId: undefined, metadata: undefined },
    ],
  ])
    await file.add(name, { event: value }, (input) => {
      const body = events.webhookBody(input.event);
      return { body, json: JSON.stringify(body) };
    });
  const deploymentSecret = 'deployment-secret-A-with-at-least-32-characters';
  const deliveries = [];
  const hook = (id, secret) => ({
    id,
    tenantId: 'tnt_01',
    url: 'https://hooks.example.com/iam',
    events: ['*'],
    active: true,
    secretSealed: authCrypto.encryptSecret(secret, deploymentSecret, `webhook:${id}`),
  });
  const deliver = async (input) => {
    const stored = hook(input.hookId, input.webhookSecret);
    const ctx = {
      options: {
        secret: deploymentSecret,
        events: { deliverWebhook: async (delivery) => deliveries.push(delivery) },
      },
      store: { get: async () => stored },
      config: { baseURL: new URL('https://iam.example.com'), webhookTimeoutMs: 5000 },
      plugins: [],
      subscribers: new Set(),
      now: () => input.now,
    };
    deliveries.length = 0;
    await events.createEvents(ctx).deliverWebhookMessage({
      id: input.messageId,
      tenantId: 'tnt_01',
      to: input.hookId,
      template: input.event,
      payload: { body: input.body },
    });
    return deliveries[0];
  };
  const body = JSON.stringify(events.webhookBody(event));
  const delivered = await file.add(
    'deliver signed webhook',
    {
      hookId: 'hook_01',
      webhookSecret: 'whsec_test_0123456789',
      messageId: 'msg_01',
      event: 'iam:groups:create',
      body,
      now: NOW + 1234,
    },
    deliver,
  );
  await file.add(
    'deliver at another second',
    {
      hookId: 'hook_02',
      webhookSecret: 'whsec_other',
      messageId: 'msg_02',
      event: 'iam:groups:create',
      body,
      now: NOW + 61_000,
    },
    deliver,
  );
  const signature = delivered.headers['x-better-iam-signature'];
  const timestamp = delivered.headers['x-better-iam-timestamp'];
  const verify = (input) => events.verifyWebhookSignature(input);
  for (const [name, input] of [
    [
      'verify valid',
      { secret: 'whsec_test_0123456789', timestamp, body, signature, now: NOW + 2000 },
    ],
    [
      'verify numeric timestamp',
      {
        secret: 'whsec_test_0123456789',
        timestamp: Number(timestamp),
        body,
        signature,
        now: NOW + 2000,
      },
    ],
    [
      'verify among several signatures',
      {
        secret: 'whsec_test_0123456789',
        timestamp,
        body,
        signature: `v0=abc, ${signature}`,
        now: NOW + 2000,
      },
    ],
    ['verify wrong secret', { secret: 'whsec_wrong', timestamp, body, signature, now: NOW + 2000 }],
    [
      'verify altered body',
      { secret: 'whsec_test_0123456789', timestamp, body: `${body} `, signature, now: NOW + 2000 },
    ],
    [
      'verify at tolerance edge',
      {
        secret: 'whsec_test_0123456789',
        timestamp,
        body,
        signature,
        now: (Number(timestamp) + 300) * 1000,
      },
    ],
    [
      'verify beyond tolerance',
      {
        secret: 'whsec_test_0123456789',
        timestamp,
        body,
        signature,
        now: (Number(timestamp) + 301) * 1000,
      },
    ],
    [
      'verify custom tolerance',
      {
        secret: 'whsec_test_0123456789',
        timestamp,
        body,
        signature,
        now: (Number(timestamp) + 301) * 1000,
        toleranceSeconds: 600,
      },
    ],
    [
      'verify upper-case hex',
      {
        secret: 'whsec_test_0123456789',
        timestamp,
        body,
        signature: signature.toUpperCase().replace('V1=', 'v1='),
        now: NOW + 2000,
      },
    ],
    [
      'verify non-numeric timestamp',
      { secret: 'whsec_test_0123456789', timestamp: 'abc', body, signature, now: NOW + 2000 },
    ],
    [
      'verify missing v1',
      {
        secret: 'whsec_test_0123456789',
        timestamp,
        body,
        signature: signature.replace('v1=', 'v2='),
        now: NOW + 2000,
      },
    ],
  ])
    await file.add(name, input, verify);
  return file.write(output);
}

export async function cryptoVectors(output) {
  const counts = {};
  for (const [name, fn] of [
    ['secrets', secrets],
    ['tokens', tokens],
    ['derivations', derivations],
    ['oauth-artifacts', oauthArtifacts],
    ['assertions', assertionsVectors],
    ['session-jwt', sessionJwt],
    ['delegation-tokens', delegationTokens],
    ['passwords', passwords],
    ['totp', totp],
    ['webhooks', webhooks],
  ])
    counts[name] = await fn(output);
  return counts;
}
