#!/usr/bin/env node
// Mixed-fleet check for the Go port of @better-iam/auth, TypeScript side. One SQLite database file is used by the
// TypeScript auth service and the Go one in turn (go/auth/fleet_test.go drives it):
//
//   node go/auth/testdata/fleet.mjs create <file>               TypeScript signs people in, enrolls, registers, queues
//   node go/auth/testdata/fleet.mjs verify <file> <go.json>     TypeScript uses what Go wrote
//
// Each command prints one JSON object on stdout. Requires the workspace to be built (packages/*/dist).
import { createHash, createPrivateKey, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const load = (pkg) => import(pathToFileURL(join(root, 'packages', pkg, 'dist', 'index.js')).href);
const core = await load('core');
const authPackage = await load('auth');
const { sqliteAdapter } = await load('adapter-sqlite');
const requireAuth = createRequire(join(root, 'packages/auth/package.json'));
const { authenticator } = requireAuth('otplib');

export const SECRET = 'fleet-test-secret-with-at-least-32-characters';
export const NOW = 1767225600000;
const RP_ID = 'iam.example.com';
const ORIGIN = 'https://iam.example.com';

const [command, file, goFile] = process.argv.slice(2);
if (!command || !file) {
  console.error('usage: fleet.mjs create|verify <file> [go.json]');
  process.exit(2);
}

function cbor(value) {
  const header = (major, size) =>
    size < 24
      ? Buffer.from([(major << 5) | size])
      : size < 256
        ? Buffer.from([(major << 5) | 24, size])
        : Buffer.from([(major << 5) | 25, size >> 8, size & 255]);
  if (typeof value === 'number') return header(value < 0 ? 1 : 0, value < 0 ? -1 - value : value);
  if (typeof value === 'string') {
    const bytes = Buffer.from(value);
    return Buffer.concat([header(3, bytes.length), bytes]);
  }
  if (Buffer.isBuffer(value)) return Buffer.concat([header(2, value.length), value]);
  if (value instanceof Map)
    return Buffer.concat([header(5, value.size), ...[...value].flatMap(([key, item]) => [cbor(key), cbor(item)])]);
  throw new Error('Unsupported CBOR test value');
}

/** tests/support/webauthn.ts VirtualAuthenticator, constructible from an exported key. */
class Authenticator {
  constructor(credentialId = randomBytes(32), privateKey) {
    this.credentialId = credentialId;
    if (privateKey) {
      this.privateKey = privateKey;
    } else {
      const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      this.privateKey = pair.privateKey;
    }
    this.rpHash = createHash('sha256').update(RP_ID).digest();
    this.counter = 0;
  }
  export() {
    return {
      credentialId: this.credentialId.toString('base64url'),
      pkcs8: this.privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
    };
  }
  register(challenge) {
    const jwk = this.privateKey.export({ format: "jwk" });
    const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
    const authData = Buffer.concat([this.rpHash, Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16),
      Buffer.from([0, this.credentialId.length]), this.credentialId, cose]);
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge, origin: ORIGIN }));
    return {
      id: this.credentialId.toString('base64url'),
      rawId: this.credentialId.toString('base64url'),
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: clientData.toString('base64url'),
        attestationObject: cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]])).toString('base64url'),
        transports: ['internal'],
      },
    };
  }
  assert(challenge, userId, counter) {
    const value = Buffer.alloc(4);
    value.writeUInt32BE(counter);
    const authData = Buffer.concat([this.rpHash, Buffer.from([0x05]), value]);
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge, origin: ORIGIN }));
    return {
      id: this.credentialId.toString('base64url'),
      rawId: this.credentialId.toString('base64url'),
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: clientData.toString('base64url'),
        authenticatorData: authData.toString('base64url'),
        signature: sign('sha256', Buffer.concat([authData, createHash('sha256').update(clientData).digest()]), this.privateKey).toString('base64url'),
        userHandle: Buffer.from(userId).toString('base64url'),
      },
    };
  }
}

function service(store, clock, inbox) {
  return authPackage.createAuth({
    store,
    secret: SECRET,
    baseURL: ORIGIN,
    sendEmail: async (message) => {
      inbox.push(message);
    },
    passkeys: { rpID: RP_ID },
    now: () => clock.now,
  });
}
const totp = (secret, now) => {
  const generator = authenticator.clone();
  generator.options = { epoch: now };
  return generator.generate(secret);
};
const sessionOf = (result) => {
  if ('mfaRequired' in result) throw new Error(`unexpected MFA challenge: ${JSON.stringify(result)}`);
  return result;
};
const challengeOf = (result) => {
  if (!('mfaRequired' in result)) throw new Error('expected an MFA challenge');
  return result.challenge;
};

const store = sqliteAdapter({ filename: file });
const inbox = [];
try {
  if (command === 'create') {
    await store.migrate();
    const clock = { now: NOW };
    const auth = service(store, clock, inbox);
    await store.transaction(async (tx) => {
      for (const [id, parentId, type] of [['root', null, 'root'], ['org', 'root', 'organization']])
        await tx.insert('tenants', { id, tenantId: id, name: id, parentId, type, status: 'active', createdAt: NOW });
    });
    const alice = await store.transaction((tx) =>
      auth.createIdentity(tx, { tenantId: 'org', email: 'alice@example.test', name: 'Alice', password: 'alice typescript password', emailVerified: true }),
    );
    const first = sessionOf(await auth.signIn({ tenantId: 'org', email: 'alice@example.test', password: 'alice typescript password' }));
    const enrollment = await auth.beginMfa({ token: first.token });
    const enabled = await auth.confirmMfa({ credential: { token: first.token }, code: totp(enrollment.secret, NOW), rememberDevice: true });
    const key = new Authenticator();
    const registration = await auth.beginPasskeyRegistration({ token: enabled.token });
    await auth.finishPasskeyRegistration(
      { token: enabled.token },
      { challengeId: registration.challengeId, response: key.register(registration.options.challenge), name: 'TypeScript key' },
    );
    await auth.requestPasswordReset({ tenantId: 'org', email: 'alice@example.test' });
    process.stdout.write(JSON.stringify({
      now: NOW,
      identityId: alice.id,
      sessionToken: enabled.token,
      totpSecret: enrollment.secret,
      recoveryCodes: enabled.recoveryCodes,
      deviceToken: enabled.deviceToken,
      passkey: key.export(),
      passwordHash: (await store.get('identities', alice.id)).passwordHash,
    }));
  } else if (command === 'verify') {
    const go = JSON.parse(readFileSync(goFile, 'utf8'));
    const clock = { now: go.now + 60_000 };
    const auth = service(store, clock, inbox);
    const checks = {};
    // Go's session for Bob authenticates here.
    checks.goSession = (await auth.authenticate({ token: go.bob.sessionToken })).identity.email;
    // Go's argon2 hash verifies, and the authenticator secret Go sealed opens.
    const challenge = challengeOf(await auth.signIn({ tenantId: 'org', email: 'bob@example.test', password: go.bob.password }));
    const verified = await auth.verifyMfa({ tenantId: 'org', challenge, code: totp(go.bob.totpSecret, clock.now) });
    checks.goTotp = verified.session.mfa;
    // Go's remembered device skips MFA.
    const remembered = sessionOf(await auth.signIn({ tenantId: 'org', email: 'bob@example.test', password: go.bob.password, deviceToken: go.bob.deviceToken }));
    checks.goDevice = typeof remembered.session.trustedDeviceId === 'string';
    // Go's stored COSE key verifies a TypeScript-made assertion.
    const key = new Authenticator(Buffer.from(go.bob.passkey.credentialId, 'base64url'),
      createPrivateKey({ key: Buffer.from(go.bob.passkey.pkcs8, 'base64'), format: 'der', type: 'pkcs8' }));
    const begun = await auth.beginPasskeyAuthentication({ tenantId: 'org', email: 'bob@example.test' });
    const passkey = await auth.finishPasskeyAuthentication({
      tenantId: 'org', challengeId: begun.challengeId, response: key.assert(begun.options.challenge, go.bob.identityId, 1),
    });
    checks.goPasskey = passkey.session.method;
    // The outbox message Go sealed is delivered here, and the reset link (digest made by Go) works.
    checks.dispatch = await auth.dispatchOutbox();
    const reset = inbox.find((message) => message.template === 'password-reset' && message.to === 'bob@example.test');
    await auth.resetPassword({ tenantId: 'org', token: reset.payload.token, password: 'bob reset by typescript' });
    // The reset revoked Bob's sessions and devices; the new password leads to his (Go-enrolled) second factor.
    checks.goReset = 'mfaRequired' in (await auth.signIn({ tenantId: 'org', email: 'bob@example.test', password: 'bob reset by typescript' }));
    // Alice's password, replaced by Go, verifies; her TypeScript-sealed authenticator still works after Go used it.
    clock.now += 30_000;
    const alice = challengeOf(await auth.signIn({ tenantId: 'org', email: 'alice@example.test', password: go.alice.password }));
    checks.alice = (await auth.verifyMfa({ tenantId: 'org', challenge: alice, code: totp(go.alice.totpSecret, clock.now) })).session.mfa;
    // Every audit event, whoever wrote it, forms one valid chain per tenant.
    const events = (await store.find('audit', { tenantId: 'org' })).sort((a, b) => a.sequence - b.sequence);
    const head = await store.get('auditChains', 'org');
    checks.chain = await core.verifyAuditChain(events, { head: { sequence: head.sequence, hash: head.hash } });
    checks.events = events.length;
    process.stdout.write(JSON.stringify(checks));
  } else {
    throw new Error(`unknown command ${command}`);
  }
} finally {
  await store.close();
}
