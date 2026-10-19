// Mixed-fleet check for authentication: the TypeScript auth service and the Rust one share a SQLite file. Used by
// crates/auth/tests/fleet.rs; runnable by hand:
//
//   node crates/auth/tests/fixtures/auth-fleet.mjs write  <file>          TypeScript signs people in, enrolls MFA,
//                                                                        registers a passkey, queues a delivery
//   node crates/auth/tests/fixtures/auth-fleet.mjs verify <file> <json>   TypeScript uses what Rust wrote
//
// Every command prints one JSON object on stdout. Run it with the Node version better-sqlite3 was built for.
import { createHash, createPrivateKey, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { createRequire } from 'node:module';
import { sqliteAdapter } from '../../../../packages/adapter-sqlite/dist/index.js';
import { createAuth } from '../../../../packages/auth/dist/index.js';

const require = createRequire(new URL('../../../../packages/auth/package.json', import.meta.url));
const { authenticator } = require('otplib');

export const SECRET = 'auth-fleet-secret-with-at-least-32-characters';
const ORIGIN = 'https://iam.example.com';
const RP_ID = 'iam.example.com';

function service(store, deliveries) {
  return createAuth({
    store,
    secret: SECRET,
    baseURL: ORIGIN,
    passkeys: { rpID: RP_ID },
    sendEmail: async (message) => {
      deliveries.push(message);
    },
  });
}

/** The code of the step after the current one: the enrollment just used the current step. */
const totp = (secret, ahead = 0) => {
  const generator = authenticator.clone();
  generator.options = { epoch: Date.now() + ahead };
  return generator.generate(secret);
};

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
    return Buffer.concat([header(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)])]);
  throw new Error('Unsupported CBOR test value');
}

async function write(file) {
  const store = sqliteAdapter({ filename: file });
  await store.migrate();
  const deliveries = [];
  const auth = service(store, deliveries);
  const now = Date.now();
  await store.transaction(async (tx) => {
    for (const [id, parentId, type] of [
      ['root', null, 'root'],
      ['org', 'root', 'organization'],
    ])
      await tx.insert('tenants', { id, tenantId: id, name: id, parentId, type, status: 'active', createdAt: now });
  });
  const create = (email, password) =>
    store.transaction((tx) =>
      auth.createIdentity(tx, { tenantId: 'org', email, name: email.split('@')[0], password, emailVerified: true }),
    );
  const ts = await create('ts@example.test', 'a typescript fleet password');
  const signedIn = await auth.signIn({ tenantId: 'org', email: 'ts@example.test', password: 'a typescript fleet password' });
  // MFA enrolled by TypeScript: the authenticator secret is sealed with the deployment secret.
  await create('mfa@example.test', 'a typescript mfa password');
  const first = await auth.signIn({ tenantId: 'org', email: 'mfa@example.test', password: 'a typescript mfa password' });
  const enrollment = await auth.beginMfa({ token: first.token });
  const enabled = await auth.confirmMfa({ credential: { token: first.token }, code: totp(enrollment.secret) });
  // A passkey registered through TypeScript (the COSE key as @simplewebauthn/server re-encodes it).
  const key = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = key.privateKey.export({ format: 'jwk' });
  const credentialId = randomBytes(32);
  const registration = await auth.beginPasskeyRegistration({ token: signedIn.token });
  const cose = cbor(
    new Map([
      [1, 2],
      [3, -7],
      [-1, 1],
      [-2, Buffer.from(jwk.x, 'base64url')],
      [-3, Buffer.from(jwk.y, 'base64url')],
    ]),
  );
  const rpHash = createHash('sha256').update(RP_ID).digest();
  const authData = Buffer.concat([rpHash, Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), Buffer.from([0, 32]), credentialId, cose]);
  const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: registration.options.challenge, origin: ORIGIN }));
  await auth.finishPasskeyRegistration(
    { token: signedIn.token },
    {
      challengeId: registration.challengeId,
      response: {
        id: credentialId.toString('base64url'),
        rawId: credentialId.toString('base64url'),
        type: 'public-key',
        clientExtensionResults: {},
        response: {
          clientDataJSON: clientData.toString('base64url'),
          attestationObject: cbor(new Map([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]])).toString('base64url'),
          transports: ['internal'],
        },
      },
    },
  );
  // A sealed delivery TypeScript queued and Rust will deliver.
  await auth.requestPasswordReset({ tenantId: 'org', email: 'ts@example.test' });
  await store.close();
  return {
    token: signedIn.token,
    identityId: ts.id,
    mfaSecret: enrollment.secret,
    recoveryCode: enabled.recoveryCodes[0],
    passkey: { credentialId: credentialId.toString('base64url'), d: jwk.d, x: jwk.x, y: jwk.y },
  };
}

async function verify(file, input) {
  const expected = JSON.parse(input);
  const store = sqliteAdapter({ filename: file });
  const deliveries = [];
  const auth = service(store, deliveries);
  const checks = {};
  // A Rust-issued session token authenticates here.
  checks.rustSession = (await auth.authenticate({ token: expected.token })).identity.id === expected.identityId;
  // A Rust argon2id hash verifies with node-argon2.
  const signedIn = await auth.signIn({ tenantId: 'org', email: 'rs@example.test', password: expected.password });
  checks.rustPassword = typeof signedIn.token === 'string';
  // A Rust-sealed authenticator secret opens, and its codes verify.
  const challenge = await auth.signIn({ tenantId: 'org', email: 'rsmfa@example.test', password: expected.mfaPassword });
  checks.mfaChallenge = challenge.mfaRequired === true;
  const verified = await auth.verifyMfa({ tenantId: 'org', challenge: challenge.challenge, code: totp(expected.mfaSecret, 30_000) });
  checks.rustMfa = verified.session.mfa === true;
  // A Rust-sealed outbox payload opens and is delivered.
  const result = await auth.dispatchOutbox();
  checks.outbox = result.delivered >= 1 && deliveries.some((message) => message.template === 'password-reset' && message.to === 'rs@example.test' && typeof message.payload.token === 'string');
  // A passkey Rust registered (its re-encoded COSE key) verifies here.
  const begun = await auth.beginPasskeyAuthentication({ tenantId: 'org', email: 'rs@example.test' });
  const { d, x, y, credentialId } = expected.passkey;
  const privateKey = createPrivateKey({ key: { kty: 'EC', crv: 'P-256', d, x, y }, format: 'jwk' });
  const rpHash = createHash('sha256').update(RP_ID).digest();
  const authData = Buffer.concat([rpHash, Buffer.from([0x05]), Buffer.from([0, 0, 0, 7])]);
  const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: begun.options.challenge, origin: ORIGIN }));
  const signature = sign('sha256', Buffer.concat([authData, createHash('sha256').update(clientData).digest()]), privateKey);
  const passkey = await auth.finishPasskeyAuthentication({
    tenantId: 'org',
    challengeId: begun.challengeId,
    response: {
      id: credentialId,
      rawId: credentialId,
      type: 'public-key',
      clientExtensionResults: {},
      response: {
        clientDataJSON: clientData.toString('base64url'),
        authenticatorData: authData.toString('base64url'),
        signature: signature.toString('base64url'),
        userHandle: Buffer.from(expected.identityId).toString('base64url'),
      },
    },
  });
  checks.rustPasskey = passkey.session.method === 'passkey' && passkey.session.identityId === expected.identityId;
  await store.close();
  return { checks };
}

const [command, file, input] = process.argv.slice(2);
const run = { write: () => write(file), verify: () => verify(file, input) }[command];
if (!run) throw new Error(`unknown command ${command}`);
process.stdout.write(`${JSON.stringify(await run())}\n`);
