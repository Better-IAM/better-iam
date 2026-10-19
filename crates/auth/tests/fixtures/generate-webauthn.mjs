// Generates crates/auth/tests/fixtures/webauthn.json: WebAuthn registration and authentication responses built in
// Node (real P-256, Ed25519 and RSA keys; X.509 attestation certificates from @peculiar/x509) together with what
// @simplewebauthn/server 13 (the TypeScript server's verifier) decides about each, so the Rust verifier can be
// checked against the library itself.
//
//   node crates/auth/tests/fixtures/generate-webauthn.mjs
import { createHash, generateKeyPairSync, randomBytes, sign, webcrypto } from 'node:crypto';
import { createRequire } from 'node:module';
import { writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const require = createRequire(new URL('../../../../packages/auth/package.json', import.meta.url));
const { verifyRegistrationResponse, verifyAuthenticationResponse } = require('@simplewebauthn/server');
const peculiar = createRequire(require.resolve('@simplewebauthn/server'))('@peculiar/x509');
peculiar.cryptoProvider.set(webcrypto);

const RP_ID = 'iam.example.com';
const ORIGIN = 'https://iam.example.com';
const rpHash = createHash('sha256').update(RP_ID).digest();
const b64u = (bytes) => Buffer.from(bytes).toString('base64url');

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
  if (Buffer.isBuffer(value) || value instanceof Uint8Array)
    return Buffer.concat([header(2, value.length), Buffer.from(value)]);
  if (Array.isArray(value)) return Buffer.concat([header(4, value.length), ...value.map(cbor)]);
  if (value instanceof Map)
    return Buffer.concat([header(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)])]);
  throw new Error('Unsupported CBOR test value');
}

function coseKey(kind, publicKey) {
  const jwk = publicKey.export({ format: 'jwk' });
  if (kind === 'ec')
    return cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
  if (kind === 'ed25519') return cbor(new Map([[1, 1], [3, -8], [-1, 6], [-2, Buffer.from(jwk.x, 'base64url')]]));
  return cbor(new Map([[1, 3], [3, -257], [-1, Buffer.from(jwk.n, 'base64url')], [-2, Buffer.from(jwk.e, 'base64url')]]));
}

function keyPair(kind) {
  if (kind === 'ec') return generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  if (kind === 'ed25519') return generateKeyPairSync('ed25519');
  return generateKeyPairSync('rsa', { modulusLength: 2048 });
}

function signWith(kind, privateKey, data) {
  if (kind === 'ed25519') return sign(null, data, privateKey);
  return sign('sha256', data, privateKey);
}

function authData({ flags, counter = 0, credentialId, cose, aaguid = Buffer.alloc(16) }) {
  const count = Buffer.alloc(4);
  count.writeUInt32BE(counter);
  const parts = [rpHash, Buffer.from([flags]), count];
  if (credentialId) parts.push(aaguid, Buffer.from([credentialId.length >> 8, credentialId.length & 255]), credentialId, cose);
  return Buffer.concat(parts);
}

function clientData(type, challenge, origin = ORIGIN) {
  return Buffer.from(JSON.stringify({ type, challenge, origin }));
}

function registration({ credentialId, fmt, attStmt, data, client, transports = ['internal'] }) {
  return {
    id: b64u(credentialId),
    rawId: b64u(credentialId),
    type: 'public-key',
    clientExtensionResults: {},
    response: {
      clientDataJSON: b64u(client),
      attestationObject: b64u(cbor(new Map([['fmt', fmt], ['attStmt', attStmt], ['authData', data]]))),
      transports,
    },
  };
}

async function verifyRegistration(response, challenge) {
  try {
    const result = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: [ORIGIN],
      expectedRPID: RP_ID,
      requireUserVerification: true,
    });
    if (!result.verified) return { verified: false };
    const info = result.registrationInfo;
    return {
      verified: true,
      fmt: info.fmt,
      aaguid: info.aaguid,
      credentialId: info.credential.id,
      publicKey: b64u(info.credential.publicKey),
      counter: info.credential.counter,
      deviceType: info.credentialDeviceType,
      backedUp: info.credentialBackedUp,
    };
  } catch (error) {
    return { error: String(error.message) };
  }
}

async function verifyAuthentication(response, challenge, credential) {
  try {
    const result = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: [ORIGIN],
      expectedRPID: RP_ID,
      requireUserVerification: true,
      credential: { id: credential.id, publicKey: new Uint8Array(Buffer.from(credential.publicKey, 'base64url')), counter: credential.counter },
    });
    return { verified: result.verified, newCounter: result.authenticationInfo.newCounter, userVerified: result.authenticationInfo.userVerified };
  } catch (error) {
    return { error: String(error.message) };
  }
}

async function certificate({ subject, issuer, keys, signingKey, ca, extensions = [] }) {
  return peculiar.X509CertificateGenerator.create({
    serialNumber: randomBytes(8).toString('hex'),
    subject,
    issuer,
    notBefore: new Date(Date.now() - 24 * 60 * 60_000),
    notAfter: new Date(Date.now() + 10 * 365 * 24 * 60 * 60_000),
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    publicKey: keys.publicKey,
    signingKey,
    extensions: [new peculiar.BasicConstraintsExtension(ca, undefined, true), ...extensions],
  });
}

const ecAlgorithm = { name: 'ECDSA', namedCurve: 'P-256' };

async function main() {
  const cases = [];
  // Plain `none` registrations and assertions for each key type.
  for (const kind of ['ec', 'ed25519', 'rsa']) {
    const keys = keyPair(kind);
    const credentialId = randomBytes(32);
    const cose = coseKey(kind, keys.publicKey);
    const challenge = b64u(randomBytes(32));
    const response = registration({
      credentialId,
      fmt: 'none',
      attStmt: new Map(),
      data: authData({ flags: 0x45, credentialId, cose }),
      client: clientData('webauthn.create', challenge),
    });
    const expected = await verifyRegistration(response, challenge);
    cases.push({ name: `none registration (${kind})`, kind: 'registration', challenge, response, expected });
    const credential = { id: expected.credentialId, publicKey: expected.publicKey, counter: 0 };
    for (const [label, counter, flags, origin] of [
      ['valid', 1, 0x05, ORIGIN],
      ['replayed counter', 0, 0x05, ORIGIN],
      ['not user-verified', 2, 0x01, ORIGIN],
      ['wrong origin', 3, 0x05, 'https://attacker.example'],
    ]) {
      const assertionChallenge = b64u(randomBytes(32));
      const data = authData({ flags, counter });
      const client = clientData('webauthn.get', assertionChallenge, origin);
      const signature = signWith(kind, keys.privateKey, Buffer.concat([data, createHash('sha256').update(client).digest()]));
      const assertion = {
        id: credential.id,
        rawId: credential.id,
        type: 'public-key',
        clientExtensionResults: {},
        response: {
          clientDataJSON: b64u(client),
          authenticatorData: b64u(data),
          signature: b64u(signature),
          userHandle: b64u('usr_01'),
        },
      };
      const stored = label === 'replayed counter' ? { ...credential, counter: 4 } : credential;
      cases.push({
        name: `${kind} assertion (${label})`,
        kind: 'authentication',
        challenge: assertionChallenge,
        credential: stored,
        response: assertion,
        expected: await verifyAuthentication(assertion, assertionChallenge, stored),
      });
    }
    // A tampered signature.
    const assertionChallenge = b64u(randomBytes(32));
    const data = authData({ flags: 0x05, counter: 9 });
    const client = clientData('webauthn.get', assertionChallenge);
    const signature = signWith(kind, keys.privateKey, Buffer.concat([data, createHash('sha256').update(client).digest()]));
    signature[signature.length - 1] ^= 1;
    const tampered = {
      id: credential.id,
      rawId: credential.id,
      type: 'public-key',
      clientExtensionResults: {},
      response: { clientDataJSON: b64u(client), authenticatorData: b64u(data), signature: b64u(signature) },
    };
    cases.push({
      name: `${kind} assertion (tampered signature)`,
      kind: 'authentication',
      challenge: assertionChallenge,
      credential,
      response: tampered,
      expected: await verifyAuthentication(tampered, assertionChallenge, credential),
    });
  }

  // Packed self attestation, and flag edge cases.
  {
    const keys = keyPair('ec');
    const credentialId = randomBytes(16);
    const cose = coseKey('ec', keys.publicKey);
    for (const [label, flags] of [
      ['packed self', 0x45],
      ['packed self, backed up multi-device', 0x5d],
      ['packed self, backed up single-device', 0x55],
      ['packed self, no user presence', 0x44],
    ]) {
      const challenge = b64u(randomBytes(32));
      const data = authData({ flags, credentialId, cose });
      const client = clientData('webauthn.create', challenge);
      const sig = sign('sha256', Buffer.concat([data, createHash('sha256').update(client).digest()]), keys.privateKey);
      const response = registration({ credentialId, fmt: 'packed', attStmt: new Map([['alg', -7], ['sig', sig]]), data, client });
      cases.push({ name: label, kind: 'registration', challenge, response, expected: await verifyRegistration(response, challenge) });
    }
  }

  // Packed full attestation with an x5c chain (no default trust anchors for packed), and fido-u2f.
  {
    const caKeys = await webcrypto.subtle.generateKey(ecAlgorithm, true, ['sign', 'verify']);
    const leafKeys = await webcrypto.subtle.generateKey(ecAlgorithm, true, ['sign', 'verify']);
    const aaguid = randomBytes(16);
    const ca = await certificate({ subject: 'CN=Test Attestation CA', issuer: 'CN=Test Attestation CA', keys: caKeys, signingKey: caKeys.privateKey, ca: true });
    const aaguidExtension = new peculiar.Extension('1.3.6.1.4.1.45724.1.1.4', false, Buffer.concat([Buffer.from([0x04, 0x10]), aaguid]));
    for (const [label, subject, extensionAaguid] of [
      ['packed full', 'C=US, O=Test Vendor, OU=Authenticator Attestation, CN=Test Authenticator', aaguid],
      ['packed full, wrong OU', 'C=US, O=Test Vendor, OU=Somebody Else, CN=Test Authenticator', aaguid],
      ['packed full, mismatched AAGUID extension', 'C=US, O=Test Vendor, OU=Authenticator Attestation, CN=Test Authenticator', randomBytes(16)],
    ]) {
      const extension = new peculiar.Extension('1.3.6.1.4.1.45724.1.1.4', false, Buffer.concat([Buffer.from([0x04, 0x10]), extensionAaguid]));
      const leaf = await certificate({ subject, issuer: ca.subject, keys: leafKeys, signingKey: caKeys.privateKey, ca: false, extensions: [extension] });
      const keys = keyPair('ec');
      const credentialId = randomBytes(16);
      const cose = coseKey('ec', keys.publicKey);
      const challenge = b64u(randomBytes(32));
      const data = authData({ flags: 0x45, credentialId, cose, aaguid });
      const client = clientData('webauthn.create', challenge);
      const signed = Buffer.concat([data, createHash('sha256').update(client).digest()]);
      const sig = Buffer.from(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, leafKeys.privateKey, signed));
      const der = (raw) => {
        const trim = (part) => {
          let index = 0;
          while (index < part.length - 1 && part[index] === 0 && !(part[index + 1] & 0x80)) index++;
          const value = part.subarray(index);
          return value[0] & 0x80 ? Buffer.concat([Buffer.from([0]), value]) : value;
        };
        const r = trim(raw.subarray(0, 32));
        const s = trim(raw.subarray(32));
        const body = Buffer.concat([Buffer.from([2, r.length]), r, Buffer.from([2, s.length]), s]);
        return Buffer.concat([Buffer.from([0x30, body.length]), body]);
      };
      const response = registration({
        credentialId,
        fmt: 'packed',
        attStmt: new Map([['alg', -7], ['sig', der(sig)], ['x5c', [Buffer.from(leaf.rawData), Buffer.from(ca.rawData)]]]),
        data,
        client,
        transports: ['usb', 'nfc'],
      });
      cases.push({ name: label, kind: 'registration', challenge, response, expected: await verifyRegistration(response, challenge) });
    }
    void aaguidExtension;
    // fido-u2f: a zero AAGUID and a signature over 0x00 || rpIdHash || clientDataHash || credentialId || publicKey.
    const leaf = await certificate({ subject: 'CN=U2F Device', issuer: ca.subject, keys: leafKeys, signingKey: caKeys.privateKey, ca: false });
    for (const [label, aaguid] of [
      ['fido-u2f', Buffer.alloc(16)],
      ['fido-u2f, non-zero AAGUID', randomBytes(16)],
    ]) {
      const keys = keyPair('ec');
      const credentialId = randomBytes(64);
      const jwk = keys.publicKey.export({ format: 'jwk' });
      const cose = coseKey('ec', keys.publicKey);
      const challenge = b64u(randomBytes(32));
      const data = authData({ flags: 0x45, credentialId, cose, aaguid });
      const client = clientData('webauthn.create', challenge);
      const publicKey = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
      const signed = Buffer.concat([Buffer.from([0]), rpHash, createHash('sha256').update(client).digest(), credentialId, publicKey]);
      const raw = Buffer.from(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, leafKeys.privateKey, signed));
      const r = raw.subarray(0, 32);
      const s = raw.subarray(32);
      const int = (part) => (part[0] & 0x80 ? Buffer.concat([Buffer.from([0]), part]) : part);
      const body = Buffer.concat([Buffer.from([2, int(r).length]), int(r), Buffer.from([2, int(s).length]), int(s)]);
      const sig = Buffer.concat([Buffer.from([0x30, body.length]), body]);
      const response = registration({
        credentialId,
        fmt: 'fido-u2f',
        attStmt: new Map([['sig', sig], ['x5c', [Buffer.from(leaf.rawData)]]]),
        data,
        client,
        transports: ['usb'],
      });
      cases.push({ name: label, kind: 'registration', challenge, response, expected: await verifyRegistration(response, challenge) });
    }
  }

  // TPM attestation (no default trust anchors for tpm): an AIK certificate with the TCG subject alternative name and
  // extended key usage, signing certInfo over a pubArea that names the credential key.
  {
    const caKeys = await webcrypto.subtle.generateKey(ecAlgorithm, true, ['sign', 'verify']);
    const aikKeys = await webcrypto.subtle.generateKey(ecAlgorithm, true, ['sign', 'verify']);
    const ca = await certificate({ subject: 'CN=Test TPM CA', issuer: 'CN=Test TPM CA', keys: caKeys, signingKey: caKeys.privateKey, ca: true });
    const aikFor = async (manufacturer, usage) =>
      certificate({
        subject: '',
        issuer: ca.subject,
        keys: aikKeys,
        signingKey: caKeys.privateKey,
        ca: false,
        extensions: [
          new peculiar.SubjectAlternativeNameExtension([
            { type: 'dn', value: `2.23.133.2.1=${manufacturer}, 2.23.133.2.2=FIDO2, 2.23.133.2.3=id:0002` },
          ]),
          new peculiar.ExtendedKeyUsageExtension([usage]),
        ],
      });
    const u16 = (value) => Buffer.from([value >> 8, value & 255]);
    const u32 = (value) => {
      const out = Buffer.alloc(4);
      out.writeUInt32BE(value >>> 0);
      return out;
    };
    const sized = (bytes) => Buffer.concat([u16(bytes.length), bytes]);
    const rawToDer = (raw) => {
      const int = (part) => {
        let index = 0;
        while (index < part.length - 1 && part[index] === 0 && !(part[index + 1] & 0x80)) index++;
        const value = part.subarray(index);
        return value[0] & 0x80 ? Buffer.concat([Buffer.from([0]), value]) : value;
      };
      const r = int(raw.subarray(0, raw.length / 2));
      const t = int(raw.subarray(raw.length / 2));
      const body = Buffer.concat([Buffer.from([2, r.length]), r, Buffer.from([2, t.length]), t]);
      return Buffer.concat([Buffer.from([0x30, body.length]), body]);
    };
    for (const [label, kind, mutate] of [
      ['tpm (ECC credential)', 'ec', {}],
      ['tpm (RSA credential)', 'rsa', {}],
      ['tpm, wrong extra data', 'ec', { extraData: true }],
      ['tpm, unknown manufacturer', 'ec', { manufacturer: 'id:12345678' }],
      ['tpm, wrong key usage', 'ec', { usage: '1.3.6.1.5.5.7.3.2' }],
      ['tpm, wrong attested name', 'ec', { name: true }],
    ]) {
      const keys = keyPair(kind);
      const jwk = keys.publicKey.export({ format: 'jwk' });
      const credentialId = randomBytes(16);
      const cose = coseKey(kind, keys.publicKey);
      const challenge = b64u(randomBytes(32));
      const aaguid = randomBytes(16);
      const data = authData({ flags: 0x45, credentialId, cose, aaguid });
      const client = clientData('webauthn.create', challenge);
      const pubArea =
        kind === 'ec'
          ? Buffer.concat([u16(0x0023), u16(0x000b), u32(0x00060472), sized(Buffer.alloc(0)), u16(0x0010), u16(0x0010), u16(0x0003), u16(0x0010), sized(Buffer.from(jwk.x, 'base64url')), sized(Buffer.from(jwk.y, 'base64url'))])
          : Buffer.concat([u16(0x0001), u16(0x000b), u32(0x00060472), sized(Buffer.alloc(0)), u16(0x0010), u16(0x0010), u16(2048), u32(0), sized(Buffer.from(jwk.n, 'base64url'))]);
      const toBeSigned = Buffer.concat([data, createHash('sha256').update(client).digest()]);
      const extraData = createHash('sha256').update(mutate.extraData ? Buffer.concat([toBeSigned, Buffer.from([1])]) : toBeSigned).digest();
      const name = Buffer.concat([u16(0x000b), createHash('sha256').update(mutate.name ? Buffer.concat([pubArea, Buffer.from([0])]) : pubArea).digest()]);
      const certInfo = Buffer.concat([
        u32(0xff544347),
        u16(0x8017),
        sized(Buffer.alloc(0)),
        sized(extraData),
        Buffer.alloc(8),
        u32(1),
        u32(2),
        Buffer.from([1]),
        Buffer.alloc(8),
        sized(name),
        sized(Buffer.alloc(0)),
      ]);
      const aik = await aikFor(mutate.manufacturer ?? 'id:FFFFF1D0', mutate.usage ?? '2.23.133.8.3');
      const sig = rawToDer(Buffer.from(await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, aikKeys.privateKey, certInfo)));
      const attStmt = new Map([
        ['ver', '2.0'],
        ['alg', -7],
        ['x5c', [Buffer.from(aik.rawData), Buffer.from(ca.rawData)]],
        ['sig', sig],
        ['certInfo', certInfo],
        ['pubArea', pubArea],
      ]);
      const response = registration({ credentialId, fmt: 'tpm', attStmt, data, client, transports: ['internal'] });
      cases.push({ name: label, kind: 'registration', challenge, response, expected: await verifyRegistration(response, challenge) });
    }
    // Formats with default trust anchors cannot be produced here; certificates that do not chain to them are refused.
    const leaf = await certificate({ subject: 'CN=Not Apple', issuer: ca.subject, keys: aikKeys, signingKey: caKeys.privateKey, ca: false });
    for (const fmt of ['apple', 'android-key', 'android-safetynet']) {
      const keys = keyPair('ec');
      const credentialId = randomBytes(16);
      const cose = coseKey('ec', keys.publicKey);
      const challenge = b64u(randomBytes(32));
      const data = authData({ flags: 0x45, credentialId, cose });
      const client = clientData('webauthn.create', challenge);
      const attStmt =
        fmt === 'android-safetynet'
          ? new Map([['ver', '1'], ['response', Buffer.from('e30.e30.sig')]])
          : new Map([['alg', -7], ['sig', Buffer.from([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])], ['x5c', [Buffer.from(leaf.rawData), Buffer.from(ca.rawData)]]]);
      const response = registration({ credentialId, fmt, attStmt, data, client });
      cases.push({ name: `${fmt} without a trusted chain`, kind: 'registration', challenge, response, expected: await verifyRegistration(response, challenge) });
    }
  }

  // Malformed registrations.
  {
    const keys = keyPair('ec');
    const credentialId = randomBytes(16);
    const cose = coseKey('ec', keys.publicKey);
    const challenge = b64u(randomBytes(32));
    const good = authData({ flags: 0x45, credentialId, cose });
    for (const [label, mutate] of [
      ['none with a statement', (r) => registration({ ...r, attStmt: new Map([['x', 1]]) })],
      ['leftover bytes', (r) => registration({ ...r, data: Buffer.concat([good, Buffer.from([0])]) })],
      ['unknown format', (r) => registration({ ...r, fmt: 'mystery' })],
      ['wrong client data type', (r) => registration({ ...r, client: clientData('webauthn.get', challenge) })],
      ['wrong challenge', (r) => registration({ ...r, client: clientData('webauthn.create', 'other') })],
      ['wrong RP', (r) => registration({ ...r, data: Buffer.concat([createHash('sha256').update('evil.example').digest(), good.subarray(32)]) })],
    ]) {
      const response = mutate({ credentialId, fmt: 'none', attStmt: new Map(), data: good, client: clientData('webauthn.create', challenge) });
      cases.push({ name: label, kind: 'registration', challenge, response, expected: await verifyRegistration(response, challenge) });
    }
  }
  const out = fileURLToPath(new URL('./webauthn.json', import.meta.url));
  writeFileSync(out, `${JSON.stringify({ description: 'WebAuthn responses and @simplewebauthn/server 13.3.3 verdicts (generate-webauthn.mjs)', rpId: RP_ID, origin: ORIGIN, cases }, null, 2)}\n`);
  console.log(`${cases.length} cases written to ${out}`);
}

await main();
