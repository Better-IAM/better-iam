import {
  constants,
  createHmac,
  generateKeyPairSync,
  randomUUID,
  sign,
  type JsonWebKey,
  type KeyObject,
} from 'node:crypto';

/**
 * Test-only JWT helpers built on node:crypto, so tests can play an external identity provider or forge IAM session
 * JWTs without depending on the library under test.
 */
export type TestKeyAlgorithm = 'EdDSA' | 'ES256' | 'ES384' | 'RS256' | 'PS256';

export interface TestKey {
  kid: string;
  alg: TestKeyAlgorithm;
  /** The private JWK, with `kid` and `alg`. */
  privateJwk: JsonWebKey & { kid: string; alg: TestKeyAlgorithm };
  /** The public JWK, with `kid`, `alg` and `use: 'sig'`. */
  publicJwk: JsonWebKey & { kid: string; alg: TestKeyAlgorithm; use: 'sig' };
  privateKey: KeyObject;
}

/** Generates a fresh signing key pair for an algorithm (RSA keys are 2048 bits). */
export function generateTestKey(alg: TestKeyAlgorithm, kid: string = randomUUID()): TestKey {
  const pair =
    alg === 'EdDSA'
      ? generateKeyPairSync('ed25519')
      : alg === 'ES256' || alg === 'ES384'
        ? generateKeyPairSync('ec', { namedCurve: alg === 'ES256' ? 'P-256' : 'P-384' })
        : generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    kid,
    alg,
    privateJwk: { ...pair.privateKey.export({ format: 'jwk' }), kid, alg },
    publicJwk: { ...pair.publicKey.export({ format: 'jwk' }), kid, alg, use: 'sig' },
    privateKey: pair.privateKey,
  };
}

const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

function signature(signer: SignTestJwtKey, data: Buffer): string {
  if (signer.alg === 'none') return '';
  if (signer.alg === 'HS256')
    return createHmac('sha256', signer.secret).update(data).digest('base64url');
  const key = signer.privateKey;
  switch (signer.alg) {
    case 'EdDSA':
      return sign(null, data, key).toString('base64url');
    case 'ES256':
    case 'ES384':
      return sign(signer.alg === 'ES256' ? 'sha256' : 'sha384', data, {
        key,
        dsaEncoding: 'ieee-p1363',
      }).toString('base64url');
    case 'RS256':
      return sign('sha256', data, key).toString('base64url');
    case 'PS256':
      return sign('sha256', data, {
        key,
        padding: constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 32,
      }).toString('base64url');
  }
}

export type SignTestJwtKey = TestKey | { alg: 'HS256'; secret: string | Buffer } | { alg: 'none' };

/**
 * Signs a compact JWT. The header defaults to `{ alg, typ: 'JWT', kid }` for the key; `header` entries override it
 * (an `undefined` entry removes the member), and the signature always uses the key's real algorithm.
 */
export function signTestJwt(
  key: SignTestJwtKey,
  payload: Record<string, unknown>,
  header: Record<string, unknown> = {},
): string {
  const base: Record<string, unknown> = {
    alg: key.alg,
    typ: 'JWT',
    ...('kid' in key ? { kid: key.kid } : {}),
  };
  const merged = { ...base, ...header };
  const signingInput = `${encode(merged)}.${encode(payload)}`;
  return `${signingInput}.${signature(key, Buffer.from(signingInput))}`;
}

/** Decodes a compact JWT without verifying it. */
export function decodeTestJwt(token: string): {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
} {
  const [header, payload, signature = ''] = token.split('.');
  return {
    header: JSON.parse(Buffer.from(header!, 'base64url').toString('utf8')),
    payload: JSON.parse(Buffer.from(payload!, 'base64url').toString('utf8')),
    signature,
  };
}

/** Rewrites the payload (merging `patch`) while keeping the original header and signature. */
export function tamperPayload(token: string, patch: Record<string, unknown>): string {
  const [header, , signature = ''] = token.split('.');
  const { payload } = decodeTestJwt(token);
  return `${header}.${encode({ ...payload, ...patch })}.${signature}`;
}
