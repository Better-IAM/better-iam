// Fixed test keys, derived from labels so they are the same on every run (never use them outside tests).
import crypto from 'node:crypto';

const seedOf = (label) =>
  crypto.createHash('sha256').update(`better-iam-spec-key:${label}`).digest();
const ed25519Pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');

/** An Ed25519 private JWK (with `kid` and `alg: EdDSA`) from a label. */
export function ed25519Jwk(label, kid = label) {
  const key = crypto.createPrivateKey({
    key: Buffer.concat([ed25519Pkcs8Prefix, seedOf(label)]),
    format: 'der',
    type: 'pkcs8',
  });
  const jwk = key.export({ format: 'jwk' });
  return { kty: jwk.kty, crv: jwk.crv, x: jwk.x, d: jwk.d, kid, alg: 'EdDSA' };
}

/** A P-256 private JWK (with `kid` and `alg: ES256`) from a label. */
export function p256Jwk(label, kid = label) {
  const ecdh = crypto.createECDH('prime256v1');
  // Reduce the seed below the group order by retrying with a counter (practically never needed).
  for (let counter = 0; ; counter++) {
    const d = crypto.createHash('sha256').update(seedOf(label)).update(String(counter)).digest();
    try {
      ecdh.setPrivateKey(d);
      break;
    } catch {
      /* Out of range: try the next candidate. */
    }
  }
  const publicKey = ecdh.getPublicKey();
  return {
    kty: 'EC',
    crv: 'P-256',
    x: publicKey.subarray(1, 33).toString('base64url'),
    y: publicKey.subarray(33, 65).toString('base64url'),
    d: ecdh.getPrivateKey().toString('base64url'),
    kid,
    alg: 'ES256',
  };
}

/** The public members of a private JWK. */
export function publicJwk(jwk) {
  const { d: _d, ...rest } = jwk;
  return rest;
}
