// RFC 6238 TOTP (SHA-1, 6 digits, 30-second steps): the defaults of otplib's `authenticator`, which the test suite and
// @better-iam/auth use. The recorder uses it to recognize codes a test computed from a secret the server returned, and
// the replay runner to compute the same code from the secret the server under test returned.
import { createHmac } from 'node:crypto';

const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(text) {
  const clean = String(text).toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const char of clean) {
    const index = alphabet.indexOf(char);
    if (index < 0) return undefined;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** The code for `secret` (base32) at `epochMs`, offset by `window` steps. */
export function totp(secret, epochMs, { step = 30, digits = 6, window = 0 } = {}) {
  const key = base32Decode(secret);
  if (!key || !key.length) return undefined;
  const counter = Math.floor(epochMs / 1000 / step) + window;
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', key).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, '0');
}

/** Whether a string can be a base32 TOTP secret (16+ characters of the RFC 4648 base32 alphabet). */
export const looksLikeTotpSecret = (value) =>
  typeof value === 'string' && /^[A-Z2-7]{16,128}=*$/.test(value);

/** The secret inside an `otpauth://` URI, if any. */
export function otpauthSecret(uri) {
  if (typeof uri !== 'string' || !uri.startsWith('otpauth://')) return undefined;
  try {
    return new URL(uri).searchParams.get('secret') ?? undefined;
  } catch {
    return undefined;
  }
}
