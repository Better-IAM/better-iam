import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { crc32 } from 'node:zlib';
import { IamError } from '@better-iam/core';

export const newId = (prefix = 'id'): string =>
  `${prefix}_${randomBytes(16).toString('base64url')}`;
export const newToken = (): string => randomBytes(32).toString('base64url');
export const hashToken = (token: string): string =>
  createHash('sha256').update(token).digest('hex');

/**
 * The type part of a prefixed credential token: `ses` (user and impersonation sessions), `key` (API keys), `rol` (role
 * sessions, including web identity), `sts` (session tokens) and `dlg` (delegated agent sessions).
 */
export type CredentialTokenType = 'ses' | 'key' | 'rol' | 'sts' | 'dlg';

/** The session kind each credential token type must resolve to; the stored kind stays authoritative. */
export const credentialTokenKinds = Object.freeze({
  ses: 'user',
  key: 'api-key',
  rol: 'role',
  sts: 'session-token',
  dlg: 'delegated',
} as const);

/**
 * A pattern secret scanners can use to find better-iam credential tokens in text. It needs lookbehind support; without
 * it, use `biam_(ses|key|rol|sts|dlg)_[A-Za-z0-9_-]{49}` with explicit boundary rules.
 */
export const credentialTokenScanPattern =
  '(?<![A-Za-z0-9_-])biam_(?:ses|key|rol|sts|dlg)_[A-Za-z0-9_-]{49}(?![A-Za-z0-9_-])';

const credentialTokenPattern = /^biam_(ses|key|rol|sts|dlg)_([A-Za-z0-9_-]{43})([A-Za-z0-9_-]{6})$/;

/** The base64url of the big-endian CRC-32 (IEEE, as zlib computes it) of the token body. */
function credentialTokenCheck(body: string): string {
  const check = Buffer.alloc(4);
  check.writeUInt32BE(crc32(body) >>> 0);
  return check.toString('base64url');
}

/**
 * A new opaque credential token, `biam_<type>_` + 43 random base64url characters + a 6-character CRC-32 checksum (58
 * characters in all). The checksum lets scanners and the server reject garbage early; it authenticates nothing.
 */
export function newCredentialToken(type: CredentialTokenType): string {
  if (!Object.hasOwn(credentialTokenKinds, type)) {
    throw new IamError('INVALID_INPUT', 'Unknown credential token type');
  }
  const body = `biam_${type}_${newToken()}`;
  return body + credentialTokenCheck(body);
}

/**
 * Parses a prefixed credential token: its type when the shape and checksum match, otherwise undefined. The type is a
 * routing hint only; authorization always uses the stored session.
 */
export function parseCredentialToken(value: string): { type: CredentialTokenType } | undefined {
  if (typeof value !== 'string') return undefined;
  const match = credentialTokenPattern.exec(value);
  if (!match) return undefined;
  const body = value.slice(0, value.length - 6);
  if (credentialTokenCheck(body) !== match[3]) return undefined;
  return { type: match[1] as CredentialTokenType };
}

/** Authenticated encryption; the application secret must be a high-entropy, stable secret. */
export function encryptSecret(value: string, secret: string, context = 'better-iam'): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', createHash('sha256').update(secret).digest(), iv);
  cipher.setAAD(Buffer.from(context));
  const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return [iv, cipher.getAuthTag(), encrypted].map((part) => part.toString('base64url')).join('.');
}

/**
 * Opens a sealed value with the first of `secrets` that authenticates it, and says which one
 * (0 is the current secret; higher indexes are previous ones kept during a rotation). Undefined
 * when none does.
 */
export function openSecret(
  value: string,
  secrets: string | readonly string[],
  context = 'better-iam',
): { value: string; index: number } | undefined {
  const parts = typeof value === 'string' ? value.split('.') : [];
  if (parts.length !== 3) return undefined;
  const [iv, tag, encrypted] = parts.map((part) => Buffer.from(part, 'base64url'));
  // Exactly what encryptSecret writes: a 96-bit IV and a full 128-bit tag. Node would otherwise accept truncated
  // tags (down to 32 bits), which makes forging a sealed value far cheaper.
  if (iv!.length !== 12 || tag!.length !== 16) return undefined;
  const keyring = typeof secrets === 'string' ? [secrets] : secrets;
  for (const [index, secret] of keyring.entries()) {
    try {
      const cipher = createDecipheriv(
        'aes-256-gcm',
        createHash('sha256').update(secret).digest(),
        iv!,
        { authTagLength: 16 },
      );
      cipher.setAAD(Buffer.from(context));
      cipher.setAuthTag(tag!);
      return {
        value: Buffer.concat([cipher.update(encrypted!), cipher.final()]).toString('utf8'),
        index,
      };
    } catch {
      /* Try the next secret. */
    }
  }
  return undefined;
}

/** Opens a sealed value with the current secret or, during a rotation, a previous one. */
export function decryptSecret(
  value: string,
  secret: string | readonly string[],
  context = 'better-iam',
): string {
  const opened = openSecret(value, secret, context);
  if (!opened) throw new IamError('INVALID_SEALED_VALUE', 'Invalid sealed value');
  return opened.value;
}
