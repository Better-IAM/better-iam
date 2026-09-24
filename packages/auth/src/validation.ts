import { IamError, type Identity, type Session } from '@better-iam/core';
import type { SafeIdentity, SafeSession } from './types.js';

export function text(value: unknown, field: string, max = 512): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > max)
    throw new IamError(
      'INVALID_INPUT',
      `${field} must be a nonempty string of at most ${max} characters`,
    );
  return value;
}
/** Control characters (C0, DEL, C1) and Unicode line/paragraph separators. */
export const controlCharacters = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;
/**
 * A display name: control and line-separator characters become spaces, so a name (from sign-up, an invitation, or
 * an identity provider) can never break an email header or forge a line in a message.
 */
export function displayName(value: unknown, max = 256): string {
  return text(text(value, 'name', max).replace(controlCharacters, ' ').trim(), 'name', max);
}
export function email(value: unknown): string {
  const normalized = text(value, 'email', 254).trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalized))
    throw new IamError('INVALID_INPUT', 'Invalid email');
  return normalized;
}
export function phone(value: unknown): string {
  const normalized = text(value, 'phone', 16);
  if (!/^\+[1-9]\d{6,14}$/.test(normalized))
    throw new IamError('INVALID_INPUT', 'Phone must use E.164 format');
  return normalized;
}
export function password(value: unknown): string {
  const result = text(value, 'password', 1024);
  if (result.length < 12)
    throw new IamError('WEAK_PASSWORD', 'Password must contain at least 12 characters');
  return result;
}
export function publicIdentity(identity: Identity): SafeIdentity {
  const { passwordHash: _password, ...safe } = identity;
  return safe;
}
/** A session without its secret-derived fields: `tokenHash`, and `uniqueKey`, which holds the same hash. */
export function publicSession(session: Session): SafeSession {
  const { tokenHash: _hash, uniqueKey: _key, ...safe } = session;
  return safe;
}
