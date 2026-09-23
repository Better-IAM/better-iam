import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';
import type { Identity, PolicyDocument } from '@better-iam/core';

export const id = (): string => randomUUID();
export const token = (): string => randomBytes(32).toString('base64url');
export const hash = (value: string): string => createHash('sha256').update(value).digest('hex');

/**
 * Compares two token hashes in constant time (for equal lengths). A stored value is typed as a string but read
 * fail-closed: anything else, or a different byte length, never matches.
 */
export function sameHash(a: string, b: string): boolean {
  const left: unknown = a;
  const right: unknown = b;
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const first = Buffer.from(left);
  const second = Buffer.from(right);
  return first.length === second.length && timingSafeEqual(first, second);
}
/** The unrestricted policy used for root authorities, owner roles, and default ceilings. */
export const all: PolicyDocument = {
  version: 1,
  statements: [{ effect: 'allow', actions: ['*'], resources: ['*'] }],
};

export type PublicIdentity = { [K in keyof Identity as Exclude<K, 'passwordHash'>]: Identity[K] };
/** Strips credential material before an identity leaves the service layer. */
export function publicIdentity(identity: Identity): PublicIdentity {
  const { passwordHash: _hash, ...safe } = identity;
  return safe;
}

/** Deterministic newest-first ordering for records that carry a creation timestamp. */
export const byNewest = (
  a: { createdAt: number; id: string },
  b: { createdAt: number; id: string },
): number => b.createdAt - a.createdAt || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
export const byId = (a: { id: string }, b: { id: string }): number =>
  a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
