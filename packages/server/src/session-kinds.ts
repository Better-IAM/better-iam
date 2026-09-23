import { IamError, type Session } from '@better-iam/core';

/**
 * Session kinds and the rules shared by every code path that branches on them. Long-lived credentials (`user`,
 * `api-key`) act in their identity's own right; temporary ones (`role`, `session-token`, `delegated`) derive from a
 * source and never pass recent-authentication, ownership or self-service checks. Unknown kinds fail closed everywhere.
 */

/** The temporary kinds: derived from a source credential, bounded by it, and never usable for self-service. */
export const temporarySessionKinds: ReadonlySet<Session['kind']> = new Set<Session['kind']>([
  'role',
  'session-token',
  'delegated',
]);

/**
 * Whether a session acts in its identity's own right (a user session or an API key), as self-service actions such as
 * accepting agreements or activating standing access require. False for temporary and unknown kinds.
 */
export function actsInOwnRight(session: Pick<Session, 'kind'>): boolean {
  return session.kind === 'user' || session.kind === 'api-key';
}

/**
 * Whether a session issued at `createdAt` falls under any revocation watermark (`sessionsRevokedBefore` of its role,
 * trust or provider): true when it was created strictly before a numeric watermark. Missing watermarks are ignored.
 */
export function revokedByWatermark(
  createdAt: number,
  ...watermarks: (number | undefined)[]
): boolean {
  return watermarks.some(
    (watermark) =>
      typeof watermark === 'number' && Number.isFinite(watermark) && createdAt < watermark,
  );
}

/**
 * The next `sessionsRevokedBefore` for a record: `max(current ?? 0, before ?? now + 1)`, so a watermark only ever
 * moves forward and never lies in the future (it can neither resurrect a session nor block new issuance). The default
 * revokes every session issued so far. Throws INVALID_INPUT when `before` is not a safe integer >= 0 or is > now + 1.
 */
export function nextWatermark(current: number | undefined, before: unknown, now: number): number {
  if (
    before !== undefined &&
    (typeof before !== 'number' || !Number.isSafeInteger(before) || before < 0 || before > now + 1)
  )
    throw new IamError('INVALID_INPUT', 'before must be a time no later than now');
  return Math.max(current ?? 0, (before as number | undefined) ?? now + 1);
}
