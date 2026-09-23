/**
 * The idle-warning clock, kept free of React so it can be tested on its own. Every time here is on the server's
 * clock: `offset` converts this browser's clock to it, so a laptop whose clock runs fast or slow neither signs people
 * out early nor lets the warning come too late.
 */

/** How long before a deadline the warning appears (capped at half the idle timeout). */
export const WARN_BEFORE_MS = 120_000;
/** Activity pings the server at most this often (capped at a third of the idle timeout). */
export const MAX_PING_AFTER_MS = 5 * 60_000;
/** After an outage or refusal, how long to wait before asking the server again. */
export const RETRY_MS = 10_000;
/** Tabs of the same browser share one idle clock over this channel. */
export const IDLE_CHANNEL = 'better-iam.idle';

export type LeaveReason = 'idle' | 'expired' | 'ended';

export interface SessionSnapshot {
  sessionId: string;
  idleTimeoutMs: number;
  /** The session's absolute end, on the server's clock. */
  expiresAt: number;
}

export interface IdleClock extends SessionSnapshot {
  /** When the server last validated (and so touched) the session, on the server's clock. */
  lastTouch: number;
  /** The server's clock minus this browser's clock. */
  offset: number;
}

export type TouchResult =
  | ({ kind: 'ok'; serverNow?: number } & SessionSnapshot)
  /** 401 UNAUTHENTICATED or SESSION_NETWORK_MISMATCH: the session is over. */
  | { kind: 'gone' }
  /** Another refusal (for example 403 MFA_REQUIRED after a policy change): the session is unusable from here. */
  | { kind: 'denied' }
  /** 5xx, 408, 429, an unreadable answer, or no network: nothing is known, so ask again later. */
  | { kind: 'retry' };

export type IdleMessage =
  | ({ type: 'touch'; at: number } & SessionSnapshot)
  | { type: 'ended'; sessionId: string; reason?: LeaveReason };

export type IdleState =
  | { kind: 'active' }
  | { kind: 'warning'; remainingMs: number; absolute: boolean }
  | { kind: 'due'; reason: 'idle' | 'expired' };

const finite = (value: unknown): value is number =>
  typeof value === 'number' && Number.isFinite(value);

export const warnBefore = (idleTimeoutMs: number): number =>
  Math.min(WARN_BEFORE_MS, Math.floor(idleTimeoutMs / 2));
export const pingAfter = (idleTimeoutMs: number): number =>
  Math.min(MAX_PING_AFTER_MS, Math.floor(idleTimeoutMs / 3));

/** This browser's estimate of the server's clock. */
export const serverTime = (clock: IdleClock, clientNow: number): number => clientNow + clock.offset;

/**
 * A clock from a server answer given at `serverNow` and received at `clientNow`. The answer was produced before it
 * arrived, so `serverNow - clientNow` never overstates the offset: deadlines computed with it fire late, never early.
 * Without `serverNow` (an older server) the previous offset is kept.
 */
export function clockFrom(
  snapshot: SessionSnapshot,
  serverNow: number | undefined,
  clientNow: number,
  previousOffset = 0,
): IdleClock {
  const offset = finite(serverNow) ? serverNow - clientNow : previousOffset;
  return {
    sessionId: snapshot.sessionId,
    idleTimeoutMs: snapshot.idleTimeoutMs,
    expiresAt: snapshot.expiresAt,
    lastTouch: clientNow + offset,
    offset,
  };
}

/**
 * The clock after the layout rendered the page with these props. A render of the same session that is not newer
 * than what the tab already knows (the router replaying a cached page) keeps the tab's clock and offset.
 */
export function clockFromRender(
  current: IdleClock | null,
  snapshot: SessionSnapshot,
  serverNow: number,
  clientNow: number,
): IdleClock {
  if (current && current.sessionId === snapshot.sessionId && serverNow <= current.lastTouch)
    return { ...current, idleTimeoutMs: snapshot.idleTimeoutMs, expiresAt: snapshot.expiresAt };
  return clockFrom(snapshot, serverNow, clientNow, current?.offset);
}

/** Records a server touch at `at` (server clock); an older one changes nothing. */
export const touchedAt = (clock: IdleClock, at: number): IdleClock =>
  at > clock.lastTouch ? { ...clock, lastTouch: at } : clock;

/**
 * Applies another tab's touch. The browser has one session cookie, so a newer touch of another session means the
 * session was replaced (signed in again, view-as started or stopped) and this tab follows it.
 */
export function mergeTouch(
  clock: IdleClock,
  message: Extract<IdleMessage, { type: 'touch' }>,
): IdleClock {
  if (message.at <= clock.lastTouch) return clock;
  return {
    ...clock,
    sessionId: message.sessionId,
    idleTimeoutMs: message.idleTimeoutMs,
    expiresAt: message.expiresAt,
    lastTouch: message.at,
  };
}

export function idleState(clock: IdleClock, clientNow: number): IdleState {
  const now = serverTime(clock, clientNow);
  const idleAt = clock.lastTouch + clock.idleTimeoutMs;
  const absolute = clock.expiresAt <= idleAt;
  const endAt = absolute ? clock.expiresAt : idleAt;
  if (now >= endAt) return { kind: 'due', reason: absolute ? 'expired' : 'idle' };
  if (now >= endAt - warnBefore(clock.idleTimeoutMs))
    return { kind: 'warning', remainingMs: endAt - now, absolute };
  return { kind: 'active' };
}

/** Why a session that the server reports gone ended: near a deadline it is that deadline, otherwise neutral. */
export function goneReason(clock: IdleClock | null, clientNow: number): LeaveReason {
  if (!clock) return 'ended';
  const state = idleState(clock, clientNow);
  if (state.kind === 'due') return state.reason;
  if (state.kind === 'warning') return state.absolute ? 'expired' : 'idle';
  return 'ended';
}

/** Classifies an `auth/getSession` answer; only a definite 401 means the session is over. */
export function classifyTouch(status: number, body: unknown): TouchResult {
  if (status >= 200 && status < 300) {
    const data = (body as { data?: unknown } | null | undefined)?.data as
      | { session?: { id?: unknown; expiresAt?: unknown }; limits?: Record<string, unknown> }
      | undefined;
    const sessionId = data?.session?.id;
    const expiresAt = data?.session?.expiresAt;
    const idleTimeoutMs = data?.limits?.idleTimeoutMs;
    const serverNow = data?.limits?.now;
    if (typeof sessionId !== 'string' || !finite(expiresAt) || !finite(idleTimeoutMs))
      return { kind: 'retry' };
    return {
      kind: 'ok',
      sessionId,
      expiresAt,
      idleTimeoutMs,
      ...(finite(serverNow) ? { serverNow } : {}),
    };
  }
  const code = (body as { error?: { code?: unknown } } | null | undefined)?.error?.code;
  if (status === 401 && (code === 'UNAUTHENTICATED' || code === 'SESSION_NETWORK_MISMATCH'))
    return { kind: 'gone' };
  if (status === 408 || status === 429 || status >= 500) return { kind: 'retry' };
  return { kind: 'denied' };
}

/** Accepts only well-formed messages: anything on the origin can post to the channel. */
export function parseIdleMessage(data: unknown): IdleMessage | undefined {
  if (!data || typeof data !== 'object') return undefined;
  const message = data as Record<string, unknown>;
  if (typeof message.sessionId !== 'string') return undefined;
  if (message.type === 'touch') {
    if (!finite(message.at) || !finite(message.idleTimeoutMs) || !finite(message.expiresAt))
      return undefined;
    return {
      type: 'touch',
      sessionId: message.sessionId,
      at: message.at,
      idleTimeoutMs: message.idleTimeoutMs,
      expiresAt: message.expiresAt,
    };
  }
  if (message.type === 'ended') {
    const reason =
      message.reason === 'idle' || message.reason === 'expired' || message.reason === 'ended'
        ? message.reason
        : undefined;
    return { type: 'ended', sessionId: message.sessionId, ...(reason ? { reason } : {}) };
  }
  return undefined;
}

/** The login page, told why the person is there (`?reason=`) so they know nothing went wrong. */
export function loginUrl(loginHref: string, reason?: LeaveReason): string {
  return reason ? `${loginHref}${loginHref.includes('?') ? '&' : '?'}reason=${reason}` : loginHref;
}

/** `m:ss` for a countdown. */
export function countdown(ms: number): string {
  const seconds = Math.max(0, Math.ceil(ms / 1000));
  return `${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
}
