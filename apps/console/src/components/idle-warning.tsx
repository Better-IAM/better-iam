'use client';
import { usePathname, useRouter } from 'next/navigation';
import { useCallback, useEffect, useRef, useState } from 'react';
import {
  classifyTouch,
  clockFrom,
  clockFromRender,
  countdown,
  goneReason,
  IDLE_CHANNEL,
  idleState,
  loginUrl,
  mergeTouch,
  parseIdleMessage,
  pingAfter,
  RETRY_MS,
  serverTime,
  touchedAt,
  type IdleClock,
  type IdleMessage,
  type LeaveReason,
  type TouchResult,
} from '@/lib/idle';

const TICK_MS = 1_000;

async function post(path: string): Promise<{ status: number; body: unknown }> {
  const response = await fetch(`/api/iam/${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-better-iam': '1' },
    credentials: 'same-origin',
    body: '{}',
  });
  const body: unknown = await response.json().catch(() => undefined);
  return { status: response.status, body };
}

/** Validates (and so touches) the session. A failed request means "unknown, ask again", never "signed out". */
async function touch(): Promise<TouchResult> {
  try {
    const { status, body } = await post('auth/getSession');
    return classifyTouch(status, body);
  } catch {
    return { kind: 'retry' };
  }
}

/** Ends the session on the server; the console's /api/iam route also ends a parked "view as" administrator session. */
async function signOut(): Promise<void> {
  try {
    await post('auth/signOut');
  } catch {
    /* Offline: the server's own idle timeout still ends the session. */
  }
}

type Warning = { remainingMs: number; absolute: boolean };

/**
 * Warns before the session lapses for inactivity (two minutes ahead, or half the idle timeout when that is
 * shorter) and offers to keep it alive; at the deadline it signs the session out on the server and sends the person
 * to the login page. Activity in any tab of the browser keeps the session alive by itself when the server has not
 * been touched for a while, so the warning only appears when the person really has been away. Deadlines are kept on
 * the server's clock (`serverNow`, then each answer's `limits.now`), so a wrong local clock changes nothing.
 */
export function IdleWarning({
  sessionId,
  idleTimeoutMs,
  expiresAt,
  serverNow,
  loginHref,
}: {
  /** The session the page was rendered for. */
  sessionId: string;
  idleTimeoutMs: number;
  /** The session's absolute end, on the server's clock. */
  expiresAt: number;
  /** The server's clock when it validated the session for this render (`getSession().limits.now`). */
  serverNow: number;
  loginHref: string;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const clock = useRef<IdleClock | null>(null);
  const inflight = useRef(false);
  const retryAt = useRef(0);
  const leaving = useRef(false);
  const channel = useRef<BroadcastChannel | null>(null);
  const lastPath = useRef(pathname);
  // Mirrors `warning` for the activity listener without re-running effects.
  const showing = useRef(false);
  const [warning, setWarning] = useState<Warning | null>(null);
  const [busy, setBusy] = useState(false);

  const show = useCallback((next: Warning | null) => {
    showing.current = next !== null;
    setWarning(next);
  }, []);

  const announce = useCallback((message: IdleMessage) => {
    try {
      channel.current?.postMessage(message);
    } catch {
      /* The channel closed while unmounting. */
    }
  }, []);

  const shareTouch = useCallback(() => {
    const current = clock.current;
    if (current)
      announce({
        type: 'touch',
        sessionId: current.sessionId,
        at: current.lastTouch,
        idleTimeoutMs: current.idleTimeoutMs,
        expiresAt: current.expiresAt,
      });
  }, [announce]);

  const leave = useCallback(
    (reason?: LeaveReason) => {
      if (leaving.current) return;
      leaving.current = true;
      router.push(loginUrl(loginHref, reason));
      router.refresh();
    },
    [router, loginHref],
  );

  /** Adopts a successful answer: its limits, a clock offset re-derived from `limits.now`, and the touch it made. */
  const adopt = useCallback(
    (result: Extract<TouchResult, { kind: 'ok' }>) => {
      const previous = clock.current;
      clock.current = clockFrom(result, result.serverNow, Date.now(), previous?.offset);
      retryAt.current = 0;
      show(null);
      shareTouch();
      // The browser now holds another session (signed in again, or view-as changed in another tab): show its pages.
      if (previous && previous.sessionId !== result.sessionId) router.refresh();
    },
    [router, show, shareTouch],
  );

  const ping = useCallback(
    async (force = false) => {
      if (inflight.current || leaving.current || (!force && Date.now() < retryAt.current)) return;
      inflight.current = true;
      try {
        const result = await touch();
        if (result.kind === 'ok') adopt(result);
        else if (result.kind === 'gone') leave(goneReason(clock.current, Date.now()));
        // An outage (5xx, 429, offline) or another refusal is not a sign-out: wait, then ask again.
        else retryAt.current = Date.now() + RETRY_MS;
      } finally {
        inflight.current = false;
      }
    },
    [adopt, leave],
  );

  /**
   * At the deadline the session is ended on the server before leaving; otherwise the login page's own session check
   * would find it valid, touch it, and send the person straight back, keeping an unattended console signed in.
   */
  const settle = useCallback(
    async (reason: 'idle' | 'expired') => {
      if (inflight.current || leaving.current || Date.now() < retryAt.current) return;
      inflight.current = true;
      try {
        // Confirms which session the browser holds first: a tab left open on an older session must not sign the
        // person out of one they started since in another tab.
        const result = await touch();
        if (result.kind === 'retry') {
          retryAt.current = Date.now() + RETRY_MS;
          return;
        }
        if (result.kind === 'ok' && result.sessionId !== clock.current?.sessionId) {
          adopt(result);
          return;
        }
        if (result.kind !== 'gone') await signOut();
        if (clock.current) announce({ type: 'ended', sessionId: clock.current.sessionId, reason });
        leave(reason);
      } finally {
        inflight.current = false;
      }
    },
    [adopt, announce, leave],
  );

  const evaluate = useCallback(() => {
    const current = clock.current;
    if (!current || leaving.current) return;
    const state = idleState(current, Date.now());
    if (state.kind === 'due') {
      show({ remainingMs: 0, absolute: state.reason === 'expired' });
      void settle(state.reason);
      return;
    }
    show(
      state.kind === 'warning'
        ? { remainingMs: state.remainingMs, absolute: state.absolute }
        : null,
    );
  }, [settle, show]);

  // One idle clock for every tab: a touch in one counts for all, and a sign-out in one ends them all.
  useEffect(() => {
    if (typeof BroadcastChannel !== 'function') return;
    const opened = new BroadcastChannel(IDLE_CHANNEL);
    channel.current = opened;
    opened.onmessage = (event: MessageEvent) => {
      const message = parseIdleMessage(event.data);
      const current = clock.current;
      if (!message || !current) return;
      if (message.type === 'touch') {
        clock.current = mergeTouch(current, message);
        if (clock.current !== current && showing.current) evaluate();
      } else if (message.sessionId === current.sessionId) leave(message.reason);
    };
    return () => {
      opened.close();
      if (channel.current === opened) channel.current = null;
    };
  }, [evaluate, leave]);

  // The layout's props change when the session is replaced (Reauth, view-as start or stop) or re-rendered.
  useEffect(() => {
    const previous = clock.current;
    clock.current = clockFromRender(
      previous,
      { sessionId, idleTimeoutMs, expiresAt },
      serverNow,
      Date.now(),
    );
    if (previous?.sessionId !== sessionId) retryAt.current = 0;
    if (clock.current.lastTouch !== previous?.lastTouch) shareTouch();
    evaluate();
  }, [sessionId, idleTimeoutMs, expiresAt, serverNow, shareTouch, evaluate]);

  // A client-side navigation rendered the new page on the server, which validated (and so touched) the session.
  useEffect(() => {
    if (lastPath.current === pathname) return;
    lastPath.current = pathname;
    const current = clock.current;
    if (!current) return;
    clock.current = touchedAt(current, serverTime(current, Date.now()));
    shareTouch();
    evaluate();
  }, [pathname, shareTouch, evaluate]);

  useEffect(() => {
    const onActivity = () => {
      const current = clock.current;
      // A person who is active but has not talked to the server for a while keeps their session without a prompt.
      if (
        current &&
        !showing.current &&
        serverTime(current, Date.now()) - current.lastTouch > pingAfter(current.idleTimeoutMs)
      )
        void ping();
    };
    const events: (keyof WindowEventMap)[] = ['pointerdown', 'keydown', 'scroll'];
    for (const event of events) window.addEventListener(event, onActivity, { passive: true });
    const timer = window.setInterval(evaluate, TICK_MS);
    return () => {
      window.clearInterval(timer);
      for (const event of events) window.removeEventListener(event, onActivity);
    };
  }, [ping, evaluate]);

  if (!warning) return null;
  const { remainingMs, absolute } = warning;
  return (
    <div
      role="alertdialog"
      aria-live="assertive"
      className="alert warning row"
      style={{
        position: 'fixed',
        left: '50%',
        bottom: 24,
        transform: 'translateX(-50%)',
        zIndex: 50,
        maxWidth: 560,
        justifyContent: 'space-between',
        boxShadow: '0 12px 32px rgba(0,0,0,0.18)',
      }}
    >
      <span>
        {absolute ? (
          <>
            Your session reaches its maximum length in <strong>{countdown(remainingMs)}</strong>.
            Save your work; you will need to sign in again.
          </>
        ) : (
          <>
            You have been inactive. For your security you will be signed out in{' '}
            <strong>{countdown(remainingMs)}</strong>.
          </>
        )}
      </span>
      <span className="row">
        {!absolute && (
          <button
            className="btn small"
            type="button"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                await ping(true);
              } finally {
                setBusy(false);
              }
            }}
          >
            {busy ? 'Extending…' : 'Stay signed in'}
          </button>
        )}
        <button
          className="btn small secondary"
          type="button"
          onClick={async () => {
            await signOut();
            if (clock.current) announce({ type: 'ended', sessionId: clock.current.sessionId });
            leave();
          }}
        >
          Sign out now
        </button>
      </span>
    </div>
  );
}
