'use client';
import { useRouter } from 'next/navigation';
import { useState, useSyncExternalStore, type FormEvent } from 'react';
import { describeError } from '@/lib/client';

const unchanging = () => () => {};

/**
 * `at` as a local time, formatted in the browser only. The server's time zone and locale differ from the person's,
 * so text rendered there would not match hydration; the server (and hydration) render nothing instead.
 */
function useLocalTime(at: number): string | null {
  return useSyncExternalStore(
    unchanging,
    () => new Date(at).toLocaleTimeString(),
    () => null,
  );
}

async function call(method: 'POST' | 'DELETE', body?: unknown) {
  const response = await fetch('/api/console/impersonate', {
    method,
    headers: { 'content-type': 'application/json', 'x-better-iam': '1' },
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const envelope = (await response.json()) as {
    data?: unknown;
    error?: { code: string; message: string };
  };
  if (envelope.error) throw new Error(`${envelope.error.code}: ${envelope.error.message}`);
  return envelope.data;
}

/** Opens a "view as" session for a member and switches the console to it. */
export function ImpersonateForm({
  tenantId,
  identityId,
  name,
  base,
}: {
  tenantId: string;
  identityId: string;
  name: string;
  base: string;
}) {
  const router = useRouter();
  const [reason, setReason] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!window.confirm(`View the console as ${name}? Everything you do is recorded against you.`))
      return;
    setBusy(true);
    setError(null);
    try {
      await call('POST', { tenantId, identityId, reason });
      router.push(base);
      router.refresh();
    } catch (caught) {
      const described = describeError(caught);
      setError(
        described.message.startsWith('RECENT_AUTH_REQUIRED')
          ? 'Re-authenticate from your account page first, then try again.'
          : described.message,
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="form compact" onSubmit={submit}>
      <div className="field">
        <label>Reason (recorded in the audit log)</label>
        <input
          className="input"
          value={reason}
          onChange={(event) => setReason(event.target.value)}
          placeholder="Support ticket 1234"
          maxLength={512}
          required
        />
      </div>
      {error && <div className="alert danger">{error}</div>}
      <button className="btn" type="submit" disabled={busy}>
        {busy ? 'Opening…' : `View as ${name}`}
      </button>
    </form>
  );
}

/** Shown above every page while an administrator is acting as a member. */
export function ImpersonationBanner({
  memberName,
  impersonatorName,
  expiresAt,
  base,
}: {
  memberName: string;
  impersonatorName?: string;
  expiresAt: number;
  base: string;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const endsAt = useLocalTime(expiresAt);

  async function stop() {
    setBusy(true);
    setError(null);
    try {
      const data = (await call('DELETE')) as { restored: boolean };
      router.push(data.restored ? base : '/cloud');
      router.refresh();
    } catch (caught) {
      setError(describeError(caught).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      className="alert warning row"
      style={{ justifyContent: 'space-between', marginBottom: 20 }}
    >
      <span>
        Viewing as <strong>{memberName}</strong>
        {impersonatorName ? ` (you are ${impersonatorName})` : ''}. Actions are attributed to you in
        the audit log; sensitive operations are unavailable.{endsAt ? ` Ends ${endsAt}.` : ''}
        {error ? ` ${error}` : ''}
      </span>
      <button className="btn small" type="button" onClick={stop} disabled={busy}>
        {busy ? 'Stopping…' : 'Stop viewing as'}
      </button>
    </div>
  );
}
