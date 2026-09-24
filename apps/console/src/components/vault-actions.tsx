'use client';
import { useRouter } from 'next/navigation';
import { useEffect, useRef, useState } from 'react';
import { describeError, iamClient } from '@/lib/client';

/** How long a revealed value stays on screen. */
const VISIBLE_MS = 60_000;

interface Shown {
  value: string;
  version?: number;
  leaseId?: string;
  expiresAt?: number;
  fields?: Record<string, unknown>;
}

/** A value on screen: masked until asked, copyable, and cleared from the page after a minute. */
function ValueBox({ shown, onClear }: { shown: Shown; onClear: () => void }) {
  const [visible, setVisible] = useState(false);
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => {
    timer.current = setTimeout(onClear, VISIBLE_MS);
    return () => clearTimeout(timer.current);
  }, [onClear]);
  const text = shown.fields ? JSON.stringify(shown.fields, null, 2) : shown.value;
  return (
    <div className="stack" style={{ width: '100%' }}>
      <pre className="result" style={{ userSelect: visible ? 'text' : 'none' }}>
        {visible ? text : '•'.repeat(Math.min(32, Math.max(8, shown.value.length)))}
      </pre>
      <div className="row">
        <button type="button" className="btn small secondary" onClick={() => setVisible(!visible)}>
          {visible ? 'Hide' : 'Show'}
        </button>
        <button
          type="button"
          className="btn small secondary"
          onClick={() => {
            void navigator.clipboard.writeText(text).then(() => {
              setCopied(true);
              setTimeout(() => setCopied(false), 2000);
            });
          }}
        >
          {copied ? 'Copied' : 'Copy'}
        </button>
        <button type="button" className="btn small secondary" onClick={onClear}>
          Clear
        </button>
        {shown.version !== undefined && <span className="small muted">version {shown.version}</span>}
        {shown.expiresAt !== undefined && (
          <span className="small muted">until {new Date(shown.expiresAt).toLocaleTimeString()}</span>
        )}
      </div>
      <span className="small muted">Cleared from this page after a minute. Every reveal is audited.</span>
    </div>
  );
}

function ErrorBadge({ error }: { error: { code: string; message: string } | null }) {
  if (!error) return null;
  return (
    <div className="alert danger">
      <strong>{error.code}</strong> — {error.message}
    </div>
  );
}

/** Reveals a static secret's value (a version or stage when given). */
export function RevealSecret({
  tenantId,
  name,
  version,
  label = 'Reveal value',
}: {
  tenantId: string;
  name: string;
  version?: number;
  label?: string;
}) {
  const [shown, setShown] = useState<Shown | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ code: string; message: string } | null>(null);
  async function reveal() {
    setBusy(true);
    setError(null);
    try {
      const result = (await iamClient().$request('vault/reveal', {
        tenantId,
        name,
        ...(version !== undefined ? { version } : {}),
      })) as Shown;
      setShown(result);
    } catch (caught) {
      setError(describeError(caught));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="stack">
      {shown ? (
        <ValueBox shown={shown} onClear={() => setShown(null)} />
      ) : (
        <div>
          <button type="button" className="btn small" disabled={busy} onClick={() => void reveal()}>
            {busy ? '…' : label}
          </button>
        </div>
      )}
      <ErrorBadge error={error} />
    </div>
  );
}

/** Checks a shared credential out (with a reason when required), shows it, and checks it back in. */
export function CheckoutSecret({
  tenantId,
  name,
  requireReason,
  maxDurationMinutes,
}: {
  tenantId: string;
  name: string;
  requireReason: boolean;
  maxDurationMinutes: number;
}) {
  const router = useRouter();
  const [reason, setReason] = useState('');
  const [minutes, setMinutes] = useState(String(Math.min(60, maxDurationMinutes)));
  const [shown, setShown] = useState<Shown | null>(null);
  const [lease, setLease] = useState<{ leaseId: string; expiresAt: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ code: string; message: string } | null>(null);
  async function checkout() {
    setBusy(true);
    setError(null);
    try {
      const result = (await iamClient().$request('vault/checkout', {
        tenantId,
        name,
        durationMs: Math.max(1, Number(minutes) || 1) * 60_000,
        ...(reason ? { reason } : {}),
      })) as Shown & { leaseId: string; expiresAt: number };
      setShown(result);
      setLease({ leaseId: result.leaseId, expiresAt: result.expiresAt });
      router.refresh();
    } catch (caught) {
      setError(describeError(caught));
    } finally {
      setBusy(false);
    }
  }
  async function checkin() {
    if (!lease) return;
    setBusy(true);
    setError(null);
    try {
      await iamClient().$request('vault/checkin', { tenantId, leaseId: lease.leaseId });
      setShown(null);
      setLease(null);
      router.refresh();
    } catch (caught) {
      setError(describeError(caught));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="stack">
      {lease ? (
        <>
          {shown ? (
            <ValueBox shown={shown} onClear={() => setShown(null)} />
          ) : (
            <span className="small muted">
              Checked out until {new Date(lease.expiresAt).toLocaleTimeString()}; reveal it again
              from this page while the check-out lasts.
            </span>
          )}
          <div>
            <button type="button" className="btn small" disabled={busy} onClick={() => void checkin()}>
              Check in
            </button>
          </div>
        </>
      ) : (
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            void checkout();
          }}
        >
          <div className="field">
            <label htmlFor="checkout-reason">
              Reason{requireReason ? '' : <span className="muted"> (optional)</span>}
            </label>
            <input
              id="checkout-reason"
              className="input"
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder="INC-1234: database unresponsive"
              required={requireReason}
              maxLength={512}
            />
          </div>
          <div className="field">
            <label htmlFor="checkout-minutes">For (minutes, at most {maxDurationMinutes})</label>
            <input
              id="checkout-minutes"
              className="input"
              type="number"
              min={1}
              max={maxDurationMinutes}
              value={minutes}
              onChange={(event) => setMinutes(event.target.value)}
            />
          </div>
          <div className="form-actions">
            <button className="btn" disabled={busy}>
              {busy ? 'Working…' : 'Check out'}
            </button>
          </div>
        </form>
      )}
      <ErrorBadge error={error} />
    </div>
  );
}

/** Requests a dynamic credential from the secret's engine and shows it once. */
export function LeaseSecret({ tenantId, name }: { tenantId: string; name: string }) {
  const router = useRouter();
  const [shown, setShown] = useState<Shown | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ code: string; message: string } | null>(null);
  async function lease() {
    setBusy(true);
    setError(null);
    try {
      setShown((await iamClient().$request('vault/lease', { tenantId, name })) as Shown);
      router.refresh();
    } catch (caught) {
      setError(describeError(caught));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="stack">
      {shown ? (
        <ValueBox shown={shown} onClear={() => setShown(null)} />
      ) : (
        <div>
          <button type="button" className="btn small" disabled={busy} onClick={() => void lease()}>
            {busy ? '…' : 'Get a credential'}
          </button>
        </div>
      )}
      <ErrorBadge error={error} />
    </div>
  );
}
