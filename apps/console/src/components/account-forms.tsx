'use client';
import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import { describeError, iamClient } from '@/lib/client';
import { sessionOptions } from '@/lib/persistence';
import { Reauth } from './api-form';

/** Enroll, disable, or refresh recovery codes for the signed-in identity's authenticator. */
export function MfaControls({ tenantId, mfa }: { tenantId: string; mfa: boolean }) {
  const router = useRouter();
  const [enrollment, setEnrollment] = useState<{ secret: string; uri: string } | null>(null);
  const [code, setCode] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [reauth, setReauth] = useState<(() => Promise<void>) | null>(null);

  async function guarded(operation: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await operation();
    } catch (caught) {
      const described = describeError(caught);
      if (described.code === 'RECENT_AUTH_REQUIRED') setReauth(() => operation);
      else setError(described.message);
    } finally {
      setBusy(false);
    }
  }

  async function begin() {
    const started = await iamClient().auth.beginMfa();
    setEnrollment(started);
  }
  async function confirm(event: FormEvent) {
    event.preventDefault();
    await guarded(async () => {
      // Enrollment replaces the session; keep this browser's "keep me signed in" choice for the new cookie.
      const result = await iamClient().auth.confirmMfa({ code }, sessionOptions());
      setCodes(result.recoveryCodes);
      setEnrollment(null);
      router.refresh();
    });
  }
  async function disable() {
    if (!window.confirm('Disable multi-factor authentication? Your sessions are revoked.')) return;
    await guarded(async () => {
      await iamClient().auth.disableMfa();
      router.push('/cloud');
      router.refresh();
    });
  }
  async function regenerate() {
    await guarded(async () => {
      setCodes((await iamClient().auth.regenerateRecoveryCodes()).recoveryCodes);
    });
  }

  return (
    <div className="stack">
      {codes && (
        <>
          <div className="alert success">
            Recovery codes — store them safely; they are not shown again.
          </div>
          <pre className="result">{codes.join('\n')}</pre>
        </>
      )}
      {enrollment ? (
        <form className="form" onSubmit={confirm}>
          <div className="field">
            <label>Authenticator secret</label>
            <code className="mono" style={{ wordBreak: 'break-all' }}>
              {enrollment.secret}
            </code>
          </div>
          <div className="field">
            <label>Current code</label>
            <input
              className="input"
              value={code}
              onChange={(event) => setCode(event.target.value)}
              inputMode="numeric"
              required
            />
          </div>
          <div className="form-actions">
            <button className="btn small" disabled={busy}>
              Confirm enrollment
            </button>
            <button
              type="button"
              className="btn small secondary"
              onClick={() => setEnrollment(null)}
            >
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <div className="row">
          {mfa ? (
            <>
              <button
                type="button"
                className="btn small secondary"
                disabled={busy}
                onClick={() => void guarded(regenerate)}
              >
                New recovery codes
              </button>
              <button
                type="button"
                className="btn small danger"
                disabled={busy}
                onClick={() => void disable()}
              >
                Disable MFA
              </button>
            </>
          ) : (
            <button
              type="button"
              className="btn small"
              disabled={busy}
              onClick={() => void guarded(begin)}
            >
              Enroll an authenticator
            </button>
          )}
        </div>
      )}
      {!mfa && (
        <p className="small muted">
          Your current session was created without a second factor. Enrolling requires recent
          authentication and signs your other sessions out.
        </p>
      )}
      {error && <div className="alert danger">{error}</div>}
      {reauth && (
        <Reauth
          tenantId={tenantId}
          onDone={() => {
            const retry = reauth;
            setReauth(null);
            void guarded(retry);
          }}
          onCancel={() => setReauth(null)}
        />
      )}
    </div>
  );
}

/** Links another organization's identity by proving its credentials server-side, so this browser's session cookie is untouched. */
export function AccountLinking() {
  const router = useRouter();
  const [org, setOrg] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [reauth, setReauth] = useState(false);

  async function submit(event?: FormEvent) {
    event?.preventDefault();
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const response = await fetch('/api/console/link', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-better-iam': '1' },
        credentials: 'same-origin',
        body: JSON.stringify({ org, email, password, code: code || undefined }),
      });
      const envelope = (await response.json()) as {
        data?: { tenantName: string };
        error?: { code: string; message: string };
      };
      if (envelope.error) {
        if (envelope.error.code === 'RECENT_AUTH_REQUIRED') {
          setReauth(true);
          return;
        }
        throw new Error(`${envelope.error.code}: ${envelope.error.message}`);
      }
      setMessage(`Linked your identity in ${envelope.data?.tenantName ?? org}.`);
      setPassword('');
      setCode('');
      router.refresh();
    } catch (caught) {
      setError(describeError(caught).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="form" onSubmit={submit}>
      <h3>Link another organization</h3>
      <p className="small muted">
        Prove you own the other account: its organization alias, email, password, and authenticator
        code if it uses MFA. The proof is verified on the server and never stored.
      </p>
      <div className="grid cols-2">
        <div className="field">
          <label>Organization alias</label>
          <input
            className="input"
            value={org}
            onChange={(event) => setOrg(event.target.value)}
            required
          />
        </div>
        <div className="field">
          <label>Email</label>
          <input
            className="input"
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            required
          />
        </div>
        <div className="field">
          <label>Password</label>
          <input
            className="input"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="off"
            required
          />
        </div>
        <div className="field">
          <label>Authenticator code (optional)</label>
          <input
            className="input"
            value={code}
            onChange={(event) => setCode(event.target.value)}
            inputMode="numeric"
          />
        </div>
      </div>
      {error && <div className="alert danger">{error}</div>}
      {message && <div className="alert success">{message}</div>}
      {reauth && (
        <Reauth
          onDone={() => {
            setReauth(false);
            void submit();
          }}
          onCancel={() => setReauth(false)}
        />
      )}
      <div className="form-actions">
        <button className="btn small" disabled={busy}>
          {busy ? 'Linking…' : 'Link account'}
        </button>
      </div>
    </form>
  );
}
