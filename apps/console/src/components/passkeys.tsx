'use client';
import { useRouter } from 'next/navigation';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import {
  browserSupportsWebAuthn,
  browserSupportsWebAuthnAutofill,
  startAuthentication,
  startRegistration,
  WebAuthnAbortService,
  type AuthenticationResponseJSON,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
} from 'better-iam/client/passkeys';
import { describeError, iamClient } from '@/lib/client';
import { describeUserAgent } from '@/lib/device';
import { AUTOFILL_REFRESH_MS, autofillFailure } from '@/lib/passkey-autofill';
import { sessionOptions } from '@/lib/persistence';
import { Reauth } from './api-form';

interface PasskeySummary {
  id: string;
  credentialId: string;
  name?: string;
  createdAt?: number;
  lastUsedAt?: number;
  deviceType?: 'singleDevice' | 'multiDevice';
  backedUp?: boolean;
}

function when(value: number | undefined): string {
  return value ? new Date(value).toLocaleDateString() : 'never';
}

/** Runs the browser's WebAuthn "get" ceremony for server-issued options. */
export async function assertPasskey(options: unknown): Promise<AuthenticationResponseJSON> {
  return startAuthentication({ optionsJSON: options as PublicKeyCredentialRequestOptionsJSON });
}

/** Register, list, and remove the signed-in person's passkeys. Registration and removal need recent authentication. */
export function PasskeyControls({ tenantId }: { tenantId: string }) {
  const router = useRouter();
  const [keys, setKeys] = useState<PasskeySummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [reauth, setReauth] = useState<(() => Promise<void>) | null>(null);
  const [naming, setNaming] = useState(false);
  const [name, setName] = useState('');
  const [renaming, setRenaming] = useState<{ id: string; name: string } | null>(null);
  // WebAuthn support is only known in the browser; deciding it after mount keeps server and client HTML identical.
  const [supported, setSupported] = useState(false);

  async function load() {
    try {
      setKeys(await iamClient().auth.listPasskeys());
    } catch (caught) {
      setError(describeError(caught).message);
    }
  }
  useEffect(() => {
    setSupported(browserSupportsWebAuthn());
    void load();
  }, []);

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

  async function add() {
    const client = iamClient();
    const registration = await client.auth.beginPasskeyRegistration();
    const response = await startRegistration({
      optionsJSON: registration.options as unknown as PublicKeyCredentialCreationOptionsJSON,
    });
    await client.auth.finishPasskeyRegistration({
      challengeId: registration.challengeId,
      response: response as unknown as RegistrationResponseJSON,
      ...(name.trim() ? { name: name.trim() } : {}),
    });
    setNaming(false);
    setName('');
    await load();
    router.refresh();
  }

  function startAdding() {
    // Suggest the browser and system as the name; the person can change it before the ceremony starts.
    setName(describeUserAgent(navigator.userAgent) ?? '');
    setNaming(true);
  }

  async function rename(event: FormEvent) {
    event.preventDefault();
    if (!renaming) return;
    const target = renaming;
    await guarded(async () => {
      await iamClient().auth.renamePasskey({ id: target.id, name: target.name.trim() });
      setRenaming(null);
      await load();
    });
  }

  async function remove(id: string) {
    if (!window.confirm('Remove this passkey? Your sessions are revoked.')) return;
    await guarded(async () => {
      await iamClient().auth.deletePasskey({ id });
      router.push('/cloud');
      router.refresh();
    });
  }

  return (
    <div className="stack">
      {keys === null ? (
        <p className="small muted">Loading…</p>
      ) : keys.length === 0 ? (
        <p className="small muted">No passkeys yet.</p>
      ) : (
        <div className="stack">
          {keys.map((key) =>
            renaming?.id === key.id ? (
              <form key={key.id} className="row" onSubmit={rename}>
                <input
                  className="input"
                  value={renaming.name}
                  maxLength={64}
                  autoFocus
                  onChange={(event) => setRenaming({ id: key.id, name: event.target.value })}
                />
                <button className="btn small" disabled={busy || !renaming.name.trim()}>
                  Save
                </button>
                <button
                  type="button"
                  className="btn small secondary"
                  onClick={() => setRenaming(null)}
                >
                  Cancel
                </button>
              </form>
            ) : (
              <div key={key.id} className="row" style={{ justifyContent: 'space-between' }}>
                <span>
                  <strong>{key.name ?? 'Passkey'}</strong>
                  {key.backedUp || key.deviceType === 'multiDevice' ? (
                    <span className="badge accent" style={{ marginLeft: 8 }}>
                      synced
                    </span>
                  ) : (
                    <span className="badge" style={{ marginLeft: 8 }}>
                      this device only
                    </span>
                  )}
                  <span className="small muted" title={key.credentialId}>
                    {' '}
                    · added {when(key.createdAt)} · last used {when(key.lastUsedAt)}
                  </span>
                </span>
                <span className="row">
                  <button
                    type="button"
                    className="btn small secondary"
                    disabled={busy}
                    onClick={() => setRenaming({ id: key.id, name: key.name ?? '' })}
                  >
                    Rename
                  </button>
                  <button
                    type="button"
                    className="btn small danger"
                    disabled={busy}
                    onClick={() => void remove(key.id)}
                  >
                    Remove
                  </button>
                </span>
              </div>
            ),
          )}
        </div>
      )}
      {supported ? (
        naming ? (
          <form
            className="row"
            onSubmit={(event) => {
              event.preventDefault();
              void guarded(add);
            }}
          >
            <input
              className="input"
              value={name}
              maxLength={64}
              placeholder="Name this passkey"
              onChange={(event) => setName(event.target.value)}
            />
            <button className="btn small" disabled={busy}>
              {busy ? 'Waiting for your passkey…' : 'Create passkey'}
            </button>
            <button type="button" className="btn small secondary" onClick={() => setNaming(false)}>
              Cancel
            </button>
          </form>
        ) : (
          <div className="row">
            <button type="button" className="btn small" disabled={busy} onClick={startAdding}>
              Add a passkey
            </button>
          </div>
        )
      ) : (
        <p className="small muted">This browser does not support passkeys.</p>
      )}
      <p className="small muted">
        A passkey signs you in without a password and can stand in for your authenticator code when
        the organization requires a second factor.
      </p>
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

/**
 * Password-free sign-in with a registered passkey; the server treats it as MFA-satisfied. The email is optional:
 * without it the authenticator offers its discoverable credentials, and browsers that support passkey autofill get
 * them offered in the email field of the login page as soon as it loads. A refused autofill sign-in is reported, and
 * autofill is offered again with a fresh challenge. Render it only where the organization allows passkeys: the
 * autofill request starts a discovery ceremony on every mount.
 */
export function PasskeySignIn({ tenantId, next }: { tenantId: string; next: string }) {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState(false);
  const [supported, setSupported] = useState(false);
  // Arms autofill again after the passkey button's ceremony (which aborted it) ends without signing in.
  const rearmAutofill = useRef<(() => void) | null>(null);
  // The browser runs one WebAuthn ceremony at a time: autofill must not start while the button's is running.
  const manual = useRef(false);
  useEffect(() => {
    setSupported(browserSupportsWebAuthn());
    let cancelled = false;
    let armed = false;
    let quickFailures = 0;
    let retry: ReturnType<typeof setTimeout> | undefined;

    function failed(
      caught: unknown,
      stage: 'browser' | 'server',
      refreshing: boolean,
      armedAt: number,
    ) {
      armed = false;
      if (cancelled) return;
      const outcome = autofillFailure({
        name: caught instanceof Error ? caught.name : undefined,
        stage,
        refreshing,
        elapsedMs: Date.now() - armedAt,
        quickFailures,
      });
      quickFailures = outcome.quickFailures;
      if (outcome.show) setError(describeError(caught).message);
      if (outcome.rearm) {
        clearTimeout(retry);
        retry = setTimeout(() => void arm(), outcome.delayMs);
      }
    }

    async function arm() {
      if (cancelled || armed || manual.current) return;
      armed = true;
      const client = iamClient();
      let begun: Awaited<ReturnType<typeof client.auth.beginPasskeyAuthentication>>;
      try {
        begun = await client.auth.beginPasskeyAuthentication({ tenantId });
      } catch {
        // Discovery could not start (rate limited, organization unavailable): autofill stays off and the passkey
        // button reports the reason when used. Retrying here would only spend more of the rate limit.
        armed = false;
        return;
      }
      if (cancelled || manual.current) {
        armed = false;
        return;
      }
      const armedAt = Date.now();
      let refreshing = false;
      // A waiting autofill request outlives its server challenge; swap in a fresh one before it expires.
      const refresh = setTimeout(() => {
        refreshing = true;
        WebAuthnAbortService.cancelCeremony();
      }, AUTOFILL_REFRESH_MS);
      let response: AuthenticationResponseJSON;
      try {
        response = await startAuthentication({
          optionsJSON: begun.options as unknown as PublicKeyCredentialRequestOptionsJSON,
          useBrowserAutofill: true,
        });
      } catch (caught) {
        clearTimeout(refresh);
        failed(caught, 'browser', refreshing, armedAt);
        return;
      }
      clearTimeout(refresh);
      setError(null);
      try {
        await client.auth.finishPasskeyAuthentication(
          { tenantId, challengeId: begun.challengeId, response: response as never },
          sessionOptions(),
        );
      } catch (caught) {
        // The person already picked a passkey and passed verification, so a refusal must be shown, not swallowed.
        failed(caught, 'server', false, armedAt);
        return;
      }
      router.push(next);
      router.refresh();
    }

    void (async () => {
      if (!browserSupportsWebAuthn() || !(await browserSupportsWebAuthnAutofill())) return;
      if (cancelled) return;
      rearmAutofill.current = () => {
        quickFailures = 0;
        void arm();
      };
      void arm();
    })();
    return () => {
      cancelled = true;
      clearTimeout(retry);
      rearmAutofill.current = null;
      WebAuthnAbortService.cancelCeremony();
    };
  }, [tenantId, next, router]);
  if (!supported) return null;

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    manual.current = true;
    let signedIn = false;
    try {
      const client = iamClient();
      const address = email.trim();
      const begun = await client.auth.beginPasskeyAuthentication(
        address ? { tenantId, email: address } : { tenantId },
      );
      const response = await assertPasskey(begun.options);
      await client.auth.finishPasskeyAuthentication(
        { tenantId, challengeId: begun.challengeId, response: response as never },
        sessionOptions(),
      );
      signedIn = true;
      router.push(next);
      router.refresh();
    } catch (caught) {
      setError(describeError(caught).message);
    } finally {
      setBusy(false);
      manual.current = false;
      if (!signedIn) rearmAutofill.current?.();
    }
  }

  if (!open)
    return (
      <>
        {error && <div className="alert danger">{error}</div>}
        <div className="row">
          <button type="button" className="btn small secondary" onClick={() => setOpen(true)}>
            Sign in with a passkey instead
          </button>
        </div>
      </>
    );
  return (
    <form className="form" onSubmit={submit}>
      <div className="field">
        <label>Email (optional)</label>
        <input
          className="input"
          type="email"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          autoComplete="username webauthn"
          placeholder="Leave empty to pick a passkey saved on this device"
        />
      </div>
      {error && <div className="alert danger">{error}</div>}
      <div className="form-actions row">
        <button className="btn" disabled={busy}>
          {busy ? 'Waiting for your passkey…' : 'Continue with passkey'}
        </button>
        <button
          type="button"
          className="btn secondary"
          onClick={() => {
            setOpen(false);
            setError(null);
          }}
        >
          Use a password
        </button>
      </div>
    </form>
  );
}
