'use client';
import { useRouter } from 'next/navigation';
import { useEffect, useState, type FormEvent } from 'react';
// Imported from the library rather than ./passkeys, which imports api-form, which imports this module.
import {
  startAuthentication,
  type PublicKeyCredentialRequestOptionsJSON,
} from 'better-iam/client/passkeys';
import { describeError, iamClient } from '@/lib/client';
import {
  challengeLapsed,
  challengeStateFrom,
  mfaStepView,
  type MfaChallengeState,
  type MfaRequiredOutcome,
} from '@/lib/mfa-step';
import { recordedRememberBrowser, sessionOptions, setRememberBrowser } from '@/lib/persistence';

export type { MfaChallengeState } from '@/lib/mfa-step';
export { sessionOptions } from '@/lib/persistence';

/** Turns an `mfaRequired` sign-in outcome into challenge state, starting enrollment when nothing is enrolled. */
export async function mfaChallengeState(
  tenantId: string,
  outcome: MfaRequiredOutcome,
  persistent?: boolean,
): Promise<MfaChallengeState> {
  const enrollment = outcome.enrollmentRequired
    ? await iamClient().auth.beginMfa({ tenantId, challenge: outcome.challenge })
    : undefined;
  return challengeStateFrom(outcome, enrollment, persistent);
}

/**
 * "Keep me signed in on this browser", asked once on a sign-in page for every method on it (password, passkey
 * including autofill, emailed link or code). The choice is remembered for this browser session (lib/persistence),
 * so the MFA step and later re-authentication issue the same kind of session cookie. `initial` is the recorded
 * choice, or the deployment's `http.persistentCookies` when none was made.
 */
export function KeepSignedIn({ initial = true }: { initial?: boolean }) {
  const [checked, setChecked] = useState(initial);
  useEffect(() => {
    const recorded = recordedRememberBrowser();
    // Record the default shown here, so flows that cannot see the deployment default (the MFA step,
    // re-authentication) follow what this box displayed.
    if (recorded === undefined) setRememberBrowser(initial);
    else setChecked(recorded);
  }, [initial]);
  return (
    <label className="row small">
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => {
          setChecked(event.target.checked);
          setRememberBrowser(event.target.checked);
        }}
      />{' '}
      Keep me signed in on this browser, whichever way I sign in (otherwise the sign-in ends when
      the browser closes)
    </label>
  );
}

/**
 * The second-factor step every sign-in method (and re-authentication) shares: an authenticator code (or first-time
 * enrollment with recovery codes), a recovery code, an emailed one-time code, or a passkey, with "remember this
 * device". When a passkey is the person's only factor it is the main action and no code field is shown.
 * `onRestart` returns to the first step once the login challenge has lapsed.
 */
export function MfaChallenge({
  tenantId,
  state,
  onDone,
  onRestart,
}: {
  tenantId: string;
  state: MfaChallengeState;
  onDone: () => void;
  onRestart?: () => void;
}) {
  const [code, setCode] = useState('');
  const [useRecovery, setUseRecovery] = useState(false);
  const [remember, setRemember] = useState(false);
  const [emailCodeSent, setEmailCodeSent] = useState(false);
  const [codeExpiresAt, setCodeExpiresAt] = useState<number | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [error, setError] = useState<{ code: string; message: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const view = mfaStepView(state, { emailCodeSent, useRecovery });
  const enrolling = view.enrolling;

  async function guarded(operation: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await operation();
    } catch (caught) {
      setError(describeError(caught));
    } finally {
      setBusy(false);
    }
  }

  async function verify(event: FormEvent) {
    event.preventDefault();
    if (view.passkeyPrimary) return usePasskey();
    await guarded(async () => {
      const client = iamClient();
      const options = sessionOptions(state.persistent);
      if (enrolling) {
        const confirmed = await client.auth.confirmMfa(
          {
            credential: { tenantId, challenge: state.challenge },
            code,
            rememberDevice: remember,
          },
          options,
        );
        setRecoveryCodes(confirmed.recoveryCodes);
        return;
      }
      if (view.recovering)
        await client.auth.recoverMfa({ tenantId, challenge: state.challenge, code }, options);
      else
        await client.auth.verifyMfa(
          {
            tenantId,
            challenge: state.challenge,
            code,
            rememberDevice: remember,
          },
          options,
        );
      onDone();
    });
  }

  const usePasskey = () =>
    guarded(async () => {
      const client = iamClient();
      const begun = await client.auth.beginPasskeyMfa({ tenantId, challenge: state.challenge });
      const response = await startAuthentication({
        optionsJSON: begun.options as unknown as PublicKeyCredentialRequestOptionsJSON,
      });
      await client.auth.finishPasskeyMfa(
        {
          tenantId,
          challengeId: begun.challengeId,
          response: response as never,
          rememberDevice: remember,
        },
        sessionOptions(state.persistent),
      );
      onDone();
    });

  const emailCode = () =>
    guarded(async () => {
      // The code lives no longer than the login challenge (five minutes from the first step), so show the server's
      // expiry instead of promising a fixed duration.
      const sent = await iamClient().auth.requestMfaCode({
        tenantId,
        challenge: state.challenge,
      });
      setEmailCodeSent(true);
      setCodeExpiresAt(typeof sent.expiresAt === 'number' ? sent.expiresAt : null);
      setCode('');
    });

  if (recoveryCodes)
    return (
      <div className="stack">
        <div className="alert success">
          Authenticator enrolled. Save these one-time recovery codes somewhere safe; they are not
          shown again.
        </div>
        <pre className="result">{recoveryCodes.join('\n')}</pre>
        {/* type="button": inside Reauth this may sit in another form, which a submit button would resubmit. */}
        <button className="btn" type="button" onClick={onDone}>
          Continue
        </button>
      </div>
    );

  return (
    <form className="form" onSubmit={verify}>
      {emailCodeSent && (
        <div className="alert info">
          We emailed a one-time code to your address. Enter it below
          {codeExpiresAt
            ? ` before ${new Date(codeExpiresAt).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}, when this sign-in attempt ends; after that, start again.`
            : '.'}
        </div>
      )}
      {view.passkeyPrimary && (
        <div className="alert info">Confirm it&apos;s you with your passkey.</div>
      )}
      {enrolling && state.enrollment && (
        <div className="stack">
          <div className="alert info">
            This account requires multi-factor authentication. Add this secret to an authenticator
            app, then enter the current code.
          </div>
          <div className="field">
            <label>Authenticator secret</label>
            <code className="mono" style={{ wordBreak: 'break-all' }}>
              {state.enrollment.secret}
            </code>
          </div>
          <div className="field">
            <label>Setup URI</label>
            <code className="mono small" style={{ wordBreak: 'break-all' }}>
              {state.enrollment.uri}
            </code>
          </div>
        </div>
      )}
      {view.codeField && (
        <div className="field">
          <label>{view.codeLabel}</label>
          <input
            className="input"
            value={code}
            onChange={(event) => setCode(event.target.value)}
            inputMode={view.recovering ? 'text' : 'numeric'}
            autoComplete="one-time-code"
            autoFocus
            required
          />
        </div>
      )}
      {view.recoveryToggle && (
        <label className="row small">
          <input
            type="checkbox"
            checked={useRecovery}
            onChange={(event) => setUseRecovery(event.target.checked)}
          />{' '}
          Use a recovery code
        </label>
      )}
      {!view.recovering && (
        <label className="row small">
          <input
            type="checkbox"
            checked={remember}
            onChange={(event) => setRemember(event.target.checked)}
          />{' '}
          Remember this device (skip this step here next time, if your organization allows it)
        </label>
      )}
      {error && (
        <div className="alert danger">
          {challengeLapsed(error.code) ? (
            <>
              This sign-in attempt has expired.{' '}
              {onRestart ? (
                <button type="button" className="btn small secondary" onClick={onRestart}>
                  Start again
                </button>
              ) : (
                'Start again from the sign-in page.'
              )}
            </>
          ) : (
            error.message
          )}
        </div>
      )}
      <div className="form-actions row">
        {view.passkeyPrimary ? (
          <button className="btn" disabled={busy}>
            {busy ? 'Waiting for your passkey…' : 'Use your passkey'}
          </button>
        ) : (
          <button className="btn" disabled={busy}>
            {busy ? 'Verifying…' : enrolling ? 'Enroll and sign in' : 'Verify'}
          </button>
        )}
        {state.emailCodeAvailable && (
          <button className="btn secondary" type="button" onClick={emailCode} disabled={busy}>
            {emailCodeSent ? 'Send a new code' : 'Email me a code instead'}
          </button>
        )}
        {state.passkeyAvailable && !view.passkeyPrimary && (
          <button className="btn secondary" type="button" onClick={usePasskey} disabled={busy}>
            Use a passkey
          </button>
        )}
      </div>
    </form>
  );
}

/**
 * Password sign-in followed by the shared second-factor step, exactly as the server demands it. The page renders
 * <KeepSignedIn /> beside it; every session-issuing call reads that choice when it is made.
 */
export function LoginFlow({
  tenantId,
  next,
  tenantName,
}: {
  tenantId: string;
  next: string;
  tenantName?: string;
}) {
  const router = useRouter();
  const [mfa, setMfa] = useState<MfaChallengeState | null>(null);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function finish() {
    router.push(next);
    router.refresh();
  }

  async function signIn(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const outcome = await iamClient().auth.signIn(
        { tenantId, email, password },
        sessionOptions(),
      );
      setPassword('');
      if ('mfaRequired' in outcome) {
        setMfa(await mfaChallengeState(tenantId, outcome));
        return;
      }
      finish();
    } catch (caught) {
      setError(describeError(caught).message);
    } finally {
      setBusy(false);
    }
  }

  if (mfa)
    return (
      <MfaChallenge
        tenantId={tenantId}
        state={mfa}
        onDone={finish}
        onRestart={() => setMfa(null)}
      />
    );

  return (
    <form className="form" onSubmit={signIn}>
      {tenantName && (
        <div className="alert info">
          Signing in to <strong>{tenantName}</strong>
        </div>
      )}
      <div className="field">
        <label>Email</label>
        <input
          className="input"
          type="email"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          autoComplete="username webauthn"
          autoFocus
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
          autoComplete="current-password"
          required
        />
      </div>
      {error && <div className="alert danger">{error}</div>}
      <div className="form-actions">
        <button className="btn" disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </div>
    </form>
  );
}

/**
 * Passwordless email sign-in: a link to click (`magic-link`, redeemed at /cloud/magic) or a six-digit code typed
 * here (`code`, redeemed on this page). Responses never reveal whether the address exists; a code works once,
 * within five minutes, and a wrong code counts against the address's sensitive rate limit.
 */
export function MagicLinkForm({ tenantId, next }: { tenantId: string; next: string }) {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [open, setOpen] = useState(false);
  const [kind, setKind] = useState<'magic-link' | 'code'>('magic-link');
  const [sent, setSent] = useState<'magic-link' | 'code' | null>(null);
  const [code, setCode] = useState('');
  const [mfa, setMfa] = useState<MfaChallengeState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function finish() {
    router.push(next);
    router.refresh();
  }

  async function guarded(operation: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await operation();
    } catch (caught) {
      setError(describeError(caught).message);
    } finally {
      setBusy(false);
    }
  }

  const send = (event?: FormEvent) => {
    event?.preventDefault();
    return guarded(async () => {
      await iamClient().auth.startPasswordless({
        tenantId,
        destination: email,
        channel: 'email',
        kind,
      });
      setCode('');
      setSent(kind);
    });
  };

  const redeem = (event: FormEvent) => {
    event.preventDefault();
    return guarded(async () => {
      const outcome = await iamClient().auth.finishPasswordless(
        { tenantId, destination: email, token: code.trim() },
        sessionOptions(),
      );
      if ('mfaRequired' in outcome) {
        setMfa(await mfaChallengeState(tenantId, outcome));
        return;
      }
      finish();
    });
  };

  if (mfa)
    return (
      <MfaChallenge
        tenantId={tenantId}
        state={mfa}
        onDone={finish}
        onRestart={() => {
          // The emailed code was used up by the first step; start over from the address.
          setMfa(null);
          setSent(null);
          setCode('');
        }}
      />
    );
  if (sent === 'magic-link')
    return (
      <div className="alert success">
        If an account with that address exists, we emailed a sign-in link. It expires in five
        minutes and works once.
      </div>
    );
  if (sent === 'code')
    return (
      <form className="form" onSubmit={redeem}>
        <div className="alert info">
          If an account with <strong>{email}</strong> exists, we emailed it a six-digit code. It
          expires in five minutes and works once.
        </div>
        <div className="field">
          <label>Code from the email</label>
          <input
            className="input"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]{6}"
            maxLength={6}
            value={code}
            onChange={(event) => setCode(event.target.value)}
            required
            autoFocus
          />
        </div>
        {error && <div className="alert danger">{error}</div>}
        <div className="form-actions row">
          <button className="btn" disabled={busy}>
            {busy ? 'Signing in…' : 'Sign in'}
          </button>
          <button type="button" className="btn secondary" disabled={busy} onClick={() => send()}>
            Send a new code
          </button>
          <button
            type="button"
            className="btn secondary"
            onClick={() => {
              setSent(null);
              setError(null);
            }}
          >
            Back
          </button>
        </div>
      </form>
    );
  if (!open)
    return (
      <div className="row">
        <button type="button" className="btn small secondary" onClick={() => setOpen(true)}>
          Email me a sign-in link or code
        </button>
      </div>
    );
  return (
    <form className="form" onSubmit={send}>
      <div className="field">
        <label>Email</label>
        <input
          className="input"
          type="email"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          autoComplete="username"
          required
        />
      </div>
      <div className="field">
        <label>Send me</label>
        <div className="row">
          <label className="row small">
            <input
              type="radio"
              name="passwordless-kind"
              checked={kind === 'magic-link'}
              onChange={() => setKind('magic-link')}
            />{' '}
            a link to click
          </label>
          <label className="row small">
            <input
              type="radio"
              name="passwordless-kind"
              checked={kind === 'code'}
              onChange={() => setKind('code')}
            />{' '}
            a code to type here
          </label>
        </div>
      </div>
      {error && <div className="alert danger">{error}</div>}
      <div className="form-actions row">
        <button className="btn" disabled={busy}>
          {busy ? 'Sending…' : kind === 'code' ? 'Send code' : 'Send sign-in link'}
        </button>
        <button type="button" className="btn secondary" onClick={() => setOpen(false)}>
          Use a password
        </button>
      </div>
    </form>
  );
}

/**
 * Redeems a sign-in link; a click, not the page load, consumes the single-use token. `signInHref` is where to start
 * again when the second-factor step lapses (the link itself is used up by then).
 */
export function MagicLinkLanding({
  tenantId,
  destination,
  token,
  next,
  signInHref,
}: {
  tenantId: string;
  destination: string;
  token: string;
  next: string;
  signInHref?: string;
}) {
  const router = useRouter();
  const [mfa, setMfa] = useState<MfaChallengeState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function finish() {
    router.push(next);
    router.refresh();
  }

  async function redeem() {
    setBusy(true);
    setError(null);
    try {
      const outcome = await iamClient().auth.finishPasswordless(
        { tenantId, destination, token },
        sessionOptions(),
      );
      if ('mfaRequired' in outcome) {
        setMfa(await mfaChallengeState(tenantId, outcome));
        return;
      }
      finish();
    } catch (caught) {
      setError(describeError(caught).message);
    } finally {
      setBusy(false);
    }
  }

  if (mfa)
    return (
      <MfaChallenge
        tenantId={tenantId}
        state={mfa}
        onDone={finish}
        onRestart={signInHref ? () => router.push(signInHref) : undefined}
      />
    );
  return (
    <div className="stack">
      <p className="small muted">
        Signing in as <strong>{destination}</strong>. The link works once and expires five minutes
        after it was sent.
      </p>
      {error && <div className="alert danger">{error}</div>}
      <button className="btn" type="button" onClick={redeem} disabled={busy}>
        {busy ? 'Signing in…' : 'Sign in'}
      </button>
    </div>
  );
}

/** Asks for a password-reset email; the response never reveals whether the address exists. */
export function ForgotPasswordForm({ tenantId }: { tenantId: string }) {
  const [email, setEmail] = useState('');
  const [sent, setSent] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await iamClient().auth.requestPasswordReset({ tenantId, email });
      setSent(true);
    } catch (caught) {
      setError(describeError(caught).message);
    } finally {
      setBusy(false);
    }
  }

  if (sent)
    return (
      <div className="alert success">
        If an account with that address exists, we emailed a link to choose a new password. The link
        expires in ten minutes.
      </div>
    );
  return (
    <form className="form" onSubmit={submit}>
      <div className="field">
        <label>Email</label>
        <input
          className="input"
          type="email"
          value={email}
          onChange={(event) => setEmail(event.target.value)}
          autoComplete="username"
          autoFocus
          required
        />
      </div>
      {error && <div className="alert danger">{error}</div>}
      <div className="form-actions">
        <button className="btn" disabled={busy}>
          {busy ? 'Sending…' : 'Email me a reset link'}
        </button>
      </div>
    </form>
  );
}

/**
 * Chooses a new password from a reset link. The reset signs the account out everywhere and issues no session (the
 * link alone does not prove the second factor), so success says so and leads to the sign-in page (`next`).
 */
export function ResetPasswordForm({
  tenantId,
  token,
  next,
}: {
  tenantId: string;
  token: string;
  next: string;
}) {
  const router = useRouter();
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (password !== confirm) {
      setError('The passwords do not match.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await iamClient().auth.resetPassword({ tenantId, token, password });
      setPassword('');
      setConfirm('');
      setDone(true);
    } catch (caught) {
      setError(describeError(caught).message);
    } finally {
      setBusy(false);
    }
  }

  if (done)
    return (
      <div className="stack">
        <div className="alert success">
          Your password is changed and every session of this account has been signed out. Sign in
          with the new password.
        </div>
        <button className="btn" type="button" onClick={() => router.push(next)}>
          Sign in
        </button>
      </div>
    );
  return (
    <form className="form" onSubmit={submit}>
      <div className="field">
        <label>New password</label>
        <input
          className="input"
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          autoComplete="new-password"
          minLength={12}
          autoFocus
          required
        />
      </div>
      <div className="field">
        <label>Repeat the new password</label>
        <input
          className="input"
          type="password"
          value={confirm}
          onChange={(event) => setConfirm(event.target.value)}
          autoComplete="new-password"
          required
        />
      </div>
      {error && <div className="alert danger">{error}</div>}
      <div className="form-actions">
        <button className="btn" disabled={busy}>
          {busy ? 'Saving…' : 'Set new password'}
        </button>
      </div>
    </form>
  );
}

/** Confirms a new email address from its link; every session of the account ends afterwards. */
export function ConfirmEmailChange({
  tenantId,
  token,
  next,
}: {
  tenantId: string;
  token: string;
  next: string;
}) {
  const router = useRouter();
  const [state, setState] = useState<'idle' | 'busy' | 'done'>('idle');
  const [error, setError] = useState<string | null>(null);

  async function confirm() {
    setState('busy');
    setError(null);
    try {
      await iamClient().auth.confirmEmailChange({ tenantId, token });
      setState('done');
    } catch (caught) {
      setError(describeError(caught).message);
      setState('idle');
    }
  }

  if (state === 'done')
    return (
      <div className="stack">
        <div className="alert success">
          Your email address is updated. Sign in again with the new address; your other sessions
          have been signed out.
        </div>
        <button className="btn" type="button" onClick={() => router.push(next)}>
          Sign in
        </button>
      </div>
    );
  return (
    <div className="stack">
      <p className="small muted">
        Confirming moves your account to the address that received this link and signs out every
        other session.
      </p>
      {error && <div className="alert danger">{error}</div>}
      <button className="btn" type="button" onClick={confirm} disabled={state === 'busy'}>
        {state === 'busy' ? 'Confirming…' : 'Confirm new email'}
      </button>
    </div>
  );
}

/** The landing page of a `verify-email` link: a click, not the page load, consumes the single-use token. */
export function VerifyEmailLanding({
  tenantId,
  token,
  next,
}: {
  tenantId: string;
  token: string;
  next: string;
}) {
  const router = useRouter();
  const [state, setState] = useState<'idle' | 'busy' | 'done'>('idle');
  const [error, setError] = useState<string | null>(null);

  async function verify() {
    setState('busy');
    setError(null);
    try {
      await iamClient().auth.verifyEmail({ tenantId, token });
      setState('done');
    } catch (caught) {
      setError(describeError(caught).message);
      setState('idle');
    }
  }

  if (state === 'done')
    return (
      <div className="stack">
        <div className="alert success">
          Your email address is verified. Sign-in links, emailed codes, and security notices can
          reach you now.
        </div>
        <button className="btn" type="button" onClick={() => router.push(next)}>
          Continue
        </button>
      </div>
    );
  return (
    <div className="stack">
      <p className="small muted">
        Verifying confirms that this address belongs to your account. The link works once and
        expires a day after it was sent.
      </p>
      {error && <div className="alert danger">{error}</div>}
      <button className="btn" type="button" onClick={verify} disabled={state === 'busy'}>
        {state === 'busy' ? 'Verifying…' : 'Verify my email'}
      </button>
    </div>
  );
}

/** Redeems an owner or member invitation, creating the account and signing in. */
export function JoinForm({
  kind,
  tenantId,
  token,
  next,
}: {
  kind: 'owner' | 'member';
  tenantId: string;
  token: string;
  next: string;
}) {
  const router = useRouter();
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [mfa, setMfa] = useState<{ challenge: string; secret: string; uri: string } | null>(null);
  const [code, setCode] = useState('');
  const [codes, setCodes] = useState<string[] | null>(null);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const client = iamClient();
      const outcome =
        kind === 'owner'
          ? await client.tenants.acceptInvitation({ tenantId, token, name, password })
          : await client.identities.acceptInvitation({ tenantId, token, name, password });
      setPassword('');
      if ('mfaRequired' in outcome) {
        const enrollment = await client.auth.beginMfa({ tenantId, challenge: outcome.challenge });
        setMfa({ challenge: outcome.challenge, ...enrollment });
        return;
      }
      router.push(next);
      router.refresh();
    } catch (caught) {
      setError(describeError(caught).message);
    } finally {
      setBusy(false);
    }
  }

  async function enroll(event: FormEvent) {
    event.preventDefault();
    if (!mfa) return;
    setBusy(true);
    setError(null);
    try {
      const confirmed = await iamClient().auth.confirmMfa({
        credential: { tenantId, challenge: mfa.challenge },
        code,
      });
      setCodes(confirmed.recoveryCodes);
    } catch (caught) {
      setError(describeError(caught).message);
    } finally {
      setBusy(false);
    }
  }

  if (codes)
    return (
      <div className="stack">
        <div className="alert success">
          Account created and authenticator enrolled. Save these recovery codes.
        </div>
        <pre className="result">{codes.join('\n')}</pre>
        <button
          className="btn"
          onClick={() => {
            router.push(next);
            router.refresh();
          }}
        >
          Continue
        </button>
      </div>
    );

  if (mfa)
    return (
      <form className="form" onSubmit={enroll}>
        <div className="alert info">
          This organization requires multi-factor authentication. Add the secret to an authenticator
          app and enter the current code.
        </div>
        <div className="field">
          <label>Authenticator secret</label>
          <code className="mono">{mfa.secret}</code>
        </div>
        <div className="field">
          <label>Code</label>
          <input
            className="input"
            value={code}
            onChange={(event) => setCode(event.target.value)}
            inputMode="numeric"
            required
            autoFocus
          />
        </div>
        {error && <div className="alert danger">{error}</div>}
        <div className="form-actions">
          <button className="btn" disabled={busy}>
            Enroll
          </button>
        </div>
      </form>
    );

  return (
    <form className="form" onSubmit={submit}>
      <div className="field">
        <label>Your name</label>
        <input
          className="input"
          value={name}
          onChange={(event) => setName(event.target.value)}
          autoComplete="name"
          required
          autoFocus
        />
      </div>
      <div className="field">
        <label>Choose a password</label>
        <input
          className="input"
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          minLength={12}
          autoComplete="new-password"
          required
        />
        <span className="help">At least 12 characters.</span>
      </div>
      {error && <div className="alert danger">{error}</div>}
      <div className="form-actions">
        <button className="btn" disabled={busy}>
          {busy
            ? 'Creating account…'
            : kind === 'owner'
              ? 'Create owner account'
              : 'Join organization'}
        </button>
      </div>
    </form>
  );
}

export function SignOutButton({ next = '/' }: { next?: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <>
      <button
        type="button"
        className="btn small secondary"
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          setError(null);
          try {
            await iamClient().auth.signOut();
          } catch (caught) {
            const described = describeError(caught);
            // Only UNAUTHENTICATED means the session is already gone. Any other failure (a store outage, a network
            // error) may have left the session and its cookie valid, so leaving the page would claim a sign-out
            // that did not happen, which matters most on a shared computer.
            if (described.code !== 'UNAUTHENTICATED') {
              setError(described.message);
              setBusy(false);
              return;
            }
          }
          router.push(next);
          router.refresh();
        }}
      >
        Sign out
      </button>
      {error && (
        <span className="badge danger" role="alert" title={error}>
          Sign-out failed ({error}). Try again.
        </span>
      )}
    </>
  );
}
