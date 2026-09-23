'use client';
import { useRouter } from 'next/navigation';
import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { describeError, iamClient } from '@/lib/client';
import {
  bodyFrom,
  dateTimeLocalValue,
  selectDefault,
  textDefault,
  type FieldSpec,
} from '@/lib/form-body';
import { sessionOptions } from '@/lib/persistence';
import { MfaChallenge, mfaChallengeState, type MfaChallengeState } from './auth-forms';

export type { FieldOption, FieldSpec } from '@/lib/form-body';

/**
 * A `datetime-local` input. An epoch default is formatted after mount, in the browser's time zone, because that is
 * the zone the submitted value is read in; formatting it during server rendering would use the server's zone.
 */
function DateTimeInput({ id, field }: { id: string; field: FieldSpec }) {
  const epoch = typeof field.defaultValue === 'number' ? field.defaultValue : undefined;
  // Empty during server rendering and hydration, so both produce the same markup.
  const [initial, setInitial] = useState(() => textDefault(field));
  useEffect(() => {
    if (epoch !== undefined) setInitial(dateTimeLocalValue(epoch));
  }, [epoch]);
  return (
    <input
      id={id}
      className="input"
      name={field.name}
      type="datetime-local"
      defaultValue={initial}
      placeholder={field.placeholder}
      required={field.required}
    />
  );
}

export function Field({ field }: { field: FieldSpec }) {
  const id = `field-${field.name}`;
  if (field.type === 'hidden')
    return <input type="hidden" name={field.name} value={textDefault(field)} />;
  if (field.type === 'checkbox')
    return (
      <div className="field inline">
        <input
          id={id}
          type="checkbox"
          name={field.name}
          defaultChecked={Boolean(field.defaultValue)}
        />
        <label htmlFor={id}>{field.label}</label>
        {field.help && <span className="help">{field.help}</span>}
      </div>
    );
  return (
    <div className="field">
      <label htmlFor={id}>
        {field.label}
        {field.required ? '' : <span className="muted"> (optional)</span>}
      </label>
      {field.type === 'textarea' || field.type === 'json' ? (
        <textarea
          id={id}
          className="textarea"
          name={field.name}
          rows={field.rows ?? (field.type === 'json' ? 8 : 4)}
          defaultValue={textDefault(field)}
          placeholder={field.placeholder}
          required={field.required}
        />
      ) : field.type === 'select' || field.type === 'multiselect' ? (
        <select
          id={id}
          className="select"
          name={field.name}
          multiple={field.type === 'multiselect'}
          // Multiselects preselect their current values, so a form that replaces a whole record keeps them.
          defaultValue={selectDefault(field)}
          required={field.required}
        >
          {field.type === 'select' && !field.required && <option value="">—</option>}
          {(field.options ?? []).map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      ) : field.type === 'datetime' ? (
        <DateTimeInput id={id} field={field} />
      ) : (
        <input
          id={id}
          className="input"
          name={field.name}
          type={field.type === 'list' ? 'text' : (field.type ?? 'text')}
          defaultValue={textDefault(field)}
          placeholder={field.placeholder}
          required={field.required}
          autoComplete={field.type === 'password' ? 'new-password' : undefined}
        />
      )}
      {field.help && <span className="help">{field.help}</span>}
    </div>
  );
}

export interface ApiFormProps {
  /** Route relative to /api/iam, for example `roles/create`. */
  path: string;
  fields: FieldSpec[];
  submitLabel?: string;
  title?: ReactNode;
  description?: ReactNode;
  /** Redirect after success; `{id}` and `{tenant.id}` style placeholders are read from the response. */
  redirectTo?: string;
  successMessage?: string;
  showResult?: boolean;
  resetOnSuccess?: boolean;
  /** Tenant of the signed-in session; needed to complete a step-up MFA check. */
  tenantId?: string;
  compact?: boolean;
}

function interpolate(template: string, result: unknown): string {
  return template.replace(/\{([\w.]+)\}/g, (_, path: string) =>
    String(
      path
        .split('.')
        .reduce<unknown>(
          (value, key) =>
            value && typeof value === 'object'
              ? (value as Record<string, unknown>)[key]
              : undefined,
          result,
        ) ?? '',
    ),
  );
}

/** Posts a JSON body to Better IAM through the typed client transport and refreshes server-rendered data on success. */
export function ApiForm({
  path,
  fields,
  submitLabel = 'Save',
  title,
  description,
  redirectTo,
  successMessage,
  showResult,
  resetOnSuccess,
  tenantId,
  compact,
}: ApiFormProps) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ code: string; message: string } | null>(null);
  const [result, setResult] = useState<unknown>(undefined);
  const [pending, setPending] = useState<{
    form: HTMLFormElement;
    body: Record<string, unknown>;
  } | null>(null);

  async function send(form: HTMLFormElement, body: Record<string, unknown>) {
    setBusy(true);
    setError(null);
    try {
      const response = await iamClient().$request(path, body);
      setResult(response);
      if (resetOnSuccess) form.reset();
      router.refresh();
      if (redirectTo) router.push(interpolate(redirectTo, response));
    } catch (caught) {
      const described = describeError(caught);
      if (described.code === 'RECENT_AUTH_REQUIRED') {
        setPending({ form, body });
      }
      setError(described);
    } finally {
      setBusy(false);
    }
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    try {
      await send(form, bodyFrom(new FormData(form), fields));
    } catch (caught) {
      setError(describeError(caught));
    }
  }

  return (
    <form className="form" onSubmit={onSubmit}>
      {title && <h3>{title}</h3>}
      {description && <p className="muted small">{description}</p>}
      {fields.map((field) => (
        <Field key={field.name} field={field} />
      ))}
      {error && error.code !== 'RECENT_AUTH_REQUIRED' && (
        <div className="alert danger">
          <strong>{error.code}</strong> — {error.message}
        </div>
      )}
      {pending && (
        <Reauth
          tenantId={tenantId}
          onDone={() => {
            const retry = pending;
            setPending(null);
            void send(retry.form, retry.body);
          }}
          onCancel={() => setPending(null)}
        />
      )}
      {successMessage && result !== undefined && !error && (
        <div className="alert success">{successMessage}</div>
      )}
      {showResult && result !== undefined && !error && (
        <pre className="result">{JSON.stringify(result, null, 2)}</pre>
      )}
      <div className="form-actions">
        <button className={compact ? 'btn small' : 'btn'} disabled={busy}>
          {busy ? 'Working…' : submitLabel}
        </button>
      </div>
    </form>
  );
}

export interface ApiButtonProps {
  path: string;
  body: Record<string, unknown>;
  label: string;
  confirm?: string;
  tone?: 'primary' | 'secondary' | 'danger';
  redirectTo?: string;
  tenantId?: string;
  showResult?: boolean;
}

/** One-click operations such as suspend, revoke, or delete. */
export function ApiButton({
  path,
  body,
  label,
  confirm: confirmation,
  tone = 'secondary',
  redirectTo,
  tenantId,
  showResult,
}: ApiButtonProps) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ code: string; message: string } | null>(null);
  const [result, setResult] = useState<unknown>(undefined);
  const [reauth, setReauth] = useState(false);

  async function run() {
    if (confirmation && !window.confirm(confirmation)) return;
    setBusy(true);
    setError(null);
    try {
      const response = await iamClient().$request(path, body);
      setResult(response);
      router.refresh();
      if (redirectTo) router.push(interpolate(redirectTo, response));
    } catch (caught) {
      const described = describeError(caught);
      if (described.code === 'RECENT_AUTH_REQUIRED') setReauth(true);
      else setError(described);
    } finally {
      setBusy(false);
    }
  }

  return (
    <span className="row" style={{ display: 'inline-flex' }}>
      <button
        type="button"
        className={`btn small ${tone === 'primary' ? '' : tone}`}
        disabled={busy}
        onClick={() => void run()}
      >
        {busy ? '…' : label}
      </button>
      {error && (
        <span className="badge danger" title={error.message}>
          {error.code}
        </span>
      )}
      {reauth && (
        <Reauth
          tenantId={tenantId}
          onDone={() => {
            setReauth(false);
            void run();
          }}
          onCancel={() => setReauth(false)}
        />
      )}
      {showResult && result !== undefined && (
        <pre className="result" style={{ width: '100%' }}>
          {JSON.stringify(result, null, 2)}
        </pre>
      )}
    </span>
  );
}

/**
 * Sensitive operations require recent authentication; this re-runs the password ceremony in place, followed by the
 * same second-factor step as sign-in (authenticator, emailed code, passkey, or recovery code). The replacement
 * session keeps the "keep me signed in" choice of this browser, so a browser-session cookie stays one.
 */
export function Reauth({
  tenantId,
  onDone,
  onCancel,
}: {
  tenantId?: string;
  onDone: () => void;
  onCancel: () => void;
}) {
  const [password, setPassword] = useState('');
  const [mfa, setMfa] = useState<MfaChallengeState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const outcome = await iamClient().auth.reauthenticate({ password }, sessionOptions());
      setPassword('');
      if ('mfaRequired' in outcome) {
        if (!tenantId) throw new Error('Tenant is unknown for MFA verification');
        setMfa(await mfaChallengeState(tenantId, outcome));
        return;
      }
      onDone();
    } catch (caught) {
      setError(describeError(caught).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    // Reauth often renders inside another form (ApiForm, account linking): its own submits must not bubble up
    // and resubmit that form.
    <div
      className="alert warning"
      style={{ width: '100%' }}
      onSubmit={(event) => event.stopPropagation()}
    >
      {mfa && tenantId ? (
        <div className="stack">
          <strong>Confirm it&apos;s you</strong>
          <span className="small">Finish the second step to continue.</span>
          <MfaChallenge
            tenantId={tenantId}
            state={mfa}
            onDone={onDone}
            onRestart={() => setMfa(null)}
          />
          <div className="form-actions">
            <button type="button" className="btn small secondary" onClick={onCancel}>
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <form className="form" onSubmit={submit}>
          <strong>Confirm it&apos;s you</strong>
          <span className="small">This operation requires recent authentication.</span>
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
          {error && (
            <span className="small" style={{ color: 'var(--danger)' }}>
              {error}
            </span>
          )}
          <div className="form-actions">
            <button className="btn small" disabled={busy}>
              Continue
            </button>
            <button type="button" className="btn small secondary" onClick={onCancel}>
              Cancel
            </button>
          </div>
        </form>
      )}
    </div>
  );
}
