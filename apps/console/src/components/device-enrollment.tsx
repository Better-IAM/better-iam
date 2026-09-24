'use client';
import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import type { DeviceEnrollmentCode } from 'better-iam';
import { Field, Reauth } from '@/components/api-form';
import { describeError, iamClient } from '@/lib/client';
import { bodyFrom, type FieldSpec } from '@/lib/form-body';

/**
 * Creates a one-time device enrollment code (`devices/createEnrollment`) and shows it once, with a copy button. Only
 * the code's hash is stored, so the list of codes shows their status but never the codes themselves.
 */
export function EnrollmentCodeForm({
  tenantId,
  fields,
  submitLabel = 'Create code',
}: {
  tenantId: string;
  fields: FieldSpec[];
  submitLabel?: string;
}) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ code: string; message: string } | null>(null);
  const [pending, setPending] = useState<Record<string, unknown> | null>(null);
  const [created, setCreated] = useState<DeviceEnrollmentCode | null>(null);
  const [copied, setCopied] = useState(false);

  async function send(body: Record<string, unknown>) {
    setBusy(true);
    setError(null);
    try {
      const result = (await iamClient().$request(
        'devices/createEnrollment',
        body,
      )) as DeviceEnrollmentCode;
      setCreated(result);
      setCopied(false);
      router.refresh();
    } catch (caught) {
      const described = describeError(caught);
      if (described.code === 'RECENT_AUTH_REQUIRED') setPending(body);
      else setError(described);
    } finally {
      setBusy(false);
    }
  }

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      void send(bodyFrom(new FormData(event.currentTarget), fields));
    } catch (caught) {
      setError(describeError(caught));
    }
  }

  function copy(code: string) {
    void navigator.clipboard.writeText(code).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  return (
    <div className="stack">
      {created ? (
        <div className="alert success">
          <div className="stack">
            <strong>Enrollment code</strong>
            <pre className="result">{created.code}</pre>
            <div className="row">
              <button
                type="button"
                className="btn small secondary"
                onClick={() => copy(created.code)}
              >
                {copied ? 'Copied' : 'Copy'}
              </button>
              <button
                type="button"
                className="btn small secondary"
                onClick={() => setCreated(null)}
              >
                Done
              </button>
              <span className="small">
                Valid until {new Date(created.expiresAt).toLocaleString()}; works once.
              </span>
            </div>
            <span className="small">
              Shown only now: Better IAM keeps only its hash. Pass it as <code>enrollmentCode</code>{' '}
              to <code>devices.enroll</code> on the device.
            </span>
          </div>
        </div>
      ) : (
        <form className="form" onSubmit={onSubmit}>
          {fields.map((field) => (
            <Field key={field.name} field={field} />
          ))}
          {error && (
            <div className="alert danger">
              <strong>{error.code}</strong> — {error.message}
            </div>
          )}
          <div className="form-actions">
            <button className="btn small" disabled={busy}>
              {busy ? 'Working…' : submitLabel}
            </button>
          </div>
        </form>
      )}
      {pending && (
        <Reauth
          tenantId={tenantId}
          onDone={() => {
            const retry = pending;
            setPending(null);
            void send(retry);
          }}
          onCancel={() => setPending(null)}
        />
      )}
    </div>
  );
}
