'use client';
import { useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import type { MyAgreement } from 'better-iam/server';
import { describeError, iamClient } from '@/lib/client';

/** Asks the signed-in member to accept the organization's required agreements they have not accepted yet. */
export function AgreementsBanner({ tenantId }: { tenantId: string }) {
  const router = useRouter();
  const [pending, setPending] = useState<MyAgreement[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    iamClient()
      .$request('agreements/listMine', { tenantId })
      .then((result) => {
        if (active)
          setPending(
            (result as MyAgreement[]).filter(
              (agreement) => agreement.required && !agreement.accepted,
            ),
          );
      })
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, [tenantId]);

  async function accept(agreement: MyAgreement) {
    setBusy(agreement.id);
    setError(null);
    try {
      await iamClient().$request('agreements/accept', {
        tenantId,
        agreementId: agreement.id,
        version: agreement.version,
      });
      setPending((current) => current.filter((item) => item.id !== agreement.id));
      router.refresh();
    } catch (caught) {
      setError(describeError(caught).message);
    } finally {
      setBusy(null);
    }
  }

  if (!pending.length) return null;
  return (
    <div className="alert warning stack" role="region" aria-label="Agreements to accept">
      <strong>
        Please review and accept {pending.length === 1 ? 'this agreement' : 'these agreements'}.
        Some access stays unavailable until you do.
      </strong>
      {pending.map((agreement) => (
        <details key={agreement.id} open={pending.length === 1}>
          <summary>
            {agreement.name} <span className="muted small">(version {agreement.version})</span>
          </summary>
          <div className="stack" style={{ marginTop: 8 }}>
            <pre className="result" style={{ whiteSpace: 'pre-wrap', maxHeight: 240 }}>
              {agreement.content}
            </pre>
            {agreement.url && (
              <a href={agreement.url} target="_blank" rel="noreferrer noopener">
                Full document
              </a>
            )}
            <span>
              <button
                className="btn small"
                disabled={busy !== null}
                onClick={() => accept(agreement)}
              >
                {busy === agreement.id ? 'Recording…' : 'I accept'}
              </button>
            </span>
          </div>
        </details>
      ))}
      {error && <span className="small">{error}</span>}
    </div>
  );
}
