'use client';
import { useState } from 'react';
import { describeError, iamClient } from '@/lib/client';

/**
 * Downloads a data-subject request's export as a JSON file. The person it is about may always download it; a request
 * handler must have signed in recently (the server asks for it).
 */
export function PrivacyExportButton({
  tenantId,
  requestId,
  label = 'Download your data',
}: {
  tenantId: string;
  requestId: string;
  label?: string;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  async function download() {
    setBusy(true);
    setError(undefined);
    try {
      const result = await iamClient().privacy.downloadExport({ tenantId, requestId });
      const blob = new Blob([JSON.stringify(result.data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `${result.number}.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (caught) {
      const described = describeError(caught);
      setError(
        described.code === 'RECENT_AUTH_REQUIRED'
          ? 'Sign in again to download it.'
          : described.message,
      );
    } finally {
      setBusy(false);
    }
  }
  return (
    <span className="row" style={{ display: 'inline-flex' }}>
      <button
        type="button"
        className="btn small secondary"
        disabled={busy}
        onClick={() => void download()}
      >
        {busy ? '…' : label}
      </button>
      {error && <span className="small danger">{error}</span>}
    </span>
  );
}
