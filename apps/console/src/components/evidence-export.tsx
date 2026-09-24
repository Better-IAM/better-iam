'use client';
import { useState } from 'react';
import { describeError, iamClient } from '@/lib/client';

/** Downloads a signed compliance evidence pack (one framework, or every control) as a JSON file. */
export function EvidenceExportButton({
  tenantId,
  framework,
  label = 'Download evidence',
}: {
  tenantId: string;
  framework?: string;
  label?: string;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  async function download() {
    setBusy(true);
    setError(undefined);
    try {
      const pack = await iamClient().compliance.exportEvidence({
        tenantId,
        ...(framework ? { framework } : {}),
      });
      const blob = new Blob([JSON.stringify(pack, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `evidence-${framework ?? 'all'}-${pack.generatedAt.slice(0, 10)}.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (caught) {
      setError(describeError(caught).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <span className="row" style={{ display: 'inline-flex' }}>
      <button type="button" className="btn small secondary" disabled={busy} onClick={() => void download()}>
        {busy ? '…' : label}
      </button>
      {error && <span className="small danger">{error}</span>}
    </span>
  );
}
