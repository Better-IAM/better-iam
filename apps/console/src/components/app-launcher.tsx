'use client';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { describeError, iamClient } from '@/lib/client';

/** Opens an app from the launcher: records the launch, then goes to the app's sign-in URL in a new tab. */
export function LaunchButton({ tenantId, appId }: { tenantId: string; appId: string }) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  async function launch() {
    setBusy(true);
    setError(undefined);
    // Opened before the request so the browser treats it as a direct result of the click.
    const tab = window.open('about:blank', '_blank');
    try {
      const { url } = await iamClient().applications.launch({ tenantId, appId });
      if (tab) {
        tab.opener = null;
        tab.location.href = url;
      } else window.location.href = url;
      router.refresh();
    } catch (caught) {
      tab?.close();
      setError(describeError(caught).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <span className="row" style={{ display: 'inline-flex' }}>
      <button type="button" className="btn small" disabled={busy} onClick={() => void launch()}>
        {busy ? '…' : 'Open'}
      </button>
      {error && <span className="small danger">{error}</span>}
    </span>
  );
}

/** Requests the access package that grants an app the person does not have yet. */
export function RequestAppButton({ tenantId, packageId }: { tenantId: string; packageId: string }) {
  const [state, setState] = useState<'idle' | 'busy' | 'sent'>('idle');
  const [error, setError] = useState<string>();
  async function request() {
    const justification = window.prompt('Why do you need this app?') ?? undefined;
    if (justification === undefined) return;
    setState('busy');
    setError(undefined);
    try {
      await iamClient().packages.request({
        tenantId,
        packageId,
        ...(justification.trim() ? { justification: justification.trim() } : {}),
      });
      setState('sent');
    } catch (caught) {
      setState('idle');
      setError(describeError(caught).message);
    }
  }
  return (
    <span className="row" style={{ display: 'inline-flex' }}>
      <button
        type="button"
        className="btn small secondary"
        disabled={state !== 'idle'}
        onClick={() => void request()}
      >
        {state === 'sent' ? 'Requested' : state === 'busy' ? '…' : 'Request access'}
      </button>
      {error && <span className="small danger">{error}</span>}
    </span>
  );
}
