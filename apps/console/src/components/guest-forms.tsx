'use client';
import { useRouter } from 'next/navigation';
import { useId, useState, type FormEvent, type ReactNode } from 'react';
import type { GuestSettingsView } from 'better-iam';
import { describeError, iamClient } from '@/lib/client';
import {
  changesSomething,
  settingsChange,
  settingsDraft,
  type GuestSettingsChange,
  type GuestSettingsDraft,
} from '@/lib/guests';
import { Reauth } from './api-form';

type Failure = { code: string; message: string };

function ListField({
  id,
  label,
  value,
  onChange,
  placeholder,
  help,
}: {
  id: string;
  label: ReactNode;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  help: ReactNode;
}) {
  return (
    <div className="field">
      <label htmlFor={id}>
        {label} <span className="muted">(optional)</span>
      </label>
      <textarea
        id={id}
        className="textarea"
        rows={3}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        spellCheck={false}
      />
      <span className="help">{help}</span>
    </div>
  );
}

/**
 * The organization's cross-tenant access settings: who may join as a guest (inbound), whether its own people may be
 * guests elsewhere (outbound), how long guest access lasts, how often sponsors review it, and the guest boundary. Only
 * what changed is sent; saving needs iam:guests:settings and a recent sign-in, which is asked for in place.
 */
export function GuestSettingsForm({
  tenantId,
  settings,
}: {
  tenantId: string;
  settings: GuestSettingsView;
}) {
  const id = useId();
  const router = useRouter();
  const [draft, setDraft] = useState<GuestSettingsDraft>(() => settingsDraft(settings));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Failure | null>(null);
  const [retry, setRetry] = useState<GuestSettingsChange | null>(null);
  const [notice, setNotice] = useState<{ tone: 'success' | 'info'; text: string } | null>(null);
  const set = (change: Partial<GuestSettingsDraft>) =>
    setDraft((current) => ({ ...current, ...change }));

  async function save(change: GuestSettingsChange) {
    setBusy(true);
    setError(null);
    try {
      const saved = await iamClient().guests.configure({ tenantId, ...change });
      setDraft(settingsDraft(saved));
      setNotice({ tone: 'success', text: 'Saved.' });
      router.refresh();
    } catch (caught) {
      const described = describeError(caught);
      if (described.code === 'RECENT_AUTH_REQUIRED') setRetry(change);
      else setError(described);
    } finally {
      setBusy(false);
    }
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setNotice(null);
    setError(null);
    let change: GuestSettingsChange;
    try {
      change = settingsChange(settings, draft);
    } catch (caught) {
      setError({ code: 'INVALID_INPUT', message: describeError(caught).message });
      return;
    }
    if (!changesSomething(change)) {
      setNotice({ tone: 'info', text: 'Nothing changed.' });
      return;
    }
    void save(change);
  }

  return (
    <div className="stack">
      <form className="form" onSubmit={submit}>
        <h3>Who may join as a guest</h3>
        <div className="field inline">
          <input
            id={`${id}-allow`}
            type="checkbox"
            checked={draft.allowGuests}
            onChange={(event) => set({ allowGuests: event.target.checked })}
          />
          <label htmlFor={`${id}-allow`}>Accept guests</label>
          <span className="help">
            Off: nobody can be invited or redeem an invitation, except people from organizations
            admitted below.
          </span>
        </div>
        <div className="grid cols-2">
          <ListField
            id={`${id}-allowed-domains`}
            label="Only from these domains"
            value={draft.allowedDomains}
            onChange={(allowedDomains) => set({ allowedDomains })}
            placeholder={'partner.example\nagency.example'}
            help="One per line; subdomains count. Empty: any domain."
          />
          <ListField
            id={`${id}-blocked-domains`}
            label="Never from these domains"
            value={draft.blockedDomains}
            onChange={(blockedDomains) => set({ blockedDomains })}
            placeholder="competitor.example"
            help="Wins over every other setting, including admitted organizations."
          />
        </div>
        <div className="grid cols-2">
          <ListField
            id={`${id}-inbound-admitted`}
            label="Always admit people from these organizations"
            value={draft.inboundAdmitted}
            onChange={(inboundAdmitted) => set({ inboundAdmitted })}
            help="Organization IDs, one per line: their verified domains are admitted even when guests are off or the domain is not listed above."
          />
          <ListField
            id={`${id}-inbound-refused`}
            label="Never admit people from these organizations"
            value={draft.inboundRefused}
            onChange={(inboundRefused) => set({ inboundRefused })}
            help="Organization IDs, one per line. An organization is known by the domains it verified."
          />
        </div>
        <h3>Your people as guests elsewhere</h3>
        <div className="field inline">
          <input
            id={`${id}-outbound`}
            type="checkbox"
            checked={draft.allowGuestInvitations}
            onChange={(event) => set({ allowGuestInvitations: event.target.checked })}
          />
          <label htmlFor={`${id}-outbound`}>
            Let people at this organization&apos;s verified domains join other organizations as
            guests
          </label>
          <span className="help">
            The other organization only learns that the person&apos;s organization does not allow
            it.
          </span>
        </div>
        <div className="grid cols-2">
          <ListField
            id={`${id}-outbound-admitted`}
            label="Always allow joining these organizations"
            value={draft.outboundAdmitted}
            onChange={(outboundAdmitted) => set({ outboundAdmitted })}
            help="Organization IDs, one per line, allowed even when the switch above is off."
          />
          <ListField
            id={`${id}-outbound-refused`}
            label="Never allow joining these organizations"
            value={draft.outboundRefused}
            onChange={(outboundRefused) => set({ outboundRefused })}
            help="Organization IDs, one per line, refused even when the switch above is on."
          />
        </div>
        <h3>Access and reviews</h3>
        <div className="grid cols-2">
          <div className="field">
            <label htmlFor={`${id}-access-days`}>Guest access lasts (days)</label>
            <input
              id={`${id}-access-days`}
              className="input"
              type="number"
              min={1}
              max={365}
              step={1}
              required
              value={draft.accessDays}
              onChange={(event) => set({ accessDays: event.target.value })}
            />
            <span className="help">
              1 to 365, from redemption or the last renewal; inviters and sponsors may choose
              another length.
            </span>
          </div>
          <div className="field">
            <label htmlFor={`${id}-review-days`}>Sponsors review every (days)</label>
            <input
              id={`${id}-review-days`}
              className="input"
              type="number"
              min={7}
              max={365}
              step={1}
              required
              value={draft.reviewEveryDays}
              onChange={(event) => set({ reviewEveryDays: event.target.value })}
            />
            <span className="help">
              7 to 365. Sponsors are emailed 14 days before a review or an access end.
            </span>
          </div>
        </div>
        <div className="field">
          <label htmlFor={`${id}-boundary`}>
            Guest boundary <span className="muted">(optional)</span>
          </label>
          <textarea
            id={`${id}-boundary`}
            className="textarea mono"
            rows={8}
            value={draft.guestBoundary}
            onChange={(event) => set({ guestBoundary: event.target.value })}
            placeholder={
              '{\n  "version": 1,\n  "statements": [\n    { "effect": "allow", "actions": ["workspace:read"], "resources": ["workspace/*"] }\n  ]\n}'
            }
            spellCheck={false}
          />
          <span className="help">
            A policy document that caps every guest&apos;s decisions here: guests can never do more
            than it allows, whatever their roles grant. Empty it to remove the boundary.
          </span>
        </div>
        <div className="form-actions">
          <button className="btn" disabled={busy}>
            {busy ? 'Working…' : 'Save settings'}
          </button>
          <button
            type="button"
            className="btn secondary"
            disabled={busy}
            onClick={() => {
              setDraft(settingsDraft(settings));
              setError(null);
              setNotice(null);
            }}
          >
            Reset
          </button>
        </div>
      </form>
      {error && (
        <div className="alert danger">
          <strong>{error.code}</strong> — {error.message}
        </div>
      )}
      {retry && (
        <Reauth
          tenantId={tenantId}
          onDone={() => {
            const pending = retry;
            setRetry(null);
            void save(pending);
          }}
          onCancel={() => setRetry(null)}
        />
      )}
      {notice && !busy && !error && <div className={`alert ${notice.tone}`}>{notice.text}</div>}
    </div>
  );
}
