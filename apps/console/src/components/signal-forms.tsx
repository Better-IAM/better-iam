'use client';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useId, useState, type FormEvent, type ReactNode } from 'react';
import type {
  SignalAction,
  SignalActionableEvent,
  SignalPollResult,
  SignalSourceCreated,
  SignalSourceView,
} from 'better-iam/server';
import { describeError, iamClient } from '@/lib/client';
import {
  actionableEventHelp,
  actionableEventTypes,
  actionsChange,
  createSourceBody,
  eventTypeLabels,
  mappingChange,
  mappingDraft,
  pollSummary,
  signalAlgorithms,
  sourceDraft,
  sourceSettingsChange,
  splitEntries,
  type KeySourceMode,
  type MappingDraft,
  type SourceDraft,
} from '@/lib/signals';
import { Reauth } from './api-form';

type Failure = { code: string; message: string };
type Actions = Partial<Record<SignalActionableEvent, SignalAction>>;
/** A SCIM connection the mapping form offers. */
export interface ScimConnectionOption {
  id: string;
  name: string;
  revoked?: boolean;
}

/**
 * Runs one signals API call for a form: tracks progress, shows the error, asks for the password (and second factor)
 * again when the operation needs recent authentication and then retries, and refreshes the server-rendered page.
 */
function useSignalCall(tenantId: string) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Failure | null>(null);
  const [retry, setRetry] = useState<{ again: () => Promise<void> } | null>(null);

  async function run<T>(call: () => Promise<T>, done?: (result: T) => void): Promise<void> {
    setBusy(true);
    setError(null);
    try {
      const result = await call();
      done?.(result);
      router.refresh();
    } catch (caught) {
      const described = describeError(caught);
      if (described.code === 'RECENT_AUTH_REQUIRED') setRetry({ again: () => run(call, done) });
      else setError(described);
    } finally {
      setBusy(false);
    }
  }

  const feedback: ReactNode = (
    <>
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
            void pending.again();
          }}
          onCancel={() => setRetry(null)}
        />
      )}
    </>
  );
  return {
    run,
    busy,
    feedback,
    fail: (message: string) => setError({ code: 'INVALID_INPUT', message }),
  };
}

/** A value to hand to the transmitter's administrator, with a copy button. */
function CopyValue({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <span className="row" style={{ display: 'flex', flexWrap: 'nowrap' }}>
      <code className="small" style={{ wordBreak: 'break-all' }}>
        {value}
      </code>
      <button
        type="button"
        className="btn small secondary"
        onClick={() => {
          void navigator.clipboard.writeText(value).then(() => {
            setCopied(true);
            setTimeout(() => setCopied(false), 2000);
          });
        }}
      >
        {copied ? 'Copied' : 'Copy'}
      </button>
    </span>
  );
}

function toggle<T>(list: readonly T[], item: T, on: boolean): T[] {
  return on
    ? list.includes(item)
      ? [...list]
      : [...list, item]
    : list.filter((entry) => entry !== item);
}

/** The transmitter settings: name, issuer, audiences, keys, algorithms, token type, and (when creating) delivery. */
function SourceFields({
  draft,
  set,
  source,
}: {
  draft: SourceDraft;
  set: (change: Partial<SourceDraft>) => void;
  /** The source being edited: the issuer and delivery are fixed, and the poll token is never shown. */
  source?: SignalSourceView;
}) {
  const id = useId();
  const keyModes: { mode: KeySourceMode; label: string; help: string }[] = [
    {
      mode: 'discover',
      label: 'Discover from the issuer',
      help: 'Reads jwks_uri from the issuer’s /.well-known/ssf-configuration (or the legacy risc-configuration) document.',
    },
    {
      mode: 'jwksUri',
      label: 'Key set URL',
      help: 'The transmitter’s published JWKS, over https.',
    },
    {
      mode: 'jwks',
      label: 'Static keys',
      help: 'Public keys pasted here; change them when the transmitter rotates.',
    },
  ];
  const delivery = source?.delivery ?? draft.delivery;
  return (
    <>
      <div className="grid cols-2">
        <div className="field">
          <label htmlFor={`${id}-name`}>Name</label>
          <input
            id={`${id}-name`}
            className="input"
            value={draft.name}
            onChange={(event) => set({ name: event.target.value })}
            maxLength={128}
            placeholder="Okta production"
            required
          />
        </div>
        <div className="field">
          <label htmlFor={`${id}-issuer`}>Issuer</label>
          {source ? (
            <code id={`${id}-issuer`} className="small" style={{ padding: '8px 0' }}>
              {source.issuer}
            </code>
          ) : (
            <input
              id={`${id}-issuer`}
              className="input"
              type="url"
              value={draft.issuer}
              onChange={(event) => set({ issuer: event.target.value })}
              maxLength={512}
              placeholder="https://example.okta.com"
              required
            />
          )}
          <span className="help">
            {source
              ? 'The iss of its events; it cannot change. Register a new source for another issuer.'
              : 'The iss the transmitter puts in its events, exactly as it sends it (a trailing slash does not matter).'}
          </span>
        </div>
      </div>
      <div className="grid cols-2">
        <div className="field">
          <label htmlFor={`${id}-audiences`}>Audiences</label>
          <textarea
            id={`${id}-audiences`}
            className="textarea"
            rows={2}
            value={draft.audiences}
            onChange={(event) => set({ audiences: event.target.value })}
            placeholder="https://iam.example.com/api/iam/signals/push"
            required
          />
          <span className="help">
            The aud values the transmitter uses for this receiver, such as the push URL or the
            client id it knows you by; events must name one. 1 to 10, one per line.
          </span>
        </div>
        <div className="field">
          <label htmlFor={`${id}-aliases`}>
            Issuer aliases <span className="muted">(optional)</span>
          </label>
          <textarea
            id={`${id}-aliases`}
            className="textarea"
            rows={2}
            value={draft.issuerAliases}
            onChange={(event) => set({ issuerAliases: event.target.value })}
            placeholder="https://example.okta.com/oauth2/default"
          />
          <span className="help">
            Other spellings of the issuer its events or your sign-in links use. Up to 5, one per
            line.
          </span>
        </div>
      </div>
      <fieldset className="stack" style={{ border: 0, padding: 0, margin: 0, gap: 6 }}>
        <legend className="small muted" style={{ marginBottom: 6 }}>
          Signing keys
        </legend>
        {keyModes.map((option) => (
          <div key={option.mode} className="field inline">
            <input
              id={`${id}-keys-${option.mode}`}
              type="radio"
              name={`${id}-keys`}
              checked={draft.keys === option.mode}
              onChange={() => set({ keys: option.mode })}
            />
            <label htmlFor={`${id}-keys-${option.mode}`}>{option.label}</label>
            <span className="help">{option.help}</span>
          </div>
        ))}
        {draft.keys === 'jwksUri' && (
          <input
            className="input"
            type="url"
            aria-label="Key set URL"
            value={draft.jwksUri}
            onChange={(event) => set({ jwksUri: event.target.value })}
            maxLength={2048}
            placeholder="https://example.okta.com/oauth2/v1/keys"
            required
          />
        )}
        {draft.keys === 'jwks' && (
          <textarea
            className="textarea"
            aria-label="Static keys"
            rows={6}
            value={draft.jwks}
            onChange={(event) => set({ jwks: event.target.value })}
            placeholder={'{ "keys": [ { "kty": "RSA", "kid": "…", "n": "…", "e": "AQAB" } ] }'}
            required
          />
        )}
      </fieldset>
      <fieldset className="stack" style={{ border: 0, padding: 0, margin: 0, gap: 6 }}>
        <legend className="small muted" style={{ marginBottom: 6 }}>
          Accepted signature algorithms
        </legend>
        <div className="row" style={{ flexWrap: 'wrap' }}>
          {signalAlgorithms.map((algorithm) => (
            <span key={algorithm} className="field inline">
              <input
                id={`${id}-alg-${algorithm}`}
                type="checkbox"
                checked={draft.algorithms.includes(algorithm)}
                onChange={(event) =>
                  set({ algorithms: toggle(draft.algorithms, algorithm, event.target.checked) })
                }
              />
              <label htmlFor={`${id}-alg-${algorithm}`}>{algorithm}</label>
            </span>
          ))}
        </div>
      </fieldset>
      <div className="field inline">
        <input
          id={`${id}-typ`}
          type="checkbox"
          checked={draft.requireTyp}
          onChange={(event) => set({ requireTyp: event.target.checked })}
        />
        <label htmlFor={`${id}-typ`}>
          Require the <code>secevent+jwt</code> token type
        </label>
        <span className="help">
          Turn off only for legacy RISC transmitters (such as Google) that send plain JWTs.
        </span>
      </div>
      {!source && (
        <fieldset className="stack" style={{ border: 0, padding: 0, margin: 0, gap: 6 }}>
          <legend className="small muted" style={{ marginBottom: 6 }}>
            Delivery
          </legend>
          <div className="field inline">
            <input
              id={`${id}-push`}
              type="radio"
              name={`${id}-delivery`}
              checked={draft.delivery === 'push'}
              onChange={() => set({ delivery: 'push' })}
            />
            <label htmlFor={`${id}-push`}>Push</label>
            <span className="help">
              The transmitter posts each event to this organization’s push URL (RFC 8935).
            </span>
          </div>
          <div className="field inline">
            <input
              id={`${id}-poll`}
              type="radio"
              name={`${id}-delivery`}
              checked={draft.delivery === 'poll'}
              onChange={() => set({ delivery: 'poll' })}
            />
            <label htmlFor={`${id}-poll`}>Poll</label>
            <span className="help">
              Events are fetched from the transmitter every minute (RFC 8936).
            </span>
          </div>
          {draft.delivery === 'push' && (
            <div className="field inline" style={{ marginLeft: 24 }}>
              <input
                id={`${id}-push-token`}
                type="checkbox"
                checked={draft.pushToken}
                onChange={(event) => set({ pushToken: event.target.checked })}
              />
              <label htmlFor={`${id}-push-token`}>Require a bearer token on pushes</label>
              <span className="help">
                Recommended. The token is shown once, after the source is created.
              </span>
            </div>
          )}
        </fieldset>
      )}
      {delivery === 'poll' && (
        <div className="grid cols-3">
          <div className="field">
            <label htmlFor={`${id}-endpoint`}>Poll endpoint</label>
            <input
              id={`${id}-endpoint`}
              className="input"
              type="url"
              value={draft.pollEndpoint}
              onChange={(event) => set({ pollEndpoint: event.target.value })}
              maxLength={2048}
              placeholder="https://transmitter.example.com/ssf/poll"
              required
            />
          </div>
          <div className="field">
            <label htmlFor={`${id}-token`}>
              Bearer token {source && <span className="muted">(optional)</span>}
            </label>
            <input
              id={`${id}-token`}
              className="input"
              type="password"
              value={draft.pollToken}
              onChange={(event) => set({ pollToken: event.target.value })}
              maxLength={4096}
              autoComplete="off"
              required={!source}
            />
            {source && (
              <span className="help">
                Stored sealed and never shown. Leave empty to keep it; a new endpoint needs it
                again.
              </span>
            )}
          </div>
          <div className="field">
            <label htmlFor={`${id}-max`}>Events per request</label>
            <input
              id={`${id}-max`}
              className="input"
              type="number"
              min={1}
              max={100}
              step={1}
              value={draft.pollMaxEvents}
              onChange={(event) => set({ pollMaxEvents: event.target.value })}
              required
            />
          </div>
        </div>
      )}
    </>
  );
}

/** How subjects map to members: sign-in connection links, SCIM external ids, and verified email addresses. */
function MappingFields({
  draft,
  set,
  scimConnections,
  verifiedDomains,
}: {
  draft: MappingDraft;
  set: (change: Partial<MappingDraft>) => void;
  /** The organization's SCIM connections; undefined when they cannot be read (ids are typed instead). */
  scimConnections?: ScimConnectionOption[];
  /** The organization's verified email domains, when known. */
  verifiedDomains?: string[];
}) {
  const id = useId();
  // Typed ids when the connections cannot be listed; kept as typed so blank lines survive while editing.
  const [scimText, setScimText] = useState(draft.scimConnectionIds.join('\n'));
  const known = new Set((scimConnections ?? []).map((connection) => connection.id));
  const unknown = draft.scimConnectionIds.filter((connectionId) => !known.has(connectionId));
  return (
    <>
      <div className="field">
        <label htmlFor={`${id}-connections`}>
          Sign-in connections <span className="muted">(optional)</span>
        </label>
        <textarea
          id={`${id}-connections`}
          className="textarea"
          rows={2}
          value={draft.connectionIds}
          onChange={(event) => set({ connectionIds: event.target.value })}
          placeholder="okta-oidc"
        />
        <span className="help">
          Ids of the OAuth, OpenID Connect or SAML sign-in connections whose linked accounts use
          this issuer&apos;s subject ids: an <code>iss_sub</code> subject then matches the member
          linked to it. Up to 10, one per line.
        </span>
      </div>
      {scimConnections ? (
        <fieldset className="stack" style={{ border: 0, padding: 0, margin: 0, gap: 4 }}>
          <legend className="small muted" style={{ marginBottom: 6 }}>
            Directory sync connections: match <code>iss_sub</code> and <code>opaque</code> subjects
            to the SCIM <code>externalId</code> of the people they provisioned
          </legend>
          {scimConnections.length === 0 && unknown.length === 0 && (
            <span className="small muted">
              This organization has no directory sync connections.
            </span>
          )}
          {scimConnections.map((connection) => (
            <div key={connection.id} className="field inline">
              <input
                id={`${id}-scim-${connection.id}`}
                type="checkbox"
                checked={draft.scimConnectionIds.includes(connection.id)}
                onChange={(event) =>
                  set({
                    scimConnectionIds: toggle(
                      draft.scimConnectionIds,
                      connection.id,
                      event.target.checked,
                    ),
                  })
                }
              />
              <label htmlFor={`${id}-scim-${connection.id}`}>
                {connection.name}
                {connection.revoked && <span className="muted"> (revoked)</span>}
              </label>
            </div>
          ))}
          {unknown.map((connectionId) => (
            <div key={connectionId} className="field inline">
              <input
                id={`${id}-scim-${connectionId}`}
                type="checkbox"
                checked
                onChange={() =>
                  set({ scimConnectionIds: toggle(draft.scimConnectionIds, connectionId, false) })
                }
              />
              <label htmlFor={`${id}-scim-${connectionId}`}>
                <code>{connectionId}</code> <span className="muted">(no longer exists)</span>
              </label>
            </div>
          ))}
        </fieldset>
      ) : (
        <div className="field">
          <label htmlFor={`${id}-scim`}>
            Directory sync connection ids <span className="muted">(optional)</span>
          </label>
          <textarea
            id={`${id}-scim`}
            className="textarea"
            rows={2}
            value={scimText}
            onChange={(event) => {
              setScimText(event.target.value);
              set({ scimConnectionIds: splitEntries(event.target.value) });
            }}
          />
          <span className="help">
            SCIM connections whose provisioned people&apos;s <code>externalId</code> matches{' '}
            <code>iss_sub</code> and <code>opaque</code> subjects. Up to 10, one per line.
          </span>
        </div>
      )}
      <div className="field inline">
        <input
          id={`${id}-email`}
          type="checkbox"
          checked={draft.matchEmail}
          onChange={(event) => set({ matchEmail: event.target.checked })}
        />
        <label htmlFor={`${id}-email`}>Match email addresses at verified domains</label>
        <span className="help">
          <code>email</code> and <code>acct:</code> subjects match the member with that address,
          only at domains this organization verified.
        </span>
      </div>
      {draft.matchEmail && verifiedDomains && (
        <span className="small muted" style={{ marginLeft: 24 }}>
          {verifiedDomains.length
            ? `Verified: ${verifiedDomains.join(', ')}`
            : 'No domain is verified yet, so no email subject can match. Verify one on the Domains page.'}
        </span>
      )}
    </>
  );
}

/** Per event type: record only, or also end the matched person's sessions. */
function ActionFields({ actions, set }: { actions: Actions; set: (next: Actions) => void }) {
  const id = useId();
  return (
    <table className="table">
      <thead>
        <tr>
          <th>Event</th>
          <th>End sessions</th>
        </tr>
      </thead>
      <tbody>
        {actionableEventTypes.map((type) => (
          <tr key={type}>
            <td>
              <label htmlFor={`${id}-${type}`} className="stack" style={{ gap: 2 }}>
                <strong>{eventTypeLabels[type]}</strong>
                <span className="small muted">{actionableEventHelp[type]}</span>
              </label>
            </td>
            <td>
              <input
                id={`${id}-${type}`}
                type="checkbox"
                checked={actions[type] === 'revoke-sessions'}
                onChange={(event) =>
                  set({ ...actions, [type]: event.target.checked ? 'revoke-sessions' : 'record' })
                }
              />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

const actionsNote =
  'Every event is recorded and feeds threat detection. Ticked events also end the matched person’s sessions (API keys keep working, root administrators are protected); disabling or containing an account is left to threat detection playbooks.';

/**
 * Registers a transmitter: its settings, how its subjects map to members, and the action per event type. On success
 * it shows the push URL and, for a push source with a token, the bearer token, which is never shown again.
 */
export function CreateSourceForm({
  tenantId,
  base,
  scimConnections,
  verifiedDomains,
}: {
  tenantId: string;
  base: string;
  scimConnections?: ScimConnectionOption[];
  verifiedDomains?: string[];
}) {
  const { run, busy, feedback, fail } = useSignalCall(tenantId);
  const [draft, setDraft] = useState<SourceDraft>(() => sourceDraft());
  const [mapping, setMapping] = useState<MappingDraft>(() => mappingDraft());
  const [actions, setActions] = useState<Actions>({});
  const [created, setCreated] = useState<SignalSourceCreated | null>(null);
  // Remounts the mapping fields after a reset, so their typed-text state starts over too.
  const [generation, setGeneration] = useState(0);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    let body: ReturnType<typeof createSourceBody>;
    try {
      body = createSourceBody(tenantId, draft, mapping, actions);
    } catch (caught) {
      fail(describeError(caught).message);
      return;
    }
    setCreated(null);
    void run(
      () => iamClient().signals.createSource(body),
      (result) => {
        setCreated(result);
        setDraft(sourceDraft());
        setMapping(mappingDraft());
        setActions({});
        setGeneration((current) => current + 1);
      },
    );
  }

  return (
    <div className="stack">
      {created && (
        <div className="alert success stack">
          <strong>
            {created.source.name} is registered.{' '}
            <Link href={`${base}/signals/${created.source.id}`}>Open the source</Link>
          </strong>
          {created.pushUrl && (
            <>
              <span className="small">The transmitter pushes its events to:</span>
              <CopyValue value={created.pushUrl} />
            </>
          )}
          {created.pushToken && (
            <>
              <span className="small">
                with the header <code>Authorization: Bearer &lt;token&gt;</code>, using this token.
                It is shown only now; rotate it on the source page if it is lost.
              </span>
              <CopyValue value={created.pushToken} />
            </>
          )}
          {created.pushUrl && !created.source.audiences.includes(created.pushUrl) && (
            <span className="small">
              If the transmitter names the push URL as the audience of its events (a Better IAM
              transmitter does unless told otherwise), add it to the audiences on the source page.
            </span>
          )}
          {created.source.delivery === 'poll' && (
            <span className="small">
              Its events are fetched every minute; use Poll now on the source page to try it.
            </span>
          )}
        </div>
      )}
      <form className="form" onSubmit={submit}>
        <SourceFields draft={draft} set={(change) => setDraft({ ...draft, ...change })} />
        <h3 className="section-title">Who events are about</h3>
        <MappingFields
          key={generation}
          draft={mapping}
          set={(change) => setMapping({ ...mapping, ...change })}
          scimConnections={scimConnections}
          verifiedDomains={verifiedDomains}
        />
        <h3 className="section-title">Actions</h3>
        <p className="small muted" style={{ margin: 0 }}>
          {actionsNote}
        </p>
        <ActionFields actions={actions} set={setActions} />
        <div className="form-actions">
          <button className="btn" disabled={busy}>
            {busy ? 'Working…' : 'Add source'}
          </button>
        </div>
      </form>
      {feedback}
    </div>
  );
}

/** Edits a source's transmitter settings; only the fields that changed are sent. */
export function SourceSettingsForm({
  tenantId,
  source,
}: {
  tenantId: string;
  source: SignalSourceView;
}) {
  const { run, busy, feedback, fail } = useSignalCall(tenantId);
  const [draft, setDraft] = useState<SourceDraft>(() => sourceDraft(source));
  const [note, setNote] = useState<string | null>(null);
  // When the stored settings change (this form saved, normalized by the server, or someone else edited them), the
  // form shows them again; saves of the mapping or the actions leave an edit in progress here alone.
  const stored = JSON.stringify(sourceDraft(source));
  const [seen, setSeen] = useState(stored);
  if (seen !== stored) {
    setSeen(stored);
    setDraft(sourceDraft(source));
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setNote(null);
    let change: ReturnType<typeof sourceSettingsChange>;
    try {
      change = sourceSettingsChange(source, draft);
    } catch (caught) {
      fail(describeError(caught).message);
      return;
    }
    if (!Object.keys(change).length) {
      setNote('Nothing changed.');
      return;
    }
    void run(
      () => iamClient().signals.updateSource({ tenantId, sourceId: source.id, ...change }),
      () => {
        setNote('Saved. Cached keys were dropped; the next event fetches them again.');
        setDraft((current) => ({ ...current, pollToken: '' }));
      },
    );
  }

  return (
    <div className="stack">
      <form className="form" onSubmit={submit}>
        <SourceFields
          draft={draft}
          set={(change) => setDraft({ ...draft, ...change })}
          source={source}
        />
        <div className="form-actions">
          <button className="btn" disabled={busy}>
            {busy ? 'Working…' : 'Save settings'}
          </button>
        </div>
      </form>
      {feedback}
      {note && !busy && <div className="alert success">{note}</div>}
    </div>
  );
}

/** Edits how a source's subjects map to members. */
export function MappingForm({
  tenantId,
  source,
  scimConnections,
  verifiedDomains,
}: {
  tenantId: string;
  source: SignalSourceView;
  scimConnections?: ScimConnectionOption[];
  verifiedDomains?: string[];
}) {
  const { run, busy, feedback } = useSignalCall(tenantId);
  const [draft, setDraft] = useState<MappingDraft>(() => mappingDraft(source.subjects));
  const [note, setNote] = useState<string | null>(null);
  // Shows the stored mapping again when it changes (saved here, or by someone else).
  const stored = JSON.stringify(source.subjects);
  const [seen, setSeen] = useState(stored);
  if (seen !== stored) {
    setSeen(stored);
    setDraft(mappingDraft(source.subjects));
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setNote(null);
    const subjects = mappingChange(source, draft);
    if (!subjects) {
      setNote('Nothing changed.');
      return;
    }
    void run(
      () => iamClient().signals.updateSource({ tenantId, sourceId: source.id, subjects }),
      () => setNote('Saved. Reprocess unmatched events to map them again.'),
    );
  }

  return (
    <div className="stack">
      <form className="form" onSubmit={submit}>
        <MappingFields
          key={seen}
          draft={draft}
          set={(change) => setDraft({ ...draft, ...change })}
          scimConnections={scimConnections}
          verifiedDomains={verifiedDomains}
        />
        <div className="form-actions">
          <button className="btn" disabled={busy}>
            {busy ? 'Working…' : 'Save mapping'}
          </button>
        </div>
      </form>
      {feedback}
      {note && !busy && <div className="alert success">{note}</div>}
    </div>
  );
}

/** Edits the action per event type (the whole map is replaced). */
export function ActionsForm({ tenantId, source }: { tenantId: string; source: SignalSourceView }) {
  const { run, busy, feedback } = useSignalCall(tenantId);
  const [actions, setActions] = useState<Actions>(() => ({ ...source.actions }));
  const [note, setNote] = useState<string | null>(null);
  // Shows the stored actions again when they change (saved here, or by someone else).
  const stored = JSON.stringify(source.actions);
  const [seen, setSeen] = useState(stored);
  if (seen !== stored) {
    setSeen(stored);
    setActions({ ...source.actions });
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setNote(null);
    const change = actionsChange(source, actions);
    if (!change) {
      setNote('Nothing changed.');
      return;
    }
    void run(
      () => iamClient().signals.updateSource({ tenantId, sourceId: source.id, actions: change }),
      () => setNote('Saved. Events already received keep their outcome.'),
    );
  }

  return (
    <div className="stack">
      <form className="form" onSubmit={submit}>
        <p className="small muted" style={{ margin: 0 }}>
          {actionsNote}
        </p>
        <ActionFields actions={actions} set={setActions} />
        <div className="form-actions">
          <button className="btn" disabled={busy}>
            {busy ? 'Working…' : 'Save actions'}
          </button>
        </div>
      </form>
      {feedback}
      {note && !busy && <div className="alert success">{note}</div>}
    </div>
  );
}

/** Replaces a push source's bearer token and shows the new one once; the old one stops working at once. */
export function RotatePushToken({
  tenantId,
  sourceId,
  hasToken,
}: {
  tenantId: string;
  sourceId: string;
  hasToken: boolean;
}) {
  const { run, busy, feedback } = useSignalCall(tenantId);
  const [token, setToken] = useState<string | null>(null);
  return (
    <div className="stack">
      <div>
        <button
          type="button"
          className="btn small secondary"
          disabled={busy}
          onClick={() => {
            if (
              hasToken &&
              !window.confirm(
                'Replace the push token? The transmitter’s pushes are refused until it sends the new one.',
              )
            )
              return;
            setToken(null);
            void run(
              () => iamClient().signals.rotatePushToken({ tenantId, sourceId }),
              (result) => setToken(result.pushToken),
            );
          }}
        >
          {busy ? '…' : hasToken ? 'Rotate token' : 'Require a token'}
        </button>
      </div>
      {token && (
        <div className="alert warning stack">
          <span className="small">
            The new bearer token, shown only now. Give it to the transmitter as{' '}
            <code>Authorization: Bearer &lt;token&gt;</code>.
          </span>
          <CopyValue value={token} />
        </div>
      )}
      {feedback}
    </div>
  );
}

/** Polls a poll source now instead of waiting for the scheduled job. */
export function PollNow({ tenantId, sourceId }: { tenantId: string; sourceId: string }) {
  const { run, busy, feedback } = useSignalCall(tenantId);
  const [outcome, setOutcome] = useState<SignalPollResult | null>(null);
  return (
    <span className="row" style={{ display: 'inline-flex', flexWrap: 'wrap' }}>
      {outcome && <span className="small muted">{pollSummary(outcome)}.</span>}
      <button
        type="button"
        className="btn small secondary"
        disabled={busy}
        onClick={() => {
          setOutcome(null);
          void run(() => iamClient().signals.poll({ tenantId, sourceId }), setOutcome);
        }}
      >
        {busy ? 'Polling…' : 'Poll now'}
      </button>
      {feedback}
    </span>
  );
}
