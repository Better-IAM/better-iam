'use client';
import { useRouter } from 'next/navigation';
import { useId, useState, type FormEvent, type ReactNode } from 'react';
import type {
  ResponseActionKind,
  ThreatDetectionRun,
  ThreatPlaybook,
  ThreatResponse,
  ThreatRuleView,
  ThreatSettingsView,
} from 'better-iam/server';
import { describeError, iamClient } from '@/lib/client';
import {
  durationLabel,
  playbookBody,
  playbookDraft,
  responseActions,
  responseHelp,
  responseKinds,
  responseLabels,
  ruleDraft,
  ruleDraftChanged,
  ruleSettingChange,
  severities,
  skipReason,
  splitList,
  subjectTypeLabels,
  subjectTypes,
  type PlaybookDraft,
  type RuleDraft,
} from '@/lib/threats';
import { Reauth } from './api-form';

type Failure = { code: string; message: string };

/**
 * Runs one threats API call for a form: tracks progress, shows the error, asks for the password (and second factor)
 * again when the operation needs recent authentication and then retries, and refreshes the server-rendered page.
 */
function useThreatCall(tenantId: string) {
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
  return { run, busy, feedback, hasFeedback: error !== null || retry !== null };
}

function toggle<T>(list: readonly T[], item: T, on: boolean): T[] {
  return on
    ? list.includes(item)
      ? [...list]
      : [...list, item]
    : list.filter((entry) => entry !== item);
}

function scanSummary(run: ThreatDetectionRun): string {
  const parts = [
    `${run.detections} new detection${run.detections === 1 ? '' : 's'}`,
    `${run.incidentsOpened} incident${run.incidentsOpened === 1 ? '' : 's'} opened`,
    ...(run.responses
      ? [`${run.responses} automatic response${run.responses === 1 ? '' : 's'}`]
      : []),
  ];
  return [
    `Read ${run.eventsScanned} event${run.eventsScanned === 1 ? '' : 's'}: ${parts.join(', ')}.`,
    ...(run.chainBreaks ? ['The audit chain failed verification.'] : []),
    ...(run.pending ? ['More events are waiting; scan again.'] : []),
  ].join(' ');
}

/** Runs detection for the organization now instead of waiting for the scheduled job. */
export function ScanNow({ tenantId }: { tenantId: string }) {
  const { run, busy, feedback } = useThreatCall(tenantId);
  const [outcome, setOutcome] = useState<ThreatDetectionRun | null>(null);
  return (
    <span className="row" style={{ display: 'inline-flex', flexWrap: 'wrap' }}>
      {outcome && <span className="small muted">{scanSummary(outcome)}</span>}
      <button
        type="button"
        className="btn small"
        disabled={busy}
        onClick={() => void run(() => iamClient().threats.detect({ tenantId }), setOutcome)}
      >
        {busy ? 'Scanning…' : 'Scan now'}
      </button>
      {feedback}
    </span>
  );
}

function ActionChoices({
  kinds,
  chosen,
  onChange,
  blockHours,
  onBlockHours,
  keepApiKeys,
  onKeepApiKeys,
}: {
  kinds: readonly ResponseActionKind[];
  chosen: ResponseActionKind[];
  onChange: (next: ResponseActionKind[]) => void;
  blockHours: string;
  onBlockHours: (value: string) => void;
  keepApiKeys: boolean;
  onKeepApiKeys: (value: boolean) => void;
}) {
  const id = useId();
  return (
    <fieldset className="stack" style={{ border: 0, padding: 0, margin: 0, gap: 6 }}>
      <legend className="small muted" style={{ marginBottom: 6 }}>
        Actions, run in this order
      </legend>
      {kinds.map((kind) => (
        <div key={kind} className="stack" style={{ gap: 2 }}>
          <div className="field inline">
            <input
              id={`${id}-${kind}`}
              type="checkbox"
              checked={chosen.includes(kind)}
              onChange={(event) => onChange(toggle(chosen, kind, event.target.checked))}
            />
            <label htmlFor={`${id}-${kind}`}>{responseLabels[kind]}</label>
            <span className="help">{responseHelp[kind]}</span>
          </div>
          {kind === 'revoke-sessions' && chosen.includes(kind) && (
            <div className="field inline" style={{ marginLeft: 24 }}>
              <input
                id={`${id}-keep`}
                type="checkbox"
                checked={keepApiKeys}
                onChange={(event) => onKeepApiKeys(event.target.checked)}
              />
              <label htmlFor={`${id}-keep`}>Keep API keys working</label>
            </div>
          )}
          {kind === 'block-network' && chosen.includes(kind) && (
            <div className="row" style={{ marginLeft: 24 }}>
              <label className="small" htmlFor={`${id}-hours`}>
                Block for (hours)
              </label>
              <input
                id={`${id}-hours`}
                className="input"
                type="number"
                min={0.1}
                max={720}
                step="any"
                value={blockHours}
                onChange={(event) => onBlockHours(event.target.value)}
                style={{ width: 90 }}
              />
            </div>
          )}
        </div>
      ))}
    </fieldset>
  );
}

/**
 * Responds by hand to an incident (its subject), an identity, or a network: the ticked actions run in order, and what
 * each one did (or why it was skipped) is shown underneath.
 */
export function RespondForm({
  tenantId,
  target,
  kinds,
  confirmContain,
}: {
  tenantId: string;
  target: { incidentId: string } | { identityId: string } | { network: string };
  /** The actions that apply to the target. */
  kinds: readonly ResponseActionKind[];
  /** Asked before a response that contains the identity. */
  confirmContain?: string;
}) {
  const id = useId();
  const { run, busy, feedback } = useThreatCall(tenantId);
  const [chosen, setChosen] = useState<ResponseActionKind[]>([]);
  const [blockHours, setBlockHours] = useState('24');
  const [keepApiKeys, setKeepApiKeys] = useState(true);
  const [reason, setReason] = useState('');
  const [taken, setTaken] = useState<ThreatResponse[] | null>(null);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const hours = Number(blockHours);
    const actions = responseActions(chosen, {
      ...(Number.isFinite(hours) && hours > 0 ? { blockHours: hours } : {}),
      keepApiKeys,
    });
    if (!actions.length) return;
    if (chosen.includes('contain') && confirmContain && !window.confirm(confirmContain)) return;
    void run(
      () => iamClient().threats.respond({ tenantId, ...target, actions, reason }),
      (responses) => {
        setTaken(responses);
        setChosen([]);
        setReason('');
      },
    );
  }

  return (
    <div className="stack">
      <form className="form" onSubmit={submit}>
        <ActionChoices
          kinds={kinds}
          chosen={chosen}
          onChange={setChosen}
          blockHours={blockHours}
          onBlockHours={setBlockHours}
          keepApiKeys={keepApiKeys}
          onKeepApiKeys={setKeepApiKeys}
        />
        <div className="field">
          <label htmlFor={`${id}-reason`}>Reason</label>
          <input
            id={`${id}-reason`}
            className="input"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="Confirmed with the account holder: not them"
            maxLength={512}
            required
          />
        </div>
        <div className="form-actions">
          <button className="btn danger" disabled={busy || chosen.length === 0}>
            {busy ? 'Working…' : 'Respond'}
          </button>
        </div>
      </form>
      {feedback}
      {taken && (
        <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
          {taken.map((response) => (
            <li key={response.id}>
              <strong>{responseLabels[response.action]}</strong>:{' '}
              {response.outcome === 'applied' ? 'done' : `skipped (${skipReason(response.reason)})`}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function RuleRow({
  rule,
  draft,
  onDraft,
  onSave,
  onReset,
  busy,
}: {
  rule: ThreatRuleView;
  draft: RuleDraft;
  onDraft: (draft: RuleDraft) => void;
  onSave: () => void;
  onReset: () => void;
  busy: boolean;
}) {
  const id = useId();
  const dirty = ruleDraftChanged(rule, draft);
  const threshold = rule.tunable?.threshold;
  const windowBounds = rule.tunable?.windowMs;
  return (
    <tr>
      <td>
        <span className="stack" style={{ gap: 2 }}>
          <strong>{rule.title}</strong>
          <span className="small muted">{rule.description}</span>
          <span className="small muted">
            {rule.category} · about {subjectTypeLabels[rule.subject].toLowerCase()} ·{' '}
            <code>{rule.technique}</code>
            {rule.customized && ' · customized'}
          </span>
          {rule.id === 'new-network' && (
            <span className="field inline">
              <input
                id={`${id}-everyone`}
                type="checkbox"
                checked={draft.everyone}
                onChange={(event) => onDraft({ ...draft, everyone: event.target.checked })}
              />
              <label htmlFor={`${id}-everyone`} className="small">
                Report everyone (people without administrator access at low severity)
              </label>
            </span>
          )}
        </span>
      </td>
      <td>
        <input
          type="checkbox"
          aria-label={`${rule.title} enabled`}
          checked={draft.enabled}
          onChange={(event) => onDraft({ ...draft, enabled: event.target.checked })}
        />
      </td>
      <td>
        <select
          className="select"
          aria-label={`${rule.title} severity`}
          value={draft.severity}
          onChange={(event) =>
            onDraft({ ...draft, severity: event.target.value as RuleDraft['severity'] })
          }
        >
          {severities.map((severity) => (
            <option key={severity} value={severity}>
              {severity}
            </option>
          ))}
        </select>
      </td>
      <td>
        {threshold ? (
          <input
            className="input"
            type="number"
            aria-label={`${rule.title} threshold`}
            min={threshold[0]}
            max={threshold[1]}
            step={1}
            value={draft.threshold}
            placeholder={String(rule.defaults.threshold ?? '')}
            onChange={(event) => onDraft({ ...draft, threshold: event.target.value })}
            style={{ width: 90 }}
          />
        ) : (
          <span className="muted">—</span>
        )}
      </td>
      <td>
        {windowBounds ? (
          <span className="stack" style={{ gap: 2 }}>
            <input
              className="input"
              type="number"
              aria-label={`${rule.title} window in minutes`}
              min={windowBounds[0] / 60_000}
              max={windowBounds[1] / 60_000}
              step={1}
              value={draft.windowMinutes}
              placeholder={
                rule.defaults.windowMs === undefined ? '' : String(rule.defaults.windowMs / 60_000)
              }
              onChange={(event) => onDraft({ ...draft, windowMinutes: event.target.value })}
              style={{ width: 90 }}
            />
            {rule.windowMs !== undefined && (
              <span className="small muted">{durationLabel(rule.windowMs)}</span>
            )}
          </span>
        ) : (
          <span className="muted">—</span>
        )}
      </td>
      <td>
        <span className="row" style={{ display: 'inline-flex' }}>
          <button type="button" className="btn small" disabled={busy || !dirty} onClick={onSave}>
            Save
          </button>
          {rule.customized && (
            <button type="button" className="btn small secondary" disabled={busy} onClick={onReset}>
              Defaults
            </button>
          )}
        </span>
      </td>
    </tr>
  );
}

/**
 * The detection rules with their settings in force, editable in place: on/off, severity, and (where the rule counts)
 * the threshold and the window in minutes. Each row saves on its own; "Defaults" drops the organization's changes.
 */
export function RulesTable({ tenantId, rules }: { tenantId: string; rules: ThreatRuleView[] }) {
  const { run, busy, feedback, hasFeedback } = useThreatCall(tenantId);
  // Only rows being edited hold a draft, so a refresh after one row's save leaves the other edits alone. A saved row
  // keeps its draft (it now matches the refreshed setting); going back to the defaults drops it.
  const [drafts, setDrafts] = useState<Record<string, RuleDraft>>({});
  const settle = (ruleId: string) =>
    setDrafts((current) => {
      const { [ruleId]: _saved, ...rest } = current;
      return rest;
    });
  const disables = (rule: ThreatRuleView, draft: RuleDraft) => rule.enabled && !draft.enabled;
  const warning =
    'Turning a rule off records a "Security settings weakened" detection against you, so other administrators see it. Continue?';
  return (
    <div className="stack">
      {/* The table sits flush in its card; messages keep the card's padding. */}
      {hasFeedback && <div style={{ padding: '12px 16px 0' }}>{feedback}</div>}
      <table className="table">
        <thead>
          <tr>
            <th>Rule</th>
            <th>On</th>
            <th>Severity</th>
            <th>Threshold</th>
            <th>Window (min)</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {rules.map((rule) => {
            const draft = drafts[rule.id] ?? ruleDraft(rule);
            return (
              <RuleRow
                key={rule.id}
                rule={rule}
                draft={draft}
                busy={busy}
                onDraft={(next) => setDrafts((current) => ({ ...current, [rule.id]: next }))}
                onSave={() => {
                  if (disables(rule, draft) && !window.confirm(warning)) return;
                  void run(() =>
                    iamClient().threats.configure({
                      tenantId,
                      rules: { [rule.id]: ruleSettingChange(rule, draft) },
                    }),
                  );
                }}
                onReset={() => {
                  if (rule.enabled && !rule.defaults.enabled && !window.confirm(warning)) return;
                  void run(
                    () => iamClient().threats.configure({ tenantId, rules: { [rule.id]: null } }),
                    () => settle(rule.id),
                  );
                }}
              />
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/**
 * The organization-wide detection settings: trusted networks, the dormancy period, the risk half-life, who the
 * `notify` response emails, and the automatic containment brake. Lists are typed one per line (or comma-separated)
 * and replace the stored ones, so emptying a list clears it.
 */
export function DetectionSettingsForm({
  tenantId,
  settings,
}: {
  tenantId: string;
  settings: ThreatSettingsView;
}) {
  const id = useId();
  const { run, busy, feedback } = useThreatCall(tenantId);
  const [networks, setNetworks] = useState(settings.trustedNetworks.join('\n'));
  const [dormantDays, setDormantDays] = useState(String(settings.dormantDays));
  const [halfLife, setHalfLife] = useState(String(settings.riskHalfLifeHours));
  const [owners, setOwners] = useState(settings.notify.owners);
  const [emails, setEmails] = useState(settings.notify.emails.join('\n'));
  const [brake, setBrake] = useState(String(settings.maxAutomaticContainments));
  const [saved, setSaved] = useState(false);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaved(false);
    void run(
      () =>
        iamClient().threats.configure({
          tenantId,
          trustedNetworks: splitList(networks),
          dormantDays: Number(dormantDays),
          riskHalfLifeHours: Number(halfLife),
          notify: { owners, emails: splitList(emails) },
          maxAutomaticContainments: Number(brake),
        }),
      () => setSaved(true),
    );
  }

  return (
    <div className="stack">
      <form className="form" onSubmit={submit}>
        <div className="field">
          <label htmlFor={`${id}-networks`}>
            Trusted networks <span className="muted">(optional)</span>
          </label>
          <textarea
            id={`${id}-networks`}
            className="textarea"
            rows={3}
            value={networks}
            onChange={(event) => setNetworks(event.target.value)}
            placeholder={'203.0.113.0/24\n2001:db8::/48'}
          />
          <span className="help">
            Offices and VPN egress, one per line (up to 50; no wider than /8, or /32 for IPv6).
            Network rules never report them and responses never block them.
          </span>
        </div>
        <div className="grid cols-3">
          <div className="field">
            <label htmlFor={`${id}-dormant`}>Dormant after (days)</label>
            <input
              id={`${id}-dormant`}
              className="input"
              type="number"
              min={7}
              max={3650}
              step={1}
              required
              value={dormantDays}
              onChange={(event) => setDormantDays(event.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor={`${id}-half-life`}>Risk half-life (hours)</label>
            <input
              id={`${id}-half-life`}
              className="input"
              type="number"
              min={1}
              max={720}
              step={1}
              required
              value={halfLife}
              onChange={(event) => setHalfLife(event.target.value)}
            />
          </div>
          <div className="field">
            <label htmlFor={`${id}-brake`}>Automatic containments per run</label>
            <input
              id={`${id}-brake`}
              className="input"
              type="number"
              min={0}
              max={100}
              step={1}
              required
              value={brake}
              onChange={(event) => setBrake(event.target.value)}
            />
          </div>
        </div>
        <div className="field inline">
          <input
            id={`${id}-owners`}
            type="checkbox"
            checked={owners}
            onChange={(event) => setOwners(event.target.checked)}
          />
          <label htmlFor={`${id}-owners`}>Email the organization&apos;s owners</label>
          <span className="help">Active owners with a verified email address.</span>
        </div>
        <div className="field">
          <label htmlFor={`${id}-emails`}>
            Also email <span className="muted">(optional)</span>
          </label>
          <textarea
            id={`${id}-emails`}
            className="textarea"
            rows={2}
            value={emails}
            onChange={(event) => setEmails(event.target.value)}
            placeholder="security@example.com"
          />
          <span className="help">
            Up to 20 addresses, one per line. Emails go out only when a playbook or a person runs
            the Notify response.
          </span>
        </div>
        <div className="form-actions">
          <button className="btn" disabled={busy}>
            {busy ? 'Working…' : 'Save settings'}
          </button>
        </div>
      </form>
      {feedback}
      {saved && !busy && <div className="alert success">Saved.</div>}
    </div>
  );
}

/**
 * Creates a playbook, or edits one: the trigger (rules, minimum severity, subject types; left empty it matches every
 * new detection) and the actions that run automatically under the threat-detection actor.
 */
export function PlaybookForm({
  tenantId,
  rules,
  playbook,
}: {
  tenantId: string;
  rules: { id: string; title: string }[];
  playbook?: ThreatPlaybook;
}) {
  const id = useId();
  const { run, busy, feedback } = useThreatCall(tenantId);
  const [draft, setDraft] = useState<PlaybookDraft>(() => playbookDraft(playbook));
  const [saved, setSaved] = useState(false);
  const set = (change: Partial<PlaybookDraft>) =>
    setDraft((current) => ({ ...current, ...change }));

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSaved(false);
    const body = playbookBody(draft, playbook !== undefined);
    const { description, ...rest } = body;
    void run(
      () =>
        playbook
          ? iamClient().threats.updatePlaybook({ tenantId, playbookId: playbook.id, ...body })
          : iamClient().threats.createPlaybook({
              tenantId,
              ...rest,
              ...(description ? { description } : {}),
            }),
      () => {
        setSaved(true);
        if (!playbook) setDraft(playbookDraft());
      },
    );
  }

  return (
    <div className="stack">
      <form className="form" onSubmit={submit}>
        <div className="grid cols-2">
          <div className="field">
            <label htmlFor={`${id}-name`}>Name</label>
            <input
              id={`${id}-name`}
              className="input"
              value={draft.name}
              onChange={(event) => set({ name: event.target.value })}
              maxLength={100}
              placeholder="Contain on password spray success"
              required
            />
          </div>
          <div className="field">
            <label htmlFor={`${id}-description`}>
              Description <span className="muted">(optional)</span>
            </label>
            <input
              id={`${id}-description`}
              className="input"
              value={draft.description}
              onChange={(event) => set({ description: event.target.value })}
              maxLength={512}
            />
          </div>
        </div>
        <div className="grid cols-3">
          <div className="field">
            <label htmlFor={`${id}-rules`}>
              Rules <span className="muted">(none selected: any rule)</span>
            </label>
            <select
              id={`${id}-rules`}
              className="select"
              multiple
              size={6}
              value={draft.ruleIds}
              onChange={(event) =>
                set({
                  ruleIds: [...event.target.selectedOptions].map((option) => option.value),
                })
              }
            >
              {rules.map((rule) => (
                <option key={rule.id} value={rule.id}>
                  {rule.title}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor={`${id}-severity`}>Minimum severity</label>
            <select
              id={`${id}-severity`}
              className="select"
              value={draft.minSeverity}
              onChange={(event) => set({ minSeverity: event.target.value })}
            >
              <option value="">any</option>
              {severities.map((severity) => (
                <option key={severity} value={severity}>
                  {severity}
                </option>
              ))}
            </select>
          </div>
          <fieldset className="stack" style={{ border: 0, padding: 0, margin: 0, gap: 4 }}>
            <legend className="small muted" style={{ marginBottom: 6 }}>
              About (none ticked: anything)
            </legend>
            {subjectTypes.map((type) => (
              <div key={type} className="field inline">
                <input
                  id={`${id}-subject-${type}`}
                  type="checkbox"
                  checked={draft.subjectTypes.includes(type)}
                  onChange={(event) =>
                    set({ subjectTypes: toggle(draft.subjectTypes, type, event.target.checked) })
                  }
                />
                <label htmlFor={`${id}-subject-${type}`}>{subjectTypeLabels[type]}</label>
              </div>
            ))}
          </fieldset>
        </div>
        <ActionChoices
          kinds={responseKinds}
          chosen={draft.actions}
          onChange={(actions) => set({ actions })}
          blockHours={draft.blockHours}
          onBlockHours={(blockHours) => set({ blockHours })}
          keepApiKeys={draft.keepApiKeys}
          onKeepApiKeys={(keepApiKeys) => set({ keepApiKeys })}
        />
        {/* An existing playbook is switched on and off from the list. */}
        {!playbook && (
          <div className="field inline">
            <input
              id={`${id}-enabled`}
              type="checkbox"
              checked={draft.enabled}
              onChange={(event) => set({ enabled: event.target.checked })}
            />
            <label htmlFor={`${id}-enabled`}>Enabled</label>
          </div>
        )}
        <div className="form-actions">
          <button className="btn" disabled={busy || draft.actions.length === 0}>
            {busy ? 'Working…' : playbook ? 'Save playbook' : 'Create playbook'}
          </button>
        </div>
      </form>
      {feedback}
      {saved && !busy && (
        <div className="alert success">{playbook ? 'Saved.' : 'Playbook created.'}</div>
      )}
    </div>
  );
}
