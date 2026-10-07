'use client';
import { useRouter } from 'next/navigation';
import { useEffect, useId, useState, type FormEvent, type ReactNode } from 'react';
import type {
  ClassificationLabel,
  ClassificationSchemeDefinition,
  ClassificationSchemeView,
  ClearanceExplanation,
  ClearanceView,
} from 'better-iam/server';
import { describeError, iamClient } from '@/lib/client';
import {
  adjudicationHelp,
  adjudicationLabels,
  compartmentName,
  effectiveStatusLabels,
  emptyClearanceDraft,
  failureLabels,
  grantBody,
  labelDraft,
  labelFromDraft,
  labelMarking,
  levelName,
  levelOptions,
  levelsByRank,
  parseDefinition,
  schemeSettingsChange,
  schemeSettingsDraft,
  statusTone,
  updateChange,
  updateDraft,
  withCompartment,
  withTopLevel,
  type ClearanceDraft,
  type ClearanceUpdateDraft,
  type LabelDraft,
  type Releasability,
  type SchemeChange,
  type SchemeSettingsDraft,
} from '@/lib/clearances';
import { Reauth } from './api-form';

type Failure = { code: string; message: string };
type Option = { value: string; label: string };
type Caveat = 'NOFORN' | 'RELTO';

/**
 * Runs one clearances API call for a form: tracks progress, shows the error, asks for the password (and second factor)
 * again when the operation needs a recent sign-in and then retries, and refreshes the server-rendered page.
 */
function useClearanceCall(tenantId: string) {
  const router = useRouter();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<Failure | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [retry, setRetry] = useState<{ again: () => Promise<void> } | null>(null);

  async function run<T>(call: () => Promise<T>, done?: (result: T) => void): Promise<void> {
    setBusy(true);
    setError(null);
    setNotice(null);
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

  /** Builds the request first; a draft the form can tell is wrong is shown without calling the server. */
  function submit<B, T>(build: () => B, call: (body: B) => Promise<T>, done?: (result: T) => void) {
    let body: B;
    try {
      body = build();
    } catch (caught) {
      setNotice(null);
      setError({ code: 'INVALID_INPUT', message: describeError(caught).message });
      return;
    }
    void run(() => call(body), done);
  }

  const feedback: ReactNode = (
    <>
      {error && (
        <div className="alert danger">
          <strong>{error.code}</strong> — {error.message}
        </div>
      )}
      {notice && !error && <div className="alert success">{notice}</div>}
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
  return { run, submit, busy, feedback, setNotice, setError };
}

function Field({
  id,
  label,
  optional,
  help,
  children,
}: {
  id: string;
  label: ReactNode;
  optional?: boolean;
  help?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="field">
      <label htmlFor={id}>
        {label}
        {optional && <span className="muted"> (optional)</span>}
      </label>
      {children}
      {help && <span className="help">{help}</span>}
    </div>
  );
}

function LevelSelect({
  id,
  value,
  onChange,
  levels,
  required = true,
  emptyLabel = 'Choose a level',
}: {
  id: string;
  value: string;
  onChange: (value: string) => void;
  levels?: Option[];
  required?: boolean;
  emptyLabel?: string;
}) {
  if (!levels)
    return (
      <input
        id={id}
        className="input"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder="level id, such as S"
        required={required}
        spellCheck={false}
      />
    );
  return (
    <select
      id={id}
      className="select"
      value={value}
      onChange={(event) => onChange(event.target.value)}
      required={required}
    >
      <option value="">{emptyLabel}</option>
      {levels.map((level) => (
        <option key={level.value} value={level.value}>
          {level.label}
        </option>
      ))}
    </select>
  );
}

/**
 * The parts of a classification label: level, compartments, NOFORN, and REL TO. Without the scheme (no
 * iam:clearances:read) levels and compartments are typed as ids, and both caveats are offered; the server validates.
 */
function LabelFields({
  draft,
  onChange,
  levels,
  compartments,
  caveats,
}: {
  draft: LabelDraft;
  onChange: (draft: LabelDraft) => void;
  levels?: Option[];
  compartments?: Option[];
  caveats?: Caveat[];
}) {
  const id = useId();
  const set = (change: Partial<LabelDraft>) => onChange({ ...draft, ...change });
  const nofornOffered = !caveats || caveats.includes('NOFORN');
  const reltoOffered = !caveats || caveats.includes('RELTO');
  return (
    <>
      <Field id={`${id}-level`} label="Level">
        <LevelSelect
          id={`${id}-level`}
          value={draft.level}
          onChange={(level) => set({ level })}
          levels={levels}
        />
      </Field>
      {compartments ? (
        compartments.length > 0 && (
          <fieldset className="field">
            <legend className="small">
              Compartments <span className="muted">(readers must be read into every one)</span>
            </legend>
            <div className="row" style={{ flexWrap: 'wrap' }}>
              {compartments.map((compartment) => (
                <label key={compartment.value} className="field inline">
                  <input
                    type="checkbox"
                    checked={draft.compartments.includes(compartment.value)}
                    onChange={(event) =>
                      set({
                        compartments: event.target.checked
                          ? [...draft.compartments, compartment.value]
                          : draft.compartments.filter((item) => item !== compartment.value),
                      })
                    }
                  />
                  {compartment.label}
                </label>
              ))}
            </div>
          </fieldset>
        )
      ) : (
        <Field
          id={`${id}-compartments`}
          label="Compartment ids"
          optional
          help="Comma-separated; readers must be read into every one."
        >
          <input
            id={`${id}-compartments`}
            className="input"
            value={draft.compartments.join(', ')}
            onChange={(event) =>
              set({
                compartments: event.target.value
                  .split(',')
                  .map((item) => item.trim())
                  .filter(Boolean),
              })
            }
            spellCheck={false}
          />
        </Field>
      )}
      {nofornOffered && (
        <div className="field inline">
          <input
            id={`${id}-noforn`}
            type="checkbox"
            checked={draft.noforn}
            onChange={(event) => set({ noforn: event.target.checked })}
          />
          <label htmlFor={`${id}-noforn`}>NOFORN: citizens of the owner countries only</label>
        </div>
      )}
      {reltoOffered && !draft.noforn && (
        <div className="grid cols-2">
          <Field id={`${id}-release`} label="Releasability">
            <select
              id={`${id}-release`}
              className="select"
              value={draft.release}
              onChange={(event) => set({ release: event.target.value as Releasability })}
            >
              <option value="unrestricted">No REL TO restriction</option>
              <option value="owners">Owner countries only (REL TO with no country)</option>
              <option value="listed">REL TO the owner countries and…</option>
            </select>
          </Field>
          {draft.release === 'listed' && (
            <Field id={`${id}-relto`} label="Releasable to" help="Alpha-3 codes, such as GBR, CAN.">
              <input
                id={`${id}-relto`}
                className="input"
                value={draft.releasableTo}
                onChange={(event) => set({ releasableTo: event.target.value })}
                placeholder="GBR, CAN, AUS"
                required
                spellCheck={false}
              />
            </Field>
          )}
        </div>
      )}
    </>
  );
}

const compartmentOptions = (definition: ClassificationSchemeDefinition | undefined) =>
  definition?.compartments.map((compartment) => ({
    value: compartment.id,
    label: compartment.name,
  }));

/** The date, investigation and citizenship fields the grant and update forms share. */
function ClearanceFields({
  draft,
  set,
  levels,
}: {
  draft: ClearanceDraft;
  set: (change: Partial<ClearanceDraft>) => void;
  levels: Option[];
}) {
  const id = useId();
  return (
    <>
      <div className="grid cols-2">
        <Field id={`${id}-level`} label="Level">
          <LevelSelect
            id={`${id}-level`}
            value={draft.level}
            onChange={(level) => set({ level })}
            levels={levels}
          />
        </Field>
        <Field
          id={`${id}-citizenship`}
          label="Adjudicated citizenship"
          help="Alpha-3 codes (USA, GBR). NOFORN and REL TO decisions read only this, never profile attributes; empty means no citizenship counts."
        >
          <input
            id={`${id}-citizenship`}
            className="input"
            value={draft.citizenship}
            onChange={(event) => set({ citizenship: event.target.value })}
            placeholder="USA"
            spellCheck={false}
          />
        </Field>
      </div>
      <div className="grid cols-2">
        <Field id={`${id}-kind`} label="Investigation" optional>
          <input
            id={`${id}-kind`}
            className="input"
            value={draft.investigationKind}
            onChange={(event) => set({ investigationKind: event.target.value })}
            placeholder="Tier 5 (SSBI)"
          />
        </Field>
        <Field id={`${id}-completed`} label="Investigation completed" optional>
          <input
            id={`${id}-completed`}
            className="input"
            type="date"
            value={draft.investigationCompletedOn}
            onChange={(event) => set({ investigationCompletedOn: event.target.value })}
          />
        </Field>
      </div>
      <div className="grid cols-2">
        <Field
          id={`${id}-due`}
          label="Reinvestigation due"
          optional
          help="Officers are emailed as it nears; it does not end the clearance."
        >
          <input
            id={`${id}-due`}
            className="input"
            type="date"
            value={draft.reinvestigationDueOn}
            onChange={(event) => set({ reinvestigationDueOn: event.target.value })}
          />
        </Field>
        <Field
          id={`${id}-ends`}
          label="Ends"
          optional
          help="From this moment decisions stop counting the clearance."
        >
          <input
            id={`${id}-ends`}
            className="input"
            type="datetime-local"
            value={draft.expiresAt}
            onChange={(event) => set({ expiresAt: event.target.value })}
          />
        </Field>
      </div>
    </>
  );
}

/**
 * Grants a clearance (iam:clearances:adjudicate and a recent sign-in). With `people` the officer first picks the
 * person; the page then opens that person's clearance under `openBase`.
 */
export function GrantClearanceForm({
  tenantId,
  identityId,
  people,
  levels,
  interimAllowed,
  openBase,
}: {
  tenantId: string;
  identityId?: string;
  people?: Option[];
  levels: Option[];
  interimAllowed: boolean;
  openBase?: string;
}) {
  const id = useId();
  const router = useRouter();
  const { submit, busy, feedback } = useClearanceCall(tenantId);
  const [person, setPerson] = useState(identityId ?? '');
  const [draft, setDraft] = useState<ClearanceDraft>(() => emptyClearanceDraft());
  const set = (change: Partial<ClearanceDraft>) =>
    setDraft((current) => ({ ...current, ...change }));

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    submit(
      () => {
        if (!person) throw new Error('Choose the person');
        return grantBody(tenantId, person, draft);
      },
      (body) => iamClient().clearances.grant(body),
      (view) => {
        setDraft(emptyClearanceDraft());
        if (openBase) router.push(`${openBase}/${encodeURIComponent(view.identityId)}`);
      },
    );
  }

  return (
    <form className="form" onSubmit={onSubmit}>
      {people && (
        <Field id={`${id}-person`} label="Person">
          <select
            id={`${id}-person`}
            className="select"
            value={person}
            onChange={(event) => setPerson(event.target.value)}
            required
          >
            <option value="">Choose a person</option>
            {people.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </Field>
      )}
      <ClearanceFields draft={draft} set={set} levels={levels} />
      {interimAllowed && (
        <div className="field inline">
          <input
            id={`${id}-interim`}
            type="checkbox"
            checked={draft.interim}
            onChange={(event) => set({ interim: event.target.checked })}
          />
          <label htmlFor={`${id}-interim`}>Interim, while the investigation completes</label>
        </div>
      )}
      {feedback}
      <div className="form-actions">
        <button className="btn" disabled={busy}>
          {busy ? 'Working…' : 'Grant clearance'}
        </button>
      </div>
    </form>
  );
}

/**
 * Changes a live clearance (iam:clearances:adjudicate and a recent sign-in): only the fields that differ are sent. The
 * draft is filled after mount, so the dates show in the browser's time zone.
 */
export function UpdateClearanceForm({
  tenantId,
  view,
  levels,
  interimAllowed,
}: {
  tenantId: string;
  view: ClearanceView;
  levels: Option[];
  interimAllowed: boolean;
}) {
  const id = useId();
  const { submit, busy, feedback, setNotice } = useClearanceCall(tenantId);
  const [draft, setDraft] = useState<ClearanceUpdateDraft | null>(null);
  useEffect(() => setDraft(updateDraft(view)), [view]);
  if (!draft) return <p className="small muted">Loading…</p>;
  const set = (change: Partial<ClearanceUpdateDraft>) =>
    setDraft((current) => (current ? { ...current, ...change } : current));

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!draft) return;
    let empty = false;
    submit(
      () => {
        const change = updateChange(view, draft);
        empty = Object.keys(change).length === 0;
        return { tenantId, identityId: view.identityId, ...change };
      },
      (body) => (empty ? Promise.resolve(view) : iamClient().clearances.update(body)),
      () => setNotice(empty ? 'Nothing changed.' : 'Saved.'),
    );
  }

  return (
    <form className="form" onSubmit={onSubmit}>
      <ClearanceFields draft={draft} set={set} levels={levels} />
      <Field
        id={`${id}-term`}
        label="Interim or final"
        help={
          view.status === 'suspended'
            ? 'Applies when the clearance is reinstated.'
            : interimAllowed
              ? undefined
              : 'This scheme does not count interim clearances.'
        }
      >
        <select
          id={`${id}-term`}
          className="select"
          value={draft.term}
          onChange={(event) => set({ term: event.target.value as ClearanceUpdateDraft['term'] })}
        >
          <option value="keep">Keep as it is</option>
          <option value="final">Final</option>
          {interimAllowed && <option value="interim">Interim</option>}
        </select>
      </Field>
      {feedback}
      <div className="form-actions">
        <button className="btn small" disabled={busy}>
          {busy ? 'Working…' : 'Save changes'}
        </button>
      </div>
    </form>
  );
}

/**
 * Labels a resource (iam:classifications:label; raising only) or declassifies it (iam:classifications:declassify, a
 * recent sign-in and a reason; lowering, changing or removing). The resource may not exist yet: the label is IAM-held
 * and outlives it.
 */
export function ResourceLabelForm({
  tenantId,
  mode,
  definition,
  initial,
}: {
  tenantId: string;
  mode: 'label' | 'declassify';
  /** The scheme in force, only when the viewer may read it; otherwise levels and compartments are typed as ids. */
  definition?: ClassificationSchemeDefinition;
  initial?: { type: string; id: string; label: ClassificationLabel; inheritToChildren: boolean };
}) {
  const id = useId();
  const { submit, busy, feedback, setNotice } = useClearanceCall(tenantId);
  const [type, setType] = useState(initial?.type ?? '');
  const [resourceId, setResourceId] = useState(initial?.id ?? '');
  const [draft, setDraft] = useState<LabelDraft>(() => labelDraft(initial?.label));
  const [inherit, setInherit] = useState(initial?.inheritToChildren ?? false);
  const [remove, setRemove] = useState(false);
  const [reason, setReason] = useState('');

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = { tenantId, type: type.trim(), id: resourceId.trim() };
    if (mode === 'label')
      submit(
        () => ({ ...target, label: labelFromDraft(draft), inheritToChildren: inherit }),
        (body) => iamClient().clearances.label(body),
        () => setNotice('Labeled.'),
      );
    else
      submit(
        () => {
          if (!reason.trim()) throw new Error('Give the reason for declassifying');
          return {
            ...target,
            label: remove ? null : labelFromDraft(draft),
            reason: reason.trim(),
            ...(remove ? {} : { inheritToChildren: inherit }),
          };
        },
        (body) => iamClient().clearances.declassify(body),
        () => {
          setReason('');
          setNotice(remove ? 'Label removed.' : 'Declassified.');
        },
      );
  }

  return (
    <form className="form" onSubmit={onSubmit}>
      {!initial && (
        <div className="grid cols-2">
          <Field
            id={`${id}-type`}
            label="Resource type"
            help="An application type, or a type registered in this organization."
          >
            <input
              id={`${id}-type`}
              className="input"
              value={type}
              onChange={(event) => setType(event.target.value)}
              placeholder="document"
              required
              spellCheck={false}
            />
          </Field>
          <Field id={`${id}-id`} label="Resource id">
            <input
              id={`${id}-id`}
              className="input"
              value={resourceId}
              onChange={(event) => setResourceId(event.target.value)}
              placeholder="q3-plan"
              required
              spellCheck={false}
            />
          </Field>
        </div>
      )}
      {mode === 'declassify' && (
        <div className="field inline">
          <input
            id={`${id}-remove`}
            type="checkbox"
            checked={remove}
            onChange={(event) => setRemove(event.target.checked)}
          />
          <label htmlFor={`${id}-remove`}>Remove the label entirely</label>
        </div>
      )}
      {!(mode === 'declassify' && remove) && (
        <>
          <LabelFields
            draft={draft}
            onChange={setDraft}
            levels={definition ? levelOptions(definition) : undefined}
            compartments={compartmentOptions(definition)}
            caveats={definition?.caveats}
          />
          <div className="field inline">
            <input
              id={`${id}-inherit`}
              type="checkbox"
              checked={inherit}
              onChange={(event) => setInherit(event.target.checked)}
            />
            <label htmlFor={`${id}-inherit`}>Pass the label down to managed child resources</label>
          </div>
        </>
      )}
      {mode === 'declassify' && (
        <Field id={`${id}-reason`} label="Reason" help="Recorded in the audit trail.">
          <input
            id={`${id}-reason`}
            className="input"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="Declassified by review board decision DR-12"
            required
          />
        </Field>
      )}
      {feedback}
      <div className="form-actions">
        <button className={`btn small${mode === 'declassify' ? ' danger' : ''}`} disabled={busy}>
          {busy ? 'Working…' : mode === 'label' ? 'Label' : remove ? 'Remove label' : 'Declassify'}
        </button>
      </div>
    </form>
  );
}

/** Saves a scheme change with the version it was read at (VERSION_CONFLICT when someone saved in between). */
function saveScheme(tenantId: string, scheme: ClassificationSchemeView, change: SchemeChange) {
  return iamClient().clearances.updateScheme({ tenantId, version: scheme.version, ...change });
}

/** The scheme's settings: name, required labels, guest ceiling, interim, adjudication, reminder recipients. */
export function SchemeSettingsForm({
  tenantId,
  scheme,
}: {
  tenantId: string;
  scheme: ClassificationSchemeView;
}) {
  const id = useId();
  const { submit, busy, feedback, setNotice } = useClearanceCall(tenantId);
  const [draft, setDraft] = useState<SchemeSettingsDraft>(() => schemeSettingsDraft(scheme));
  useEffect(() => setDraft(schemeSettingsDraft(scheme)), [scheme]);
  const set = (change: Partial<SchemeSettingsDraft>) =>
    setDraft((current) => ({ ...current, ...change }));

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    let empty = false;
    submit(
      () => {
        const change = schemeSettingsChange(scheme, draft);
        empty = Object.keys(change).length === 0;
        return change;
      },
      (change) => (empty ? Promise.resolve(scheme) : saveScheme(tenantId, scheme, change)),
      () => setNotice(empty ? 'Nothing changed.' : 'Saved.'),
    );
  }

  return (
    <form className="form" onSubmit={onSubmit}>
      <div className="grid cols-2">
        <Field id={`${id}-name`} label="Name">
          <input
            id={`${id}-name`}
            className="input"
            value={draft.name}
            onChange={(event) => set({ name: event.target.value })}
            required
          />
        </Field>
        <Field
          id={`${id}-guests`}
          label="Guest ceiling"
          help="The highest level a guest's clearance counts as."
        >
          <LevelSelect
            id={`${id}-guests`}
            value={draft.guestCeiling}
            onChange={(guestCeiling) => set({ guestCeiling })}
            levels={levelOptions(scheme.definition)}
            required={false}
            emptyLabel="Guests hold no clearance"
          />
        </Field>
      </div>
      <Field
        id={`${id}-require`}
        label="Types that must carry a label"
        optional
        help="Comma-separated resource types; * for every application type. An unlabeled resource of these types is refused to everyone (root included) unless the default label below applies."
      >
        <input
          id={`${id}-require`}
          className="input"
          value={draft.requireLabels}
          onChange={(event) => set({ requireLabels: event.target.value })}
          placeholder="document, dataset"
          spellCheck={false}
        />
      </Field>
      <div className="grid cols-2">
        <Field
          id={`${id}-adjudication`}
          label="Adjudication"
          help={adjudicationHelp[draft.adjudication]}
        >
          <select
            id={`${id}-adjudication`}
            className="select"
            value={draft.adjudication}
            onChange={(event) =>
              set({ adjudication: event.target.value as SchemeSettingsDraft['adjudication'] })
            }
          >
            {(['within-own', 'unrestricted'] as const).map((mode) => (
              <option key={mode} value={mode}>
                {adjudicationLabels[mode]}
              </option>
            ))}
          </select>
        </Field>
        <Field
          id={`${id}-notify`}
          label="Also remind"
          optional
          help="Addresses emailed with the owners about reinvestigations and clearances ending."
        >
          <input
            id={`${id}-notify`}
            className="input"
            value={draft.notifyEmails}
            onChange={(event) => set({ notifyEmails: event.target.value })}
            placeholder="security-office@example.com"
            spellCheck={false}
          />
        </Field>
      </div>
      <div className="field inline">
        <input
          id={`${id}-interim`}
          type="checkbox"
          checked={draft.interimAllowed}
          onChange={(event) => set({ interimAllowed: event.target.checked })}
        />
        <label htmlFor={`${id}-interim`}>Count interim clearances</label>
        <span className="help">Off: interim clearances stop counting at once.</span>
      </div>
      {feedback}
      <div className="form-actions">
        <button className="btn small" disabled={busy}>
          {busy ? 'Working…' : 'Save settings'}
        </button>
      </div>
    </form>
  );
}

/** The label unlabeled resources of the required types get instead of being refused, or none. */
export function DefaultLabelForm({
  tenantId,
  scheme,
}: {
  tenantId: string;
  scheme: ClassificationSchemeView;
}) {
  const { submit, run, busy, feedback, setNotice } = useClearanceCall(tenantId);
  const [draft, setDraft] = useState<LabelDraft>(() =>
    labelDraft(scheme.defaultLabel, levelsByRank(scheme.definition)[0]?.id),
  );
  return (
    <form
      className="form"
      onSubmit={(event) => {
        event.preventDefault();
        submit(
          () => ({ defaultLabel: labelFromDraft(draft) }),
          (change) => saveScheme(tenantId, scheme, change),
          () => setNotice('Saved.'),
        );
      }}
    >
      <LabelFields
        draft={draft}
        onChange={setDraft}
        levels={levelOptions(scheme.definition)}
        compartments={compartmentOptions(scheme.definition)}
        caveats={scheme.definition.caveats}
      />
      {feedback}
      <div className="form-actions">
        <button className="btn small" disabled={busy}>
          {busy ? 'Working…' : 'Set default label'}
        </button>
        {scheme.defaultLabel && (
          <button
            type="button"
            className="btn small secondary"
            disabled={busy}
            onClick={() =>
              void run(
                () => saveScheme(tenantId, scheme, { defaultLabel: null }),
                () => setNotice('Removed: unlabeled resources of the required types are refused.'),
              )
            }
          >
            Remove default
          </button>
        )}
      </div>
    </form>
  );
}

/**
 * Changes the scheme's definition: add a compartment, add a level above the top one, or edit the whole definition as
 * JSON (levels and compartments that clearances or labels use cannot be removed or re-ranked: RESOURCE_IN_USE).
 */
export function SchemeDefinitionForms({
  tenantId,
  scheme,
}: {
  tenantId: string;
  scheme: ClassificationSchemeView;
}) {
  const id = useId();
  const { submit, busy, feedback, setNotice } = useClearanceCall(tenantId);
  const [compartment, setCompartment] = useState({ id: '', name: '' });
  const [level, setLevel] = useState({ id: '', name: '', abbreviation: '' });
  const [json, setJson] = useState(() => JSON.stringify(scheme.definition, null, 2));
  useEffect(() => setJson(JSON.stringify(scheme.definition, null, 2)), [scheme]);
  const save = (build: () => ClassificationSchemeDefinition, done: () => void, message: string) =>
    submit(
      () => ({ definition: build() }),
      (change) => saveScheme(tenantId, scheme, change),
      () => {
        done();
        setNotice(message);
      },
    );

  return (
    <div className="stack">
      <div className="grid cols-2">
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            save(
              () => withCompartment(scheme.definition, compartment),
              () => setCompartment({ id: '', name: '' }),
              'Compartment added.',
            );
          }}
        >
          <h3>Add a compartment</h3>
          <div className="grid cols-2">
            <Field id={`${id}-cid`} label="Id" help="Opaque; audit events and labels carry it.">
              <input
                id={`${id}-cid`}
                className="input"
                value={compartment.id}
                onChange={(event) => setCompartment({ ...compartment, id: event.target.value })}
                placeholder="c-17"
                required
                spellCheck={false}
              />
            </Field>
            <Field
              id={`${id}-cname`}
              label="Name"
              help="Shown only to holders of iam:clearances:read."
            >
              <input
                id={`${id}-cname`}
                className="input"
                value={compartment.name}
                onChange={(event) => setCompartment({ ...compartment, name: event.target.value })}
                required
              />
            </Field>
          </div>
          <div className="form-actions">
            <button className="btn small" disabled={busy}>
              Add compartment
            </button>
          </div>
        </form>
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            save(
              () => withTopLevel(scheme.definition, level),
              () => setLevel({ id: '', name: '', abbreviation: '' }),
              'Level added.',
            );
          }}
        >
          <h3>Add a level above the top</h3>
          <div className="grid cols-3">
            <Field id={`${id}-lid`} label="Id">
              <input
                id={`${id}-lid`}
                className="input"
                value={level.id}
                onChange={(event) => setLevel({ ...level, id: event.target.value })}
                required
                spellCheck={false}
              />
            </Field>
            <Field id={`${id}-lname`} label="Name">
              <input
                id={`${id}-lname`}
                className="input"
                value={level.name}
                onChange={(event) => setLevel({ ...level, name: event.target.value })}
                required
              />
            </Field>
            <Field id={`${id}-labbr`} label="Marking" optional>
              <input
                id={`${id}-labbr`}
                className="input"
                value={level.abbreviation}
                onChange={(event) => setLevel({ ...level, abbreviation: event.target.value })}
              />
            </Field>
          </div>
          <div className="form-actions">
            <button className="btn small" disabled={busy}>
              Add level
            </button>
          </div>
        </form>
      </div>
      <details>
        <summary className="small">Edit the definition as JSON</summary>
        <form
          className="form"
          onSubmit={(event) => {
            event.preventDefault();
            save(
              () => parseDefinition(json),
              () => undefined,
              'Definition saved.',
            );
          }}
        >
          <Field
            id={`${id}-json`}
            label="Definition"
            help="Rename levels and compartments, add owner countries and caveats. New levels go above every existing one; a level or compartment that clearances or labels use cannot be removed or re-ranked."
          >
            <textarea
              id={`${id}-json`}
              className="textarea mono"
              rows={14}
              value={json}
              onChange={(event) => setJson(event.target.value)}
              spellCheck={false}
            />
          </Field>
          <div className="form-actions">
            <button className="btn small" disabled={busy}>
              Save definition
            </button>
          </div>
        </form>
      </details>
      {feedback}
    </div>
  );
}

/**
 * For investigations (iam:clearances:adjudicate): whether a person may read a resource, which dimension the first
 * refused party fails, the label decisions apply, and each party's clearance. Decisions themselves only ever say
 * CLEARANCE_REQUIRED.
 */
export function ExplainTool({
  tenantId,
  people,
  definition,
  initialIdentityId,
}: {
  tenantId: string;
  people: Option[];
  /** Only when the viewer may read the scheme: names levels and compartments instead of their ids. */
  definition?: ClassificationSchemeDefinition;
  initialIdentityId?: string;
}) {
  const id = useId();
  const { submit, busy, feedback } = useClearanceCall(tenantId);
  const [identityId, setIdentityId] = useState(initialIdentityId ?? '');
  const [type, setType] = useState('');
  const [resourceId, setResourceId] = useState('');
  const [result, setResult] = useState<ClearanceExplanation | null>(null);
  const personName = (value: string) =>
    people.find((option) => option.value === value)?.label ?? value;

  return (
    <div className="stack">
      <form
        className="form"
        onSubmit={(event) => {
          event.preventDefault();
          setResult(null);
          submit(
            () => ({ tenantId, identityId, type: type.trim(), id: resourceId.trim() }),
            (body) => iamClient().clearances.explain(body),
            setResult,
          );
        }}
      >
        <div className="grid cols-3">
          <Field id={`${id}-person`} label="Person or agent">
            <select
              id={`${id}-person`}
              className="select"
              value={identityId}
              onChange={(event) => setIdentityId(event.target.value)}
              required
            >
              <option value="">Choose</option>
              {people.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </Field>
          <Field id={`${id}-type`} label="Resource type">
            <input
              id={`${id}-type`}
              className="input"
              value={type}
              onChange={(event) => setType(event.target.value)}
              placeholder="document"
              required
              spellCheck={false}
            />
          </Field>
          <Field id={`${id}-id`} label="Resource id">
            <input
              id={`${id}-id`}
              className="input"
              value={resourceId}
              onChange={(event) => setResourceId(event.target.value)}
              required
              spellCheck={false}
            />
          </Field>
        </div>
        {feedback}
        <div className="form-actions">
          <button className="btn small" disabled={busy}>
            {busy ? 'Working…' : 'Explain'}
          </button>
        </div>
      </form>
      {result && (
        <div className="stack">
          <div className={`alert ${result.allowed ? 'success' : 'warning'}`}>
            <strong>{result.allowed ? 'May read' : 'Refused'}</strong>
            {' — '}
            {result.label ? (
              <>
                label <code>{labelMarking(result.label, definition)}</code>
              </>
            ) : (
              'no label applies'
            )}
            {result.failure && (
              <>
                {'. '}
                {personName(result.party.identityId)}: {failureLabels[result.failure]}
              </>
            )}
            {result.allowed &&
              ' Roles and policies still decide: the clearance only stops reading up.'}
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>Party</th>
                <th>Clearance</th>
                <th>Level</th>
                <th>Compartments</th>
                <th>Citizenship</th>
              </tr>
            </thead>
            <tbody>
              {result.parties.map((party) => (
                <tr key={party.identityId}>
                  <td>
                    {personName(party.identityId)}
                    {result.failure && party.identityId === result.party.identityId && (
                      <>
                        {' '}
                        <span className="badge danger">fails</span>
                      </>
                    )}
                  </td>
                  <td>
                    <span className={`badge ${statusTone(party.status)}`}>
                      {effectiveStatusLabels[party.status]}
                    </span>
                  </td>
                  <td>{party.level ? levelName(definition, party.level) : '—'}</td>
                  <td>
                    {party.compartments.length
                      ? party.compartments
                          .map((item) => compartmentName(definition, item))
                          .join(', ')
                      : '—'}
                  </td>
                  <td>{party.citizenship.length ? party.citizenship.join(', ') : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
