'use client';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState, type FormEvent, type ReactNode } from 'react';
import type {
  MyOnboarding,
  OnboardingCheck,
  OnboardingField,
  OnboardingFlowStatus,
  OnboardingStepStatus,
} from 'better-iam/server';
import { describeError, iamClient } from '@/lib/client';

type Mode = 'member' | 'setup';

/** Where a tenant setup check is satisfied in the console. */
function checkLink(
  check: OnboardingCheck | undefined,
  base: string,
): { href: string; label: string } {
  switch (check) {
    case 'verified-domain':
      return { href: `${base}/domains`, label: 'Verify a domain' };
    case 'members':
    case 'owners':
      return { href: `${base}/members`, label: 'Open members' };
    case 'mfa-policy':
    case 'slug':
      return { href: `${base}/settings`, label: 'Open settings' };
    case 'agreement':
      return { href: `${base}/agreements`, label: 'Publish terms of use' };
    case 'directory-sync':
      return { href: `${base}/directory`, label: 'Set up directory sync' };
    case 'member-onboarding':
      return { href: `${base}/onboarding`, label: 'Create a member flow' };
    default:
      return { href: `${base}/settings`, label: 'Open settings' };
  }
}

/** Levels read better as "Platform" for the root tenant and the tenant's own name elsewhere. */
export function levelName(source: { type: string; name: string }): string {
  return source.type === 'root' ? 'Platform' : source.name;
}

function Mark({ state }: { state: OnboardingStepStatus['state'] }) {
  const symbol =
    state === 'complete'
      ? '✓'
      : state === 'submitted'
        ? '…'
        : state === 'rejected'
          ? '!'
          : state === 'unavailable'
            ? '–'
            : '';
  return (
    <span className={`onboarding-mark ${state}`} aria-hidden="true">
      {symbol}
    </span>
  );
}

function stateLabel(step: OnboardingStepStatus): string {
  switch (step.state) {
    case 'complete':
      return 'Done';
    case 'submitted':
      return 'Waiting for review';
    case 'rejected':
      return 'Needs another look';
    case 'unavailable':
      return 'Not applicable';
    default:
      return step.optional ? 'Optional' : 'To do';
  }
}

/** A form step's inputs, typed by field: answers are sent as strings, numbers and booleans. */
function StepForm({
  fields,
  answers,
  disabled,
  submitLabel,
  onSubmit,
}: {
  fields: OnboardingField[];
  answers?: Record<string, unknown>;
  disabled: boolean;
  submitLabel: string;
  onSubmit: (answers: Record<string, unknown>) => void;
}) {
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const values: Record<string, unknown> = {};
    for (const field of fields) {
      if (field.type === 'boolean') {
        values[field.name] = data.get(field.name) === 'on';
        continue;
      }
      const raw = data.get(field.name);
      const text = typeof raw === 'string' ? raw : '';
      if (!text.trim()) continue;
      values[field.name] = field.type === 'number' ? Number(text) : text;
    }
    onSubmit(values);
  }
  return (
    <form className="form" onSubmit={submit}>
      {fields.map((field) => {
        const id = `onboarding-${field.name}`;
        const current = answers?.[field.name];
        if (field.type === 'boolean')
          return (
            <div className="field inline" key={field.name}>
              <input id={id} type="checkbox" name={field.name} defaultChecked={current === true} />
              <label htmlFor={id}>
                {field.label}
                {field.required ? '' : <span className="muted"> (optional)</span>}
              </label>
              {field.help && <span className="help">{field.help}</span>}
            </div>
          );
        const value = current === undefined || current === null ? '' : String(current);
        return (
          <div className="field" key={field.name}>
            <label htmlFor={id}>
              {field.label}
              {field.required ? '' : <span className="muted"> (optional)</span>}
            </label>
            {field.type === 'textarea' ? (
              <textarea
                id={id}
                className="textarea"
                name={field.name}
                rows={4}
                defaultValue={value}
                placeholder={field.placeholder}
                required={field.required}
                maxLength={field.maxLength}
              />
            ) : field.type === 'select' ? (
              <select
                id={id}
                className="select"
                name={field.name}
                defaultValue={value}
                required={field.required}
              >
                <option value="">Choose…</option>
                {(field.options ?? []).map((option) => (
                  <option key={option} value={option}>
                    {option}
                  </option>
                ))}
              </select>
            ) : (
              <input
                id={id}
                className="input"
                name={field.name}
                type={field.type === 'text' ? 'text' : field.type}
                defaultValue={value}
                placeholder={field.placeholder}
                required={field.required}
                maxLength={field.maxLength}
                min={field.min}
                max={field.max}
                step={field.type === 'number' ? 'any' : undefined}
              />
            )}
            {field.help && <span className="help">{field.help}</span>}
          </div>
        );
      })}
      <div className="form-actions">
        <button className="btn small" disabled={disabled}>
          {submitLabel}
        </button>
      </div>
    </form>
  );
}

function Answers({
  fields,
  answers,
}: {
  fields: OnboardingField[];
  answers: Record<string, unknown>;
}) {
  const rows = fields.filter((field) => answers[field.name] !== undefined);
  if (!rows.length) return null;
  return (
    <dl className="kv small">
      {rows.map((field) => (
        <div key={field.name} style={{ display: 'contents' }}>
          <dt>{field.label}</dt>
          <dd>
            {typeof answers[field.name] === 'boolean'
              ? answers[field.name]
                ? 'Yes'
                : 'No'
              : String(answers[field.name])}
          </dd>
        </div>
      ))}
    </dl>
  );
}

function StepBody({
  step,
  mode,
  base,
  busy,
  readOnly,
  submit,
}: {
  step: OnboardingStepStatus;
  mode: Mode;
  base: string;
  busy: boolean;
  readOnly: boolean;
  submit: (
    step: OnboardingStepStatus,
    body: { answers?: Record<string, unknown>; acknowledged?: boolean },
  ) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const done = step.state === 'complete';
  const act = !readOnly;
  let body: ReactNode = null;
  switch (step.kind) {
    case 'form':
      body =
        done && !editing ? (
          <div className="stack" style={{ gap: 6 }}>
            <Answers fields={step.fields ?? []} answers={step.answers ?? {}} />
            {act && (
              <span>
                <button
                  type="button"
                  className="btn small secondary"
                  onClick={() => setEditing(true)}
                >
                  Edit answers
                </button>
              </span>
            )}
          </div>
        ) : act ? (
          <StepForm
            fields={step.fields ?? []}
            answers={step.answers}
            disabled={busy}
            submitLabel={done ? 'Save answers' : 'Save and continue'}
            onSubmit={(answers) => {
              setEditing(false);
              submit(step, { answers });
            }}
          />
        ) : null;
      break;
    case 'acknowledge':
      body = (
        <div className="stack" style={{ gap: 8 }}>
          <pre className="result" style={{ whiteSpace: 'pre-wrap', maxHeight: 280 }}>
            {step.content}
          </pre>
          {!done && act && (
            <>
              <label className="field inline">
                <input
                  type="checkbox"
                  checked={confirmed}
                  onChange={(event) => setConfirmed(event.target.checked)}
                />
                <span>I have read and understood this</span>
              </label>
              <span>
                <button
                  type="button"
                  className="btn small"
                  disabled={busy || !confirmed}
                  onClick={() => submit(step, { acknowledged: true })}
                >
                  Confirm
                </button>
              </span>
            </>
          )}
        </div>
      );
      break;
    case 'task':
      body = (
        <div className="row">
          {step.url && (
            <a
              className="btn small secondary"
              href={step.url}
              target="_blank"
              rel="noreferrer noopener"
            >
              Open ↗
            </a>
          )}
          {step.state === 'rejected' && step.note && (
            <span className="badge warning" title="Note from the reviewer">
              {step.note}
            </span>
          )}
          {!done && step.state !== 'submitted' && act && (
            <button
              type="button"
              className="btn small"
              disabled={busy}
              onClick={() => submit(step, {})}
            >
              {step.verification === 'admin'
                ? step.state === 'rejected'
                  ? 'Submit again'
                  : 'Submit for review'
                : 'Mark as done'}
            </button>
          )}
          {step.state === 'submitted' && (
            <span className="small muted">An administrator will confirm this.</span>
          )}
        </div>
      );
      break;
    case 'verify-email':
      if (!done)
        body = (
          <Link className="btn small secondary" href={`${base}/account`}>
            Verify your email
          </Link>
        );
      break;
    case 'mfa':
    case 'passkey':
      if (!done)
        body = (
          <Link className="btn small secondary" href={`${base}/account`}>
            {step.kind === 'mfa' ? 'Set up two-step verification' : 'Add a passkey'}
          </Link>
        );
      break;
    case 'agreement':
      if (step.state === 'pending')
        body = (
          <span className="small">
            Review and accept <strong>{step.agreement}</strong> in the notice at the top of this
            page.
          </span>
        );
      else if (step.state === 'unavailable' && step.detail)
        body = <span className="small muted">{step.detail}</span>;
      break;
    case 'check': {
      const link = checkLink(step.check, base);
      body = (
        <div className="row">
          {step.detail && <span className="small muted">{step.detail}</span>}
          {!done && (
            <Link className="btn small secondary" href={link.href}>
              {link.label}
            </Link>
          )}
        </div>
      );
      break;
    }
  }
  return (
    <li className={`onboarding-step ${step.state}`}>
      <Mark state={step.state} />
      <div className="stack" style={{ gap: 6, flex: 1, minWidth: 0 }}>
        <div className="row spread">
          <strong>{step.title}</strong>
          <span className={`small ${done ? 'muted' : ''}`}>{stateLabel(step)}</span>
        </div>
        {step.description && (
          <p className="small muted" style={{ whiteSpace: 'pre-wrap', margin: 0 }}>
            {step.description}
          </p>
        )}
        {mode === 'setup' && readOnly && !done && step.kind !== 'check' && (
          <span className="small muted">
            An administrator of this organization completes this step.
          </span>
        )}
        {body}
      </div>
    </li>
  );
}

export function FlowProgress({ done, total }: { done: number; total: number }) {
  const percent = total ? Math.round((done / total) * 100) : 100;
  return (
    <div className="stack" style={{ gap: 4 }}>
      <div className={`meter ${percent === 100 ? 'success' : ''}`} aria-hidden="true">
        <span style={{ width: `${percent}%` }} />
      </div>
      <span className="small muted">
        {done} of {total} step{total === 1 ? '' : 's'} done
      </span>
    </div>
  );
}

/**
 * The onboarding checklists of the signed-in person (`member`) or of the organization's own setup (`setup`): one
 * card per flow with its steps, each completed in place. Steps that complete on their own link to where that happens.
 */
export function OnboardingChecklist({
  tenantId,
  base,
  initial,
  mode,
  readOnly = false,
}: {
  tenantId: string;
  base: string;
  initial: MyOnboarding;
  mode: Mode;
  readOnly?: boolean;
}) {
  const router = useRouter();
  const [flows, setFlows] = useState<OnboardingFlowStatus[]>(initial.flows);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<{ flowId: string; message: string } | null>(null);

  async function submit(
    flow: OnboardingFlowStatus,
    step: OnboardingStepStatus,
    body: { answers?: Record<string, unknown>; acknowledged?: boolean },
  ) {
    setBusy(step.id);
    setError(null);
    try {
      const result = (await iamClient().$request(
        mode === 'member' ? 'onboarding/submitStep' : 'onboarding/submitSetupStep',
        { tenantId, flowId: flow.id, stepId: step.id, ...body },
      )) as { flow: OnboardingFlowStatus };
      setFlows((current) => current.map((item) => (item.id === flow.id ? result.flow : item)));
      router.refresh();
    } catch (caught) {
      setError({ flowId: flow.id, message: describeError(caught).message });
    } finally {
      setBusy(null);
    }
  }

  if (!flows.length)
    return (
      <div className="empty">
        {mode === 'member'
          ? 'There is nothing to set up. You are all set.'
          : 'No setup checklist applies to this organization.'}
      </div>
    );
  return (
    <div className="stack">
      {flows.map((flow) => (
        <section className="card" key={flow.id} aria-labelledby={`flow-${flow.id}`}>
          <div className="card-header">
            <div>
              <h2 id={`flow-${flow.id}`}>
                <span className="row">
                  {flow.name}
                  {flow.complete ? (
                    <span className="badge success">complete</span>
                  ) : flow.required ? (
                    <span className="badge warning">required</span>
                  ) : (
                    <span className="badge">optional</span>
                  )}
                </span>
              </h2>
              {flow.description && <p style={{ whiteSpace: 'pre-wrap' }}>{flow.description}</p>}
            </div>
            <span className="badge" title="Where this checklist comes from">
              {levelName(flow.source)}
            </span>
          </div>
          <div className="card-body stack">
            <FlowProgress done={flow.done} total={flow.total} />
            <ol className="onboarding-steps">
              {flow.steps.map((step) => (
                <StepBody
                  key={step.id}
                  step={step}
                  mode={mode}
                  base={base}
                  busy={busy !== null}
                  readOnly={readOnly}
                  submit={(target, body) => void submit(flow, target, body)}
                />
              ))}
            </ol>
            {error?.flowId === flow.id && <div className="alert danger">{error.message}</div>}
          </div>
        </section>
      ))}
    </div>
  );
}
