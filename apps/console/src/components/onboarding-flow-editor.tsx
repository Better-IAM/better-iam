'use client';
import { useRouter } from 'next/navigation';
import { useState, type FormEvent } from 'react';
import type {
  OnboardingAudience,
  OnboardingCheck,
  OnboardingFieldType,
  OnboardingFlow,
  OnboardingScope,
  OnboardingStep,
  OnboardingStepKind,
} from 'better-iam/server';
import { describeError, iamClient } from '@/lib/client';

type AttributeType = 'string' | 'number' | 'boolean';

interface FieldDraft {
  key: number;
  name: string;
  nameTouched: boolean;
  label: string;
  type: OnboardingFieldType;
  required: boolean;
  options: string;
  help: string;
  attribute: string;
}
interface StepDraft {
  key: number;
  id: string;
  idTouched: boolean;
  kind: OnboardingStepKind;
  title: string;
  description: string;
  optional: boolean;
  fields: FieldDraft[];
  content: string;
  url: string;
  verification: 'self' | 'admin';
  agreement: string;
  check: OnboardingCheck;
  minimum: string;
}

const kindLabels: Record<OnboardingStepKind, string> = {
  form: 'Form (collect answers)',
  acknowledge: 'Read and confirm',
  task: 'Task (done elsewhere)',
  agreement: 'Accept terms of use',
  'verify-email': 'Verify email address',
  mfa: 'Set up two-step verification',
  passkey: 'Add a passkey',
  check: 'Setup check (automatic)',
};
const memberKinds: OnboardingStepKind[] = [
  'form',
  'acknowledge',
  'task',
  'agreement',
  'verify-email',
  'mfa',
  'passkey',
];
const tenantKinds: OnboardingStepKind[] = ['check', 'form', 'acknowledge', 'task'];
const checkLabels: Record<OnboardingCheck, string> = {
  'verified-domain': 'A verified email domain',
  members: 'At least N members',
  owners: 'At least N owners',
  'mfa-policy': 'MFA required for everyone',
  agreement: 'Terms of use published',
  slug: 'A sign-in alias',
  sso: 'An SSO connection',
  'directory-sync': 'Directory sync connected',
  'member-onboarding': 'Member onboarding configured',
};
const fieldTypes: OnboardingFieldType[] = [
  'text',
  'textarea',
  'email',
  'url',
  'number',
  'boolean',
  'select',
  'date',
];
const attributeTypeOf = (type: OnboardingFieldType): AttributeType =>
  type === 'number' ? 'number' : type === 'boolean' ? 'boolean' : 'string';

let counter = 0;
const nextKey = () => ++counter;
const slug = (value: string) =>
  value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 40) || 'step';
const fieldName = (value: string) => {
  const name = value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 40);
  return /^[a-z]/.test(name) ? name : `field_${name}`.slice(0, 40);
};

function blankField(): FieldDraft {
  return {
    key: nextKey(),
    name: '',
    nameTouched: false,
    label: '',
    type: 'text',
    required: false,
    options: '',
    help: '',
    attribute: '',
  };
}
function blankStep(kind: OnboardingStepKind, title = ''): StepDraft {
  return {
    key: nextKey(),
    id: title ? slug(title) : '',
    idTouched: false,
    kind,
    title,
    description: '',
    optional: false,
    fields: kind === 'form' ? [blankField()] : [],
    content: '',
    url: '',
    verification: 'self',
    agreement: '',
    check: 'members',
    minimum: '',
  };
}
function draftOf(step: OnboardingStep): StepDraft {
  return {
    ...blankStep(step.kind, step.title),
    id: step.id,
    idTouched: true,
    description: step.description ?? '',
    optional: step.optional === true,
    fields: (step.fields ?? []).map((field) => ({
      key: nextKey(),
      name: field.name,
      nameTouched: true,
      label: field.label,
      type: field.type,
      required: field.required === true,
      options: (field.options ?? []).join('\n'),
      help: field.help ?? '',
      attribute: field.attribute ?? '',
    })),
    content: step.content ?? '',
    url: step.url ?? '',
    verification: step.verification ?? 'self',
    agreement: step.agreement ?? '',
    check: step.check ?? 'members',
    minimum: step.minimum !== undefined ? String(step.minimum) : '',
  };
}
/** A draft as API input; `mapAttributes` keeps attribute mappings (member flows that reach their own people). */
function stepOf(draft: StepDraft, mapAttributes: boolean): Record<string, unknown> {
  const step: Record<string, unknown> = {
    id: draft.id || slug(draft.title),
    kind: draft.kind,
    title: draft.title.trim(),
  };
  if (draft.description.trim()) step.description = draft.description;
  if (draft.optional) step.optional = true;
  if (draft.kind === 'form')
    step.fields = draft.fields.map((field) => {
      const result: Record<string, unknown> = {
        name: field.name || fieldName(field.label),
        label: field.label.trim(),
        type: field.type,
      };
      if (field.required) result.required = true;
      if (field.help.trim()) result.help = field.help.trim();
      if (field.type === 'select')
        result.options = field.options
          .split(/[\n,]/)
          .map((option) => option.trim())
          .filter(Boolean);
      if (mapAttributes && field.attribute && field.type !== 'textarea')
        result.attribute = field.attribute;
      return result;
    });
  if (draft.kind === 'acknowledge') step.content = draft.content;
  if (draft.kind === 'task') {
    if (draft.url.trim()) step.url = draft.url.trim();
    step.verification = draft.verification;
  }
  if (draft.kind === 'agreement') step.agreement = draft.agreement.trim();
  if (draft.kind === 'check') {
    step.check = draft.check;
    if ((draft.check === 'members' || draft.check === 'owners') && draft.minimum.trim())
      step.minimum = Number(draft.minimum);
  }
  return step;
}

interface Template {
  label: string;
  audience: OnboardingAudience;
  name: string;
  description: string;
  steps: (attributes: Record<string, AttributeType>) => StepDraft[];
}
const templates: Template[] = [
  {
    label: 'New member essentials',
    audience: 'member',
    name: 'Welcome aboard',
    description: 'Everything a new member does in their first days.',
    steps: (attributes) => {
      const profile = blankStep('form', 'Tell us about yourself');
      profile.fields = [
        ...Object.entries(attributes)
          .filter(([, type]) => type === 'string')
          .slice(0, 2)
          .map(([name]) => ({
            ...blankField(),
            name,
            nameTouched: true,
            label: name.charAt(0).toUpperCase() + name.slice(1),
            attribute: name,
          })),
        { ...blankField(), name: 'phone', nameTouched: true, label: 'Work phone' },
      ];
      const conduct = blankStep('acknowledge', 'Code of conduct');
      conduct.content = 'Treat everyone with respect.\nReport security incidents right away.';
      return [
        blankStep('verify-email', 'Verify your email address'),
        blankStep('mfa', 'Set up two-step verification'),
        conduct,
        profile,
      ];
    },
  },
  {
    label: 'Security basics',
    audience: 'member',
    name: 'Security basics',
    description: 'Protect your account before you get access.',
    steps: () => {
      const passkey = blankStep('passkey', 'Add a passkey');
      passkey.optional = true;
      const training = blankStep('task', 'Complete security awareness training');
      training.url = 'https://example.com/training';
      training.verification = 'admin';
      return [blankStep('mfa', 'Set up two-step verification'), passkey, training];
    },
  },
  {
    label: 'Organization setup',
    audience: 'tenant',
    name: 'Organization setup',
    description: 'Get your organization ready before inviting everyone.',
    steps: () => {
      const owners = blankStep('check', 'Add a second owner');
      owners.check = 'owners';
      owners.minimum = '2';
      const members = blankStep('check', 'Invite your team');
      members.check = 'members';
      members.minimum = '3';
      const domain = blankStep('check', 'Verify your email domain');
      domain.check = 'verified-domain';
      const mfa = blankStep('check', 'Require two-step verification');
      mfa.check = 'mfa-policy';
      const sso = blankStep('check', 'Connect single sign-on');
      sso.check = 'sso';
      sso.optional = true;
      const company = blankStep('form', 'About your company');
      company.fields = [
        {
          ...blankField(),
          name: 'size',
          nameTouched: true,
          label: 'Company size',
          type: 'select',
          options: '1-10\n11-50\n51-250\n251+',
          required: true,
        },
        {
          ...blankField(),
          name: 'billing_email',
          nameTouched: true,
          label: 'Billing contact',
          type: 'email',
        },
      ];
      return [company, owners, members, domain, mfa, sso];
    },
  },
  {
    label: 'Project setup',
    audience: 'tenant',
    name: 'Project setup',
    description: 'A short checklist for every new project.',
    steps: () => {
      const brief = blankStep('form', 'Describe the project');
      brief.fields = [
        {
          ...blankField(),
          name: 'purpose',
          nameTouched: true,
          label: 'Purpose',
          type: 'textarea',
          required: true,
        },
        {
          ...blankField(),
          name: 'data_classification',
          nameTouched: true,
          label: 'Data classification',
          type: 'select',
          options: 'Public\nInternal\nConfidential',
          required: true,
        },
      ];
      const members = blankStep('check', 'Add the project team');
      members.check = 'members';
      members.minimum = '2';
      const onboarding = blankStep('check', 'Set up member onboarding');
      onboarding.check = 'member-onboarding';
      onboarding.optional = true;
      return [brief, members, onboarding];
    },
  },
];

function StepEditor({
  draft,
  index,
  count,
  mapAttributes,
  attributes,
  editing,
  update,
  move,
  remove,
}: {
  draft: StepDraft;
  index: number;
  count: number;
  /** Answers may fill attributes: member flows that reach the defining tenant's own people. */
  mapAttributes: boolean;
  attributes: Record<string, AttributeType>;
  editing: boolean;
  update: (change: Partial<StepDraft>) => void;
  move: (offset: number) => void;
  remove: () => void;
}) {
  const updateField = (key: number, change: Partial<FieldDraft>) =>
    update({
      fields: draft.fields.map((field) =>
        field.key === key
          ? {
              ...field,
              ...change,
              ...(change.label !== undefined && !field.nameTouched && !editing
                ? { name: fieldName(change.label) }
                : {}),
            }
          : field,
      ),
    });
  return (
    <li className="onboarding-editor-step">
      <div className="row spread">
        <strong className="small">
          {index + 1}. {kindLabels[draft.kind]}
        </strong>
        <span className="row">
          <button
            type="button"
            className="btn small ghost"
            disabled={index === 0}
            onClick={() => move(-1)}
            aria-label="Move up"
          >
            ↑
          </button>
          <button
            type="button"
            className="btn small ghost"
            disabled={index === count - 1}
            onClick={() => move(1)}
            aria-label="Move down"
          >
            ↓
          </button>
          <button
            type="button"
            className="btn small ghost"
            onClick={remove}
            aria-label="Remove step"
          >
            Remove
          </button>
        </span>
      </div>
      <div className="grid cols-2">
        <div className="field">
          <label>Title</label>
          <input
            className="input"
            value={draft.title}
            required
            maxLength={120}
            onChange={(event) =>
              update({
                title: event.target.value,
                ...(draft.idTouched ? {} : { id: slug(event.target.value) }),
              })
            }
          />
        </div>
        <div className="field">
          <label>Step ID</label>
          <input
            className="input mono"
            value={draft.id}
            // Browsers compile pattern with the `v` flag, where a literal dash in a class must be escaped.
            pattern="[a-z0-9][a-z0-9\-]{0,39}"
            title="Lowercase letters, digits and dashes"
            onChange={(event) => update({ id: event.target.value, idTouched: true })}
          />
          <span className="help">Progress is kept per step ID; keep it when you edit a step.</span>
        </div>
      </div>
      <div className="field">
        <label>
          Description <span className="muted">(optional)</span>
        </label>
        <textarea
          className="textarea"
          rows={2}
          value={draft.description}
          onChange={(event) => update({ description: event.target.value })}
        />
      </div>
      {draft.kind === 'form' && (
        <div className="stack" style={{ gap: 8 }}>
          {draft.fields.map((field) => (
            <div className="onboarding-editor-field" key={field.key}>
              <div className="grid cols-3">
                <div className="field">
                  <label>Question</label>
                  <input
                    className="input"
                    value={field.label}
                    required
                    onChange={(event) => updateField(field.key, { label: event.target.value })}
                  />
                </div>
                <div className="field">
                  <label>Answer type</label>
                  <select
                    className="select"
                    value={field.type}
                    onChange={(event) =>
                      updateField(field.key, {
                        type: event.target.value as OnboardingFieldType,
                        attribute: '',
                      })
                    }
                  >
                    {fieldTypes.map((type) => (
                      <option key={type} value={type}>
                        {type}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="field">
                  <label>Key</label>
                  <input
                    className="input mono"
                    value={field.name}
                    placeholder={fieldName(field.label || 'answer')}
                    onChange={(event) =>
                      updateField(field.key, { name: event.target.value, nameTouched: true })
                    }
                  />
                </div>
              </div>
              {field.type === 'select' && (
                <div className="field">
                  <label>Choices (one per line)</label>
                  <textarea
                    className="textarea"
                    rows={3}
                    value={field.options}
                    onChange={(event) => updateField(field.key, { options: event.target.value })}
                  />
                </div>
              )}
              <div className="row">
                <label className="field inline">
                  <input
                    type="checkbox"
                    checked={field.required}
                    onChange={(event) => updateField(field.key, { required: event.target.checked })}
                  />
                  <span>{field.type === 'boolean' ? 'Must be checked' : 'Required'}</span>
                </label>
                {mapAttributes &&
                  field.type !== 'textarea' &&
                  Object.entries(attributes).some(
                    ([, type]) => type === attributeTypeOf(field.type),
                  ) && (
                    <label className="field inline">
                      <span className="small">Fills profile attribute</span>
                      <select
                        className="select"
                        value={field.attribute}
                        onChange={(event) =>
                          updateField(field.key, { attribute: event.target.value })
                        }
                      >
                        <option value="">—</option>
                        {Object.entries(attributes)
                          .filter(([, type]) => type === attributeTypeOf(field.type))
                          .map(([name]) => (
                            <option key={name} value={name}>
                              {name}
                            </option>
                          ))}
                      </select>
                    </label>
                  )}
                <button
                  type="button"
                  className="btn small ghost"
                  disabled={draft.fields.length === 1}
                  onClick={() =>
                    update({ fields: draft.fields.filter((item) => item.key !== field.key) })
                  }
                >
                  Remove question
                </button>
              </div>
            </div>
          ))}
          <span>
            <button
              type="button"
              className="btn small secondary"
              onClick={() => update({ fields: [...draft.fields, blankField()] })}
            >
              Add question
            </button>
          </span>
        </div>
      )}
      {draft.kind === 'acknowledge' && (
        <div className="field">
          <label>Text to read</label>
          <textarea
            className="textarea"
            rows={5}
            required
            value={draft.content}
            onChange={(event) => update({ content: event.target.value })}
          />
        </div>
      )}
      {draft.kind === 'task' && (
        <div className="grid cols-2">
          <div className="field">
            <label>
              Link <span className="muted">(optional)</span>
            </label>
            <input
              className="input"
              type="url"
              value={draft.url}
              placeholder="https://"
              onChange={(event) => update({ url: event.target.value })}
            />
          </div>
          <div className="field">
            <label>Who confirms it</label>
            <select
              className="select"
              value={draft.verification}
              onChange={(event) => update({ verification: event.target.value as 'self' | 'admin' })}
            >
              <option value="self">The person marks it done</option>
              <option value="admin">An administrator verifies it</option>
            </select>
          </div>
        </div>
      )}
      {draft.kind === 'agreement' && (
        <div className="field">
          <label>Agreement name</label>
          <input
            className="input"
            required
            value={draft.agreement}
            placeholder="Acceptable use"
            onChange={(event) => update({ agreement: event.target.value })}
          />
          <span className="help">
            A terms-of-use agreement of the member&apos;s own organization or project with this
            name. Where none exists, the step is skipped.
          </span>
        </div>
      )}
      {draft.kind === 'check' && (
        <div className="grid cols-2">
          <div className="field">
            <label>Complete when the tenant has</label>
            <select
              className="select"
              value={draft.check}
              onChange={(event) => update({ check: event.target.value as OnboardingCheck })}
            >
              {(Object.keys(checkLabels) as OnboardingCheck[]).map((check) => (
                <option key={check} value={check}>
                  {checkLabels[check]}
                </option>
              ))}
            </select>
          </div>
          {(draft.check === 'members' || draft.check === 'owners') && (
            <div className="field">
              <label>How many (N)</label>
              <input
                className="input"
                type="number"
                min={1}
                max={10000}
                placeholder="2"
                value={draft.minimum}
                onChange={(event) => update({ minimum: event.target.value })}
              />
            </div>
          )}
        </div>
      )}
      <label className="field inline">
        <input
          type="checkbox"
          checked={draft.optional}
          onChange={(event) => update({ optional: event.target.checked })}
        />
        <span>Optional step (never holds the checklist back)</span>
      </label>
    </li>
  );
}

/**
 * Builds or edits an onboarding flow: who it is for, how far down the tenant tree it reaches, and its steps. Member
 * flows onboard people; tenant flows are setup checklists for the organizations or projects below this tenant.
 */
export function OnboardingFlowEditor({
  tenantId,
  isRoot,
  descendantTypes,
  identityAttributes,
  groups,
  flow,
  onDone,
}: {
  tenantId: string;
  isRoot: boolean;
  descendantTypes: string[];
  identityAttributes: Record<string, AttributeType>;
  groups: { id: string; name: string }[];
  flow?: OnboardingFlow;
  onDone?: () => void;
}) {
  const router = useRouter();
  const editing = flow !== undefined;
  const hasChildren = descendantTypes.length > 0;
  const [audience, setAudience] = useState<OnboardingAudience>(flow?.audience ?? 'member');
  const [name, setName] = useState(flow?.name ?? '');
  const [description, setDescription] = useState(flow?.description ?? '');
  const [appliesTo, setAppliesTo] = useState<OnboardingScope>(
    flow?.appliesTo ?? (isRoot ? 'descendants' : 'tenant'),
  );
  const [tenantTypes, setTenantTypes] = useState<string[]>(flow?.tenantTypes ?? []);
  const [required, setRequired] = useState(flow?.required ?? true);
  const [locked, setLocked] = useState(flow?.locked ?? false);
  const [includeExisting, setIncludeExisting] = useState(flow?.includeExisting ?? false);
  const [enabled, setEnabled] = useState(flow?.enabled ?? true);
  const [completionGroups, setCompletionGroups] = useState<string[]>(
    flow?.completionGroupIds ?? [],
  );
  const [rule, setRule] = useState(flow?.rule ? JSON.stringify(flow.rule, null, 2) : '');
  const [steps, setSteps] = useState<StepDraft[]>(() =>
    flow ? flow.steps.map(draftOf) : [blankStep('acknowledge', 'Welcome')],
  );
  const [addKind, setAddKind] = useState<OnboardingStepKind>('form');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const kinds = audience === 'member' ? memberKinds : tenantKinds;
  const effectiveScope: OnboardingScope = audience === 'tenant' ? 'descendants' : appliesTo;
  const reachesOwnPeople = audience === 'member' && effectiveScope !== 'descendants';

  function applyTemplate(template: Template) {
    setAudience(template.audience);
    if (!name) setName(template.name);
    if (!description) setDescription(template.description);
    if (template.audience === 'tenant') setAppliesTo('descendants');
    setSteps(template.steps(identityAttributes));
    setAddKind(template.audience === 'member' ? 'form' : 'check');
  }

  function update(key: number, change: Partial<StepDraft>) {
    setSteps((current) =>
      current.map((step) => (step.key === key ? { ...step, ...change } : step)),
    );
  }
  function move(index: number, offset: number) {
    setSteps((current) => {
      const next = [...current];
      const [item] = next.splice(index, 1);
      next.splice(index + offset, 0, item!);
      return next;
    });
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      let parsedRule: unknown = null;
      if (audience === 'member' && rule.trim()) {
        try {
          parsedRule = JSON.parse(rule);
        } catch {
          throw new Error('The targeting rule must be valid JSON');
        }
      }
      const body: Record<string, unknown> = {
        tenantId,
        name: name.trim(),
        description: description.trim() ? description : editing ? null : undefined,
        appliesTo: effectiveScope,
        tenantTypes:
          effectiveScope !== 'tenant' && tenantTypes.length
            ? tenantTypes
            : editing
              ? null
              : undefined,
        required,
        locked: effectiveScope !== 'tenant' && audience === 'member' ? locked : false,
        includeExisting,
        enabled,
        steps: steps.map((step) => stepOf(step, reachesOwnPeople)),
      };
      if (audience === 'member') {
        body.rule = parsedRule ?? (editing ? null : undefined);
        body.completionGroupIds =
          reachesOwnPeople && completionGroups.length
            ? completionGroups
            : editing
              ? null
              : undefined;
      }
      if (editing)
        await iamClient().$request('onboarding/updateFlow', { ...body, flowId: flow.id });
      else await iamClient().$request('onboarding/createFlow', { ...body, audience });
      setSaved(true);
      if (!editing) {
        setName('');
        setDescription('');
        setSteps([blankStep('acknowledge', 'Welcome')]);
        setRule('');
        setCompletionGroups([]);
      }
      router.refresh();
      onDone?.();
    } catch (caught) {
      setError(describeError(caught).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="form" onSubmit={submit}>
      {!editing && (
        <div className="field">
          <label>Start from a template</label>
          <div className="row" style={{ flexWrap: 'wrap' }}>
            {templates
              .filter((template) => template.audience === 'member' || hasChildren)
              .map((template) => (
                <button
                  type="button"
                  className="btn small secondary"
                  key={template.label}
                  onClick={() => applyTemplate(template)}
                >
                  {template.label}
                </button>
              ))}
          </div>
        </div>
      )}
      <div className="grid cols-2">
        <div className="field">
          <label>Name</label>
          <input
            className="input"
            required
            maxLength={100}
            value={name}
            onChange={(event) => setName(event.target.value)}
          />
        </div>
        {!editing && hasChildren ? (
          <div className="field">
            <label>Who completes it</label>
            <select
              className="select"
              value={audience}
              onChange={(event) => {
                const next = event.target.value as OnboardingAudience;
                setAudience(next);
                setSteps((current) =>
                  current.filter((step) =>
                    (next === 'member' ? memberKinds : tenantKinds).includes(step.kind),
                  ),
                );
                setAddKind(next === 'member' ? 'form' : 'check');
              }}
            >
              <option value="member">People who join (member onboarding)</option>
              <option value="tenant">Administrators of new tenants below (setup checklist)</option>
            </select>
          </div>
        ) : (
          <div className="field">
            <label>Who completes it</label>
            <input
              className="input"
              readOnly
              value={
                audience === 'member' ? 'People who join' : 'Administrators of new tenants below'
              }
            />
          </div>
        )}
      </div>
      <div className="field">
        <label>
          Description <span className="muted">(optional)</span>
        </label>
        <textarea
          className="textarea"
          rows={2}
          value={description}
          onChange={(event) => setDescription(event.target.value)}
        />
      </div>
      {audience === 'member' && hasChildren && (
        <div className="field">
          <label>Reach</label>
          <select
            className="select"
            value={appliesTo}
            onChange={(event) => setAppliesTo(event.target.value as OnboardingScope)}
          >
            <option value="tenant">
              People of this {isRoot ? 'platform tenant' : 'tenant'} only
            </option>
            <option value="descendants">
              People of the tenants below ({descendantTypes.join(', ')})
            </option>
            <option value="subtree">Both</option>
          </select>
        </div>
      )}
      {effectiveScope !== 'tenant' && hasChildren && (
        <fieldset className="field">
          <label>Tenant types reached (none selected = all)</label>
          <div className="row">
            {descendantTypes.map((type) => (
              <label className="field inline" key={type}>
                <input
                  type="checkbox"
                  checked={tenantTypes.includes(type)}
                  onChange={(event) =>
                    setTenantTypes((current) =>
                      event.target.checked
                        ? [...current, type]
                        : current.filter((item) => item !== type),
                    )
                  }
                />
                <span>{type}</span>
              </label>
            ))}
          </div>
        </fieldset>
      )}
      <div className="row" style={{ flexWrap: 'wrap', gap: 16 }}>
        <label className="field inline">
          <input
            type="checkbox"
            checked={required}
            onChange={(event) => setRequired(event.target.checked)}
          />
          <span>Required</span>
        </label>
        {audience === 'member' && effectiveScope !== 'tenant' && (
          <label className="field inline" title="Tenants below cannot switch a locked flow off">
            <input
              type="checkbox"
              checked={locked}
              onChange={(event) => setLocked(event.target.checked)}
            />
            <span>Locked for tenants below</span>
          </label>
        )}
        <label className="field inline">
          <input
            type="checkbox"
            checked={includeExisting}
            onChange={(event) => setIncludeExisting(event.target.checked)}
          />
          <span>
            {audience === 'member' ? 'Also ask existing members' : 'Also ask existing tenants'}
          </span>
        </label>
        <label className="field inline">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(event) => setEnabled(event.target.checked)}
          />
          <span>Active</span>
        </label>
      </div>
      {reachesOwnPeople && groups.length > 0 && (
        <fieldset className="field">
          <label>When someone finishes, add them to</label>
          <div className="row" style={{ flexWrap: 'wrap' }}>
            {groups.map((group) => (
              <label className="field inline" key={group.id}>
                <input
                  type="checkbox"
                  checked={completionGroups.includes(group.id)}
                  onChange={(event) =>
                    setCompletionGroups((current) =>
                      event.target.checked
                        ? [...current, group.id]
                        : current.filter((item) => item !== group.id),
                    )
                  }
                />
                <span>{group.name}</span>
              </label>
            ))}
          </div>
        </fieldset>
      )}
      {audience === 'member' && (
        <details open={Boolean(rule)}>
          <summary className="small">Only for some people (targeting rule)</summary>
          <div className="field" style={{ marginTop: 8 }}>
            <textarea
              className="textarea mono"
              rows={4}
              value={rule}
              placeholder={
                '{ "include": [{ "StringEquals": { "principal.department": "Engineering" } }] }'
              }
              onChange={(event) => setRule(event.target.value)}
            />
            <span className="help">
              The access-package rule language: include clauses (any matches) and optional exclude
              clauses over principal.kind, principal.owner, identity.email, identity.emailDomain,
              identity.groups and declared attributes (
              {Object.keys(identityAttributes).join(', ') || 'none declared'}). Empty = everyone.
            </span>
          </div>
        </details>
      )}
      <div className="stack" style={{ gap: 8 }}>
        <h3 style={{ margin: 0 }}>Steps</h3>
        <ol className="onboarding-editor-steps">
          {steps.map((step, index) => (
            <StepEditor
              key={step.key}
              draft={step}
              index={index}
              count={steps.length}
              mapAttributes={reachesOwnPeople}
              attributes={identityAttributes}
              editing={editing}
              update={(change) => update(step.key, change)}
              move={(offset) => move(index, offset)}
              remove={() => setSteps((current) => current.filter((item) => item.key !== step.key))}
            />
          ))}
        </ol>
        <div className="row">
          <select
            className="select"
            value={addKind}
            onChange={(event) => setAddKind(event.target.value as OnboardingStepKind)}
            aria-label="Step kind"
            style={{ maxWidth: 280 }}
          >
            {kinds.map((kind) => (
              <option key={kind} value={kind}>
                {kindLabels[kind]}
              </option>
            ))}
          </select>
          <button
            type="button"
            className="btn small secondary"
            disabled={steps.length >= 25}
            onClick={() => setSteps((current) => [...current, blankStep(addKind)])}
          >
            Add step
          </button>
        </div>
      </div>
      {error && <div className="alert danger">{error}</div>}
      {saved && !error && (
        <div className="alert success">{editing ? 'Saved.' : 'Flow created.'}</div>
      )}
      <div className="form-actions">
        <button className="btn" disabled={busy || steps.length === 0}>
          {busy ? 'Saving…' : editing ? 'Save changes' : 'Create flow'}
        </button>
      </div>
    </form>
  );
}
