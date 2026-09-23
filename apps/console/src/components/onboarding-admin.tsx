import 'server-only';
import Link from 'next/link';
import type { OnboardingFlow } from 'better-iam/server';
import { ApiButton, ApiForm } from '@/components/api-form';
import { OnboardingFlowEditor } from '@/components/onboarding-flow-editor';
import { Alert, Badge, Card, KeyValues, Table, Time } from '@/components/ui';
import type { Iam } from '@/lib/iam';
import { tryRead, type credential } from '@/lib/session';

type Credential = Awaited<ReturnType<typeof credential>>;

const kindNames: Record<string, string> = {
  form: 'Form',
  acknowledge: 'Read and confirm',
  task: 'Task',
  agreement: 'Terms of use',
  'verify-email': 'Verify email',
  mfa: 'Two-step verification',
  passkey: 'Passkey',
  check: 'Setup check',
};

const levelName = (source: { type: string; name: string }) =>
  source.type === 'root' ? 'Platform' : source.name;

function reach(flow: OnboardingFlow): string {
  if (flow.audience === 'tenant')
    return `Setup checklist for new ${flow.tenantTypes ? `${flow.tenantTypes.join(' / ')} ` : ''}tenants below`;
  const types = flow.tenantTypes ? ` (${flow.tenantTypes.join(', ')})` : '';
  return flow.appliesTo === 'tenant'
    ? 'People of this tenant'
    : flow.appliesTo === 'descendants'
      ? `People of tenants below${types}`
      : `People here and below${types}`;
}

function StepList({ flow }: { flow: OnboardingFlow }) {
  return (
    <Table
      head={['#', 'Step', 'Kind', '']}
      rows={flow.steps.map((step, index) => [
        index + 1,
        <span key="title">
          {step.title} <span className="muted small mono">{step.id}</span>
        </span>,
        kindNames[step.kind] ?? step.kind,
        step.optional ? <Badge key="optional">optional</Badge> : '',
      ])}
    />
  );
}

/**
 * Onboarding administration for one tenant level (the platform root, an organization, or a project): the welcome
 * screen, the flows defined here, what is inherited from above, and a builder for new flows.
 */
export async function OnboardingAdmin({
  iam,
  auth,
  tenantId,
  isRoot,
  progressBase,
  setupHref,
}: {
  iam: Iam;
  auth: Credential;
  tenantId: string;
  isRoot: boolean;
  /** Progress pages live at `{progressBase}/{flowId}`. */
  progressBase: string;
  /** The tenant's own setup checklist page (not for the root). */
  setupHref?: string;
}) {
  const [effective, groups] = await Promise.all([
    tryRead(() => iam.api.onboarding.effective(auth, { tenantId })),
    tryRead(() => iam.api.groups.list(auth, { tenantId })),
  ]);
  if (!effective)
    return (
      <Alert tone="warning">
        Requires <code>iam:onboarding:read</code>.
      </Alert>
    );
  const inherited = effective.memberFlows.filter((item) => item.inherited);
  const switchable = inherited.filter((item) => item.canDisable);
  const own = effective.settings.own;
  const resolved = effective.settings.resolved;
  const inheritedValue = (
    key: 'welcomeTitle' | 'welcomeMessage' | 'supportEmail' | 'supportUrl',
  ) => {
    const source = resolved.sources[key];
    return source && source.tenantId !== tenantId ? resolved[key] : undefined;
  };
  const editor = (flow?: OnboardingFlow) => (
    <OnboardingFlowEditor
      tenantId={tenantId}
      isRoot={isRoot}
      descendantTypes={effective.descendantTypes}
      identityAttributes={effective.identityAttributes}
      groups={(groups ?? []).map((group) => ({ id: group.id, name: group.name }))}
      flow={flow}
    />
  );
  return (
    <div className="stack">
      <Card
        title="Levels"
        description="Flows and welcome settings pass down the tenant tree. Each level adds its own and may switch off the unlocked flows it inherits."
      >
        <div className="row" style={{ flexWrap: 'wrap' }}>
          {effective.levels.map((level, index) => (
            <span className="row" key={level.tenantId}>
              {index > 0 && <span className="muted">→</span>}
              <Badge tone={level.tenantId === tenantId ? 'accent' : 'neutral'}>
                {levelName(level)} <span className="muted">· {level.type}</span>
              </Badge>
            </span>
          ))}
          {effective.descendantTypes.length > 0 && (
            <span className="small muted">
              → {effective.descendantTypes.join(', ')} tenants below
            </span>
          )}
        </div>
      </Card>

      <Card
        title="Welcome screen"
        description="Shown above the Get started checklist. Leave a field empty to use the value from the level above."
      >
        <ApiForm
          path="onboarding/setSettings"
          tenantId={tenantId}
          submitLabel="Save welcome screen"
          successMessage="Saved."
          fields={[
            { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
            {
              name: 'welcomeTitle',
              label: 'Title',
              defaultValue: own?.welcomeTitle ?? '',
              placeholder: inheritedValue('welcomeTitle') ?? 'Welcome aboard',
            },
            {
              name: 'welcomeMessage',
              label: 'Message',
              type: 'textarea',
              rows: 3,
              defaultValue: own?.welcomeMessage ?? '',
              placeholder: inheritedValue('welcomeMessage') ?? 'What newcomers should know first.',
            },
            {
              name: 'supportEmail',
              label: 'Support email',
              type: 'email',
              defaultValue: own?.supportEmail ?? '',
              placeholder: inheritedValue('supportEmail'),
            },
            {
              name: 'supportUrl',
              label: 'Help page',
              defaultValue: own?.supportUrl ?? '',
              placeholder: inheritedValue('supportUrl') ?? 'https://',
            },
            ...(switchable.length
              ? [
                  {
                    name: 'disabledFlowIds',
                    label: 'Inherited flows switched off here (and below)',
                    type: 'multiselect' as const,
                    defaultValue: own?.disabledFlowIds ?? [],
                    options: switchable.map((item) => ({
                      value: item.flow.id,
                      label: `${item.flow.name} (${levelName(item.source)})`,
                    })),
                    help: 'Locked flows are not listed: the level that defines them requires them.',
                  },
                ]
              : []),
          ]}
        />
      </Card>

      {effective.setupFlows.length > 0 && setupHref && (
        <Card
          title="Setup checklists for this tenant"
          description="Defined by the levels above; this tenant's administrators complete them."
          actions={
            <Link className="btn small" href={setupHref}>
              Open setup
            </Link>
          }
          flush
        >
          <Table
            head={['Checklist', 'From', 'Steps']}
            rows={effective.setupFlows.map((item) => [
              item.flow.name,
              levelName(item.source),
              item.flow.steps.length,
            ])}
          />
        </Card>
      )}

      {inherited.length > 0 && (
        <Card
          title="Inherited member onboarding"
          description="Flows from the levels above that reach this tenant's people."
          flush
        >
          <Table
            head={['Flow', 'From', 'Steps', 'Status', '']}
            rows={inherited.map((item) => [
              <span key="name" className="stack" style={{ gap: 2 }}>
                <strong>{item.flow.name}</strong>
                {item.flow.description && (
                  <span className="small muted">{item.flow.description}</span>
                )}
              </span>,
              levelName(item.source),
              item.flow.steps.length,
              <span key="status" className="row">
                {item.flow.required ? (
                  <Badge tone="accent">required</Badge>
                ) : (
                  <Badge>optional</Badge>
                )}
                {item.flow.locked && <Badge tone="warning">locked</Badge>}
                {item.disabledBy && (
                  <Badge tone="danger">
                    off
                    {item.disabledBy.tenantId === tenantId
                      ? ' here'
                      : ` (${levelName(item.disabledBy)})`}
                  </Badge>
                )}
              </span>,
              <Link
                key="progress"
                className="btn small secondary"
                href={`${progressBase}/${item.flow.id}`}
              >
                Progress
              </Link>,
            ])}
          />
        </Card>
      )}

      {effective.ownFlows.length === 0 ? (
        <Card title="Flows defined here">
          <div className="empty">No flows yet. Build one below, or start from a template.</div>
        </Card>
      ) : (
        effective.ownFlows.map((flow) => (
          <Card
            key={flow.id}
            title={
              <span className="row" style={{ flexWrap: 'wrap' }}>
                {flow.name}
                <Badge tone={flow.audience === 'member' ? 'info' : 'accent'}>
                  {flow.audience === 'member' ? 'member onboarding' : 'tenant setup'}
                </Badge>
                {flow.required ? <Badge tone="accent">required</Badge> : <Badge>optional</Badge>}
                {flow.locked && <Badge tone="warning">locked</Badge>}
                {!flow.enabled && <Badge tone="danger">paused</Badge>}
                <Badge>v{flow.version}</Badge>
              </span>
            }
            description={
              <>
                {reach(flow)}
                {flow.includeExisting ? ' · existing ones too' : ' · newcomers only'}
                {flow.rule ? ' · targeted' : ''}
                {flow.completionGroupIds?.length
                  ? ` · joins ${flow.completionGroupIds.length} group${flow.completionGroupIds.length === 1 ? '' : 's'} on completion`
                  : ''}
                {' · updated '}
                <Time value={flow.updatedAt} />
              </>
            }
            actions={
              <>
                <Link className="btn small secondary" href={`${progressBase}/${flow.id}`}>
                  Progress
                </Link>
                <ApiButton
                  path="onboarding/updateFlow"
                  body={{ tenantId, flowId: flow.id, enabled: !flow.enabled }}
                  label={flow.enabled ? 'Pause' : 'Resume'}
                  tenantId={tenantId}
                />
                <ApiButton
                  path="onboarding/deleteFlow"
                  body={{ tenantId, flowId: flow.id }}
                  label="Delete"
                  tone="danger"
                  confirm={`Delete "${flow.name}" and everyone's progress through it?`}
                  tenantId={tenantId}
                />
              </>
            }
          >
            <div className="stack">
              {flow.description && (
                <p className="small" style={{ whiteSpace: 'pre-wrap', margin: 0 }}>
                  {flow.description}
                </p>
              )}
              <StepList flow={flow} />
              <details>
                <summary className="small">Edit flow</summary>
                <div style={{ marginTop: 12 }}>{editor(flow)}</div>
              </details>
            </div>
          </Card>
        ))
      )}

      <Card
        title="New flow"
        description={
          effective.descendantTypes.length
            ? 'Onboard this tenant’s people, the people of tenants below it, or give new tenants below a setup checklist.'
            : 'Onboard the people who join this tenant.'
        }
      >
        {editor()}
      </Card>
    </div>
  );
}

function Answers({
  answers,
  titles,
}: {
  answers?: Record<string, Record<string, unknown>>;
  titles: Map<string, string>;
}) {
  if (!answers) return <span className="muted">—</span>;
  return (
    <details>
      <summary className="small">Answers</summary>
      <KeyValues
        items={Object.entries(answers).flatMap(([stepId, values]) =>
          Object.entries(values).map(([key, value]): [string, string] => [
            `${titles.get(stepId) ?? stepId} · ${key}`,
            typeof value === 'boolean' ? (value ? 'Yes' : 'No') : String(value),
          ]),
        )}
      />
    </details>
  );
}

function Meter({ done, total }: { done: number; total: number }) {
  const percent = total ? Math.round((done / total) * 100) : 100;
  return (
    <span className="stack" style={{ gap: 2, minWidth: 110 }}>
      <span className={`meter ${percent === 100 ? 'success' : ''}`}>
        <span style={{ width: `${percent}%` }} />
      </span>
      <span className="small muted">
        {done}/{total}
      </span>
    </span>
  );
}

/** Progress through one flow as this tenant sees it, with verification and reset actions. */
export async function OnboardingReport({
  iam,
  auth,
  tenantId,
  flowId,
}: {
  iam: Iam;
  auth: Credential;
  tenantId: string;
  flowId: string;
}) {
  const [report, effective] = await Promise.all([
    tryRead(() => iam.api.onboarding.progress(auth, { tenantId, flowId })),
    tryRead(() => iam.api.onboarding.effective(auth, { tenantId })),
  ]);
  if (!report)
    return (
      <Alert tone="warning">
        This flow does not reach this tenant, or reading progress requires{' '}
        <code>iam:onboarding:read</code>.
      </Alert>
    );
  const flow =
    effective?.ownFlows.find((item) => item.id === flowId) ??
    effective?.memberFlows.find((item) => item.flow.id === flowId)?.flow;
  const titles = new Map((flow?.steps ?? []).map((step) => [step.id, step.title]));
  const definer = report.flow.source.tenantId === tenantId;
  const verify = (subjectId: string, stepId: string) => (
    <span className="row" key={`${subjectId}:${stepId}`}>
      <span className="small">{titles.get(stepId) ?? stepId}</span>
      <ApiButton
        path="onboarding/verifyStep"
        body={{ tenantId, flowId, subjectId, stepId }}
        label="Approve"
        tone="primary"
        tenantId={tenantId}
      />
      <ApiButton
        path="onboarding/verifyStep"
        body={{
          tenantId,
          flowId,
          subjectId,
          stepId,
          approve: false,
          note: 'Please take another look.',
        }}
        label="Send back"
        tenantId={tenantId}
      />
    </span>
  );
  const status = (row: {
    complete: boolean;
    awaiting: string[];
    startedAt?: number;
    completionError?: string;
  }) => (
    <span className="row">
      {row.complete ? (
        <Badge tone="success">complete</Badge>
      ) : row.awaiting.length ? (
        <Badge tone="warning">waiting for review</Badge>
      ) : row.startedAt ? (
        <Badge tone="info">in progress</Badge>
      ) : (
        <Badge>not started</Badge>
      )}
      {row.completionError && (
        <span className="badge danger" title={row.completionError}>
          groups not applied
        </span>
      )}
    </span>
  );
  const summary = report.summary;
  return (
    <div className="stack">
      <div className="grid cols-4">
        <div className="card stat">
          <span className="label">From</span>
          <span className="value" style={{ fontSize: 18 }}>
            {levelName(report.flow.source)}
          </span>
          <span className="hint">{report.flow.inherited ? 'inherited' : 'defined here'}</span>
        </div>
        <div className="card stat">
          <span className="label">{report.flow.audience === 'tenant' ? 'Tenants' : 'People'}</span>
          <span className="value">{summary.subjects}</span>
        </div>
        <div className="card stat">
          <span className="label">Complete</span>
          <span className="value">{summary.complete}</span>
          <span className="hint">
            {summary.subjects ? Math.round((summary.complete / summary.subjects) * 100) : 0}%
          </span>
        </div>
        <div className="card stat">
          <span className="label">Version</span>
          <span className="value">v{report.flow.version}</span>
          <span className="hint">{report.flow.required ? 'required' : 'optional'}</span>
        </div>
      </div>
      {report.flow.disabledBy && (
        <Alert tone="warning">
          Switched off for this tenant by {levelName(report.flow.disabledBy)}.
        </Alert>
      )}
      {report.members && (report.members.length > 0 || report.flow.audience === 'member') && (
        <Card title="People" description="This tenant's people the flow applies to." flush>
          <Table
            head={['Member', 'Progress', 'Status', 'Waiting for review', 'Answers', '']}
            empty="Nobody here is asked to complete this flow."
            rows={report.members.map((row) => [
              <span key="who" className="stack" style={{ gap: 2 }}>
                <strong>{row.identity.name}</strong>
                <span className="small muted">{row.identity.email}</span>
              </span>,
              <Meter key="meter" done={row.done} total={row.total} />,
              status(row),
              row.awaiting.length ? (
                <span key="verify" className="stack" style={{ gap: 4 }}>
                  {row.awaiting.map((stepId) => verify(row.identity.id, stepId))}
                </span>
              ) : (
                <span className="muted">—</span>
              ),
              <Answers key="answers" answers={row.answers} titles={titles} />,
              row.startedAt ? (
                <ApiButton
                  path="onboarding/resetProgress"
                  body={{ tenantId, flowId, subjectId: row.identity.id }}
                  label="Reset"
                  confirm={`Start ${row.identity.name}'s onboarding over?`}
                  tenantId={tenantId}
                />
              ) : (
                ''
              ),
            ])}
          />
        </Card>
      )}
      {report.descendants && (
        <Card
          title="Tenants below"
          description="Counts only: people's names stay with their own tenant."
          flush
        >
          <Table
            head={['Tenant', 'Type', 'People', 'Complete']}
            empty="No tenant below has people this flow applies to yet."
            rows={report.descendants.map((row) => [
              row.tenant.name,
              row.tenant.type,
              row.people,
              row.people ? (
                <Meter key="meter" done={row.complete} total={row.people} />
              ) : (
                <span key="none" className="muted">
                  —
                </span>
              ),
            ])}
          />
        </Card>
      )}
      {report.tenants && (
        <Card title="Tenants setting up" flush>
          <Table
            head={['Tenant', 'Progress', 'Status', 'Waiting for review', 'Answers', 'Completed']}
            empty="No tenant is asked to complete this checklist yet."
            rows={report.tenants.map((row) => [
              <span key="who" className="stack" style={{ gap: 2 }}>
                <strong>{row.tenant.name}</strong>
                <span className="small muted">
                  {row.tenant.type} · {row.tenant.status}
                </span>
              </span>,
              <Meter key="meter" done={row.done} total={row.total} />,
              status(row),
              row.awaiting.length ? (
                <span key="verify" className="stack" style={{ gap: 4 }}>
                  {row.awaiting.map((stepId) => verify(row.tenant.tenantId, stepId))}
                </span>
              ) : (
                <span className="muted">—</span>
              ),
              <Answers key="answers" answers={row.answers} titles={titles} />,
              <Time key="time" value={row.completedAt} />,
            ])}
          />
        </Card>
      )}
      {report.truncated && <Alert tone="info">Showing the first 1000 tenants below.</Alert>}
      {definer && (
        <Card
          title="Start over"
          description="Clears everyone's progress through this flow; they go through it again."
        >
          <ApiButton
            path="onboarding/resetProgress"
            body={{ tenantId, flowId }}
            label="Reset everyone's progress"
            tone="danger"
            confirm="Reset everyone's progress through this flow?"
            tenantId={tenantId}
          />
        </Card>
      )}
    </div>
  );
}
