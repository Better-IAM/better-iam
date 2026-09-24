import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';
import { describeTrigger, stepSummary, triggerOptions } from '@/lib/workflows';

/** Starting points for the steps field: copy one, then replace the IDs with your own groups and packages. */
const examples = [
  {
    title: 'Joiner: welcome and base access',
    steps: [
      { kind: 'add-to-group', groupId: '<group id>' },
      {
        kind: 'send-email',
        to: 'manager',
        subject: '{name} joins {organization}',
        body: '{name} ({email}) starts in {attribute.department}. Their base access is ready.',
      },
    ],
  },
  {
    title: 'Mover: department change',
    steps: [{ kind: 'remove-from-all-groups' }, { kind: 'assign-package', packageId: '<package id>' }],
  },
  {
    title: 'Leaver: remove access now, delete after 30 days',
    steps: [
      { kind: 'revoke-sessions' },
      { kind: 'remove-from-all-groups' },
      { kind: 'revoke-packages' },
      { kind: 'emit-event', name: 'person.left' },
      { kind: 'wait', hours: 720 },
      { kind: 'delete' },
    ],
  },
];

export default async function Workflows({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const [workflows, runs, groups, packages] = await Promise.all([
    tryRead(() => iam.api.workflows.list(auth, { tenantId })),
    tryRead(() => iam.api.workflows.listRuns(auth, { tenantId, limit: 25 })),
    tryRead(() => iam.api.groups.list(auth, { tenantId })),
    tryRead(() => iam.api.packages.list(auth, { tenantId })),
  ]);
  return (
    <>
      <PageHeader
        title="Workflows"
        description="Joiner, mover and leaver automation. A workflow runs its steps for each person its trigger fires for, within its scope, with the rights of whoever saved it last; those rights are checked again at every step. A daily brake stops a workflow that would start more runs than expected."
        actions={
          workflows ? (
            <ApiButton
              path="workflows/evaluate"
              body={{ tenantId }}
              label="Run due now"
              tenantId={tenantId}
            />
          ) : undefined
        }
      />
      {!workflows ? (
        <Alert tone="warning">
          Requires <code>iam:workflows:read</code>.
        </Alert>
      ) : (
        <div className="stack">
          <Card title="Workflows" flush>
            <Table
              head={['Workflow', 'Trigger', 'Steps', 'Runs (30 days)', 'Owner', '']}
              rows={workflows.map((workflow) => [
                <span key="n">
                  <Link href={`${base}/workflows/${workflow.id}`}>{workflow.name}</Link>{' '}
                  {!workflow.enabled && <Badge>disabled</Badge>}
                  {workflow.brakedOn && <Badge tone="danger">braked {workflow.brakedOn}</Badge>}
                </span>,
                <span key="t" className="small">
                  {describeTrigger(workflow.trigger)}
                </span>,
                <span key="s" className="small">
                  {workflow.steps.map(stepSummary).join(' → ')}
                </span>,
                <span key="r" className="small">
                  {workflow.runs?.last30Days ?? 0}
                  {workflow.runs?.active ? ` · ${workflow.runs.active} active` : ''}
                  {workflow.runs?.failed ? (
                    <>
                      {' · '}
                      <Badge tone="danger">{workflow.runs.failed} failed</Badge>
                    </>
                  ) : null}
                </span>,
                <span key="o" className="small">
                  {workflow.ownerName ?? workflow.ownerId}
                </span>,
                <ApiButton
                  key="x"
                  path="workflows/update"
                  body={{ tenantId, workflowId: workflow.id, enabled: !workflow.enabled }}
                  label={workflow.enabled ? 'Disable' : 'Enable'}
                  tenantId={tenantId}
                />,
              ])}
              empty="No workflows yet."
            />
          </Card>

          <Card title="Recent runs" flush>
            <Table
              head={['Person', 'Workflow', 'Status', 'Started', 'Progress']}
              rows={(runs?.runs ?? []).map((run) => [
                <Link key="p" href={`${base}/members/${run.identityId}`}>
                  {run.identityName ?? run.identityId}
                </Link>,
                <Link key="w" href={`${base}/workflows/${run.workflowId}`}>
                  {run.workflowName}
                </Link>,
                <Badge
                  key="s"
                  tone={
                    run.status === 'completed'
                      ? 'success'
                      : run.status === 'failed'
                        ? 'danger'
                        : run.status === 'cancelled'
                          ? 'neutral'
                          : 'accent'
                  }
                >
                  {run.status}
                </Badge>,
                <Time key="t" value={run.startedAt} />,
                <span key="g" className="small">
                  {run.results.length}/{run.steps.length}
                  {run.error ? ` · ${run.error.code}` : ''}
                  {run.status === 'waiting' ? (
                    <>
                      {' · until '}
                      <Time value={run.nextAt} />
                    </>
                  ) : null}
                </span>,
              ])}
              empty="Nothing has run yet."
            />
          </Card>

          <Card
            title="New workflow"
            description="You become its owner: you must hold every right its steps use. Mover and leaver workflows start from everyone's current values, so only later changes fire."
          >
            <ApiForm
              path="workflows/create"
              tenantId={tenantId}
              submitLabel="Create workflow"
              redirectTo={`${base}/workflows/{id}`}
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'name', label: 'Name', required: true, placeholder: 'Engineering joiners' },
                { name: 'description', label: 'Description' },
                {
                  name: 'kind',
                  label: 'Trigger',
                  type: 'select',
                  required: true,
                  options: triggerOptions,
                  group: 'trigger',
                },
                {
                  name: 'attributes',
                  label: 'Mover: attributes to watch',
                  type: 'list',
                  placeholder: 'department, managerId',
                  group: 'trigger',
                },
                {
                  name: 'attribute',
                  label: 'Date: attribute holding the date',
                  placeholder: 'startDate, createdAt or expiresAt',
                  group: 'trigger',
                },
                {
                  name: 'offsetDays',
                  label: 'Date: days after it (negative for before)',
                  type: 'number',
                  group: 'trigger',
                },
                {
                  name: 'scope',
                  label: 'Scope (rule conditions; empty = every active person)',
                  type: 'json',
                  rows: 4,
                  placeholder: '{ "include": [{ "StringEquals": { "principal.department": "Engineering" } }] }',
                },
                {
                  name: 'steps',
                  label: 'Steps',
                  type: 'json',
                  required: true,
                  rows: 10,
                  defaultValue: JSON.stringify(examples[0]!.steps, null, 2),
                },
                {
                  name: 'includeExisting',
                  label: 'Joiner: also run for people who are already here',
                  type: 'checkbox',
                },
                { name: 'maxRunsPerDay', label: 'Daily brake (runs per day)', type: 'number' },
              ]}
            />
          </Card>

          <Card
            title="Step reference"
            description="add-to-group {groupId, days?} · remove-from-group {groupId} · remove-from-all-groups · assign-package {packageId, days?} · revoke-packages {packageId?} · send-email {to: subject|manager|address, subject, body} · revoke-sessions · disable · enable · set-attributes {attributes} · set-expiry {days|null} · delete (last) · emit-event {name} · wait {hours}. Emails fill {name}, {email}, {organization}, {workflow} and {attribute.<name>}."
          >
            <div className="stack">
              {examples.map((example) => (
                <details key={example.title}>
                  <summary className="small">{example.title}</summary>
                  <pre className="result">{JSON.stringify(example.steps, null, 2)}</pre>
                </details>
              ))}
              {groups && groups.length > 0 && (
                <details>
                  <summary className="small">Group IDs</summary>
                  <Table
                    head={['Group', 'ID']}
                    rows={groups.map((group) => [group.name, <code key="i">{group.id}</code>])}
                  />
                </details>
              )}
              {packages && packages.length > 0 && (
                <details>
                  <summary className="small">Package IDs</summary>
                  <Table
                    head={['Package', 'ID']}
                    rows={packages.map((item) => [item.name, <code key="i">{item.id}</code>])}
                  />
                </details>
              )}
            </div>
          </Card>
        </div>
      )}
    </>
  );
}
