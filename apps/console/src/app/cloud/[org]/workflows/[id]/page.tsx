import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, KeyValues, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';
import { describeTrigger, stepSummary } from '@/lib/workflows';

export default async function WorkflowPage({
  params,
}: {
  params: Promise<{ org: string; id: string }>;
}) {
  const { org, id } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const [workflow, preview, people] = await Promise.all([
    tryRead(() => iam.api.workflows.get(auth, { tenantId, workflowId: id })),
    tryRead(() => iam.api.workflows.preview(auth, { tenantId, workflowId: id })),
    tryRead(() => iam.api.identities.list(auth, { tenantId })),
  ]);
  if (!workflow)
    return (
      <>
        <PageHeader title="Workflow" />
        <Alert tone="warning">
          Not found, or requires <code>iam:workflows:read</code>.
        </Alert>
      </>
    );
  const personOptions = (people ?? [])
    .filter((person) => person.kind === 'user' && person.status !== 'deleted')
    .map((person) => ({ value: person.id, label: person.email ?? person.name }));
  return (
    <>
      <PageHeader
        title={
          <span className="row">
            {workflow.name} <Badge>v{workflow.version}</Badge>
            {workflow.enabled ? <Badge tone="success">enabled</Badge> : <Badge>disabled</Badge>}
          </span>
        }
        description={<Link href={`${base}/workflows`}>← All workflows</Link>}
        actions={
          <ApiButton
            path="workflows/delete"
            body={{ tenantId, workflowId: workflow.id }}
            label="Delete"
            tone="danger"
            confirm={`Delete "${workflow.name}"? Its pending and waiting runs are cancelled.`}
            redirectTo={`${base}/workflows`}
            tenantId={tenantId}
          />
        }
      />
      <div className="stack">
        {workflow.brakedOn && (
          <Alert tone="danger">
            The daily brake stopped this workflow on {workflow.brakedOn}: it would have started more
            than {workflow.maxRunsPerDay} runs. Check the changes that triggered it, then raise the
            limit below if they are expected.
          </Alert>
        )}
        <Card title="Definition">
          <KeyValues
            items={[
              ['Trigger', describeTrigger(workflow.trigger)],
              ['Steps', workflow.steps.map(stepSummary).join(' → ')],
              [
                'Scope',
                workflow.scope ? (
                  <code key="s" className="small">
                    {JSON.stringify(workflow.scope)}
                  </code>
                ) : (
                  'every active person'
                ),
              ],
              ['Owner', workflow.ownerName ?? workflow.ownerId],
              ['Daily brake', `${workflow.maxRunsPerDay} runs`],
              ['Active since', <Time key="a" value={workflow.activeSince} />],
            ]}
          />
          {workflow.description && <p className="small muted">{workflow.description}</p>}
        </Card>

        {preview && (
          <Card
            title="Preview"
            description="What the workflow would do at the next evaluation. Nothing here has run."
          >
            <KeyValues
              items={[
                ['In scope now', `${preview.inScope.length} people`],
                [
                  'Would start now',
                  preview.wouldStart.length
                    ? preview.wouldStart.map((item) => item.name).join(', ')
                    : 'nobody',
                ],
                ...(workflow.trigger.kind === 'date'
                  ? ([
                      [
                        'Coming up (30 days)',
                        preview.upcoming.length
                          ? preview.upcoming
                              .map((item) => `${item.name} (${new Date(item.at).toISOString().slice(0, 10)})`)
                              .join(', ')
                          : 'nobody',
                      ],
                    ] as [string, string][])
                  : []),
              ]}
            />
            <Table
              head={['Step', 'Owner may do it']}
              rows={preview.steps.map((step) => [
                <span key="k">
                  {step.index + 1}. {stepSummary(workflow.steps[step.index]!)}
                </span>,
                step.allowed ? (
                  <Badge key="a" tone="success">
                    yes
                  </Badge>
                ) : (
                  <span key="a" className="small">
                    <Badge tone="danger">no</Badge> {step.reason}
                  </span>
                ),
              ])}
            />
          </Card>
        )}

        <Card
          title="Run now"
          description="Runs the workflow for the people you choose, whatever its trigger and scope. You need the steps' rights over each of them."
        >
          <ApiForm
            path="workflows/run"
            tenantId={tenantId}
            submitLabel="Run"
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
              { name: 'workflowId', label: 'Workflow', type: 'hidden', defaultValue: workflow.id },
              {
                name: 'identityIds',
                label: 'People',
                type: 'multiselect',
                required: true,
                options: personOptions,
              },
            ]}
          />
        </Card>

        <Card title="Runs" flush>
          <Table
            head={['Person', 'Status', 'Started', 'Steps', '']}
            rows={workflow.recentRuns.map((run) => [
              <Link key="p" href={`${base}/members/${run.identityId}`}>
                {run.identityName ?? run.identityId}
              </Link>,
              <span key="s">
                <Badge
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
                </Badge>
                {run.error && <span className="small"> {run.error.message}</span>}
                {run.status === 'waiting' && (
                  <span className="small">
                    {' '}
                    until <Time value={run.nextAt} />
                  </span>
                )}
              </span>,
              <span key="t" className="small">
                <Time value={run.startedAt} /> · {run.occurrence.split(':')[0]}
              </span>,
              <span key="r" className="small">
                {run.results
                  .map((result) => `${result.kind}: ${result.outcome}${result.detail ? ` (${result.detail})` : ''}`)
                  .join('; ') || '—'}
              </span>,
              run.status === 'failed' ? (
                <span key="x" className="row">
                  <ApiButton
                    path="workflows/retryRun"
                    body={{ tenantId, runId: run.id }}
                    label="Retry"
                    tenantId={tenantId}
                  />
                  <ApiButton
                    path="workflows/cancelRun"
                    body={{ tenantId, runId: run.id }}
                    label="Cancel"
                    tenantId={tenantId}
                  />
                </span>
              ) : run.status === 'pending' || run.status === 'waiting' ? (
                <ApiButton
                  key="x"
                  path="workflows/cancelRun"
                  body={{ tenantId, runId: run.id }}
                  label="Cancel"
                  confirm="Cancel this run? Steps already done stay done."
                  tenantId={tenantId}
                />
              ) : (
                <span key="x" />
              ),
            ])}
            empty="No runs yet."
          />
        </Card>

        <Card
          title="Edit"
          description="Saving makes you the owner (you need every step's rights). Runs already started keep their steps."
        >
          <ApiForm
            path="workflows/update"
            tenantId={tenantId}
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
              { name: 'workflowId', label: 'Workflow', type: 'hidden', defaultValue: workflow.id },
              { name: 'name', label: 'Name', required: true, defaultValue: workflow.name },
              {
                name: 'description',
                label: 'Description',
                defaultValue: workflow.description ?? '',
              },
              {
                name: 'steps',
                label: 'Steps',
                type: 'json',
                rows: 10,
                defaultValue: JSON.stringify(workflow.steps, null, 2),
              },
              {
                name: 'scope',
                label: 'Scope (empty keeps it; null clears it)',
                type: 'json',
                rows: 4,
                defaultValue: workflow.scope ? JSON.stringify(workflow.scope, null, 2) : '',
              },
              {
                name: 'maxRunsPerDay',
                label: 'Daily brake (runs per day)',
                type: 'number',
                defaultValue: workflow.maxRunsPerDay,
              },
              {
                name: 'enabled',
                label: 'Enabled',
                type: 'checkbox',
                defaultValue: workflow.enabled,
              },
            ]}
          />
        </Card>
      </div>
    </>
  );
}
