import Link from 'next/link';
import type { InvariantSubject } from 'better-iam/server';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Stat, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Invariants({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const [invariants, run] = await Promise.all([
    tryRead(() => iam.api.invariants.list(auth, { tenantId })),
    tryRead(() => iam.api.invariants.run(auth, { tenantId })),
  ]);
  const results = new Map((run?.results ?? []).map((result) => [result.invariant.id, result]));
  const subject = (value: InvariantSubject) =>
    'identityId' in value ? (
      <Link href={`${base}/members/${value.identityId}`}>one person</Link>
    ) : 'groupId' in value ? (
      <Link href={`${base}/groups/${value.groupId}`}>members of a group</Link>
    ) : 'attribute' in value ? (
      <span>
        everyone with <code>{value.attribute.name}</code> ={' '}
        <code>{String(value.attribute.value)}</code>
      </span>
    ) : (
      <span>everyone</span>
    );
  return (
    <>
      <PageHeader
        title="Access invariants"
        description="Guardrails over who may, or must never, perform an action on a resource. Monitored invariants are reported here; enforced ones also refuse any role, policy, binding, group, package, or configuration change that would newly break them."
      />
      {!invariants || !run ? (
        <Alert tone="warning">
          Requires <code>iam:invariants:read</code>.
        </Alert>
      ) : (
        <div className="stack">
          <div className="grid cols-4">
            <Stat label="Invariants" value={invariants.length} />
            <Stat label="Passing" value={run.summary.passed} />
            <Stat label="Broken" value={run.summary.failed} />
            <Stat label="Cannot evaluate" value={run.summary.errors} />
          </div>
          <Card
            title="Invariants"
            description={
              <>
                Evaluated <Time value={run.generatedAt} /> against the current configuration.
              </>
            }
            flush
          >
            <Table
              head={['Invariant', 'Who', 'Rule', 'Mode', 'Status', '']}
              rows={invariants.map((invariant) => {
                const result = results.get(invariant.id);
                return [
                  <span key="n" className="stack">
                    <strong>{invariant.name}</strong>
                    {invariant.description && (
                      <span className="small muted">{invariant.description}</span>
                    )}
                  </span>,
                  <span key="w" className="small">
                    {subject(invariant.subject)}
                  </span>,
                  <span key="r" className="small">
                    {invariant.expect === 'deny' ? 'must never' : 'must always be able to'}{' '}
                    <code>{invariant.action}</code> on{' '}
                    <code>
                      {invariant.resource.type}/{invariant.resource.id}
                    </code>
                  </span>,
                  <Badge key="m" tone={invariant.mode === 'enforce' ? 'accent' : 'neutral'}>
                    {invariant.mode}
                  </Badge>,
                  !result ? (
                    <span key="s" className="muted">
                      —
                    </span>
                  ) : result.error ? (
                    <span key="s" className="stack small">
                      <Badge tone="warning">error</Badge>
                      <span className="muted">{result.error.message}</span>
                    </span>
                  ) : result.passed ? (
                    <span key="s" className="small">
                      <Badge tone="success">passing</Badge> {result.evaluated} checked
                    </span>
                  ) : (
                    <span key="s" className="stack small">
                      <Badge tone="danger">broken</Badge>
                      {result.violations.slice(0, 5).map((violation) => (
                        <span key={violation.identity.id}>
                          <Link href={`${base}/members/${violation.identity.id}`}>
                            {violation.identity.name}
                          </Link>{' '}
                          <span className="muted">({violation.reason})</span>
                        </span>
                      ))}
                      {result.violations.length > 5 && (
                        <span className="muted">and {result.violations.length - 5} more</span>
                      )}
                    </span>
                  ),
                  <span key="a" className="row">
                    <ApiButton
                      path="invariants/update"
                      body={{
                        tenantId,
                        invariantId: invariant.id,
                        mode: invariant.mode === 'enforce' ? 'monitor' : 'enforce',
                      }}
                      label={invariant.mode === 'enforce' ? 'Monitor only' : 'Enforce'}
                      tenantId={tenantId}
                    />
                    <ApiButton
                      path="invariants/delete"
                      body={{ tenantId, invariantId: invariant.id }}
                      label="Delete"
                      tone="danger"
                      confirm={`Delete the invariant "${invariant.name}"?`}
                      tenantId={tenantId}
                    />
                  </span>,
                ];
              })}
              empty="No invariants yet."
            />
          </Card>
          <Card title="New invariant">
            <ApiForm
              path="invariants/create"
              tenantId={tenantId}
              submitLabel="Create"
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'name', label: 'Name', required: true },
                { name: 'description', label: 'Description' },
                {
                  name: 'subject',
                  label: 'Who',
                  type: 'json',
                  rows: 2,
                  required: true,
                  defaultValue: '{ "everyone": true }',
                  help: 'One of { "everyone": true }, { "identityId": "…" }, { "groupId": "…" }, or { "attribute": { "name": "department", "value": "Sales" } }.',
                },
                {
                  name: 'expect',
                  label: 'Rule',
                  type: 'select',
                  required: true,
                  options: [
                    { value: 'deny', label: 'Must never be allowed' },
                    { value: 'allow', label: 'Must always be allowed' },
                  ],
                },
                {
                  name: 'action',
                  label: 'Action',
                  required: true,
                  placeholder: 'documents:delete',
                },
                {
                  name: 'type',
                  label: 'Resource type',
                  required: true,
                  group: 'resource',
                  placeholder: 'workspace',
                },
                { name: 'id', label: 'Resource ID', required: true, group: 'resource' },
                {
                  name: 'mode',
                  label: 'Mode',
                  type: 'select',
                  required: true,
                  options: [
                    { value: 'monitor', label: 'Monitor (report only)' },
                    { value: 'enforce', label: 'Enforce (refuse changes that break it)' },
                  ],
                },
              ]}
            />
          </Card>
        </div>
      )}
    </>
  );
}
