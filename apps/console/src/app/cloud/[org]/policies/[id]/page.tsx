import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, Json, PageHeader, Table } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Policy({ params }: { params: Promise<{ org: string; id: string }> }) {
  const { org, id } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const policy = await tryRead(() => iam.api.policies.get(auth, { tenantId, policyId: id }));
  if (!policy) notFound();
  const [versions, lint] = await Promise.all([
    tryRead(() => iam.api.policies.listVersions(auth, { tenantId, policyId: id })),
    tryRead(() => iam.api.analysis.lintPolicy(auth, { tenantId, policyId: id })),
  ]);
  const protectedPolicy = policy.uniqueKey === 'system:owner';
  return (
    <>
      <PageHeader
        title={
          <>
            {policy.name} <Badge>v{policy.version}</Badge>
            {protectedPolicy && <Badge tone="warning">protected</Badge>}
          </>
        }
        description={
          <>
            {policy.description ?? 'Policy'} · <Link href={`${base}/policies`}>all policies</Link>
          </>
        }
        actions={
          !protectedPolicy && (
            <ApiButton
              path="policies/delete"
              body={{ tenantId, policyId: id }}
              label="Delete policy"
              tone="danger"
              confirm="Delete this policy? It must not be attached to any role."
              redirectTo={`${base}/policies`}
              tenantId={tenantId}
            />
          )
        }
      />
      <div className="stack">
        {protectedPolicy && (
          <Alert tone="warning">The Owner policy is protected and cannot be edited.</Alert>
        )}
        <div className="grid cols-2">
          <Card title="Current document">
            <Json value={policy.document} />
          </Card>
          <Card
            title="Update"
            description="Optimistic concurrency: the update must name the current version. Previous versions are retained."
          >
            {protectedPolicy ? (
              <p className="muted">Not editable.</p>
            ) : (
              <ApiForm
                path="policies/update"
                tenantId={tenantId}
                submitLabel={`Save as v${policy.version + 1}`}
                successMessage="Policy updated."
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'policyId', label: 'Policy', type: 'hidden', defaultValue: id },
                  {
                    name: 'version',
                    label: 'Version',
                    type: 'number',
                    required: true,
                    defaultValue: String(policy.version),
                    help: 'Must equal the current version.',
                  },
                  { name: 'name', label: 'Name', defaultValue: policy.name },
                  {
                    name: 'description',
                    label: 'Description',
                    defaultValue: policy.description ?? '',
                  },
                  {
                    name: 'document',
                    label: 'Policy document',
                    type: 'json',
                    rows: 12,
                    defaultValue: JSON.stringify(policy.document, null, 2),
                  },
                ]}
              />
            )}
          </Card>
        </div>
        <Card
          title="Lint"
          description="Statements that are valid but probably not what you meant: conditions on keys the server never sets, denies that silently never fire, allows another statement shadows, and more."
          flush
        >
          {!lint ? (
            <div className="empty">
              Requires <code>iam:policies:read</code>.
            </div>
          ) : !lint.valid ? (
            <div className="card-body">
              <Alert tone="danger">
                {lint.error?.code}: {lint.error?.message}
              </Alert>
            </div>
          ) : (
            <Table
              head={['Severity', 'Statement', 'Check', 'Message']}
              rows={lint.warnings.map((warning) => [
                <Badge key="s" tone={warning.severity === 'warning' ? 'warning' : 'neutral'}>
                  {warning.severity}
                </Badge>,
                warning.statement < 0 ? 'document' : (warning.sid ?? `#${warning.statement + 1}`),
                <code key="c" className="small">
                  {warning.code}
                </code>,
                warning.message,
              ])}
              empty="No lint warnings."
            />
          )}
          {!protectedPolicy && (
            <div className="card-body">
              <ApiForm
                path="analysis/lintPolicy"
                tenantId={tenantId}
                submitLabel="Lint draft"
                compact
                showResult
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'document',
                    label: 'Draft document',
                    type: 'json',
                    required: true,
                    rows: 8,
                    defaultValue: JSON.stringify(policy.document, null, 2),
                    help: 'Checked against this organization’s actions, resource types, and attributes before you save it.',
                  },
                ]}
              />
            </div>
          )}
        </Card>
        <Card
          title="Test a document"
          description="Evaluates a candidate document against an action, a resource, and the context you supply, without saving. Requires iam:policies:simulate."
        >
          <ApiForm
            path="policies/test"
            tenantId={tenantId}
            submitLabel="Evaluate"
            showResult
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
              {
                name: 'document',
                label: 'Policy document',
                type: 'json',
                required: true,
                rows: 8,
                defaultValue: JSON.stringify(policy.document, null, 2),
              },
              { name: 'action', label: 'Action', required: true, placeholder: 'workspaces:read' },
              {
                name: 'resource',
                label: 'Resource',
                required: true,
                placeholder: 'workspace/engineering',
              },
              {
                name: 'context',
                label: 'Context',
                type: 'json',
                rows: 4,
                defaultValue: JSON.stringify(
                  {
                    'principal.id': 'usr_example',
                    'principal.mfa': true,
                    'resource.relations': [],
                  },
                  null,
                  2,
                ),
                help: 'Trusted context keys as the server would derive them.',
              },
            ]}
          />
        </Card>
        <Card title="Version history" flush>
          {versions ? (
            <Table
              head={['Version', 'Name', 'Description', 'Statements', '']}
              rows={[...versions]
                .reverse()
                .map((version) => [
                  `v${version.version}`,
                  version.name,
                  version.description ?? '—',
                  version.document.statements.length,
                  version.version !== policy.version && !protectedPolicy ? (
                    <ApiButton
                      key="r"
                      path="policies/restoreVersion"
                      body={{ tenantId, policyId: id, version: version.version }}
                      label={`Restore as v${policy.version + 1}`}
                      tenantId={tenantId}
                    />
                  ) : (
                    ''
                  ),
                ])}
            />
          ) : (
            <div className="empty">
              Requires <code>iam:policies:read</code>.
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
