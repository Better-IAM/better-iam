import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Card, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Resources({
  params,
  searchParams,
}: {
  params: Promise<{ org: string }>;
  searchParams: Promise<{ type?: string }>;
}) {
  const { org } = await params;
  const { type } = await searchParams;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const [types, resources] = await Promise.all([
    tryRead(() => iam.api.resourceTypes.list(auth, { tenantId })),
    tryRead(() =>
      iam.api.resources.list(auth, { tenantId, ...(type ? { type } : {}), limit: 200 }),
    ),
  ]);
  const managed = (types ?? []).filter((candidate) => candidate.managed);
  return (
    <>
      <PageHeader
        title="Resource registry"
        description="Managed resources registered with IAM. Authorization resolves ownership, parents, and attributes from here, so policies can say things like “approve invoices under 10,000”."
      />
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <Card
          title="Registered resources"
          flush
          actions={
            <span className="row">
              {managed.map((candidate) => (
                <Link
                  key={candidate.name}
                  className={candidate.name === type ? 'btn small' : 'btn small secondary'}
                  href={`${base}/resources?type=${candidate.name}`}
                >
                  {candidate.name}
                </Link>
              ))}
              {type && (
                <Link className="btn small ghost" href={`${base}/resources`}>
                  all
                </Link>
              )}
            </span>
          }
        >
          {resources ? (
            <Table
              head={['Resource', 'Attributes', 'Parent', 'Owner', 'Registered', '']}
              rows={resources.map((resource) => [
                <code key="r">
                  {resource.type}/{resource.resourceId}
                </code>,
                <code key="a" className="small">
                  {JSON.stringify(resource.attributes)}
                </code>,
                resource.parentId ? (
                  <code key="p" className="small">
                    {resource.parentType}/{resource.parentId}
                  </code>
                ) : (
                  '—'
                ),
                resource.ownerId ? (
                  <code key="o" className="small">
                    {resource.ownerId}
                  </code>
                ) : (
                  '—'
                ),
                <Time key="t" value={resource.createdAt} />,
                <ApiButton
                  key="d"
                  path="resources/delete"
                  body={{ tenantId, type: resource.type, id: resource.resourceId }}
                  label="Delete"
                  tone="danger"
                  confirm={`Delete ${resource.type}/${resource.resourceId}?`}
                  tenantId={tenantId}
                />,
              ])}
              empty="No resources registered."
            />
          ) : (
            <div className="empty">
              Requires <code>iam:resources:read</code>.
            </div>
          )}
        </Card>
        <Card
          title="Register a resource"
          description="Requires iam:resources:create on iam/{type}/{id}."
        >
          <ApiForm
            path="resources/register"
            tenantId={tenantId}
            submitLabel="Register"
            successMessage="Resource registered."
            resetOnSuccess
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
              {
                name: 'type',
                label: 'Type',
                type: 'select',
                required: true,
                options: managed.map((candidate) => ({
                  value: candidate.name,
                  label: candidate.name,
                })),
              },
              { name: 'id', label: 'Resource ID', required: true, placeholder: 'inv-1042' },
              {
                name: 'attributes',
                label: 'Attributes',
                type: 'json',
                rows: 4,
                placeholder: '{"amount": 250}',
              },
              {
                name: 'parentId',
                label: 'Parent resource ID',
                help: 'Required when the type declares a parent.',
              },
              { name: 'ownerId', label: 'Owner identity ID' },
            ]}
          />
        </Card>
      </div>
    </>
  );
}
