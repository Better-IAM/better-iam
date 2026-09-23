import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Agreements({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const agreements = await tryRead(() => iam.api.agreements.list(auth, { tenantId }));
  const statuses = agreements
    ? await Promise.all(
        agreements.map((agreement) =>
          tryRead(() => iam.api.agreements.status(auth, { tenantId, agreementId: agreement.id })),
        ),
      )
    : [];
  return (
    <>
      <PageHeader
        title="Terms of use"
        description="Agreements members accept, such as an acceptable-use policy. Members see required agreements they owe at the top of the console. Policies see principal.agreements (names accepted) and principal.pendingAgreements (required ones owed), so a deny statement can hold back access until people accept."
      />
      {!agreements ? (
        <Alert tone="warning">
          Requires <code>iam:agreements:read</code>.
        </Alert>
      ) : (
        <div className="stack">
          {agreements.map((agreement, index) => {
            const status = statuses[index];
            return (
              <Card
                key={agreement.id}
                title={
                  <span className="row">
                    {agreement.name} <Badge>v{agreement.version}</Badge>
                    {agreement.required ? (
                      <Badge tone="accent">required</Badge>
                    ) : (
                      <Badge>optional</Badge>
                    )}
                  </span>
                }
                description={
                  <>
                    Updated <Time value={agreement.updatedAt} />
                    {agreement.reacceptAfterDays &&
                      ` · accepted again every ${agreement.reacceptAfterDays} days`}
                    {agreement.url && (
                      <>
                        {' · '}
                        <a href={agreement.url} target="_blank" rel="noreferrer noopener">
                          document
                        </a>
                      </>
                    )}
                  </>
                }
              >
                <div className="stack">
                  <pre className="result" style={{ whiteSpace: 'pre-wrap', maxHeight: 200 }}>
                    {agreement.content}
                  </pre>
                  {status && (
                    <Table
                      head={['Member', 'Status']}
                      rows={[
                        ...status.accepted.map((entry) => [
                          <Link key="m" href={`${base}/members/${entry.identity.id}`}>
                            {entry.identity.name}
                          </Link>,
                          <span key="s" className="small">
                            <Badge tone="success">accepted</Badge> v{entry.version},{' '}
                            <Time value={entry.acceptedAt} />
                          </span>,
                        ]),
                        ...status.pending.map((entry) => [
                          <Link key="m" href={`${base}/members/${entry.identity.id}`}>
                            {entry.identity.name}
                          </Link>,
                          <span key="s" className="small">
                            <Badge tone="warning">pending</Badge>
                            {entry.acceptedVersion !== undefined &&
                              ` (accepted v${entry.acceptedVersion})`}
                          </span>,
                        ]),
                      ]}
                      empty="No members yet."
                    />
                  )}
                  <details>
                    <summary className="small">Edit</summary>
                    <ApiForm
                      path="agreements/update"
                      tenantId={tenantId}
                      submitLabel="Save"
                      fields={[
                        {
                          name: 'tenantId',
                          label: 'Tenant',
                          type: 'hidden',
                          defaultValue: tenantId,
                        },
                        {
                          name: 'agreementId',
                          label: 'Agreement',
                          type: 'hidden',
                          defaultValue: agreement.id,
                        },
                        {
                          name: 'content',
                          label: 'Text',
                          type: 'textarea',
                          rows: 8,
                          required: true,
                          defaultValue: agreement.content,
                        },
                        { name: 'url', label: 'Link', defaultValue: agreement.url ?? '' },
                        {
                          name: 'newVersion',
                          label: 'Publish as a new version (everyone accepts again)',
                          type: 'checkbox',
                        },
                        {
                          name: 'required',
                          label: 'Required',
                          type: 'checkbox',
                          defaultValue: agreement.required,
                        },
                      ]}
                    />
                  </details>
                  <span>
                    <ApiButton
                      path="agreements/delete"
                      body={{ tenantId, agreementId: agreement.id }}
                      label="Delete"
                      tone="danger"
                      confirm={`Delete "${agreement.name}" and every acceptance of it?`}
                      tenantId={tenantId}
                    />
                  </span>
                </div>
              </Card>
            );
          })}
          <Card title="New agreement">
            <ApiForm
              path="agreements/create"
              tenantId={tenantId}
              submitLabel="Publish"
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'name', label: 'Name', required: true, placeholder: 'Acceptable use' },
                { name: 'content', label: 'Text', type: 'textarea', rows: 8, required: true },
                { name: 'url', label: 'Link', placeholder: 'https://…' },
                { name: 'required', label: 'Required', type: 'checkbox', defaultValue: true },
                {
                  name: 'reacceptAfterDays',
                  label: 'Accept again every (days)',
                  type: 'number',
                },
              ]}
            />
          </Card>
        </div>
      )}
    </>
  );
}
