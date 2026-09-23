import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, StatusBadge, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const thirtyDays = 30 * 86400_000;

export default async function ServiceAccounts({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const [services, keys] = await Promise.all([
    tryRead(() => iam.api.serviceAccounts.list(auth, { tenantId })),
    tryRead(() => iam.api.credentials.list(auth, { tenantId })),
  ]);
  const now = Date.now();
  const active = services?.filter((service) => service.status === 'active') ?? [];
  return (
    <>
      <PageHeader
        title="Service accounts"
        description="Non-human identities for integrations. API keys are hashed at rest, expire, and inherit the ceiling of the administrator who issued them."
      />
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <div className="stack">
          <Card title="Service accounts" flush>
            {services ? (
              <Table
                head={['Name', 'Description', 'Status', 'Created', 'Expires', 'Keys', '']}
                rows={services.map((service) => [
                  <Link key="n" href={`${base}/members/${service.id}`}>
                    {service.name}
                  </Link>,
                  service.description ?? <span className="muted">—</span>,
                  <StatusBadge key="s" status={service.status} />,
                  <Time key="c" value={service.createdAt} />,
                  <Time key="e" value={service.expiresAt} />,
                  keys
                    ? keys.filter((item) => item.identityId === service.id && !item.expired).length
                    : '—',
                  <span key="a" className="actions">
                    {service.status === 'active' && (
                      <ApiButton
                        path="credentials/create"
                        body={{
                          tenantId,
                          identityId: service.id,
                          expiresInSeconds: 60 * 60 * 24 * 90,
                        }}
                        label="Issue 90-day key"
                        tone="primary"
                        showResult
                        tenantId={tenantId}
                      />
                    )}
                    {service.status === 'active' ? (
                      <ApiButton
                        path="serviceAccounts/setStatus"
                        body={{ tenantId, identityId: service.id, status: 'disabled' }}
                        label="Disable"
                        confirm={`Disable ${service.name} and revoke its keys?`}
                        tenantId={tenantId}
                      />
                    ) : (
                      <ApiButton
                        path="serviceAccounts/setStatus"
                        body={{ tenantId, identityId: service.id, status: 'active' }}
                        label="Enable"
                        tenantId={tenantId}
                      />
                    )}
                    <ApiButton
                      path="serviceAccounts/delete"
                      body={{ tenantId, identityId: service.id }}
                      label="Delete"
                      tone="danger"
                      confirm={`Delete ${service.name}? Its keys and bindings are removed permanently.`}
                      tenantId={tenantId}
                    />
                  </span>,
                ])}
                empty="No service accounts."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:identities:read</code>.
              </div>
            )}
          </Card>
          <Card
            title="API keys"
            description="The plaintext key is shown once, in the response of the issuing action. Last use is recorded at most once a minute; keys unused for 30 days are flagged for review. Requires iam:credentials:read."
            flush
          >
            {keys ? (
              <Table
                head={['Name', 'Service account', 'Created', 'Expires', 'Last used', '']}
                rows={keys.map((item) => [
                  <span key="n" className="row">
                    {item.name ?? (
                      <code className="small" title={item.id}>
                        {item.id.slice(0, 8)}
                      </code>
                    )}
                    {item.description && <span className="small muted">{item.description}</span>}
                  </span>,
                  services?.find((service) => service.id === item.identityId)?.name ??
                    item.identityId,
                  <Time key="c" value={item.createdAt} />,
                  <span key="e" className="row">
                    <Time value={item.expiresAt} />
                    {item.expired && <Badge tone="danger">expired</Badge>}
                  </span>,
                  <span key="l" className="row">
                    {item.lastUsedAt ? <Time value={item.lastUsedAt} /> : 'never'}
                    {!item.expired && (item.lastUsedAt ?? item.createdAt) < now - thirtyDays && (
                      <Badge tone="warning">unused 30d</Badge>
                    )}
                  </span>,
                  <span key="a" className="actions">
                    <ApiButton
                      path="credentials/rotate"
                      body={{ tenantId, credentialId: item.id }}
                      label="Rotate"
                      showResult
                      tenantId={tenantId}
                    />
                    <ApiButton
                      path="credentials/revoke"
                      body={{ tenantId, credentialId: item.id }}
                      label="Revoke"
                      tone="danger"
                      confirm="Revoke this key immediately?"
                      tenantId={tenantId}
                    />
                  </span>,
                ])}
                empty="No keys issued."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:credentials:read</code>.
              </div>
            )}
          </Card>
        </div>
        <div className="stack">
          <Card
            title="Create a service account"
            description="Requires iam:identities:create and a grant authority. Bind roles from the account's page afterwards."
          >
            <ApiForm
              path="serviceAccounts/create"
              tenantId={tenantId}
              submitLabel="Create service account"
              successMessage="Service account created."
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'name', label: 'Name', required: true, placeholder: 'ci-deployer' },
                { name: 'description', label: 'Description' },
                {
                  name: 'expiresAt',
                  label: 'Deactivate on',
                  type: 'datetime',
                  help: 'Optional: keys stop working at this time and the account is disabled.',
                },
              ]}
            />
          </Card>
          {active.length > 0 && (
            <Card
              title="Issue a labeled key"
              description="A name and purpose make reviews and rotation easier; the key is shown once in the result."
            >
              <ApiForm
                path="credentials/create"
                tenantId={tenantId}
                submitLabel="Issue key"
                showResult
                resetOnSuccess
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'identityId',
                    label: 'Service account',
                    type: 'select',
                    required: true,
                    options: active.map((service) => ({ value: service.id, label: service.name })),
                  },
                  { name: 'name', label: 'Name', placeholder: 'github-actions' },
                  { name: 'description', label: 'Purpose' },
                  {
                    name: 'scopes',
                    label: 'Restrict to actions',
                    type: 'list',
                    placeholder: 'documents:read, documents:write',
                    help: 'Optional allowlist; the key can never do more than the service account itself.',
                  },
                  {
                    name: 'expiresInSeconds',
                    label: 'Expires in (days)',
                    type: 'number',
                    multiplier: 86400,
                    placeholder: '90',
                  },
                ]}
              />
            </Card>
          )}
          <Alert tone="info">
            Use a key as <code>Authorization: Bearer …</code> against <code>/api/iam</code> or pass
            it to <code>iam.require</code> on your servers. Optional session policies can further
            reduce a key&apos;s privileges.
          </Alert>
        </div>
      </div>
    </>
  );
}
