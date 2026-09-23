import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, StatusBadge, Table, Time } from '@/components/ui';
import { getIam } from '@/lib/iam';
import { credential, requireRootSession } from '@/lib/session';

export default async function Administrators() {
  const session = await requireRootSession();
  const iam = await getIam();
  const auth = await credential();
  const tenantId = session.session.tenantId;
  const identities = await iam.api.identities.list(auth, { tenantId });
  return (
    <>
      <PageHeader
        title="Root administrators"
        description="Root authority is a protected capability on identities of the installation root. It is never a role name, and it always requires MFA."
      />
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <Card title="Root tenant identities" flush>
          <Table
            head={['Name', 'Email', 'Status', 'Capability', 'Created', '']}
            rows={identities.map((identity) => [
              identity.name,
              identity.email ?? '—',
              <StatusBadge key="s" status={identity.status} />,
              identity.rootAdmin ? (
                <Badge key="c" tone="danger">
                  root administrator
                </Badge>
              ) : (
                <span key="c" className="muted">
                  ordinary identity
                </span>
              ),
              <Time key="t" value={identity.createdAt} />,
              <span key="a" className="actions">
                {identity.kind === 'user' &&
                  (identity.rootAdmin ? (
                    <ApiButton
                      path="root/setAdministrator"
                      body={{ tenantId, identityId: identity.id, enabled: false }}
                      label="Revoke root"
                      tone="danger"
                      confirm={`Remove root authority from ${identity.name}? Their sessions are revoked.`}
                      tenantId={tenantId}
                    />
                  ) : (
                    <ApiButton
                      path="root/setAdministrator"
                      body={{ tenantId, identityId: identity.id, enabled: true }}
                      label="Grant root"
                      tone="primary"
                      confirm={`Grant universal root authority to ${identity.name}?`}
                      tenantId={tenantId}
                    />
                  ))}
                {identity.id !== session.identity.id &&
                  (identity.status === 'active' ? (
                    <ApiButton
                      path="identities/setStatus"
                      body={{ tenantId, identityId: identity.id, status: 'disabled' }}
                      label="Disable"
                      tenantId={tenantId}
                    />
                  ) : (
                    <ApiButton
                      path="identities/setStatus"
                      body={{ tenantId, identityId: identity.id, status: 'active' }}
                      label="Enable"
                      tenantId={tenantId}
                    />
                  ))}
              </span>,
            ])}
          />
        </Card>
        <div className="stack">
          <Card
            title="Add an administrator"
            description="Create the identity, then grant root. The person must enroll MFA at first sign-in."
          >
            <ApiForm
              path="identities/create"
              tenantId={tenantId}
              submitLabel="Create identity"
              successMessage="Identity created. Grant root authority from the list."
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'name', label: 'Name', required: true },
                { name: 'email', label: 'Email', type: 'email', required: true },
                {
                  name: 'password',
                  label: 'Initial password',
                  type: 'password',
                  help: 'Leave empty to require a password reset or invitation.',
                },
              ]}
            />
          </Card>
          <Card title="Or invite by email">
            <ApiForm
              path="identities/invite"
              tenantId={tenantId}
              submitLabel="Send invitation"
              successMessage="Invitation queued. Grant root authority once they have joined."
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'email', label: 'Email', type: 'email', required: true },
                { name: 'name', label: 'Name' },
              ]}
            />
          </Card>
          <Alert tone="warning">
            The final active root administrator cannot be removed. Recovery for a lost root is a
            deployment operation (<code>better-iam recover-root</code>), never a web action.
          </Alert>
        </div>
      </div>
    </>
  );
}
