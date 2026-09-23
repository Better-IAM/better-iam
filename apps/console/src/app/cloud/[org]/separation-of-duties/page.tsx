import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function SeparationOfDuties({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const [rules, violations, roles] = await Promise.all([
    tryRead(() => iam.api.sod.list(auth, { tenantId })),
    tryRead(() => iam.api.sod.violations(auth, { tenantId })),
    tryRead(() => iam.api.roles.list(auth, { tenantId })),
  ]);
  const roleName = new Map((roles ?? []).map((role) => [role.id, role.name]));
  return (
    <>
      <PageHeader
        title="Separation of duties"
        description="Roles nobody may hold together, such as requesting and approving payments. Prevent rules refuse any grant that would create a conflict; detect rules only report it."
      />
      <div className="stack">
        <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
          <Card title="Rules" flush>
            {rules ? (
              <Table
                head={['Rule', 'Conflicting roles', 'Mode', 'Created', '']}
                rows={rules.map((rule) => [
                  <span key="n" className="stack">
                    <strong>{rule.name}</strong>
                    {rule.description && <span className="small muted">{rule.description}</span>}
                  </span>,
                  <span key="r" className="small">
                    {rule.roleIds.map((roleId, index) => (
                      <span key={roleId}>
                        {index > 0 && ' · '}
                        <Link href={`${base}/roles/${roleId}`}>
                          {roleName.get(roleId) ?? roleId}
                        </Link>
                      </span>
                    ))}
                  </span>,
                  rule.mode === 'prevent' ? (
                    <Badge key="m" tone="danger">
                      prevent
                    </Badge>
                  ) : (
                    <Badge key="m" tone="warning">
                      detect
                    </Badge>
                  ),
                  <Time key="c" value={rule.createdAt} />,
                  <span key="a" className="actions">
                    <ApiButton
                      path="sod/update"
                      body={{
                        tenantId,
                        ruleId: rule.id,
                        mode: rule.mode === 'prevent' ? 'detect' : 'prevent',
                      }}
                      label={rule.mode === 'prevent' ? 'Detect only' : 'Prevent'}
                      tenantId={tenantId}
                    />
                    <ApiButton
                      path="sod/delete"
                      body={{ tenantId, ruleId: rule.id }}
                      label="Delete"
                      tone="danger"
                      confirm={`Delete the rule ${rule.name}?`}
                      tenantId={tenantId}
                    />
                  </span>,
                ])}
                empty="No rules yet."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:sod:read</code>.
              </div>
            )}
          </Card>
          <div className="stack">
            <Card title="Add a rule" description="Requires iam:sod:manage.">
              <ApiForm
                path="sod/create"
                tenantId={tenantId}
                submitLabel="Add rule"
                resetOnSuccess
                showResult
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'name', label: 'Name', required: true, placeholder: 'Payments' },
                  {
                    name: 'roleIds',
                    label: 'Conflicting roles',
                    type: 'multiselect',
                    required: true,
                    options: (roles ?? [])
                      .filter((role) => !role.protected)
                      .map((role) => ({ value: role.id, label: role.name })),
                    help: 'Pick two or more; holding any two of them is a conflict.',
                  },
                  {
                    name: 'mode',
                    label: 'Mode',
                    type: 'select',
                    options: [
                      { value: 'prevent', label: 'Prevent new conflicts' },
                      { value: 'detect', label: 'Detect only' },
                    ],
                  },
                  { name: 'description', label: 'Description' },
                ]}
              />
            </Card>
            <Alert tone="info">
              Conflicts that exist when a prevent rule is added stay in place and are listed below
              and on the Security findings page until someone removes one of the roles.
            </Alert>
          </div>
        </div>
        <Card title="Current conflicts" flush>
          {violations ? (
            <Table
              head={['Member', 'Rule', 'Roles held', 'Mode']}
              rows={violations.map((violation) => [
                <Link key="m" href={`${base}/members/${violation.identityId}`}>
                  {violation.identityName}
                </Link>,
                violation.ruleName,
                violation.roleNames.join(' + '),
                violation.mode,
              ])}
              empty="Nobody holds conflicting roles."
            />
          ) : (
            <div className="empty">
              Requires <code>iam:sod:read</code>.
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
