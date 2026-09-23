import { ImpactPreviewForm } from '@/components/impact-preview';
import { Alert, Card, PageHeader } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Impact({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const [roles, policies] = await Promise.all([
    tryRead(() => iam.api.roles.list(auth, { tenantId })),
    tryRead(() => iam.api.policies.list(auth, { tenantId })),
  ]);
  return (
    <>
      <PageHeader
        title="Change impact"
        description="Before editing a role or policy, see exactly who would gain or lose which actions on the resources you care about. The change is applied with the same validation and rights as the real edit, evaluated for every holder, then rolled back."
      />
      {!roles ? (
        <Alert tone="warning">
          Requires <code>iam:roles:read</code>.
        </Alert>
      ) : (
        <Card title="Preview a change">
          <ImpactPreviewForm
            tenantId={tenantId}
            base={base}
            targets={{
              roles: roles
                .filter((role) => !role.protected)
                .map((role) => ({
                  id: role.id,
                  name: role.name,
                  permissions: [
                    ...new Set(
                      (role.document?.statements ?? [])
                        .filter((statement) => statement.effect === 'allow')
                        .flatMap((statement) => statement.actions),
                    ),
                  ],
                })),
              policies: (policies ?? [])
                .filter((policy) => policy.uniqueKey !== 'system:owner')
                .map((policy) => ({ id: policy.id, name: policy.name, document: policy.document })),
            }}
          />
        </Card>
      )}
    </>
  );
}
