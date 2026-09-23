import { OnboardingChecklist } from '@/components/onboarding-checklist';
import { Alert, PageHeader } from '@/components/ui';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Setup({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const page = await orgPage(org);
  const { iam, auth, tenantId, tenant, base, session } = page;
  const [setup, access] = await Promise.all([
    tryRead(() => iam.api.onboarding.setup(auth, { tenantId })),
    can(page, [{ action: 'iam:onboarding:manage' }]),
  ]);
  const label = tenant.type === 'project' ? 'project' : 'organization';
  const manage = access[key('iam:onboarding:manage', undefined, tenantId)] === true;
  return (
    <>
      <PageHeader
        title="Setup checklist"
        description={`What the levels above ask of every new ${label}. Checks follow the ${label}'s real state and tick themselves off.`}
      />
      {!setup ? (
        <Alert tone="warning">
          Requires <code>iam:onboarding:read</code>.
        </Alert>
      ) : (
        <div className="stack">
          {setup.complete && setup.flows.length > 0 && (
            <Alert tone="success">Setup is complete. Nice work.</Alert>
          )}
          <OnboardingChecklist
            tenantId={tenantId}
            base={base}
            initial={setup}
            mode="setup"
            readOnly={!manage || Boolean(session.session.impersonatorId)}
          />
        </div>
      )}
    </>
  );
}
