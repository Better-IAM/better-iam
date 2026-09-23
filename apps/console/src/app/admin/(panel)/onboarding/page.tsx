import { OnboardingAdmin } from '@/components/onboarding-admin';
import { PageHeader } from '@/components/ui';
import { getIam } from '@/lib/iam';
import { credential, requireRootSession } from '@/lib/session';

export default async function PlatformOnboarding() {
  const session = await requireRootSession();
  const iam = await getIam();
  const auth = await credential();
  return (
    <>
      <PageHeader
        title="Platform onboarding"
        description="Defaults for every organization and project: member onboarding that reaches everyone below, setup checklists for new tenants, and the welcome screen they inherit."
      />
      <OnboardingAdmin
        iam={iam}
        auth={auth}
        tenantId={session.session.tenantId}
        isRoot
        progressBase="/admin/onboarding"
      />
    </>
  );
}
