import Link from 'next/link';
import { OnboardingReport } from '@/components/onboarding-admin';
import { PageHeader } from '@/components/ui';
import { getIam } from '@/lib/iam';
import { credential, requireRootSession, tryRead } from '@/lib/session';

export default async function PlatformOnboardingProgress({
  params,
}: {
  params: Promise<{ flowId: string }>;
}) {
  const { flowId } = await params;
  const session = await requireRootSession();
  const iam = await getIam();
  const auth = await credential();
  const tenantId = session.session.tenantId;
  const flow = await tryRead(() => iam.api.onboarding.getFlow(auth, { tenantId, flowId }));
  return (
    <>
      <PageHeader
        title={flow?.name ?? 'Onboarding flow'}
        description={
          flow?.audience === 'tenant'
            ? 'Every tenant this setup checklist applies to, with its answers and the tasks waiting for platform review.'
            : 'How the people of every tenant below are getting on (counts only).'
        }
        actions={
          <Link className="btn small secondary" href="/admin/onboarding">
            All flows
          </Link>
        }
      />
      <OnboardingReport iam={iam} auth={auth} tenantId={tenantId} flowId={flowId} />
    </>
  );
}
