import Link from 'next/link';
import { OnboardingReport } from '@/components/onboarding-admin';
import { PageHeader } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function OnboardingProgress({
  params,
}: {
  params: Promise<{ org: string; flowId: string }>;
}) {
  const { org, flowId } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const effective = await tryRead(() => iam.api.onboarding.effective(auth, { tenantId }));
  const name =
    effective?.ownFlows.find((flow) => flow.id === flowId)?.name ??
    effective?.memberFlows.find((item) => item.flow.id === flowId)?.flow.name ??
    'Onboarding flow';
  return (
    <>
      <PageHeader
        title={name}
        description="Who has finished, who is on the way, and the tasks waiting for a reviewer."
        actions={
          <Link className="btn small secondary" href={`${base}/onboarding`}>
            All flows
          </Link>
        }
      />
      <OnboardingReport iam={iam} auth={auth} tenantId={tenantId} flowId={flowId} />
    </>
  );
}
