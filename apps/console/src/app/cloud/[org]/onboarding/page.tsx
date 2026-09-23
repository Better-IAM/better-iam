import Link from 'next/link';
import { OnboardingAdmin } from '@/components/onboarding-admin';
import { PageHeader } from '@/components/ui';
import { orgPage } from '@/lib/org';

export default async function Onboarding({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, tenant, base } = await orgPage(org);
  const project = tenant.type === 'project';
  return (
    <>
      <PageHeader
        title="Onboarding"
        description={
          project
            ? 'Checklists for people joining this project, on top of what the organization and the platform ask.'
            : 'Checklists for people joining this organization and setup checklists for its projects, on top of what the platform asks.'
        }
        actions={
          <Link className="btn small secondary" href={`${base}/get-started`}>
            Preview as a member
          </Link>
        }
      />
      <OnboardingAdmin
        iam={iam}
        auth={auth}
        tenantId={tenantId}
        isRoot={false}
        progressBase={`${base}/onboarding`}
        setupHref={`${base}/setup`}
      />
    </>
  );
}
