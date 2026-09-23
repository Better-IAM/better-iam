import { OnboardingChecklist, FlowProgress } from '@/components/onboarding-checklist';
import { Alert, Card, PageHeader } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function GetStarted({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, tenant, session, base } = await orgPage(org);
  const mine = await tryRead(() => iam.api.onboarding.mine(auth, { tenantId }));
  if (!mine)
    return (
      <>
        <PageHeader title="Get started" />
        <Alert tone="warning">Onboarding is available from an ordinary sign-in session.</Alert>
      </>
    );
  const { welcome } = mine;
  // The overall meter follows the required flows (all of them when none is required), like the banner.
  const counted = mine.flows.some((flow) => flow.required)
    ? mine.flows.filter((flow) => flow.required)
    : mine.flows;
  const done = counted.reduce((sum, flow) => sum + flow.done, 0);
  const total = counted.reduce((sum, flow) => sum + flow.total, 0);
  const impersonating = Boolean(session.session.impersonatorId);
  return (
    <>
      <PageHeader
        title={welcome.welcomeTitle ?? `Welcome to ${tenant.name}`}
        description={
          mine.complete
            ? 'You have finished everything required. Optional steps stay here for later.'
            : 'A few steps to finish setting up your account.'
        }
      />
      <div className="stack">
        {(welcome.welcomeMessage || welcome.supportEmail || welcome.supportUrl || total > 0) && (
          <Card>
            <div className="stack">
              {welcome.welcomeMessage && (
                <p style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{welcome.welcomeMessage}</p>
              )}
              {total > 0 && <FlowProgress done={done} total={total} />}
              {(welcome.supportEmail || welcome.supportUrl) && (
                <span className="small muted">
                  Need help?{' '}
                  {welcome.supportEmail && (
                    <a href={`mailto:${welcome.supportEmail}`}>{welcome.supportEmail}</a>
                  )}
                  {welcome.supportEmail && welcome.supportUrl && ' · '}
                  {welcome.supportUrl && (
                    <a href={welcome.supportUrl} target="_blank" rel="noreferrer noopener">
                      Help center ↗
                    </a>
                  )}
                </span>
              )}
            </div>
          </Card>
        )}
        {impersonating && (
          <Alert tone="info">
            You are viewing this checklist as {session.identity.name}; only they can complete it.
          </Alert>
        )}
        <OnboardingChecklist
          tenantId={tenantId}
          base={base}
          initial={mine}
          mode="member"
          readOnly={impersonating}
        />
      </div>
    </>
  );
}
