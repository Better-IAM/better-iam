import type { ReactNode } from 'react';
import Link from 'next/link';
import { AgreementsBanner } from '@/components/agreements-banner';
import { SignOutButton } from '@/components/auth-forms';
import { IdleWarning } from '@/components/idle-warning';
import { ImpersonationBanner } from '@/components/impersonation';
import { OnboardingBanner } from '@/components/onboarding-banner';
import { SignInNotice } from '@/components/sign-in-notice';
import { Shell } from '@/components/shell';
import { Badge } from '@/components/ui';
import type { Identity } from 'better-iam';
import { getIam } from '@/lib/iam';
import { orgAreas } from '@/lib/navigation';
import { requireOrgSession } from '@/lib/session';

export const dynamic = 'force-dynamic';

export default async function OrgLayout({
  children,
  params,
}: {
  children: ReactNode;
  params: Promise<{ org: string }>;
}) {
  const { org } = await params;
  const { session, tenant } = await requireOrgSession(org);
  const base = `/cloud/${encodeURIComponent(org)}`;
  // The banner names the administrator to themselves; the member being viewed need not hold read permission on them.
  const impersonatorId = session.session.impersonatorId;
  const impersonator = impersonatorId
    ? await (await getIam()).store.get<Identity>('identities', impersonatorId)
    : undefined;
  return (
    <Shell
      brand={tenant.name}
      subtitle={tenant.slug ? `Cloud console · ${tenant.slug}` : 'Cloud console'}
      homeHref={base}
      areas={orgAreas(base)}
      account={{ name: session.identity.name, detail: session.identity.email }}
      accountMenu={
        <>
          <span className="row">
            {session.identity.owner && <Badge tone="accent">owner</Badge>}
            {session.session.mfa && <Badge tone="success">MFA</Badge>}
            {impersonatorId && <Badge tone="warning">view as</Badge>}
          </span>
          <span className="row">
            <Link className="btn small secondary" href={`${base}/account`}>
              Account
            </Link>
            <SignOutButton next="/cloud" />
          </span>
        </>
      }
    >
      {impersonatorId && (
        <ImpersonationBanner
          memberName={session.identity.name}
          impersonatorName={impersonator?.name}
          expiresAt={session.session.expiresAt}
          base={base}
        />
      )}
      {!impersonatorId && <AgreementsBanner tenantId={tenant.id} />}
      {!impersonatorId && <OnboardingBanner tenantId={tenant.id} href={`${base}/get-started`} />}
      {!impersonatorId && (
        <SignInNotice
          sessionId={session.session.id}
          previous={session.session.previousSignIn}
          accountHref={`${base}/account`}
        />
      )}
      <IdleWarning
        sessionId={session.session.id}
        idleTimeoutMs={session.limits.idleTimeoutMs}
        expiresAt={session.session.expiresAt}
        serverNow={session.limits.now}
        loginHref={`/cloud/login?org=${encodeURIComponent(org)}`}
      />
      {children}
    </Shell>
  );
}
