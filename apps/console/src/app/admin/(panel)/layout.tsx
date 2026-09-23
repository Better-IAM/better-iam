import Link from 'next/link';
import type { ReactNode } from 'react';
import { SignOutButton } from '@/components/auth-forms';
import { IdleWarning } from '@/components/idle-warning';
import { Shell } from '@/components/shell';
import { adminAreas } from '@/lib/navigation';
import { requireRootSession } from '@/lib/session';

export const dynamic = 'force-dynamic';

export default async function AdminLayout({ children }: { children: ReactNode }) {
  const session = await requireRootSession();
  return (
    <Shell
      brand="Better IAM"
      subtitle="Administration panel"
      homeHref="/admin"
      areas={adminAreas()}
      account={{ name: session.identity.name, detail: session.identity.email }}
      links={
        <Link className="appbar-link" href="/cloud">
          Cloud console ↗
        </Link>
      }
      accountMenu={
        <>
          <span className="badge accent">root administrator</span>
          <SignOutButton next="/admin/login" />
        </>
      }
    >
      <IdleWarning
        sessionId={session.session.id}
        idleTimeoutMs={session.limits.idleTimeoutMs}
        expiresAt={session.session.expiresAt}
        serverNow={session.limits.now}
        loginHref="/admin/login"
      />
      {children}
    </Shell>
  );
}
