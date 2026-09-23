import type { ReactNode } from 'react';
import Link from 'next/link';
import { iamNext } from '@/lib/iam';
import { signOut } from '../login/actions';
import { ClientSession, Providers } from '../providers';

export default async function OrgLayout(props: {
  params: Promise<{ org: string }>;
  children: ReactNode;
}) {
  const { org } = await props.params;
  // Unknown aliases 404; visitors signed in elsewhere go to /login?org=...&next=...
  const { tenant, session } = await iamNext.requireTenantSession({ slug: org });
  return (
    <>
      <header>
        <nav>
          <Link href={`/${org}`}>
            <strong>{tenant.name}</strong>
          </Link>{' '}
          · <Link href={`/${org}/documents/roadmap`}>Document</Link> ·{' '}
          <Link href={`/${org}/notes`}>Notes</Link> ·{' '}
          <Link href={`/${org}/security`}>Security</Link>
        </nav>
        <form action={signOut} className="inline">
          <span>{session.identity.name} </span>
          <button type="submit">Sign out</button>
        </form>
      </header>
      <Providers initialSession={await iamNext.sessionForClient()}>
        <ClientSession />
        {props.children}
      </Providers>
    </>
  );
}
