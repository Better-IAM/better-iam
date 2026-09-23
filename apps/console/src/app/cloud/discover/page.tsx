import Link from 'next/link';
import { redirect } from 'next/navigation';
import { isIamError } from '@/lib/errors';
import { getIam } from '@/lib/iam';

export const dynamic = 'force-dynamic';

/** Home-realm discovery: maps a work email to the organization that verified its domain. */
export default async function Discover({
  searchParams,
}: {
  searchParams: Promise<{ email?: string }>;
}) {
  const { email } = await searchParams;
  if (!email) redirect('/cloud');
  const iam = await getIam();
  let target: string | undefined;
  let problem = 'No organization has verified this email domain.';
  try {
    const found = await iam.api.domains.discover({ email });
    target = found.slug ?? found.tenantId;
  } catch (error) {
    if (!isIamError(error)) throw error;
    if (error.status !== 404) problem = error.message;
  }
  if (target) redirect(`/cloud/login?org=${encodeURIComponent(target)}`);
  return (
    <main className="auth">
      <div className="card">
        <div className="card-body stack">
          <div className="brand-mark">
            <strong>Cloud console</strong>
            <p>Find your organization</p>
          </div>
          <div className="alert warning">{problem}</div>
          <p className="small muted">
            <Link href="/cloud">Sign in with an organization alias instead</Link>
          </p>
        </div>
      </div>
    </main>
  );
}
