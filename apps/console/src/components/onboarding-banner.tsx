'use client';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useState } from 'react';
import type { MyOnboarding } from 'better-iam/server';
import { iamClient } from '@/lib/client';

/**
 * Reminds the signed-in person of required onboarding they have not finished, with a link to their checklist. It
 * re-reads their onboarding on every page change, so it disappears as soon as the last required step is done.
 */
export function OnboardingBanner({ tenantId, href }: { tenantId: string; href: string }) {
  const pathname = usePathname();
  const [state, setState] = useState<{ pending: number; left: number; title?: string } | null>(
    null,
  );

  useEffect(() => {
    let active = true;
    iamClient()
      .$request('onboarding/mine', { tenantId })
      .then((result) => {
        if (!active) return;
        const mine = result as MyOnboarding;
        const open = mine.flows.filter((flow) => flow.required && !flow.complete);
        setState({
          pending: mine.pending,
          left: open.reduce((sum, flow) => sum + (flow.total - flow.done), 0),
          title: mine.welcome.welcomeTitle,
        });
      })
      .catch(() => undefined);
    return () => {
      active = false;
    };
  }, [tenantId, pathname]);

  if (!state?.pending || pathname === href) return null;
  return (
    <div className="alert info row spread" role="region" aria-label="Onboarding">
      <span>
        <strong>{state.title ?? 'Finish getting started'}.</strong>{' '}
        {state.left === 1 ? 'One step is' : `${state.left} steps are`} left in your onboarding; some
        access may wait until you finish.
      </span>
      <Link className="btn small" href={href}>
        Continue
      </Link>
    </div>
  );
}
