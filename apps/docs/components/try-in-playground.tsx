import type { ReactNode } from 'react';
import Link from 'next/link';
import { RiArrowRightLine, RiFlaskLine } from 'react-icons/ri';
import { buttonStyles } from '@/components/base/buttons/button';
import { cx } from '@/utils/cx';

const pretty = (value: unknown) => JSON.stringify(value, null, 2);

/**
 * The playground reads its state from `#s=` as base64url-encoded JSON (see `encodeState` in
 * `components/playground/policy-playground.tsx`); this builds the same encoding on the server.
 */
export function playgroundUrl(input: {
  grants: unknown[];
  boundaries?: unknown[];
  action: string;
  resource: string;
  context?: Record<string, unknown>;
}): string {
  const state = {
    grants: input.grants.map(pretty),
    boundaries: (input.boundaries ?? []).map(pretty),
    action: input.action,
    resource: input.resource,
    context: pretty(input.context ?? {}),
  };
  return `/playground#s=${Buffer.from(JSON.stringify(state), 'utf8').toString('base64url')}`;
}

/**
 * A "Try it in the playground" link for a policy example:
 * `<TryInPlayground grants={[policy]} action="documents:read" resource="document/q3" context={{ 'principal.mfa': true }} />`.
 * The reader lands on the playground with the documents, request, and context filled in.
 */
export function TryInPlayground({
  grants,
  boundaries,
  action,
  resource,
  context,
  children = 'Try it in the playground',
}: {
  grants: unknown[];
  boundaries?: unknown[];
  action: string;
  resource: string;
  context?: Record<string, unknown>;
  children?: ReactNode;
}) {
  return (
    <Link
      href={playgroundUrl({ grants, boundaries, action, resource, context })}
      className={cx(
        buttonStyles.base,
        buttonStyles.size.small,
        buttonStyles.variant.secondary,
        'not-prose group/try -mt-2 mb-6 gap-1.5 px-2.5 no-underline',
      )}
    >
      <RiFlaskLine className="size-4" aria-hidden />
      <span className={buttonStyles.label.small}>{children}</span>
      <RiArrowRightLine
        className="size-4 transition-transform group-hover/try:translate-x-0.5"
        aria-hidden
      />
    </Link>
  );
}
