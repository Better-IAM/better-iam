import type { ReactNode } from 'react';
import Link from 'next/link';
import { cx } from '@/utils/cx';

export function FeatureGrid({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cx('not-prose my-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-3', className)}>
      {children}
    </div>
  );
}

/** A compact feature tile: icon, title, one or two sentences, and an optional link. */
export function Feature({
  icon,
  title,
  href,
  children,
}: {
  icon?: ReactNode;
  title: string;
  href?: string;
  children: ReactNode;
}) {
  const body = (
    <>
      <div className="flex items-center gap-2.5">
        {icon ? (
          <span className="flex size-7 items-center justify-center rounded-lg border border-border-button-default bg-background-primary-default text-foreground-icon-primary shadow-xs transition-colors [&_svg]:size-4 group-hover:border-text-primary group-hover:bg-text-primary group-hover:text-background-full">
            {icon}
          </span>
        ) : null}
        <h3 className="text-body-semibold">{title}</h3>
      </div>
      <div className="text-body-regular leading-6 text-text-secondary">{children}</div>
    </>
  );
  const className =
    'group flex flex-col gap-2 rounded-2xl border border-border-button-default bg-background-primary-default p-4 shadow-xs transition-[background-color,border-color]';
  return href ? (
    <Link
      href={href}
      className={cx(
        className,
        'hover:border-border-button-hover hover:bg-background-primary-hover',
      )}
    >
      {body}
    </Link>
  ) : (
    <div className={className}>{body}</div>
  );
}
