import type { ReactNode } from 'react';
import Link from 'next/link';
import { cn } from '@/lib/cn';

export function FeatureGrid({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn('not-prose my-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-3', className)}>
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
      <div className="flex items-center gap-2">
        {icon ? (
          <span className="flex size-7 items-center justify-center rounded-lg bg-fd-primary/10 text-fd-primary [&_svg]:size-4">
            {icon}
          </span>
        ) : null}
        <h3 className="text-sm font-semibold">{title}</h3>
      </div>
      <div className="text-sm leading-relaxed text-fd-muted-foreground">{children}</div>
    </>
  );
  const className = 'flex flex-col gap-2 rounded-xl border bg-fd-card p-4 transition-colors';
  return href ? (
    <Link href={href} className={cn(className, 'hover:border-fd-primary/40 hover:bg-fd-accent/40')}>
      {body}
    </Link>
  ) : (
    <div className={className}>{body}</div>
  );
}
