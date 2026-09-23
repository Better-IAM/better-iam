import type { SVGProps } from 'react';
import { cx } from '@/utils/cx';

/** Better IAM mark: a solid shield with a keyhole cut through it, drawn on a 24px grid in the current color. */
export function LogoMark(props: SVGProps<SVGSVGElement>) {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true" {...props}>
      <path
        fill="currentColor"
        fillRule="evenodd"
        d="M12 1.75 3.75 4.9v6.02c0 5.02 3.44 9.6 8.25 11.33 4.81-1.73 8.25-6.31 8.25-11.33V4.9L12 1.75ZM10.84 11.83a2.35 2.35 0 1 1 2.32 0l.56 3.92h-3.44l.56-3.92Z"
      />
    </svg>
  );
}

export function Logo({ className }: { className?: string }) {
  return (
    // Block-level flex, not inline-flex: an inline box sits on the parent's text baseline and rides a few pixels high.
    <span className={cx('flex w-fit items-center gap-2 text-headline-semibold', className)}>
      <LogoMark className="size-5 text-text-primary" />
      <span className="tracking-[-0.01em]">
        Better<span className="text-text-secondary">IAM</span>
      </span>
    </span>
  );
}
