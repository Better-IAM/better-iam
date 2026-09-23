import { cx } from '@/utils/cx';

/** Lifecycle status, told apart by weight rather than hue: new is solid ink, beta outlined, experimental dashed. */
const tones: Record<string, string> = {
  new: 'bg-text-primary text-background-full',
  beta: 'border border-text-primary text-text-primary',
  experimental: 'border border-dashed border-text-secondary text-text-secondary',
  deprecated: 'bg-background-secondary-default text-text-tertiary line-through',
};

export function StatusBadge({ status, className }: { status: string; className?: string }) {
  return (
    <span
      className={cx(
        'ms-auto inline-flex shrink-0 items-center rounded-full px-1.5 py-px font-mono text-[0.625rem] leading-4 font-medium tracking-wide uppercase',
        tones[status] ?? 'bg-background-secondary-default text-text-secondary',
        className,
      )}
    >
      {status}
    </span>
  );
}
