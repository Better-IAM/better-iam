import { cn } from '@/lib/cn';

const tones: Record<string, string> = {
  new: 'bg-fd-primary/12 text-fd-primary ring-fd-primary/25',
  beta: 'bg-amber-500/12 text-amber-600 ring-amber-500/25 dark:text-amber-400',
  experimental: 'bg-fuchsia-500/12 text-fuchsia-600 ring-fuchsia-500/25 dark:text-fuchsia-400',
  deprecated: 'bg-red-500/12 text-red-600 ring-red-500/25 dark:text-red-400',
};

export function StatusBadge({ status, className }: { status: string; className?: string }) {
  return (
    <span
      className={cn(
        'ms-auto inline-flex shrink-0 items-center rounded-full px-1.5 py-px font-mono text-[0.625rem] font-medium uppercase tracking-wide ring-1 ring-inset',
        tones[status] ?? 'bg-fd-muted text-fd-muted-foreground ring-fd-border',
        className,
      )}
    >
      {status}
    </span>
  );
}
