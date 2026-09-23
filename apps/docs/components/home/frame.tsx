import type { ReactNode } from 'react';
import { Pause, Play, RotateCcw } from 'lucide-react';
import { cn } from '@/lib/cn';

/** The card every landing-page diagram sits in: a quiet title bar, the figure, and an optional footnote. */
export function DiagramFrame({
  label,
  live = false,
  actions,
  footer,
  className,
  bodyClassName,
  children,
}: {
  label: ReactNode;
  live?: boolean;
  actions?: ReactNode;
  footer?: ReactNode;
  className?: string;
  bodyClassName?: string;
  children: ReactNode;
}) {
  return (
    <figure
      className={cn(
        'diagram-frame relative min-w-0 overflow-hidden rounded-2xl border bg-fd-card',
        className,
      )}
    >
      <div className="flex h-11 items-center gap-2 border-b px-4 text-xs text-fd-muted-foreground sm:px-5">
        {live ? <span aria-hidden className="live-dot" /> : null}
        <span className="truncate">{label}</span>
        {actions ? (
          <div className="ms-auto flex shrink-0 items-center gap-1.5">{actions}</div>
        ) : null}
      </div>
      <div className={cn('p-4 sm:p-6', bodyClassName)}>{children}</div>
      {footer ? (
        <figcaption className="border-t px-4 py-3 text-xs leading-5 text-fd-muted-foreground sm:px-5">
          {footer}
        </figcaption>
      ) : null}
    </figure>
  );
}

/** Pauses or resumes a diagram that plays by itself. */
export function PlayToggle({
  paused,
  onClick,
  compact = false,
}: {
  paused: boolean;
  onClick: () => void;
  compact?: boolean;
}) {
  const Icon = paused ? Play : Pause;
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={paused ? 'Play the animation' : 'Pause the animation'}
      className="inline-flex h-7 items-center gap-1.5 rounded-lg px-2 text-xs text-fd-muted-foreground transition-colors hover:bg-fd-accent hover:text-fd-foreground"
    >
      <Icon className="size-3" />
      {compact ? null : paused ? 'Play' : 'Pause'}
    </button>
  );
}

export function ReplayButton({
  onClick,
  label = 'Replay',
}: {
  onClick: () => void;
  label?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex h-7 items-center gap-1.5 rounded-lg px-2 text-xs text-fd-muted-foreground transition-colors hover:bg-fd-accent hover:text-fd-foreground"
    >
      <RotateCcw className="size-3" />
      {label}
    </button>
  );
}

/** A two-to-four option switch whose selected thumb is drawn by the caller (so it can animate between options). */
export function segmentClass(active: boolean) {
  return cn(
    'relative z-0 inline-flex h-8 items-center rounded-lg px-3 text-xs font-medium transition-colors',
    active ? 'text-fd-foreground' : 'text-fd-muted-foreground hover:text-fd-foreground',
  );
}
