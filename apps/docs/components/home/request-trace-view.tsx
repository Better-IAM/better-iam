'use client';

import type { ReactNode } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { Check, FileCode2 } from 'lucide-react';
import { cn } from '@/lib/cn';
import { PlayToggle } from './frame';
import { ease, useStepper } from './motion';

export const stages: {
  label: string;
  detail: ReactNode;
  bar: [number, number];
  afterCommit?: boolean;
}[] = [
  {
    label: 'Credential',
    detail: 'The cookie resolves to an identity and a session.',
    bar: [0, 12],
  },
  {
    label: 'Re-validate',
    detail: 'Inside the transaction: identity active, session live, MFA and network rules hold.',
    bar: [12, 26],
  },
  {
    label: 'Authorize',
    detail: (
      <>
        <code>iam:identities:create</code> on <code>iam/{'{tenantId}'}</code> is allowed.
      </>
    ),
    bar: [26, 46],
  },
  {
    label: 'Apply',
    detail: 'The invitation is written, then duty and invariant checks run.',
    bar: [46, 76],
  },
  { label: 'Audit', detail: 'An event joins the tenant’s SHA-256 hash chain.', bar: [76, 88] },
  {
    label: 'Fan-out',
    detail: 'After commit: webhooks and subscribers.',
    bar: [88, 100],
    afterCommit: true,
  },
];

/**
 * The pipeline trace. By default it plays by itself; pass `step` to drive it from outside (the scroll story does),
 * and `stacked` to put the code above the trace for narrow columns.
 */
export function RequestTraceView({
  code,
  step: controlledStep,
  stacked = false,
}: {
  code: ReactNode;
  step?: number;
  stacked?: boolean;
}) {
  const auto = useStepper(stages.length + 1, { interval: 650, hold: 3600 });
  const controlled = controlledStep !== undefined;
  const step = controlled ? controlledStep : auto.step;
  const { ref, toggle, paused } = auto;
  const complete = step >= stages.length;

  return (
    <div
      ref={ref}
      className="hero-frame relative overflow-hidden rounded-2xl border bg-fd-card text-start"
    >
      <div className={cn('grid', !stacked && 'lg:grid-cols-[minmax(0,0.92fr)_minmax(0,1.08fr)]')}>
        {/* Code pane */}
        <div
          className={cn('flex min-w-0 flex-col border-b', !stacked && 'lg:border-b-0 lg:border-e')}
        >
          <PaneBar>
            <FileCode2 className="size-3.5" />
            <span className="font-mono">routes/invite.ts</span>
          </PaneBar>
          <div className="home-code overflow-x-auto px-5 py-5 font-mono text-[0.8125rem] leading-6">
            {code}
          </div>
          <p
            className={cn(
              'mt-auto hidden border-t px-5 py-3 text-xs leading-5 text-fd-muted-foreground',
              !stacked && 'lg:block',
            )}
          >
            Browser, server action, CLI, and SCIM calls all enter this same pipeline.
          </p>
        </div>

        {/* Trace pane */}
        <div className="flex min-w-0 flex-col">
          <PaneBar>
            <span>Pipeline trace</span>
            <span className="ms-auto flex items-center gap-1">
              {controlled ? null : <PlayToggle paused={paused} onClick={toggle} compact />}
              <AnimatePresence mode="wait" initial={false}>
                {complete ? (
                  <motion.span
                    key="done"
                    initial={{ opacity: 0, scale: 0.9 }}
                    animate={{ opacity: 1, scale: 1 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.35, ease }}
                    className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-2 py-0.5 text-[0.6875rem] font-medium text-emerald-700 dark:text-emerald-300"
                  >
                    <Check className="size-3" /> Allowed · committed
                  </motion.span>
                ) : (
                  <motion.span
                    key={paused ? 'paused' : 'running'}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    className="inline-flex items-center gap-1.5 rounded-full bg-fd-muted px-2 py-0.5 text-[0.6875rem] font-medium"
                  >
                    {paused ? (
                      'Paused'
                    ) : (
                      <>
                        <span className="live-dot" /> Running
                      </>
                    )}
                  </motion.span>
                )}
              </AnimatePresence>
            </span>
          </PaneBar>

          <ol className="relative flex flex-col py-3">
            {/* The spine fills as the request moves down the pipeline. */}
            <span aria-hidden className="absolute bottom-7 left-[1.8rem] top-7 w-px bg-fd-border" />
            <motion.span
              aria-hidden
              className="absolute bottom-7 left-[1.8rem] top-7 w-px origin-top bg-fd-primary"
              animate={{ scaleY: Math.min(step, stages.length - 1) / (stages.length - 1) }}
              transition={{ duration: 0.55, ease }}
            />
            {stages.map((stage, index) => {
              const state = index < step ? 'done' : index === step ? 'running' : 'pending';
              return (
                <li
                  key={stage.label}
                  className="relative isolate grid grid-cols-[1.5rem_minmax(0,1fr)] items-start gap-x-3 px-5 py-2 sm:grid-cols-[1.5rem_5.5rem_minmax(0,1fr)_6rem]"
                >
                  {state === 'running' ? (
                    <motion.span
                      layoutId="trace-active-row"
                      aria-hidden
                      className="absolute inset-x-2 inset-y-0 -z-10 rounded-lg bg-fd-primary/[0.07]"
                      transition={{ type: 'spring', stiffness: 380, damping: 34 }}
                    />
                  ) : null}
                  <StageDot state={state} />
                  <span
                    className={cn(
                      'text-sm font-medium leading-6 transition-colors duration-300',
                      state === 'pending' && 'text-fd-muted-foreground/70',
                    )}
                  >
                    {stage.label}
                  </span>
                  <span
                    className={cn(
                      'col-start-2 text-[0.8125rem] leading-6 transition-opacity duration-300 sm:col-start-auto [&_code]:font-mono [&_code]:text-[0.75rem] [&_code]:text-fd-foreground',
                      state === 'pending'
                        ? 'text-fd-muted-foreground opacity-50'
                        : 'text-fd-muted-foreground',
                    )}
                  >
                    {stage.detail}
                  </span>
                  <span
                    aria-hidden
                    className="relative mt-2.5 hidden h-1.5 rounded-full bg-fd-muted sm:block"
                  >
                    <motion.span
                      className={cn(
                        'absolute inset-y-0 rounded-full',
                        stage.afterCommit ? 'trace-bar-after' : 'bg-fd-primary',
                      )}
                      style={{
                        left: `${stage.bar[0]}%`,
                        width: `${stage.bar[1] - stage.bar[0]}%`,
                        transformOrigin: 'left center',
                      }}
                      initial={false}
                      animate={{ scaleX: state === 'pending' ? 0 : 1 }}
                      transition={{ duration: state === 'running' ? 0.6 : 0.3, ease }}
                    />
                  </span>
                </li>
              );
            })}
          </ol>
          <p
            className={cn(
              'mt-auto border-t px-5 py-3 text-xs leading-5 text-fd-muted-foreground',
              stacked ? 'hidden' : 'lg:hidden',
            )}
          >
            Browser, server action, CLI, and SCIM calls all enter this same pipeline.
          </p>
        </div>
      </div>
    </div>
  );
}

function StageDot({ state }: { state: 'done' | 'running' | 'pending' }) {
  return (
    <span className="relative z-10 mt-1 flex size-4 items-center justify-center justify-self-center">
      {state === 'running' ? (
        <motion.span
          aria-hidden
          className="absolute inset-0 rounded-full bg-fd-primary/30"
          initial={{ scale: 0.6, opacity: 0.9 }}
          animate={{ scale: 1.9, opacity: 0 }}
          transition={{ duration: 1, repeat: Infinity, ease: 'easeOut' }}
        />
      ) : null}
      <span
        className={cn(
          'relative flex size-4 items-center justify-center rounded-full border transition-colors duration-300',
          state === 'pending' ? 'border-fd-border bg-fd-card' : 'border-fd-primary bg-fd-primary',
        )}
      >
        <AnimatePresence>
          {state === 'done' ? (
            <motion.span
              key="check"
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              exit={{ scale: 0 }}
              transition={{ type: 'spring', stiffness: 500, damping: 28 }}
              className="text-fd-primary-foreground"
            >
              <Check className="size-2.5" strokeWidth={3.5} />
            </motion.span>
          ) : null}
        </AnimatePresence>
      </span>
    </span>
  );
}

function PaneBar({ children }: { children: ReactNode }) {
  return (
    <div className="flex h-11 items-center gap-2 border-b px-5 text-xs text-fd-muted-foreground">
      {children}
    </div>
  );
}
