'use client';

import { useEffect, useState } from 'react';
import { AnimatePresence, animate, motion } from 'motion/react';
import { Check, Clock3, ShieldCheck, UserCheck, X } from 'lucide-react';
import { cn } from '@/lib/cn';
import { DiagramFrame, PlayToggle, ReplayButton } from './frame';
import { ease, useStepper } from './motion';

/**
 * Just-in-time elevation, as documented in guides/privileged-access/elevation: an eligible binding grants nothing,
 * an activation needs a reason, an MFA session, and (here) an approver, and it ends by itself at `expiresAt`.
 */
const phases = [
  {
    label: 'Eligible',
    title: 'Alice is eligible for Production admin',
    body: 'An eligible binding grants nothing until it is activated.',
    event: null,
    allowed: false,
  },
  {
    label: 'Request',
    title: 'She activates it with a reason',
    body: 'Justification “INC-4211”, from a session that completed MFA, for 30 minutes.',
    event: 'binding:activation-requested',
    allowed: false,
  },
  {
    label: 'Approve',
    title: 'The platform team approves',
    body: 'Two-person control: a member of the approver group decides, never the requester. The role applies from now.',
    event: 'binding:activation-approved',
    allowed: true,
  },
  {
    label: 'Active',
    title: 'The role applies, like a standing binding',
    body: 'Decisions, policy conditions, and access reviews all see it while it is live.',
    event: null,
    allowed: true,
  },
  {
    label: 'Expired',
    title: 'It ends on its own',
    body: 'At expiresAt it stops granting at the next request. Nobody has to remember to revoke it.',
    event: null,
    allowed: false,
  },
] as const;

const ACTIVE = 3;

export function ElevationTimeline() {
  const { ref, step, select, replay, toggle, paused } = useStepper(phases.length, {
    interval: (current) => (current === ACTIVE ? 3600 : 2300),
    hold: 3200,
  });
  const phase = phases[step]!;
  const progress = step / (phases.length - 1);

  return (
    <div ref={ref}>
      <DiagramFrame
        live={!paused}
        label={
          <>
            Just-in-time elevation · <span className="font-mono">Production admin</span>
          </>
        }
        actions={
          <>
            <PlayToggle paused={paused} onClick={toggle} compact />
            <ReplayButton onClick={replay} />
          </>
        }
      >
        {/* Track */}
        <div className="relative px-1 pt-1">
          <div className="absolute left-[10%] right-[10%] top-[1.0625rem] h-0.5 rounded-full bg-fd-muted" />
          <motion.div
            className="absolute left-[10%] top-[1.0625rem] h-0.5 w-[80%] origin-left rounded-full bg-fd-primary"
            initial={false}
            animate={{ scaleX: progress }}
            transition={{ duration: 0.6, ease }}
          />
          <ol className="relative grid grid-cols-5">
            {phases.map((item, index) => {
              const reached = index <= step;
              return (
                <li key={item.label} className="flex flex-col items-center gap-2">
                  <button
                    type="button"
                    onClick={() => select(index)}
                    aria-label={`Show ${item.label}`}
                    aria-current={index === step ? 'step' : undefined}
                    className={cn(
                      'relative flex size-8 items-center justify-center rounded-full border-2 bg-fd-card transition-colors duration-300',
                      reached ? 'border-fd-primary' : 'border-fd-border',
                      index === ACTIVE && reached && 'bg-fd-primary',
                    )}
                  >
                    {index === step ? (
                      <motion.span
                        layoutId="elevation-ring"
                        className="absolute -inset-1.5 rounded-full border border-fd-primary/40"
                        transition={{ type: 'spring', stiffness: 400, damping: 32 }}
                      />
                    ) : null}
                    <PhaseIcon index={index} reached={reached} />
                  </button>
                  <span
                    className={cn(
                      'text-center text-xs font-medium transition-colors',
                      index === step ? 'text-fd-foreground' : 'text-fd-muted-foreground',
                    )}
                  >
                    {item.label}
                  </span>
                </li>
              );
            })}
          </ol>
        </div>

        {/* Current phase */}
        <div className="mt-6 grid gap-4 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-start">
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={step}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.3, ease }}
              className="flex min-h-[4.5rem] flex-col gap-1.5"
            >
              <p className="text-[0.9375rem] font-medium">{phase.title}</p>
              <p className="text-[0.8125rem] leading-5 text-fd-muted-foreground">{phase.body}</p>
              {phase.event ? (
                <p className="mt-1 inline-flex w-fit items-center gap-1.5 rounded-md border bg-fd-background px-2 py-0.5 font-mono text-[0.6875rem] text-fd-muted-foreground">
                  <span className="size-1.5 rounded-full bg-fd-primary" /> audit · {phase.event}
                </p>
              ) : null}
            </motion.div>
          </AnimatePresence>
          <StatusCard active={phase.allowed} step={step} />
        </div>

        {/* Effective access over time */}
        <div className="mt-6 border-t pt-4">
          <p className="mb-2 flex items-center justify-between text-xs text-fd-muted-foreground">
            <span>
              Can Alice run <span className="font-mono text-fd-foreground">deploy:production</span>?
            </span>
            <span className="font-mono">time →</span>
          </p>
          <div className="grid grid-cols-5 gap-1">
            {phases.map((item, index) => (
              <div key={item.label} className="relative h-7 overflow-hidden rounded-md bg-fd-muted">
                <motion.div
                  className={cn(
                    'absolute inset-0 flex items-center justify-center gap-1 text-[0.6875rem] font-medium',
                    item.allowed
                      ? 'bg-emerald-500/20 text-emerald-700 dark:text-emerald-300'
                      : 'bg-red-500/10 text-red-600/80 dark:text-red-400/80',
                  )}
                  initial={false}
                  animate={{ clipPath: index <= step ? 'inset(0 0% 0 0)' : 'inset(0 100% 0 0)' }}
                  transition={{ duration: 0.45, ease }}
                >
                  {item.allowed ? <Check className="size-3" /> : <X className="size-3" />}
                  <span className="hidden sm:inline">{item.allowed ? 'allowed' : 'denied'}</span>
                </motion.div>
              </div>
            ))}
          </div>
        </div>
      </DiagramFrame>
    </div>
  );
}

function PhaseIcon({ index, reached }: { index: number; reached: boolean }) {
  const className = cn(
    'relative size-3.5',
    reached
      ? index === ACTIVE
        ? 'text-fd-primary-foreground'
        : 'text-fd-primary'
      : 'text-fd-muted-foreground',
  );
  if (index === 0) return <ShieldCheck className={className} />;
  if (index === 1) return <Clock3 className={className} />;
  if (index === 2) return <UserCheck className={className} />;
  if (index === ACTIVE) return <Check className={className} strokeWidth={3} />;
  return <X className={className} />;
}

/** The activation's `active` flag, with a remaining-time readout that runs down while the role applies. */
function StatusCard({ active, step }: { active: boolean; step: number }) {
  const [remaining, setRemaining] = useState(30 * 60);

  useEffect(() => {
    if (step < ACTIVE) {
      setRemaining(30 * 60);
      return;
    }
    if (step > ACTIVE) {
      setRemaining(0);
      return;
    }
    const controls = animate(30 * 60, 0, {
      duration: 3.3,
      ease: 'linear',
      onUpdate: (value) => setRemaining(Math.round(value)),
    });
    return () => controls.stop();
  }, [step]);

  const minutes = String(Math.floor(remaining / 60)).padStart(2, '0');
  const seconds = String(remaining % 60).padStart(2, '0');

  return (
    <div className="flex w-full items-center gap-3 rounded-xl border bg-fd-background px-3.5 py-2.5 sm:w-52">
      <div className="flex flex-col gap-0.5">
        <span className="text-[0.6875rem] text-fd-muted-foreground">activation.active</span>
        <AnimatePresence mode="wait" initial={false}>
          <motion.span
            key={String(active)}
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.2 }}
            className={cn(
              'font-mono text-sm',
              active ? 'text-emerald-600 dark:text-emerald-400' : 'text-fd-muted-foreground',
            )}
          >
            {String(active)}
          </motion.span>
        </AnimatePresence>
      </div>
      <div className="ms-auto flex flex-col items-end gap-0.5">
        <span className="text-[0.6875rem] text-fd-muted-foreground">remaining</span>
        <span
          className={cn(
            'font-mono text-sm tabular-nums',
            step === ACTIVE ? 'text-fd-foreground' : 'text-fd-muted-foreground',
          )}
        >
          {minutes}:{seconds}
        </span>
      </div>
    </div>
  );
}
