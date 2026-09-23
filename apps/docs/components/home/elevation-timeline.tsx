'use client';

import { useEffect, useRef, useState, type KeyboardEvent, type PointerEvent } from 'react';
import { AnimatePresence, animate, motion } from 'motion/react';
import {
  RiCheckLine,
  RiCloseLine,
  RiShieldCheckLine,
  RiTimeLine,
  RiUserFollowLine,
} from 'react-icons/ri';
import { cx } from '@/utils/cx';
import { DiagramFrame, PlayToggle, ReplayButton } from './frame';
import { ease, useStepper } from './motion';

/**
 * Just-in-time elevation, as documented in guides/privileged-access/elevation: an eligible binding grants nothing,
 * an activation needs a reason, an MFA session, and (here) an approver, and it ends by itself at `expiresAt`.
 * Hovering a phase previews it; clicking or dragging along the track scrubs to it.
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
const WINDOW = 30 * 60;

export function ElevationTimeline() {
  const { ref, step, select, replay, toggle, paused } = useStepper(phases.length, {
    interval: (current) => (current === ACTIVE ? 3600 : 2300),
    hold: 3200,
  });
  // The phase under the pointer (or keyboard focus) previews in the panel below without moving the timeline.
  const [preview, setPreview] = useState<number | null>(null);
  const scrubbing = useRef(false);
  const shown = preview ?? step;
  const phase = phases[shown]!;
  const progress = step / (phases.length - 1);

  function indexAt(event: PointerEvent<HTMLElement>) {
    const rect = event.currentTarget.getBoundingClientRect();
    const index = Math.floor(((event.clientX - rect.left) / rect.width) * phases.length);
    return Math.min(phases.length - 1, Math.max(0, index));
  }

  function onPointerDown(event: PointerEvent<HTMLOListElement>) {
    // Touch keeps its taps (the buttons' clicks) and vertical scrolling; mouse and pen can drag along the track.
    if (event.button !== 0 || event.pointerType === 'touch') return;
    scrubbing.current = true;
    event.currentTarget.setPointerCapture(event.pointerId);
    select(indexAt(event));
  }

  function onPointerMove(event: PointerEvent<HTMLOListElement>) {
    if (!scrubbing.current) return;
    const index = indexAt(event);
    setPreview(index);
    if (index !== step) select(index);
  }

  function onPointerUp(event: PointerEvent<HTMLOListElement>) {
    scrubbing.current = false;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  }

  function onKeyDown(event: KeyboardEvent<HTMLOListElement>) {
    const delta = event.key === 'ArrowRight' ? 1 : event.key === 'ArrowLeft' ? -1 : 0;
    if (!delta) return;
    event.preventDefault();
    const next = Math.min(phases.length - 1, Math.max(0, step + delta));
    select(next);
    event.currentTarget.querySelectorAll<HTMLButtonElement>('button')[next]?.focus();
  }

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
        {/* Track: hover to preview a phase, click or drag to scrub. */}
        <div className="relative px-1 pt-1">
          <div className="absolute top-[1.0625rem] right-[10%] left-[10%] h-0.5 rounded-full bg-background-tertiary-default" />
          <motion.div
            className="absolute top-[1.0625rem] left-[10%] h-0.5 w-[80%] origin-left rounded-full bg-text-primary"
            initial={false}
            animate={{ scaleX: progress }}
            transition={{ duration: 0.6, ease }}
          />
          <ol
            className="relative grid touch-pan-y grid-cols-5 select-none"
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            onPointerCancel={onPointerUp}
            onMouseLeave={() => setPreview(null)}
            onKeyDown={onKeyDown}
          >
            {phases.map((item, index) => {
              const reached = index <= step;
              const previewed = preview === index && index !== step;
              return (
                <motion.li
                  key={item.label}
                  className="group flex cursor-pointer flex-col items-center gap-2"
                  onMouseEnter={() => setPreview(index)}
                  initial={{ opacity: 0, y: 6 }}
                  whileInView={{ opacity: 1, y: 0 }}
                  viewport={{ once: true, amount: 0.5 }}
                  transition={{ delay: index * 0.07, duration: 0.4, ease }}
                >
                  <button
                    type="button"
                    onClick={() => select(index)}
                    onFocus={() => setPreview(index)}
                    onBlur={() => setPreview(null)}
                    aria-label={`Show ${item.label}`}
                    aria-current={index === step ? 'step' : undefined}
                    className={cx(
                      'relative flex size-8 cursor-pointer items-center justify-center rounded-full border-2 bg-surface-raised transition-[border-color,background-color,translate,scale] duration-300 active:scale-95 motion-safe:group-hover:-translate-y-0.5',
                      reached
                        ? 'border-text-primary'
                        : 'border-border-button-default group-hover:border-border-button-hover',
                      index === ACTIVE && reached && 'bg-text-primary',
                    )}
                  >
                    {index === step ? (
                      <motion.span
                        layoutId="elevation-ring"
                        className="absolute -inset-1.5 rounded-full border border-text-tertiary"
                        transition={{ type: 'spring', stiffness: 400, damping: 32 }}
                      />
                    ) : null}
                    <AnimatePresence>
                      {previewed ? (
                        <motion.span
                          aria-hidden
                          className="absolute -inset-1.5 rounded-full border border-dashed border-text-tertiary"
                          initial={{ opacity: 0, scale: 0.8 }}
                          animate={{ opacity: 1, scale: 1 }}
                          exit={{ opacity: 0, scale: 0.8 }}
                          transition={{ duration: 0.2 }}
                        />
                      ) : null}
                    </AnimatePresence>
                    <PhaseIcon index={index} reached={reached} />
                  </button>
                  <span
                    className={cx(
                      'text-center text-caption-1-medium transition-colors',
                      index === shown
                        ? 'text-text-primary'
                        : 'text-text-secondary group-hover:text-text-primary',
                    )}
                  >
                    {item.label}
                  </span>
                </motion.li>
              );
            })}
          </ol>
        </div>

        {/* Current (or previewed) phase */}
        <div className="mt-6 grid gap-4 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-start">
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={shown}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -6 }}
              transition={{ duration: 0.25, ease }}
              className="flex min-h-[4.5rem] flex-col gap-1.5"
            >
              <p className="text-headline-medium text-text-primary">
                {phase.title}{' '}
                {shown !== step ? (
                  <span className="ms-1 inline-block rounded-md border border-dashed border-border-button-hover px-1.5 align-[0.125rem] font-mono text-caption-2-regular text-text-secondary">
                    preview
                  </span>
                ) : null}
              </p>
              <p className="text-body-2-regular leading-5 text-text-secondary">{phase.body}</p>
              {phase.event ? (
                <p className="mt-1 inline-flex w-fit items-center gap-1.5 rounded-md border border-border-button-default bg-background-primary-default px-2 py-0.5 font-mono text-caption-2-regular text-text-secondary">
                  <span className="size-1.5 rounded-full bg-text-primary" /> audit · {phase.event}
                </p>
              ) : null}
            </motion.div>
          </AnimatePresence>
          <StatusCard active={phase.allowed} step={shown} />
        </div>

        {/* Effective access over time */}
        <div className="mt-6 border-t border-separator-border pt-4">
          <p className="mb-2 flex items-center justify-between text-caption-1-regular text-text-secondary">
            <span>
              Can Alice run <span className="font-mono text-text-primary">deploy:production</span>?
            </span>
            <span className="font-mono">time →</span>
          </p>
          <div className="grid grid-cols-5 gap-1" onMouseLeave={() => setPreview(null)}>
            {phases.map((item, index) => (
              <motion.div
                key={item.label}
                role="presentation"
                onMouseEnter={() => setPreview(index)}
                onClick={() => select(index)}
                className={cx(
                  'relative h-7 cursor-pointer overflow-hidden rounded-md bg-background-tertiary-default outline-offset-2 transition-[outline-color] duration-200',
                  index === preview
                    ? 'outline-1 outline-text-primary'
                    : 'outline-1 outline-transparent hover:outline-border-button-hover',
                )}
                initial={{ opacity: 0, y: 4 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.5 }}
                transition={{ delay: 0.2 + index * 0.06, duration: 0.35, ease }}
              >
                <motion.div
                  className={cx(
                    'absolute inset-0 flex items-center justify-center gap-1 rounded-md text-caption-2-medium',
                    item.allowed
                      ? 'bg-text-primary text-background-full'
                      : 'hatch border border-dashed border-text-primary text-text-primary',
                  )}
                  initial={false}
                  animate={{ clipPath: index <= step ? 'inset(0 0% 0 0)' : 'inset(0 100% 0 0)' }}
                  transition={{ duration: 0.45, ease }}
                >
                  {item.allowed ? (
                    <RiCheckLine className="size-3" aria-hidden />
                  ) : (
                    <RiCloseLine className="size-3" aria-hidden />
                  )}
                  <span className="hidden sm:inline">{item.allowed ? 'allowed' : 'denied'}</span>
                </motion.div>
              </motion.div>
            ))}
          </div>
        </div>
      </DiagramFrame>
    </div>
  );
}

function PhaseIcon({ index, reached }: { index: number; reached: boolean }) {
  const className = cx(
    'relative size-3.5 transition-colors duration-300',
    reached
      ? index === ACTIVE
        ? 'text-background-full'
        : 'text-text-primary'
      : 'text-foreground-icon-tertiary group-hover:text-text-secondary',
  );
  if (index === 0) return <RiShieldCheckLine className={className} aria-hidden />;
  if (index === 1) return <RiTimeLine className={className} aria-hidden />;
  if (index === 2) return <RiUserFollowLine className={className} aria-hidden />;
  if (index === ACTIVE) return <RiCheckLine className={cx(className, 'size-4')} aria-hidden />;
  return <RiCloseLine className={className} aria-hidden />;
}

/**
 * The activation's `active` flag, with a remaining-time readout and a window bar that run down while the role
 * applies, then close at expiry.
 */
function StatusCard({ active, step }: { active: boolean; step: number }) {
  const [remaining, setRemaining] = useState(WINDOW);

  useEffect(() => {
    if (step < ACTIVE) {
      setRemaining(WINDOW);
      return;
    }
    if (step > ACTIVE) {
      setRemaining(0);
      return;
    }
    const controls = animate(WINDOW, 0, {
      duration: 3.3,
      ease: 'linear',
      onUpdate: (value) => setRemaining(Math.round(value)),
    });
    return () => controls.stop();
  }, [step]);

  const minutes = String(Math.floor(remaining / 60)).padStart(2, '0');
  const seconds = String(remaining % 60).padStart(2, '0');
  const expired = step > ACTIVE;

  return (
    <div
      className={cx(
        'flex w-full flex-col gap-2.5 rounded-xl border bg-background-primary-default px-3.5 py-2.5 shadow-xs transition-colors duration-300 sm:w-52',
        active ? 'border-text-primary' : 'border-border-button-default',
      )}
    >
      <div className="flex items-center gap-3">
        <div className="flex flex-col gap-1">
          <span className="text-caption-2-regular text-text-secondary">activation.active</span>
          <AnimatePresence mode="wait" initial={false}>
            <motion.span
              key={String(active)}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.2 }}
              className={cx(
                'w-fit rounded-md border px-1.5 font-mono text-body-2-regular',
                active
                  ? 'border-text-primary bg-text-primary text-background-full'
                  : 'border-dashed border-border-button-hover text-text-secondary',
              )}
            >
              {String(active)}
            </motion.span>
          </AnimatePresence>
        </div>
        <div className="ms-auto flex flex-col items-end gap-1">
          <span className="text-caption-2-regular text-text-secondary">
            {expired ? 'expired' : 'remaining'}
          </span>
          <motion.span
            key={expired ? 'expired' : 'running'}
            initial={expired ? { opacity: 0, scale: 0.9 } : false}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ type: 'spring', stiffness: 420, damping: 22 }}
            className={cx(
              'font-mono text-body-regular tabular-nums',
              step === ACTIVE ? 'text-text-primary' : 'text-text-secondary',
              expired && 'line-through decoration-text-tertiary',
            )}
          >
            {minutes}:{seconds}
          </motion.span>
        </div>
      </div>
      {/* The activation window: full until it starts, draining while it is live, empty once it expires. */}
      <div aria-hidden className="h-1 overflow-hidden rounded-full bg-background-secondary-default">
        <div
          className={cx(
            'h-full rounded-full duration-500',
            // Frame-by-frame while counting down; eased when the window opens or closes.
            step === ACTIVE ? 'transition-none' : 'transition-[width,background-color]',
            step === ACTIVE || (active && step < ACTIVE)
              ? 'bg-text-primary'
              : 'bg-border-button-hover',
          )}
          style={{ width: `${(remaining / WINDOW) * 100}%` }}
        />
      </div>
    </div>
  );
}
