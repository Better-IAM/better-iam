'use client';

import type { KeyboardEvent, ReactNode } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { RiCheckLine, RiFileCodeLine, RiPauseLine, RiPlayLine } from 'react-icons/ri';
import { Chip } from '@/components/base/badges/chip';
import { cx } from '@/utils/cx';
import { ease, useStepper } from './motion';

/**
 * The request pipeline as one compact frame that plays by itself: a trace timeline whose segments are sized like
 * the stages' share of the request, and a horizontal track of stage panels that slides to the stage in progress.
 * Readers can pick a stage (which pauses the autoplay) or pause it outright. The wording follows "The request
 * pipeline" in guides/concepts.
 */
const INTERVAL = 4200;

const stages: {
  label: string;
  title: string;
  body: ReactNode;
  detail: ReactNode;
  note?: string;
  bar: [number, number];
  afterCommit?: boolean;
}[] = [
  {
    label: 'Credential',
    title: 'Resolve the credential',
    detail: 'The cookie resolves to an identity and a session.',
    body: 'The session cookie, bearer token, or API key becomes an identity and a session. When the call carries request headers, the client’s address comes from them too, so network rules judge the address that actually presented the credential.',
    bar: [0, 12],
  },
  {
    label: 'Re-validate',
    title: 'Re-validate inside the transaction',
    detail: 'Identity active, session live, MFA and network rules hold.',
    body: 'An administrator may have disabled the person or ended the session a moment ago, so the transaction re-reads both and checks every revocation condition again: status, expiry, tenant ancestry, idle timeout, MFA, and network rules.',
    bar: [12, 26],
  },
  {
    label: 'Authorize',
    title: 'Authorize the operation',
    detail: (
      <>
        <code>iam:identities:create</code> on <code>iam/{'{tenantId}'}</code> is allowed.
      </>
    ),
    body: 'Every provisioning operation is itself an action on a resource, evaluated like any product action against roles, policies, boundaries, and grant authorities. A denial commits only a deny audit event, and the caller receives a typed error.',
    note: 'ACCESS_DENIED · 403',
    bar: [26, 46],
  },
  {
    label: 'Apply',
    title: 'Apply the change',
    detail: 'The invitation is written, then duty and invariant checks run.',
    body: 'Plugin hooks run around the change itself, then separation-of-duties rules and access invariants are checked. Any failure rolls the whole transaction back, so a change that breaks a rule never becomes visible.',
    note: 'INVARIANT_VIOLATION · 409',
    bar: [46, 76],
  },
  {
    label: 'Audit',
    title: 'Append the audit event',
    detail: 'An event joins the tenant’s SHA-256 hash chain.',
    body: 'One event joins the tenant’s hash chain in the same transaction. Each event includes the hash of the one before, so altering, reordering, or removing a record is detectable.',
    bar: [76, 88],
  },
  {
    label: 'Fan-out',
    title: 'Fan out after commit',
    detail: 'After commit: webhooks and subscribers.',
    body: 'Subscribers, plugin afterAudit hooks, and signed webhooks are queued in the transaction and dispatched once it commits. Nothing is emitted for a change that rolled back.',
    bar: [88, 100],
    afterCommit: true,
  },
];

export function PipelineCarousel({ code }: { code: ReactNode }) {
  const { ref, step, select, toggle, paused, hovered, setHovered } = useStepper(stages.length, {
    interval: INTERVAL,
    hold: INTERVAL + 1800,
  });
  const complete = step === stages.length - 1;

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const delta = event.key === 'ArrowRight' ? 1 : event.key === 'ArrowLeft' ? -1 : 0;
    if (!delta) return;
    event.preventDefault();
    const next = (step + delta + stages.length) % stages.length;
    select(next);
    event.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus();
  }

  return (
    <div
      ref={ref}
      className="border-t border-separator-border"
      onPointerEnter={(event) => event.pointerType === 'mouse' && setHovered(true)}
      onPointerLeave={() => setHovered(false)}
    >
      {/* Trace timeline */}
      <div className="px-5 pt-6 pb-5 sm:px-8 lg:px-12">
        <div className="mb-7 flex items-center gap-3">
          <span className="eyebrow">Trace · one request</span>
          <AnimatePresence mode="wait" initial={false}>
            {complete ? (
              <motion.span
                key="done"
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.3, ease }}
                className="inline-flex items-center gap-1.5 rounded-full bg-text-primary px-2.5 py-0.5 text-caption-1-medium text-background-full"
              >
                <RiCheckLine className="size-3.5" aria-hidden /> Allowed · committed
              </motion.span>
            ) : (
              <motion.span
                key={paused ? 'paused' : hovered ? 'held' : 'running'}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="inline-flex items-center gap-1.5 rounded-full bg-background-secondary-default px-2.5 py-0.5 text-caption-1-medium text-text-secondary"
              >
                {paused ? (
                  'Paused'
                ) : hovered ? (
                  'Held while you read'
                ) : (
                  <>
                    <span className="live-dot" /> Running
                  </>
                )}
              </motion.span>
            )}
          </AnimatePresence>
          <button
            type="button"
            onClick={toggle}
            aria-label={paused ? 'Play the pipeline' : 'Pause the pipeline'}
            className="ms-auto inline-flex h-7 items-center gap-1.5 rounded-lg px-2 text-caption-1-medium text-text-secondary transition-colors hover:bg-background-secondary-default hover:text-text-primary"
          >
            {paused ? <RiPlayLine className="size-3.5" /> : <RiPauseLine className="size-3.5" />}
            {paused ? 'Play' : 'Pause'}
          </button>
        </div>

        <div
          role="tablist"
          aria-label="Pipeline stages"
          onKeyDown={onKeyDown}
          className="relative flex gap-1.5"
        >
          {stages.map((stage, index) => {
            const state = index < step ? 'done' : index === step ? 'active' : 'pending';
            return (
              <button
                key={stage.label}
                type="button"
                role="tab"
                aria-selected={index === step}
                aria-controls="pipeline-panel"
                tabIndex={index === step ? 0 : -1}
                onClick={() => select(index)}
                style={{ ['--w' as string]: stage.bar[1] - stage.bar[0] }}
                className="group flex min-w-0 flex-1 cursor-pointer flex-col gap-2 text-start sm:grow-[var(--w)]"
              >
                <span className="relative block h-2 overflow-hidden rounded-full bg-background-tertiary-default transition-[height,margin] duration-200 group-hover:-my-0.5 group-hover:h-3">
                  <motion.span
                    key={state === 'active' ? `${step}-${paused}-${hovered}` : state}
                    className={cx(
                      'absolute inset-0 origin-left rounded-full',
                      stage.afterCommit ? 'trace-bar-after' : 'bg-text-primary',
                    )}
                    initial={{
                      scaleX: state === 'done' || (state === 'active' && hovered) ? 1 : 0,
                    }}
                    animate={{ scaleX: state === 'pending' ? 0 : 1 }}
                    transition={
                      state === 'active' && !paused && !hovered
                        ? { duration: INTERVAL / 1000, ease: 'linear' }
                        : { duration: 0.3, ease }
                    }
                  />
                  {state === 'pending' ? (
                    <span className="absolute inset-0 origin-left scale-x-0 rounded-full bg-text-tertiary transition-transform duration-300 group-hover:scale-x-100" />
                  ) : null}
                </span>
                <span className="flex items-baseline gap-1.5">
                  <span
                    className={cx(
                      'font-mono text-caption-2-regular tabular-nums',
                      state === 'pending' ? 'text-text-tertiary' : 'text-text-primary',
                    )}
                  >
                    0{index + 1}
                  </span>
                  <span
                    className={cx(
                      'hidden truncate text-caption-1-medium transition-colors md:inline',
                      state === 'active'
                        ? 'text-text-primary'
                        : 'text-text-secondary group-hover:text-text-primary',
                    )}
                  >
                    {stage.label}
                  </span>
                </span>
              </button>
            );
          })}
          {/* The commit point: everything to the right of it happens after the transaction commits. */}
          <span
            aria-hidden
            className="pointer-events-none absolute -top-3 hidden h-8 border-s border-dashed border-text-tertiary sm:block"
            // Segments grow with their share of the request; five 6px gaps shift the 88% boundary by 6.6px.
            style={{ left: 'calc(88% + 6.6px)' }}
          >
            <span className="absolute -top-4 -translate-x-1/2 font-mono text-caption-2-regular text-text-tertiary">
              commit
            </span>
          </span>
        </div>
      </div>

      {/* Code beside the sliding stage panels */}
      <div className="grid border-t border-separator-border lg:grid-cols-12">
        <div className="flex min-w-0 flex-col border-b border-separator-border lg:col-span-5 lg:border-e lg:border-b-0">
          <div className="flex h-10 items-center gap-2 border-b border-separator-border px-5 text-caption-1-regular text-text-secondary sm:px-8 lg:ps-12 lg:pe-5">
            <RiFileCodeLine className="size-3.5" aria-hidden />
            <span className="font-mono">routes/invite.ts</span>
          </div>
          <div
            data-lenis-prevent-horizontal
            data-focus={step === 0 ? 'credential' : 'call'}
            className="pipeline-code home-code overflow-x-auto px-5 py-5 font-mono text-[0.78rem] leading-[1.35rem] sm:px-8 lg:ps-12 lg:pe-5"
          >
            {code}
          </div>
          <p className="mt-auto border-t border-separator-border px-5 py-3 text-caption-1-regular leading-5 text-text-secondary sm:px-8 lg:ps-12 lg:pe-5">
            Browser, server action, CLI, and SCIM calls all enter this same pipeline.
          </p>
        </div>

        <div
          id="pipeline-panel"
          role="tabpanel"
          aria-label={stages[step]!.title}
          className="relative min-w-0 overflow-hidden py-6 lg:col-span-7 lg:py-8"
        >
          <div className="ps-5 sm:ps-8">
            <motion.ol
              className="flex"
              initial={false}
              animate={{ x: `-${step * 84}%` }}
              transition={{ duration: 0.7, ease }}
            >
              {stages.map((stage, index) => {
                const current = index === step;
                return (
                  <li key={stage.label} className="w-[84%] shrink-0 pe-4" aria-hidden={!current}>
                    <motion.button
                      type="button"
                      tabIndex={-1}
                      onClick={() => select(index)}
                      className={cx(
                        'flex h-full w-full flex-col gap-3 rounded-2xl border p-5 text-start transition-[border-color,box-shadow] duration-300 sm:p-6',
                        current
                          ? 'cursor-default border-border-button-default bg-surface-raised shadow-sm hover:border-border-button-hover hover:shadow-md'
                          : 'cursor-pointer border-separator-border bg-transparent hover:border-border-button-hover',
                      )}
                      animate={{ opacity: current ? 1 : 0.4, scale: current ? 1 : 0.97 }}
                      // The next stage peeks in from the right; pointing at it brings it forward.
                      whileHover={current ? { y: -3 } : { opacity: 0.75, scale: 0.985 }}
                      whileTap={current ? undefined : { scale: 0.97 }}
                      transition={{ duration: 0.5, ease }}
                    >
                      <span className="flex items-center gap-2">
                        <span className="flex size-6 items-center justify-center rounded-full bg-text-primary font-mono text-caption-2-semibold text-background-full tabular-nums">
                          {index + 1}
                        </span>
                        <span className="eyebrow">{stage.label}</span>
                        {stage.afterCommit ? (
                          <Chip variant="caption" color="soft" className="ms-auto">
                            after commit
                          </Chip>
                        ) : null}
                      </span>
                      <span className="text-title-2-semibold tracking-[-0.015em]">
                        {stage.title}
                      </span>
                      <motion.span
                        key={current ? `detail-${step}` : 'detail'}
                        className="rounded-lg border border-dashed border-border-button-default px-3 py-2 text-body-2-regular text-text-primary [&_code]:font-mono [&_code]:text-caption-1-regular"
                        initial={current ? { opacity: 0, x: 12 } : false}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ duration: 0.5, ease, delay: 0.25 }}
                      >
                        {stage.detail}
                      </motion.span>
                      <span className="text-body-regular leading-6 text-text-secondary">
                        {stage.body}
                      </span>
                      {stage.note ? (
                        <span className="mt-auto w-fit rounded-md border border-border-button-default bg-background-secondary-default px-2 py-0.5 font-mono text-caption-2-regular text-text-secondary">
                          on failure: {stage.note}
                        </span>
                      ) : null}
                    </motion.button>
                  </li>
                );
              })}
            </motion.ol>
          </div>
        </div>
      </div>
    </div>
  );
}
