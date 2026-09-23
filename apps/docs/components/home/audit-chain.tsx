'use client';

import { useEffect, useRef, useState } from 'react';
import { AnimatePresence, motion, useInView } from 'motion/react';
import {
  RiCheckLine,
  RiLinkM,
  RiLinkUnlinkM,
  RiShieldCheckLine,
  RiShieldCrossLine,
} from 'react-icons/ri';
import {
  auditEventHash,
  auditGenesis,
  verifyAuditChain,
  type AuditChainVerification,
  type AuditEvent,
} from '@better-iam/core';
import { cx } from '@/utils/cx';
import { DiagramFrame, ReplayButton, segmentClass } from './frame';
import { ease } from './motion';

/**
 * A real audit hash chain, built and verified in the browser with `auditEventHash` and `verifyAuditChain` from
 * @better-iam/core. Each scenario is an attempt to rewrite history; the verifier reports how it was caught.
 * Hovering an event lights up the hashes that tie it to its neighbours; the verifier's walk down the chain plays
 * out record by record, so a break shows where the walk stopped.
 */
type EventBody = Pick<
  AuditEvent,
  'id' | 'tenantId' | 'actorId' | 'action' | 'resourceId' | 'timestamp' | 'outcome'
>;

const base: EventBody[] = [
  {
    id: 'audit_01',
    tenantId: 'acme',
    actorId: 'usr_alice',
    action: 'binding:activation-requested',
    resourceId: 'iam/act_7',
    timestamp: 1790000000000,
    outcome: 'allow',
  },
  {
    id: 'audit_02',
    tenantId: 'acme',
    actorId: 'usr_priya',
    action: 'binding:activation-approved',
    resourceId: 'iam/act_7',
    timestamp: 1790000042000,
    outcome: 'allow',
  },
  {
    id: 'audit_03',
    tenantId: 'acme',
    actorId: 'usr_alice',
    action: 'binding:deactivate',
    resourceId: 'iam/act_7',
    timestamp: 1790001100000,
    outcome: 'allow',
  },
  {
    id: 'audit_04',
    tenantId: 'acme',
    actorId: 'usr_olivia',
    action: 'identity:offboard',
    resourceId: 'iam/usr_bob',
    timestamp: 1790002000000,
    outcome: 'allow',
  },
];

type Scenario = 'intact' | 'edit' | 'rehash' | 'rewrite';

const scenarios: { id: Scenario; label: string; story: string }[] = [
  {
    id: 'intact',
    label: 'Intact',
    story: 'Every event stores the previous event’s hash, so the four form one chain.',
  },
  {
    id: 'edit',
    label: 'Edit #2',
    story:
      'Someone changes who approved the request: Alice now appears to approve her own. Its stored hash no longer matches its contents.',
  },
  {
    id: 'rehash',
    label: 'Re-hash #2',
    story:
      'They recompute #2’s hash to cover the edit. Now #3 points at a hash that no longer exists.',
  },
  {
    id: 'rewrite',
    label: 'Rewrite the rest',
    story:
      'They rewrite every later event too. The chain is self-consistent, but it no longer ends at the head stored for the tenant.',
  },
];

/** The verifier's walk: how long it spends on each event before moving to the next. */
const WALK = 0.15;

/** Chains events the way `appendAuditEvent` does: sequence from 1, genesis `previousHash`, hash over the rest. */
async function chain(events: EventBody[]) {
  const out: AuditEvent[] = [];
  let previousHash = auditGenesis;
  for (const [index, body] of events.entries()) {
    const event: AuditEvent = { ...body, sequence: index + 1, previousHash };
    event.hash = await auditEventHash(event);
    out.push(event);
    previousHash = event.hash;
  }
  return out;
}

async function build(scenario: Scenario) {
  const honest = await chain(base);
  const head = { sequence: honest.at(-1)!.sequence!, hash: honest.at(-1)!.hash! };
  let events = honest.map((event) => ({ ...event }));
  if (scenario !== 'intact') events[1] = { ...events[1]!, actorId: 'usr_alice' };
  if (scenario === 'rehash') events[1]!.hash = await auditEventHash(events[1]!);
  if (scenario === 'rewrite') {
    const edited = base.map((event, index) =>
      index === 1 ? { ...event, actorId: 'usr_alice' } : event,
    );
    events = await chain(edited);
  }
  const verification = await verifyAuditChain(events, { head });
  return { events, verification, honest };
}

type Status = 'pending' | 'verified' | 'broken' | 'unchecked';

export function AuditChain() {
  const [scenario, setScenario] = useState<Scenario>('intact');
  const [result, setResult] = useState<{
    events: AuditEvent[];
    verification: AuditChainVerification;
    honest: AuditEvent[];
    scenario: Scenario;
  }>();
  const [hovered, setHovered] = useState<number | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, amount: 0.3 });

  useEffect(() => {
    let current = true;
    void build(scenario).then((next) => {
      if (current) setResult({ ...next, scenario });
    });
    return () => {
      current = false;
    };
  }, [scenario]);

  const failure = result?.verification.failure;
  const story = scenarios.find((item) => item.id === scenario)!.story;
  // The verifier checks events in order and stops at the first failure: everything before it verified, nothing
  // after it checked.
  const status = (index: number): Status =>
    !result
      ? 'pending'
      : !failure || index + 1 < failure.sequence
        ? 'verified'
        : index + 1 === failure.sequence
          ? 'broken'
          : 'unchecked';
  const settle = ((failure ? failure.sequence : base.length) - 1) * WALK + 0.25;
  const run = result ? result.scenario : 'pending';

  return (
    <DiagramFrame
      label="Audit chain · tenant acme"
      live
      bodyClassName="p-0 sm:p-0"
      actions={
        <AnimatePresence initial={false}>
          {scenario !== 'intact' ? (
            <motion.span
              key="restore"
              initial={{ opacity: 0, x: 6 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 6 }}
              transition={{ duration: 0.2 }}
            >
              <ReplayButton onClick={() => setScenario('intact')} label="Restore" />
            </motion.span>
          ) : null}
        </AnimatePresence>
      }
    >
      <div ref={ref} className="p-4 sm:p-6">
        <div
          className="-mx-1 mb-4 flex w-fit max-w-[calc(100%+0.5rem)] overflow-x-auto rounded-lg bg-segmented-control-background p-0.5"
          role="radiogroup"
          aria-label="Try to rewrite history"
        >
          {scenarios.map((item) => (
            <button
              key={item.id}
              type="button"
              role="radio"
              aria-checked={scenario === item.id}
              onClick={() => setScenario(item.id)}
              className={cx(
                segmentClass(scenario === item.id),
                'h-7 cursor-pointer px-2.5 whitespace-nowrap',
              )}
            >
              {scenario === item.id ? (
                <motion.span
                  layoutId="audit-scenario"
                  className="absolute inset-0 -z-10 rounded-md bg-segmented-control-selected-background shadow-xs"
                  transition={{ type: 'spring', stiffness: 500, damping: 38 }}
                />
              ) : null}
              {item.label}
            </button>
          ))}
        </div>
        <AnimatePresence mode="wait" initial={false}>
          <motion.p
            key={scenario}
            className="mb-5 min-h-10 text-body-2-regular leading-5 text-text-secondary"
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.2 }}
          >
            {story}
          </motion.p>
        </AnimatePresence>

        <ol className="grid gap-2 lg:grid-cols-4 lg:gap-0" onMouseLeave={() => setHovered(null)}>
          {base.map((event, index) => {
            const stored = result?.events[index];
            const honest = result?.honest[index];
            const state = status(index);
            const broken = state === 'broken';
            const edited = scenario !== 'intact' && index === 1;
            const rewritten = scenario === 'rewrite' && index > 1;
            const linkBroken =
              failure?.reason === 'previous-hash-mismatch' && failure.sequence === index + 1;
            const hashBroken =
              (failure?.reason === 'hash-mismatch' || failure?.reason === 'head-mismatch') &&
              failure.sequence === index + 1;
            const walk = index * WALK;
            // Hovering event N lights its own hashes, N-1's hash (which N's prev must equal), and N+1's prev.
            const litPrev = hovered === index || hovered === index - 1;
            const litHash = hovered === index || hovered === index + 1;
            return (
              <li key={event.id} className="flex flex-col lg:flex-row lg:items-center">
                {/* The first card keeps an invisible link slot so all four cards are the same width. */}
                <span className={cx(index === 0 && 'hidden lg:invisible lg:block')}>
                  <ChainLink
                    state={linkBroken ? 'broken' : state === 'unchecked' ? 'unchecked' : 'intact'}
                    lit={hovered !== null && (hovered === index || hovered === index - 1)}
                    delay={walk}
                    show={inView}
                  />
                </span>
                <motion.div
                  tabIndex={0}
                  onMouseEnter={() => setHovered(index)}
                  onFocus={() => setHovered(index)}
                  onBlur={() => setHovered(null)}
                  className={cx(
                    'relative flex min-w-0 flex-1 flex-col gap-1.5 rounded-xl border bg-background-primary-default p-3 shadow-xs transition-[border-color,box-shadow,translate] duration-300 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-border-focus-ring',
                    state === 'unchecked'
                      ? 'border-dashed border-border-button-hover shadow-none'
                      : hovered === index
                        ? 'border-border-button-hover shadow-sm'
                        : 'border-border-button-default',
                    'motion-safe:hover:-translate-y-0.5 motion-safe:focus-visible:-translate-y-0.5',
                  )}
                  initial={{ opacity: 0, y: 10 }}
                  animate={
                    inView
                      ? {
                          opacity: state === 'unchecked' ? 0.5 : 1,
                          y: 0,
                          x: broken ? [0, -4, 4, -3, 3, 0] : 0,
                        }
                      : undefined
                  }
                  transition={{ delay: walk, duration: broken ? 0.45 : 0.5, ease }}
                >
                  {/* Tampered: the event is hatched and outlined in ink once the walk reaches it. */}
                  <AnimatePresence>
                    {broken ? (
                      <motion.span
                        key={run}
                        aria-hidden
                        className="hatch pointer-events-none absolute -inset-px rounded-xl border border-text-primary"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        transition={{ delay: walk, duration: 0.3 }}
                      />
                    ) : null}
                  </AnimatePresence>
                  <div className="relative flex items-center gap-2">
                    <span className="rounded bg-background-secondary-default px-1.5 py-px font-mono text-caption-2-regular text-text-primary tabular-nums">
                      sequence {index + 1}
                    </span>
                    <AnimatePresence>
                      {edited || rewritten ? (
                        <motion.span
                          initial={{ opacity: 0, scale: 0.8 }}
                          animate={{ opacity: 1, scale: 1 }}
                          exit={{ opacity: 0, scale: 0.8 }}
                          className="ms-auto rounded-md border border-dashed border-text-primary bg-background-primary-default px-1 font-mono text-[0.625rem] leading-4 tracking-wide text-text-primary uppercase"
                        >
                          {edited ? 'edited' : 'rewritten'}
                        </motion.span>
                      ) : null}
                    </AnimatePresence>
                    <StatusMark
                      key={`${run}-${state}`}
                      state={state}
                      delay={walk}
                      className={edited || rewritten ? undefined : 'ms-auto'}
                    />
                  </div>
                  <p
                    className="relative truncate font-mono text-caption-2-regular text-text-primary"
                    title={event.action}
                  >
                    {event.action}
                  </p>
                  <p className="relative truncate font-mono text-caption-2-regular text-text-secondary">
                    actor{' '}
                    {edited ? (
                      <>
                        <span className="text-text-tertiary line-through decoration-text-tertiary">
                          {event.actorId}
                        </span>{' '}
                        <span className="font-medium text-text-primary">usr_alice</span>
                      </>
                    ) : (
                      <span className="text-text-primary">{event.actorId}</span>
                    )}
                  </p>
                  <Hash
                    label="prev"
                    value={stored?.previousHash}
                    bad={Boolean(linkBroken)}
                    lit={litPrev}
                  />
                  <Hash
                    label="hash"
                    value={stored?.hash}
                    changed={Boolean(stored && honest && stored.hash !== honest.hash)}
                    bad={Boolean(hashBroken)}
                    lit={litHash}
                  />
                </motion.div>
              </li>
            );
          })}
        </ol>

        {/* The verifier's own output */}
        <div
          className={cx(
            'mt-5 flex flex-col gap-3 rounded-xl border bg-background-primary-default p-3.5 shadow-xs transition-colors duration-300',
            result?.verification.valid === false
              ? 'border-text-primary'
              : 'border-border-button-default',
          )}
        >
          <div className="flex flex-wrap items-center gap-3">
            <AnimatePresence mode="wait" initial={false}>
              <motion.div
                key={result ? `${scenario}-${result.verification.valid}` : 'pending'}
                className="flex shrink-0 items-center"
                initial={{ opacity: 0, scale: 0.96 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.25, ease, delay: result ? settle : 0 }}
              >
                {result?.verification.valid === false ? (
                  <span className="hatch inline-flex items-center gap-2 rounded-lg border border-text-primary px-2.5 py-1 whitespace-nowrap text-text-primary">
                    <RiShieldCrossLine className="size-4 shrink-0" aria-hidden />
                    <span className="text-body-medium">
                      Tampering detected at #{failure?.sequence}
                    </span>
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-2 rounded-lg border border-text-primary bg-text-primary px-2.5 py-1 whitespace-nowrap text-background-full">
                    <RiShieldCheckLine className="size-4 shrink-0" aria-hidden />
                    <span className="text-body-medium">Chain verified</span>
                  </span>
                )}
              </motion.div>
            </AnimatePresence>
            {result ? (
              <span
                className="shrink-0 rounded-md border border-border-button-default px-1.5 py-0.5 font-mono text-caption-2-regular whitespace-nowrap text-text-secondary sm:ms-auto"
                title="The tenant's chain head, stored separately in auditChains"
              >
                head #{result.honest.at(-1)!.sequence} · {result.honest.at(-1)!.hash!.slice(0, 10)}…
              </span>
            ) : null}
          </div>
          <code className="min-w-0 overflow-x-auto border-t border-separator-border pt-3 font-mono text-caption-2-regular whitespace-nowrap text-text-secondary">
            verifyAuditChain(events, {'{ head }'}) →{' '}
            {result
              ? result.verification.valid
                ? `{ valid: true, checked: ${result.verification.checked} }`
                : `{ valid: false, failure: { sequence: ${failure?.sequence}, reason: '${failure?.reason}' } }`
              : '…'}
          </code>
        </div>
      </div>
    </DiagramFrame>
  );
}

/** Where the verifier's walk left an event: checked in ink, caught (a crossed shield), or never reached. */
function StatusMark({
  state,
  delay,
  className,
}: {
  state: Status;
  delay: number;
  className?: string;
}) {
  if (state === 'pending') return null;
  const label =
    state === 'verified' ? 'verified' : state === 'broken' ? 'tampering detected' : 'not checked';
  return (
    <motion.span
      role="img"
      aria-label={label}
      title={label}
      className={cx('relative flex size-4 shrink-0 items-center justify-center', className)}
      initial={{ opacity: 0, scale: 0.4 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ delay, type: 'spring', stiffness: 500, damping: 24 }}
    >
      {state === 'verified' ? (
        <span className="flex size-4 items-center justify-center rounded-full bg-text-primary text-background-full">
          <RiCheckLine className="size-3" aria-hidden />
        </span>
      ) : state === 'broken' ? (
        <RiShieldCrossLine className="size-4 text-text-primary" aria-hidden />
      ) : (
        <span className="size-3.5 rounded-full border border-dashed border-border-button-active" />
      )}
    </motion.span>
  );
}

function Hash({
  label,
  value,
  changed,
  bad,
  lit,
}: {
  label: string;
  value?: string;
  changed?: boolean;
  bad?: boolean;
  lit?: boolean;
}) {
  return (
    <p className="relative flex items-center gap-1.5 font-mono text-caption-2-regular">
      <span className="w-8 shrink-0 text-text-secondary">{label}</span>
      <AnimatePresence mode="wait" initial={false}>
        <motion.span
          key={value ?? 'pending'}
          className={cx(
            'truncate rounded border px-1 outline-offset-1 transition-colors duration-200',
            bad
              ? 'hatch border-text-primary text-text-primary line-through decoration-text-tertiary'
              : changed
                ? 'border-dashed border-text-primary text-text-primary'
                : lit
                  ? 'border-text-primary bg-text-primary text-background-full'
                  : 'border-transparent bg-background-secondary-default text-text-primary',
            lit && (bad || changed) && 'outline-1 outline-text-primary',
          )}
          initial={{ opacity: 0, filter: 'blur(3px)' }}
          animate={{ opacity: 1, filter: 'blur(0px)' }}
          exit={{ opacity: 0, filter: 'blur(3px)' }}
          transition={{ duration: 0.25 }}
        >
          {value ? `${value.slice(0, 10)}…` : '…'}
        </motion.span>
      </AnimatePresence>
    </p>
  );
}

/** The link between two events: whole while `previousHash` matches, split when it does not. */
function ChainLink({
  state,
  lit,
  delay,
  show,
}: {
  state: 'intact' | 'broken' | 'unchecked';
  lit: boolean;
  delay: number;
  show: boolean;
}) {
  const broken = state === 'broken';
  return (
    <span aria-hidden className="flex items-center justify-center py-1 lg:px-1 lg:py-0">
      <motion.span
        className={cx(
          'flex size-6 items-center justify-center rounded-full border transition-colors duration-200',
          broken
            ? 'hatch border-text-primary bg-background-primary-default text-text-primary'
            : lit
              ? 'border-text-primary bg-text-primary text-background-full'
              : state === 'unchecked'
                ? 'border-dashed border-border-button-hover text-text-tertiary'
                : 'border-transparent text-text-primary',
        )}
        initial={{ opacity: 0, scale: 0.5 }}
        animate={
          show
            ? {
                opacity: state === 'unchecked' && !lit ? 0.5 : 1,
                scale: lit ? 1.12 : 1,
                rotate: broken ? -20 : 0,
              }
            : undefined
        }
        transition={{
          delay,
          type: 'spring',
          stiffness: 400,
          damping: 20,
          scale: { type: 'spring', stiffness: 500, damping: 24 },
        }}
      >
        {broken ? (
          <RiLinkUnlinkM className="size-3.5" />
        ) : (
          <RiLinkM className="size-3.5 rotate-90 lg:rotate-0" />
        )}
      </motion.span>
    </span>
  );
}
