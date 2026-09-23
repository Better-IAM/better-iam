'use client';

import { useEffect, useRef, useState } from 'react';
import { AnimatePresence, motion, useInView } from 'motion/react';
import { Link2, Link2Off, ShieldAlert, ShieldCheck } from 'lucide-react';
import {
  auditEventHash,
  auditGenesis,
  verifyAuditChain,
  type AuditChainVerification,
  type AuditEvent,
} from '@better-iam/core';
import { cn } from '@/lib/cn';
import { DiagramFrame, segmentClass } from './frame';
import { ease } from './motion';

/**
 * A real audit hash chain, built and verified in the browser with `auditEventHash` and `verifyAuditChain` from
 * @better-iam/core. Each scenario is an attempt to rewrite history; the verifier reports how it was caught.
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

export function AuditChain() {
  const [scenario, setScenario] = useState<Scenario>('intact');
  const [result, setResult] = useState<{
    events: AuditEvent[];
    verification: AuditChainVerification;
    honest: AuditEvent[];
  }>();
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, amount: 0.3 });

  useEffect(() => {
    let current = true;
    void build(scenario).then((next) => {
      if (current) setResult(next);
    });
    return () => {
      current = false;
    };
  }, [scenario]);

  const failure = result?.verification.failure;
  const story = scenarios.find((item) => item.id === scenario)!.story;

  return (
    <DiagramFrame label="Audit chain · tenant acme" live bodyClassName="p-0 sm:p-0">
      <div ref={ref} className="p-4 sm:p-6">
        <div
          className="-mx-1 mb-4 flex w-fit max-w-[calc(100%+0.5rem)] overflow-x-auto rounded-lg bg-fd-muted p-0.5"
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
              className={cn(segmentClass(scenario === item.id), 'h-7 whitespace-nowrap px-2.5')}
            >
              {scenario === item.id ? (
                <motion.span
                  layoutId="audit-scenario"
                  className="absolute inset-0 -z-10 rounded-md bg-fd-background shadow-sm"
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
            className="mb-5 min-h-10 text-[0.8125rem] leading-5 text-fd-muted-foreground"
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.2 }}
          >
            {story}
          </motion.p>
        </AnimatePresence>

        <ol className="grid gap-2 lg:grid-cols-4 lg:gap-0">
          {base.map((event, index) => {
            const stored = result?.events[index];
            const honest = result?.honest[index];
            const broken = failure && failure.sequence === index + 1;
            const edited = scenario !== 'intact' && index === 1;
            const rewritten = scenario === 'rewrite' && index > 1;
            const linkBroken =
              failure?.reason === 'previous-hash-mismatch' && failure.sequence === index + 1;
            const hashBroken =
              (failure?.reason === 'hash-mismatch' || failure?.reason === 'head-mismatch') &&
              failure.sequence === index + 1;
            return (
              <li key={event.id} className="flex flex-col lg:flex-row lg:items-center">
                {/* The first card keeps an invisible link slot so all four cards are the same width. */}
                <span className={cn(index === 0 && 'hidden lg:invisible lg:block')}>
                  <ChainLink broken={Boolean(linkBroken)} delay={index * 0.15} show={inView} />
                </span>
                <motion.div
                  className={cn(
                    'flex min-w-0 flex-1 flex-col gap-1.5 rounded-xl border bg-fd-background p-3 transition-colors duration-300',
                    broken && 'border-red-500/60 bg-red-500/[0.05]',
                    !broken && (edited || rewritten) && 'border-amber-500/50',
                  )}
                  initial={{ opacity: 0, y: 10 }}
                  animate={
                    inView ? { opacity: 1, y: 0, x: broken ? [0, -4, 4, -3, 3, 0] : 0 } : undefined
                  }
                  transition={{
                    delay: broken ? 0 : index * 0.15,
                    duration: broken ? 0.45 : 0.5,
                    ease,
                  }}
                >
                  <div className="flex items-center gap-2">
                    <span className="rounded bg-fd-muted px-1.5 py-px font-mono text-[0.6875rem] tabular-nums">
                      sequence {index + 1}
                    </span>
                    <AnimatePresence>
                      {edited || rewritten ? (
                        <motion.span
                          initial={{ opacity: 0, scale: 0.8 }}
                          animate={{ opacity: 1, scale: 1 }}
                          exit={{ opacity: 0, scale: 0.8 }}
                          className="ms-auto text-[0.625rem] font-medium uppercase tracking-wide text-amber-600 dark:text-amber-400"
                        >
                          {edited ? 'edited' : 'rewritten'}
                        </motion.span>
                      ) : null}
                    </AnimatePresence>
                  </div>
                  <p
                    className="truncate font-mono text-[0.6875rem] text-fd-foreground"
                    title={event.action}
                  >
                    {event.action}
                  </p>
                  <p className="font-mono text-[0.6875rem] text-fd-muted-foreground">
                    actor{' '}
                    <span
                      className={cn(
                        edited ? 'text-amber-600 dark:text-amber-400' : 'text-fd-foreground',
                      )}
                    >
                      {edited ? 'usr_alice' : event.actorId}
                    </span>
                  </p>
                  <Hash label="prev" value={stored?.previousHash} bad={Boolean(linkBroken)} />
                  <Hash
                    label="hash"
                    value={stored?.hash}
                    changed={Boolean(stored && honest && stored.hash !== honest.hash)}
                    bad={Boolean(hashBroken)}
                  />
                </motion.div>
              </li>
            );
          })}
        </ol>

        {/* The verifier's own output */}
        <div className="mt-5 flex flex-col gap-3 rounded-xl border bg-fd-background p-3.5 sm:flex-row sm:items-center">
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={result ? `${scenario}-${result.verification.valid}` : 'pending'}
              className="flex shrink-0 items-center gap-2.5 whitespace-nowrap"
              initial={{ opacity: 0, scale: 0.96 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.25, ease }}
            >
              {result?.verification.valid === false ? (
                <ShieldAlert className="size-5 shrink-0 text-red-600 dark:text-red-400" />
              ) : (
                <ShieldCheck className="size-5 shrink-0 text-emerald-600 dark:text-emerald-400" />
              )}
              <span className="text-sm font-medium">
                {result?.verification.valid === false
                  ? `Tampering detected at #${failure?.sequence}`
                  : 'Chain verified'}
              </span>
            </motion.div>
          </AnimatePresence>
          {result ? (
            <span
              className="shrink-0 whitespace-nowrap rounded-md border px-1.5 py-0.5 font-mono text-[0.6875rem] text-fd-muted-foreground"
              title="The tenant's chain head, stored separately in auditChains"
            >
              head #{result.honest.at(-1)!.sequence} · {result.honest.at(-1)!.hash!.slice(0, 10)}…
            </span>
          ) : null}
          <code className="min-w-0 overflow-x-auto whitespace-nowrap font-mono text-[0.6875rem] text-fd-muted-foreground sm:ms-auto">
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

function Hash({
  label,
  value,
  changed,
  bad,
}: {
  label: string;
  value?: string;
  changed?: boolean;
  bad?: boolean;
}) {
  return (
    <p className="flex items-center gap-1.5 font-mono text-[0.6875rem]">
      <span className="w-8 shrink-0 text-fd-muted-foreground">{label}</span>
      <AnimatePresence mode="wait" initial={false}>
        <motion.span
          key={value ?? 'pending'}
          className={cn(
            'truncate rounded px-1 transition-shadow',
            changed
              ? 'bg-amber-500/15 text-amber-700 dark:text-amber-300'
              : 'bg-fd-muted text-fd-foreground',
            bad && 'ring-1 ring-red-500/70',
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
function ChainLink({ broken, delay, show }: { broken: boolean; delay: number; show: boolean }) {
  return (
    <span
      aria-hidden
      className={cn(
        'flex items-center justify-center py-1 lg:px-1.5 lg:py-0',
        broken ? 'text-red-600 dark:text-red-400' : 'text-fd-primary',
      )}
    >
      <motion.span
        initial={{ opacity: 0, scale: 0.5 }}
        animate={show ? { opacity: 1, scale: 1, rotate: broken ? -20 : 0 } : undefined}
        transition={{ delay: broken ? 0 : delay, type: 'spring', stiffness: 400, damping: 20 }}
      >
        {broken ? (
          <Link2Off className="size-4" />
        ) : (
          <Link2 className="size-4 rotate-90 lg:rotate-0" />
        )}
      </motion.span>
    </span>
  );
}
