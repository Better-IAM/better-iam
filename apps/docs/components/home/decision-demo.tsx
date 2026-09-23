'use client';

import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import Link from 'next/link';
import { AnimatePresence, motion, useAnimate, useInView, type Variants } from 'motion/react';
import {
  RiArrowRightLine,
  RiCheckLine,
  RiCloseLine,
  RiShieldCheckLine,
  RiShieldCrossLine,
} from 'react-icons/ri';
import { evaluatePolicy, type PolicyDocument } from '@better-iam/core';
import { Switch } from '@/components/base/switch/switch';
import { cx } from '@/utils/cx';
import { DiagramFrame } from './frame';
import { ease, useReducedMotionSafe } from './motion';

/**
 * A live policy decision, computed by the real `evaluatePolicy` from @better-iam/core. The statements below are
 * drawn from the same documents that are evaluated, and the flow follows the evaluator's order: any matching deny
 * wins, then some grant must allow, then every boundary must allow.
 */
const grant: PolicyDocument = {
  version: 1,
  statements: [
    {
      sid: 'ApproveOwnInvoices',
      effect: 'allow',
      actions: ['invoices:approve'],
      resources: ['invoice/*'],
      conditions: {
        StringEquals: { 'resource.ownerId': '${principal.id}' },
        IpAddress: { 'request.sourceIp': '10.0.0.0/8' },
      },
    },
    {
      sid: 'RequireMfa',
      effect: 'deny',
      actions: ['invoices:*'],
      resources: ['invoice/*'],
      conditions: { Bool: { 'principal.mfa': false } },
    },
  ],
};

const boundaryFor = (approvals: boolean): PolicyDocument => ({
  version: 1,
  statements: [
    {
      sid: 'FinanceCeiling',
      effect: 'allow',
      actions: approvals ? ['invoices:*'] : ['invoices:read'],
      resources: ['invoice/*'],
    },
  ],
});

/** Which evaluator step a switch, statement, or gate belongs to: hovering one lights up the others. */
type Kind = 'deny' | 'grant' | 'boundary';

const toggles = [
  { key: 'owner', label: 'Alice owns the invoice', kind: 'grant' },
  { key: 'office', label: 'Request from the office network', kind: 'grant' },
  { key: 'mfa', label: 'Session completed MFA', kind: 'deny' },
  { key: 'ceiling', label: 'Boundary includes approvals', kind: 'boundary' },
] as const;

type Toggle = (typeof toggles)[number]['key'];
type GateState = 'pass' | 'fail' | 'skip';
type Focus = { kind: Kind; toggle?: Toggle } | null;

/** How far apart the gates light up after a switch flips, in seconds; the verdict follows the last one. */
const GATE_STEP = 0.22;
const VERDICT_AT = 3 * GATE_STEP;

const column: Variants = {
  hidden: {},
  shown: { transition: { staggerChildren: 0.07, delayChildren: 0.1 } },
};
const rise: Variants = {
  hidden: { opacity: 0, y: 10 },
  shown: { opacity: 1, y: 0, transition: { duration: 0.45, ease } },
};

export function DecisionDemo() {
  const [state, setState] = useState<Record<Toggle, boolean>>({
    owner: true,
    office: true,
    mfa: false,
    ceiling: true,
  });
  // Every flip re-runs the evaluation, so the gates replay even when the verdict stays the same.
  const [run, setRun] = useState(0);
  const [focus, setFocus] = useState<Focus>(null);
  const flowRef = useRef<HTMLDivElement>(null);
  const shown = useInView(flowRef, { once: true, amount: 0.6 });
  const reduced = useReducedMotionSafe();
  const [verdictScope, animateVerdict] = useAnimate<HTMLDivElement>();

  const decision = useMemo(
    () =>
      evaluatePolicy({
        action: 'invoices:approve',
        resource: 'invoice/inv_1009',
        context: {
          'principal.id': 'usr_alice',
          'principal.mfa': state.mfa,
          'resource.ownerId': state.owner ? 'usr_alice' : 'usr_bob',
          'request.sourceIp': state.office ? '10.4.2.7' : '203.0.113.9',
        },
        grants: [grant],
        boundaries: [boundaryFor(state.ceiling)],
      }),
    [state],
  );

  const denied = decision.reason === 'explicit-deny';
  const gates: { title: string; kind: Kind; state: GateState; outcome: string }[] = [
    {
      title: 'Deny statements',
      kind: 'deny',
      state: denied ? 'fail' : 'pass',
      outcome: denied ? 'RequireMfa matches' : 'none match',
    },
    {
      title: 'Grants',
      kind: 'grant',
      state: denied ? 'skip' : decision.reason === 'no-grant' ? 'fail' : 'pass',
      outcome: denied
        ? 'not reached'
        : decision.reason === 'no-grant'
          ? 'nothing allows it'
          : 'ApproveOwnInvoices allows',
    },
    {
      title: 'Boundaries',
      kind: 'boundary',
      state: decision.allowed ? 'pass' : decision.reason === 'boundary-deny' ? 'fail' : 'skip',
      outcome: decision.allowed
        ? 'FinanceCeiling allows'
        : decision.reason === 'boundary-deny'
          ? 'FinanceCeiling excludes it'
          : 'not reached',
    },
  ];
  const context: { key: string; value: string; kind: Kind; toggle: Toggle }[] = [
    { key: 'principal.id', value: "'usr_alice'", kind: 'grant', toggle: 'owner' },
    { key: 'principal.mfa', value: String(state.mfa), kind: 'deny', toggle: 'mfa' },
    {
      key: 'resource.ownerId',
      value: state.owner ? "'usr_alice'" : "'usr_bob'",
      kind: 'grant',
      toggle: 'owner',
    },
    {
      key: 'request.sourceIp',
      value: state.office ? "'10.4.2.7'" : "'203.0.113.9'",
      kind: 'grant',
      toggle: 'office',
    },
  ];

  /** Lit: part of what is hovered. Dim: something else is hovered. */
  const lit = (kind: Kind, toggle?: Toggle) =>
    focus !== null && focus.kind === kind && (!focus.toggle || !toggle || focus.toggle === toggle);
  const dim = (kind: Kind, toggle?: Toggle) => focus !== null && !lit(kind, toggle);
  const hover = (kind: Kind) => ({
    onPointerEnter: () => setFocus({ kind }),
    onPointerLeave: () => setFocus(null),
  });

  function flip(key: Toggle, value: boolean) {
    setState((current) => ({ ...current, [key]: value }));
    setRun((count) => count + 1);
  }

  // A verdict that did not change still answers the flip with a small press, once the gates have run.
  useEffect(() => {
    if (run === 0 || reduced || !verdictScope.current) return;
    const controls = animateVerdict(
      verdictScope.current,
      { scale: [1, 0.97, 1] },
      { delay: VERDICT_AT, duration: 0.4, ease },
    );
    return () => controls.stop();
  }, [run, reduced, animateVerdict, verdictScope]);

  return (
    <DiagramFrame
      live
      label={
        <>
          <span className="font-mono text-text-primary">alice</span> →{' '}
          <span className="font-mono text-text-primary">invoices:approve</span> on{' '}
          <span className="font-mono text-text-primary">invoice/inv_1009</span>
        </>
      }
      footer={
        <span className="flex flex-wrap items-center justify-between gap-2">
          <span>Evaluated in your browser by the same function the server uses.</span>
          <Link
            href="/playground"
            className="group/link inline-flex items-center gap-1 rounded-sm text-caption-1-medium text-text-primary underline-offset-4 hover:underline"
          >
            Open the playground
            <RiArrowRightLine
              className="size-3.5 transition-transform duration-200 group-hover/link:translate-x-0.5"
              aria-hidden
            />
          </Link>
        </span>
      }
    >
      <div className="grid gap-6 md:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
        {/* Inputs */}
        <motion.div
          variants={column}
          initial="hidden"
          whileInView="shown"
          viewport={{ once: true, amount: 0.3 }}
          className="flex flex-col gap-2"
        >
          <motion.p variants={rise} className="eyebrow mb-1">
            Request context
          </motion.p>
          {toggles.map((toggle) => (
            <motion.div key={toggle.key} variants={rise}>
              <Switch
                isSelected={state[toggle.key]}
                onChange={(value) => flip(toggle.key, value)}
                onHoverChange={(hovering) =>
                  setFocus(hovering ? { kind: toggle.kind, toggle: toggle.key } : null)
                }
                className={cx(
                  // Raised rather than primary: in dark mode the switch's off track is the primary surface's color.
                  'flex w-full flex-row-reverse justify-between gap-3 rounded-lg border bg-surface-raised px-3 py-2.5 shadow-xs transition-[border-color,opacity,scale] duration-200 active:scale-[0.99]',
                  lit(toggle.kind, toggle.key)
                    ? 'border-border-button-hover'
                    : 'border-border-button-default hover:border-border-button-hover',
                  dim(toggle.kind, toggle.key) && 'opacity-50',
                )}
              >
                <span className="text-body-2-regular">{toggle.label}</span>
              </Switch>
            </motion.div>
          ))}
          <motion.div
            variants={rise}
            className="mt-2 rounded-lg border border-dashed border-border-button-default px-3 py-2.5"
          >
            <p className="mb-1.5 text-caption-2-regular text-text-secondary">
              What the evaluator receives
            </p>
            <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 font-mono text-caption-2-regular leading-5">
              {context.map((row) => (
                <div
                  key={row.key}
                  className={cx(
                    'contents [&>*]:transition-opacity [&>*]:duration-200',
                    dim(row.kind, row.toggle) && '[&>*]:opacity-40',
                  )}
                >
                  <dt className="text-text-secondary">{row.key}</dt>
                  <dd className="overflow-hidden">
                    <AnimatePresence mode="popLayout" initial={false}>
                      <motion.span
                        key={row.value}
                        className="block truncate text-text-primary"
                        initial={{ opacity: 0, y: 6 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -6 }}
                        transition={{ duration: 0.2 }}
                      >
                        {row.value}
                      </motion.span>
                    </AnimatePresence>
                  </dd>
                </div>
              ))}
            </dl>
          </motion.div>
        </motion.div>

        {/* Documents */}
        <motion.div
          variants={column}
          initial="hidden"
          whileInView="shown"
          viewport={{ once: true, amount: 0.3 }}
          className="flex flex-col gap-2"
        >
          <motion.p variants={rise} className="eyebrow mb-1">
            Documents
          </motion.p>
          <motion.div variants={rise}>
            <Statement
              effect="allow"
              sid="ApproveOwnInvoices"
              scope="invoices:approve on invoice/*"
              matched={decision.matched.includes('grant:0:ApproveOwnInvoices')}
              lit={lit('grant')}
              dim={dim('grant')}
              {...hover('grant')}
            >
              <Condition
                op="StringEquals"
                ok={state.owner}
                lit={lit('grant', 'owner')}
                dim={focus?.kind === 'grant' && dim('grant', 'owner')}
              >
                resource.ownerId = {'${principal.id}'}
              </Condition>
              <Condition
                op="IpAddress"
                ok={state.office}
                lit={lit('grant', 'office')}
                dim={focus?.kind === 'grant' && dim('grant', 'office')}
              >
                request.sourceIp in 10.0.0.0/8
              </Condition>
            </Statement>
          </motion.div>
          <motion.div variants={rise}>
            <Statement
              effect="deny"
              sid="RequireMfa"
              scope="invoices:* on invoice/*"
              matched={decision.matched.includes('grant:0:RequireMfa')}
              lit={lit('deny')}
              dim={dim('deny')}
              {...hover('deny')}
            >
              <Condition op="Bool" ok={!state.mfa} deny lit={lit('deny', 'mfa')}>
                principal.mfa = false
              </Condition>
            </Statement>
          </motion.div>
          <motion.div variants={rise}>
            <Statement
              effect="boundary"
              sid="FinanceCeiling"
              scope={`${state.ceiling ? 'invoices:*' : 'invoices:read'} on invoice/*`}
              matched={decision.matched.includes('boundary:0:FinanceCeiling')}
              lit={lit('boundary')}
              dim={dim('boundary')}
              {...hover('boundary')}
            />
          </motion.div>
        </motion.div>
      </div>

      {/* Evaluation flow */}
      <div className="mt-6 border-t border-separator-border pt-5">
        <div
          ref={flowRef}
          className="grid grid-cols-[repeat(3,minmax(0,1fr))] gap-2 sm:grid-cols-[repeat(3,minmax(0,1fr))_minmax(0,1.15fr)] sm:gap-0"
        >
          {gates.map((gate, index) => {
            const delay = index * GATE_STEP;
            const emphasized = focus?.kind === gate.kind;
            return (
              <div key={gate.title} className="flex items-center">
                <motion.div
                  key={run}
                  {...hover(gate.kind)}
                  className={cx(
                    'relative flex min-w-0 flex-1 flex-col gap-0.5 rounded-lg border px-2.5 py-2 transition-[translate,box-shadow,border-color] duration-200',
                    gate.state === 'pass' && 'border-text-primary bg-background-primary-default',
                    gate.state === 'fail' &&
                      'hatch border-text-primary bg-background-primary-default',
                    gate.state === 'skip' && 'border-dashed border-border-button-hover',
                    emphasized &&
                      '-translate-y-0.5 shadow-sm ring-1 ring-text-primary ring-offset-2 ring-offset-surface-raised',
                  )}
                  initial={{ opacity: 0.2, y: 6 }}
                  animate={shown ? { opacity: gate.state === 'skip' ? 0.5 : 1, y: 0 } : undefined}
                  transition={{ delay, duration: 0.35, ease }}
                >
                  <span className="flex items-center gap-1.5 text-caption-1-medium">
                    <GateIcon state={gate.state} shown={shown} delay={delay} />
                    <span className="truncate">{gate.title}</span>
                  </span>
                  <span
                    className={cx(
                      'hidden truncate font-mono text-caption-2-regular leading-4 md:block',
                      gate.state === 'fail' ? 'text-text-primary' : 'text-text-secondary',
                    )}
                  >
                    {gate.outcome}
                  </span>
                </motion.div>
                <span
                  aria-hidden
                  className="relative mx-1 hidden h-px w-4 shrink-0 bg-border-button-default sm:block"
                >
                  <motion.span
                    key={run}
                    className={cx(
                      'absolute inset-0 origin-left',
                      gate.state === 'pass' ? 'bg-text-primary' : 'bg-border-button-hover',
                    )}
                    initial={{ scaleX: 0 }}
                    animate={shown ? { scaleX: 1 } : undefined}
                    transition={{ delay: delay + 0.15, duration: 0.25, ease }}
                  />
                </span>
              </div>
            );
          })}
          <div ref={verdictScope} className="col-span-3 sm:col-span-1">
            <motion.div
              aria-live="polite"
              className="relative flex h-full items-center overflow-hidden rounded-lg border border-text-primary px-3 py-2"
              initial={{ opacity: 0, scale: 0.96 }}
              animate={shown ? { opacity: 1, scale: 1 } : undefined}
              transition={{ delay: VERDICT_AT, duration: 0.35, ease }}
            >
              {/* Denied is hatched; Allowed fills with ink. The fill crossfades once the gates have run. */}
              <span aria-hidden className="hatch absolute inset-0 bg-background-primary-default" />
              <motion.span
                aria-hidden
                className="absolute inset-0 bg-text-primary"
                initial={false}
                animate={{ opacity: decision.allowed ? 1 : 0 }}
                transition={{ delay: run === 0 ? 0 : VERDICT_AT, duration: 0.35, ease }}
              />
              <AnimatePresence mode="popLayout" initial={false}>
                <motion.span
                  key={decision.allowed ? 'allowed' : 'denied'}
                  className={cx(
                    'relative flex min-w-0 items-center gap-2.5',
                    decision.allowed ? 'text-background-full' : 'text-text-primary',
                  )}
                  initial={{ opacity: 0, y: 10, filter: 'blur(3px)' }}
                  animate={{
                    opacity: 1,
                    y: 0,
                    filter: 'blur(0px)',
                    transition: { delay: VERDICT_AT, duration: 0.35, ease },
                  }}
                  exit={{
                    opacity: 0,
                    y: -10,
                    filter: 'blur(3px)',
                    transition: { delay: VERDICT_AT, duration: 0.3, ease },
                  }}
                >
                  {decision.allowed ? (
                    <RiShieldCheckLine className="size-5 shrink-0" aria-hidden />
                  ) : (
                    <RiShieldCrossLine className="size-5 shrink-0" aria-hidden />
                  )}
                  <span className="flex min-w-0 flex-col">
                    <span className="text-body-semibold">
                      {decision.allowed ? 'Allowed' : 'Denied'}
                    </span>
                    <span
                      className={cx(
                        'truncate font-mono text-caption-2-regular',
                        decision.allowed ? 'opacity-70' : 'text-text-secondary',
                      )}
                    >
                      {decision.reason}
                    </span>
                  </span>
                </motion.span>
              </AnimatePresence>
            </motion.div>
          </div>
        </div>
      </div>
    </DiagramFrame>
  );
}

function Statement({
  effect,
  sid,
  scope,
  matched,
  lit,
  dim,
  onPointerEnter,
  onPointerLeave,
  children,
}: {
  effect: 'allow' | 'deny' | 'boundary';
  sid: string;
  scope: string;
  matched: boolean;
  lit: boolean;
  dim: boolean;
  onPointerEnter: () => void;
  onPointerLeave: () => void;
  children?: ReactNode;
}) {
  return (
    <motion.div
      layout
      onPointerEnter={onPointerEnter}
      onPointerLeave={onPointerLeave}
      className={cx(
        'rounded-lg border bg-background-primary-default px-3 py-2.5 transition-[border-color,box-shadow,opacity] duration-300',
        matched
          ? 'border-text-primary'
          : lit
            ? 'border-border-button-hover'
            : 'border-border-button-default',
        matched && effect === 'deny' && 'hatch',
        lit ? 'shadow-sm' : 'shadow-xs',
        dim && 'opacity-50',
      )}
    >
      <div className="flex items-center gap-2">
        <span
          className={cx(
            'rounded-full border px-1.5 py-px font-mono text-caption-2-medium tracking-wide uppercase',
            effect === 'allow' && 'border-text-primary bg-text-primary text-background-full',
            effect === 'deny' &&
              'hatch border-text-primary bg-background-primary-default text-text-primary',
            effect === 'boundary' && 'border-border-button-hover text-text-secondary',
          )}
        >
          {effect}
        </span>
        <span className="truncate font-mono text-caption-1-medium">{sid}</span>
        <AnimatePresence>
          {matched ? (
            <motion.span
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.8 }}
              className="ms-auto inline-flex shrink-0 items-center gap-1 text-caption-2-medium text-text-primary"
            >
              <span aria-hidden className="size-1.5 rounded-full bg-text-primary" />
              matched
            </motion.span>
          ) : null}
        </AnimatePresence>
      </div>
      <p className="mt-1 font-mono text-caption-2-regular text-text-secondary">{scope}</p>
      {children ? <div className="mt-2 flex flex-col gap-0.5">{children}</div> : null}
    </motion.div>
  );
}

/**
 * One condition line with a live marker: a check when the condition holds, a cross when it does not. Ink means it
 * helps the request; hatched means it works against it (for deny statements, a met condition means the deny applies).
 */
function Condition({
  op,
  ok,
  deny,
  lit,
  dim,
  children,
}: {
  op: string;
  ok: boolean;
  deny?: boolean;
  lit?: boolean;
  dim?: boolean;
  children: ReactNode;
}) {
  const bad = deny ? ok : !ok;
  return (
    <div
      className={cx(
        '-mx-1.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 rounded-md px-1.5 py-0.5 font-mono text-caption-2-regular transition-[background-color,opacity] duration-200',
        lit && 'bg-background-secondary-default',
        dim && 'opacity-40',
      )}
    >
      <motion.span
        key={String(ok)}
        initial={{ scale: 0.4, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ type: 'spring', stiffness: 600, damping: 24 }}
        className={cx(
          'flex size-3.5 shrink-0 items-center justify-center rounded-full',
          bad
            ? 'hatch border border-text-primary bg-background-primary-default text-text-primary'
            : 'bg-text-primary text-background-full',
        )}
      >
        {ok ? (
          <RiCheckLine className="size-3" aria-hidden />
        ) : (
          <RiCloseLine className="size-3" aria-hidden />
        )}
      </motion.span>
      <span className="text-text-tertiary">{op}</span>
      <span
        className={cx(
          'break-all transition-colors',
          bad && !deny
            ? 'text-text-secondary line-through decoration-text-tertiary'
            : 'text-text-primary',
        )}
      >
        {children}
      </span>
    </div>
  );
}

function GateIcon({ state, shown, delay }: { state: GateState; shown: boolean; delay: number }) {
  if (state === 'skip')
    return (
      <span className="size-4 shrink-0 rounded-full border border-dashed border-text-tertiary" />
    );
  return (
    <motion.span
      className={cx(
        'flex size-4 shrink-0 items-center justify-center rounded-full',
        state === 'pass'
          ? 'bg-text-primary text-background-full'
          : 'border border-text-primary bg-background-primary-default text-text-primary',
      )}
      initial={{ scale: 0 }}
      animate={shown ? { scale: 1 } : undefined}
      transition={{ delay: delay + 0.12, type: 'spring', stiffness: 520, damping: 22 }}
    >
      {state === 'pass' ? (
        <RiCheckLine className="size-3" aria-hidden />
      ) : (
        <RiCloseLine className="size-3" aria-hidden />
      )}
    </motion.span>
  );
}
