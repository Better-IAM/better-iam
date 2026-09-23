'use client';

import { useMemo, useState, type ReactNode } from 'react';
import Link from 'next/link';
import { AnimatePresence, motion } from 'motion/react';
import { ArrowRight, Check, ShieldCheck, ShieldX, X } from 'lucide-react';
import { evaluatePolicy, type PolicyDocument } from '@better-iam/core';
import { cn } from '@/lib/cn';
import { DiagramFrame } from './frame';
import { ease } from './motion';

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

const toggles = [
  { key: 'owner', label: 'Alice owns the invoice' },
  { key: 'office', label: 'Request from the office network' },
  { key: 'mfa', label: 'Session completed MFA' },
  { key: 'ceiling', label: 'Boundary includes approvals' },
] as const;

type Toggle = (typeof toggles)[number]['key'];
type GateState = 'pass' | 'fail' | 'skip';

export function DecisionDemo() {
  const [state, setState] = useState<Record<Toggle, boolean>>({
    owner: true,
    office: true,
    mfa: false,
    ceiling: true,
  });
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
  const gates: { title: string; state: GateState; outcome: string }[] = [
    {
      title: 'Deny statements',
      state: denied ? 'fail' : 'pass',
      outcome: denied ? 'RequireMfa matches' : 'none match',
    },
    {
      title: 'Grants',
      state: denied ? 'skip' : decision.reason === 'no-grant' ? 'fail' : 'pass',
      outcome: denied
        ? 'not reached'
        : decision.reason === 'no-grant'
          ? 'nothing allows it'
          : 'ApproveOwnInvoices allows',
    },
    {
      title: 'Boundaries',
      state: decision.allowed ? 'pass' : decision.reason === 'boundary-deny' ? 'fail' : 'skip',
      outcome: decision.allowed
        ? 'FinanceCeiling allows'
        : decision.reason === 'boundary-deny'
          ? 'FinanceCeiling excludes it'
          : 'not reached',
    },
  ];
  const context: [string, string][] = [
    ['principal.id', "'usr_alice'"],
    ['principal.mfa', String(state.mfa)],
    ['resource.ownerId', state.owner ? "'usr_alice'" : "'usr_bob'"],
    ['request.sourceIp', state.office ? "'10.4.2.7'" : "'203.0.113.9'"],
  ];
  const flowKey = gates.map((gate) => gate.state).join('-');

  return (
    <DiagramFrame
      live
      label={
        <>
          <span className="font-mono text-fd-foreground">alice</span> →{' '}
          <span className="font-mono text-fd-foreground">invoices:approve</span> on{' '}
          <span className="font-mono text-fd-foreground">invoice/inv_1009</span>
        </>
      }
      footer={
        <span className="flex flex-wrap items-center justify-between gap-2">
          <span>Evaluated in your browser by the same function the server uses.</span>
          <Link
            href="/playground"
            className="inline-flex items-center gap-1 text-fd-primary hover:underline"
          >
            Open the playground <ArrowRight className="size-3" />
          </Link>
        </span>
      }
    >
      <div className="grid gap-6 md:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
        {/* Inputs */}
        <div className="flex flex-col gap-2">
          <p className="mb-1 text-[0.6875rem] font-medium uppercase tracking-[0.08em] text-fd-muted-foreground">
            Request context
          </p>
          {toggles.map((toggle) => (
            <button
              key={toggle.key}
              type="button"
              role="switch"
              aria-checked={state[toggle.key]}
              onClick={() =>
                setState((current) => ({ ...current, [toggle.key]: !current[toggle.key] }))
              }
              className="flex items-center justify-between gap-3 rounded-lg border bg-fd-background px-3 py-2.5 text-start text-[0.8125rem] transition-colors hover:border-fd-primary/40"
            >
              {toggle.label}
              <span
                aria-hidden
                className={cn(
                  'relative flex h-5 w-9 shrink-0 items-center rounded-full px-0.5 transition-colors',
                  state[toggle.key]
                    ? 'justify-end bg-fd-primary'
                    : 'justify-start bg-fd-muted ring-1 ring-fd-border',
                )}
              >
                <motion.span
                  layout
                  transition={{ type: 'spring', stiffness: 700, damping: 35 }}
                  className="size-4 rounded-full bg-white shadow"
                />
              </span>
            </button>
          ))}
          <div className="mt-2 rounded-lg border border-dashed px-3 py-2.5">
            <p className="mb-1.5 text-[0.6875rem] text-fd-muted-foreground">
              What the evaluator receives
            </p>
            <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 font-mono text-[0.6875rem] leading-5">
              {context.map(([key, value]) => (
                <div key={key} className="contents">
                  <dt className="text-fd-muted-foreground">{key}</dt>
                  <dd className="overflow-hidden">
                    <AnimatePresence mode="popLayout" initial={false}>
                      <motion.span
                        key={value}
                        className="block truncate text-fd-foreground"
                        initial={{ opacity: 0, y: 6 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: -6 }}
                        transition={{ duration: 0.2 }}
                      >
                        {value}
                      </motion.span>
                    </AnimatePresence>
                  </dd>
                </div>
              ))}
            </dl>
          </div>
        </div>

        {/* Documents */}
        <div className="flex flex-col gap-2">
          <p className="mb-1 text-[0.6875rem] font-medium uppercase tracking-[0.08em] text-fd-muted-foreground">
            Documents
          </p>
          <Statement
            effect="allow"
            sid="ApproveOwnInvoices"
            scope="invoices:approve on invoice/*"
            matched={decision.matched.includes('grant:0:ApproveOwnInvoices')}
          >
            <Condition op="StringEquals" ok={state.owner}>
              resource.ownerId = {'${principal.id}'}
            </Condition>
            <Condition op="IpAddress" ok={state.office}>
              request.sourceIp in 10.0.0.0/8
            </Condition>
          </Statement>
          <Statement
            effect="deny"
            sid="RequireMfa"
            scope="invoices:* on invoice/*"
            matched={decision.matched.includes('grant:0:RequireMfa')}
          >
            <Condition op="Bool" ok={!state.mfa} deny>
              principal.mfa = false
            </Condition>
          </Statement>
          <Statement
            effect="boundary"
            sid="FinanceCeiling"
            scope={`${state.ceiling ? 'invoices:*' : 'invoices:read'} on invoice/*`}
            matched={decision.matched.includes('boundary:0:FinanceCeiling')}
          />
        </div>
      </div>

      {/* Evaluation flow */}
      <div className="mt-6 border-t pt-5">
        <div
          key={flowKey}
          className="grid grid-cols-[repeat(3,minmax(0,1fr))] gap-2 sm:grid-cols-[repeat(3,minmax(0,1fr))_minmax(0,1.15fr)] sm:gap-0"
        >
          {gates.map((gate, index) => (
            <div key={gate.title} className="flex items-center">
              <motion.div
                className={cn(
                  'flex min-w-0 flex-1 flex-col gap-0.5 rounded-lg border px-2.5 py-2',
                  gate.state === 'pass' && 'border-emerald-500/40 bg-emerald-500/[0.06]',
                  gate.state === 'fail' && 'border-red-500/45 bg-red-500/[0.07]',
                  gate.state === 'skip' && 'border-dashed opacity-50',
                )}
                initial={{ opacity: 0.2, y: 6 }}
                animate={{ opacity: gate.state === 'skip' ? 0.5 : 1, y: 0 }}
                transition={{ delay: index * 0.18, duration: 0.35, ease }}
              >
                <span className="flex items-center gap-1.5 text-xs font-medium">
                  <GateIcon state={gate.state} />
                  <span className="truncate">{gate.title}</span>
                </span>
                <span
                  className={cn(
                    'hidden truncate font-mono text-[0.6875rem] leading-4 md:block',
                    gate.state === 'fail'
                      ? 'text-red-600 dark:text-red-400'
                      : 'text-fd-muted-foreground',
                  )}
                >
                  {gate.outcome}
                </span>
              </motion.div>
              <motion.span
                aria-hidden
                className={cn(
                  'mx-1 hidden h-px w-4 origin-left sm:block',
                  gate.state === 'pass' ? 'bg-emerald-500/60' : 'bg-fd-border',
                )}
                initial={{ scaleX: 0 }}
                animate={{ scaleX: 1 }}
                transition={{ delay: index * 0.18 + 0.15, duration: 0.25 }}
              />
            </div>
          ))}
          <motion.div
            aria-live="polite"
            className={cn(
              'col-span-3 flex items-center gap-2.5 rounded-lg border px-3 py-2 sm:col-span-1',
              decision.allowed
                ? 'border-emerald-500/50 bg-emerald-500/10'
                : 'border-red-500/50 bg-red-500/10',
            )}
            initial={{ opacity: 0, scale: 0.96 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.6, duration: 0.35, ease }}
          >
            {decision.allowed ? (
              <ShieldCheck className="size-5 shrink-0 text-emerald-600 dark:text-emerald-400" />
            ) : (
              <ShieldX className="size-5 shrink-0 text-red-600 dark:text-red-400" />
            )}
            <span className="flex min-w-0 flex-col">
              <span className="text-sm font-medium">{decision.allowed ? 'Allowed' : 'Denied'}</span>
              <span className="truncate font-mono text-[0.6875rem] text-fd-muted-foreground">
                {decision.reason}
              </span>
            </span>
          </motion.div>
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
  children,
}: {
  effect: 'allow' | 'deny' | 'boundary';
  sid: string;
  scope: string;
  matched: boolean;
  children?: ReactNode;
}) {
  return (
    <motion.div
      layout
      className={cn(
        'rounded-lg border bg-fd-background px-3 py-2.5 transition-colors duration-300',
        matched && effect === 'deny' && 'border-red-500/45',
        matched && effect !== 'deny' && 'border-emerald-500/40',
      )}
    >
      <div className="flex items-center gap-2">
        <span
          className={cn(
            'rounded px-1.5 py-px font-mono text-[0.625rem] font-medium uppercase tracking-wide',
            effect === 'allow' && 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300',
            effect === 'deny' && 'bg-red-500/10 text-red-700 dark:text-red-300',
            effect === 'boundary' && 'bg-sky-500/10 text-sky-700 dark:text-sky-300',
          )}
        >
          {effect}
        </span>
        <span className="truncate font-mono text-xs font-medium">{sid}</span>
        <AnimatePresence>
          {matched ? (
            <motion.span
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.8 }}
              className="ms-auto shrink-0 text-[0.6875rem] text-fd-muted-foreground"
            >
              matched
            </motion.span>
          ) : null}
        </AnimatePresence>
      </div>
      <p className="mt-1 font-mono text-[0.6875rem] text-fd-muted-foreground">{scope}</p>
      {children ? <div className="mt-2 flex flex-col gap-1">{children}</div> : null}
    </motion.div>
  );
}

/** One condition line with a live marker. For deny statements a met condition means the deny applies. */
function Condition({
  op,
  ok,
  deny,
  children,
}: {
  op: string;
  ok: boolean;
  deny?: boolean;
  children: ReactNode;
}) {
  const bad = deny ? ok : !ok;
  return (
    <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 font-mono text-[0.6875rem]">
      <motion.span
        key={String(ok)}
        initial={{ scale: 0.4, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        transition={{ type: 'spring', stiffness: 600, damping: 24 }}
        className={cn(
          'flex size-3.5 shrink-0 items-center justify-center rounded-full',
          bad
            ? 'bg-red-500/15 text-red-600 dark:text-red-400'
            : 'bg-emerald-500/15 text-emerald-700 dark:text-emerald-300',
        )}
      >
        {ok ? (
          <Check className="size-2.5" strokeWidth={3} />
        ) : (
          <X className="size-2.5" strokeWidth={3} />
        )}
      </motion.span>
      <span className="text-fd-muted-foreground/80">{op}</span>
      <span
        className={cn('break-all', bad ? 'text-red-600 dark:text-red-400' : 'text-fd-foreground')}
      >
        {children}
      </span>
    </div>
  );
}

function GateIcon({ state }: { state: GateState }) {
  if (state === 'pass')
    return <Check className="size-3.5 text-emerald-600 dark:text-emerald-400" strokeWidth={3} />;
  if (state === 'fail')
    return <X className="size-3.5 text-red-600 dark:text-red-400" strokeWidth={3} />;
  return (
    <span className="size-3.5 rounded-full border border-dashed border-fd-muted-foreground/50" />
  );
}
