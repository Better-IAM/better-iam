'use client';

import { useEffect, useState, type KeyboardEvent, type PointerEvent, type ReactNode } from 'react';
import { AnimatePresence, animate, motion, useReducedMotion, useSpring } from 'motion/react';
import { Check, Fingerprint, Link2, ScrollText, ShieldCheck } from 'lucide-react';
import {
  auditEventHash,
  verifyAuditChain,
  type AuditChainVerification,
  type AuditEvent,
} from '@better-iam/core';
import { cn } from '@/lib/cn';
import { PlayToggle } from './frame';
import { ease, useReducedMotionSafe, useStepper } from './motion';

/**
 * The hero: the page's intro on the left, three pillars below it, and a deck of cards on the right that plays one
 * real flow end to end. An owner signs in with a passkey (`auth:session:create`), invites Alice (authorized as
 * `iam:identities:create` on `iam/{tenantId}`), and the invitation joins the tenant's audit chain, hashed and verified
 * in the browser with @better-iam/core.
 */
const INTERVAL = 4800;

const pillars = [
  {
    label: 'Authenticate',
    icon: Fingerprint,
    body: 'Passkeys, MFA, single sign-on, and sessions under each tenant’s own policy.',
  },
  {
    label: 'Authorize',
    icon: ShieldCheck,
    body: 'Roles, policies, and boundaries in one evaluator that explains itself.',
  },
  {
    label: 'Audit',
    icon: ScrollText,
    body: 'Every change appended to a hash chain that anyone can verify.',
  },
] as const;

export function HeroShowcase({ intro }: { intro: ReactNode }) {
  const { ref, step, select, toggle, paused } = useStepper(pillars.length, {
    interval: INTERVAL,
    hold: INTERVAL,
  });

  return (
    <div className="grid gap-12 lg:grid-cols-[minmax(0,1.12fr)_minmax(0,1fr)] lg:grid-rows-[auto_auto] lg:gap-x-12 lg:gap-y-12">
      <div className="lg:col-start-1 lg:row-start-1">{intro}</div>
      <div ref={ref} className="min-w-0 lg:col-start-2 lg:row-span-2 lg:row-start-1 lg:self-center">
        <Deck step={step} paused={paused} onToggle={toggle} />
      </div>
      <div className="lg:col-start-1 lg:row-start-2">
        <Pillars step={step} paused={paused} onSelect={select} />
      </div>
    </div>
  );
}

/** Autoplay tabs: a line fills along the top of the active pillar while its card plays. */
function Pillars({
  step,
  paused,
  onSelect,
}: {
  step: number;
  paused: boolean;
  onSelect: (index: number) => void;
}) {
  // Arrow keys move between pillars, as in any tab list.
  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const delta =
      event.key === 'ArrowRight' || event.key === 'ArrowDown'
        ? 1
        : event.key === 'ArrowLeft' || event.key === 'ArrowUp'
          ? -1
          : 0;
    if (!delta) return;
    event.preventDefault();
    const next = (step + delta + pillars.length) % pillars.length;
    onSelect(next);
    event.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus();
  }

  return (
    <div
      role="tablist"
      aria-label="What Better IAM does"
      onKeyDown={onKeyDown}
      className="grid gap-4 sm:grid-cols-3 sm:gap-5"
    >
      {pillars.map((pillar, index) => {
        const active = index === step;
        const Icon = pillar.icon;
        return (
          <button
            key={pillar.label}
            type="button"
            role="tab"
            aria-selected={active}
            tabIndex={active ? 0 : -1}
            onClick={() => onSelect(index)}
            className="group relative flex flex-col gap-1.5 pt-4 text-start"
          >
            <span aria-hidden className="absolute inset-x-0 top-0 h-px bg-fd-border" />
            {active ? (
              <motion.span
                key={`${step}-${paused}`}
                aria-hidden
                className="absolute inset-x-0 top-0 h-px origin-left bg-fd-primary"
                initial={{ scaleX: paused ? 1 : 0 }}
                animate={{ scaleX: 1 }}
                transition={{ duration: paused ? 0 : INTERVAL / 1000, ease: 'linear' }}
              />
            ) : null}
            <span
              className={cn(
                'flex items-center gap-2 text-sm font-medium transition-colors',
                !active && 'text-fd-muted-foreground group-hover:text-fd-foreground',
              )}
            >
              <Icon className={cn('size-4 transition-colors', active ? 'text-fd-primary' : '')} />
              {pillar.label}
            </span>
            <span className="text-[0.8125rem] leading-5 text-fd-muted-foreground">
              {pillar.body}
            </span>
          </button>
        );
      })}
    </div>
  );
}

const cards = [
  { title: 'Authenticate', icon: Fingerprint, chip: 'auth', Body: SignInCard },
  { title: 'Authorize', icon: ShieldCheck, chip: 'decision', Body: DecisionCard },
  { title: 'Audit', icon: ScrollText, chip: 'audit chain', Body: AuditCard },
] as const;

/** Where a card sits in the deck: 0 is in front; 1 and 2 show only their top edges, like cards in a stack. */
const depthStyles = [
  { y: 0, scale: 1 },
  { y: -16, scale: 0.955 },
  { y: -32, scale: 0.91 },
];

function Deck({ step, paused, onToggle }: { step: number; paused: boolean; onToggle: () => void }) {
  const reduced = useReducedMotion();
  const rotateX = useSpring(0, { stiffness: 140, damping: 18 });
  const rotateY = useSpring(0, { stiffness: 140, damping: 18 });

  function onPointerMove(event: PointerEvent<HTMLDivElement>) {
    if (reduced || event.pointerType !== 'mouse') return;
    const bounds = event.currentTarget.getBoundingClientRect();
    rotateY.set(((event.clientX - bounds.left) / bounds.width - 0.5) * 9);
    rotateX.set(-((event.clientY - bounds.top) / bounds.height - 0.5) * 9);
  }
  function onPointerLeave() {
    rotateX.set(0);
    rotateY.set(0);
  }

  return (
    <div
      className="relative [perspective:1400px]"
      onPointerMove={onPointerMove}
      onPointerLeave={onPointerLeave}
    >
      <motion.div
        style={{ rotateX, rotateY, transformStyle: 'preserve-3d' }}
        className="relative mx-auto h-[26rem] w-full max-w-[34rem]"
      >
        {cards.map((card, index) => {
          const depth = (index - step + cards.length) % cards.length;
          const Icon = card.icon;
          return (
            <motion.div
              key={card.title}
              className={cn(
                'hero-card absolute inset-x-0 bottom-0 flex h-[24rem] flex-col overflow-hidden rounded-2xl border transition-colors duration-500',
                depth === 0 ? 'bg-fd-card' : 'bg-fd-muted',
              )}
              style={{ zIndex: cards.length - depth, transformOrigin: 'top center' }}
              initial={false}
              animate={depthStyles[depth]}
              transition={{ type: 'spring', stiffness: 220, damping: 28 }}
              aria-hidden={depth !== 0}
            >
              <div
                className={cn(
                  'flex h-11 shrink-0 items-center gap-2 border-b px-4 text-xs text-fd-muted-foreground transition-opacity duration-300',
                  depth !== 0 && 'opacity-0',
                )}
              >
                <span className="font-mono tabular-nums">0{index + 1}</span>
                <Icon className="size-3.5 text-fd-primary" />
                <span className="font-medium text-fd-foreground">{card.title}</span>
                <span className="ms-auto flex items-center gap-1.5">
                  {depth === 0 ? <PlayToggle paused={paused} onClick={onToggle} compact /> : null}
                  <span className="rounded-full border px-2 py-0.5 font-mono text-[0.625rem]">
                    {card.chip}
                  </span>
                </span>
              </div>
              <div className="min-h-0 flex-1 p-4 sm:p-5">
                {depth === 0 ? <card.Body key={step} /> : null}
              </div>
            </motion.div>
          );
        })}
      </motion.div>
    </div>
  );
}

/** Runs a card's little script: returns how far along it is (0 to `stages`), or all the way with reduced motion. */
function useScript(stages: number, every = 700, start = 350) {
  const reduced = useReducedMotionSafe();
  const [stage, setStage] = useState(0);
  useEffect(() => {
    if (reduced) {
      setStage(stages);
      return;
    }
    const timers = Array.from({ length: stages }, (_, index) =>
      setTimeout(() => setStage(index + 1), start + index * every),
    );
    return () => timers.forEach(clearTimeout);
  }, [reduced, stages, every, start]);
  return stage;
}

function SignInCard() {
  const email = 'olivia@acme.test';
  const reduced = useReducedMotionSafe();
  const [typed, setTyped] = useState(0);
  const stage = useScript(3, 800, 1100);

  useEffect(() => {
    if (reduced) {
      setTyped(email.length);
      return;
    }
    const controls = animate(0, email.length, {
      duration: 0.8,
      ease: 'linear',
      onUpdate: (value) => setTyped(Math.round(value)),
    });
    return () => controls.stop();
  }, [reduced]);

  return (
    <div className="flex h-full flex-col gap-3">
      <p className="text-[0.9375rem] font-medium">Sign in to Acme</p>
      <div className="flex flex-col gap-1.5">
        <span className="text-xs text-fd-muted-foreground">Email</span>
        <div className="flex h-10 items-center rounded-lg border bg-fd-background px-3 font-mono text-[0.8125rem]">
          {email.slice(0, typed)}
          {stage === 0 ? <span className="caret ms-px h-4 w-px bg-fd-foreground" /> : null}
        </div>
      </div>
      <motion.div
        className="relative flex h-10 items-center justify-center gap-2 rounded-lg bg-fd-primary text-sm font-medium text-fd-primary-foreground"
        animate={stage === 1 ? { scale: [1, 0.97, 1] } : { scale: 1 }}
        transition={{ duration: 0.35 }}
      >
        {stage === 1 ? (
          <motion.span
            aria-hidden
            className="absolute inset-0 rounded-lg ring-2 ring-fd-primary"
            initial={{ opacity: 0.8, scale: 1 }}
            animate={{ opacity: 0, scale: 1.08 }}
            transition={{ duration: 0.8, repeat: Infinity }}
          />
        ) : null}
        <Fingerprint className="size-4" />
        {stage >= 2 ? 'Passkey verified' : 'Continue with passkey'}
      </motion.div>
      <AnimatePresence>
        {stage >= 2 ? (
          <motion.div
            className="mt-auto rounded-xl border bg-fd-background p-3 font-mono text-xs leading-6"
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45, ease }}
          >
            <div className="mb-1 flex items-center gap-2 font-sans">
              <span className="flex size-4 items-center justify-center rounded-full bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
                <Check className="size-2.5" strokeWidth={3.5} />
              </span>
              <span className="text-[0.8125rem] font-medium">Session issued</span>
              <span className="ms-auto text-[0.6875rem] text-fd-muted-foreground">
                auth:session:create
              </span>
            </div>
            <Row name="method" value="'passkey'" accent />
            <Row name="mfa" value="true" />
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: stage >= 3 ? 1 : 0 }}>
              <Row name="expiresAt" value="per tenant policy" plain />
            </motion.div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </div>
  );
}

function DecisionCard() {
  const stage = useScript(4, 650, 500);
  const gates = [
    'No deny statement matches',
    'A grant allows the action',
    'Every boundary allows it',
  ];
  return (
    <div className="flex h-full flex-col gap-3.5">
      <pre className="whitespace-pre-wrap rounded-lg border bg-fd-background px-3 py-2.5 font-mono text-[0.75rem] leading-5 text-fd-muted-foreground">
        <span className="text-fd-foreground">iam.api.identities.invite</span>(credential, {'{'}
        {'\n'} tenantId, email: <span className="text-fd-primary">&apos;alice@acme.test&apos;</span>
        {'\n'}
        {'}'})
      </pre>
      <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-0.5 font-mono text-xs leading-5">
        <dt className="text-fd-muted-foreground">action</dt>
        <dd className="truncate">iam:identities:create</dd>
        <dt className="text-fd-muted-foreground">resource</dt>
        <dd className="truncate">iam/{'{tenantId}'}</dd>
      </dl>
      <ol className="flex flex-col gap-2">
        {gates.map((gate, index) => (
          <li key={gate} className="flex items-center gap-2.5 text-[0.8125rem]">
            <span className="relative flex size-4 shrink-0 items-center justify-center rounded-full border">
              <AnimatePresence>
                {stage > index ? (
                  <motion.span
                    className="absolute inset-[-1px] flex items-center justify-center rounded-full bg-fd-primary text-fd-primary-foreground"
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    transition={{ type: 'spring', stiffness: 500, damping: 24 }}
                  >
                    <Check className="size-2.5" strokeWidth={3.5} />
                  </motion.span>
                ) : null}
              </AnimatePresence>
            </span>
            <span
              className={cn('transition-colors', stage > index ? '' : 'text-fd-muted-foreground')}
            >
              {gate}
            </span>
          </li>
        ))}
      </ol>
      <AnimatePresence>
        {stage >= 4 ? (
          <motion.div
            className="mt-auto flex items-center gap-3 rounded-xl border border-emerald-500/40 bg-emerald-500/[0.08] px-3.5 py-3"
            initial={{ opacity: 0, scale: 0.96 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ type: 'spring', stiffness: 380, damping: 26 }}
          >
            <ShieldCheck className="size-5 text-emerald-600 dark:text-emerald-400" />
            <span className="text-sm font-medium">Allowed</span>
            <span className="ms-auto font-mono text-[0.6875rem] text-fd-muted-foreground">
              reason: allowed
            </span>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </div>
  );
}

type Body = Pick<
  AuditEvent,
  'id' | 'tenantId' | 'actorId' | 'action' | 'resourceId' | 'timestamp' | 'outcome'
>;

const trail: Body[] = [
  {
    id: 'audit_39',
    tenantId: 'acme',
    actorId: 'usr_olivia',
    action: 'iam:roles:create',
    resourceId: 'role_editor',
    timestamp: 1790000000000,
    outcome: 'allow',
  },
  {
    id: 'audit_40',
    tenantId: 'acme',
    actorId: 'usr_olivia',
    action: 'auth:session:create',
    resourceId: 'usr_olivia',
    timestamp: 1790000600000,
    outcome: 'allow',
  },
  {
    id: 'audit_41',
    tenantId: 'acme',
    actorId: 'usr_olivia',
    action: 'iam:identities:create',
    resourceId: 'usr_alice',
    timestamp: 1790000660000,
    outcome: 'allow',
  },
];

/** Chains the trail from sequence 39 (after an earlier head), exactly as appendAuditEvent would. */
let chained: Promise<{ events: AuditEvent[]; verification: AuditChainVerification }> | undefined;
function chainTrail() {
  chained ??= (async () => {
    const events: AuditEvent[] = [];
    let previousHash = '9f2c41d07be3a85c6e1f0d2b7a4c9e38f5b16d0a2c7e4f91b3d8a6c05e2f7b14';
    for (const [index, body] of trail.entries()) {
      const event: AuditEvent = { ...body, sequence: 39 + index, previousHash };
      event.hash = await auditEventHash(event);
      events.push(event);
      previousHash = event.hash;
    }
    return { events, verification: await verifyAuditChain(events) };
  })();
  return chained;
}

function AuditCard() {
  const [chain, setChain] = useState<{
    events: AuditEvent[];
    verification: AuditChainVerification;
  }>();
  const stage = useScript(2, 900, 700);
  useEffect(() => {
    let live = true;
    void chainTrail().then((result) => live && setChain(result));
    return () => {
      live = false;
    };
  }, []);

  const shown = chain ? (stage >= 1 ? chain.events : chain.events.slice(0, 2)) : [];
  return (
    <div className="flex h-full flex-col gap-2">
      <ol className="flex flex-col-reverse gap-1.5">
        <AnimatePresence initial={false}>
          {shown.map((event, index) => (
            <motion.li
              key={event.id}
              layout
              initial={{ opacity: 0, y: -14, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              transition={{ duration: 0.45, ease }}
              className={cn(
                'flex flex-col gap-0.5 rounded-lg border bg-fd-background px-3 py-2 font-mono text-[0.6875rem] leading-5',
                index === 2 && 'border-fd-primary/50',
              )}
            >
              <span className="flex items-center gap-2">
                <span className="text-fd-muted-foreground">#{event.sequence}</span>
                <span className="truncate text-fd-foreground">{event.action}</span>
                {index === 2 ? (
                  <span className="ms-auto rounded-full bg-fd-primary/10 px-1.5 font-sans text-[0.625rem] font-medium text-fd-primary">
                    new
                  </span>
                ) : null}
              </span>
              <span className="flex items-center gap-1.5 text-fd-muted-foreground">
                <Link2 className="size-3 shrink-0 text-fd-primary/70" />
                prev {event.previousHash!.slice(0, 8)}… · hash{' '}
                <span className="text-fd-foreground">{event.hash!.slice(0, 8)}…</span>
              </span>
            </motion.li>
          ))}
        </AnimatePresence>
      </ol>
      <AnimatePresence>
        {chain && stage >= 2 ? (
          <motion.div
            className="mt-auto flex items-center gap-2.5 rounded-xl border border-emerald-500/40 bg-emerald-500/[0.08] px-3.5 py-2.5"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, ease }}
          >
            <ShieldCheck className="size-5 shrink-0 text-emerald-600 dark:text-emerald-400" />
            <span className="flex min-w-0 flex-col">
              <span className="text-sm font-medium">Chain verified</span>
              <span className="truncate font-mono text-[0.6875rem] text-fd-muted-foreground">
                verifyAuditChain → {'{'} valid: {String(chain.verification.valid)}, checked:{' '}
                {chain.verification.checked} {'}'}
              </span>
            </span>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </div>
  );
}

function Row({
  name,
  value,
  accent,
  plain,
}: {
  name: string;
  value: string;
  accent?: boolean;
  plain?: boolean;
}) {
  return (
    <div className="flex gap-3">
      <span className="w-20 shrink-0 text-fd-muted-foreground">{name}</span>
      <span
        className={cn(accent && 'text-fd-primary', plain && 'font-sans text-fd-muted-foreground')}
      >
        {value}
      </span>
    </div>
  );
}
