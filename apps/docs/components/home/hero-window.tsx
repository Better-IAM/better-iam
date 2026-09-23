'use client';

import {
  useEffect,
  useId,
  useState,
  type KeyboardEvent,
  type PointerEvent,
  type ReactNode,
} from 'react';
import { AnimatePresence, animate, motion, useSpring } from 'motion/react';
import type { IconType } from 'react-icons';
import {
  RiCheckLine,
  RiCornerDownRightLine,
  RiFileCodeLine,
  RiFileList2Line,
  RiFingerprintLine,
  RiLinkM,
  RiPauseLine,
  RiPlayLine,
  RiRestartLine,
  RiShieldCheckLine,
} from 'react-icons/ri';
import {
  auditEventHash,
  verifyAuditChain,
  type AuditChainVerification,
  type AuditEvent,
} from '@better-iam/core';
import { Chip } from '@/components/base/badges/chip';
import { cx } from '@/utils/cx';
import { ease, useReducedMotionSafe, useStepper } from './motion';

/**
 * The hero's product window. Three pillars play in turn: an owner signs in with a passkey (`auth:session:create`,
 * a session with `mfa: true`), invites Alice (authorized as `iam:identities:create` on `iam/{tenantId}`), and the
 * invitation joins the tenant's audit chain, hashed and verified in the browser with @better-iam/core.
 * Each pillar runs its code in the middle while the scene on the right plays it out: a band follows the lines the
 * scene is on, and the status bar reports what reached the audit chain.
 */
const INTERVAL = 6400;
/** The outgoing scene takes this long to leave, so the next script starts after it. */
const SWAP = 400;
/** The code pane's rhythm in rem (`leading-5`, `py-4`), shared by the text and the band that follows it. */
const LINE = 1.25;
const PAD = 1;

type Script = { stages: number; every: number; start: number };

type Pillar = {
  label: string;
  icon: IconType;
  body: string;
  file: string;
  /** A stage every `every` ms after `start`, from 0 up to `stages`. */
  script: Script;
  /** The 1-based line range of the snippet each stage is running, indexed by stage. */
  lines: readonly (readonly [first: number, last: number])[];
  /** What the pillar leaves behind once its script reaches stage `at`. */
  event: { at: number; action: string; note: string };
};

const pillars: readonly Pillar[] = [
  {
    label: 'Authenticate',
    icon: RiFingerprintLine,
    body: 'Passkeys, MFA, single sign-on, and sessions under each tenant’s own policy.',
    file: 'app/login/passkey.ts',
    // Email typed (begin), passkey pressed (the browser ceremony), then the server finishes and issues the session.
    script: { stages: 3, every: 800, start: 1100 },
    lines: [
      [3, 7],
      [8, 10],
      [12, 17],
      [12, 17],
    ],
    event: { at: 2, action: 'auth:session:create', note: 'appended to the audit chain' },
  },
  {
    label: 'Authorize',
    icon: RiShieldCheckLine,
    body: 'Roles, policies, and boundaries in one evaluator that explains itself.',
    file: 'app/api/invite/route.ts',
    // The invitation's request, its three gates, the decision, then your own action through the same evaluator.
    script: { stages: 5, every: 650, start: 500 },
    lines: [
      [1, 5],
      [1, 5],
      [1, 5],
      [1, 5],
      [1, 5],
      [7, 13],
    ],
    event: { at: 4, action: 'iam:identities:create', note: 'appended to the audit chain' },
  },
  {
    label: 'Audit',
    icon: RiFileList2Line,
    body: 'Every change appended to a hash chain that anyone can verify.',
    file: 'scripts/verify-audit.ts',
    // The chain so far, the invitation appended to it, then the verification.
    script: { stages: 2, every: 900, start: 700 },
    lines: [
      [3, 5],
      [3, 5],
      [6, 8],
    ],
    event: { at: 2, action: 'verifyAuditChain', note: 'checked 3 events, chain intact' },
  },
];

export function HeroWindow({ code }: { code: ReactNode[] }) {
  const { ref, step, select, toggle, paused, hovered, setHovered } = useStepper(pillars.length, {
    interval: INTERVAL,
    hold: INTERVAL,
  });
  const pillar = pillars[step]!;
  // Replaying remounts the scene and restarts its script.
  const [run, setRun] = useState(0);
  const stage = useScript(pillar.script, `${step}:${run}`);
  const reduced = useReducedMotionSafe();
  const rotateX = useSpring(0, { stiffness: 150, damping: 20 });
  const rotateY = useSpring(0, { stiffness: 150, damping: 20 });

  // A slight tilt toward the pointer, so the window feels like an object on the page.
  function onPointerMove(event: PointerEvent<HTMLDivElement>) {
    if (reduced || event.pointerType !== 'mouse') return;
    const bounds = event.currentTarget.getBoundingClientRect();
    rotateY.set(((event.clientX - bounds.left) / bounds.width - 0.5) * 3);
    rotateX.set(-((event.clientY - bounds.top) / bounds.height - 0.5) * 3);
  }
  function onPointerLeave() {
    rotateX.set(0);
    rotateY.set(0);
    setHovered(false);
  }
  function replay() {
    select(step);
    setRun((value) => value + 1);
  }

  return (
    <div
      className="[perspective:1800px]"
      onPointerEnter={(event) => event.pointerType === 'mouse' && setHovered(true)}
      onPointerMove={onPointerMove}
      onPointerLeave={onPointerLeave}
    >
      <motion.div
        ref={ref}
        style={{ rotateX, rotateY }}
        className="overflow-hidden rounded-2xl border border-border-button-default bg-surface-raised shadow-sm transition-[border-color,box-shadow] duration-300 hover:border-border-button-hover hover:shadow-lg"
      >
        {/* No window chrome: a product panel, not a browser. Rail | code | result share one header row. */}
        <div className="xl:grid xl:grid-cols-[15rem_minmax(0,1fr)]">
          <div className="xl:flex xl:flex-col xl:border-e xl:border-separator-border">
            <div className="hidden xl:block">
              <PaneHeader>
                <span className="live-dot" aria-hidden />
                <span>Walkthrough</span>
                <span className="ms-auto font-mono text-text-tertiary tabular-nums">
                  0{step + 1} / 0{pillars.length}
                </span>
              </PaneHeader>
            </div>
            {/* While the pointer rests on the card the pillar holds, so its scene can be read to the end. */}
            <PillarTabs step={step} paused={paused || hovered} onSelect={select} />
          </div>

          <div
            id="hero-panel"
            role="tabpanel"
            aria-label={pillar.label}
            className="grid lg:grid-cols-[minmax(0,1.35fr)_minmax(0,1fr)] xl:grid-cols-[minmax(0,1fr)_21rem]"
          >
            <CodePane code={code[step]} step={step} stage={stage} />

            <div className="flex min-w-0 flex-col bg-surface-sunken">
              <PaneHeader>
                <span>Result</span>
                <button
                  type="button"
                  onClick={replay}
                  className="group/replay ms-auto -me-2 inline-flex h-7 items-center gap-1.5 rounded-lg px-2 text-caption-1-medium transition-colors hover:bg-background-secondary-default hover:text-text-primary"
                >
                  <RiRestartLine
                    className="size-3.5 transition-transform duration-500 group-hover/replay:-rotate-180"
                    aria-hidden
                  />
                  Replay
                </button>
              </PaneHeader>
              <div className="relative h-[25rem] overflow-hidden lg:h-auto lg:flex-1">
                <div
                  aria-hidden
                  className="grid-lines absolute inset-0 [background-size:28px_28px]"
                />
                <AnimatePresence mode="wait" initial={false}>
                  <motion.div
                    key={`${step}:${run}`}
                    className="absolute inset-0 flex p-5"
                    initial={{ opacity: 0, x: 24 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -24 }}
                    transition={{ duration: SWAP / 1000, ease }}
                  >
                    {step === 0 ? (
                      <SignInScene stage={stage} />
                    ) : step === 1 ? (
                      <DecisionScene stage={stage} />
                    ) : (
                      <AuditScene stage={stage} />
                    )}
                  </motion.div>
                </AnimatePresence>
              </div>
            </div>
          </div>
        </div>

        <StatusBar
          pillar={pillar}
          step={step}
          stage={stage}
          state={paused ? 'paused' : hovered ? 'held' : undefined}
          paused={paused}
          onToggle={toggle}
        />
      </motion.div>
    </div>
  );
}

/**
 * The pillars as steps. On wide screens they form a vertical rail of numbered nodes joined by a line that fills in as
 * the walkthrough moves along; narrower, they sit in a row of tabs. A ring around the active node shows its time.
 */
function PillarTabs({
  step,
  paused,
  onSelect,
}: {
  step: number;
  paused: boolean;
  onSelect: (index: number) => void;
}) {
  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const forward = event.key === 'ArrowRight' || event.key === 'ArrowDown';
    const back = event.key === 'ArrowLeft' || event.key === 'ArrowUp';
    if (!forward && !back) return;
    event.preventDefault();
    const next = (step + (forward ? 1 : -1) + pillars.length) % pillars.length;
    onSelect(next);
    event.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus();
  }

  return (
    <div
      role="tablist"
      aria-label="What Better IAM does"
      onKeyDown={onKeyDown}
      className="grid grid-cols-3 border-b border-separator-border xl:flex xl:flex-col xl:border-b-0 xl:py-2"
    >
      {pillars.map((pillar, index) => {
        const active = index === step;
        const done = index < step;
        const Icon = pillar.icon;
        return (
          <button
            key={pillar.label}
            type="button"
            role="tab"
            aria-selected={active}
            aria-controls="hero-panel"
            tabIndex={active ? 0 : -1}
            onClick={() => onSelect(index)}
            className={cx(
              'group relative flex min-w-0 items-start gap-3 px-3 py-3.5 text-start transition-colors duration-200 sm:px-4 xl:px-5',
              index > 0 && 'border-s border-separator-border xl:border-s-0',
              active
                ? 'bg-background-secondary-default/60'
                : 'hover:bg-background-secondary-default/40',
            )}
          >
            {/* Without the node (small screens), a line along the top shows the time left. */}
            {active ? (
              <motion.span
                key={`${step}-${paused}`}
                aria-hidden
                className="absolute inset-x-0 top-0 h-0.5 origin-left bg-text-primary sm:hidden"
                initial={{ scaleX: paused ? 1 : 0 }}
                animate={{ scaleX: 1 }}
                transition={{ duration: paused ? 0 : INTERVAL / 1000, ease: 'linear' }}
              />
            ) : null}

            {/* The rail's line, in two halves around the node, ink once the walkthrough has passed it. */}
            {index > 0 ? (
              <span
                aria-hidden
                className={cx(
                  'absolute start-[calc(2.125rem-0.5px)] top-0 hidden h-2 w-px transition-colors duration-500 xl:block',
                  index <= step ? 'bg-text-primary' : 'bg-separator-border',
                )}
              />
            ) : null}
            {index < pillars.length - 1 ? (
              <span
                aria-hidden
                className={cx(
                  'absolute start-[calc(2.125rem-0.5px)] top-[3rem] bottom-0 hidden w-px transition-colors duration-500 xl:block',
                  index < step ? 'bg-text-primary' : 'bg-separator-border',
                )}
              />
            ) : null}

            <span className="relative hidden size-7 shrink-0 sm:block">
              <span
                className={cx(
                  'flex size-7 items-center justify-center rounded-full border font-mono text-caption-2-regular tabular-nums transition-colors duration-300',
                  active
                    ? 'border-text-primary bg-text-primary text-background-full'
                    : done
                      ? 'border-text-primary text-text-primary'
                      : 'border-border-button-hover text-text-tertiary group-hover:text-text-primary',
                )}
              >
                {done ? <RiCheckLine className="size-3.5" aria-hidden /> : `0${index + 1}`}
              </span>
              {active ? (
                <svg
                  aria-hidden
                  viewBox="0 0 36 36"
                  className="pointer-events-none absolute -inset-1 size-9 -rotate-90 text-text-primary"
                >
                  <motion.circle
                    key={`${step}-${paused}`}
                    cx="18"
                    cy="18"
                    r="17"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.25"
                    initial={{ pathLength: paused ? 1 : 0 }}
                    animate={{ pathLength: 1 }}
                    transition={{ duration: paused ? 0 : INTERVAL / 1000, ease: 'linear' }}
                  />
                </svg>
              ) : null}
            </span>

            <span className="flex min-w-0 flex-col gap-1 sm:pt-1">
              <span
                className={cx(
                  'flex items-center gap-2 text-body-medium transition-colors',
                  active
                    ? 'text-text-primary'
                    : 'text-text-secondary group-hover:text-text-primary',
                )}
              >
                <Icon className="hidden size-4 shrink-0 sm:block" aria-hidden />
                <span className="truncate">{pillar.label}</span>
              </span>
              <span
                className={cx(
                  'hidden text-caption-1-regular leading-[1.1rem] transition-colors duration-300 md:block',
                  active ? 'text-text-secondary' : 'text-text-tertiary',
                )}
              >
                {pillar.body}
              </span>
            </span>
          </button>
        );
      })}
    </div>
  );
}

/**
 * The pillar's source with line numbers. A band slides to the lines the scene is running and the rest dim; pointing
 * at the code brings every line back.
 */
function CodePane({ code, step, stage }: { code: ReactNode; step: number; stage: number }) {
  const pillar = pillars[step]!;
  const [first, last] = pillar.lines[Math.min(stage, pillar.lines.length - 1)]!;
  const id = useId();
  const scope = `[data-hero-code="${id}"]`;

  return (
    <div className="flex min-w-0 flex-col border-b border-separator-border lg:border-e lg:border-b-0">
      <PaneHeader>
        <RiFileCodeLine className="size-3.5 shrink-0" aria-hidden />
        <AnimatePresence mode="wait" initial={false}>
          <motion.span
            key={pillar.file}
            className="truncate font-mono"
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.2 }}
          >
            {pillar.file}
          </motion.span>
        </AnimatePresence>
        <span className="ms-auto hidden shrink-0 font-mono text-text-tertiary tabular-nums sm:inline">
          L{first}
          {last > first ? `–${last}` : ''}
        </span>
      </PaneHeader>
      <div className="relative h-[23.25rem]">
        <motion.div
          aria-hidden
          className="pointer-events-none absolute inset-x-0 bg-background-secondary-default"
          initial={false}
          animate={{
            top: `${PAD + (first - 1) * LINE}rem`,
            height: `${(last - first + 1) * LINE}rem`,
          }}
          transition={{ duration: 0.5, ease }}
        >
          <span className="absolute inset-y-0 start-0 w-0.5 bg-text-primary" />
        </motion.div>
        <div
          data-hero-code={id}
          data-lenis-prevent-horizontal
          className="hero-code home-code relative h-full overflow-x-auto px-4 py-4 font-mono text-[0.75rem] leading-5"
        >
          <style>{`${scope} .line:nth-child(n + ${first}):nth-child(-n + ${last}) { opacity: 1; }
${scope} .line:nth-child(n + ${first}):nth-child(-n + ${last})::before { color: var(--color-text-primary); }`}</style>
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={step}
              initial={{ opacity: 0, x: 16, filter: 'blur(4px)' }}
              animate={{ opacity: 1, x: 0, filter: 'blur(0px)' }}
              exit={{ opacity: 0, x: -16, filter: 'blur(4px)' }}
              transition={{ duration: 0.35, ease }}
            >
              {code}
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}

/** What the current pillar left behind, whether the walkthrough is running, held, or paused, and its play control. */
function StatusBar({
  pillar,
  step,
  stage,
  state,
  paused,
  onToggle,
}: {
  pillar: Pillar;
  step: number;
  stage: number;
  state?: 'paused' | 'held';
  paused: boolean;
  onToggle: () => void;
}) {
  const reached = stage >= pillar.event.at;
  return (
    <div className="flex h-10 items-center gap-3 border-t border-separator-border px-4 font-mono text-caption-1-regular">
      <AnimatePresence mode="wait" initial={false}>
        <motion.span
          key={`${step}:${reached}`}
          className="flex min-w-0 items-center gap-2"
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -6 }}
          transition={{ duration: 0.25, ease }}
        >
          {reached ? (
            <>
              <Done />
              <span className="truncate">{pillar.event.action}</span>
              <span className="hidden truncate font-sans text-text-secondary sm:inline">
                {pillar.event.note}
              </span>
            </>
          ) : (
            <>
              <span
                aria-hidden
                className="size-4 shrink-0 rounded-full border border-dashed border-text-tertiary motion-safe:animate-spin"
              />
              <span className="truncate text-text-tertiary">running {pillar.file}</span>
            </>
          )}
        </motion.span>
      </AnimatePresence>
      <span className="ms-auto shrink-0 text-text-tertiary tabular-nums">
        {state ?? <span className="xl:hidden">{`0${step + 1} / 0${pillars.length}`}</span>}
      </span>
      <button
        type="button"
        onClick={onToggle}
        aria-label={paused ? 'Play the walkthrough' : 'Pause the walkthrough'}
        className="-me-2 inline-flex h-7 shrink-0 items-center gap-1.5 rounded-lg px-2 font-sans text-caption-1-medium text-text-secondary transition-colors hover:bg-background-secondary-default hover:text-text-primary"
      >
        {paused ? (
          <RiPlayLine className="size-3.5" aria-hidden />
        ) : (
          <RiPauseLine className="size-3.5" aria-hidden />
        )}
        {paused ? 'Play' : 'Pause'}
      </button>
    </div>
  );
}

function PaneHeader({ children }: { children: ReactNode }) {
  return (
    <div className="flex h-10 shrink-0 items-center gap-2 border-b border-separator-border px-4 text-caption-1-regular text-text-secondary">
      {children}
    </div>
  );
}

/**
 * Plays a scene's script from the top whenever `key` changes: how far along it is (0 to `stages`), or all the way
 * with reduced motion.
 */
function useScript({ stages, every, start }: Script, key: string) {
  const reduced = useReducedMotionSafe();
  const [progress, setProgress] = useState({ key, stage: 0 });
  useEffect(() => {
    if (reduced) {
      setProgress({ key, stage: stages });
      return;
    }
    setProgress({ key, stage: 0 });
    const timers = Array.from({ length: stages }, (_, index) =>
      setTimeout(() => setProgress({ key, stage: index + 1 }), SWAP + start + index * every),
    );
    return () => timers.forEach(clearTimeout);
  }, [reduced, stages, every, start, key]);
  // Until the effect catches up with a new key, the new script is at its start.
  if (progress.key === key) return progress.stage;
  return reduced ? stages : 0;
}

function Scene({ children }: { children: ReactNode }) {
  return <div className="mx-auto flex h-full w-full max-w-md flex-col gap-3">{children}</div>;
}

function Done({ className }: { className?: string }) {
  return (
    <span
      className={cx(
        'flex size-4 shrink-0 items-center justify-center rounded-full bg-text-primary text-background-full',
        className,
      )}
    >
      <RiCheckLine className="size-3" aria-hidden />
    </span>
  );
}

function SignInScene({ stage }: { stage: number }) {
  const email = 'olivia@acme.test';
  const reduced = useReducedMotionSafe();
  const [typed, setTyped] = useState(0);

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
    <Scene>
      <div className="rounded-xl border border-border-button-default bg-background-primary-default p-4 shadow-xs">
        <p className="text-headline-semibold">Sign in to Acme</p>
        <label className="mt-3 flex flex-col gap-1.5">
          <span className="text-caption-1-medium text-text-secondary">Email</span>
          <span className="flex h-9 items-center rounded-lg border border-border-button-default bg-background-primary-default px-3 font-mono text-body-2-regular shadow-xs">
            {email.slice(0, typed)}
            {stage === 0 ? <span className="caret ms-px h-4 w-px bg-text-primary" /> : null}
          </span>
        </label>
        <motion.span
          className="bg-button-primary relative mt-3 flex h-9 items-center justify-center gap-2 rounded-2lg text-body-medium text-button-primary-foreground shadow-xs"
          animate={stage === 1 ? { scale: [1, 0.97, 1] } : { scale: 1 }}
          transition={{ duration: 0.35 }}
        >
          <RiFingerprintLine className="size-4" aria-hidden />
          {stage >= 2 ? 'Passkey verified' : 'Continue with passkey'}
        </motion.span>
      </div>
      <AnimatePresence>
        {stage >= 2 ? (
          <motion.div
            className="rounded-xl border border-border-button-default bg-background-primary-default p-4 font-mono text-caption-1-regular leading-6 shadow-xs"
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45, ease }}
          >
            <div className="mb-1.5 flex items-center gap-2 font-sans">
              <Done />
              <span className="text-body-medium">Session issued</span>
            </div>
            <Field name="method" value="'passkey'" />
            <Field name="mfa" value="true" />
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: stage >= 3 ? 1 : 0 }}>
              <Field name="expiresAt" value="per tenant policy" muted />
            </motion.div>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </Scene>
  );
}

function DecisionScene({ stage }: { stage: number }) {
  const gates = [
    'No deny statement matches',
    'A grant allows the action',
    'Every boundary allows it',
  ];
  return (
    <Scene>
      <div className="rounded-xl border border-border-button-default bg-background-primary-default p-4 shadow-xs">
        <dl className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 font-mono text-caption-1-regular leading-5">
          <dt className="text-text-secondary">principal</dt>
          <dd className="truncate">usr_olivia · mfa true</dd>
          <dt className="text-text-secondary">action</dt>
          <dd className="truncate">iam:identities:create</dd>
          <dt className="text-text-secondary">resource</dt>
          <dd className="truncate">iam/{'{tenantId}'}</dd>
        </dl>
        <ol className="mt-3 flex flex-col gap-2 border-t border-separator-border pt-3">
          {gates.map((gate, index) => (
            <li key={gate} className="flex items-center gap-2.5 text-body-2-regular">
              <span className="relative flex size-4 shrink-0 items-center justify-center rounded-full border border-border-button-hover">
                <AnimatePresence>
                  {stage > index ? (
                    <motion.span
                      className="absolute -inset-px"
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      transition={{ type: 'spring', stiffness: 500, damping: 24 }}
                    >
                      <Done />
                    </motion.span>
                  ) : null}
                </AnimatePresence>
              </span>
              <span className={cx('transition-colors', stage > index ? '' : 'text-text-tertiary')}>
                {gate}
              </span>
            </li>
          ))}
        </ol>
      </div>
      <AnimatePresence>
        {stage >= 4 ? (
          <motion.div
            className="flex items-center gap-3 rounded-xl bg-text-primary px-4 py-3 text-background-full"
            initial={{ opacity: 0, scale: 0.96 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ type: 'spring', stiffness: 380, damping: 26 }}
          >
            <RiShieldCheckLine className="size-5 shrink-0" aria-hidden />
            <span className="text-body-semibold">Allowed</span>
            <span className="ms-auto font-mono text-caption-2-regular opacity-70">
              reason: allowed
            </span>
          </motion.div>
        ) : null}
      </AnimatePresence>
      <AnimatePresence>
        {stage >= 5 ? (
          <motion.div
            className="flex items-start gap-3 rounded-xl border border-border-button-default bg-background-primary-default px-4 py-3 shadow-xs"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45, ease }}
          >
            <RiCornerDownRightLine
              className="mt-0.5 size-4 shrink-0 text-text-secondary"
              aria-hidden
            />
            <span className="flex min-w-0 flex-col gap-0.5">
              <span className="truncate font-mono text-caption-1-regular">
                iam.require · invoices:approve
              </span>
              <span className="text-caption-1-regular text-text-secondary">
                The same evaluator. It throws ACCESS_DENIED when it denies.
              </span>
            </span>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </Scene>
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

function AuditScene({ stage }: { stage: number }) {
  const [chain, setChain] = useState<{
    events: AuditEvent[];
    verification: AuditChainVerification;
  }>();
  useEffect(() => {
    let live = true;
    void chainTrail().then((result) => live && setChain(result));
    return () => {
      live = false;
    };
  }, []);

  const shown = chain ? (stage >= 1 ? chain.events : chain.events.slice(0, 2)) : [];
  return (
    <Scene>
      <ol className="flex flex-col-reverse gap-2">
        <AnimatePresence initial={false}>
          {shown.map((event, index) => (
            <motion.li
              key={event.id}
              layout
              initial={{ opacity: 0, y: -14, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              transition={{ duration: 0.45, ease }}
              className={cx(
                'flex flex-col gap-0.5 rounded-xl border bg-background-primary-default px-3.5 py-2.5 font-mono text-caption-1-regular leading-5 shadow-xs',
                index === 2 ? 'border-text-primary' : 'border-border-button-default',
              )}
            >
              <span className="flex items-center gap-2">
                <span className="text-text-secondary">#{event.sequence}</span>
                <span className="truncate">{event.action}</span>
                {index === 2 ? (
                  <Chip variant="caption" color="gray" className="ms-auto px-1.5 py-0 font-sans">
                    new
                  </Chip>
                ) : null}
              </span>
              <span className="flex items-center gap-1.5 text-text-secondary">
                <RiLinkM className="size-3 shrink-0" aria-hidden />
                prev {event.previousHash!.slice(0, 8)}… · hash{' '}
                <span className="text-text-primary">{event.hash!.slice(0, 8)}…</span>
              </span>
            </motion.li>
          ))}
        </AnimatePresence>
      </ol>
      <AnimatePresence>
        {chain && stage >= 2 ? (
          <motion.div
            className="mt-auto flex items-center gap-3 rounded-xl bg-text-primary px-4 py-3 text-background-full"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, ease }}
          >
            <RiShieldCheckLine className="size-5 shrink-0" aria-hidden />
            <span className="flex min-w-0 flex-col">
              <span className="text-body-semibold">Chain verified</span>
              <span className="truncate font-mono text-caption-2-regular opacity-70">
                {'{'} valid: {String(chain.verification.valid)}, checked:{' '}
                {chain.verification.checked} {'}'}
              </span>
            </span>
          </motion.div>
        ) : null}
      </AnimatePresence>
    </Scene>
  );
}

function Field({ name, value, muted }: { name: string; value: string; muted?: boolean }) {
  return (
    <div className="flex gap-3">
      <span className="w-20 shrink-0 text-text-secondary">{name}</span>
      <span className={cx(muted && 'font-sans text-text-secondary')}>{value}</span>
    </div>
  );
}
