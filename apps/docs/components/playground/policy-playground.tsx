'use client';

import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { AnimatePresence, MotionConfig, motion } from 'motion/react';
import {
  RiAddLine,
  RiArrowRightLine,
  RiArrowRightSLine,
  RiCheckLine,
  RiCloseLine,
  RiErrorWarningLine,
  RiFileCopyLine,
  RiLinkM,
  RiRestartLine,
  RiShieldCheckLine,
  RiShieldCrossLine,
  RiSubtractLine,
} from 'react-icons/ri';
import type { PolicyDocument } from '@better-iam/core';
import { Button } from '@/components/base/buttons/button';
import { cx } from '@/utils/cx';
import { ConditionBuilder, PopCheck } from './condition-builder';
import { JsonEditor, useOverflowing } from './json-editor';
import { contextKeys, scenarios, type Scenario } from './presets';
import { evaluate, parseDocument, reasons, type StatementTrace } from './trace';

interface State {
  grants: string[];
  boundaries: string[];
  action: string;
  resource: string;
  context: string;
}

/** The site's one easing curve: a quick start and a long, soft settle. */
const ease = [0.16, 1, 0.3, 1] as const;

const pretty = (value: unknown) => JSON.stringify(value, null, 2);

function fromScenario(scenario: Scenario): State {
  return {
    grants: scenario.grants.map(pretty),
    boundaries: scenario.boundaries.map(pretty),
    action: scenario.action,
    resource: scenario.resource,
    context: pretty(scenario.context),
  };
}

function encodeState(state: State) {
  const bytes = new TextEncoder().encode(JSON.stringify(state));
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeState(value: string): State | undefined {
  try {
    const binary = atob(value.replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    const parsed = JSON.parse(new TextDecoder().decode(bytes));
    if (
      Array.isArray(parsed.grants) &&
      Array.isArray(parsed.boundaries) &&
      typeof parsed.action === 'string'
    )
      return parsed as State;
  } catch {
    // An unreadable link falls back to the first scenario.
  }
  return undefined;
}

/**
 * The character range of `statements[index]` in a policy document's JSON text, so the editor can highlight the
 * statement hovered in the trace. Scans the text (strings and nesting) instead of re-serializing it.
 */
function statementRange(text: string, index: number): [number, number] | undefined {
  let depth = 0;
  let key = '';
  let lastString = '';
  let inStatements = false;
  let count = -1;
  let start = -1;
  for (let position = 0; position < text.length; position++) {
    const char = text[position];
    if (char === '"') {
      let end = position + 1;
      while (end < text.length && text[end] !== '"') end += text[end] === '\\' ? 2 : 1;
      lastString = text.slice(position + 1, end);
      position = end;
    } else if (char === ':' && depth === 1) key = lastString;
    else if (char === '{' || char === '[') {
      depth++;
      if (char === '[' && depth === 2 && key === 'statements') inStatements = true;
      else if (char === '{' && inStatements && depth === 3 && ++count === index) start = position;
    } else if (char === '}' || char === ']') {
      if (start >= 0 && depth === 3) return [start, position + 1];
      if (inStatements && depth === 2) return undefined;
      depth--;
    }
  }
  return undefined;
}

const emptyGrant = pretty({
  version: 1,
  statements: [
    { sid: 'New', effect: 'allow', actions: ['documents:read'], resources: ['document/*'] },
  ],
});

const panel =
  'flex min-w-0 flex-col overflow-hidden rounded-2xl border border-border-button-default bg-surface-raised shadow-sm';
const panelHeader =
  'flex h-11 shrink-0 items-center gap-2 border-b border-separator-border px-4 sm:px-5';
const input =
  'h-9 w-full min-w-0 rounded-lg border border-border-button-default bg-background-primary-default px-3 font-mono text-body-regular text-text-primary shadow-xs outline-none transition-[border-color,box-shadow] duration-150 hover:border-border-button-hover focus:border-border-button-active focus:ring-2 focus:ring-border-focus-ring';

export function PolicyPlayground() {
  const [scenarioId, setScenarioId] = useState(scenarios[0]!.id);
  const [state, setState] = useState<State>(() => fromScenario(scenarios[0]!));
  const [tab, setTab] = useState<'grants' | 'boundaries'>('grants');
  const [copied, setCopied] = useState(false);
  // Presentation only: the statement hovered in the trace (or the decision), and the context key just inserted.
  const [hovered, setHovered] = useState<string>();
  const [inserted, setInserted] = useState<string>();

  useEffect(() => {
    const shared = new URLSearchParams(window.location.hash.slice(1)).get('s');
    const decoded = shared ? decodeState(shared) : undefined;
    if (decoded) {
      setState(decoded);
      setScenarioId('');
    }
  }, []);

  const parsedGrants = useMemo(() => state.grants.map(parseDocument), [state.grants]);
  const parsedBoundaries = useMemo(() => state.boundaries.map(parseDocument), [state.boundaries]);
  const parsedContext = useMemo(() => {
    try {
      const value = JSON.parse(state.context || '{}');
      if (value === null || typeof value !== 'object' || Array.isArray(value))
        return { error: 'Context must be a JSON object of key/value pairs' };
      return { value: value as Record<string, unknown> };
    } catch (error) {
      return { error: `JSON: ${(error as Error).message}` };
    }
  }, [state.context]);

  const invalid =
    parsedGrants.some((doc) => doc.error) ||
    parsedBoundaries.some((doc) => doc.error) ||
    parsedContext.error;
  const result = useMemo(() => {
    if (invalid || !parsedContext.value) return undefined;
    return evaluate(
      parsedGrants.map((doc) => doc.document as PolicyDocument),
      parsedBoundaries.map((doc) => doc.document as PolicyDocument),
      state.action,
      state.resource,
      parsedContext.value,
    );
  }, [invalid, parsedGrants, parsedBoundaries, parsedContext, state.action, state.resource]);

  const update = (patch: Partial<State>) => {
    setState((current) => ({ ...current, ...patch }));
    setScenarioId('');
  };
  const docs = tab === 'grants' ? state.grants : state.boundaries;
  const parsedDocs = tab === 'grants' ? parsedGrants : parsedBoundaries;
  const setDocs = (next: string[]) =>
    update(tab === 'grants' ? { grants: next } : { boundaries: next });

  // A new decision replays the trace, so a highlight from the previous one should not linger.
  const decision = result?.decision;
  const traceKey = decision
    ? `${decision.allowed}:${decision.reason}:${decision.matched.join(',')}`
    : 'none';
  useEffect(() => setHovered(undefined), [traceKey]);
  const hoveredStatement = result?.statements.find((statement) => statement.id === hovered);
  const hoveredTab = hoveredStatement
    ? hoveredStatement.kind === 'grant'
      ? 'grants'
      : 'boundaries'
    : undefined;

  useEffect(() => {
    if (!inserted) return;
    const timer = setTimeout(() => setInserted(undefined), 1200);
    return () => clearTimeout(timer);
  }, [inserted]);

  function share() {
    const url = `${window.location.origin}${window.location.pathname}#s=${encodeState(state)}`;
    window.history.replaceState(null, '', url);
    void navigator.clipboard?.writeText(url);
    setCopied(true);
    setTimeout(() => setCopied(false), 1600);
  }

  function insertKey(key: string, example: unknown) {
    if (!parsedContext.value) return;
    update({
      context: pretty({ ...parsedContext.value, [key]: parsedContext.value[key] ?? example }),
    });
  }

  const summary = scenarios.find((scenario) => scenario.id === scenarioId)?.summary ?? '';

  return (
    <MotionConfig reducedMotion="user">
      <div className="flex flex-col gap-6">
        {/* Scenarios */}
        <div className="flex flex-col gap-3">
          <div className="flex items-center gap-3">
            <span className="eyebrow">Scenarios</span>
            <Button
              variant="secondary"
              size="small"
              leadingIcon={copied ? PopCheck : RiLinkM}
              onClick={share}
              className="ms-auto"
            >
              {copied ? 'Link copied' : 'Share'}
            </Button>
          </div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-6">
            {scenarios.map((scenario, index) => {
              const active = scenarioId === scenario.id;
              return (
                <button
                  key={scenario.id}
                  type="button"
                  onClick={() => {
                    setState(fromScenario(scenario));
                    setScenarioId(scenario.id);
                    setTab('grants');
                  }}
                  className={cx(
                    'button-press-motion group relative isolate flex min-h-[4.75rem] flex-col items-start gap-1.5 rounded-xl border p-3 text-start',
                    active
                      ? 'border-text-primary text-background-full'
                      : 'border-border-button-default bg-surface-raised text-text-primary shadow-xs hover:border-border-button-hover hover:bg-background-primary-hover',
                  )}
                >
                  {active ? (
                    <motion.span
                      layoutId="playground-scenario"
                      aria-hidden
                      className="absolute -inset-px -z-10 rounded-xl bg-text-primary"
                      transition={{ type: 'spring', stiffness: 420, damping: 36 }}
                    />
                  ) : null}
                  <span aria-hidden className="flex w-full items-center">
                    <span
                      className={cx(
                        'font-mono text-caption-2-regular tabular-nums transition-colors duration-200',
                        active
                          ? 'text-background-full/60'
                          : 'text-text-tertiary group-hover:text-text-secondary',
                      )}
                    >
                      0{index + 1}
                    </span>
                    {active ? (
                      <PopCheck className="ms-auto size-3.5" />
                    ) : (
                      <RiArrowRightLine className="ms-auto size-3.5 -translate-x-1 text-foreground-icon-secondary opacity-0 transition-[opacity,translate] duration-200 group-hover:translate-x-0 group-hover:opacity-100" />
                    )}
                  </span>
                  <span className="text-body-2-medium text-pretty">{scenario.title}</span>
                </button>
              );
            })}
          </div>
          <div className="min-h-[1.125rem]">
            <AnimatePresence mode="wait" initial={false}>
              {scenarioId ? (
                <motion.p
                  key={scenarioId}
                  className="text-body-2-regular text-text-secondary"
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -4 }}
                  transition={{ duration: 0.2, ease }}
                >
                  {summary.split(/(`[^`]+`)/).map((part, index) =>
                    part.startsWith('`') ? (
                      <code
                        key={index}
                        className="rounded-md border border-separator-border bg-surface-raised px-1 py-px font-mono text-[0.85em] text-text-primary"
                      >
                        {part.slice(1, -1)}
                      </code>
                    ) : (
                      part
                    ),
                  )}
                </motion.p>
              ) : null}
            </AnimatePresence>
          </div>
        </div>

        <div className="grid gap-6 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
          {/* Policies */}
          <section className={cx(panel, 'lg:self-start')}>
            <div className="flex items-center gap-2 border-b border-separator-border px-3 py-2 sm:px-4">
              <div
                role="tablist"
                className="inline-flex gap-0.5 rounded-2lg bg-segmented-control-background p-1"
              >
                {(['grants', 'boundaries'] as const).map((value) => {
                  const selected = tab === value;
                  return (
                    <button
                      key={value}
                      role="tab"
                      type="button"
                      aria-selected={selected}
                      onClick={() => setTab(value)}
                      className={cx(
                        'relative isolate inline-flex h-7 items-center rounded-md px-2.5 capitalize transition-[color,box-shadow] duration-200',
                        selected
                          ? 'text-body-2-medium text-text-primary'
                          : 'text-body-2-regular text-text-secondary hover:text-text-primary',
                        // The hovered trace statement lives in this other tab.
                        !selected &&
                          hoveredTab === value &&
                          'text-text-primary ring-1 ring-text-primary',
                      )}
                    >
                      {selected ? (
                        <motion.span
                          layoutId="playground-tab"
                          aria-hidden
                          className="absolute inset-0 -z-10 rounded-md bg-segmented-control-selected-background shadow-2xs"
                          transition={{ type: 'spring', stiffness: 500, damping: 38 }}
                        />
                      ) : null}
                      {value}
                      <span
                        className={cx(
                          'ms-1.5 inline-flex min-w-4 justify-center rounded-full px-1 font-mono text-caption-2-medium tabular-nums transition-colors duration-200',
                          selected
                            ? 'bg-text-primary text-background-full'
                            : 'bg-background-tertiary-default text-text-secondary',
                        )}
                      >
                        {(value === 'grants' ? state.grants : state.boundaries).length}
                      </span>
                    </button>
                  );
                })}
              </div>
              <Button
                variant="ghost"
                size="small"
                leadingIcon={RiAddLine}
                onClick={() => setDocs([...docs, emptyGrant])}
                className="ms-auto bg-transparent text-text-secondary hover:text-text-primary [&_svg]:transition-transform [&_svg]:duration-300 hover:[&_svg]:rotate-90"
              >
                Document
              </Button>
            </div>
            <div className="flex flex-col gap-5 p-4 sm:p-5">
              <motion.p
                key={tab}
                className="text-caption-1-regular leading-5 text-text-secondary"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.25 }}
              >
                {tab === 'grants'
                  ? 'Grant documents come from the roles and policies bound to the principal. Their allows form a union.'
                  : 'Boundaries (tenant, principal, session, or credential ceilings) each intersect: every one must allow the request.'}
              </motion.p>
              {docs.length === 0 ? (
                <div className="rounded-xl border border-dashed border-border-button-hover p-6 text-center text-body-2-regular text-text-secondary">
                  No {tab}.{' '}
                  {tab === 'boundaries'
                    ? 'Without boundaries, grants decide alone.'
                    : 'Nothing is allowed.'}
                </div>
              ) : null}
              {docs.map((text, index) => {
                const error = parsedDocs[index]?.error;
                const mark =
                  hoveredStatement && hoveredTab === tab && hoveredStatement.document === index
                    ? statementRange(text, hoveredStatement.index)
                    : undefined;
                return (
                  <motion.div
                    key={`${tab}-${index}`}
                    className="flex flex-col gap-2"
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.35, ease, delay: Math.min(index, 4) * 0.05 }}
                  >
                    <div className="flex items-center gap-2 text-caption-1-regular">
                      <span
                        className={cx(
                          'shrink-0 rounded-md px-1.5 py-0.5 font-mono text-caption-2-medium transition-colors duration-200',
                          mark
                            ? 'bg-text-primary text-background-full'
                            : 'bg-background-secondary-default text-text-secondary',
                        )}
                      >
                        {tab === 'grants' ? 'grant' : 'boundary'}:{index}
                      </span>
                      {error ? (
                        <span className="flex min-w-0 items-center gap-1 text-text-primary">
                          <RiErrorWarningLine className="size-3.5 shrink-0" aria-hidden />
                          <span className="truncate">{error}</span>
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-text-secondary">
                          <RiCheckLine className="size-3.5" aria-hidden /> valid
                        </span>
                      )}
                      <Button
                        variant="ghost"
                        size="xs"
                        iconOnly
                        leadingIcon={RiSubtractLine}
                        aria-label="Remove document"
                        onClick={() => setDocs(docs.filter((_, position) => position !== index))}
                        className="ms-auto shrink-0 bg-transparent text-text-secondary hover:text-text-primary"
                      />
                    </div>
                    <JsonEditor
                      label={`${tab} document ${index}`}
                      value={text}
                      invalid={Boolean(error)}
                      mark={mark}
                      onChange={(value) =>
                        setDocs(
                          docs.map((current, position) => (position === index ? value : current)),
                        )
                      }
                      minRows={8}
                    />
                    <ConditionBuilder
                      documentText={text}
                      onChange={(value) =>
                        setDocs(
                          docs.map((current, position) => (position === index ? value : current)),
                        )
                      }
                    />
                  </motion.div>
                );
              })}
            </div>
          </section>

          {/* Request and decision */}
          <section className="flex min-w-0 flex-col gap-4">
            <div className={panel}>
              <div className={panelHeader}>
                <h2 className="text-body-semibold">Request</h2>
              </div>
              <div className="flex flex-col gap-3 p-4 sm:p-5">
                <div className="grid gap-3 sm:grid-cols-2">
                  <label className="flex flex-col gap-1.5 text-caption-1-medium text-text-secondary">
                    Action
                    <input
                      value={state.action}
                      onChange={(event) => update({ action: event.target.value })}
                      className={input}
                    />
                  </label>
                  <label className="flex flex-col gap-1.5 text-caption-1-medium text-text-secondary">
                    Resource <span className="sr-only">(type/id)</span>
                    <input
                      value={state.resource}
                      onChange={(event) => update({ resource: event.target.value })}
                      className={input}
                    />
                  </label>
                </div>
                <div className="flex items-center gap-2 text-caption-1-medium text-text-secondary">
                  <span>Context</span>
                  {parsedContext.error ? (
                    <span className="flex min-w-0 items-center gap-1 text-caption-1-regular text-text-primary">
                      <RiErrorWarningLine className="size-3.5 shrink-0" aria-hidden />
                      <span className="truncate">{parsedContext.error}</span>
                    </span>
                  ) : null}
                </div>
                <JsonEditor
                  label="Evaluation context"
                  value={state.context}
                  invalid={Boolean(parsedContext.error)}
                  onChange={(value) => update({ context: value })}
                  minRows={5}
                />
                <details className="group text-caption-1-regular">
                  <summary className="flex w-fit cursor-pointer list-none items-center gap-1 text-caption-1-medium text-text-secondary transition-colors select-none hover:text-text-primary [&::-webkit-details-marker]:hidden">
                    <RiArrowRightSLine
                      className="size-4 transition-transform duration-200 group-open:rotate-90"
                      aria-hidden
                    />
                    Keys the server provides
                  </summary>
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {contextKeys.map((entry) => (
                      <button
                        key={entry.key}
                        type="button"
                        title={entry.note}
                        onClick={() => {
                          insertKey(entry.key, entry.example);
                          if (parsedContext.value) setInserted(entry.key);
                        }}
                        className={cx(
                          'button-press-motion inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-caption-2-regular',
                          inserted === entry.key
                            ? 'border-text-primary bg-text-primary text-background-full'
                            : 'border-border-button-default bg-background-primary-default text-text-secondary hover:border-border-button-hover hover:text-text-primary',
                        )}
                      >
                        {inserted === entry.key ? <PopCheck className="size-3" /> : null}
                        {entry.key}
                      </button>
                    ))}
                  </div>
                </details>
              </div>
            </div>

            <div className="relative">
              <Decision result={result} blocked={Boolean(invalid)} onHover={setHovered} />
            </div>
            <AnimatePresence initial={false}>
              {result?.statements.length ? (
                <Trace
                  key="trace"
                  statements={result.statements}
                  traceKey={traceKey}
                  hovered={hovered}
                  onHover={setHovered}
                />
              ) : null}
            </AnimatePresence>
            <Button
              variant="ghost"
              size="small"
              leadingIcon={RiRestartLine}
              onClick={() => {
                setState(fromScenario(scenarios[0]!));
                setScenarioId(scenarios[0]!.id);
                window.history.replaceState(null, '', window.location.pathname);
              }}
              className="self-start bg-transparent text-text-secondary hover:text-text-primary [&_svg]:transition-transform [&_svg]:duration-500 hover:[&_svg]:-rotate-180"
            >
              Reset
            </Button>
          </section>
        </div>
      </div>
    </MotionConfig>
  );
}

const fade = {
  initial: { opacity: 0, y: 6 },
  animate: { opacity: 1, y: 0 },
  exit: { opacity: 0, transition: { duration: 0.12 } },
  transition: { duration: 0.3, ease },
};

function Decision({
  result,
  blocked,
  onHover,
}: {
  result?: ReturnType<typeof evaluate>;
  blocked: boolean;
  onHover: (id?: string) => void;
}) {
  const decision = !blocked && result && !result.error ? result.decision : undefined;
  const allowed = Boolean(decision?.allowed);
  const info = decision
    ? (reasons[decision.reason] ?? { title: decision.reason, text: '' })
    : undefined;
  return (
    <AnimatePresence mode="popLayout" initial={false}>
      {blocked || !result ? (
        <motion.div
          key="blocked"
          {...fade}
          className="rounded-2xl border border-dashed border-border-button-hover p-5 text-body-regular text-text-secondary"
        >
          Fix the highlighted input to evaluate. The validator is the same one the server runs
          before storing a policy.
        </motion.div>
      ) : result.error ? (
        <motion.div
          key="error"
          {...fade}
          className="hatch flex items-start gap-3 rounded-2xl border border-text-primary bg-surface-raised p-5 text-body-regular text-text-primary"
        >
          <RiErrorWarningLine className="mt-0.5 size-5 shrink-0" aria-hidden />
          {result.error}
        </motion.div>
      ) : decision && info ? (
        <motion.div
          key="decision"
          {...fade}
          aria-live="polite"
          className={cx(
            'relative overflow-hidden rounded-2xl border border-text-primary p-5 shadow-sm transition-[background-color,color] duration-300',
            allowed
              ? 'bg-text-primary text-background-full'
              : 'bg-surface-raised text-text-primary',
          )}
        >
          {/* Denied is hatched; the hatching fades in and out as the decision flips. */}
          <AnimatePresence initial={false}>
            {allowed ? null : (
              <motion.span
                key="hatch"
                aria-hidden
                className="hatch pointer-events-none absolute inset-0"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.3 }}
              />
            )}
          </AnimatePresence>
          <div className="relative flex items-center gap-3">
            <span
              className={cx(
                'flex size-11 shrink-0 items-center justify-center rounded-xl border transition-colors duration-300',
                allowed
                  ? 'border-background-full/25 bg-background-full/10'
                  : 'border-text-primary bg-surface-raised',
              )}
            >
              <AnimatePresence mode="wait" initial={false}>
                <motion.span
                  key={allowed ? 'allowed' : 'denied'}
                  className="flex"
                  initial={{ scale: 0.4, rotate: -35, opacity: 0 }}
                  animate={{ scale: 1, rotate: 0, opacity: 1 }}
                  exit={{ scale: 0.4, rotate: 35, opacity: 0 }}
                  transition={{ type: 'spring', stiffness: 520, damping: 26 }}
                >
                  {allowed ? (
                    <RiShieldCheckLine className="size-6" aria-hidden />
                  ) : (
                    <RiShieldCrossLine className="size-6" aria-hidden />
                  )}
                </motion.span>
              </AnimatePresence>
            </span>
            <div className="flex min-w-0 flex-col">
              <AnimatePresence mode="wait" initial={false}>
                <motion.span
                  key={allowed ? 'allowed' : 'denied'}
                  className="text-title-2-semibold tracking-[-0.015em]"
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -8 }}
                  transition={{ duration: 0.18, ease }}
                >
                  {allowed ? 'Allowed' : 'Denied'}
                </motion.span>
              </AnimatePresence>
              <span
                className={cx(
                  'font-mono text-caption-1-regular transition-colors duration-300',
                  allowed ? 'text-background-full/70' : 'text-text-secondary',
                )}
              >
                reason: {decision.reason}
              </span>
            </div>
            <CopyDecision decision={decision} inverted={allowed} />
          </div>
          <p
            className={cx(
              'relative mt-4 text-body-regular leading-6 transition-colors duration-300',
              allowed ? 'text-background-full/75' : 'text-text-secondary',
            )}
          >
            <span
              className={cx(
                'text-body-medium',
                allowed ? 'text-background-full' : 'text-text-primary',
              )}
            >
              {info.title}.
            </span>{' '}
            {info.text}
          </p>
          {decision.matched.length ? (
            <div className="relative mt-4 flex flex-wrap gap-1.5">
              {decision.matched.map((id) => (
                <code
                  key={id}
                  onMouseEnter={() => onHover(id)}
                  onMouseLeave={() => onHover(undefined)}
                  className={cx(
                    'cursor-default rounded-md border px-1.5 py-0.5 font-mono text-caption-1-regular transition-colors duration-200',
                    allowed
                      ? 'border-background-full/25 bg-background-full/10 hover:bg-background-full/20'
                      : 'border-border-button-default bg-surface-raised hover:border-text-primary',
                  )}
                >
                  {id}
                </code>
              ))}
            </div>
          ) : null}
        </motion.div>
      ) : null}
    </AnimatePresence>
  );
}

function CopyDecision({ decision, inverted }: { decision: unknown; inverted: boolean }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      aria-label="Copy decision JSON"
      onClick={() => {
        void navigator.clipboard?.writeText(JSON.stringify(decision, null, 2));
        setCopied(true);
        setTimeout(() => setCopied(false), 1400);
      }}
      className={cx(
        'button-press-motion ms-auto flex size-8 shrink-0 items-center justify-center self-start rounded-lg border',
        inverted
          ? 'border-background-full/25 text-background-full/80 hover:bg-background-full/10 hover:text-background-full'
          : 'border-border-button-default bg-surface-raised text-foreground-icon-secondary shadow-xs hover:border-border-button-hover hover:text-text-primary',
      )}
    >
      <AnimatePresence mode="wait" initial={false}>
        {copied ? (
          <PopCheck key="copied" className="size-4" />
        ) : (
          <motion.span
            key="copy"
            className="flex"
            initial={{ scale: 0.4, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.4, opacity: 0 }}
            transition={{ duration: 0.15 }}
          >
            <RiFileCopyLine className="size-4" aria-hidden />
          </motion.span>
        )}
      </AnimatePresence>
    </button>
  );
}

function Pill({ ok, children }: { ok: boolean; children: ReactNode }) {
  return (
    <span
      className={cx(
        'inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-caption-2-medium',
        ok
          ? 'border-border-button-default bg-background-secondary-default text-text-primary'
          : 'hatch border-dashed border-text-primary text-text-secondary',
      )}
    >
      {ok ? (
        <RiCheckLine className="size-3" aria-hidden />
      ) : (
        <RiCloseLine className="size-3" aria-hidden />
      )}
      {children}
    </span>
  );
}

function show(value: unknown) {
  return value === undefined ? 'missing' : JSON.stringify(value);
}

/** A statement's outcome: ink check when an allow matched, hatched cross when a deny matched, dashed when neither. */
function StatementMark({ statement }: { statement: StatementTrace }) {
  if (!statement.matched)
    return (
      <span className="size-5 shrink-0 rounded-full border border-dashed border-border-button-hover" />
    );
  const deny = statement.effect === 'deny';
  return (
    <motion.span
      className={cx(
        'flex size-5 shrink-0 items-center justify-center rounded-full',
        deny
          ? 'hatch border border-text-primary text-text-primary'
          : 'bg-text-primary text-background-full',
      )}
      initial={{ scale: 0 }}
      animate={{ scale: 1 }}
      transition={{ type: 'spring', stiffness: 520, damping: 22, delay: 0.15 }}
    >
      {deny ? (
        <RiCloseLine className="size-3.5" aria-hidden />
      ) : (
        <RiCheckLine className="size-3.5" aria-hidden />
      )}
    </motion.span>
  );
}

function Trace({
  statements,
  traceKey,
  hovered,
  onHover,
}: {
  statements: StatementTrace[];
  traceKey: string;
  hovered?: string;
  onHover: (id?: string) => void;
}) {
  const scrollerRef = useRef<HTMLDivElement>(null);
  const overflowing = useOverflowing(scrollerRef);
  return (
    <motion.div
      className={panel}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, transition: { duration: 0.12 } }}
      transition={{ duration: 0.3, ease }}
    >
      <div className={panelHeader}>
        <h2 className="text-body-semibold">Statement trace</h2>
        <span
          aria-hidden
          className="ms-auto hidden text-caption-1-regular text-text-tertiary lg:inline"
        >
          Hover a statement to find it in the editor
        </span>
      </div>
      <div
        ref={scrollerRef}
        data-lenis-prevent={overflowing ? '' : undefined}
        className="lg:max-h-[min(72vh,44rem)] lg:overflow-y-auto"
      >
        <motion.ol
          key={traceKey}
          className="flex flex-col gap-2 p-3 sm:p-4"
          initial="hidden"
          animate="shown"
          variants={{ shown: { transition: { staggerChildren: 0.06 } } }}
        >
          {statements.map((statement) => {
            const active = hovered === statement.id;
            return (
              <motion.li
                key={statement.id}
                variants={{
                  hidden: { opacity: 0, y: 8 },
                  shown: { opacity: 1, y: 0, transition: { duration: 0.35, ease } },
                }}
                onMouseEnter={() => onHover(statement.id)}
                onMouseLeave={() => onHover(undefined)}
                className={cx(
                  'rounded-xl border p-3 transition-[border-color,background-color,box-shadow] duration-200',
                  statement.matched || active
                    ? 'border-text-primary'
                    : 'border-border-button-default',
                  active
                    ? 'bg-background-primary-hover shadow-xs ring-1 ring-text-primary'
                    : 'bg-background-primary-default',
                )}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <StatementMark statement={statement} />
                  <code className="font-mono text-caption-1-medium">{statement.id}</code>
                  <span
                    className={cx(
                      'rounded-full border border-text-primary px-2 font-mono text-caption-2-medium uppercase',
                      statement.effect === 'deny'
                        ? 'hatch text-text-primary'
                        : 'bg-text-primary text-background-full',
                    )}
                  >
                    {statement.effect}
                  </span>
                  <span className="ms-auto text-caption-1-regular text-text-secondary">
                    {statement.matched ? 'matched' : 'did not match'}
                  </span>
                </div>
                <div className="mt-2.5 flex flex-wrap gap-1.5">
                  <Pill ok={statement.actionMatched}>action</Pill>
                  <Pill ok={statement.resourceMatched}>resource</Pill>
                  {statement.conditions.length === 0 ? <Pill ok>no conditions</Pill> : null}
                </div>
                {statement.conditions.length ? (
                  <ul className="mt-2.5 flex flex-col gap-1.5 border-t border-separator-border pt-2.5">
                    {statement.conditions.map((condition) => (
                      <li
                        key={`${condition.operator}:${condition.key}`}
                        className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 font-mono text-caption-1-regular"
                      >
                        <span
                          className={cx(
                            'flex size-3.5 shrink-0 items-center justify-center self-center rounded-full',
                            condition.passed
                              ? 'bg-text-primary text-background-full'
                              : 'hatch border border-text-primary text-text-primary',
                          )}
                        >
                          {condition.passed ? (
                            <RiCheckLine className="size-2.5" aria-hidden />
                          ) : (
                            <RiCloseLine className="size-2.5" aria-hidden />
                          )}
                        </span>
                        <span className="font-semibold text-text-primary">
                          {condition.operator}
                        </span>
                        <span className="text-text-primary">{condition.key}</span>
                        <span className="text-text-secondary">
                          expects {show(condition.expected)}
                        </span>
                        <span className="text-text-secondary">
                          got{' '}
                          <span
                            className={
                              condition.present
                                ? 'text-text-primary'
                                : 'hatch rounded-sm border border-dashed border-text-tertiary px-1 text-text-primary'
                            }
                          >
                            {show(condition.actual)}
                          </span>
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : null}
              </motion.li>
            );
          })}
        </motion.ol>
      </div>
    </motion.div>
  );
}
