'use client';

import { useEffect, useMemo, useState, type ReactNode } from 'react';
import {
  Check,
  CircleCheck,
  CircleX,
  Copy,
  Link2,
  Minus,
  Plus,
  RotateCcw,
  ShieldCheck,
  ShieldX,
  X,
} from 'lucide-react';
import type { PolicyDocument } from '@better-iam/core';
import { cn } from '@/lib/cn';
import { ConditionBuilder } from './condition-builder';
import { JsonEditor } from './json-editor';
import { contextKeys, scenarios, type Scenario } from './presets';
import { evaluate, parseDocument, reasons, type StatementTrace } from './trace';

interface State {
  grants: string[];
  boundaries: string[];
  action: string;
  resource: string;
  context: string;
}

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

const emptyGrant = pretty({
  version: 1,
  statements: [
    { sid: 'New', effect: 'allow', actions: ['documents:read'], resources: ['document/*'] },
  ],
});

export function PolicyPlayground() {
  const [scenarioId, setScenarioId] = useState(scenarios[0]!.id);
  const [state, setState] = useState<State>(() => fromScenario(scenarios[0]!));
  const [tab, setTab] = useState<'grants' | 'boundaries'>('grants');
  const [copied, setCopied] = useState(false);

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

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center gap-2">
        {scenarios.map((scenario) => (
          <button
            key={scenario.id}
            type="button"
            onClick={() => {
              setState(fromScenario(scenario));
              setScenarioId(scenario.id);
              setTab('grants');
            }}
            className={cn(
              'rounded-full border px-3 py-1 text-sm transition-colors',
              scenarioId === scenario.id
                ? 'border-fd-primary/50 bg-fd-primary/10 text-fd-primary'
                : 'bg-fd-card text-fd-muted-foreground hover:text-fd-foreground',
            )}
          >
            {scenario.title}
          </button>
        ))}
        <button
          type="button"
          onClick={share}
          className="ms-auto inline-flex items-center gap-1.5 rounded-lg border bg-fd-card px-3 py-1.5 text-sm transition-colors hover:bg-fd-accent"
        >
          {copied ? <Check className="size-4 text-fd-primary" /> : <Link2 className="size-4" />}
          {copied ? 'Link copied' : 'Share'}
        </button>
      </div>
      {scenarioId ? (
        <p className="-mt-3 text-sm text-fd-muted-foreground">
          {(scenarios.find((scenario) => scenario.id === scenarioId)?.summary ?? '')
            .split(/(`[^`]+`)/)
            .map((part, index) =>
              part.startsWith('`') ? (
                <code
                  key={index}
                  className="rounded bg-fd-muted px-1 font-mono text-[0.8em] text-fd-foreground"
                >
                  {part.slice(1, -1)}
                </code>
              ) : (
                part
              ),
            )}
        </p>
      ) : null}

      <div className="grid gap-6 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)]">
        {/* Policies */}
        <section className="flex min-w-0 flex-col gap-3 rounded-2xl border bg-fd-card p-4">
          <div className="flex items-center gap-2">
            <div
              role="tablist"
              className="inline-flex rounded-lg border bg-fd-background p-0.5 text-sm"
            >
              {(['grants', 'boundaries'] as const).map((value) => (
                <button
                  key={value}
                  role="tab"
                  type="button"
                  aria-selected={tab === value}
                  onClick={() => setTab(value)}
                  className={cn(
                    'rounded-md px-3 py-1 capitalize transition-colors',
                    tab === value
                      ? 'bg-fd-primary text-fd-primary-foreground'
                      : 'text-fd-muted-foreground hover:text-fd-foreground',
                  )}
                >
                  {value}
                  <span className="ms-1.5 font-mono text-xs opacity-70">
                    {(value === 'grants' ? state.grants : state.boundaries).length}
                  </span>
                </button>
              ))}
            </div>
            <button
              type="button"
              onClick={() => setDocs([...docs, emptyGrant])}
              className="ms-auto inline-flex items-center gap-1 rounded-lg px-2 py-1 text-sm text-fd-muted-foreground transition-colors hover:bg-fd-accent hover:text-fd-foreground"
            >
              <Plus className="size-4" /> Document
            </button>
          </div>
          <p className="text-xs text-fd-muted-foreground">
            {tab === 'grants'
              ? 'Grant documents come from the roles and policies bound to the principal. Their allows form a union.'
              : 'Boundaries (tenant, principal, session, or credential ceilings) each intersect: every one must allow the request.'}
          </p>
          {docs.length === 0 ? (
            <div className="rounded-lg border border-dashed p-6 text-center text-sm text-fd-muted-foreground">
              No {tab}.{' '}
              {tab === 'boundaries'
                ? 'Without boundaries, grants decide alone.'
                : 'Nothing is allowed.'}
            </div>
          ) : null}
          {docs.map((text, index) => (
            <div key={`${tab}-${index}`} className="flex flex-col gap-1.5">
              <div className="flex items-center gap-2 text-xs">
                <span className="font-mono text-fd-muted-foreground">
                  {tab === 'grants' ? 'grant' : 'boundary'}:{index}
                </span>
                {parsedDocs[index]?.error ? (
                  <span className="truncate text-red-600 dark:text-red-400">
                    {parsedDocs[index]?.error}
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 text-fd-primary">
                    <Check className="size-3" /> valid
                  </span>
                )}
                <button
                  type="button"
                  aria-label="Remove document"
                  onClick={() => setDocs(docs.filter((_, position) => position !== index))}
                  className="ms-auto rounded p-1 text-fd-muted-foreground hover:bg-fd-accent hover:text-fd-foreground"
                >
                  <Minus className="size-3.5" />
                </button>
              </div>
              <JsonEditor
                label={`${tab} document ${index}`}
                value={text}
                invalid={Boolean(parsedDocs[index]?.error)}
                onChange={(value) =>
                  setDocs(docs.map((current, position) => (position === index ? value : current)))
                }
                minRows={8}
              />
              <ConditionBuilder
                documentText={text}
                onChange={(value) =>
                  setDocs(docs.map((current, position) => (position === index ? value : current)))
                }
              />
            </div>
          ))}
        </section>

        {/* Request and decision */}
        <section className="flex min-w-0 flex-col gap-4">
          <div className="flex flex-col gap-3 rounded-2xl border bg-fd-card p-4">
            <h2 className="text-sm font-semibold">Request</h2>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="flex flex-col gap-1 text-xs text-fd-muted-foreground">
                Action
                <input
                  value={state.action}
                  onChange={(event) => update({ action: event.target.value })}
                  className="rounded-lg border bg-fd-background px-3 py-2 font-mono text-sm text-fd-foreground outline-none focus:border-fd-primary/60 focus:ring-2 focus:ring-fd-primary/15"
                />
              </label>
              <label className="flex flex-col gap-1 text-xs text-fd-muted-foreground">
                Resource <span className="sr-only">(type/id)</span>
                <input
                  value={state.resource}
                  onChange={(event) => update({ resource: event.target.value })}
                  className="rounded-lg border bg-fd-background px-3 py-2 font-mono text-sm text-fd-foreground outline-none focus:border-fd-primary/60 focus:ring-2 focus:ring-fd-primary/15"
                />
              </label>
            </div>
            <div className="flex items-center gap-2 text-xs text-fd-muted-foreground">
              <span>Context</span>
              {parsedContext.error ? (
                <span className="truncate text-red-600 dark:text-red-400">
                  {parsedContext.error}
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
            <details className="group text-xs">
              <summary className="cursor-pointer select-none text-fd-muted-foreground hover:text-fd-foreground">
                Keys the server provides
              </summary>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {contextKeys.map((entry) => (
                  <button
                    key={entry.key}
                    type="button"
                    title={entry.note}
                    onClick={() => insertKey(entry.key, entry.example)}
                    className="rounded-md border bg-fd-background px-1.5 py-0.5 font-mono text-[0.7rem] text-fd-muted-foreground transition-colors hover:border-fd-primary/40 hover:text-fd-foreground"
                  >
                    {entry.key}
                  </button>
                ))}
              </div>
            </details>
          </div>

          <Decision result={result} blocked={Boolean(invalid)} />
          {result?.statements.length ? <Trace statements={result.statements} /> : null}
          <button
            type="button"
            onClick={() => {
              setState(fromScenario(scenarios[0]!));
              setScenarioId(scenarios[0]!.id);
              window.history.replaceState(null, '', window.location.pathname);
            }}
            className="inline-flex items-center gap-1.5 self-start text-xs text-fd-muted-foreground hover:text-fd-foreground"
          >
            <RotateCcw className="size-3.5" /> Reset
          </button>
        </section>
      </div>
    </div>
  );
}

function Decision({ result, blocked }: { result?: ReturnType<typeof evaluate>; blocked: boolean }) {
  if (blocked || !result)
    return (
      <div className="rounded-2xl border border-dashed p-5 text-sm text-fd-muted-foreground">
        Fix the highlighted input to evaluate. The validator is the same one the server runs before
        storing a policy.
      </div>
    );
  if (result.error)
    return (
      <div className="rounded-2xl border border-red-500/40 bg-red-500/5 p-5 text-sm text-red-700 dark:text-red-300">
        {result.error}
      </div>
    );
  const decision = result.decision!;
  const info = reasons[decision.reason] ?? { title: decision.reason, text: '' };
  return (
    <div
      aria-live="polite"
      className={cn(
        'relative overflow-hidden rounded-2xl border p-5',
        decision.allowed
          ? 'border-emerald-500/40 bg-emerald-500/[0.06]'
          : 'border-red-500/40 bg-red-500/[0.06]',
      )}
    >
      <div className="flex items-center gap-3">
        {decision.allowed ? (
          <ShieldCheck className="size-8 text-emerald-600 dark:text-emerald-400" />
        ) : (
          <ShieldX className="size-8 text-red-600 dark:text-red-400" />
        )}
        <div className="flex flex-col">
          <span
            className={cn(
              'text-lg font-semibold',
              decision.allowed
                ? 'text-emerald-700 dark:text-emerald-300'
                : 'text-red-700 dark:text-red-300',
            )}
          >
            {decision.allowed ? 'Allowed' : 'Denied'}
          </span>
          <span className="font-mono text-xs text-fd-muted-foreground">
            reason: {decision.reason}
          </span>
        </div>
        <CopyDecision decision={decision} />
      </div>
      <p className="mt-3 text-sm text-fd-muted-foreground">
        <span className="font-medium text-fd-foreground">{info.title}.</span> {info.text}
      </p>
      {decision.matched.length ? (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {decision.matched.map((id) => (
            <code
              key={id}
              className="rounded-md border bg-fd-background px-1.5 py-0.5 font-mono text-xs"
            >
              {id}
            </code>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function CopyDecision({ decision }: { decision: unknown }) {
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
      className="ms-auto rounded-md p-1.5 text-fd-muted-foreground hover:bg-fd-accent hover:text-fd-foreground"
    >
      {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
    </button>
  );
}

function Pill({ ok, children }: { ok: boolean; children: ReactNode }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[0.7rem] font-medium',
        ok
          ? 'bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
          : 'bg-fd-muted text-fd-muted-foreground',
      )}
    >
      {ok ? <Check className="size-3" /> : <X className="size-3" />}
      {children}
    </span>
  );
}

function show(value: unknown) {
  return value === undefined ? 'missing' : JSON.stringify(value);
}

function Trace({ statements }: { statements: StatementTrace[] }) {
  return (
    <div className="flex flex-col gap-2 rounded-2xl border bg-fd-card p-4">
      <h2 className="text-sm font-semibold">Statement trace</h2>
      <ol className="flex flex-col gap-2">
        {statements.map((statement) => (
          <li
            key={statement.id}
            className={cn(
              'rounded-lg border bg-fd-background p-3',
              statement.matched &&
                (statement.effect === 'deny' ? 'border-red-500/40' : 'border-emerald-500/40'),
            )}
          >
            <div className="flex flex-wrap items-center gap-2">
              {statement.matched ? (
                statement.effect === 'deny' ? (
                  <CircleX className="size-4 text-red-600 dark:text-red-400" />
                ) : (
                  <CircleCheck className="size-4 text-emerald-600 dark:text-emerald-400" />
                )
              ) : (
                <span className="size-4 rounded-full border-2 border-fd-border" />
              )}
              <code className="font-mono text-xs">{statement.id}</code>
              <span
                className={cn(
                  'rounded px-1.5 py-0.5 font-mono text-[0.65rem] uppercase',
                  statement.effect === 'deny'
                    ? 'bg-red-500/10 text-red-700 dark:text-red-300'
                    : 'bg-fd-primary/10 text-fd-primary',
                )}
              >
                {statement.effect}
              </span>
              <span className="ms-auto text-xs text-fd-muted-foreground">
                {statement.matched ? 'matched' : 'did not match'}
              </span>
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              <Pill ok={statement.actionMatched}>action</Pill>
              <Pill ok={statement.resourceMatched}>resource</Pill>
              {statement.conditions.length === 0 ? <Pill ok>no conditions</Pill> : null}
            </div>
            {statement.conditions.length ? (
              <ul className="mt-2 flex flex-col gap-1">
                {statement.conditions.map((condition) => (
                  <li
                    key={`${condition.operator}:${condition.key}`}
                    className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 font-mono text-[0.72rem]"
                  >
                    {condition.passed ? (
                      <Check className="size-3 shrink-0 self-center text-emerald-600 dark:text-emerald-400" />
                    ) : (
                      <X className="size-3 shrink-0 self-center text-red-600 dark:text-red-400" />
                    )}
                    <span className="text-fd-primary">{condition.operator}</span>
                    <span>{condition.key}</span>
                    <span className="text-fd-muted-foreground">
                      expects {show(condition.expected)}
                    </span>
                    <span className="text-fd-muted-foreground">
                      got{' '}
                      <span
                        className={
                          condition.present
                            ? 'text-fd-foreground'
                            : 'text-amber-600 dark:text-amber-400'
                        }
                      >
                        {show(condition.actual)}
                      </span>
                    </span>
                  </li>
                ))}
              </ul>
            ) : null}
          </li>
        ))}
      </ol>
    </div>
  );
}
