'use client';

import { useId, useMemo, useState } from 'react';
import { Plus } from 'lucide-react';
import { contextKeys } from './presets';

/** Every condition operator of `@better-iam/core`, with the value type it compares and a plain-English meaning. */
const operators: {
  name: string;
  kind: 'string' | 'number' | 'boolean' | 'date' | 'ip' | 'array';
  meaning: string;
}[] = [
  { name: 'StringEquals', kind: 'string', meaning: 'is exactly one of these texts' },
  { name: 'StringNotEquals', kind: 'string', meaning: 'is a text, and none of these' },
  {
    name: 'StringEqualsIgnoreCase',
    kind: 'string',
    meaning: 'is one of these texts, ignoring case',
  },
  {
    name: 'StringNotEqualsIgnoreCase',
    kind: 'string',
    meaning: 'is a text, none of these, ignoring case',
  },
  { name: 'StringLike', kind: 'string', meaning: 'matches one of these * / ? patterns' },
  { name: 'StringNotLike', kind: 'string', meaning: 'is a text matching none of these patterns' },
  { name: 'StringLikeIgnoreCase', kind: 'string', meaning: 'matches a pattern, ignoring case' },
  { name: 'Bool', kind: 'boolean', meaning: 'is true (or false)' },
  { name: 'NumericEquals', kind: 'number', meaning: 'is one of these numbers' },
  { name: 'NumericNotEquals', kind: 'number', meaning: 'is a number, and none of these' },
  { name: 'NumericLessThan', kind: 'number', meaning: 'is below this number' },
  { name: 'NumericLessThanEquals', kind: 'number', meaning: 'is at most this number' },
  { name: 'NumericGreaterThan', kind: 'number', meaning: 'is above this number' },
  { name: 'NumericGreaterThanEquals', kind: 'number', meaning: 'is at least this number' },
  { name: 'DateBefore', kind: 'date', meaning: 'is a moment before this one' },
  { name: 'DateAfter', kind: 'date', meaning: 'is a moment after this one' },
  { name: 'IpAddress', kind: 'ip', meaning: 'is an IP address inside this network' },
  { name: 'NotIpAddress', kind: 'ip', meaning: 'is an IP address outside this network' },
  { name: 'ArrayContains', kind: 'array', meaning: 'is a list containing this value' },
  { name: 'ArrayContainsAll', kind: 'array', meaning: 'is a list containing all of these' },
  { name: 'Exists', kind: 'boolean', meaning: 'is present (true) or absent (false)' },
];

const placeholders: Record<string, string> = {
  string: 'finance',
  number: '10000',
  boolean: 'true',
  date: '2026-12-31T23:59:59Z',
  ip: '10.0.0.0/8',
  array: 'grp_oncall',
};

/** Parses what the reader typed into the JSON value the operator expects. */
function parseValue(kind: string, raw: string): unknown {
  const text = raw.trim();
  if (kind === 'number') return Number(text);
  if (kind === 'boolean') return text !== 'false';
  return text;
}

/**
 * Adds a condition to a statement of one policy document without hand-editing JSON. It rewrites the document text,
 * so the result stays visible (and editable) in the editor above.
 */
export function ConditionBuilder({
  documentText,
  onChange,
}: {
  documentText: string;
  onChange: (next: string) => void;
}) {
  const statements = useMemo(() => {
    try {
      const document = JSON.parse(documentText) as { statements?: { sid?: string }[] };
      return (document.statements ?? []).map((statement, index) => statement.sid ?? `#${index}`);
    } catch {
      return undefined;
    }
  }, [documentText]);
  const listId = useId();
  const [statement, setStatement] = useState(0);
  const [operator, setOperator] = useState('StringEquals');
  const [key, setKey] = useState('principal.id');
  const [value, setValue] = useState('');
  const kind = operators.find((entry) => entry.name === operator)?.kind ?? 'string';

  if (!statements?.length) return null;

  function add() {
    try {
      const document = JSON.parse(documentText) as {
        statements: { conditions?: Record<string, Record<string, unknown>> }[];
      };
      const target = document.statements[Math.min(statement, document.statements.length - 1)]!;
      target.conditions ??= {};
      target.conditions[operator] ??= {};
      target.conditions[operator]![key] = parseValue(kind, value || placeholders[kind]!);
      onChange(JSON.stringify(document, null, 2));
      setValue('');
    } catch {
      // The editor shows the JSON error; nothing to add to an invalid document.
    }
  }

  const field =
    'min-w-0 rounded-lg border bg-fd-background px-2 py-1.5 font-mono text-xs text-fd-foreground outline-none focus:border-fd-primary/60';
  return (
    <details className="rounded-lg border bg-fd-background text-xs">
      <summary className="cursor-pointer select-none px-3 py-2 text-fd-muted-foreground hover:text-fd-foreground">
        Add a condition without editing JSON
      </summary>
      <div className="flex flex-col gap-2 border-t p-3">
        <p className="text-fd-muted-foreground">
          The statement applies only when the context value{' '}
          <span className="text-fd-foreground">
            {operators.find((entry) => entry.name === operator)?.meaning}
          </span>
          .
        </p>
        <div className="grid gap-2 sm:grid-cols-2">
          <label className="flex flex-col gap-1 text-fd-muted-foreground">
            Statement
            <select
              className={field}
              value={statement}
              onChange={(event) => setStatement(Number(event.target.value))}
            >
              {statements.map((name, index) => (
                <option key={name + index} value={index}>
                  {name}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-fd-muted-foreground">
            Operator
            <select
              className={field}
              value={operator}
              onChange={(event) => setOperator(event.target.value)}
            >
              {operators.map((entry) => (
                <option key={entry.name} value={entry.name}>
                  {entry.name}
                </option>
              ))}
            </select>
          </label>
          <label className="flex flex-col gap-1 text-fd-muted-foreground">
            Context key
            <input
              className={field}
              list={listId}
              value={key}
              onChange={(event) => setKey(event.target.value)}
            />
            <datalist id={listId}>
              {contextKeys.map((entry) => (
                <option key={entry.key} value={entry.key}>
                  {entry.note}
                </option>
              ))}
            </datalist>
          </label>
          <label className="flex flex-col gap-1 text-fd-muted-foreground">
            Value
            <input
              className={field}
              placeholder={placeholders[kind]}
              value={value}
              onChange={(event) => setValue(event.target.value)}
            />
          </label>
        </div>
        <button
          type="button"
          onClick={add}
          className="inline-flex items-center gap-1.5 self-start rounded-lg bg-fd-primary px-3 py-1.5 font-medium text-fd-primary-foreground transition-opacity hover:opacity-90"
        >
          <Plus className="size-3.5" /> Add condition
        </button>
      </div>
    </details>
  );
}
