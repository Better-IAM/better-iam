'use client';

import { useEffect, useId, useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { RiAddLine, RiCheckLine } from 'react-icons/ri';
import { Button } from '@/components/base/buttons/button';
import { cx } from '@/utils/cx';
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

/** A check that pops in, for buttons that confirm what they just did (copy, share, add). */
export function PopCheck({ className }: { className?: string }) {
  return (
    <motion.span
      aria-hidden
      className={cx('inline-flex items-center justify-center', className)}
      initial={{ scale: 0.3, rotate: -40, opacity: 0 }}
      animate={{ scale: 1, rotate: 0, opacity: 1 }}
      transition={{ type: 'spring', stiffness: 600, damping: 22 }}
    >
      <RiCheckLine className="size-full" />
    </motion.span>
  );
}

/** The BoardUI input look, as a native field (selects and a datalist need the platform controls). */
export const fieldClass =
  'h-8 min-w-0 rounded-lg border border-border-button-default bg-background-primary-default px-2.5 font-mono text-caption-1-regular text-text-primary shadow-xs outline-none transition-[border-color,box-shadow] duration-150 placeholder:text-text-tertiary hover:border-border-button-hover focus:border-border-button-active focus:ring-2 focus:ring-border-focus-ring';

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
  const [added, setAdded] = useState(false);
  const kind = operators.find((entry) => entry.name === operator)?.kind ?? 'string';

  useEffect(() => {
    if (!added) return;
    const timer = setTimeout(() => setAdded(false), 1400);
    return () => clearTimeout(timer);
  }, [added]);

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
      setAdded(true);
    } catch {
      // The editor shows the JSON error; nothing to add to an invalid document.
    }
  }

  return (
    <details className="group/builder rounded-xl border border-dashed border-border-button-default text-caption-1-regular transition-colors duration-200 open:border-solid open:bg-background-primary-default hover:border-border-button-hover">
      <summary className="flex cursor-pointer list-none items-center gap-2 px-3 py-2 text-caption-1-medium text-text-secondary transition-colors select-none hover:text-text-primary [&::-webkit-details-marker]:hidden">
        <span className="flex size-5 items-center justify-center rounded-md border border-border-button-default bg-background-primary-default shadow-xs transition-[transform,border-color] duration-200 group-hover/builder:border-border-button-hover group-open/builder:rotate-45">
          <RiAddLine className="size-3.5" aria-hidden />
        </span>
        Add a condition without editing JSON
      </summary>
      <div className="flex flex-col gap-3 border-t border-separator-border p-3">
        <p className="text-text-secondary">
          The statement applies only when the context value{' '}
          <AnimatePresence mode="wait" initial={false}>
            <motion.span
              key={operator}
              className="text-caption-1-medium text-text-primary"
              initial={{ opacity: 0, y: 3 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -3 }}
              transition={{ duration: 0.15 }}
            >
              {operators.find((entry) => entry.name === operator)?.meaning}
            </motion.span>
          </AnimatePresence>
          .
        </p>
        <div className="grid gap-2.5 sm:grid-cols-2">
          <label className="flex flex-col gap-1 text-caption-1-medium text-text-secondary">
            Statement
            <select
              className={fieldClass}
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
          <label className="flex flex-col gap-1 text-caption-1-medium text-text-secondary">
            Operator
            <select
              className={fieldClass}
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
          <label className="flex flex-col gap-1 text-caption-1-medium text-text-secondary">
            Context key
            <input
              className={fieldClass}
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
          <label className="flex flex-col gap-1 text-caption-1-medium text-text-secondary">
            Value
            <input
              className={fieldClass}
              placeholder={placeholders[kind]}
              value={value}
              onChange={(event) => setValue(event.target.value)}
            />
          </label>
        </div>
        <Button
          size="small"
          leadingIcon={added ? PopCheck : RiAddLine}
          onClick={add}
          className="self-start"
        >
          {added ? 'Condition added' : 'Add condition'}
        </Button>
      </div>
    </details>
  );
}
