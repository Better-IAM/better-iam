'use client';

import { useId, type KeyboardEvent, type ReactNode } from 'react';
import { cn } from '@/lib/cn';

const token =
  /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|([{}[\],])/g;

/** Tokenizes JSON text into highlighted spans. Unknown text (while typing) is rendered as-is. */
function highlight(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  let last = 0;
  let key = 0;
  for (const match of text.matchAll(token)) {
    const index = match.index ?? 0;
    if (index > last) out.push(text.slice(last, index));
    const [whole, string, colon, literal, number, punctuation] = match;
    if (string !== undefined) {
      const variable = /\$\{[^}]*\}/.test(string);
      out.push(
        <span
          key={key++}
          className={
            colon
              ? 'text-sky-700 dark:text-sky-300'
              : variable
                ? 'text-fuchsia-700 dark:text-fuchsia-300'
                : 'text-emerald-700 dark:text-emerald-300'
          }
        >
          {string}
        </span>,
      );
      if (colon)
        out.push(
          <span key={key++} className="text-fd-muted-foreground">
            {colon}
          </span>,
        );
    } else if (literal !== undefined) {
      out.push(
        <span key={key++} className="text-amber-700 dark:text-amber-300">
          {literal}
        </span>,
      );
    } else if (number !== undefined) {
      out.push(
        <span key={key++} className="text-orange-700 dark:text-orange-300">
          {number}
        </span>,
      );
    } else if (punctuation !== undefined) {
      out.push(
        <span key={key++} className="text-fd-muted-foreground">
          {punctuation}
        </span>,
      );
    } else out.push(whole);
    last = index + whole.length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

/**
 * A dependency-free JSON editor: a transparent textarea stacked over a highlighted `<pre>` in one grid cell,
 * so both share wrapping and the editor grows with its content.
 */
export function JsonEditor({
  value,
  onChange,
  label,
  invalid,
  minRows = 6,
}: {
  value: string;
  onChange: (value: string) => void;
  label: string;
  invalid?: boolean;
  minRows?: number;
}) {
  const id = useId();

  function onKeyDown(event: KeyboardEvent<HTMLTextAreaElement>) {
    if (event.key !== 'Tab' || event.shiftKey) return;
    event.preventDefault();
    const target = event.currentTarget;
    const { selectionStart, selectionEnd } = target;
    const next = `${value.slice(0, selectionStart)}  ${value.slice(selectionEnd)}`;
    onChange(next);
    requestAnimationFrame(() => {
      target.selectionStart = target.selectionEnd = selectionStart + 2;
    });
  }

  const shared =
    'col-start-1 row-start-1 m-0 whitespace-pre-wrap break-words p-3 font-mono text-[0.8rem] leading-relaxed [overflow-wrap:anywhere]';
  return (
    <div
      className={cn(
        'grid rounded-lg border bg-fd-background transition-colors focus-within:border-fd-primary/60 focus-within:ring-2 focus-within:ring-fd-primary/15',
        invalid && 'border-red-500/50 focus-within:border-red-500/70 focus-within:ring-red-500/15',
      )}
      style={{ minHeight: `${minRows * 1.625 + 1.5}rem` }}
    >
      <label htmlFor={id} className="sr-only">
        {label}
      </label>
      <pre aria-hidden className={cn(shared, 'pointer-events-none text-fd-foreground')}>
        {highlight(value)}
        {'\n'}
      </pre>
      <textarea
        id={id}
        value={value}
        spellCheck={false}
        autoCapitalize="off"
        autoComplete="off"
        autoCorrect="off"
        onChange={(event) => onChange(event.target.value)}
        onKeyDown={onKeyDown}
        className={cn(
          shared,
          'resize-none overflow-hidden bg-transparent text-transparent caret-fd-foreground outline-none selection:bg-fd-primary/25',
        )}
      />
    </div>
  );
}
