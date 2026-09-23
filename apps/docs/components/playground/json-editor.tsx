'use client';

import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
  type RefObject,
} from 'react';
import { AnimatePresence, motion, useReducedMotion } from 'motion/react';
import { cx } from '@/utils/cx';

const token =
  /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|(-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)|([{}[\],])/g;

/**
 * Tokenizes JSON text into highlighted spans. Unknown text (while typing) is rendered as-is. Monochrome, like the
 * site's code themes: keys and literals at full contrast (literals heavier), strings a step back, punctuation two.
 * JetBrains Mono keeps one advance width across weights, so the heavier spans stay aligned with the textarea caret.
 */
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
              ? 'text-text-primary'
              : variable
                ? 'text-text-primary underline decoration-text-tertiary decoration-dotted underline-offset-[3px]'
                : 'text-text-secondary'
          }
        >
          {string}
        </span>,
      );
      if (colon)
        out.push(
          <span key={key++} className="text-text-tertiary">
            {colon}
          </span>,
        );
    } else if (literal !== undefined) {
      out.push(
        <span key={key++} className="font-semibold text-text-primary">
          {literal}
        </span>,
      );
    } else if (number !== undefined) {
      out.push(
        <span key={key++} className="font-medium text-text-primary">
          {number}
        </span>,
      );
    } else if (punctuation !== undefined) {
      out.push(
        <span key={key++} className="text-text-tertiary">
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
 * Whether an element currently scrolls vertically. Scroll areas are marked `data-lenis-prevent` only while they
 * overflow, so their own wheel scrolling stays native without turning the page's smooth scroll off above them
 * the rest of the time.
 */
export function useOverflowing(ref: RefObject<HTMLElement | null>) {
  const [overflowing, setOverflowing] = useState(false);
  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    const measure = () => setOverflowing(element.scrollHeight > element.clientHeight + 1);
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    for (const child of Array.from(element.children)) observer.observe(child);
    return () => observer.disconnect();
  }, [ref]);
  return overflowing;
}

/**
 * A dependency-free JSON editor: a transparent textarea stacked over a highlighted `<pre>` in one grid cell,
 * so both share wrapping and the editor grows with its content (on wide screens up to a cap, then it scrolls).
 * `mark` is a character range to highlight, such as the statement hovered in the trace.
 */
export function JsonEditor({
  value,
  onChange,
  label,
  invalid,
  minRows = 6,
  mark,
}: {
  value: string;
  onChange: (value: string) => void;
  label: string;
  invalid?: boolean;
  minRows?: number;
  mark?: [number, number];
}) {
  const id = useId();
  const reduced = useReducedMotion();
  const scrollerRef = useRef<HTMLDivElement>(null);
  const preRef = useRef<HTMLPreElement>(null);
  const overflowing = useOverflowing(scrollerRef);
  const [band, setBand] = useState<{ top: number; height: number }>();
  const [start, end] = mark ?? [];

  // Measures the marked range as whole lines, including lines the editor soft-wraps.
  const measure = useCallback(() => {
    const pre = preRef.current;
    const from = pre?.querySelector<HTMLElement>('[data-mark="start"]');
    const to = pre?.querySelector<HTMLElement>('[data-mark="end"]');
    if (!pre || !from || !to) return setBand(undefined);
    const line = parseFloat(getComputedStyle(pre).lineHeight);
    const top = from.offsetTop - (line - from.offsetHeight) / 2;
    const bottom = to.offsetTop - (line - to.offsetHeight) / 2 + line;
    setBand({ top, height: bottom - top });
  }, []);

  useLayoutEffect(() => {
    measure();
    if (start === undefined || !preRef.current) return;
    const observer = new ResizeObserver(measure);
    observer.observe(preRef.current);
    return () => observer.disconnect();
  }, [measure, start, end, value]);

  // Brings the marked statement into view inside the editor (never scrolls the page).
  useEffect(() => {
    const scroller = scrollerRef.current;
    if (!band || !scroller || scroller.scrollHeight <= scroller.clientHeight) return;
    const { scrollTop, clientHeight } = scroller;
    if (band.top < scrollTop || band.top + band.height > scrollTop + clientHeight)
      scroller.scrollTo({ top: Math.max(0, band.top - 12), behavior: reduced ? 'auto' : 'smooth' });
  }, [band, reduced]);

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

  const marked = start !== undefined && end !== undefined && end > start;
  const shared =
    'relative col-start-1 row-start-1 m-0 whitespace-pre-wrap break-words p-3 font-mono text-[0.8rem] leading-relaxed [overflow-wrap:anywhere]';
  return (
    <div
      className={cx(
        'overflow-hidden rounded-xl border bg-surface-sunken transition-[border-color,box-shadow] duration-200',
        invalid
          ? 'border-dashed border-text-primary'
          : 'border-border-button-default hover:border-border-button-hover',
        'focus-within:border-border-button-active focus-within:ring-2 focus-within:ring-border-focus-ring',
      )}
    >
      <div
        ref={scrollerRef}
        data-lenis-prevent={overflowing ? '' : undefined}
        className="lg:max-h-[min(72vh,44rem)] lg:overflow-y-auto"
      >
        <div className="relative grid" style={{ minHeight: `${minRows * 1.625 + 1.5}rem` }}>
          <AnimatePresence>
            {marked && band ? (
              <motion.div
                aria-hidden
                className="pointer-events-none absolute inset-x-0 border-s-2 border-text-primary bg-text-primary/[0.06]"
                initial={{ opacity: 0, top: band.top, height: band.height }}
                animate={{ opacity: 1, top: band.top, height: band.height }}
                exit={{ opacity: 0 }}
                transition={{ type: 'spring', stiffness: 520, damping: 42 }}
              />
            ) : null}
          </AnimatePresence>
          <label htmlFor={id} className="sr-only">
            {label}
          </label>
          <pre
            ref={preRef}
            aria-hidden
            className={cx(shared, 'pointer-events-none text-text-primary')}
          >
            {marked ? (
              <>
                {highlight(value.slice(0, start))}
                <span data-mark="start" />
                {highlight(value.slice(start, end))}
                <span data-mark="end" />
                {highlight(value.slice(end))}
              </>
            ) : (
              highlight(value)
            )}
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
            className={cx(
              shared,
              'resize-none overflow-hidden bg-transparent text-transparent caret-text-primary outline-none selection:bg-text-primary/15',
            )}
          />
        </div>
      </div>
    </div>
  );
}
