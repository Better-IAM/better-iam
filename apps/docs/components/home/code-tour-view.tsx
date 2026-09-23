'use client';

import { useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { Check, Copy, FileCode2 } from 'lucide-react';
import { useCopyButton } from 'fumadocs-ui/utils/use-copy-button';
import { cn } from '@/lib/cn';
import { ease } from './motion';

export interface TourStep {
  id: string;
  title: string;
  summary: string;
  file: string;
  code: ReactNode;
  /** The plain source, for the copy button. */
  raw: string;
}

/** A numbered walk from configuration to UI: pick a step on the left, read its code on the right. */
export function CodeTourView({ steps }: { steps: TourStep[] }) {
  const [active, setActive] = useState(0);
  const tabs = useRef<(HTMLButtonElement | null)[]>([]);
  const current = steps[active]!;

  function onKeyDown(event: KeyboardEvent) {
    const delta =
      event.key === 'ArrowDown' || event.key === 'ArrowRight'
        ? 1
        : event.key === 'ArrowUp' || event.key === 'ArrowLeft'
          ? -1
          : 0;
    if (!delta) return;
    event.preventDefault();
    const next = (active + delta + steps.length) % steps.length;
    setActive(next);
    tabs.current[next]?.focus();
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)] lg:gap-8">
      <div
        role="tablist"
        aria-orientation="vertical"
        aria-label="Integration steps"
        onKeyDown={onKeyDown}
        className="-mx-5 flex snap-x gap-2 overflow-x-auto px-5 pb-1 lg:mx-0 lg:flex-col lg:gap-1 lg:overflow-visible lg:px-0 lg:pb-0"
      >
        {steps.map((step, index) => {
          const selected = index === active;
          return (
            <button
              key={step.id}
              ref={(element) => {
                tabs.current[index] = element;
              }}
              type="button"
              role="tab"
              id={`tour-tab-${step.id}`}
              aria-selected={selected}
              aria-controls="tour-panel"
              tabIndex={selected ? 0 : -1}
              onClick={() => setActive(index)}
              className={cn(
                'relative flex shrink-0 snap-start items-start gap-3 rounded-xl px-3 py-2.5 text-start transition-colors lg:px-4 lg:py-3.5',
                'max-lg:border max-lg:bg-fd-card',
                selected ? 'max-lg:border-fd-primary/50' : 'hover:bg-fd-accent/50',
              )}
            >
              {selected ? (
                <motion.span
                  layoutId="tour-highlight"
                  aria-hidden
                  className="absolute inset-0 hidden rounded-xl border bg-fd-card shadow-sm lg:block"
                  transition={{ type: 'spring', stiffness: 420, damping: 36 }}
                />
              ) : null}
              <span
                className={cn(
                  'relative mt-0.5 flex size-6 shrink-0 items-center justify-center rounded-full border font-mono text-[0.6875rem] tabular-nums transition-colors',
                  selected
                    ? 'border-fd-primary bg-fd-primary text-fd-primary-foreground'
                    : 'text-fd-muted-foreground',
                )}
              >
                {index + 1}
              </span>
              <span className="relative flex flex-col gap-1">
                <span
                  className={cn(
                    'whitespace-nowrap text-sm font-medium lg:whitespace-normal',
                    !selected && 'text-fd-muted-foreground',
                  )}
                >
                  {step.title}
                </span>
                <span className="hidden text-[0.8125rem] leading-5 text-fd-muted-foreground lg:block">
                  {step.summary}
                </span>
              </span>
            </button>
          );
        })}
      </div>

      <div
        id="tour-panel"
        role="tabpanel"
        aria-labelledby={`tour-tab-${current.id}`}
        className="relative min-w-0 overflow-hidden rounded-2xl border bg-fd-card"
      >
        <div className="flex h-11 items-center gap-2 border-b px-5 text-xs text-fd-muted-foreground">
          <FileCode2 className="size-3.5" />
          <AnimatePresence mode="wait" initial={false}>
            <motion.span
              key={current.file}
              className="font-mono"
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.2 }}
            >
              {current.file}
            </motion.span>
          </AnimatePresence>
          <span className="ms-auto font-mono tabular-nums">
            {active + 1} / {steps.length}
          </span>
          <CopyCode text={current.raw} />
        </div>
        <p className="border-b px-5 py-3 text-[0.8125rem] leading-5 text-fd-muted-foreground lg:hidden">
          {current.summary}
        </p>
        <div className="home-code relative min-h-[26rem] overflow-x-auto px-5 py-5 font-mono text-[0.8125rem] leading-6">
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={current.id}
              initial={{ opacity: 0, y: 10, filter: 'blur(4px)' }}
              animate={{ opacity: 1, y: 0, filter: 'blur(0px)' }}
              exit={{ opacity: 0, y: -6, filter: 'blur(4px)' }}
              transition={{ duration: 0.28, ease }}
            >
              {current.code}
            </motion.div>
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
}

function CopyCode({ text }: { text: string }) {
  const [copied, onClick] = useCopyButton(() => navigator.clipboard.writeText(text));
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={copied ? 'Copied' : 'Copy the code'}
      className="-me-2 inline-flex size-7 items-center justify-center rounded-lg transition-colors hover:bg-fd-accent hover:text-fd-foreground"
    >
      {copied ? <Check className="size-3.5 text-fd-primary" /> : <Copy className="size-3.5" />}
    </button>
  );
}
