'use client';

import { useEffect, useRef, useState } from 'react';
import { AnimatePresence, motion, useInView } from 'motion/react';
import { Ban } from 'lucide-react';
import { cn } from '@/lib/cn';
import { DiagramFrame, segmentClass } from './frame';
import { ease } from './motion';

/**
 * The default hierarchy (root → organization → project) as a live tree. "Isolation" shows that membership in a
 * parent grants nothing in a child; "Suspension" shows a suspended tenant taking its subtree and sessions with it.
 */
interface Node {
  id: string;
  name: string;
  type: string;
  x: number; // percent of the width
  row: 0 | 1 | 2;
  parent?: string;
  sessions: number;
}

const nodes: Node[] = [
  { id: 'root', name: 'Platform', type: 'root', x: 50, row: 0, sessions: 1 },
  { id: 'acme', name: 'Acme', type: 'organization', x: 27, row: 1, parent: 'root', sessions: 3 },
  {
    id: 'globex',
    name: 'Globex',
    type: 'organization',
    x: 73,
    row: 1,
    parent: 'root',
    sessions: 3,
  },
  { id: 'billing', name: 'Billing', type: 'project', x: 12, row: 2, parent: 'acme', sessions: 1 },
  { id: 'web', name: 'Web app', type: 'project', x: 42, row: 2, parent: 'acme', sessions: 2 },
  { id: 'data', name: 'Data', type: 'project', x: 73, row: 2, parent: 'globex', sessions: 1 },
];

const ROW_TOP = [0, 124, 248];
const NODE_HEIGHT = 62;
const HEIGHT = 310;

type Mode = 'isolation' | 'suspension';

const captions: Record<Mode, string> = {
  isolation:
    'Every tenant has its own directory and access model. Owning Acme grants nothing inside Billing: reaching another tenant takes platform-controlled role assumption or root authority.',
  suspension:
    'Suspending Acme suspends its whole subtree: sign-in and authorization need every ancestor active, and existing sessions below it are removed.',
};

export function TenantTree() {
  const [mode, setMode] = useState<Mode>('isolation');
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, amount: 0.3 });
  // Edges are drawn in real pixels (not a stretched viewBox) so pathLength animates cleanly.
  const [width, setWidth] = useState(576);
  useEffect(() => {
    const element = ref.current;
    if (!element) return;
    const observer = new ResizeObserver(([entry]) => setWidth(entry!.contentRect.width));
    observer.observe(element);
    return () => observer.disconnect();
  }, []);
  const suspended = (node: Node) =>
    mode === 'suspension' && (node.id === 'acme' || node.parent === 'acme');

  return (
    <DiagramFrame
      label="Tenant tree"
      actions={
        <div
          className="flex rounded-lg bg-fd-muted p-0.5"
          role="radiogroup"
          aria-label="What to show"
        >
          {(['isolation', 'suspension'] as const).map((option) => (
            <button
              key={option}
              type="button"
              role="radio"
              aria-checked={mode === option}
              onClick={() => setMode(option)}
              className={cn(segmentClass(mode === option), 'h-7 capitalize')}
            >
              {mode === option ? (
                <motion.span
                  layoutId="tenant-mode"
                  className="absolute inset-0 -z-10 rounded-md bg-fd-background shadow-sm"
                  transition={{ type: 'spring', stiffness: 500, damping: 38 }}
                />
              ) : null}
              {option}
            </button>
          ))}
        </div>
      }
      footer={
        <AnimatePresence mode="wait" initial={false}>
          <motion.span
            key={mode}
            className="block"
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.25 }}
          >
            {captions[mode]}
          </motion.span>
        </AnimatePresence>
      }
    >
      <div ref={ref} className="relative mx-auto w-full max-w-xl" style={{ height: HEIGHT }}>
        {/* Edges */}
        <svg
          className="absolute inset-0 h-full w-full overflow-visible"
          viewBox={`0 0 ${width} ${HEIGHT}`}
          aria-hidden
        >
          {nodes
            .filter((node) => node.parent)
            .map((node, index) => {
              const parent = nodes.find((candidate) => candidate.id === node.parent)!;
              const x1 = (parent.x / 100) * width;
              const x2 = (node.x / 100) * width;
              const y1 = ROW_TOP[parent.row]! + NODE_HEIGHT;
              const y2 = ROW_TOP[node.row]!;
              const mid = (y1 + y2) / 2;
              const d = `M ${x1} ${y1} C ${x1} ${mid}, ${x2} ${mid}, ${x2} ${y2}`;
              const blocked = mode === 'isolation' && node.id === 'billing';
              return (
                <g key={node.id}>
                  <motion.path
                    d={d}
                    fill="none"
                    strokeWidth={1.5}
                    className={cn(
                      'stroke-fd-primary/45 transition-opacity duration-500',
                      (suspended(node) || blocked) && 'opacity-25',
                    )}
                    initial={{ pathLength: 0 }}
                    animate={{ pathLength: inView ? 1 : 0 }}
                    transition={{ duration: 0.7, delay: 0.2 + index * 0.12, ease }}
                  />
                  <AnimatePresence>
                    {blocked && inView ? (
                      <motion.path
                        d={d}
                        fill="none"
                        strokeWidth={1.75}
                        strokeDasharray="5 5"
                        className="stroke-red-500/75"
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        transition={{ delay: 0.7, duration: 0.4 }}
                      />
                    ) : null}
                  </AnimatePresence>
                </g>
              );
            })}
        </svg>

        {/* "No implicit access" marker on the Acme → Billing edge */}
        <AnimatePresence>
          {mode === 'isolation' && inView ? (
            <motion.span
              className="absolute z-10 flex -translate-x-1/2 -translate-y-1/2 items-center gap-1 whitespace-nowrap rounded-full border border-red-500/40 bg-fd-card px-2 py-0.5 text-[0.6875rem] font-medium text-red-600 shadow-sm dark:text-red-400"
              style={{
                left: '19.5%',
                top: `${((ROW_TOP[1]! + NODE_HEIGHT + ROW_TOP[2]!) / 2 / HEIGHT) * 100}%`,
              }}
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.8 }}
              transition={{ delay: 0.9, duration: 0.3 }}
            >
              <Ban className="size-3" /> no implicit access
            </motion.span>
          ) : null}
        </AnimatePresence>

        {/* Nodes */}
        {nodes.map((node, index) => {
          const off = suspended(node);
          return (
            <motion.div
              key={node.id}
              className={cn(
                'absolute flex w-[27%] max-w-44 -translate-x-1/2 flex-col justify-center gap-0.5 rounded-xl border bg-fd-background px-2.5 transition-[border-color] duration-500 sm:px-3',
                node.id === 'root' && 'border-fd-primary/50',
                off && 'border-dashed',
                mode === 'suspension' && node.id === 'acme' && 'border-solid border-amber-500/60',
              )}
              style={{ left: `${node.x}%`, top: ROW_TOP[node.row], height: NODE_HEIGHT }}
              initial={{ opacity: 0, y: 8 }}
              animate={inView ? { opacity: off && node.id !== 'acme' ? 0.6 : 1, y: 0 } : undefined}
              transition={{ delay: node.row * 0.25 + index * 0.04, duration: 0.45, ease }}
            >
              <AnimatePresence>
                {mode === 'suspension' && node.id === 'acme' ? (
                  <motion.span
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: 4 }}
                    className="absolute -top-2.5 left-2 rounded-full border border-amber-500/40 bg-fd-background px-1.5 text-[0.5625rem] font-medium uppercase leading-4 tracking-wide text-amber-700 dark:text-amber-300"
                  >
                    suspended
                  </motion.span>
                ) : null}
              </AnimatePresence>
              <span className="truncate text-[0.8125rem] font-medium">{node.name}</span>
              <span className="truncate font-mono text-[0.6875rem] text-fd-muted-foreground">
                {node.type}
              </span>
              <SessionDots count={off ? 0 : node.sessions} />
            </motion.div>
          );
        })}
      </div>
    </DiagramFrame>
  );
}

/** Live sessions as small pulsing dots on the node's top edge; they vanish when the subtree is suspended. */
function SessionDots({ count }: { count: number }) {
  return (
    <span className="absolute -top-1 right-2 flex gap-1" aria-hidden>
      <AnimatePresence>
        {Array.from({ length: count }, (_, index) => (
          <motion.span
            key={index}
            className="size-2 rounded-full border-2 border-fd-background bg-emerald-500"
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            exit={{ scale: 0, opacity: 0 }}
            transition={{ delay: index * 0.08, type: 'spring', stiffness: 500, damping: 25 }}
          />
        ))}
      </AnimatePresence>
    </span>
  );
}
