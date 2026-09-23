'use client';

import { useEffect, useRef, useState } from 'react';
import { AnimatePresence, motion, useInView } from 'motion/react';
import { RiForbidLine } from 'react-icons/ri';
import { cx } from '@/utils/cx';
import { DiagramFrame, segmentClass } from './frame';
import { ease, useReducedMotionSafe } from './motion';

/**
 * The default hierarchy (root → organization → project) as a live tree. "Isolation" shows that membership in a
 * parent grants nothing in a child; "Suspension" shows a suspended tenant taking its subtree and sessions with it.
 * Hovering a tenant traces its path to the root and its subtree; clicking one suspends it, and the suspension
 * travels down the tree one level at a time.
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

const byId = new Map(nodes.map((node) => [node.id, node]));

/** The node's ancestors, nearest first. */
function ancestors(id: string) {
  const out: string[] = [];
  for (let node = byId.get(id); node?.parent; node = byId.get(node.parent)) out.push(node.parent);
  return out;
}

/** Whether `node` is `root` or sits somewhere below it. */
function within(node: Node, root: string) {
  return node.id === root || ancestors(node.id).includes(root);
}

const ROW_TOP = [0, 124, 248];
const NODE_HEIGHT = 62;
const HEIGHT = 310;
/** How long the suspension takes to travel down one level of the tree. */
const LEVEL_DELAY = 0.22;

type Mode = 'isolation' | 'suspension';

const isolationCaption =
  'Every tenant has its own directory and access model. Owning Acme grants nothing inside Billing: reaching another tenant takes platform-controlled role assumption or root authority.';
const suspensionCaption = (name: string) =>
  `Suspending ${name} suspends its whole subtree: sign-in and authorization need every ancestor active, and existing sessions below it are removed.`;

export function TenantTree() {
  const [mode, setMode] = useState<Mode>('isolation');
  const [target, setTarget] = useState('acme');
  const [hovered, setHovered] = useState<string | null>(null);
  // True for a moment after the reader changes what is suspended, so the change cascades level by level.
  const [cascading, setCascading] = useState(false);
  const reduced = useReducedMotionSafe();
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
  useEffect(() => {
    if (!cascading) return;
    const timer = setTimeout(() => setCascading(false), 1400);
    return () => clearTimeout(timer);
  }, [cascading, mode, target]);

  const origin = byId.get(target)!;
  const suspended = (node: Node) => mode === 'suspension' && within(node, target);
  const delay = (node: Node) =>
    cascading && within(node, target) ? (node.row - origin.row) * LEVEL_DELAY : 0;
  // Hover or focus traces a tenant's path to the root and its whole subtree.
  const lit = hovered
    ? new Set([
        hovered,
        ...ancestors(hovered),
        ...nodes.filter((node) => within(node, hovered)).map((node) => node.id),
      ])
    : null;

  function choose(next: Mode) {
    if (next === mode) return;
    setMode(next);
    setCascading(true);
  }

  function toggle(node: Node) {
    if (mode === 'suspension' && target === node.id) {
      setMode('isolation');
    } else {
      setMode('suspension');
      setTarget(node.id);
    }
    setCascading(true);
  }

  const caption = mode === 'isolation' ? isolationCaption : suspensionCaption(origin.name);

  return (
    <DiagramFrame
      label={
        <>
          Tenant tree
          <span className="hidden text-text-tertiary sm:inline">
            {' '}
            · click a tenant to suspend it
          </span>
        </>
      }
      actions={
        <div
          className="flex rounded-lg bg-segmented-control-background p-0.5"
          role="radiogroup"
          aria-label="What to show"
        >
          {(['isolation', 'suspension'] as const).map((option) => (
            <button
              key={option}
              type="button"
              role="radio"
              aria-checked={mode === option}
              onClick={() => choose(option)}
              className={cx(segmentClass(mode === option), 'h-7 cursor-pointer capitalize')}
            >
              {mode === option ? (
                <motion.span
                  layoutId="tenant-mode"
                  className="absolute inset-0 -z-10 rounded-md bg-segmented-control-selected-background shadow-xs"
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
            key={caption}
            className="block"
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.25 }}
          >
            {caption}
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
              const parent = byId.get(node.parent!)!;
              const x1 = (parent.x / 100) * width;
              const x2 = (node.x / 100) * width;
              const y1 = ROW_TOP[parent.row]! + NODE_HEIGHT;
              const y2 = ROW_TOP[node.row]!;
              const mid = (y1 + y2) / 2;
              const d = `M ${x1} ${y1} C ${x1} ${mid}, ${x2} ${mid}, ${x2} ${y2}`;
              const blocked = mode === 'isolation' && node.id === 'billing';
              const traced = Boolean(lit?.has(node.id) && lit.has(parent.id));
              const dim = lit ? !traced : suspended(node) || blocked;
              return (
                <g key={node.id}>
                  <motion.path
                    d={d}
                    fill="none"
                    stroke="currentColor"
                    strokeWidth={1.5}
                    className="text-text-tertiary"
                    initial={{ pathLength: 0, opacity: 1 }}
                    animate={{ pathLength: inView ? 1 : 0, opacity: dim ? 0.25 : 1 }}
                    transition={{
                      pathLength: { duration: 0.7, delay: 0.2 + index * 0.12, ease },
                      opacity: { duration: 0.3, delay: Math.max(0, delay(node) - 0.1) },
                    }}
                  />
                  {/* The traced path draws itself in ink over the resting edge. */}
                  <AnimatePresence>
                    {traced && inView ? (
                      <motion.path
                        d={d}
                        fill="none"
                        stroke="currentColor"
                        strokeWidth={1.75}
                        className="text-text-primary"
                        initial={{ pathLength: 0, opacity: 1 }}
                        animate={{ pathLength: 1, opacity: 1 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.35, ease }}
                      />
                    ) : null}
                  </AnimatePresence>
                  <AnimatePresence>
                    {blocked && inView ? (
                      <motion.path
                        d={d}
                        fill="none"
                        stroke="currentColor"
                        strokeWidth={1.5}
                        strokeDasharray="4 4"
                        className="text-text-primary"
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
              className="hatch pointer-events-none absolute z-10 flex -translate-x-1/2 -translate-y-1/2 items-center gap-1 rounded-full border border-text-primary bg-background-primary-default px-2 py-0.5 text-caption-2-medium whitespace-nowrap text-text-primary shadow-xs"
              style={{
                left: '19.5%',
                top: `${((ROW_TOP[1]! + NODE_HEIGHT + ROW_TOP[2]!) / 2 / HEIGHT) * 100}%`,
              }}
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: lit && !lit.has('billing') ? 0.35 : 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.8 }}
              transition={{ delay: lit ? 0 : 0.9, duration: 0.3 }}
            >
              <RiForbidLine className="size-3" aria-hidden /> no implicit access
            </motion.span>
          ) : null}
        </AnimatePresence>

        {/* Nodes */}
        {nodes.map((node, index) => {
          const off = suspended(node);
          const isOrigin = off && node.id === target;
          const wait = delay(node);
          const faded = Boolean(lit && !lit.has(node.id));
          return (
            <motion.div
              key={node.id}
              className="absolute w-[27%] max-w-44 -translate-x-1/2"
              style={{ left: `${node.x}%`, top: ROW_TOP[node.row], height: NODE_HEIGHT }}
              initial={{ opacity: 0, y: 8 }}
              animate={inView ? { opacity: off && !isOrigin ? 0.6 : 1, y: 0 } : undefined}
              transition={
                cascading
                  ? { delay: wait, duration: 0.35, ease }
                  : { delay: node.row * 0.25 + index * 0.04, duration: 0.45, ease }
              }
            >
              <button
                type="button"
                onClick={() => toggle(node)}
                onMouseEnter={() => setHovered(node.id)}
                onMouseLeave={() => setHovered(null)}
                onFocus={() => setHovered(node.id)}
                onBlur={() => setHovered(null)}
                aria-pressed={isOrigin}
                aria-label={`${node.name}, ${node.type}${off ? ', suspended' : ''}. ${
                  isOrigin ? 'Resume' : 'Suspend'
                } it and everything below it.`}
                title={isOrigin ? `Resume ${node.name}` : `Suspend ${node.name} and its subtree`}
                style={{ transitionDelay: wait ? `${wait}s` : undefined }}
                className={cx(
                  'group relative flex h-full w-full cursor-pointer flex-col justify-center gap-0.5 rounded-xl border bg-background-primary-default px-2.5 text-start shadow-xs transition-[opacity,translate,scale,border-color,box-shadow] duration-300 active:scale-[0.98] sm:px-3',
                  off
                    ? 'border-transparent shadow-none'
                    : hovered === node.id
                      ? 'border-text-primary shadow-sm'
                      : lit?.has(node.id) || node.id === 'root'
                        ? 'border-border-button-hover'
                        : 'border-border-button-default hover:border-border-button-hover',
                  !off &&
                    'motion-safe:hover:-translate-y-0.5 motion-safe:focus-visible:-translate-y-0.5',
                  faded && 'opacity-35',
                )}
              >
                {/* Suspended: the tenant itself hatched in ink, everything below it dashed. */}
                <AnimatePresence>
                  {off ? (
                    <motion.span
                      aria-hidden
                      className={cx(
                        'pointer-events-none absolute -inset-px rounded-xl border',
                        isOrigin
                          ? 'hatch border-text-primary'
                          : 'border-dashed border-border-button-hover',
                      )}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      exit={{ opacity: 0, transition: { duration: 0.3, delay: wait } }}
                      transition={{ duration: 0.3, delay: wait }}
                    />
                  ) : null}
                </AnimatePresence>
                {/* A ring that ripples out as the suspension reaches this tenant. */}
                {off && cascading && !reduced ? (
                  <motion.span
                    key={`${target}-ripple`}
                    aria-hidden
                    className="pointer-events-none absolute -inset-px rounded-xl border border-text-primary"
                    initial={{ opacity: 0, scale: 1 }}
                    animate={{ opacity: [0, 0.7, 0], scale: [1, 1, 1.12] }}
                    transition={{ duration: 0.7, delay: wait, ease: 'easeOut' }}
                  />
                ) : null}
                <AnimatePresence>
                  {isOrigin ? (
                    <motion.span
                      initial={{ opacity: 0, y: 4 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: 4 }}
                      className="absolute -top-2.5 left-2 rounded-full border border-text-primary bg-background-primary-default px-1.5 font-mono text-[0.5625rem] leading-4 font-medium tracking-wide text-text-primary uppercase"
                    >
                      suspended
                    </motion.span>
                  ) : null}
                </AnimatePresence>
                <span className="relative truncate text-body-2-medium text-text-primary">
                  {node.name}
                </span>
                <span className="relative truncate font-mono text-caption-2-regular text-text-secondary">
                  {node.type}
                </span>
                <SessionDots count={off ? 0 : node.sessions} delay={wait} />
              </button>
            </motion.div>
          );
        })}
      </div>
    </DiagramFrame>
  );
}

/** Live sessions as small dots on the node's top edge; they vanish when the subtree is suspended. */
function SessionDots({ count, delay }: { count: number; delay: number }) {
  return (
    <span className="absolute -top-1 right-2 flex gap-1" aria-hidden>
      <AnimatePresence>
        {Array.from({ length: count }, (_, index) => (
          <motion.span
            key={index}
            className="size-2 rounded-full border-2 border-surface-raised bg-text-primary"
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            exit={{ scale: 0, opacity: 0, transition: { delay: delay + index * 0.05 } }}
            transition={{
              delay: delay + index * 0.08,
              type: 'spring',
              stiffness: 500,
              damping: 25,
            }}
          />
        ))}
      </AnimatePresence>
    </span>
  );
}
