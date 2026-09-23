'use client';

import { Fragment, useState, type ReactNode } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import {
  RiBaseStationLine,
  RiBuilding2Line,
  RiGroupLine,
  RiPlugLine,
  RiWindowLine,
} from 'react-icons/ri';
import { cx } from '@/utils/cx';
import { LogoMark } from '@/components/logo';
import { DiagramFrame, PlayToggle } from './frame';
import { ease, useStepper } from './motion';

/**
 * Every federation surface, drawn as lanes into and out of the one instance. Captions follow the federation guides.
 * Hovering or focusing a lane lights its path to the hub (a dashed flow along the connector) and dims the rest.
 */
const lanes: {
  side: 'in' | 'out';
  name: string;
  icon: ReactNode;
  protocol: string;
  caption: string;
}[] = [
  {
    side: 'in',
    name: 'Corporate IdP',
    icon: <RiBuilding2Line aria-hidden />,
    protocol: 'OIDC · SAML 2.0',
    caption:
      'People sign in with their company’s identity provider. SAML connections are managed per tenant, with metadata import.',
  },
  {
    side: 'out',
    name: 'Your apps and MCP servers',
    icon: <RiWindowLine aria-hidden />,
    protocol: 'OAuth 2.0 · OIDC',
    caption:
      'Better IAM is the OAuth and OpenID Connect provider for your own apps, APIs, and MCP servers, with dynamic client registration.',
  },
  {
    side: 'in',
    name: 'HR system or directory',
    icon: <RiGroupLine aria-hidden />,
    protocol: 'SCIM 2.0',
    caption:
      'An upstream directory provisions people and groups in over SCIM 2.0, with filters, PATCH, and bulk requests.',
  },
  {
    side: 'out',
    name: 'SaaS apps',
    icon: <RiPlugLine aria-hidden />,
    protocol: 'SCIM 2.0',
    caption:
      'Outbound SCIM pushes people and groups to downstream apps, and deactivates them when they leave.',
  },
  {
    side: 'out',
    name: 'Signal receivers',
    icon: <RiBaseStationLine aria-hidden />,
    protocol: 'CAEP · RISC',
    caption:
      'Security events leave as signed Shared Signals, so other systems can end sessions and react to risk.',
  },
];

type Lane = (typeof lanes)[number];

export function FederationMap() {
  const { ref, step, select, toggle, paused, inView } = useStepper(lanes.length, {
    interval: 2600,
    hold: 2600,
  });
  // A hovered or focused lane takes over the highlight (and the caption) from the autoplay.
  const [hovered, setHovered] = useState<number | null>(null);
  const shown = hovered ?? step;
  const lane = lanes[shown]!;
  const running = inView && !paused;

  function bind(index: number) {
    return {
      onClick: () => select(index),
      onMouseEnter: () => setHovered(index),
      onMouseLeave: () => setHovered(null),
      onFocus: () => setHovered(index),
      onBlur: () => setHovered(null),
    };
  }

  return (
    <div ref={ref}>
      <DiagramFrame
        live={!paused}
        label="Federation · one instance, every protocol"
        actions={<PlayToggle paused={paused} onClick={toggle} />}
        footer={
          <AnimatePresence mode="wait" initial={false}>
            <motion.span
              key={shown}
              className="block"
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.25 }}
            >
              <span className="font-medium text-text-primary">{lane.name}.</span> {lane.caption}
            </motion.span>
          </AnimatePresence>
        }
      >
        {/* Wide layout: sources, hub, targets */}
        <div className="hidden grid-cols-[minmax(0,1fr)_minmax(0,0.9fr)_auto_minmax(0,0.9fr)_minmax(0,1fr)] grid-rows-5 items-center gap-y-2.5 md:grid">
          <div className="col-start-3 row-span-5 row-start-1 flex h-full items-center px-1">
            <Hub running={running} lane={lane} focused={hovered !== null} />
          </div>
          {lanes.map((item, index) => {
            const active = index === shown;
            const dim = hovered !== null && !active;
            const row = { gridRowStart: index + 1 };
            const reveal = {
              initial: { opacity: 0, x: item.side === 'in' ? -10 : 10 },
              whileInView: { opacity: 1, x: 0 },
              viewport: { once: true, amount: 0.5 },
              transition: { delay: 0.1 + index * 0.08, duration: 0.45, ease },
            };
            const endpoint = (
              <Endpoint
                item={item}
                active={active}
                selected={index === step}
                dim={dim}
                {...bind(index)}
              />
            );
            const beam = <Beam label={item.protocol} active={active} dim={dim} running={running} />;
            return item.side === 'in' ? (
              <Fragment key={item.name}>
                <motion.div style={row} className="col-start-1" {...reveal}>
                  {endpoint}
                </motion.div>
                <motion.div style={row} className="col-start-2" {...reveal}>
                  {beam}
                </motion.div>
              </Fragment>
            ) : (
              <Fragment key={item.name}>
                <motion.div style={row} className="col-start-4" {...reveal}>
                  {beam}
                </motion.div>
                <motion.div style={row} className="col-start-5" {...reveal}>
                  {endpoint}
                </motion.div>
              </Fragment>
            );
          })}
        </div>

        {/* Narrow layout: the hub, then one row per lane */}
        <div className="flex flex-col gap-2 md:hidden">
          <Hub running={running} lane={lane} focused={hovered !== null} />
          {lanes.map((item, index) => {
            const active = index === shown;
            return (
              <motion.div
                key={item.name}
                initial={{ opacity: 0, y: 6 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true, amount: 0.5 }}
                transition={{ delay: index * 0.06, duration: 0.4, ease }}
              >
                <button
                  type="button"
                  aria-pressed={index === step}
                  {...bind(index)}
                  className={cx(
                    'group flex w-full cursor-pointer items-center gap-3 rounded-xl border bg-background-primary-default px-3 py-2.5 text-start shadow-xs transition-[border-color,box-shadow,opacity,scale] duration-300 active:scale-[0.99]',
                    active
                      ? 'border-text-primary shadow-sm'
                      : 'border-border-button-default hover:border-border-button-hover',
                    hovered !== null && !active && 'opacity-50',
                  )}
                >
                  <span
                    className={cx(
                      'shrink-0 transition-colors [&_svg]:size-4',
                      active ? 'text-text-primary' : 'text-foreground-icon-secondary',
                    )}
                  >
                    {item.icon}
                  </span>
                  <span className="flex min-w-0 flex-col">
                    <span className="truncate text-body-2-medium text-text-primary">
                      {item.name}
                    </span>
                    <span className="font-mono text-caption-2-regular text-text-secondary">
                      {item.side === 'in' ? '→ Better IAM' : 'Better IAM →'} · {item.protocol}
                    </span>
                  </span>
                </button>
              </motion.div>
            );
          })}
        </div>
      </DiagramFrame>
    </div>
  );
}

function Hub({ running, lane, focused }: { running: boolean; lane: Lane; focused: boolean }) {
  return (
    <div
      className={cx(
        'relative flex w-full flex-col items-center gap-2 rounded-2xl border bg-background-primary-default px-5 py-5 text-center shadow-xs transition-colors duration-300 md:w-40 md:py-8',
        focused ? 'border-text-primary' : 'border-border-button-hover',
      )}
    >
      <motion.span
        aria-hidden
        className="absolute inset-0 rounded-2xl border border-text-primary"
        animate={
          running ? { scale: [1, 1.06, 1], opacity: [0.35, 0, 0.35] } : { scale: 1, opacity: 0 }
        }
        transition={
          running ? { duration: 2.6, repeat: Infinity, ease: 'easeOut' } : { duration: 0.3 }
        }
      />
      <LogoMark className="size-8 text-text-primary" />
      <span className="text-body-medium text-text-primary">Better IAM</span>
      <span className="text-caption-2-regular text-text-secondary">
        One tenant model, one audit log
      </span>
      {/* The protocol of the lane that is lit. */}
      <AnimatePresence mode="wait" initial={false}>
        <motion.span
          key={lane.name}
          aria-hidden
          className="mt-1 rounded-md border border-border-button-default bg-background-secondary-default px-1.5 font-mono text-[0.625rem] leading-4 whitespace-nowrap text-text-secondary"
          initial={{ opacity: 0, y: 3 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -3 }}
          transition={{ duration: 0.2 }}
        >
          {lane.protocol}
        </motion.span>
      </AnimatePresence>
    </div>
  );
}

function Endpoint({
  item,
  active,
  selected,
  dim,
  ...handlers
}: {
  item: Lane;
  active: boolean;
  selected: boolean;
  dim: boolean;
  onClick: () => void;
  onMouseEnter: () => void;
  onMouseLeave: () => void;
  onFocus: () => void;
  onBlur: () => void;
}) {
  return (
    <button
      type="button"
      aria-pressed={selected}
      {...handlers}
      className={cx(
        'group flex w-full cursor-pointer items-center gap-2.5 rounded-xl border bg-background-primary-default px-3 py-2.5 text-start shadow-xs transition-[border-color,box-shadow,opacity,translate,scale] duration-300 active:scale-[0.98] motion-safe:hover:-translate-y-0.5 motion-safe:focus-visible:-translate-y-0.5',
        active
          ? 'border-text-primary shadow-sm'
          : 'border-border-button-default hover:border-border-button-hover',
        dim && 'opacity-40',
      )}
    >
      <span
        className={cx(
          'shrink-0 transition-[color,translate] duration-300 [&_svg]:size-4',
          active ? 'text-text-primary' : 'text-foreground-icon-secondary',
          // The icon leans toward the hub on hover.
          item.side === 'in'
            ? 'motion-safe:group-hover:translate-x-0.5'
            : 'motion-safe:group-hover:-translate-x-0.5',
        )}
      >
        {item.icon}
      </span>
      <span
        className={cx(
          'min-w-0 truncate text-body-2-medium transition-colors',
          active ? 'text-text-primary' : 'text-text-secondary group-hover:text-text-primary',
        )}
      >
        {item.name}
      </span>
    </button>
  );
}

/**
 * A left-to-right connector with its protocol on top. The lit lane carries a dashed flow (an animated
 * stroke-dashoffset) toward its destination; every lane also carries packets on a full-width carrier that is
 * translated by its own width, so the motion is a transform and never triggers layout.
 */
function Beam({
  label,
  active,
  dim,
  running,
}: {
  label: string;
  active: boolean;
  dim: boolean;
  running: boolean;
}) {
  return (
    <div
      className={cx(
        'relative flex flex-col items-center gap-1 px-2 transition-opacity duration-300',
        dim && 'opacity-30',
      )}
    >
      <span
        className={cx(
          'font-mono text-[0.625rem] whitespace-nowrap transition-colors duration-300',
          active ? 'text-text-primary' : 'text-text-tertiary',
        )}
      >
        {label}
      </span>
      <span className="relative block h-2 w-full overflow-visible">
        <svg className="absolute inset-0 h-full w-full overflow-visible" aria-hidden>
          <line
            x1="0"
            y1="50%"
            x2="100%"
            y2="50%"
            stroke="currentColor"
            strokeWidth={1}
            className="text-border-button-hover"
          />
          <AnimatePresence>
            {active ? (
              <motion.line
                x1="0"
                y1="50%"
                x2="100%"
                y2="50%"
                stroke="currentColor"
                strokeWidth={1.5}
                strokeDasharray="4 4"
                className="text-text-primary"
                initial={{ opacity: 0, strokeDashoffset: 0 }}
                animate={{ opacity: 1, strokeDashoffset: running ? [0, -16] : 0 }}
                exit={{ opacity: 0 }}
                transition={{
                  opacity: { duration: 0.25 },
                  strokeDashoffset: running
                    ? { duration: 0.7, repeat: Infinity, ease: 'linear' }
                    : { duration: 0 },
                }}
              />
            ) : null}
          </AnimatePresence>
        </svg>
        {running
          ? [0, 1, 2].map((packet) => (
              <motion.span
                key={`${packet}-${active}`}
                aria-hidden
                className="absolute inset-0"
                initial={{ x: '0%', opacity: 0 }}
                animate={{ x: ['0%', '100%'], opacity: active ? [0, 1, 1, 0] : [0, 0.5, 0.5, 0] }}
                transition={{
                  duration: active ? 1.4 : 2.8,
                  repeat: Infinity,
                  ease: 'linear',
                  delay: packet * (active ? 0.47 : 0.93),
                }}
              >
                <span
                  className={cx(
                    'absolute top-1/2 left-0 size-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full',
                    active
                      ? 'bg-text-primary shadow-[0_0_0_3px_color-mix(in_oklab,var(--color-text-primary)_18%,transparent)]'
                      : 'bg-text-tertiary',
                  )}
                />
              </motion.span>
            ))
          : null}
        <span
          className={cx(
            'absolute top-1/2 -right-0.5 size-0 -translate-y-1/2 border-y-[4px] border-l-[6px] border-y-transparent transition-colors duration-300',
            active ? 'border-l-text-primary' : 'border-l-border-button-hover',
          )}
        />
      </span>
    </div>
  );
}
