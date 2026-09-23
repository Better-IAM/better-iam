'use client';

import { Fragment, type ReactNode } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { AppWindow, Building2, Cable, Radio, Users } from 'lucide-react';
import { cn } from '@/lib/cn';
import { LogoMark } from '@/components/logo';
import { DiagramFrame, PlayToggle } from './frame';
import { useStepper } from './motion';

/** Every federation surface, drawn as lanes into and out of the one instance. Captions follow the federation guides. */
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
    icon: <Building2 />,
    protocol: 'OIDC · SAML 2.0',
    caption:
      'People sign in with their company’s identity provider. SAML connections are managed per tenant, with metadata import.',
  },
  {
    side: 'out',
    name: 'Your apps and MCP servers',
    icon: <AppWindow />,
    protocol: 'OAuth 2.0 · OIDC',
    caption:
      'Better IAM is the OAuth and OpenID Connect provider for your own apps, APIs, and MCP servers, with dynamic client registration.',
  },
  {
    side: 'in',
    name: 'HR system or directory',
    icon: <Users />,
    protocol: 'SCIM 2.0',
    caption:
      'An upstream directory provisions people and groups in over SCIM 2.0, with filters, PATCH, and bulk requests.',
  },
  {
    side: 'out',
    name: 'SaaS apps',
    icon: <Cable />,
    protocol: 'SCIM 2.0',
    caption:
      'Outbound SCIM pushes people and groups to downstream apps, and deactivates them when they leave.',
  },
  {
    side: 'out',
    name: 'Signal receivers',
    icon: <Radio />,
    protocol: 'CAEP · RISC',
    caption:
      'Security events leave as signed Shared Signals, so other systems can end sessions and react to risk.',
  },
];

export function FederationMap() {
  const { ref, step, select, toggle, paused, inView } = useStepper(lanes.length, {
    interval: 2600,
    hold: 2600,
  });
  const lane = lanes[step]!;

  return (
    <div ref={ref}>
      <DiagramFrame
        live={!paused}
        label="Federation · one instance, every protocol"
        actions={<PlayToggle paused={paused} onClick={toggle} />}
        footer={
          <AnimatePresence mode="wait" initial={false}>
            <motion.span
              key={step}
              className="block"
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.25 }}
            >
              <span className="font-medium text-fd-foreground">{lane.name}.</span> {lane.caption}
            </motion.span>
          </AnimatePresence>
        }
      >
        {/* Wide layout: sources, hub, targets */}
        <div className="hidden grid-cols-[minmax(0,1fr)_minmax(0,0.9fr)_auto_minmax(0,0.9fr)_minmax(0,1fr)] grid-rows-5 items-center gap-y-2.5 md:grid">
          <div className="col-start-3 row-span-5 row-start-1 flex h-full items-center px-1">
            <Hub running={inView && !paused} />
          </div>
          {lanes.map((item, index) => {
            const active = index === step;
            const row = { gridRowStart: index + 1 };
            return item.side === 'in' ? (
              <Fragment key={item.name}>
                <div style={row} className="col-start-1">
                  <Endpoint item={item} active={active} onClick={() => select(index)} />
                </div>
                <div style={row} className="col-start-2">
                  <Beam label={item.protocol} active={active} running={inView && !paused} />
                </div>
              </Fragment>
            ) : (
              <Fragment key={item.name}>
                <div style={row} className="col-start-4">
                  <Beam label={item.protocol} active={active} running={inView && !paused} />
                </div>
                <div style={row} className="col-start-5">
                  <Endpoint item={item} active={active} onClick={() => select(index)} />
                </div>
              </Fragment>
            );
          })}
        </div>

        {/* Narrow layout: the hub, then one row per lane */}
        <div className="flex flex-col gap-2 md:hidden">
          <Hub running={inView && !paused} />
          {lanes.map((item, index) => (
            <button
              key={item.name}
              type="button"
              onClick={() => select(index)}
              className={cn(
                'flex items-center gap-3 rounded-xl border px-3 py-2.5 text-start transition-colors',
                index === step ? 'border-fd-primary/50 bg-fd-primary/[0.05]' : 'bg-fd-background',
              )}
            >
              <span className="text-fd-primary [&_svg]:size-4">{item.icon}</span>
              <span className="flex min-w-0 flex-col">
                <span className="truncate text-[0.8125rem] font-medium">{item.name}</span>
                <span className="font-mono text-[0.6875rem] text-fd-muted-foreground">
                  {item.side === 'in' ? '→ Better IAM' : 'Better IAM →'} · {item.protocol}
                </span>
              </span>
            </button>
          ))}
        </div>
      </DiagramFrame>
    </div>
  );
}

function Hub({ running }: { running: boolean }) {
  return (
    <div className="relative flex w-full flex-col items-center gap-2 rounded-2xl border border-fd-primary/40 bg-fd-background px-5 py-5 text-center md:w-40 md:py-8">
      <motion.span
        aria-hidden
        className="absolute inset-0 rounded-2xl border border-fd-primary/30"
        animate={
          running ? { scale: [1, 1.06, 1], opacity: [0.6, 0, 0.6] } : { scale: 1, opacity: 0 }
        }
        transition={
          running ? { duration: 2.6, repeat: Infinity, ease: 'easeOut' } : { duration: 0.3 }
        }
      />
      <LogoMark className="size-8 text-fd-primary" />
      <span className="text-sm font-medium">Better IAM</span>
      <span className="text-[0.6875rem] leading-4 text-fd-muted-foreground">
        One tenant model, one audit log
      </span>
    </div>
  );
}

function Endpoint({
  item,
  active,
  onClick,
}: {
  item: (typeof lanes)[number];
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={cn(
        'flex w-full items-center gap-2.5 rounded-xl border px-3 py-2.5 text-start transition-colors duration-300',
        active
          ? 'border-fd-primary/50 bg-fd-primary/[0.06]'
          : 'bg-fd-background hover:border-fd-primary/30',
      )}
    >
      <span
        className={cn(
          'shrink-0 transition-colors [&_svg]:size-4',
          active ? 'text-fd-primary' : 'text-fd-muted-foreground',
        )}
      >
        {item.icon}
      </span>
      <span
        className={cn(
          'min-w-0 truncate text-[0.8125rem] font-medium',
          !active && 'text-fd-muted-foreground',
        )}
      >
        {item.name}
      </span>
    </button>
  );
}

/**
 * A left-to-right connector with its protocol on top and packets travelling along it. Each packet rides a full-width
 * carrier that is translated by its own width, so the motion is a transform and never triggers layout.
 */
function Beam({ label, active, running }: { label: string; active: boolean; running: boolean }) {
  return (
    <div className="relative flex flex-col items-center gap-1 px-2">
      <span
        className={cn(
          'whitespace-nowrap font-mono text-[0.625rem] transition-colors duration-300',
          active ? 'text-fd-primary' : 'text-fd-muted-foreground/70',
        )}
      >
        {label}
      </span>
      <span className="relative block h-px w-full overflow-visible">
        <span
          className={cn(
            'absolute inset-0 transition-colors duration-300',
            active ? 'bg-fd-primary/60' : 'bg-fd-border',
          )}
        />
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
                  className={cn(
                    'absolute left-0 top-1/2 size-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full',
                    active
                      ? 'bg-fd-primary shadow-[0_0_0_3px_color-mix(in_oklab,var(--color-fd-primary)_18%,transparent)]'
                      : 'bg-fd-muted-foreground/40',
                  )}
                />
              </motion.span>
            ))
          : null}
        <span
          className={cn(
            'absolute -right-0.5 top-1/2 size-0 -translate-y-1/2 border-y-[4px] border-l-[6px] border-y-transparent transition-colors duration-300',
            active ? 'border-l-fd-primary' : 'border-l-fd-border',
          )}
        />
      </span>
    </div>
  );
}
