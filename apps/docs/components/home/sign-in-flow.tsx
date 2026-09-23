'use client';

import type { ReactNode } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { Check, Fingerprint, Globe, KeyRound, Mail, MessageSquareText } from 'lucide-react';
import { cn } from '@/lib/cn';
import { DiagramFrame, PlayToggle } from './frame';
import { ease, useStepper } from './motion';

/** AuthMethod values from @better-iam/core and what each sign-in proves. */
const methods = [
  {
    value: 'password',
    label: 'Password',
    icon: KeyRound,
    factor: 'When required: TOTP, a passkey, or an emailed code',
  },
  {
    value: 'passkey',
    label: 'Passkey',
    icon: Fingerprint,
    factor: 'Satisfied by the passkey itself',
  },
  {
    value: 'passwordless-email',
    label: 'Email link or code',
    icon: Mail,
    factor: 'When required: TOTP, a passkey, or an emailed code',
  },
  {
    value: 'passwordless-sms',
    label: 'SMS code',
    icon: MessageSquareText,
    factor: 'When required: TOTP, a passkey, or an emailed code',
  },
  {
    value: 'federated',
    label: 'OIDC or SAML',
    icon: Globe,
    factor: 'When required: TOTP, a passkey, or an emailed code',
  },
] as const;

const checks = [
  { title: 'Method allowed', detail: 'The tenant policy is checked before any credential' },
  { title: 'Credential verified', detail: 'Rate-limited per tenant, and optionally per IP' },
  { title: 'Second factor', detail: '' },
  { title: 'Network allowed', detail: 'IP allowlists and blocked networks, at issuance' },
] as const;

export function SignInFlow() {
  const { ref, step, select, toggle, paused } = useStepper(methods.length, {
    interval: 3600,
    hold: 3600,
  });
  const method = methods[step]!;

  return (
    <div ref={ref}>
      <DiagramFrame
        live={!paused}
        label="One sign-in, from method to session"
        actions={<PlayToggle paused={paused} onClick={toggle} />}
        footer={
          <>
            Policies read the result as <code className="font-mono">principal.authMethod</code> and{' '}
            <code className="font-mono">principal.mfa</code>, so a rule can demand a passkey for
            sensitive actions.
          </>
        }
      >
        <div className="grid gap-5 md:grid-cols-[minmax(0,0.85fr)_minmax(0,1fr)_minmax(0,1fr)] md:gap-4">
          {/* Methods */}
          <Column title="Method">
            <div className="flex flex-wrap gap-1.5 md:flex-col md:gap-1">
              {methods.map((item, index) => {
                const Icon = item.icon;
                const selected = index === step;
                return (
                  <button
                    key={item.value}
                    type="button"
                    onClick={() => select(index)}
                    aria-pressed={selected}
                    className={cn(
                      'relative flex items-center gap-2 rounded-lg px-2.5 py-2 text-start text-[0.8125rem] transition-colors',
                      selected
                        ? 'text-fd-foreground'
                        : 'text-fd-muted-foreground hover:text-fd-foreground',
                    )}
                  >
                    {selected ? (
                      <motion.span
                        layoutId="signin-method"
                        aria-hidden
                        className="absolute inset-0 rounded-lg border border-fd-primary/40 bg-fd-primary/[0.07]"
                        transition={{ type: 'spring', stiffness: 420, damping: 34 }}
                      />
                    ) : null}
                    <Icon
                      className={cn('relative size-4 shrink-0', selected && 'text-fd-primary')}
                    />
                    <span className="relative">{item.label}</span>
                  </button>
                );
              })}
            </div>
          </Column>

          {/* Checks */}
          <Column title="Checks">
            <ol key={method.value} className="flex flex-col gap-2.5">
              {checks.map((check, index) => (
                <motion.li
                  key={check.title}
                  className="flex items-start gap-2.5"
                  initial={{ opacity: 0.35 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.25 + index * 0.45, duration: 0.3 }}
                >
                  <span className="relative mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full border border-fd-border">
                    <motion.span
                      className="absolute inset-[-1px] flex items-center justify-center rounded-full bg-fd-primary text-fd-primary-foreground"
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      transition={{
                        delay: 0.45 + index * 0.45,
                        type: 'spring',
                        stiffness: 500,
                        damping: 26,
                      }}
                    >
                      <Check className="size-2.5" strokeWidth={3.5} />
                    </motion.span>
                  </span>
                  <span className="flex flex-col">
                    <span className="text-[0.8125rem] font-medium leading-5">{check.title}</span>
                    <span className="text-xs leading-5 text-fd-muted-foreground">
                      {check.detail || method.factor}
                    </span>
                  </span>
                </motion.li>
              ))}
            </ol>
          </Column>

          {/* Session */}
          <Column title="Session">
            <div
              key={method.value}
              className="relative rounded-xl border bg-fd-background p-3.5 font-mono text-xs leading-6"
            >
              {/* The card fills in once the checks have passed. */}
              <motion.span
                className="absolute right-3 top-3 rounded-full px-1.5 py-px font-sans text-[0.625rem] font-medium uppercase tracking-wide"
                initial={{ opacity: 1 }}
                animate={{ opacity: 0 }}
                transition={{ delay: 2, duration: 0.2 }}
              >
                <span className="text-fd-muted-foreground">waiting</span>
              </motion.span>
              <motion.span
                className="absolute right-3 top-3 rounded-full bg-emerald-500/15 px-1.5 py-px font-sans text-[0.625rem] font-medium uppercase tracking-wide text-emerald-700 dark:text-emerald-300"
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: 2.1, type: 'spring', stiffness: 500, damping: 26 }}
              >
                issued
              </motion.span>
              <motion.div
                initial={{ opacity: 0.25 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 2.1, duration: 0.45, ease }}
              >
                <Field name="kind" value="'user'" />
                <Field name="method" value={`'${method.value}'`} highlight />
                <Field name="mfa" value="true" />
                <Field name="client" value="{ ip: '203.0.113.7' }" />
                <Field name="expiresAt" value="capped by policy" muted />
              </motion.div>
            </div>
            <p className="mt-2.5 text-xs leading-5 text-fd-muted-foreground">
              Lifetime, idle timeout, and session count follow the tenant&apos;s policy.
            </p>
          </Column>
        </div>
      </DiagramFrame>
    </div>
  );
}

function Column({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-3">
      <p className="text-[0.6875rem] font-medium uppercase tracking-[0.08em] text-fd-muted-foreground">
        {title}
      </p>
      {children}
    </div>
  );
}

function Field({
  name,
  value,
  highlight,
  muted,
}: {
  name: string;
  value: string;
  highlight?: boolean;
  muted?: boolean;
}) {
  return (
    <div className="flex gap-2">
      <span className="w-20 shrink-0 text-fd-muted-foreground">{name}</span>
      <AnimatePresence mode="wait" initial={false}>
        <motion.span
          key={value}
          initial={{ opacity: 0, x: -4 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: 4 }}
          transition={{ duration: 0.2 }}
          className={cn(
            'truncate',
            highlight && 'text-fd-primary',
            muted && 'font-sans text-fd-muted-foreground',
          )}
        >
          {value}
        </motion.span>
      </AnimatePresence>
    </div>
  );
}
