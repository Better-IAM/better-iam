'use client';

import type { ReactNode } from 'react';
import { AnimatePresence, motion, type Variants } from 'motion/react';
import {
  RiCheckLine,
  RiFingerprintLine,
  RiGlobalLine,
  RiKey2Line,
  RiMailLine,
  RiMessage2Line,
} from 'react-icons/ri';
import { cx } from '@/utils/cx';
import { DiagramFrame, PlayToggle } from './frame';
import { ease, useStepper } from './motion';

/** AuthMethod values from @better-iam/core and what each sign-in proves. */
const methods = [
  {
    value: 'password',
    label: 'Password',
    icon: RiKey2Line,
    detail: 'Checked against the tenant’s password policy and history',
    factor: 'When required: TOTP, a passkey, or an emailed code',
  },
  {
    value: 'passkey',
    label: 'Passkey',
    icon: RiFingerprintLine,
    detail: 'A WebAuthn credential bound to this site',
    factor: 'Satisfied by the passkey itself',
  },
  {
    value: 'passwordless-email',
    label: 'Email link or code',
    icon: RiMailLine,
    detail: 'A magic link or a one-time code, sent by email',
    factor: 'When required: TOTP, a passkey, or an emailed code',
  },
  {
    value: 'passwordless-sms',
    label: 'SMS code',
    icon: RiMessage2Line,
    detail: 'A one-time code, sent by text message',
    factor: 'When required: TOTP, a passkey, or an emailed code',
  },
  {
    value: 'federated',
    label: 'OIDC or SAML',
    icon: RiGlobalLine,
    detail: 'Any OIDC or SAML identity provider',
    factor: 'When required: TOTP, a passkey, or an emailed code',
  },
] as const;

const checks = [
  { title: 'Method allowed', detail: 'The tenant policy is checked before any credential' },
  { title: 'Credential verified', detail: 'Rate-limited per tenant, and optionally per IP' },
  { title: 'Second factor', detail: '' },
  { title: 'Network allowed', detail: 'IP allowlists and blocked networks, at issuance' },
] as const;

/** When each check passes, in seconds after a method is picked; the session is issued after the last one. */
const checkAt = (index: number) => 0.45 + index * 0.45;
const ISSUED_AT = 2.1;

const columns: Variants = {
  hidden: {},
  shown: { transition: { staggerChildren: 0.12, delayChildren: 0.1 } },
};
const rise: Variants = {
  hidden: { opacity: 0, y: 12 },
  shown: { opacity: 1, y: 0, transition: { duration: 0.5, ease } },
};

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
            Policies read the result as{' '}
            <code className="font-mono text-text-primary">principal.authMethod</code> and{' '}
            <code className="font-mono text-text-primary">principal.mfa</code>, so a rule can demand
            a passkey for sensitive actions.
          </>
        }
      >
        <motion.div
          variants={columns}
          initial="hidden"
          whileInView="shown"
          viewport={{ once: true, amount: 0.3 }}
          className="grid gap-5 md:grid-cols-[minmax(0,0.85fr)_minmax(0,1fr)_minmax(0,1fr)] md:gap-4"
        >
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
                    className={cx(
                      'group relative flex cursor-pointer items-start gap-2 rounded-lg px-2.5 py-2 text-start text-body-2-regular transition-[color,background-color,scale] duration-200 active:scale-[0.98]',
                      selected
                        ? 'text-text-primary'
                        : 'text-text-secondary hover:bg-background-secondary-default hover:text-text-primary',
                    )}
                  >
                    {selected ? (
                      <motion.span
                        layoutId="signin-method"
                        aria-hidden
                        className="absolute inset-0 rounded-lg border border-border-button-default bg-background-primary-default shadow-xs"
                        transition={{ type: 'spring', stiffness: 420, damping: 34 }}
                      />
                    ) : null}
                    <Icon
                      className={cx(
                        'relative mt-px size-4 shrink-0 transition-[color,scale] duration-200 group-hover:scale-110',
                        selected
                          ? 'text-foreground-icon-primary'
                          : 'text-foreground-icon-secondary group-hover:text-foreground-icon-primary',
                      )}
                      aria-hidden
                    />
                    <span className="relative flex min-w-0 flex-col">
                      <span>{item.label}</span>
                      {/* A short detail line opens on hover, and stays open for the current method. */}
                      <span
                        className={cx(
                          'hidden transition-[grid-template-rows,opacity] duration-300 ease-out md:grid',
                          selected
                            ? 'grid-rows-[1fr] opacity-100'
                            : 'grid-rows-[0fr] opacity-0 group-hover:grid-rows-[1fr] group-hover:opacity-100 group-hover:delay-100 group-focus-visible:grid-rows-[1fr] group-focus-visible:opacity-100',
                        )}
                      >
                        <span className="min-h-0 overflow-hidden">
                          <span className="block pt-0.5 text-caption-1-regular text-text-secondary">
                            {item.detail}
                          </span>
                        </span>
                      </span>
                    </span>
                  </button>
                );
              })}
            </div>
            {/* Small screens show the methods as chips, so the current one's detail sits below them. */}
            <div className="relative h-4 md:hidden">
              <AnimatePresence mode="wait" initial={false}>
                <motion.p
                  key={method.value}
                  className="truncate text-caption-1-regular text-text-secondary"
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -4 }}
                  transition={{ duration: 0.2 }}
                >
                  {method.detail}
                </motion.p>
              </AnimatePresence>
            </div>
          </Column>

          {/* Checks */}
          <Column title="Checks">
            <ol key={method.value} className="flex flex-col gap-2.5">
              {checks.map((check, index) => (
                <motion.li
                  key={check.title}
                  className="relative flex items-start gap-2.5"
                  initial={{ opacity: 0.35 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.25 + index * 0.45, duration: 0.3 }}
                >
                  {/* The rail to the next check draws in once this one passes. */}
                  {index < checks.length - 1 ? (
                    <span
                      aria-hidden
                      className="absolute start-[7.5px] top-[1.125rem] -bottom-3 w-px bg-border-button-default"
                    >
                      <motion.span
                        className="absolute inset-0 origin-top bg-text-primary"
                        initial={{ scaleY: 0 }}
                        animate={{ scaleY: 1 }}
                        transition={{ delay: checkAt(index) + 0.12, duration: 0.33, ease }}
                      />
                    </span>
                  ) : null}
                  <span className="relative mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full border border-border-button-hover bg-surface-raised">
                    <motion.span
                      className="absolute -inset-px flex items-center justify-center rounded-full bg-text-primary text-background-full"
                      initial={{ scale: 0 }}
                      animate={{ scale: 1 }}
                      transition={{
                        delay: checkAt(index),
                        type: 'spring',
                        stiffness: 500,
                        damping: 26,
                      }}
                    >
                      <RiCheckLine className="size-3" aria-hidden />
                    </motion.span>
                  </span>
                  <span className="flex flex-col">
                    <span className="text-body-2-medium leading-5">{check.title}</span>
                    <span className="text-caption-1-regular leading-5 text-text-secondary">
                      {check.detail || method.factor}
                    </span>
                  </span>
                </motion.li>
              ))}
            </ol>
          </Column>

          {/* Session */}
          <Column title="Session">
            <motion.div
              key={method.value}
              className="relative rounded-xl border border-border-button-default bg-background-primary-default p-3.5 font-mono text-caption-1-regular leading-6 shadow-xs"
              initial={{ opacity: 0.6, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.35, ease }}
            >
              {/* Once the checks pass, the card takes an ink edge: the session exists. */}
              <motion.span
                aria-hidden
                className="pointer-events-none absolute -inset-px rounded-xl border border-text-primary"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: ISSUED_AT, duration: 0.4 }}
              />
              {/* The card fills in once the checks have passed. */}
              <motion.span
                className="absolute end-3 top-3 rounded-full border border-dashed border-border-button-hover px-1.5 py-px font-sans text-caption-2-medium tracking-wide text-text-tertiary uppercase"
                initial={{ opacity: 1 }}
                animate={{ opacity: 0 }}
                transition={{ delay: ISSUED_AT - 0.1, duration: 0.2 }}
              >
                waiting
              </motion.span>
              <motion.span
                className="absolute end-3 top-3 inline-flex items-center gap-1 rounded-full border border-text-primary bg-text-primary px-1.5 py-px font-sans text-caption-2-medium tracking-wide text-background-full uppercase"
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: ISSUED_AT, type: 'spring', stiffness: 500, damping: 26 }}
              >
                <RiCheckLine className="size-3" aria-hidden />
                issued
              </motion.span>
              <motion.div
                initial={{ opacity: 0.25 }}
                animate={{ opacity: 1 }}
                transition={{ delay: ISSUED_AT, duration: 0.45, ease }}
              >
                <Field name="kind" value="'user'" />
                <Field name="method" value={`'${method.value}'`} highlight />
                <Field name="mfa" value="true" />
                <Field name="client" value="{ ip: '203.0.113.7' }" />
                <Field name="expiresAt" value="capped by policy" muted />
              </motion.div>
            </motion.div>
            <p className="mt-2.5 text-caption-1-regular leading-5 text-text-secondary">
              Lifetime, idle timeout, and session count follow the tenant&apos;s policy.
            </p>
          </Column>
        </motion.div>
      </DiagramFrame>
    </div>
  );
}

function Column({ title, children }: { title: string; children: ReactNode }) {
  return (
    <motion.div variants={rise} className="flex min-w-0 flex-col gap-3">
      <p className="eyebrow">{title}</p>
      {children}
    </motion.div>
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
      <span className="w-20 shrink-0 text-text-secondary">{name}</span>
      <AnimatePresence mode="wait" initial={false}>
        <motion.span
          key={value}
          initial={{ opacity: 0, x: -4 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: 4 }}
          transition={{ duration: 0.2 }}
          className={cx(
            'truncate text-text-primary',
            highlight && '-ms-1 rounded-md bg-background-secondary-default px-1',
            muted && 'font-sans text-text-secondary',
          )}
        >
          {value}
        </motion.span>
      </AnimatePresence>
    </div>
  );
}
