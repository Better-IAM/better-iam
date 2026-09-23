import 'server-only';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { BetterIam } from 'better-iam';
import type { BetterIamOptions } from 'better-iam/server';
import type { DeliveryMessage } from 'better-iam/auth';
import type { ScimProvisioner } from 'better-iam/scim';
import type { ScimService } from 'better-iam/scim';

export interface Delivery {
  id: string;
  tenantId: string;
  to: string;
  template: string;
  payload: Record<string, string>;
  receivedAt: number;
}
interface ConsoleState {
  iam: BetterIam;
  inbox: Map<string, Delivery>;
  ready: Promise<void>;
  webhook: boolean;
  /** Outbound SCIM provisioning, served at /api/iam/provisioning for the App provisioning page. */
  provisioner: ScimProvisioner;
  /** Inbound SCIM for identity providers at /api/iam/scim/v2; the Directory sync page uses /api/iam/scim-admin. */
  directory: ScimService;
}

// One IAM instance per process, kept across Next.js dev reloads.
const shared = globalThis as typeof globalThis & { __betterIamConsole?: Promise<ConsoleState> };

async function deliver(inbox: Map<string, Delivery>, message: DeliveryMessage) {
  const webhook = process.env.DELIVERY_WEBHOOK_URL;
  if (webhook) {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      'idempotency-key': message.id,
    };
    if (process.env.DELIVERY_WEBHOOK_TOKEN)
      headers.authorization = `Bearer ${process.env.DELIVERY_WEBHOOK_TOKEN}`;
    const response = await fetch(webhook, {
      method: 'POST',
      headers,
      body: JSON.stringify(message),
      redirect: 'error',
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) throw new Error('Delivery provider rejected the message.');
    return;
  }
  inbox.set(message.id, { ...message, receivedAt: Date.now() });
  while (inbox.size > 200) inbox.delete(inbox.keys().next().value!);
}

async function create(): Promise<ConsoleState> {
  // The library and its native drivers are loaded by Node at runtime, never bundled by webpack.
  const configUrl = pathToFileURL(
    resolve(process.cwd(), process.env.BETTER_IAM_CONFIG ?? 'better-iam.config.mjs'),
  ).href;
  const { createOptions } = (await import(
    /* webpackIgnore: true */ configUrl
  )) as typeof import('../../better-iam.config.mjs');
  const { betterIam } = (await import(
    /* webpackIgnore: true */ 'better-iam'
  )) as typeof import('better-iam');
  const inbox = new Map<string, Delivery>();
  const send = (message: DeliveryMessage) => deliver(inbox, message);
  const options = await createOptions({ authentication: { sendEmail: send, sendSms: send } });
  const iam = betterIam(options as BetterIamOptions);
  const ready = iam.initialize();
  const { createScimProvisioner } = (await import(
    /* webpackIgnore: true */ 'better-iam/scim'
  )) as typeof import('better-iam/scim');
  // Downstream bearer tokens are encrypted with a key derived from the deployment secret; keys derived from secrets
  // being rotated out still open tokens sealed before the switch.
  const provisioningKey = (secret: string) =>
    createHash('sha256').update(`better-iam:console-provisioning:${secret}`).digest('base64');
  const previousSecrets = (options as { previousSecrets?: string[] }).previousSecrets ?? [];
  const provisioner = createScimProvisioner({
    ...iam.protocolHost,
    encryptionKey: provisioningKey(options.secret),
    ...(previousSecrets.length
      ? { previousEncryptionKeys: previousSecrets.map(provisioningKey) }
      : {}),
    basePath: '/api/iam/provisioning',
    allowInsecureLocalhost: process.env.NODE_ENV !== 'production',
  });
  iam.useProtocol(provisioner);
  provisioner.subscribe(iam.events);
  // The console runs no `rotate-secrets` step of its own: while secrets are being rotated out, re-seal stored
  // downstream tokens with the current key once per start (idempotent; unreadable tokens are left for the operator).
  if (previousSecrets.length)
    void ready.then(() => provisioner.rotateKeys()).catch(() => undefined);
  // Expiries and other time-based changes emit no event; a periodic sync catches them.
  setInterval(() => void provisioner.syncAll().catch(() => undefined), 15 * 60_000).unref();
  // Birthright access packages: SCIM pushes, invitations, and group changes take effect through the reconciler.
  setInterval(
    () => void ready.then(() => iam.reconcilePackages()).catch(() => undefined),
    15 * 60_000,
  ).unref();
  // Hourly housekeeping: the retention sweep (expired and long-delivered records) and the invariant monitor, which
  // records invariant:broken / invariant:restored audit events for the Governance pages and webhooks.
  setInterval(
    () =>
      void ready
        .then(async () => {
          await iam.sweepExpired();
          await iam.checkInvariants();
          // Team membership reviews past their due date complete and apply their removals.
          await iam.closeOverdueTeamReviews();
        })
        .catch(() => undefined),
    60 * 60_000,
  ).unref();
  // Billing: spend-budget alerts hourly; daily seat counts (for a `seats` meter, when the platform defines one),
  // statements for months that have ended (accounts already invoiced are skipped), and yesterday's spend spikes.
  setInterval(
    () => void ready.then(() => iam.billing.checkBudgets()).catch(() => undefined),
    60 * 60_000,
  ).unref();
  setInterval(
    () =>
      void ready
        .then(async () => {
          await iam.billing.recordSeats();
          await iam.billing.closePeriod();
          await iam.billing.detectAnomalies();
        })
        .catch(() => undefined),
    24 * 60 * 60_000,
  ).unref();
  // Inbound SCIM: identity providers push people and groups; the job title and department feed the declared
  // identity attributes, and enterprise managers become Identity.managerId.
  const { createScimService } = (await import(
    /* webpackIgnore: true */ 'better-iam/scim'
  )) as typeof import('better-iam/scim');
  const directory = createScimService({
    ...iam.protocolHost,
    basePath: '/api/iam/scim/v2',
    adminBasePath: '/api/iam/scim-admin',
    mapAttributes: (user) => {
      const attributes: Record<string, unknown> = {};
      if (user.title) attributes.title = user.title;
      if (typeof user.enterprise?.department === 'string')
        attributes.department = user.enterprise.department;
      return Object.keys(attributes).length ? attributes : undefined;
    },
  });
  iam.useProtocol(directory);
  let dispatching = false;
  const worker = setInterval(async () => {
    if (dispatching) return;
    dispatching = true;
    try {
      await ready;
      await iam.auth.dispatchOutbox();
      await iam.dispatchAuditHooks();
    } catch {
      /* retried on the next tick */
    } finally {
      dispatching = false;
    }
  }, 1000);
  worker.unref();
  return {
    iam,
    inbox,
    ready,
    webhook: Boolean(process.env.DELIVERY_WEBHOOK_URL),
    provisioner,
    directory,
  };
}

async function state(): Promise<ConsoleState> {
  shared.__betterIamConsole ??= create();
  const current = await shared.__betterIamConsole;
  await current.ready;
  return current;
}

export async function getIam(): Promise<BetterIam> {
  return (await state()).iam;
}
export async function getDeliveries(): Promise<{ messages: Delivery[]; webhook: boolean }> {
  const current = await state();
  return {
    messages: [...current.inbox.values()].sort((a, b) => b.receivedAt - a.receivedAt),
    webhook: current.webhook,
  };
}
export async function getProvisioner(): Promise<ScimProvisioner> {
  return (await state()).provisioner;
}
export async function getDirectory(): Promise<ScimService> {
  return (await state()).directory;
}
/** Type-only export for the browser client; never import this value from client code. */
export type Iam = BetterIam;
