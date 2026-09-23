import type { BetterIam } from '@better-iam/server';
import { createIamNext } from '@better-iam/next';

export const demo = {
  org: 'acme',
  reader: { email: 'reader@acme.test', password: 'example-reader-password' },
  owner: { email: 'owner@acme.test', password: 'example-owner-password' },
  guest: { email: 'guest@acme.test', password: 'example-guest-password' },
};

/** An email the demo captured instead of sending (shown on /dev/inbox in development). */
export interface DemoMessage {
  id: string;
  tenantId: string;
  to: string;
  template: string;
  payload: Record<string, string>;
}

async function create(inbox: DemoMessage[]): Promise<BetterIam> {
  // Workspace packages resolve outside node_modules, where serverExternalPackages does not apply, so the server and
  // its native dependencies load at runtime instead of being bundled.
  const [{ betterIam }, { sqliteAdapter }, otplib] = await Promise.all([
    import(/* webpackIgnore: true */ '@better-iam/server'),
    import(/* webpackIgnore: true */ '@better-iam/adapter-sqlite'),
    import(/* webpackIgnore: true */ 'otplib'),
  ]);
  const authenticator = otplib.authenticator ?? otplib.default.authenticator;
  const iam = betterIam({
    database: sqliteAdapter({ filename: process.env.BETTER_IAM_DATABASE ?? ':memory:' }),
    secret: process.env.BETTER_IAM_SECRET ?? 'example-nextjs-secret-with-at-least-32-characters',
    baseURL: process.env.BETTER_IAM_BASE_URL ?? 'http://localhost:3300',
    permissions: { actions: ['documents:read', 'documents:write'] },
    resolveResource: async (reference) => reference,
    authentication: {
      passwordlessEmail: true,
      sendEmail: async (message) => {
        inbox.push(message);
      },
    },
  });
  await seed(iam, inbox, (secret) => authenticator.generate(secret));
  return iam;
}

/** Demo data: an `acme` organization with its owner, a reader who may read documents, and a guest with no grants. */
async function seed(iam: BetterIam, inbox: DemoMessage[], totp: (secret: string) => string) {
  await iam.initialize();
  const root = await iam.bootstrap({
    email: 'root@example.test',
    name: 'Root',
    password: 'example-root-password',
  });
  const tenantId = root.tenant.id;
  const challenge = await iam.api.auth.signIn({
    tenantId,
    email: 'root@example.test',
    password: 'example-root-password',
  });
  if (!('mfaRequired' in challenge)) throw new Error('Root must enroll MFA');
  const enrollment = await iam.api.auth.beginMfa({ tenantId, challenge: challenge.challenge });
  const rootSession = await iam.api.auth.confirmMfa({
    credential: { tenantId, challenge: challenge.challenge },
    code: totp(enrollment.secret),
  });
  const organization = await iam.api.tenants.create(
    { token: rootSession.token },
    {
      parentId: tenantId,
      type: 'organization',
      name: 'Acme',
      slug: demo.org,
      ownerEmail: demo.owner.email,
    },
  );
  await iam.auth.dispatchOutbox();
  const invitation = inbox.find((message) => message.template === 'owner-invitation');
  if (!invitation?.payload.token) throw new Error('Owner invitation was not delivered');
  const org = organization.tenant.id;
  const owner = await iam.api.tenants.acceptInvitation({
    tenantId: org,
    token: invitation.payload.token,
    name: 'Olivia Owner',
    password: demo.owner.password,
  });
  if (!('token' in owner)) throw new Error('The demo owner should not need MFA');
  const credential = { token: owner.token };
  const reader = await iam.api.identities.create(credential, {
    tenantId: org,
    email: demo.reader.email,
    name: 'Riley Reader',
    password: demo.reader.password,
  });
  await iam.api.identities.create(credential, {
    tenantId: org,
    email: demo.guest.email,
    name: 'Gale Guest',
    password: demo.guest.password,
  });
  const policy = await iam.api.policies.create(credential, {
    tenantId: org,
    name: 'Read documents',
    document: {
      version: 1,
      statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['document/*'] }],
    },
  });
  const role = await iam.api.roles.create(credential, {
    tenantId: org,
    name: 'Reader',
    policyIds: [policy.id],
  });
  await iam.api.bindings.create(credential, {
    tenantId: org,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: reader.id,
  });
}

// One instance per process: Next may evaluate this module once per server layer.
const holder = globalThis as unknown as {
  __betterIamExample?: Promise<BetterIam>;
  __betterIamExampleInbox?: DemoMessage[];
};
/** Captured emails, newest last. */
export const inbox: DemoMessage[] = (holder.__betterIamExampleInbox ??= []);
export function getIam(): Promise<BetterIam> {
  holder.__betterIamExample ??= create(inbox);
  return holder.__betterIamExample;
}

export const iamNext = createIamNext(getIam, {
  loginPath: '/login',
  stepUpPath: '/reauth',
  interrupts: 'forbidden',
  // Email (sign-in codes, password resets) goes out after each response; /api/cron retries what failed.
  dispatchAfterResponse: true,
});
