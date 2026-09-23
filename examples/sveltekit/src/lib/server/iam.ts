import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { createIamKit } from '@better-iam/svelte/kit';
import { authenticator } from 'otplib';
import { building } from '$app/environment';

// `vite build` imports server modules to analyse routes; nothing runs then, so a placeholder is enough.
const secret = building
  ? 'placeholder secret used only while building'
  : process.env.BETTER_IAM_SECRET;
if (!secret || secret.length < 32)
  throw new Error('Set BETTER_IAM_SECRET to a stable random secret of at least 32 characters.');

/** The app's IAM instance. */
export const iam = betterIam({
  database: sqliteAdapter({
    filename: building ? ':memory:' : (process.env.BETTER_IAM_DATABASE ?? '.data/iam.db'),
  }),
  secret,
  baseURL: process.env.BETTER_IAM_BASE_URL ?? 'http://localhost:5173',
  permissions: {
    resourceTypes: {
      project: {
        description: 'A project owned by the application',
        actions: ['projects:read', 'projects:manage'],
      },
    },
  },
  // Demo only: a real app loads the project and returns its owning tenant from its own storage.
  resolveResource: async (reference) => reference,
});

/** Serves `/api/iam/**`, fills `event.locals.iam`, and guards whole sections of the app. */
export const iamKit = createIamKit(iam, {
  protect: [{ path: '/account' }, { path: '/admin', authorize: { action: 'iam:identities:read' } }],
});

/** The demo tenant, created on first start when DEMO_SEED=1. */
export const demo: { tenantId?: string } = {};

/** Bootstraps a fresh database with one member. The root TOTP secret is discarded: never do this for real. */
export async function seed(): Promise<void> {
  await iam.initialize();
  if (process.env.DEMO_SEED !== '1') return;
  const password = 'demo root password for the sveltekit example';
  let tenantId: string;
  try {
    tenantId = (await iam.bootstrap({ email: 'root@example.test', name: 'Root', password })).tenant
      .id;
  } catch (error) {
    if ((error as { code?: string }).code !== 'ALREADY_INITIALIZED') throw error;
    return;
  }
  const challenge = await iam.api.auth.signIn({ tenantId, email: 'root@example.test', password });
  if (!('mfaRequired' in challenge)) throw new Error('Root sign-in must require MFA');
  const enrollment = await iam.api.auth.beginMfa({ tenantId, challenge: challenge.challenge });
  const session = await iam.api.auth.confirmMfa({
    credential: { tenantId, challenge: challenge.challenge },
    code: authenticator.generate(enrollment.secret),
  });
  await iam.api.identities.create(
    { token: session.token },
    {
      tenantId,
      email: 'member@example.test',
      name: 'Mia Member',
      password: 'demo member password for sveltekit',
    },
  );
  demo.tenantId = tenantId;
}
