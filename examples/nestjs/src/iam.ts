import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { authenticator } from 'otplib';

const secret = process.env.BETTER_IAM_SECRET;
if (!secret || secret.length < 32)
  throw new Error('Set BETTER_IAM_SECRET to a stable random secret of at least 32 characters.');

export const iam = betterIam({
  database: sqliteAdapter({ filename: process.env.BETTER_IAM_DATABASE ?? 'iam.db' }),
  secret,
  baseURL: process.env.BETTER_IAM_BASE_URL ?? 'http://localhost:3000',
  permissions: {
    resourceTypes: {
      // Registered with IAM, so list endpoints can use the listAccessible reverse query.
      project: { managed: true, actions: ['projects:read', 'projects:manage'] },
    },
  },
});

/** Demo data, created once when DEMO_SEED=1. The root TOTP secret is discarded: never do this for real. */
export async function seed(): Promise<string | undefined> {
  const password = 'demo root password for the nestjs example';
  let tenantId: string;
  try {
    tenantId = (await iam.bootstrap({ email: 'root@example.test', name: 'Root', password })).tenant
      .id;
  } catch (error) {
    if ((error as { code?: string }).code === 'ALREADY_INITIALIZED') return undefined;
    throw error;
  }
  const challenge = await iam.api.auth.signIn({ tenantId, email: 'root@example.test', password });
  if (!('mfaRequired' in challenge)) throw new Error('Root sign-in must require MFA');
  const enrollment = await iam.api.auth.beginMfa({ tenantId, challenge: challenge.challenge });
  const { token } = await iam.api.auth.confirmMfa({
    credential: { tenantId, challenge: challenge.challenge },
    code: authenticator.generate(enrollment.secret),
  });
  const root = { token };
  const member = await iam.api.identities.create(root, {
    tenantId,
    email: 'member@example.test',
    name: 'Mia Member',
    password: 'demo member password for nestjs',
  });
  await iam.api.resources.registerMany(root, {
    tenantId,
    resources: ['apollo', 'gemini', 'mercury'].map((id) => ({ type: 'project', id })),
  });
  const reader = await iam.api.roles.create(root, {
    tenantId,
    name: 'Apollo and Gemini reader',
    document: {
      version: 1,
      statements: [
        {
          effect: 'allow',
          actions: ['projects:read'],
          resources: ['project/apollo', 'project/gemini'],
        },
      ],
    },
  });
  await iam.api.bindings.create(root, {
    tenantId,
    roleId: reader.id,
    subjectType: 'identity',
    subjectId: member.id,
  });
  return tenantId;
}
