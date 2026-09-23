import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';

const secret = process.env.BETTER_IAM_SECRET;
if (!secret || secret.length < 32)
  throw new Error('Set BETTER_IAM_SECRET to a stable random secret of at least 32 characters.');

/** The app's IAM instance. The Nuxt module finds it through `betterIam.instance` in nuxt.config.ts. */
export const iam = betterIam({
  database: sqliteAdapter({ filename: process.env.BETTER_IAM_DATABASE ?? '.data/iam.db' }),
  secret,
  baseURL: process.env.BETTER_IAM_BASE_URL ?? 'http://localhost:3000',
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
