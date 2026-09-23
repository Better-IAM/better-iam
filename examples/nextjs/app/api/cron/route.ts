import { iamNext } from '@/lib/iam';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

// Point a scheduler (Vercel Cron, GitHub Actions, any HTTP cron) here with `Authorization: Bearer $CRON_SECRET`.
// The development fallback secret is for this demo only.
export const GET = iamNext.background.cron({
  secret: process.env.CRON_SECRET ?? 'example-cron-secret',
  tasks: { outbox: true, events: true, purge: true },
});
