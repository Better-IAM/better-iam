import { notFound } from 'next/navigation';
import stats from '@/generated/stats.json';
import { socialCard, type SocialCard } from '@/lib/og';

export const revalidate = false;

/** Social cards for the pages outside the docs (`siteImages` in lib/metadata.ts points at these). */
const cards: Record<string, SocialCard> = {
  'home.png': {
    trail: ['Open source', 'Apache 2.0'],
    title: 'Identity and access management for TypeScript',
    description:
      'Authentication, authorization, multi-tenancy, federation, and a tamper-evident audit log, in your own database.',
    tags: [
      `${stats.methods} API methods`,
      `${stats.packages} packages`,
      `${stats.errorCodes} error codes`,
    ],
  },
  'playground.png': {
    trail: ['Playground'],
    title: 'Policy playground',
    description:
      'Write policy documents and watch the real engine from @better-iam/core decide, statement by statement, in your browser.',
    tags: ['@better-iam/core'],
  },
};

export async function GET(_req: Request, { params }: RouteContext<'/og/[image]'>) {
  const { image } = await params;
  const card = cards[image];
  if (!card) notFound();
  return socialCard(card);
}

export function generateStaticParams() {
  return Object.keys(cards).map((image) => ({ image }));
}

export const dynamicParams = false;
