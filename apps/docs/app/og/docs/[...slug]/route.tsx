import { notFound } from 'next/navigation';
import { docsSeo } from '@/lib/docs-seo';
import { socialCard } from '@/lib/og';
import { source } from '@/lib/source';
import { getPageImageUrl } from '@/lib/shared';

export const revalidate = false;

/** A docs page's social card: where it sits, its title and description, and the packages it documents. */
export async function GET(_req: Request, { params }: RouteContext<'/og/docs/[...slug]'>) {
  const { slug } = await params;
  const page = source.getPage(slug.slice(0, -1));
  if (!page) notFound();

  const seo = docsSeo(page);
  return socialCard({
    trail: seo.trail,
    title: seo.title,
    description: page.data.description,
    tags: page.data.packages,
  });
}

export function generateStaticParams() {
  return source.getPages().map((page) => ({
    slug: getPageImageUrl(page).segments,
  }));
}

export const dynamicParams = false;
