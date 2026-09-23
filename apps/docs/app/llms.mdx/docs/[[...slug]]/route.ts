import { notFound } from 'next/navigation';
import { docsLlms, source } from '@/lib/source';
import { getPageMarkdownUrl } from '@/lib/shared';

export const revalidate = false;

export async function GET(_req: Request, { params }: RouteContext<'/llms.mdx/docs/[[...slug]]'>) {
  const { slug } = await params;
  // URLs end in `/content.md` (see `getPageMarkdownUrl`); anything else would silently serve the parent page.
  if (slug?.at(-1) !== 'content.md') notFound();
  const page = source.getPage(slug.slice(0, -1));
  if (!page) notFound();

  return new Response(await docsLlms.page(page), {
    headers: { 'Content-Type': 'text/markdown; charset=utf-8' },
  });
}

export function generateStaticParams() {
  return source.getPages().map((page) => ({
    slug: getPageMarkdownUrl(page).segments,
  }));
}
