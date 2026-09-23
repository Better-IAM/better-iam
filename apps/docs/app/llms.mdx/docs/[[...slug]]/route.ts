import { notFound } from 'next/navigation';
import { docsLlms, source } from '@/lib/source';
import { getPageMarkdownUrl, siteUrl } from '@/lib/shared';

export const revalidate = false;

export async function GET(_req: Request, { params }: RouteContext<'/llms.mdx/docs/[[...slug]]'>) {
  const { slug } = await params;
  // URLs end in `/content.md` (see `getPageMarkdownUrl`); anything else would silently serve the parent page.
  if (slug?.at(-1) !== 'content.md') notFound();
  const page = source.getPage(slug.slice(0, -1));
  if (!page) notFound();

  return new Response(await docsLlms.page(page), {
    headers: {
      'Content-Type': 'text/markdown; charset=utf-8',
      // Search engines index the HTML page; this Markdown copy (also served at /docs/x.md) points back to it.
      Link: `<${new URL(page.url, siteUrl)}>; rel="canonical"`,
    },
  });
}

export function generateStaticParams() {
  return source.getPages().map((page) => ({
    slug: getPageMarkdownUrl(page).segments,
  }));
}
