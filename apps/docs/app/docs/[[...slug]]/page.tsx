import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import {
  DocsBody,
  DocsDescription,
  DocsPage,
  DocsTitle,
  MarkdownCopyButton,
  PageLastUpdate,
  ViewOptionsPopover,
} from 'fumadocs-ui/layouts/docs/page';
import { TocFooter } from '@/components/toc-footer';
import { createRelativeLink } from 'fumadocs-ui/mdx';
import { getMDXComponents } from '@/components/mdx';
import { PageMeta } from '@/components/page-meta';
import { PageFeedback } from '@/components/page-feedback';
import { apiUsage, methodsIn } from '@/lib/api-usage';
import { source } from '@/lib/source';
import { appName, getPageImageUrl, getPageMarkdownUrl, sourceFileUrl } from '@/lib/shared';

export default async function Page(props: PageProps<'/docs/[[...slug]]'>) {
  const params = await props.params;
  const page = source.getPage(params.slug);
  if (!page) notFound();

  const MDX = page.data.body;
  const markdownUrl = getPageMarkdownUrl(page).url;
  // Guides list the API methods they use; reference pages already are the API.
  const methods =
    page.slugs[0] === 'reference'
      ? []
      : [...methodsIn(await page.data.getText('processed'), (await apiUsage()).known)].sort();

  return (
    <DocsPage
      toc={page.data.toc}
      full={page.data.full}
      tableOfContent={{
        style: 'clerk',
        footer: <TocFooter path={page.path} url={page.url} methods={methods} />,
      }}
    >
      <DocsTitle>{page.data.title}</DocsTitle>
      <DocsDescription className="mb-0">{page.data.description}</DocsDescription>
      <div className="flex flex-row flex-wrap items-center gap-2 border-b pb-6">
        <MarkdownCopyButton markdownUrl={markdownUrl} />
        <ViewOptionsPopover
          markdownUrl={markdownUrl}
          githubUrl={sourceFileUrl(`apps/docs/content/docs/${page.path}`)}
        />
        <PageMeta
          status={page.data.status}
          packages={page.data.packages}
          sources={page.data.sources}
        />
      </div>
      <DocsBody>
        <MDX
          components={getMDXComponents({
            a: createRelativeLink(source, page),
          })}
        />
      </DocsBody>
      <PageFeedback url={page.url} />
      {page.data.lastModified ? (
        <PageLastUpdate date={page.data.lastModified} className="mt-2" />
      ) : null}
    </DocsPage>
  );
}

export async function generateStaticParams() {
  return source.generateParams();
}

export async function generateMetadata(props: PageProps<'/docs/[[...slug]]'>): Promise<Metadata> {
  const params = await props.params;
  const page = source.getPage(params.slug);
  if (!page) notFound();

  const image = getPageImageUrl(page).url;
  return {
    title: page.data.title,
    description: page.data.description,
    alternates: {
      canonical: page.url,
      types: { 'text/markdown': getPageMarkdownUrl(page).url },
    },
    openGraph: {
      title: `${page.data.title} | ${appName}`,
      description: page.data.description,
      url: page.url,
      images: image,
    },
    twitter: { images: image },
  };
}
