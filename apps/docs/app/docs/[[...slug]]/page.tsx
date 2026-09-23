import type { Metadata } from 'next';
import { notFound } from 'next/navigation';
import {
  DocsBody,
  DocsDescription,
  DocsPage,
  DocsTitle,
  MarkdownCopyButton,
  ViewOptionsPopover,
} from 'fumadocs-ui/layouts/docs/page';
import { TocFooter } from '@/components/toc-footer';
import { createRelativeLink } from 'fumadocs-ui/mdx';
import { getMDXComponents } from '@/components/mdx';
import { PageMeta } from '@/components/page-meta';
import { PageFeedback } from '@/components/page-feedback';
import { CreatorCredit } from '@/components/site/creator-credit';
import { JsonLd } from '@/components/json-ld';
import { apiUsage, methodsIn } from '@/lib/api-usage';
import { docsSeo, readingMinutes } from '@/lib/docs-seo';
import { articleJsonLd, pageMetadata, siteDescription } from '@/lib/metadata';
import { source } from '@/lib/source';
import { getPageImageUrl, getPageMarkdownUrl, sourceFileUrl } from '@/lib/shared';

export default async function Page(props: PageProps<'/docs/[[...slug]]'>) {
  const params = await props.params;
  const page = source.getPage(params.slug);
  if (!page) notFound();

  const MDX = page.data.body;
  const markdownUrl = getPageMarkdownUrl(page).url;
  const seo = docsSeo(page);
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
      <JsonLd
        data={articleJsonLd({
          title: seo.title,
          description: page.data.description,
          path: page.url,
          image: getPageImageUrl(page).url,
          section: seo.section,
          keywords: seo.keywords,
          breadcrumbs: seo.breadcrumbs,
        })}
      />
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
      <div className="mt-2 flex flex-wrap items-center justify-between gap-3">
        <CreatorCredit label="Better IAM is created by" />
        {page.data.lastModified ? (
          <p className="text-caption-1-regular text-text-secondary">
            Last updated{' '}
            <time dateTime={new Date(page.data.lastModified).toISOString()}>
              {new Date(page.data.lastModified).toLocaleDateString('en-US', {
                year: 'numeric',
                month: 'long',
                day: 'numeric',
                timeZone: 'UTC',
              })}
            </time>
          </p>
        ) : null}
      </div>
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

  const seo = docsSeo(page);
  const minutes = readingMinutes(await page.data.getText('processed'));
  return pageMetadata({
    title: seo.title,
    description: page.data.description ?? siteDescription,
    path: page.url,
    image: { url: getPageImageUrl(page).url, alt: seo.imageAlt },
    type: 'article',
    section: seo.section,
    keywords: seo.keywords,
    // Slack shows these under the link preview.
    labels: [
      ['Section', seo.trail.join(' / ')],
      ['Reading time', `${minutes} min`],
    ],
    alternateTypes: { 'text/markdown': getPageMarkdownUrl(page).url },
  });
}
