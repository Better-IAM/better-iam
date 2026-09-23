import { docsKeywords, sectionNames } from './metadata';
import { appName } from './shared';
import { source, type DocsPage } from './source';

/**
 * What search engines and link previews learn about a docs page: its document title (frontmatter `metaTitle`
 * when the sidebar title is too terse out of context, "{group} API" for API reference groups), where it sits,
 * its keywords, and its breadcrumb trail. Shared by the page's metadata and its social card.
 */
export function docsSeo(page: DocsPage) {
  const [sectionSlug = ''] = page.slugs;
  const section = sectionNames[sectionSlug] ?? 'Documentation';
  const isApiGroup =
    page.slugs.length === 3 && page.slugs[0] === 'reference' && page.slugs[1] === 'api';
  const title = page.data.metaTitle ?? (isApiGroup ? `${page.data.title} API` : page.data.title);

  // Folder landing pages between the section root and this page.
  const ancestors = page.slugs
    .slice(0, -1)
    .map((_, index) => source.getPage(page.slugs.slice(0, index + 1)))
    .filter((ancestor): ancestor is DocsPage => ancestor !== undefined);
  const parent = ancestors.length > 1 ? ancestors.at(-1) : undefined;
  const trail = parent ? [section, parent.data.title] : [section];

  // Home, the section's landing page, folder landing pages, then the page (a section root is named after its section).
  const breadcrumbs = [
    { name: appName, path: '/' },
    ...ancestors.map((ancestor, index) => ({
      name: index === 0 ? section : ancestor.data.title,
      path: ancestor.url,
    })),
    { name: page.slugs.length === 1 ? section : page.data.title, path: page.url },
  ];

  return {
    title,
    section,
    trail,
    keywords: docsKeywords(sectionSlug, [
      title,
      page.data.title,
      ...ancestors.slice(1).map((ancestor) => ancestor.data.title),
      ...(page.data.packages ?? []),
    ]),
    breadcrumbs,
    imageAlt: `${trail.join(' / ')}: ${title}. ${appName} documentation.`,
  };
}

/** Minutes to read a page's Markdown at about 230 words a minute, for link previews. */
export function readingMinutes(markdown: string) {
  const words = markdown
    .replace(/```[\s\S]*?```/g, ' ')
    .split(/\s+/)
    .filter(Boolean).length;
  return Math.max(1, Math.round(words / 230));
}
