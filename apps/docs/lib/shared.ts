import { createGetUrl } from 'fumadocs-core/source';

export const appName = 'Better IAM';
export const appDescription =
  'Embeddable authentication, identity provisioning, and access management for TypeScript applications.';
export const version = '0.1.0';

export const docsRoute = '/docs';
export const docsImageRoute = '/og/docs';
export const docsContentRoute = '/llms.mdx/docs';

/** Canonical origin used for metadata, sitemap and llms.txt links; on Railway, the service's public domain. */
export const siteUrl = (
  process.env.DOCS_SITE_URL ??
  (process.env.RAILWAY_PUBLIC_DOMAIN
    ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
    : 'http://localhost:4000')
).replace(/\/$/, '');

/**
 * The public repository, for "Edit this page", source-file, and issue links, for example
 * `NEXT_PUBLIC_DOCS_REPOSITORY_URL=https://github.com/acme/better-iam`. Unset (the default), the site shows no
 * repository links at all rather than guessing a URL that may not exist.
 */
export const repositoryUrl =
  process.env.NEXT_PUBLIC_DOCS_REPOSITORY_URL?.replace(/\/$/, '') || undefined;
export const repositoryBranch = process.env.NEXT_PUBLIC_DOCS_REPOSITORY_BRANCH || 'main';

/** A link to a file in the repository, or undefined when no repository is configured. */
export function sourceFileUrl(path: string): string | undefined {
  return repositoryUrl ? `${repositoryUrl}/blob/${repositoryBranch}/${path}` : undefined;
}

/** A prefilled "new issue" link, or undefined when no repository is configured. */
export function newIssueUrl(title: string, body: string): string | undefined {
  if (!repositoryUrl) return undefined;
  return `${repositoryUrl}/issues/new?${new URLSearchParams({ title, body, labels: 'documentation' })}`;
}

const getContentUrl = createGetUrl(docsContentRoute);

export function getPageMarkdownUrl(page: { slugs: string[]; locale?: string }) {
  const segments = [...page.slugs, 'content.md'];

  return { segments, url: getContentUrl(segments, page.locale) };
}

const getImageUrl = createGetUrl(docsImageRoute);

export function getPageImageUrl(page: { slugs: string[]; locale?: string }) {
  const segments = [...page.slugs, 'image.png'];

  return { segments, url: getImageUrl(segments, page.locale) };
}
