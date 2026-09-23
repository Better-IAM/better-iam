import type { Metadata } from 'next';
import { appName, creator, repositoryUrl, siteUrl, version } from './shared';

/**
 * Search and social metadata shared by every page: the site's title, description, and keywords, the social card
 * format, `pageMetadata()` for a page's canonical URL and Open Graph / X card tags, and the JSON-LD builders.
 */

export const siteTitle = `${appName}: identity and access management for TypeScript`;
/** The search snippet and social card text for the site (at most about 160 characters). */
export const siteDescription =
  'Open-source authentication and access management for TypeScript: passkeys, SSO, SCIM, policies, multi-tenancy, and audit logs in your own database.';
export const siteKeywords = [
  appName,
  'identity and access management',
  'IAM',
  'authentication',
  'authorization',
  'access control',
  'TypeScript',
  'Node.js',
  'RBAC',
  'ABAC',
  'policy engine',
  'multi-tenant',
  'single sign-on',
  'SSO',
  'OpenID Connect',
  'OAuth 2.0',
  'SAML',
  'SCIM',
  'passkeys',
  'WebAuthn',
  'MFA',
  'audit log',
  'open source',
];

/** The docs' five root sections, as readers see them in the sidebar, cards, and breadcrumbs. */
export const sectionNames: Record<string, string> = {
  guides: 'Guides',
  frameworks: 'Frameworks',
  federation: 'Federation',
  operations: 'Operations',
  reference: 'Reference',
};

/** Extra keywords for every page in a section. */
const sectionKeywords: Record<string, string[]> = {
  guides: ['authentication', 'authorization', 'access control'],
  frameworks: ['framework integration', 'middleware', 'route guards'],
  federation: ['identity federation', 'single sign-on', 'OpenID Connect', 'SAML', 'SCIM'],
  operations: ['deployment', 'production', 'PostgreSQL', 'SQLite'],
  reference: ['API reference', 'TypeScript API', 'REST API'],
};

/** Keywords for a docs page: its own titles and packages, its section's terms, then the core terms. */
export function docsKeywords(section: string, terms: (string | undefined)[]): string[] {
  return unique([
    ...terms,
    sectionNames[section],
    ...(sectionKeywords[section] ?? []),
    appName,
    'TypeScript',
    'identity and access management',
  ]);
}

/**
 * Social cards are 1200×630 PNGs: the 1.91:1 image Facebook, LinkedIn, X (`summary_large_image`), Slack,
 * Discord, iMessage, WhatsApp, Telegram, Bluesky, and Mastodon all render full width.
 */
export const socialImageSize = { width: 1200, height: 630 };

/** Routes of the site-wide social cards (`app/og/[image]/route.tsx`). */
export const siteImages = {
  home: { url: '/og/home.png', alt: `${appName}: identity and access management for TypeScript` },
  playground: {
    url: '/og/playground.png',
    alt: `${appName} policy playground: evaluate policy documents in the browser`,
  },
} satisfies Record<string, SocialImage>;

export interface SocialImage {
  url: string;
  alt: string;
}

/** The site's X account, for example `DOCS_X_HANDLE=@betteriam`. Unset, cards carry no `twitter:site`. */
const xHandle = normalizeHandle(process.env.DOCS_X_HANDLE);

function normalizeHandle(value: string | undefined) {
  const handle = value?.trim().replace(/^@?/, '@');
  return handle && handle.length > 1 ? handle : undefined;
}

/** Search console ownership tokens, read at build time; each tag renders only when its variable is set. */
export function siteVerification(): Metadata['verification'] {
  const google = process.env.DOCS_GOOGLE_SITE_VERIFICATION;
  const bing = process.env.DOCS_BING_SITE_VERIFICATION;
  const yandex = process.env.DOCS_YANDEX_VERIFICATION;
  if (!google && !bing && !yandex) return undefined;
  return {
    ...(google ? { google } : {}),
    ...(yandex ? { yandex } : {}),
    ...(bing ? { other: { 'msvalidate.01': bing } } : {}),
  };
}

export interface PageSeo {
  /** The document title; the root layout's template appends " | Better IAM" unless `absolute` is set. */
  title: string;
  absolute?: boolean;
  description: string;
  /** Canonical path, for example `/docs/guides/quickstart`. Left out only by the root layout's defaults. */
  path?: string;
  image: SocialImage;
  type?: 'website' | 'article';
  /** For articles: the docs section, rendered as `article:section`. */
  section?: string;
  keywords?: string[];
  /** Label and value pairs that Slack shows under the link preview (`twitter:label1` / `twitter:data1`). */
  labels?: [string, string][];
  /** Alternate representations of the page, keyed by MIME type. */
  alternateTypes?: Record<string, string>;
}

/**
 * A page's complete search and social metadata. Next.js merges metadata shallowly, so a page that sets
 * `openGraph` or `twitter` replaces the root layout's; this always returns both in full.
 */
export function pageMetadata(seo: PageSeo): Metadata {
  const image = { ...seo.image, ...socialImageSize, type: 'image/png' };
  const socialTitle = seo.absolute ? seo.title : `${seo.title} | ${appName}`;
  const labels = Object.fromEntries(
    (seo.labels ?? []).flatMap(([label, data], index) => [
      [`twitter:label${index + 1}`, label],
      [`twitter:data${index + 1}`, data],
    ]),
  );
  return {
    title: seo.absolute ? { absolute: seo.title } : seo.title,
    description: seo.description,
    keywords: seo.keywords ?? siteKeywords,
    ...(seo.path
      ? {
          alternates: {
            canonical: seo.path,
            ...(seo.alternateTypes ? { types: seo.alternateTypes } : {}),
          },
        }
      : {}),
    openGraph: {
      type: seo.type ?? 'website',
      siteName: appName,
      locale: 'en_US',
      ...(seo.path ? { url: seo.path } : {}),
      title: socialTitle,
      description: seo.description,
      images: [image],
      ...(seo.type === 'article' ? { authors: [creator], section: seo.section } : {}),
    },
    twitter: {
      card: 'summary_large_image',
      title: socialTitle,
      description: seo.description,
      images: [image],
      ...(xHandle ? { site: xHandle, creator: xHandle } : {}),
    },
    ...(seo.labels?.length ? { other: labels } : {}),
  };
}

const absolute = (path: string) => new URL(path, siteUrl).toString();

const ids = {
  website: `${siteUrl}/#website`,
  software: `${siteUrl}/#software`,
  creator: `${siteUrl}/#creator`,
};

/** The creator, the site, and the software it documents, as one schema.org graph for the home page. */
export function siteJsonLd() {
  return {
    '@context': 'https://schema.org',
    '@graph': [
      { '@type': 'Person', '@id': ids.creator, name: creator },
      {
        '@type': 'WebSite',
        '@id': ids.website,
        url: absolute('/'),
        name: appName,
        description: siteDescription,
        inLanguage: 'en',
        publisher: { '@id': ids.creator },
        about: { '@id': ids.software },
      },
      {
        '@type': 'SoftwareApplication',
        '@id': ids.software,
        name: appName,
        description: siteDescription,
        url: absolute('/'),
        image: absolute(siteImages.home.url),
        applicationCategory: 'DeveloperApplication',
        applicationSubCategory: 'Identity and access management',
        operatingSystem: 'Node.js',
        softwareVersion: version,
        license: 'https://www.apache.org/licenses/LICENSE-2.0',
        isAccessibleForFree: true,
        offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
        author: { '@id': ids.creator },
        ...(repositoryUrl ? { sameAs: [repositoryUrl] } : {}),
        keywords: siteKeywords.join(', '),
      },
    ],
  };
}

/** A docs page as a TechArticle, with its breadcrumb trail. */
export function articleJsonLd(article: {
  title: string;
  description?: string;
  path: string;
  image: string;
  section: string;
  keywords: string[];
  breadcrumbs: { name: string; path: string }[];
}) {
  return {
    '@context': 'https://schema.org',
    '@graph': [
      {
        '@type': 'TechArticle',
        headline: article.title,
        description: article.description,
        url: absolute(article.path),
        mainEntityOfPage: absolute(article.path),
        image: absolute(article.image),
        articleSection: article.section,
        keywords: article.keywords.join(', '),
        inLanguage: 'en',
        author: { '@type': 'Person', '@id': ids.creator, name: creator },
        publisher: { '@type': 'Person', '@id': ids.creator, name: creator },
        isPartOf: { '@type': 'WebSite', '@id': ids.website, name: appName, url: absolute('/') },
        about: { '@type': 'SoftwareApplication', '@id': ids.software, name: appName },
      },
      {
        '@type': 'BreadcrumbList',
        itemListElement: article.breadcrumbs.map((crumb, index) => ({
          '@type': 'ListItem',
          position: index + 1,
          name: crumb.name,
          item: absolute(crumb.path),
        })),
      },
    ],
  };
}

function unique(values: (string | undefined)[]): string[] {
  const seen = new Set<string>();
  const result: string[] = [];
  for (const value of values) {
    const key = value?.toLowerCase();
    if (!value || !key || seen.has(key)) continue;
    seen.add(key);
    result.push(value);
  }
  return result;
}
