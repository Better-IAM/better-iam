import { createMDX } from 'fumadocs-mdx/next';

const withMDX = createMDX({ macro: false });

// The canonical origin, resolved the same way as `siteUrl` in lib/shared.ts (read at build time).
const siteUrl =
  process.env.DOCS_SITE_URL ??
  (process.env.RAILWAY_PUBLIC_DOMAIN ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}` : undefined);
const canonical = siteUrl ? new URL(siteUrl) : undefined;
const escapeHost = (host) => host.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/**
 * One address per page for search engines: `www.` and Railway's generated `*.up.railway.app` hosts redirect
 * permanently to the canonical origin. Railway's health check (`healthcheck.railway.app`) matches neither.
 */
function canonicalHostRedirects() {
  if (!canonical || canonical.hostname === 'localhost') return [];
  const destination = `${canonical.origin}/:path*`;
  const self = [{ type: 'host', value: escapeHost(canonical.hostname) }];
  return [
    {
      source: '/:path*',
      has: [{ type: 'host', value: `www\\.${escapeHost(canonical.hostname)}` }],
      destination,
      permanent: true,
    },
    {
      source: '/:path*',
      has: [{ type: 'host', value: '.+\\.up\\.railway\\.app' }],
      missing: self,
      destination,
      permanent: true,
    },
  ];
}

/** @type {import('next').NextConfig} */
const config = {
  reactStrictMode: true,
  // Concurrent `next dev` servers must not share one output directory (see the console's next.config.ts).
  distDir: process.env.NEXT_DIST_DIR || '.next',
  async redirects() {
    return [
      ...canonicalHostRedirects(),
      { source: '/docs', destination: '/docs/guides', permanent: true },
    ];
  },
  async headers() {
    // Plain-text copies of the whole site for AI tools; search results should show the pages themselves.
    return ['/llms.txt', '/llms-full.txt'].map((source) => ({
      source,
      headers: [{ key: 'X-Robots-Tag', value: 'noindex' }],
    }));
  },
};

export default withMDX(config);
