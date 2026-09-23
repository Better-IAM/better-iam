import { createMDX } from 'fumadocs-mdx/next';

const withMDX = createMDX({ macro: false });

/** @type {import('next').NextConfig} */
const config = {
  reactStrictMode: true,
  // Concurrent `next dev` servers must not share one output directory (see the console's next.config.ts).
  distDir: process.env.NEXT_DIST_DIR || '.next',
  async redirects() {
    return [{ source: '/docs', destination: '/docs/guides', permanent: false }];
  },
};

export default withMDX(config);
