import type { NextConfig } from 'next';

const config: NextConfig = {
  // The IAM server, its adapters, and their native drivers run in Node.js; never bundle them.
  serverExternalPackages: [
    'better-iam',
    '@better-iam/core',
    '@better-iam/auth',
    '@better-iam/server',
    '@better-iam/adapter-sqlite',
    '@better-iam/adapter-postgres',
    '@better-iam/cli',
    'better-sqlite3',
    'argon2',
    'kysely',
    'pg',
  ],
  poweredByHeader: false,
  // Several dev servers may run from this checkout at once; give each its own build directory.
  distDir: process.env.NEXT_DIST_DIR ?? '.next',
  // An administration console must never be framed (clickjacking of approve/delete buttons), sniffed into another
  // content type, or leak its URLs (sign-in, reset and invitation tokens) to other sites through the Referer.
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'Content-Security-Policy', value: "frame-ancestors 'none'; base-uri 'self'; object-src 'none'" },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'no-referrer' },
        ],
      },
    ];
  },
};

export default config;
