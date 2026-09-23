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
};

export default config;
