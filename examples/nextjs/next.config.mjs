/** @type {import('next').NextConfig} */
export default {
  // The IAM server and its native dependencies run as plain Node modules; @better-iam/next is bundled with the app.
  serverExternalPackages: [
    '@better-iam/server',
    '@better-iam/auth',
    '@better-iam/adapter-sqlite',
    'argon2',
    'better-sqlite3',
    'otplib',
  ],
  experimental: { authInterrupts: true },
};
