export default defineNuxtConfig({
  compatibilityDate: '2026-09-01',
  modules: ['@better-iam/nuxt'],
  betterIam: {
    // server/iam.ts exports the betterIam() instance; the module mounts its API at /api/iam.
    instance: '~~/server/iam',
    loginPath: '/login',
  },
  // Workspace packages are bundled here (they are symlinks, not node_modules); Better IAM targets Node 22.
  nitro: { esbuild: { options: { target: 'node22' } } },
  devtools: { enabled: false },
  telemetry: false,
});
