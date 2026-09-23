import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';
export default defineConfig({
  // NestJS decorators (tests/nestjs.test.ts) are the legacy TypeScript form.
  esbuild: { jsx: 'automatic', tsconfigRaw: { compilerOptions: { experimentalDecorators: true } } },
  test: {
    include: ['tests/**/*.test.ts', 'tests/**/*.test.tsx'],
    testTimeout: 30000,
    hookTimeout: 30000,
    fileParallelism: false,
  },
  resolve: {
    alias: {
      '@better-iam/react': fileURLToPath(
        new URL('./packages/react/src/index.tsx', import.meta.url),
      ),
      '@better-iam/next': fileURLToPath(new URL('./packages/next/src/index.ts', import.meta.url)),
      '@better-iam/vue': fileURLToPath(new URL('./packages/vue/src/index.ts', import.meta.url)),
      '@better-iam/nuxt/h3': fileURLToPath(new URL('./packages/nuxt/src/h3.ts', import.meta.url)),
      '@better-iam/svelte/kit': fileURLToPath(
        new URL('./packages/svelte/src/kit.ts', import.meta.url),
      ),
      '@better-iam/svelte': fileURLToPath(
        new URL('./packages/svelte/src/index.ts', import.meta.url),
      ),
      '@better-iam/react-router': fileURLToPath(
        new URL('./packages/react-router/src/index.ts', import.meta.url),
      ),
      '@better-iam/middleware/express': fileURLToPath(
        new URL('./packages/middleware/src/express.ts', import.meta.url),
      ),
      '@better-iam/middleware/hono': fileURLToPath(
        new URL('./packages/middleware/src/hono.ts', import.meta.url),
      ),
      '@better-iam/middleware/fastify': fileURLToPath(
        new URL('./packages/middleware/src/fastify.ts', import.meta.url),
      ),
      '@better-iam/middleware': fileURLToPath(
        new URL('./packages/middleware/src/index.ts', import.meta.url),
      ),
      '@better-iam/mcp': fileURLToPath(new URL('./packages/mcp/src/index.ts', import.meta.url)),
      '@better-iam/a2a': fileURLToPath(new URL('./packages/a2a/src/index.ts', import.meta.url)),
      '@better-iam/client/session': fileURLToPath(
        new URL('./packages/client/src/session.ts', import.meta.url),
      ),
      '@better-iam/nestjs/testing': fileURLToPath(
        new URL('./packages/nestjs/src/testing.ts', import.meta.url),
      ),
      '@better-iam/nestjs': fileURLToPath(
        new URL('./packages/nestjs/src/index.ts', import.meta.url),
      ),
      // Listed before the package entry: string aliases also match `@better-iam/server/...` subpaths.
      '@better-iam/server/session-tokens': fileURLToPath(
        new URL('./packages/server/src/session-tokens.ts', import.meta.url),
      ),
      '@better-iam/server/assertions': fileURLToPath(
        new URL('./packages/server/src/assertions.ts', import.meta.url),
      ),
      '@better-iam/core/conformance': fileURLToPath(
        new URL('./packages/core/src/conformance.ts', import.meta.url),
      ),
      '@better-iam/core': fileURLToPath(new URL('./packages/core/src/index.ts', import.meta.url)),
      '@better-iam/auth': fileURLToPath(new URL('./packages/auth/src/index.ts', import.meta.url)),
      '@better-iam/server': fileURLToPath(
        new URL('./packages/server/src/index.ts', import.meta.url),
      ),
      '@better-iam/oauth': fileURLToPath(new URL('./packages/oauth/src/index.ts', import.meta.url)),
      '@better-iam/saml': fileURLToPath(new URL('./packages/saml/src/index.ts', import.meta.url)),
      '@better-iam/scim': fileURLToPath(new URL('./packages/scim/src/index.ts', import.meta.url)),
      '@better-iam/adapter-postgres': fileURLToPath(
        new URL('./packages/adapter-postgres/src/index.ts', import.meta.url),
      ),
      '@better-iam/adapter-sqlite': fileURLToPath(
        new URL('./packages/adapter-sqlite/src/index.ts', import.meta.url),
      ),
      '@better-iam/adapter-libsql': fileURLToPath(
        new URL('./packages/adapter-libsql/src/index.ts', import.meta.url),
      ),
      '@better-iam/client': fileURLToPath(
        new URL('./packages/client/src/index.ts', import.meta.url),
      ),
      '@better-iam/cli': fileURLToPath(new URL('./packages/cli/src/index.ts', import.meta.url)),
      '@better-iam/projects': fileURLToPath(
        new URL('./packages/projects/src/index.ts', import.meta.url),
      ),
    },
  },
});
