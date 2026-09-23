import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [sveltekit()],
  // One copy of SvelteKit and Svelte for the app and @better-iam/svelte, so `redirect()`/`error()` are recognised.
  resolve: { dedupe: ['@sveltejs/kit', 'svelte'] },
  // The IAM server and its native modules (argon2, better-sqlite3) load from node_modules at runtime.
  ssr: { external: ['@better-iam/server', '@better-iam/adapter-sqlite'] },
});
