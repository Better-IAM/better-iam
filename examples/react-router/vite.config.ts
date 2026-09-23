import { reactRouter } from '@react-router/dev/vite';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [reactRouter()],
  // One copy of React Router and React for the app and @better-iam/react-router / @better-iam/react.
  resolve: { dedupe: ['react-router', 'react', 'react-dom'] },
  // The IAM server and its native modules (argon2, better-sqlite3) load from node_modules at runtime.
  ssr: { external: ['@better-iam/server', '@better-iam/adapter-sqlite'] },
});
