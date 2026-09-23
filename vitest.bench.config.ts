import { defineConfig } from 'vitest/config';
import base from './vitest.config.js';

/** Scale benchmarks (`pnpm bench:scale`): same aliases as the test suite, run on demand only. */
export default defineConfig({
  ...base,
  test: {
    ...base.test,
    include: ['tests/bench/**/*.bench.ts'],
    testTimeout: 30 * 60_000,
    hookTimeout: 30 * 60_000,
  },
});
