import { readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { runPnpm } from './tooling.mjs';
const root = resolve(import.meta.dirname, '..');
for (const archive of (await readdir(resolve(root, 'artifacts'))).filter((name) =>
  name.endsWith('.tgz'),
)) {
  runPnpm(
    ['exec', 'attw', resolve(root, 'artifacts', archive), '--profile', 'esm-only', '--quiet'],
    { cwd: root },
  );
}
console.log('Packed TypeScript exports pass ESM and bundler resolution checks.');
