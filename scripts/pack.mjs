import { mkdir, readdir, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { runPnpm } from './tooling.mjs';
const root = resolve(import.meta.dirname, '..');
const destination = resolve(root, 'artifacts');
await mkdir(destination, { recursive: true });
for (const name of await readdir(resolve(root, 'packages'))) {
  runPnpm(['pack', '--pack-destination', destination], { cwd: resolve(root, 'packages', name) });
}
console.log(`Packed packages into ${destination}. No packages were published.`);
