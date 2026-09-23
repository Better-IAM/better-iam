import { readdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
const version = process.argv[2];
if (!/^\d+\.\d+\.\d+(?:-[a-zA-Z0-9.-]+)?$/.test(version ?? ''))
  throw new Error('Usage: node scripts/release-version.mjs VERSION');
const root = resolve(import.meta.dirname, '..');
for (const name of await readdir(resolve(root, 'packages'))) {
  const path = resolve(root, 'packages', name, 'package.json');
  const pkg = JSON.parse(await readFile(path, 'utf8'));
  pkg.version = version;
  await writeFile(path, JSON.stringify(pkg, null, 2) + '\n');
}
console.log(
  `Updated package metadata to ${version}; review changes, update changelog, and run pnpm install and pnpm check before packing.`,
);
