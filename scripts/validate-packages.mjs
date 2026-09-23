import { readdir, readFile, access } from 'node:fs/promises';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { publint } from 'publint';
const root = resolve(import.meta.dirname, '..');
let failures = 0;
const versions = new Set();
for (const name of await readdir(resolve(root, 'packages'))) {
  const directory = resolve(root, 'packages', name);
  const manifest = JSON.parse(await readFile(resolve(directory, 'package.json'), 'utf8'));
  versions.add(manifest.version);
  if (manifest.license !== 'Apache-2.0' || manifest.private)
    throw new Error(`${name}: expected publishable Apache-2.0 package`);
  if (manifest.publishConfig?.access !== 'public' || !manifest.repository?.directory)
    throw new Error(`${name}: expected publishConfig.access "public" and repository.directory`);
  for (const entry of Object.values(manifest.exports))
    for (const target of Object.values(entry)) await access(resolve(directory, target));
  const result = await publint({ pkgDir: directory });
  for (const message of result.messages) {
    if (message.type === 'error') {
      failures++;
      console.error(name, message.code);
    } else console.log(name, message.code);
  }
}
if (versions.size !== 1) throw new Error('Package versions are not synchronized');
if (failures) throw new Error(`${failures} package validation errors`);
console.log('All packages have valid exports, synchronized versions, and publishable metadata.');
