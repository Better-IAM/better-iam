import { mkdir, mkdtemp, readdir, readFile, writeFile, rm } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import { runPnpm } from './tooling.mjs';
const root = resolve(import.meta.dirname, '..');
const files = (await readdir(resolve(root, 'artifacts'))).filter((f) => f.endsWith('.tgz'));
const expected = (await readdir(resolve(root, 'packages'), { withFileTypes: true })).filter(
  (entry) => entry.isDirectory(),
).length;
if (files.length < expected) throw new Error(`Run pack:all first; expected ${expected} archives`);
const workRoot = resolve(root, 'work');
await mkdir(workRoot, { recursive: true });
const directory = await mkdtemp(join(workRoot, 'packed-'));
const deps = {},
  overrides = {};
for (const folder of await readdir(resolve(root, 'packages'))) {
  const p = JSON.parse(await readFile(resolve(root, 'packages', folder, 'package.json'), 'utf8'));
  const filename = `${p.name.replace('@', '').replace('/', '-')}-${p.version}.tgz`;
  deps[p.name] = `file:${resolve(root, 'artifacts', filename).replaceAll('\\', '/')}`;
  overrides[p.name] = deps[p.name];
}
await writeFile(
  join(directory, 'package.json'),
  JSON.stringify({ private: true, type: 'module', dependencies: deps }),
);
await writeFile(
  join(directory, 'pnpm-workspace.yaml'),
  'allowBuilds:\n  argon2: true\n  better-sqlite3: true\n  esbuild: true\noverrides:\n' +
    Object.entries(overrides)
      .map(([name, value]) => `  ${JSON.stringify(name)}: ${JSON.stringify(value)}`)
      .join('\n') +
    '\n',
);
const run = (command, args) => {
  const result = spawnSync(command, args, { cwd: directory, stdio: 'inherit', shell: false });
  if (result.status !== 0) throw new Error(`Packed consumer failed: ${command}`);
};
try {
  runPnpm(['install', '--ignore-scripts=false'], { cwd: directory });
  await writeFile(
    join(directory, 'smoke.mjs'),
    `import { betterIam, definePolicy } from 'better-iam';\nimport { sqliteAdapter } from 'better-iam/adapter-sqlite';\nimport { createIamClient } from 'better-iam/client';\nconst database=sqliteAdapter({filename:':memory:'});const iam=betterIam({database,secret:'packed-smoke-test-secret-32-characters',baseURL:'http://localhost:3000'});await iam.initialize();const root=await iam.bootstrap({email:'root@example.test',name:'Root',password:'Strong packed package password!'});if(!root.identity.rootAdmin||typeof createIamClient!=='function'||!definePolicy({version:1,statements:[{effect:'allow',actions:['test:read'],resources:['*']}]}))throw new Error('Invalid packaged API');await database.close();console.log('Packed consumer imports, SQLite migration, and root bootstrap passed.');\n`,
  );
  run(process.execPath, ['smoke.mjs']);
  runPnpm(['exec', 'better-iam', '--help'], { cwd: directory });
} finally {
  if (!resolve(directory).startsWith(workRoot + sep))
    throw new Error('Refusing cleanup outside work directory');
  await rm(directory, { recursive: true, force: true });
}
