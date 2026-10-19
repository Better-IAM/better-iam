// spec/api/openapi.json: the OpenAPI 3.1 document of the docs site, built by apps/docs/scripts/generate.mjs (its `api`
// and `openapi` steps) into a temporary directory, so the docs site's own files are untouched. The external
// documentation links point at the public site.
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { root } from './util.mjs';

export const docsSiteUrl = 'https://better-iam.com';

export async function buildOpenApi() {
  const temp = await mkdtemp(join(tmpdir(), 'better-iam-spec-openapi-'));
  try {
    await new Promise((resolve, reject) => {
      const child = spawn(
        process.execPath,
        [join(root, 'apps/docs/scripts/generate.mjs'), 'api', 'openapi'],
        {
          cwd: root,
          env: {
            ...process.env,
            DOCS_GENERATED_DIR: join(temp, 'generated'),
            DOCS_PUBLIC_DIR: join(temp, 'public'),
            DOCS_SITE_URL: docsSiteUrl,
          },
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      );
      let log = '';
      child.stdout.on('data', (chunk) => (log += chunk));
      child.stderr.on('data', (chunk) => (log += chunk));
      child.on('error', reject);
      child.on('exit', (code) =>
        code === 0 && !log.includes('✗')
          ? resolve()
          : reject(new Error(`docs generator failed:\n${log}`)),
      );
    });
    const text = await readFile(join(temp, 'public', 'openapi.json'), 'utf8');
    return JSON.parse(text);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
}

export async function generateOpenApi(output, openapi) {
  // Same document and member order as the docs site's /openapi.json; only the indentation differs.
  output.add('api/openapi.json', `${JSON.stringify(openapi, null, 2)}\n`);
  return `openapi.json (${Object.keys(openapi.paths).length} operations, ${Object.keys(openapi.components.schemas).length} schemas)`;
}
