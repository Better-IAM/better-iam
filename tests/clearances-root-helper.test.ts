import { readFileSync, readdirSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import type { Decision } from '@better-iam/core';
import {
  decideOn,
  isRootOverride,
  type PreparedDecision,
} from '../packages/server/src/decisions.js';

/**
 * Security clearances turn root's override into an evaluator (mandatory access control still applies to it) instead
 * of a fixed decision. Code that recognizes root by reading `prepared.fixed.reason === 'ROOT_OVERRIDE'` would then
 * silently stop recognizing it and fail open (cross-tenant root SSH certificates and their sweep, credential requests,
 * usage and audit), so `isRootOverride` in decisions.ts is the only place allowed to read a fixed decision's reason.
 */

const repository = fileURLToPath(new URL('..', import.meta.url));
const skipped = new Set(['node_modules', 'dist', '.next', '.turbo', 'coverage', 'generated']);

function sources(directory: string, into: string[] = []): string[] {
  let entries;
  try {
    entries = readdirSync(directory, { withFileTypes: true });
  } catch {
    return into;
  }
  for (const entry of entries) {
    if (skipped.has(entry.name)) continue;
    const path = join(directory, entry.name);
    if (entry.isDirectory()) sources(path, into);
    else if (/\.(ts|tsx|mts|cts)$/.test(entry.name) && !entry.name.endsWith('.d.ts'))
      into.push(path);
  }
  return into;
}

/** Every TypeScript source of the packages and apps, by repository-relative path with forward slashes. */
function sourceFiles(): Map<string, string> {
  const files = new Map<string, string>();
  for (const area of ['packages', 'apps'])
    for (const project of readdirSync(join(repository, area), { withFileTypes: true }))
      if (project.isDirectory())
        for (const path of sources(join(repository, area, project.name, 'src')))
          files.set(relative(repository, path).split(sep).join('/'), readFileSync(path, 'utf8'));
  return files;
}

const helperFile = 'packages/server/src/decisions.ts';

describe('root override recognition', () => {
  const files = sourceFiles();

  it('scans the server sources', () => {
    expect(files.has(helperFile)).toBe(true);
    expect(
      [...files.keys()].filter((path) => path.startsWith('packages/server/src/')).length,
    ).toBeGreaterThan(50);
  });

  it('reads fixed.reason === ROOT_OVERRIDE only inside isRootOverride', () => {
    const pattern = /\.fixed\.reason\s*[!=]==?\s*['"`]ROOT_OVERRIDE['"`]/g;
    const hits = [...files].flatMap(([path, text]) =>
      [...text.matchAll(pattern)].map((match) => ({ path, index: match.index })),
    );
    expect(hits.map((hit) => hit.path)).toEqual([helperFile]);
    const helper = files.get(helperFile)!;
    const start = helper.indexOf('export function isRootOverride(');
    expect(start).toBeGreaterThan(-1);
    const end = helper.indexOf('\n}\n', start);
    expect(hits[0]!.index).toBeGreaterThan(start);
    expect(hits[0]!.index).toBeLessThan(end);
  });

  it('reads no fixed decision reason outside decisions.ts', () => {
    const offenders = [...files]
      .filter(
        ([path, text]) =>
          path !== helperFile && /\.fixed\s*\.\s*reason\b|\.fixed\?\.reason\b/.test(text),
      )
      .map(([path]) => path);
    expect(offenders).toEqual([]);
  });

  it('never recognizes root by the shape of a prepared decision alone', () => {
    // `'fixed' in prepared` with no further test (a negation used as "not root") is how the SSH grant deadline once
    // told root apart; under clearances root is no longer fixed.
    const offenders = [...files]
      .filter(([, text]) => /!\s*\(\s*'fixed'\s+in\s+\w+\s*\)/.test(text))
      .map(([path]) => path);
    expect(offenders).toEqual([]);
  });
});

describe('isRootOverride and decideOn', () => {
  const override: Decision = { allowed: true, reason: 'ROOT_OVERRIDE', matched: [] };
  const refusal: Decision = { allowed: false, reason: 'CLEARANCE_REQUIRED', matched: [] };
  const resource = { tenantId: 't', type: 'document', id: 'd' };

  it('recognizes the fixed and the evaluator forms of root', () => {
    expect(isRootOverride({ fixed: override })).toBe(true);
    expect(
      isRootOverride({ fixed: { allowed: false, reason: 'TENANT_MISMATCH', matched: [] } }),
    ).toBe(false);
    const root: PreparedDecision = { rootOverride: true, evaluate: () => refusal };
    expect(isRootOverride(root)).toBe(true);
    expect(isRootOverride({ evaluate: () => override })).toBe(false);
  });

  it('decides a fixed decision as itself and an evaluator per resource and action', () => {
    expect(decideOn({ fixed: override }, resource)).toBe(override);
    const seen: Array<string | undefined> = [];
    const prepared: PreparedDecision = {
      rootOverride: true,
      evaluate: (_resource, action) => {
        seen.push(action);
        return action === 'documents:read' ? refusal : override;
      },
    };
    expect(decideOn(prepared, resource, 'documents:read')).toBe(refusal);
    expect(decideOn(prepared, resource, 'iam:resources:read')).toBe(override);
    expect(decideOn(prepared, resource).allowed).toBe(true);
    expect(seen).toEqual(['documents:read', 'iam:resources:read', undefined]);
  });
});
