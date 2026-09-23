import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

describe('browser package isolation', () => {
  it('bundles the client without Node, server code, cryptography, or database drivers', async () => {
    const result = await build({
      entryPoints: [fileURLToPath(new URL('../packages/client/src/index.ts', import.meta.url))],
      platform: 'browser',
      target: ['es2022'],
      bundle: true,
      format: 'esm',
      write: false,
      metafile: true,
    });
    const inputs = Object.keys(result.metafile!.inputs);
    expect(inputs).toHaveLength(1);
    expect(inputs[0]).toMatch(/client[/\\]src[/\\]index\.ts$/);
    expect(result.outputFiles[0]!.text).toContain('createIamClient');
    expect(result.outputFiles[0]!.text).not.toMatch(/node:|argon2|better-sqlite3|oidc-provider/);
  });

  it('keeps optional passkey browser helpers separate from the authentication server', async () => {
    const result = await build({
      entryPoints: [fileURLToPath(new URL('../packages/client/src/passkeys.ts', import.meta.url))],
      platform: 'browser',
      target: ['es2022'],
      bundle: true,
      format: 'esm',
      write: false,
      metafile: true,
    });
    const inputs = Object.keys(result.metafile!.inputs);
    expect(
      inputs.some((input) => input.includes('@simplewebauthn') && input.includes('browser')),
    ).toBe(true);
    expect(
      inputs.some((input) =>
        /packages[/\\](server|auth|adapter-postgres|adapter-sqlite)[/\\]/.test(input),
      ),
    ).toBe(false);
    expect(inputs.some((input) => input.includes('@simplewebauthn/server'))).toBe(false);
    expect(result.outputFiles[0]!.text).toContain('startRegistration');
  });
});
