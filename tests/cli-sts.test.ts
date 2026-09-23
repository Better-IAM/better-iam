import { createRequire } from 'node:module';
import { mkdir, mkdtemp, writeFile, rm } from 'node:fs/promises';
import { resolve, join, sep } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runCli } from '@better-iam/cli';
import type { AuditEvent } from '@better-iam/core';
import { betterIam, type BetterIamOptions, type CallerIdentity } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { generateTestKey } from './support/jwt-keys.js';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const work = resolve('work');
const created: string[] = [];
afterEach(async () => {
  for (const folder of created.splice(0)) {
    if (!resolve(folder).startsWith(work + sep)) throw new Error('Unsafe test cleanup');
    await rm(folder, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 }).catch(
      () => undefined,
    );
  }
});
const secret = 'cli-sts-testing-secret-with-32-characters';
const issuer = 'http://localhost:3000/api/iam';

/**
 * `better-iam whoami`: prints sts.getCallerIdentity for BETTER_IAM_TOKEN, for every kind of credential a CLI holds
 * (API keys, session tokens, session JWTs), without a permission or an audit event.
 */
describe('whoami CLI', () => {
  it('prints the caller identity of API keys, session tokens and session JWTs', async () => {
    await mkdir(work, { recursive: true });
    const folder = await mkdtemp(join(work, 'cli-sts-test-'));
    created.push(folder);
    const config = join(folder, 'better-iam.config.mjs'),
      filename = join(folder, 'iam.db'),
      output: string[] = [];
    const key = generateTestKey('EdDSA', 'cli-k1');
    const options = {
      secret,
      baseURL: 'http://localhost:3000',
      permissions: { actions: ['documents:read'] },
      sts: { jwt: { signingKeys: [key.privateJwk] } },
    };
    await writeFile(
      config,
      `import { sqliteAdapter } from '@better-iam/adapter-sqlite';\nconst options = ${JSON.stringify(options)};\nexport default () => ({ ...options, database: sqliteAdapter({ filename: ${JSON.stringify(filename)} }) });\n`,
    );
    const io = {
      out: (message: string) => output.push(message),
      env: {
        BETTER_IAM_ROOT_EMAIL: 'root@example.test',
        BETTER_IAM_ROOT_NAME: 'Root',
        BETTER_IAM_ROOT_PASSWORD: 'a strong cli root password',
      } as NodeJS.ProcessEnv,
    };
    await runCli(['migrate', '--config', config], io);
    await runCli(['bootstrap', '--config', config], io);
    const tenantId = JSON.parse(output.at(-1)!).tenant.id as string;
    const open = () =>
      betterIam({
        ...(options as unknown as BetterIamOptions),
        database: sqliteAdapter({ filename }),
      });
    let iam = open();
    let rootToken: string, apiKey: string, sessionToken: string, sessionJwt: string;
    let accountId: string, rootId: string, sessionTokenId: string, auditCount: number;
    try {
      const challenge = await iam.api.auth.signIn({
        tenantId,
        email: 'root@example.test',
        password: 'a strong cli root password',
      });
      if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
      const enrollment = await iam.api.auth.beginMfa({ tenantId, challenge: challenge.challenge });
      const root = await iam.api.auth.confirmMfa({
        credential: { tenantId, challenge: challenge.challenge },
        code: authenticator.generate(enrollment.secret),
      });
      rootToken = root.token;
      rootId = (await iam.api.auth.getSession({ token: rootToken })).identity.id;
      const credential = { token: rootToken };
      const account = await iam.api.serviceAccounts.create(credential, { tenantId, name: 'ci' });
      accountId = account.id;
      const minter = await iam.api.roles.create(credential, {
        tenantId,
        name: 'Token minter',
        permissions: ['iam:session-tokens:create'],
      });
      await iam.api.bindings.create(credential, {
        tenantId,
        roleId: minter.id,
        subjectType: 'identity',
        subjectId: account.id,
      });
      apiKey = (await iam.api.credentials.create(credential, { tenantId, identityId: account.id }))
        .token;
      const minted = await iam.api.sts.getSessionToken(credential, { sessionName: 'cli-check' });
      sessionToken = minted.token;
      sessionTokenId = minted.session.id;
      sessionJwt = (await iam.api.sts.getSessionToken({ token: apiKey }, { format: 'jwt' })).token;
      auditCount = (await iam.store.find<AuditEvent>('audit', { tenantId })).length;
    } finally {
      await iam.store.close();
    }
    const as = (token: string) => ({ ...io, env: { ...io.env, BETTER_IAM_TOKEN: token } });
    const whoami = async (token: string): Promise<CallerIdentity> => {
      await runCli(['whoami', '--config', config], as(token));
      const printed = output.at(-1)!;
      for (const field of ['tokenHash', 'uniqueKey', 'policy', 'sourceSessionId'])
        expect(printed).not.toContain(`"${field}"`);
      expect(printed).not.toContain(token);
      return JSON.parse(printed) as CallerIdentity;
    };

    expect(await whoami(apiKey)).toMatchObject({
      identityId: accountId,
      identityTenantId: tenantId,
      identityKind: 'service',
      tenantId,
      sessionKind: 'api-key',
      format: 'opaque',
      mfa: false,
    });
    const token = await whoami(sessionToken);
    expect(token).toMatchObject({
      identityId: rootId,
      identityKind: 'user',
      tenantId,
      sessionId: sessionTokenId,
      sessionKind: 'session-token',
      sessionName: 'cli-check',
      format: 'opaque',
      mfa: true,
    });
    expect(token.expiresAt).toBeGreaterThan(Date.now());
    expect(await whoami(sessionJwt)).toMatchObject({
      identityId: accountId,
      sessionKind: 'session-token',
      format: 'jwt',
      audience: [issuer],
      mfa: false,
    });
    // Pretty-printed JSON, like the other commands.
    expect(output.at(-1)).toContain('\n  "identityId"');

    // Needs no permission and records nothing.
    iam = open();
    try {
      expect((await iam.store.find<AuditEvent>('audit', { tenantId })).length).toBe(auditCount);
      // Real credentials that have since died: the API key is revoked (and with it the session JWT minted from it),
      // and the session token's row has expired.
      const credentialId = (await iam.authenticate({ token: apiKey })).session.id;
      await iam.api.credentials.revoke({ token: rootToken }, { tenantId, credentialId });
      await iam.store.transaction(async (tx) => {
        const row = (await tx.get<Record<string, unknown> & { id: string; tenantId: string }>(
          'sessions',
          sessionTokenId,
        ))!;
        await tx.put('sessions', { ...row, expiresAt: Date.now() - 1000 });
      });
    } finally {
      await iam.store.close();
    }
    const printed = output.length;
    for (const dead of [apiKey, sessionJwt, sessionToken])
      await expect(runCli(['whoami', '--config', config], as(dead))).rejects.toMatchObject({
        code: 'UNAUTHENTICATED',
      });
    expect(output).toHaveLength(printed);
  });

  it('fails with MISSING_ENV without a token, refuses other flags, and rejects dead credentials', async () => {
    await mkdir(work, { recursive: true });
    const folder = await mkdtemp(join(work, 'cli-sts-test-'));
    created.push(folder);
    const config = join(folder, 'better-iam.config.mjs'),
      filename = join(folder, 'iam.db'),
      output: string[] = [];
    await writeFile(
      config,
      `import { sqliteAdapter } from '@better-iam/adapter-sqlite';\nexport default () => ({database:sqliteAdapter({filename:${JSON.stringify(filename)}}),secret:${JSON.stringify(secret)},baseURL:'http://localhost:3000'});\n`,
    );
    const io = { out: (message: string) => output.push(message), env: {} as NodeJS.ProcessEnv };
    await runCli(['migrate', '--config', config], io);
    const printed = output.length;
    await expect(runCli(['whoami', '--config', config], io)).rejects.toMatchObject({
      code: 'MISSING_ENV',
      message: 'Set BETTER_IAM_TOKEN to a session or API key',
    });
    await expect(
      runCli(['whoami', '--config', config], { ...io, env: { BETTER_IAM_TOKEN: '' } }),
    ).rejects.toMatchObject({ code: 'MISSING_ENV' });
    const withToken = { ...io, env: { BETTER_IAM_TOKEN: 'biam_sts_' + 'a'.repeat(49) } };
    for (const flags of [
      ['--tenant', 'tenant-1'],
      ['--output', join(folder, 'out.json')],
      ['--retention-days', '3'],
      ['--limit', '10'],
      ['--database', 'sqlite'],
      ['--unknown', 'x'],
    ])
      await expect(
        runCli(['whoami', '--config', config, ...flags], withToken),
      ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    // A well-formed token with a bad checksum, and an unknown legacy token, are both unauthenticated.
    await expect(runCli(['whoami', '--config', config], withToken)).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    await expect(
      runCli(['whoami', '--config', config], {
        ...io,
        env: { BETTER_IAM_TOKEN: 'x'.repeat(43) },
      }),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    expect(output).toHaveLength(printed);

    await runCli(['help'], io);
    expect(output.at(-1)).toContain('better-iam whoami --config better-iam.config.mjs');
    expect(output.at(-1)).toContain('whoami prints who BETTER_IAM_TOKEN acts as');
  });
});
