import { afterEach, describe, expect, it } from 'vitest';
import { betterIam, type BetterIamOptions } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore } from '@better-iam/core';
import { resolveConfig, type StsOptions } from '../packages/server/src/options.js';

const open: IamStore[] = [];
afterEach(async () => {
  for (const database of open.splice(0)) await database.close();
});

function options(sts?: StsOptions): BetterIamOptions {
  const database = sqliteAdapter({ filename: ':memory:' });
  open.push(database);
  return {
    database,
    secret: 'sts-config-test-secret-with-32-characters',
    baseURL: 'http://localhost:3000',
    ...(sts !== undefined ? { sts } : {}),
  };
}

function configError(sts: unknown): { code?: string; message: string } {
  try {
    resolveConfig(options(sts as StsOptions));
  } catch (error) {
    return error as { code?: string; message: string };
  }
  throw new Error('expected INVALID_CONFIG');
}

describe('sts configuration', () => {
  it('applies the defaults', () => {
    expect(resolveConfig(options()).sts).toEqual({
      maxRoleSessionSeconds: 3600,
      maxSessionTokenSeconds: 43200,
      maxSessionTokensPerIdentity: 50,
      webIdentity: {
        enabled: false,
        jwksCacheSeconds: 600,
        fetchTimeoutMs: 5000,
        maxJwksBytes: 65536,
        maxExchangesPerWindow: 600,
        maxSessionsPerTrust: 1000,
        allowPrivateNetworks: false,
        allowInsecureLocalhost: false,
      },
    });
  });

  it('constructs betterIam with defaults and with every bound at its limit', () => {
    expect(() => betterIam(options())).not.toThrow();
    expect(() => betterIam(options({}))).not.toThrow();
    for (const edge of ['min', 'max'] as const) {
      const pick = (min: number, max: number) => (edge === 'min' ? min : max);
      const sts: StsOptions = {
        maxRoleSessionSeconds: pick(900, 43200),
        maxSessionTokenSeconds: pick(900, 129600),
        maxSessionTokensPerIdentity: pick(1, 1000),
        webIdentity: {
          enabled: true,
          allowedIssuers: ['https://token.actions.githubusercontent.com'],
          jwksCacheSeconds: pick(60, 3600),
          fetchTimeoutMs: pick(500, 10000),
          maxJwksBytes: pick(1024, 1048576),
          maxExchangesPerWindow: pick(1, 100000),
          maxSessionsPerTrust: pick(1, 100000),
          allowPrivateNetworks: true,
          allowInsecureLocalhost: true,
          fetchJson: async () => ({}),
        },
      };
      expect(() => betterIam(options(sts))).not.toThrow();
      const { webIdentity, ...ceilings } = resolveConfig(options(sts)).sts;
      expect(ceilings).toEqual({
        maxRoleSessionSeconds: sts.maxRoleSessionSeconds,
        maxSessionTokenSeconds: sts.maxSessionTokenSeconds,
        maxSessionTokensPerIdentity: sts.maxSessionTokensPerIdentity,
      });
      expect(webIdentity).toMatchObject({
        enabled: true,
        allowedIssuers: ['https://token.actions.githubusercontent.com'],
        jwksCacheSeconds: sts.webIdentity!.jwksCacheSeconds,
        allowPrivateNetworks: true,
        allowInsecureLocalhost: true,
      });
      expect(webIdentity).not.toHaveProperty('fetchJson');
    }
  });

  it.each([
    ['maxRoleSessionSeconds', { maxRoleSessionSeconds: 899 }],
    ['maxRoleSessionSeconds', { maxRoleSessionSeconds: 43201 }],
    ['maxRoleSessionSeconds', { maxRoleSessionSeconds: 1000.5 }],
    ['maxRoleSessionSeconds', { maxRoleSessionSeconds: '3600' }],
    ['maxSessionTokenSeconds', { maxSessionTokenSeconds: 899 }],
    ['maxSessionTokenSeconds', { maxSessionTokenSeconds: 129601 }],
    ['maxSessionTokensPerIdentity', { maxSessionTokensPerIdentity: 0 }],
    ['maxSessionTokensPerIdentity', { maxSessionTokensPerIdentity: 1001 }],
    ['webIdentity.jwksCacheSeconds', { webIdentity: { jwksCacheSeconds: 59 } }],
    ['webIdentity.jwksCacheSeconds', { webIdentity: { jwksCacheSeconds: 3601 } }],
    ['webIdentity.fetchTimeoutMs', { webIdentity: { fetchTimeoutMs: 499 } }],
    ['webIdentity.fetchTimeoutMs', { webIdentity: { fetchTimeoutMs: 10001 } }],
    ['webIdentity.maxJwksBytes', { webIdentity: { maxJwksBytes: 1023 } }],
    ['webIdentity.maxJwksBytes', { webIdentity: { maxJwksBytes: 1048577 } }],
    ['webIdentity.maxExchangesPerWindow', { webIdentity: { maxExchangesPerWindow: 0 } }],
    ['webIdentity.maxExchangesPerWindow', { webIdentity: { maxExchangesPerWindow: 100001 } }],
    ['webIdentity.maxSessionsPerTrust', { webIdentity: { maxSessionsPerTrust: 0 } }],
    ['webIdentity.maxSessionsPerTrust', { webIdentity: { maxSessionsPerTrust: 100001 } }],
    ['webIdentity.enabled', { webIdentity: { enabled: 'yes' } }],
    ['webIdentity.allowPrivateNetworks', { webIdentity: { allowPrivateNetworks: 1 } }],
    ['webIdentity.allowInsecureLocalhost', { webIdentity: { allowInsecureLocalhost: 'true' } }],
    ['webIdentity.fetchJson', { webIdentity: { fetchJson: 'https://proxy' } }],
    ['webIdentity', { webIdentity: 'on' }],
    ['options', 'on'],
    [
      'webIdentity.allowedIssuers',
      { webIdentity: { allowedIssuers: 'https://token.actions.githubusercontent.com' } },
    ],
    [
      'webIdentity.allowedIssuers',
      {
        webIdentity: {
          allowedIssuers: Array.from({ length: 101 }, (_, i) => `https://idp${i}.example.com`),
        },
      },
    ],
    ['webIdentity.allowedIssuers', { webIdentity: { allowedIssuers: ['http://idp.example.com'] } }],
    [
      'webIdentity.allowedIssuers',
      { webIdentity: { allowedIssuers: ['https://idp.example.com/?a'] } },
    ],
    [
      'webIdentity.allowedIssuers',
      {
        webIdentity: {
          allowedIssuers: ['http://localhost:3000/api/iam'],
          allowInsecureLocalhost: true,
        },
      },
    ],
  ])('refuses an invalid %s', (field, sts) => {
    const error = configError(sts);
    expect(error.code).toBe('INVALID_CONFIG');
    expect(error.message).toMatch(new RegExp(`^sts\\.${field.replace('.', '\\.')} `));
    expect(() => betterIam(options(sts as StsOptions))).toThrow(
      expect.objectContaining({ code: 'INVALID_CONFIG' }),
    );
  });

  it('accepts loopback issuers only with allowInsecureLocalhost, and deduplicates the allowlist', () => {
    const { webIdentity } = resolveConfig(
      options({
        webIdentity: {
          allowInsecureLocalhost: true,
          allowedIssuers: ['http://127.0.0.1:9000', 'http://127.0.0.1:9000'],
        },
      }),
    ).sts;
    expect(webIdentity.allowedIssuers).toEqual(['http://127.0.0.1:9000']);
    expect(Object.isFrozen(webIdentity.allowedIssuers)).toBe(true);
  });
});
