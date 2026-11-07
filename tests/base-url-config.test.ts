import { afterEach, describe, expect, it } from 'vitest';
import { betterIam, IamError } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore } from '@better-iam/core';

const open: IamStore[] = [];
afterEach(async () => {
  for (const database of open.splice(0)) await database.close();
});

function create(baseURL: string) {
  const database = sqliteAdapter({ filename: ':memory:' });
  open.push(database);
  return betterIam({ database, secret: 'base-url-config-test-secret-32-chars!', baseURL });
}

describe('baseURL validation', () => {
  it.each(['not a url', '', '/api/iam', 'localhost:3000'])(
    'refuses %j with INVALID_CONFIG instead of a TypeError',
    (baseURL) => {
      let caught: unknown;
      try {
        create(baseURL);
      } catch (error) {
        caught = error;
      }
      expect(caught).toBeInstanceOf(IamError);
      expect(caught).toMatchObject({ code: 'INVALID_CONFIG' });
    },
  );

  it('still requires HTTPS outside localhost', () => {
    expect(() => create('http://example.com')).toThrow(/HTTPS is required/);
  });
});
