import { afterEach, describe, expect, it } from 'vitest';
import { createRequestHelpers } from '@better-iam/middleware';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

describe('middleware plan()', () => {
  it('plans for the request credential and plans never when signed out', async () => {
    const f = await organizationFixture();
    const helpers = (headers: Headers) =>
      createRequestHelpers(async () => f.iam, {
        url: new URL('http://localhost:3000/documents'),
        headers,
        setCookie: () => undefined,
      });
    const owner = helpers(new Headers({ authorization: `Bearer ${f.ownerCredential.token}` }));
    expect(await owner.plan({ action: 'documents:read', type: 'document' })).toMatchObject({
      tenantId: f.tenantId,
      kind: 'always',
    });
    const anonymous = helpers(new Headers());
    expect(await anonymous.plan({ action: 'documents:read', type: 'document' })).toMatchObject({
      kind: 'never',
      filter: { kind: 'false' },
    });
  });
});
