import {
  BULK_MAX_OPERATIONS,
  ENTERPRISE_SCHEMA,
  GROUP_SCHEMA,
  LIST_SCHEMA,
  MAX_PAYLOAD_SIZE,
  USER_SCHEMA,
  type GroupLink,
  type UserLink,
} from './types.js';

export function response(body: unknown, status = 200, headers?: HeadersInit): Response {
  return new Response(status === 204 || status === 304 ? null : JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/scim+json', 'cache-control': 'no-store', ...headers },
  });
}
export function listResponse(resources: unknown[], totalResults: number, startIndex = 1): unknown {
  return {
    schemas: [LIST_SCHEMA],
    totalResults,
    startIndex,
    itemsPerPage: resources.length,
    Resources: resources,
  };
}
export function userResource(link: UserLink, base: string) {
  return {
    schemas: link.enterprise ? [USER_SCHEMA, ENTERPRISE_SCHEMA] : [USER_SCHEMA],
    id: link.id,
    externalId: link.externalId,
    userName: link.userName,
    displayName: link.displayName,
    active: link.active,
    emails: link.emails,
    name: link.name,
    title: link.title,
    ...(link.enterprise ? { [ENTERPRISE_SCHEMA]: link.enterprise } : {}),
    meta: {
      resourceType: 'User',
      created: new Date(link.createdAt).toISOString(),
      lastModified: new Date(link.updatedAt).toISOString(),
      version: `W/"${link.version}"`,
      location: `${base}/Users/${encodeURIComponent(link.id)}`,
    },
  };
}
export function groupResource(link: GroupLink, base: string) {
  return {
    schemas: [GROUP_SCHEMA],
    id: link.id,
    externalId: link.externalId,
    displayName: link.displayName,
    members: link.members.map((value) => ({
      value,
      $ref: `${base}/Users/${encodeURIComponent(value)}`,
      type: 'User',
    })),
    meta: {
      resourceType: 'Group',
      created: new Date(link.createdAt).toISOString(),
      lastModified: new Date(link.updatedAt).toISOString(),
      version: `W/"${link.version}"`,
      location: `${base}/Groups/${encodeURIComponent(link.id)}`,
    },
  };
}

/** Discovery documents describe exactly the implemented subset: filtering, sorting, PATCH, bulk, ETags, pagination; no password changes. */
export const serviceProviderConfig = {
  schemas: ['urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig'],
  patch: { supported: true },
  bulk: { supported: true, maxOperations: BULK_MAX_OPERATIONS, maxPayloadSize: MAX_PAYLOAD_SIZE },
  filter: { supported: true, maxResults: 200 },
  changePassword: { supported: false },
  sort: { supported: true },
  etag: { supported: true },
  authenticationSchemes: [
    {
      type: 'oauthbearertoken',
      name: 'Scoped SCIM bearer token',
      description: 'Connection-scoped bearer token',
      specUri: 'https://www.rfc-editor.org/rfc/rfc6750',
      primary: true,
    },
  ],
};
const attribute = (name: string, overrides: Record<string, unknown> = {}) => ({
  name,
  type: 'string',
  multiValued: false,
  required: false,
  mutability: 'readWrite',
  returned: 'default',
  ...overrides,
});
export const resourceTypeDocuments = ['User', 'Group'].map((name) => ({
  schemas: ['urn:ietf:params:scim:schemas:core:2.0:ResourceType'],
  id: name,
  name,
  endpoint: `/${name}s`,
  schema: name === 'User' ? USER_SCHEMA : GROUP_SCHEMA,
  ...(name === 'User'
    ? { schemaExtensions: [{ schema: ENTERPRISE_SCHEMA, required: false }] }
    : {}),
}));
export const schemaDocuments = [
  {
    id: USER_SCHEMA,
    name: 'User',
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:Schema'],
    attributes: [
      ...['userName', 'displayName', 'externalId', 'active', 'title'].map((name) =>
        attribute(name, {
          type: name === 'active' ? 'boolean' : 'string',
          required: name === 'userName',
          uniqueness: name === 'userName' ? 'server' : 'none',
          caseExact: name === 'externalId',
        }),
      ),
      attribute('name', {
        type: 'complex',
        subAttributes: [
          'formatted',
          'familyName',
          'givenName',
          'middleName',
          'honorificPrefix',
          'honorificSuffix',
        ].map((name) => attribute(name)),
      }),
      attribute('emails', {
        type: 'complex',
        multiValued: true,
        subAttributes: ['value', 'type', 'display', 'primary'].map((name) =>
          attribute(name, {
            type: name === 'primary' ? 'boolean' : 'string',
            required: name === 'value',
          }),
        ),
      }),
    ],
  },
  {
    id: ENTERPRISE_SCHEMA,
    name: 'EnterpriseUser',
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:Schema'],
    attributes: [
      ...['employeeNumber', 'costCenter', 'organization', 'division', 'department'].map((name) =>
        attribute(name),
      ),
      attribute('manager', {
        type: 'complex',
        subAttributes: ['value', 'displayName', '$ref'].map((name) => attribute(name)),
      }),
    ],
  },
  {
    id: GROUP_SCHEMA,
    name: 'Group',
    schemas: ['urn:ietf:params:scim:schemas:core:2.0:Schema'],
    attributes: [
      attribute('displayName', { required: true, uniqueness: 'none' }),
      attribute('members', {
        type: 'complex',
        multiValued: true,
        subAttributes: [
          {
            name: 'value',
            type: 'string',
            required: true,
            mutability: 'immutable',
            returned: 'default',
          },
        ],
      }),
    ],
  },
];
