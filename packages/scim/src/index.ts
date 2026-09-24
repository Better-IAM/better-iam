import { randomBytes, randomUUID } from 'node:crypto';
import { IamError, type CredentialInput, type IamStore } from '@better-iam/core';
import { attributeList, parseScimFilter, projectResource, sortResources } from './filter.js';
import { createProvisioning } from './provisioning.js';
import {
  groupResource,
  listResponse,
  resourceTypeDocuments,
  response,
  schemaDocuments,
  serviceProviderConfig,
  userResource,
} from './resources.js';
import {
  BULK_MAX_OPERATIONS,
  BULK_REQUEST_SCHEMA,
  BULK_RESPONSE_SCHEMA,
  ERROR_SCHEMA,
  MAX_PAYLOAD_SIZE,
  SEARCH_SCHEMA,
  type Connection,
  type ConnectionSummary,
  type GroupLink,
  type GroupSummary,
  type ObjectValue,
  type ScimConfig,
  type UserLink,
} from './types.js';
import { activeTenant, fields, hash, object, text } from './validation.js';

export { parseScimFilter } from './filter.js';
export * from './outbound.js';
export type {
  Connection as ScimConnection,
  ConnectionSummary as ScimConnectionSummary,
  GroupSummary as ScimGroupSummary,
  GroupLink as ScimGroupLink,
  ScimConfig,
  UserLink as ScimUserLink,
} from './types.js';

/** A SCIM operation's result before it becomes an HTTP response or a bulk operation entry. */
interface Outcome {
  status: number;
  body: unknown;
  headers?: Record<string, string>;
}
/** One Users/Groups/discovery request, from HTTP or from a bulk operation. */
interface ScimRequest {
  method: string;
  resourceType: string;
  resourceId?: string;
  body?: ObjectValue;
  ifMatch?: string | null;
  ifNoneMatch?: string | null;
  /** Query parameters (filter, sorting, paging, projection); bulk operations have none. */
  query?: URLSearchParams;
}
interface ListQuery {
  filter?: string;
  startIndex: number;
  count: number;
  sortBy?: string;
  sortOrder?: string;
  attributes?: string[];
  excludedAttributes?: string[];
}

function errorOutcome(error: unknown): Outcome {
  const status =
    error instanceof IamError ? error.status : error instanceof SyntaxError ? 400 : 500;
  return {
    status,
    body: {
      schemas: [ERROR_SCHEMA],
      status: String(status),
      scimType: error instanceof IamError ? error.code : 'invalidSyntax',
      detail:
        error instanceof IamError
          ? error.message
          : status === 500
            ? 'The SCIM operation failed.'
            : 'Invalid JSON.',
    },
  };
}
const toResponse = (outcome: Outcome) => response(outcome.body, outcome.status, outcome.headers);

/** One JSON administration route: turns the request body into a service call. */
type AdminRoute = (credential: CredentialInput, body: ObjectValue) => Promise<unknown>;
const ADMIN_MAX_BODY = 64 * 1024;
/** Reads a request body, refusing it once it exceeds `limit` bytes. */
async function limitedText(request: Request, limit: number): Promise<string> {
  const reader = request.body?.getReader();
  if (!reader) return '';
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const item = await reader.read();
    if (item.done) break;
    size += item.value.byteLength;
    if (size > limit) {
      await reader.cancel();
      throw new IamError('PAYLOAD_TOO_LARGE', 'Request body is too large.', 413);
    }
    chunks.push(item.value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function pagination(startIndex: unknown, count: unknown): { startIndex: number; count: number } {
  const start = startIndex === undefined || startIndex === null ? 1 : Number(startIndex);
  const size = count === undefined || count === null ? 100 : Number(count);
  if (!Number.isInteger(start) || start < 1 || !Number.isInteger(size) || size < 0)
    throw new IamError('invalidValue', 'Invalid pagination.');
  return { startIndex: start, count: Math.min(size, 200) };
}
function queryFromUrl(params: URLSearchParams): ListQuery {
  return {
    filter: params.get('filter') ?? undefined,
    ...pagination(params.get('startIndex'), params.get('count')),
    sortBy: params.get('sortBy') ?? undefined,
    sortOrder: params.get('sortOrder') ?? undefined,
    attributes: attributeList(params.get('attributes')),
    excludedAttributes: attributeList(params.get('excludedAttributes')),
  };
}
/** POST `/.search` (RFC 7644 §3.4.3) carries the query in a SearchRequest body. */
function queryFromBody(body: ObjectValue): ListQuery {
  fields(body, [
    'schemas',
    'filter',
    'startIndex',
    'count',
    'sortBy',
    'sortOrder',
    'attributes',
    'excludedAttributes',
  ]);
  if (
    !Array.isArray(body.schemas) ||
    body.schemas.length !== 1 ||
    body.schemas[0] !== SEARCH_SCHEMA
  )
    throw new IamError('invalidSyntax', 'A SearchRequest body is required.');
  for (const key of ['filter', 'sortBy', 'sortOrder'])
    if (body[key] !== undefined && typeof body[key] !== 'string')
      throw new IamError('invalidValue', `${key} must be a string.`);
  return {
    filter: body.filter as string | undefined,
    ...pagination(body.startIndex, body.count),
    sortBy: body.sortBy as string | undefined,
    sortOrder: body.sortOrder as string | undefined,
    attributes: attributeList(body.attributes),
    excludedAttributes: attributeList(body.excludedAttributes),
  };
}

/**
 * SCIM 2.0 provisioning server: connection-scoped bearer tokens, Users and Groups with RFC 7644 filtering, sorting,
 * attribute projection, `/.search`, PATCH value paths, `/Bulk`, ETags and pagination, and explicit
 * administrator-controlled group-to-role mappings.
 */
export function createScimService(config: ScimConfig) {
  const { store } = config;
  const basePath = (config.basePath ?? '/scim/v2').replace(/\/$/, '');
  if (!basePath.startsWith('/'))
    throw new IamError('configuration', 'SCIM basePath must be absolute.');
  const adminBasePath = (config.adminBasePath ?? '/scim/admin').replace(/\/$/, '');
  if (!adminBasePath.startsWith('/'))
    throw new IamError('configuration', 'SCIM adminBasePath must be absolute.');
  if (
    adminBasePath === basePath ||
    adminBasePath.startsWith(`${basePath}/`) ||
    basePath.startsWith(`${adminBasePath}/`)
  )
    throw new IamError('configuration', 'SCIM adminBasePath must not overlap basePath.');
  const provisioning = createProvisioning(config);

  async function perform(
    tx: IamStore,
    connection: Connection,
    base: string,
    request: ScimRequest,
  ): Promise<Outcome> {
    const { method, resourceType, resourceId } = request;
    if (method === 'GET' && resourceType === 'ServiceProviderConfig')
      return { status: 200, body: serviceProviderConfig };
    if (method === 'GET' && ['ResourceTypes', 'Schemas'].includes(resourceType)) {
      const resources = resourceType === 'ResourceTypes' ? resourceTypeDocuments : schemaDocuments;
      if (resourceId) {
        const resource = resources.find((row) => row.id === resourceId);
        if (!resource) throw new IamError('notFound', 'Schema not found.', 404);
        return { status: 200, body: resource };
      }
      return { status: 200, body: listResponse(resources, resources.length) };
    }
    if (resourceType !== 'Users' && resourceType !== 'Groups')
      throw new IamError('notFound', 'Unsupported SCIM resource.', 404);
    const collection = resourceType === 'Users' ? 'scimUsers' : 'scimGroups';
    const render = (row: UserLink | GroupLink): ObjectValue =>
      resourceType === 'Users'
        ? userResource(row as UserLink, base)
        : groupResource(row as GroupLink, base);
    const projection = request.query
      ? {
          attributes: attributeList(request.query.get('attributes')),
          excluded: attributeList(request.query.get('excludedAttributes')),
        }
      : {};
    const present = (row: UserLink | GroupLink) =>
      projectResource(render(row), projection.attributes, projection.excluded);

    const search = resourceId === '.search';
    if ((method === 'GET' && !resourceId) || (method === 'POST' && search)) {
      const query = search ? queryFromBody(request.body!) : queryFromUrl(request.query!);
      const matches = sortResources(
        (
          await tx.find<UserLink | GroupLink>(collection, {
            tenantId: connection.tenantId,
            connectionId: connection.id,
          })
        )
          .sort((a, b) => a.id.localeCompare(b.id))
          .map(render)
          .filter(parseScimFilter(query.filter)),
        query.sortBy,
        query.sortOrder,
      );
      const page = matches.slice(query.startIndex - 1, query.startIndex - 1 + query.count);
      return {
        status: 200,
        body: listResponse(
          page.map((resource) =>
            projectResource(resource, query.attributes, query.excludedAttributes),
          ),
          matches.length,
          query.startIndex,
        ),
      };
    }
    if (search) throw new IamError('invalidMethod', '/.search accepts POST only.', 405);

    const row = resourceId ? await tx.get<UserLink | GroupLink>(collection, resourceId) : undefined;
    if (
      resourceId &&
      (!row || row.tenantId !== connection.tenantId || row.connectionId !== connection.id)
    )
      throw new IamError('notFound', 'Resource not found.', 404);
    if (
      row &&
      request.ifMatch &&
      request.ifMatch !== '*' &&
      request.ifMatch !== `W/"${row.version}"`
    )
      throw new IamError('invalidVers', 'Version conflict.', 412);
    if (method === 'GET' && row) {
      const etag = `W/"${row.version}"`;
      if (request.ifNoneMatch === etag || request.ifNoneMatch === '*')
        return { status: 304, body: null, headers: { etag } };
      return { status: 200, body: present(row), headers: { etag } };
    }
    if (method === 'POST' && !resourceId) {
      const saved =
        resourceType === 'Users'
          ? await provisioning.saveUser(tx, connection, request.body!)
          : await provisioning.saveGroup(tx, connection, request.body!);
      return {
        status: 201,
        body: present(saved),
        headers: {
          location: `${base}/${resourceType}/${saved.id}`,
          etag: `W/"${saved.version}"`,
        },
      };
    }
    if (row && (method === 'PUT' || method === 'PATCH')) {
      const saved =
        method === 'PATCH'
          ? await provisioning.patch(tx, connection, resourceType, row, request.body!)
          : resourceType === 'Users'
            ? await provisioning.saveUser(tx, connection, request.body!, row as UserLink)
            : await provisioning.saveGroup(tx, connection, request.body!, row as GroupLink);
      return {
        status: 200,
        body: present(saved),
        headers: {
          location: `${base}/${resourceType}/${saved.id}`,
          etag: `W/"${saved.version}"`,
        },
      };
    }
    if (row && method === 'DELETE') {
      if (resourceType === 'Users') await provisioning.deleteUser(tx, connection, row as UserLink);
      else await provisioning.deleteGroup(tx, connection, row as GroupLink);
      await tx.delete(collection, row.id);
      await provisioning.audit(
        tx,
        connection,
        `iam:scim:Delete${resourceType === 'Users' ? 'User' : 'Group'}`,
        row.id,
      );
      return { status: 204, body: null };
    }
    throw new IamError('invalidMethod', 'Method is not supported for this resource.', 405);
  }

  /** Runs one request in its own transaction, so a failed bulk operation never leaves partial writes. */
  function run(request: Request, connectionId: string, base: string, scim: ScimRequest) {
    return store.transaction(async (tx) => {
      const connection = await provisioning.authenticate(tx, request, connectionId);
      return perform(tx, connection, base, scim);
    });
  }

  /**
   * RFC 7644 §3.7 bulk: each operation commits independently; `bulkId:` references resolve to resources created
   * earlier in the request in any order, and `failOnErrors` stops processing after that many failures.
   */
  async function bulk(
    request: Request,
    connectionId: string,
    base: string,
    body: ObjectValue,
  ): Promise<Outcome> {
    fields(body, ['schemas', 'Operations', 'failOnErrors']);
    if (
      !Array.isArray(body.schemas) ||
      body.schemas.length !== 1 ||
      body.schemas[0] !== BULK_REQUEST_SCHEMA
    )
      throw new IamError('invalidSyntax', 'A BulkRequest body is required.');
    if (!Array.isArray(body.Operations) || !body.Operations.length)
      throw new IamError('invalidSyntax', 'Bulk requests require at least one operation.');
    if (body.Operations.length > BULK_MAX_OPERATIONS)
      throw new IamError(
        'tooMany',
        `Bulk requests accept at most ${BULK_MAX_OPERATIONS} operations.`,
        413,
      );
    const failOnErrors = body.failOnErrors;
    if (
      failOnErrors !== undefined &&
      (!Number.isInteger(failOnErrors) || (failOnErrors as number) < 1)
    )
      throw new IamError('invalidValue', 'failOnErrors must be a positive integer.');
    // An invalid credential fails the whole request rather than every operation individually.
    await store.transaction((tx) => provisioning.authenticate(tx, request, connectionId));

    const declared = new Set<string>();
    const operations = body.Operations.map((item, index) => {
      const op = object(item);
      fields(op, ['method', 'bulkId', 'path', 'data', 'version']);
      const method = typeof op.method === 'string' ? op.method.toUpperCase() : '';
      if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method))
        throw new IamError('invalidSyntax', `Operation ${index + 1} has an unsupported method.`);
      const path = text(op.path, 'path')!;
      const bulkId = op.bulkId === undefined ? undefined : text(op.bulkId, 'bulkId')!;
      if (bulkId !== undefined) {
        if (!/^[\w.-]{1,64}$/.test(bulkId) || declared.has(bulkId))
          throw new IamError('invalidValue', `bulkId "${bulkId}" is invalid or duplicated.`);
        declared.add(bulkId);
      }
      if (method === 'POST' && bulkId === undefined)
        throw new IamError('invalidSyntax', 'POST operations require a bulkId.');
      if (method !== 'DELETE' && op.data === undefined)
        throw new IamError('invalidSyntax', `${method} operations require data.`);
      const version = op.version === undefined ? undefined : text(op.version, 'version')!;
      return { method, bulkId, path, data: op.data, version };
    });

    const created = new Map<string, string>();
    const failed = new Set<string>();
    const results: ObjectValue[] = [];
    let errors = 0;
    let pending = operations;
    const record = (operation: (typeof operations)[number], outcome: Outcome) => {
      const entry: ObjectValue = { method: operation.method, status: String(outcome.status) };
      if (operation.bulkId !== undefined) entry.bulkId = operation.bulkId;
      if (outcome.headers?.location) entry.location = outcome.headers.location;
      if (outcome.headers?.etag) entry.version = outcome.headers.etag;
      if (outcome.status >= 400) {
        entry.response = outcome.body;
        errors++;
        if (operation.bulkId !== undefined) failed.add(operation.bulkId);
      } else if (operation.method === 'POST' && operation.bulkId !== undefined)
        created.set(operation.bulkId, String((outcome.body as ObjectValue).id));
      results.push(entry);
    };
    const stopped = () => failOnErrors !== undefined && errors >= (failOnErrors as number);
    while (pending.length && !stopped()) {
      const deferred: typeof operations = [];
      for (const operation of pending) {
        if (stopped()) break;
        const serialized = JSON.stringify({ path: operation.path, data: operation.data ?? null });
        const references = [...serialized.matchAll(/bulkId:([\w.-]+)/g)].map((match) => match[1]!);
        const unknown = references.find((reference) => !declared.has(reference));
        const broken = references.find((reference) => failed.has(reference));
        if (unknown !== undefined || broken !== undefined) {
          record(
            operation,
            errorOutcome(
              new IamError(
                'invalidValue',
                unknown !== undefined
                  ? `Unknown bulkId reference "${unknown}".`
                  : `Referenced operation "${broken}" failed.`,
                unknown !== undefined ? 400 : 409,
              ),
            ),
          );
          continue;
        }
        if (references.some((reference) => !created.has(reference))) {
          deferred.push(operation);
          continue;
        }
        const resolved = JSON.parse(
          serialized.replace(
            /bulkId:([\w.-]+)/g,
            (_, reference: string) => created.get(reference)!,
          ),
        ) as { path: string; data: unknown };
        const match = /^\/(Users|Groups)(?:\/([^/?]+))?$/.exec(resolved.path);
        let outcome: Outcome;
        try {
          if (!match || (operation.method === 'POST') === (match[2] !== undefined))
            throw new IamError('invalidPath', `Invalid bulk operation path "${operation.path}".`);
          outcome = await run(request, connectionId, base, {
            method: operation.method,
            resourceType: match[1]!,
            resourceId: match[2] === undefined ? undefined : decodeURIComponent(match[2]),
            body: resolved.data === null ? undefined : object(resolved.data),
            ifMatch: operation.version,
          });
          if (operation.method === 'DELETE')
            outcome.headers = { location: `${base}${resolved.path}` };
        } catch (error) {
          outcome = errorOutcome(error);
        }
        record(operation, outcome);
      }
      if (deferred.length === pending.length) {
        // Nothing progressed: the remaining operations reference each other in a cycle.
        for (const operation of deferred)
          record(
            operation,
            errorOutcome(
              new IamError('invalidValue', 'Circular bulkId references cannot be resolved.', 409),
            ),
          );
        break;
      }
      pending = deferred;
    }
    return { status: 200, body: { schemas: [BULK_RESPONSE_SCHEMA], Operations: results } };
  }

  function summary(connection: Connection, users: number, groups: number): ConnectionSummary {
    return {
      id: connection.id,
      tenantId: connection.tenantId,
      name: connection.name,
      path: `${basePath}/${connection.id}`,
      expiresAt: connection.expiresAt,
      revoked: connection.revoked,
      createdAt: connection.createdAt,
      lastUsedAt: connection.lastUsedAt,
      rotatedAt: connection.rotatedAt,
      users,
      groups,
      roleMappings: connection.roleMappings,
    };
  }
  function lifetime(expiresIn: number | undefined): number {
    const seconds = expiresIn ?? 90 * 86400;
    if (!Number.isInteger(seconds) || seconds < 60 || seconds > 365 * 86400)
      throw new IamError(
        'invalidValue',
        'Credential lifetime must be between 60 seconds and one year.',
      );
    return seconds;
  }

  const service = {
    basePath,
    adminBasePath,
    /** Issues a connection-scoped bearer token; the plaintext is returned once and stored only as a hash. */
    async createConnection(
      credential: CredentialInput,
      input: { tenantId: string; name: string; expiresIn?: number },
    ) {
      const name = text(input.name, 'name')!;
      const expiresIn = lifetime(input.expiresIn);
      const token = randomBytes(32).toString('base64url');
      const connection: Connection = {
        id: randomUUID(),
        tenantId: input.tenantId,
        name,
        tokenHash: hash(token),
        expiresAt: Date.now() + expiresIn * 1000,
        revoked: false,
        roleMappings: {},
        createdAt: Date.now(),
      };
      await store.transaction(async (tx) => {
        await config.authorize(credential, 'iam:scim:connections:create', {
          tenantId: input.tenantId,
          type: 'scim',
          id: '*',
        });
        const principal = await config.authenticate(credential);
        await activeTenant(tx, input.tenantId);
        await tx.insert('scimConnections', connection);
        await provisioning.audit(
          tx,
          connection,
          'iam:scim:CreateConnection',
          connection.id,
          principal.identity.id,
        );
      });
      return {
        id: connection.id,
        tenantId: connection.tenantId,
        token,
        expiresAt: connection.expiresAt,
        path: `${basePath}/${connection.id}`,
      };
    },
    /** A tenant's connections with usage metadata and provisioned counts; tokens are never returned. */
    async listConnections(
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<ConnectionSummary[]> {
      return store.transaction(async (tx) => {
        await config.authorize(credential, 'iam:scim:connections:read', {
          tenantId: input.tenantId,
          type: 'scim',
          id: '*',
        });
        const connections = await tx.find<Connection>('scimConnections', {
          tenantId: input.tenantId,
        });
        const users = await tx.find<UserLink>('scimUsers', { tenantId: input.tenantId });
        const groups = await tx.find<GroupLink>('scimGroups', { tenantId: input.tenantId });
        return connections
          .sort((a, b) => (a.createdAt ?? 0) - (b.createdAt ?? 0) || a.id.localeCompare(b.id))
          .map((connection) =>
            summary(
              connection,
              users.filter((row) => row.connectionId === connection.id).length,
              groups.filter((row) => row.connectionId === connection.id).length,
            ),
          );
      });
    },
    /**
     * Replaces the connection's bearer token: the old token stops working immediately, provisioned users, groups
     * and role mappings are kept, and the new token is returned once.
     */
    async rotateToken(
      credential: CredentialInput,
      input: { tenantId: string; connectionId: string; expiresIn?: number },
    ) {
      const expiresIn = lifetime(input.expiresIn);
      const token = randomBytes(32).toString('base64url');
      return store.transaction(async (tx) => {
        await config.authorize(credential, 'iam:scim:credentials:create', {
          tenantId: input.tenantId,
          type: 'scim',
          id: input.connectionId,
        });
        const principal = await config.authenticate(credential);
        const connection = await tx.get<Connection>('scimConnections', input.connectionId);
        if (!connection || connection.tenantId !== input.tenantId)
          throw new IamError('notFound', 'Connection not found.', 404);
        if (connection.revoked)
          throw new IamError('CONFLICT', 'A revoked connection cannot be rotated.', 409);
        await activeTenant(tx, input.tenantId);
        const now = Date.now();
        const rotated: Connection = {
          ...connection,
          tokenHash: hash(token),
          expiresAt: now + expiresIn * 1000,
          rotatedAt: now,
        };
        await tx.put('scimConnections', rotated);
        await provisioning.audit(
          tx,
          rotated,
          'iam:scim:RotateToken',
          rotated.id,
          principal.identity.id,
        );
        return {
          id: rotated.id,
          tenantId: rotated.tenantId,
          token,
          expiresAt: rotated.expiresAt,
          path: `${basePath}/${rotated.id}`,
        };
      });
    },
    /** Invalidates the token immediately and removes the bindings its role mappings created. */
    async revokeConnection(
      credential: CredentialInput,
      input: { tenantId: string; connectionId: string },
    ) {
      await store.transaction(async (tx) => {
        await config.authorize(credential, 'iam:scim:connections:delete', {
          tenantId: input.tenantId,
          type: 'scim',
          id: input.connectionId,
        });
        const principal = await config.authenticate(credential);
        const connection = await tx.get<Connection>('scimConnections', input.connectionId);
        if (!connection || connection.tenantId !== input.tenantId)
          throw new IamError('notFound', 'Connection not found.', 404);
        await tx.put('scimConnections', { ...connection, revoked: true });
        for (const binding of await tx.find('bindings', {
          tenantId: input.tenantId,
          scimConnectionId: connection.id,
        }))
          await tx.delete('bindings', binding.id);
        await provisioning.audit(
          tx,
          connection,
          'iam:scim:RevokeConnection',
          connection.id,
          principal.identity.id,
        );
      });
    },
    /** The groups the IdP pushed through a connection, by name, with member counts and mapped roles. */
    async listGroups(
      credential: CredentialInput,
      input: { tenantId: string; connectionId: string },
    ): Promise<GroupSummary[]> {
      return store.transaction(async (tx) => {
        await config.authorize(credential, 'iam:scim:connections:read', {
          tenantId: input.tenantId,
          type: 'scim',
          id: input.connectionId,
        });
        const connection = await tx.get<Connection>('scimConnections', input.connectionId);
        if (!connection || connection.tenantId !== input.tenantId)
          throw new IamError('notFound', 'Connection not found.', 404);
        const groups = await tx.find<GroupLink>('scimGroups', {
          tenantId: input.tenantId,
          connectionId: connection.id,
        });
        return groups
          .sort((a, b) => a.displayName.localeCompare(b.displayName) || a.id.localeCompare(b.id))
          .map((group) => ({
            id: group.id,
            groupId: group.groupId,
            displayName: group.displayName,
            ...(group.externalId !== undefined ? { externalId: group.externalId } : {}),
            members: group.members.length,
            roleIds: [...(connection.roleMappings[group.id] ?? [])],
          }));
      });
    },
    /** Maps a SCIM group to roles; the administrator must hold `iam:bindings:create` on every role. */
    async setRoleMappings(
      credential: CredentialInput,
      input: { tenantId: string; connectionId: string; groupId: string; roleIds: string[] },
    ) {
      if (!config.syncRoleMappings)
        throw new IamError('configuration', 'Role mapping callback is required.');
      if (
        !Array.isArray(input.roleIds) ||
        input.roleIds.length > 100 ||
        input.roleIds.some((roleId) => typeof roleId !== 'string' || !roleId)
      )
        throw new IamError('invalidValue', 'roleIds must list at most 100 role IDs.');
      await store.transaction(async (tx) => {
        await config.authorize(credential, 'iam:scim:mappings:update', {
          tenantId: input.tenantId,
          type: 'scim',
          id: input.connectionId,
        });
        const principal = await config.authenticate(credential);
        const connection = await tx.get<Connection>('scimConnections', input.connectionId);
        const group = await tx.get<GroupLink>('scimGroups', input.groupId);
        if (
          !connection ||
          connection.tenantId !== input.tenantId ||
          !group ||
          group.connectionId !== connection.id
        )
          throw new IamError('notFound', 'Connection or group not found.', 404);
        for (const roleId of input.roleIds) {
          const role = await tx.get('roles', roleId);
          if (!role || role.tenantId !== input.tenantId || role.protected === true)
            throw new IamError('invalidValue', 'Role is unavailable.');
          await config.authorize(credential, 'iam:bindings:create', {
            tenantId: input.tenantId,
            type: 'iam',
            id: roleId,
          });
        }
        connection.roleMappings = {
          ...connection.roleMappings,
          [input.groupId]: [...new Set(input.roleIds)],
        };
        await tx.put('scimConnections', connection);
        await provisioning.syncGroup(tx, connection, group, credential);
        await provisioning.audit(
          tx,
          connection,
          'iam:scim:SetRoleMappings',
          group.id,
          principal.identity.id,
        );
      });
    },
    /**
     * Fetch handler for `{basePath}/{connectionId}/{Users|Groups|ServiceProviderConfig|ResourceTypes|Schemas}[/{id}]`,
     * `{Users|Groups}/.search`, and `Bulk`, plus the JSON administration API under `{adminBasePath}/connections/…`.
     */
    async handler(request: Request): Promise<Response | undefined> {
      const url = new URL(request.url);
      if (url.pathname.startsWith(`${adminBasePath}/`)) return admin(request, url);
      if (!url.pathname.startsWith(`${basePath}/`)) return undefined;
      try {
        const parts = url.pathname
          .slice(basePath.length + 1)
          .split('/')
          .map(decodeURIComponent);
        const [connectionId, resourceType, resourceId] = parts;
        if (!connectionId || !resourceType || parts.length > 3)
          throw new IamError('notFound', 'SCIM resource not found.', 404);
        // Body is parsed before opening a database transaction; network input cannot hold the writer lock.
        let body: ObjectValue | undefined;
        if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
          if (!request.headers.get('content-type')?.match(/application\/(scim\+)?json/i))
            throw new IamError('invalidSyntax', 'A JSON content type is required.', 415);
          // Read with a cap: the body arrives before the connection's token is checked.
          const raw = await limitedText(request, MAX_PAYLOAD_SIZE).catch((error: unknown) => {
            throw error instanceof IamError && error.status === 413
              ? new IamError('tooLarge', 'Request body is too large.', 413)
              : error;
          });
          body = object(JSON.parse(raw));
        }
        const base = `${url.origin}${basePath}/${encodeURIComponent(connectionId)}`;
        if (resourceType === 'Bulk') {
          if (request.method !== 'POST' || resourceId)
            throw new IamError('invalidMethod', 'Bulk accepts POST only.', 405);
          return toResponse(await bulk(request, connectionId, base, body!));
        }
        return toResponse(
          await run(request, connectionId, base, {
            method: request.method,
            resourceType,
            resourceId,
            body,
            ifMatch: request.headers.get('if-match'),
            ifNoneMatch: request.headers.get('if-none-match'),
            query: url.searchParams,
          }),
        );
      } catch (error) {
        return toResponse(errorOutcome(error));
      }
    },
  };

  const id = (body: ObjectValue, field: string) => text(body[field], field)!;
  const routes: Record<string, AdminRoute> = {
    'connections/list': async (credential, body) =>
      service.listConnections(credential, { tenantId: id(body, 'tenantId') }),
    'connections/create': async (credential, body) =>
      service.createConnection(credential, {
        tenantId: id(body, 'tenantId'),
        name: body.name as string,
        expiresIn: body.expiresIn as number | undefined,
      }),
    'connections/rotate': async (credential, body) =>
      service.rotateToken(credential, {
        tenantId: id(body, 'tenantId'),
        connectionId: id(body, 'connectionId'),
        expiresIn: body.expiresIn as number | undefined,
      }),
    'connections/revoke': async (credential, body) =>
      service.revokeConnection(credential, {
        tenantId: id(body, 'tenantId'),
        connectionId: id(body, 'connectionId'),
      }),
    'connections/groups': async (credential, body) =>
      service.listGroups(credential, {
        tenantId: id(body, 'tenantId'),
        connectionId: id(body, 'connectionId'),
      }),
    'connections/mappings': async (credential, body) =>
      service.setRoleMappings(credential, {
        tenantId: id(body, 'tenantId'),
        connectionId: id(body, 'connectionId'),
        groupId: id(body, 'groupId'),
        roleIds: body.roleIds as string[],
      }),
  };
  /**
   * JSON administration API for consoles and scripts: `POST {adminBasePath}/connections/…` with the caller's IAM
   * credential. Like the IAM API it requires `X-Better-IAM: 1`, a JSON object body, and a same-origin `Origin` when
   * one is sent, and answers `{ data }` or `{ error: { code, message } }`.
   */
  async function admin(request: Request, url: URL): Promise<Response> {
    const reply = (body: unknown, status = 200) =>
      Response.json(body, {
        status,
        headers: { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' },
      });
    const path = url.pathname.slice(adminBasePath.length + 1);
    const route = Object.hasOwn(routes, path) ? routes[path] : undefined;
    if (!route) return reply({ error: { code: 'NOT_FOUND', message: 'Unknown route.' } }, 404);
    try {
      if (request.method !== 'POST') throw new IamError('METHOD_NOT_ALLOWED', 'Use POST.', 405);
      if (
        request.headers.get('x-better-iam') !== '1' ||
        !request.headers.get('content-type')?.toLowerCase().startsWith('application/json')
      )
        throw new IamError('CSRF_REJECTED', 'JSON requests require X-Better-IAM: 1.', 403);
      const origin = request.headers.get('origin');
      if (origin !== null && origin !== url.origin)
        throw new IamError('CSRF_REJECTED', 'Cross-origin requests are rejected.', 403);
      const raw = await limitedText(request, ADMIN_MAX_BODY);
      let body: unknown;
      try {
        body = JSON.parse(raw);
      } catch {
        throw new IamError('INVALID_INPUT', 'The body must be JSON.');
      }
      if (!body || typeof body !== 'object' || Array.isArray(body))
        throw new IamError('INVALID_INPUT', 'The body must be a JSON object.');
      const data = await route({ headers: request.headers }, body as ObjectValue);
      return reply({ data: data ?? null });
    } catch (error) {
      const known = error instanceof IamError;
      return reply(
        {
          error: {
            code: known ? error.code : 'INTERNAL_ERROR',
            message: known ? error.message : 'The SCIM administration request failed.',
          },
        },
        known ? error.status : 500,
      );
    }
  }
  return service;
}

export type ScimService = ReturnType<typeof createScimService>;
