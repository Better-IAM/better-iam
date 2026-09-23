import { randomUUID } from 'node:crypto';
import { IamError, type IamPlugin, type StoredRecord } from '@better-iam/core';

/** Tenant-scoped project record owned by this plugin. */
export interface Project extends StoredRecord {
  name: string;
  description?: string;
  status: 'active' | 'archived';
  createdBy: string;
  createdAt: number;
  updatedAt: number;
}

const NAME_MAX_LENGTH = 100;
const DESCRIPTION_MAX_LENGTH = 500;
const COLLECTION = 'projects';

interface ReadStore {
  get<T extends StoredRecord = StoredRecord>(
    collection: string,
    id: string,
  ): Promise<T | undefined>;
  find<T extends StoredRecord = StoredRecord>(
    collection: string,
    filter?: Record<string, unknown>,
  ): Promise<T[]>;
}
function object(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== 'object' || Array.isArray(input))
    throw new IamError('INVALID_INPUT', 'A JSON object is required');
  return input as Record<string, unknown>;
}
function rejectUnknown(input: Record<string, unknown>, allowed: string[]) {
  for (const key of Object.keys(input))
    if (!allowed.includes(key)) throw new IamError('INVALID_INPUT', `Unexpected field ${key}`);
}
function text(value: unknown, field: string): string {
  if (typeof value !== 'string') throw new IamError('INVALID_INPUT', `${field} is required`);
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > NAME_MAX_LENGTH)
    throw new IamError('INVALID_INPUT', `${field} must be 1-${NAME_MAX_LENGTH} characters`);
  return trimmed;
}
function optionalText(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== 'string') throw new IamError('INVALID_INPUT', `${field} must be text`);
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  if (trimmed.length > DESCRIPTION_MAX_LENGTH)
    throw new IamError(
      'INVALID_INPUT',
      `${field} must be at most ${DESCRIPTION_MAX_LENGTH} characters`,
    );
  return trimmed;
}
function projectId(input: unknown): string {
  if (typeof input !== 'string' || !input.trim())
    throw new IamError('INVALID_INPUT', 'projectId is required');
  return input;
}
async function load(store: ReadStore, id: string, tenantId: string): Promise<Project> {
  const project = await store.get<Project>(COLLECTION, id);
  if (!project || project.tenantId !== tenantId)
    throw new IamError('NOT_FOUND', 'Project not found', 404);
  return project;
}
async function assertNameAvailable(
  store: ReadStore,
  tenantId: string,
  name: string,
  exceptId?: string,
) {
  if (
    (await store.find<Project>(COLLECTION, { tenantId })).some(
      (project) => project.name === name && project.id !== exceptId,
    )
  )
    throw new IamError('CONFLICT', 'A project with this name already exists', 409);
}

/**
 * Reference plugin providing tenant-scoped project records.
 *
 * Registering the plugin adds the `projects:read` and `projects:write` actions
 * to the catalog and mounts `POST /api/iam/plugins/projects/{create|list|get|update|archive|restore}`.
 * Every endpoint runs in the server's transactional authorization service; root
 * override, tenant scope, ancestry boundaries, and policies apply unchanged.
 */
export function createProjectsPlugin(): IamPlugin {
  return {
    id: 'projects',
    actions: ['projects:read', 'projects:write'],
    endpoints: [
      {
        method: 'POST',
        path: 'create',
        action: 'projects:write',
        validate(value) {
          const input = object(value);
          rejectUnknown(input, ['tenantId', 'name', 'description']);
          const validated: Record<string, unknown> = {
            tenantId: input.tenantId,
            name: text(input.name, 'name'),
          };
          const description = optionalText(input.description, 'description');
          if (description) validated.description = description;
          return validated;
        },
        async handler({ store, principal, tenantId }, input) {
          const name = String(input.name);
          await assertNameAvailable(store, tenantId, name);
          const now = Date.now();
          return store.insert<Project>(COLLECTION, {
            id: randomUUID(),
            tenantId,
            name,
            ...(input.description ? { description: String(input.description) } : {}),
            status: 'active',
            createdBy: principal.identity.id,
            createdAt: now,
            updatedAt: now,
          });
        },
      },
      {
        method: 'POST',
        path: 'list',
        action: 'projects:read',
        validate(value) {
          const input = object(value);
          rejectUnknown(input, ['tenantId', 'status']);
          if (
            input.status !== undefined &&
            input.status !== null &&
            !['active', 'archived'].includes(String(input.status))
          )
            throw new IamError('INVALID_INPUT', 'status must be active or archived');
          const validated: Record<string, unknown> = { tenantId: input.tenantId };
          if (input.status !== undefined && input.status !== null)
            validated.status = String(input.status);
          return validated;
        },
        async handler({ store, tenantId }, input) {
          const projects = await store.find<Project>(
            COLLECTION,
            input.status ? { tenantId, status: String(input.status) } : { tenantId },
          );
          return [...projects].sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1));
        },
      },
      {
        method: 'POST',
        path: 'get',
        action: 'projects:read',
        validate(value) {
          const input = object(value);
          rejectUnknown(input, ['tenantId', 'projectId']);
          return { tenantId: input.tenantId, projectId: projectId(input.projectId) };
        },
        async handler({ store, tenantId }, input) {
          return load(store, String(input.projectId), tenantId);
        },
      },
      {
        method: 'POST',
        path: 'update',
        action: 'projects:write',
        validate(value) {
          const input = object(value);
          rejectUnknown(input, ['tenantId', 'projectId', 'name', 'description']);
          if (input.name === undefined && input.description === undefined)
            throw new IamError('INVALID_INPUT', 'Provide a name or description');
          const validated: Record<string, unknown> = {
            tenantId: input.tenantId,
            projectId: projectId(input.projectId),
          };
          if (input.name !== undefined) validated.name = text(input.name, 'name');
          if (input.description !== undefined) {
            const description = optionalText(input.description, 'description');
            // An explicit empty description clears the field; absent leaves it unchanged.
            if (description !== undefined) validated.description = description;
            else validated.clearDescription = true;
          }
          return validated;
        },
        async handler({ store, tenantId }, input) {
          const project = await load(store, String(input.projectId), tenantId);
          if (input.name !== undefined)
            await assertNameAvailable(store, tenantId, String(input.name), project.id);
          const next: Project = {
            ...project,
            ...(input.name !== undefined ? { name: String(input.name) } : {}),
          };
          if (input.clearDescription) delete next.description;
          else if (input.description !== undefined) next.description = String(input.description);
          return store.put<Project>(COLLECTION, { ...next, updatedAt: Date.now() });
        },
      },
      {
        method: 'POST',
        path: 'archive',
        action: 'projects:write',
        validate(value) {
          const input = object(value);
          rejectUnknown(input, ['tenantId', 'projectId']);
          return { tenantId: input.tenantId, projectId: projectId(input.projectId) };
        },
        async handler({ store, tenantId }, input) {
          const project = await load(store, String(input.projectId), tenantId);
          if (project.status !== 'active')
            throw new IamError('INVALID_TRANSITION', 'Project is not active');
          return store.put<Project>(COLLECTION, {
            ...project,
            status: 'archived',
            updatedAt: Date.now(),
          });
        },
      },
      {
        method: 'POST',
        path: 'restore',
        action: 'projects:write',
        validate(value) {
          const input = object(value);
          rejectUnknown(input, ['tenantId', 'projectId']);
          return { tenantId: input.tenantId, projectId: projectId(input.projectId) };
        },
        async handler({ store, tenantId }, input) {
          const project = await load(store, String(input.projectId), tenantId);
          if (project.status !== 'archived')
            throw new IamError('INVALID_TRANSITION', 'Project is not archived');
          return store.put<Project>(COLLECTION, {
            ...project,
            status: 'active',
            updatedAt: Date.now(),
          });
        },
      },
    ],
    /** Runs inside the server's purge transaction before tenant records are removed. */
    async purge(store, tenantIds) {
      for (const tenantId of tenantIds)
        for (const project of await store.find<Project>(COLLECTION, { tenantId }))
          await store.delete(COLLECTION, project.id);
    },
  };
}
