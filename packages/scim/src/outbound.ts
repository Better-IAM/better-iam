import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID } from 'node:crypto';
import {
  IamError,
  appendAuditEvent,
  tenantTreeActive,
  type CredentialInput,
  type IamStore,
  type Identity,
  type ResourceRef,
  type StoredRecord,
} from '@better-iam/core';

const USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const ENTERPRISE_SCHEMA = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
const PATCH_SCHEMA = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const GROUP_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:Group';
const loopback = ['localhost', '127.0.0.1', '[::1]'];

/** SCIM user attributes the provisioner can fill from declared identity attributes. */
export type ProvisioningAttribute = 'title' | 'department' | 'division' | 'employeeNumber';

export interface ProvisioningConfig {
  store: IamStore;
  /** `iam:scim:targets:*` on `scim/outbound/{targetId}`; `iam.protocolHost` supplies it. */
  authorize(credential: CredentialInput, action: string, resource: ResourceRef): Promise<unknown>;
  authenticate(credential: CredentialInput): Promise<{ identity: { id: string } }>;
  /** Base64-encoded 32-byte key that encrypts downstream bearer tokens at rest. */
  encryptionKey: string;
  /**
   * Keys being rotated out (base64, 32 bytes each): tokens sealed with them still open, and
   * `rotateKeys()` re-seals them with `encryptionKey`.
   */
  previousEncryptionKeys?: string[];
  /** Allows `http://` targets on loopback addresses, for local development and tests only. */
  allowInsecureLocalhost?: boolean;
  /** Per-request timeout for downstream calls (default 10 seconds). */
  timeoutMs?: number;
  fetch?: typeof fetch;
  /**
   * Where `handler` serves the JSON management API (`{basePath}/targets/{list,get,create,update,delete,sync}`),
   * default `/scim/provisioning`. Mount under the IAM API path (for example `/api/iam/provisioning`) to reach it with
   * the typed client's `$request('provisioning/targets/list', …)`.
   */
  basePath?: string;
}

export interface ProvisioningTargetInput {
  name: string;
  /** The downstream SCIM 2.0 base URL (the one ending before `/Users`). */
  baseUrl: string;
  /** Bearer token the downstream service issued for provisioning. Write-only. */
  token: string;
  /** Only members of these groups are provisioned; empty means every active member of the tenant. */
  groupIds?: string[];
  /** What happens downstream when someone leaves scope: `deactivate` (default, `active: false`) or `delete`. */
  deprovision?: 'deactivate' | 'delete';
  /** SCIM attribute → identity attribute name, e.g. `{ department: 'department' }`. */
  attributeMapping?: Partial<Record<ProvisioningAttribute, string>>;
  /** Also maintain the scoped `groupIds` downstream as SCIM groups whose members are the provisioned users. */
  pushGroups?: boolean;
  enabled?: boolean;
}

export interface ProvisioningRun {
  startedAt: number;
  finishedAt: number;
  created: number;
  updated: number;
  deactivated: number;
  deleted: number;
  unchanged: number;
  failed: number;
  /** Group changes when `pushGroups` is on. */
  groups: { created: number; updated: number; deleted: number; unchanged: number };
  /** The first 20 failures, for a member (`identityId`) or a pushed group (`groupId`). */
  errors: { identityId?: string; groupId?: string; status?: number; message: string }[];
}

/** One change a sync would make downstream. */
export interface ProvisioningChange {
  identityId: string;
  email?: string;
  action: 'create' | 'adopt' | 'update' | 'reactivate' | 'deactivate' | 'delete';
}

/** What `syncTarget` would do now, computed with read-only lookups downstream. */
export interface ProvisioningPreview {
  counts: Record<ProvisioningChange['action'] | 'unchanged', number>;
  /** The first 200 changes. */
  changes: ProvisioningChange[];
  /** Lookups that failed (a sync would retry them). */
  errors: { identityId: string; status?: number; message: string }[];
}

/** A provisioning target as administrators see it; the token is never returned. */ export interface ProvisioningTarget {
  id: string;
  tenantId: string;
  name: string;
  baseUrl: string;
  groupIds: string[];
  deprovision: 'deactivate' | 'delete';
  attributeMapping: Partial<Record<ProvisioningAttribute, string>>;
  pushGroups: boolean;
  enabled: boolean;
  createdAt: number;
  updatedAt: number;
  tokenUpdatedAt: number;
  /** Accounts currently provisioned (linked and active downstream). */
  provisioned: number;
  lastRun?: ProvisioningRun;
}

interface TargetRecord extends StoredRecord {
  name: string;
  baseUrl: string;
  sealedToken: string;
  groupIds: string[];
  deprovision: 'deactivate' | 'delete';
  attributeMapping: Partial<Record<ProvisioningAttribute, string>>;
  pushGroups?: boolean;
  enabled: boolean;
  createdAt: number;
  updatedAt: number;
  tokenUpdatedAt: number;
  lastRun?: ProvisioningRun;
}

interface LinkRecord extends StoredRecord {
  targetId: string;
  identityId: string;
  remoteId: string;
  fingerprint: string;
  active: boolean;
  syncedAt: number;
}

interface GroupLinkRecord extends StoredRecord {
  targetId: string;
  groupId: string;
  remoteId: string;
  fingerprint: string;
  syncedAt: number;
}

class DownstreamError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
  }
}

const hash = (value: string) => createHash('sha256').update(value).digest('hex');
/** Temporary and access-package memberships stop counting at `expiresAt`, before the purge worker removes them. */
const liveMembership = (membership: StoredRecord) =>
  typeof membership.expiresAt !== 'number' || membership.expiresAt > Date.now();

/**
 * Outbound SCIM 2.0 provisioning: keeps downstream applications' user directories in step with a tenant's members.
 * Each target receives the active members in scope (all members, or members of chosen groups) as SCIM users keyed by
 * `externalId`; people who leave scope, are disabled, or are deleted are deactivated (or deleted) downstream.
 */
export function createScimProvisioner(config: ProvisioningConfig) {
  const key = Buffer.from(config.encryptionKey ?? '', 'base64');
  if (key.length !== 32)
    throw new IamError('configuration', 'Provisioning encryptionKey must encode exactly 32 bytes.');
  const previousKeys = (config.previousEncryptionKeys ?? []).map((value) =>
    Buffer.from(value ?? '', 'base64'),
  );
  if (previousKeys.some((previous) => previous.length !== 32))
    throw new IamError(
      'configuration',
      'Each previous provisioning encryption key must encode exactly 32 bytes.',
    );
  const request = config.fetch ?? fetch;
  const timeoutMs = config.timeoutMs ?? 10_000;
  const running = new Map<string, Promise<ProvisioningRun>>();

  const seal = (value: string) => {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    return Buffer.concat([
      iv,
      cipher.update(value, 'utf8'),
      cipher.final(),
      cipher.getAuthTag(),
    ]).toString('base64');
  };
  /** Opens a sealed token with the current key or a previous one; `index` 0 is the current key. */
  const openWith = (value: string): { value: string; index: number } | undefined => {
    const buffer = Buffer.from(value, 'base64');
    for (const [index, candidate] of [key, ...previousKeys].entries()) {
      try {
        const decipher = createDecipheriv('aes-256-gcm', candidate, buffer.subarray(0, 12));
        decipher.setAuthTag(buffer.subarray(-16));
        return {
          value: Buffer.concat([
            decipher.update(buffer.subarray(12, -16)),
            decipher.final(),
          ]).toString('utf8'),
          index,
        };
      } catch {
        /* Try the next key. */
      }
    }
    return undefined;
  };
  const open = (value: string) => {
    const opened = openWith(value);
    if (!opened)
      throw new IamError('INVALID_SEALED_VALUE', 'The stored downstream token cannot be opened.');
    return opened.value;
  };

  function baseUrl(value: unknown): string {
    let parsed: URL;
    try {
      parsed = new URL(String(value));
    } catch {
      throw new IamError('INVALID_INPUT', 'The SCIM base URL must be an absolute HTTPS URL.');
    }
    const local =
      config.allowInsecureLocalhost &&
      parsed.protocol === 'http:' &&
      loopback.includes(parsed.hostname);
    if (
      (parsed.protocol !== 'https:' && !local) ||
      parsed.username ||
      parsed.password ||
      parsed.hash ||
      parsed.search
    )
      throw new IamError('INVALID_INPUT', 'The SCIM base URL must be an absolute HTTPS URL.');
    return `${parsed.origin}${parsed.pathname.replace(/\/$/, '')}`;
  }
  function settings(input: Partial<ProvisioningTargetInput>, current?: TargetRecord) {
    const name = input.name ?? current?.name;
    const groupIds = input.groupIds ?? current?.groupIds ?? [];
    const deprovision: 'deactivate' | 'delete' =
      input.deprovision ?? current?.deprovision ?? 'deactivate';
    const mapping = input.attributeMapping ?? current?.attributeMapping ?? {};
    const enabled = input.enabled ?? current?.enabled ?? true;
    const pushGroups = input.pushGroups ?? current?.pushGroups ?? false;
    if (typeof pushGroups !== 'boolean' || (pushGroups && !groupIds.length))
      throw new IamError('INVALID_INPUT', 'pushGroups needs the groups to push in groupIds.');
    if (typeof name !== 'string' || !name.trim() || name.length > 200)
      throw new IamError('INVALID_INPUT', 'A target name of at most 200 characters is required.');
    if (
      !Array.isArray(groupIds) ||
      groupIds.length > 50 ||
      groupIds.some((id) => typeof id !== 'string' || !id)
    )
      throw new IamError('INVALID_INPUT', 'groupIds must list at most 50 group IDs.');
    if (deprovision !== 'deactivate' && deprovision !== 'delete')
      throw new IamError('INVALID_INPUT', 'deprovision must be deactivate or delete.');
    if (
      !mapping ||
      typeof mapping !== 'object' ||
      Object.entries(mapping).some(
        ([attribute, source]) =>
          !['title', 'department', 'division', 'employeeNumber'].includes(attribute) ||
          typeof source !== 'string' ||
          !/^[a-zA-Z][a-zA-Z0-9_]{0,63}$/.test(source),
      )
    )
      throw new IamError(
        'INVALID_INPUT',
        'attributeMapping maps title, department, division, or employeeNumber to identity attributes.',
      );
    if (typeof enabled !== 'boolean')
      throw new IamError('INVALID_INPUT', 'enabled must be a boolean.');
    return {
      name: name.trim(),
      baseUrl: baseUrl(input.baseUrl ?? current?.baseUrl),
      groupIds: [...new Set(groupIds)],
      deprovision,
      attributeMapping: { ...mapping },
      pushGroups,
      enabled,
    };
  }
  function token(value: unknown): string {
    if (typeof value !== 'string' || value.length < 8 || value.length > 4096 || /\s/.test(value))
      throw new IamError('INVALID_INPUT', 'A downstream bearer token is required.');
    return value;
  }
  async function summary(target: TargetRecord, store: IamStore = config.store) {
    const links = await store.find<LinkRecord>('provisioningLinks', { targetId: target.id });
    const result: ProvisioningTarget = {
      id: target.id,
      tenantId: target.tenantId,
      name: target.name,
      baseUrl: target.baseUrl,
      groupIds: [...target.groupIds],
      deprovision: target.deprovision,
      attributeMapping: { ...target.attributeMapping },
      pushGroups: target.pushGroups === true,
      enabled: target.enabled,
      createdAt: target.createdAt,
      updatedAt: target.updatedAt,
      tokenUpdatedAt: target.tokenUpdatedAt,
      provisioned: links.filter((link) => link.active).length,
      ...(target.lastRun ? { lastRun: target.lastRun } : {}),
    };
    return result;
  }
  async function authorized(
    credential: CredentialInput,
    action: string,
    tenantId: string,
    targetId: string,
  ) {
    await config.authorize(credential, action, {
      tenantId,
      type: 'scim',
      id: `outbound/${targetId}`,
    });
    return config.authenticate(credential);
  }
  async function owned(store: IamStore, tenantId: string, targetId: string) {
    const target =
      typeof targetId === 'string' && targetId
        ? await store.get<TargetRecord>('provisioningTargets', targetId)
        : undefined;
    if (!target || target.tenantId !== tenantId)
      throw new IamError('NOT_FOUND', 'Provisioning target not found.', 404);
    return target;
  }
  async function audit(
    tx: IamStore,
    tenantId: string,
    actorId: string,
    action: string,
    resourceId: string,
  ) {
    await appendAuditEvent(tx, {
      id: randomUUID(),
      tenantId,
      actorId,
      action,
      resourceId,
      timestamp: Date.now(),
      outcome: 'allow',
    });
  }

  /** One downstream SCIM call with the target's bearer token. */
  async function call(
    target: TargetRecord,
    method: string,
    path: string,
    body?: unknown,
  ): Promise<{ status: number; json?: Record<string, unknown> }> {
    let response: Response;
    try {
      response = await request(`${target.baseUrl}${path}`, {
        method,
        redirect: 'error',
        signal: AbortSignal.timeout(timeoutMs),
        headers: {
          authorization: `Bearer ${open(target.sealedToken)}`,
          accept: 'application/scim+json',
          ...(body ? { 'content-type': 'application/scim+json' } : {}),
        },
        ...(body ? { body: JSON.stringify(body) } : {}),
      });
    } catch (error) {
      throw new DownstreamError(
        error instanceof Error && error.name === 'TimeoutError'
          ? 'The SCIM service did not answer in time.'
          : 'The SCIM service is unreachable.',
      );
    }
    const text = await response.text();
    if (text.length > 1_000_000) throw new DownstreamError('The SCIM response is too large.');
    let json: Record<string, unknown> | undefined;
    try {
      json = text ? (JSON.parse(text) as Record<string, unknown>) : undefined;
    } catch {
      json = undefined;
    }
    return { status: response.status, json };
  }
  function failure(result: { status: number; json?: Record<string, unknown> }, what: string) {
    const detail =
      typeof result.json?.detail === 'string' ? `: ${result.json.detail.slice(0, 200)}` : '';
    return new DownstreamError(`${what} failed with HTTP ${result.status}${detail}`, result.status);
  }

  /** The SCIM representation of an in-scope member. */
  function user(target: TargetRecord, identity: Identity) {
    const enterprise: Record<string, unknown> = {};
    let title: string | undefined;
    for (const [attribute, source] of Object.entries(target.attributeMapping)) {
      const value = identity.attributes?.[source];
      if (value === undefined || value === null) continue;
      if (attribute === 'title') title = String(value);
      else enterprise[attribute] = String(value);
    }
    return {
      schemas: [USER_SCHEMA, ...(Object.keys(enterprise).length ? [ENTERPRISE_SCHEMA] : [])],
      externalId: identity.id,
      userName: identity.email!,
      displayName: identity.name,
      name: { formatted: identity.name },
      emails: [{ value: identity.email!, type: 'work', primary: true }],
      ...(title !== undefined ? { title } : {}),
      active: true,
      ...(Object.keys(enterprise).length ? { [ENTERPRISE_SCHEMA]: enterprise } : {}),
    };
  }

  /** The single downstream resource matching one of the filters, if any. */
  async function lookup(target: TargetRecord, resource: 'Users' | 'Groups', filters: string[]) {
    for (const filter of filters) {
      const found = await call(
        target,
        'GET',
        `/${resource}?${new URLSearchParams({ filter, count: '2' })}`,
      );
      if (found.status !== 200) throw failure(found, `Looking up ${resource.toLowerCase()}`);
      const resources = Array.isArray(found.json?.Resources)
        ? (found.json!.Resources as { id?: unknown }[])
        : [];
      if (resources.length > 1)
        throw new DownstreamError(`Several downstream ${resource.toLowerCase()} match.`);
      if (resources.length === 1 && typeof resources[0]!.id === 'string') return resources[0]!.id;
    }
    return undefined;
  }
  const quoted = (value: string) => `"${value.replace(/["\\]/g, '')}"`;
  /** An existing downstream user for the same person, so a first sync adopts instead of duplicating. */
  function adopt(target: TargetRecord, identity: Identity): Promise<string | undefined> {
    return lookup(target, 'Users', [
      `externalId eq ${quoted(identity.id)}`,
      `userName eq ${quoted(identity.email!)}`,
    ]);
  }

  /**
   * With `pushGroups`, each scoped group exists downstream (adopted by `externalId` or `displayName`) with the
   * provisioned users as members; groups that leave scope or disappear are deleted downstream.
   */
  async function pushGroups(
    target: TargetRecord,
    live: boolean,
    run: ProvisioningRun,
    fail: (id: string, error: unknown, subject: 'groupId') => void,
  ): Promise<void> {
    const store = config.store;
    const links = new Map(
      (await store.find<GroupLinkRecord>('provisioningGroupLinks', { targetId: target.id })).map(
        (link) => [link.groupId, link],
      ),
    );
    if (!target.pushGroups && !links.size) return;
    const remoteUsers = new Map(
      (await store.find<LinkRecord>('provisioningLinks', { targetId: target.id }))
        .filter((link) => link.active)
        .map((link) => [link.identityId, link.remoteId]),
    );
    const wanted = new Set<string>();
    for (const groupId of live && target.pushGroups ? target.groupIds : []) {
      const group = await store.get<StoredRecord & { name?: string }>('groups', groupId);
      if (!group || group.tenantId !== target.tenantId || typeof group.name !== 'string') continue;
      wanted.add(groupId);
      const members = (await store.find('groupMembers', { tenantId: target.tenantId, groupId }))
        .filter(liveMembership)
        .map((membership) => remoteUsers.get(String(membership.identityId)))
        .filter((remoteId): remoteId is string => !!remoteId)
        .sort()
        .map((value) => ({ value }));
      const payload = {
        schemas: [GROUP_SCHEMA],
        externalId: groupId,
        displayName: group.name,
        members,
      };
      const fingerprint = hash(JSON.stringify(payload));
      const link = links.get(groupId);
      try {
        if (link?.fingerprint === fingerprint) {
          run.groups.unchanged++;
          continue;
        }
        let remoteId =
          link?.remoteId ??
          (await lookup(target, 'Groups', [
            `externalId eq ${quoted(groupId)}`,
            `displayName eq ${quoted(group.name)}`,
          ]));
        let created = false;
        if (remoteId) {
          const replaced = await call(target, 'PUT', `/Groups/${encodeURIComponent(remoteId)}`, {
            ...payload,
            id: remoteId,
          });
          if (replaced.status === 404) remoteId = undefined;
          else if (replaced.status < 200 || replaced.status >= 300)
            throw failure(replaced, 'Updating the group');
        }
        if (!remoteId) {
          const posted = await call(target, 'POST', '/Groups', payload);
          if (posted.status !== 201 && posted.status !== 200)
            throw failure(posted, 'Creating the group');
          if (typeof posted.json?.id !== 'string')
            throw new DownstreamError('The SCIM service returned no group ID.');
          remoteId = posted.json.id;
          created = true;
        }
        const record: GroupLinkRecord = {
          id: hash(`${target.id}:group:${groupId}`),
          tenantId: target.tenantId,
          targetId: target.id,
          groupId,
          remoteId,
          fingerprint,
          syncedAt: Date.now(),
        };
        await store.transaction(async (tx) => {
          if (await tx.get('provisioningGroupLinks', record.id))
            await tx.put('provisioningGroupLinks', record);
          else await tx.insert('provisioningGroupLinks', record);
        });
        if (created) run.groups.created++;
        else run.groups.updated++;
      } catch (error) {
        fail(groupId, error, 'groupId');
      }
    }
    for (const [groupId, link] of links) {
      if (wanted.has(groupId)) continue;
      try {
        const removed = await call(
          target,
          'DELETE',
          `/Groups/${encodeURIComponent(link.remoteId)}`,
        );
        if (removed.status !== 204 && removed.status !== 200 && removed.status !== 404)
          throw failure(removed, 'Deleting the group');
        await store.transaction((tx) => tx.delete('provisioningGroupLinks', link.id));
        run.groups.deleted++;
      } catch (error) {
        fail(groupId, error, 'groupId');
      }
    }
  }

  /** Who should exist downstream now, and what the target has provisioned so far. */
  async function scopeOf(target: TargetRecord) {
    const store = config.store;
    const active = await tenantTreeActive(store, target.tenantId);
    const members = new Set<string>();
    if (target.groupIds.length)
      for (const groupId of target.groupIds)
        for (const membership of await store.find('groupMembers', {
          tenantId: target.tenantId,
          groupId,
        }))
          if (liveMembership(membership)) members.add(String(membership.identityId));
    const inScope = new Map<string, Identity>();
    if (active && target.enabled)
      for (const identity of await store.find<Identity>('identities', {
        tenantId: target.tenantId,
      }))
        if (
          identity.kind === 'user' &&
          identity.status === 'active' &&
          identity.email &&
          (typeof identity.expiresAt !== 'number' || identity.expiresAt > Date.now()) &&
          (!target.groupIds.length || members.has(identity.id))
        )
          inScope.set(identity.id, identity);
    const links = new Map(
      (await store.find<LinkRecord>('provisioningLinks', { targetId: target.id })).map((link) => [
        link.identityId,
        link,
      ]),
    );
    return { active, inScope, links };
  }

  /** The plan of the next sync: never writes downstream or to the store. */
  async function preview(target: TargetRecord): Promise<ProvisioningPreview> {
    const { inScope, links } = await scopeOf(target);
    const result: ProvisioningPreview = {
      counts: {
        create: 0,
        adopt: 0,
        update: 0,
        reactivate: 0,
        deactivate: 0,
        delete: 0,
        unchanged: 0,
      },
      changes: [],
      errors: [],
    };
    const plan = (change: ProvisioningChange) => {
      result.counts[change.action]++;
      if (result.changes.length < 200) result.changes.push(change);
    };
    for (const [identityId, identity] of inScope) {
      const link = links.get(identityId);
      if (link) {
        if (!link.active) plan({ identityId, email: identity.email, action: 'reactivate' });
        else if (link.fingerprint !== hash(JSON.stringify(user(target, identity))))
          plan({ identityId, email: identity.email, action: 'update' });
        else result.counts.unchanged++;
        continue;
      }
      try {
        const existing = await adopt(target, identity);
        plan({ identityId, email: identity.email, action: existing ? 'adopt' : 'create' });
      } catch (error) {
        if (result.errors.length < 20)
          result.errors.push({
            identityId,
            ...(error instanceof DownstreamError && error.status ? { status: error.status } : {}),
            message: error instanceof DownstreamError ? error.message : 'Lookup failed.',
          });
      }
    }
    for (const [identityId, link] of links) {
      if (inScope.has(identityId)) continue;
      if (target.deprovision === 'delete') plan({ identityId, action: 'delete' });
      else if (link.active) plan({ identityId, action: 'deactivate' });
    }
    return result;
  }
  async function reconcile(target: TargetRecord): Promise<ProvisioningRun> {
    const run: ProvisioningRun = {
      startedAt: Date.now(),
      finishedAt: 0,
      created: 0,
      updated: 0,
      deactivated: 0,
      deleted: 0,
      unchanged: 0,
      failed: 0,
      groups: { created: 0, updated: 0, deleted: 0, unchanged: 0 },
      errors: [],
    };
    const fail = (
      identityId: string,
      error: unknown,
      subject: 'identityId' | 'groupId' = 'identityId',
    ) => {
      run.failed++;
      if (run.errors.length < 20)
        run.errors.push({
          [subject]: identityId,
          ...(error instanceof DownstreamError && error.status ? { status: error.status } : {}),
          message:
            error instanceof DownstreamError ? error.message : 'Provisioning failed unexpectedly.',
        });
    };
    const store = config.store;
    const { active, inScope, links } = await scopeOf(target);
    const save = (link: LinkRecord) =>
      store.transaction(async (tx) => {
        if (await tx.get('provisioningLinks', link.id)) await tx.put('provisioningLinks', link);
        else await tx.insert('provisioningLinks', link);
      });

    for (const [identityId, identity] of inScope) {
      const payload = user(target, identity);
      const fingerprint = hash(JSON.stringify(payload));
      const link = links.get(identityId);
      try {
        if (link?.active && link.fingerprint === fingerprint) {
          run.unchanged++;
          continue;
        }
        let remoteId = link?.remoteId ?? (await adopt(target, identity));
        let created = false;
        if (remoteId) {
          const replaced = await call(target, 'PUT', `/Users/${encodeURIComponent(remoteId)}`, {
            ...payload,
            id: remoteId,
          });
          if (replaced.status === 404) remoteId = undefined;
          else if (replaced.status < 200 || replaced.status >= 300)
            throw failure(replaced, 'Updating the user');
        }
        if (!remoteId) {
          const posted = await call(target, 'POST', '/Users', payload);
          if (posted.status !== 201 && posted.status !== 200)
            throw failure(posted, 'Creating the user');
          if (typeof posted.json?.id !== 'string')
            throw new DownstreamError('The SCIM service returned no user ID.');
          remoteId = posted.json.id;
          created = true;
        }
        await save({
          id: hash(`${target.id}:${identityId}`),
          tenantId: target.tenantId,
          targetId: target.id,
          identityId,
          remoteId,
          fingerprint,
          active: true,
          syncedAt: Date.now(),
        });
        if (created) run.created++;
        else run.updated++;
      } catch (error) {
        fail(identityId, error);
      }
    }
    for (const [identityId, link] of links) {
      if (inScope.has(identityId)) continue;
      try {
        if (target.deprovision === 'delete') {
          const removed = await call(
            target,
            'DELETE',
            `/Users/${encodeURIComponent(link.remoteId)}`,
          );
          if (removed.status !== 204 && removed.status !== 200 && removed.status !== 404)
            throw failure(removed, 'Deleting the user');
          await store.transaction((tx) => tx.delete('provisioningLinks', link.id));
          run.deleted++;
          continue;
        }
        if (!link.active) continue;
        const patched = await call(target, 'PATCH', `/Users/${encodeURIComponent(link.remoteId)}`, {
          schemas: [PATCH_SCHEMA],
          Operations: [{ op: 'replace', value: { active: false } }],
        });
        if (patched.status === 404) {
          await store.transaction((tx) => tx.delete('provisioningLinks', link.id));
          continue;
        }
        if (patched.status < 200 || patched.status >= 300)
          throw failure(patched, 'Deactivating the user');
        await save({ ...link, active: false, fingerprint: '', syncedAt: Date.now() });
        run.deactivated++;
      } catch (error) {
        fail(identityId, error);
      }
    }
    await pushGroups(target, active && target.enabled, run, fail);
    run.finishedAt = Date.now();
    await store.transaction(async (tx) => {
      const current = await tx.get<TargetRecord>('provisioningTargets', target.id);
      if (current) await tx.put('provisioningTargets', { ...current, lastRun: run });
    });
    return run;
  }
  /** Runs one reconciliation per target at a time; concurrent requests share the running one. */
  function runOnce(target: TargetRecord): Promise<ProvisioningRun> {
    const pending = running.get(target.id);
    if (pending) return pending;
    const run = reconcile(target).finally(() => running.delete(target.id));
    running.set(target.id, run);
    return run;
  }

  async function syncAll(
    input: { tenantId?: string } = {},
  ): Promise<Record<string, ProvisioningRun>> {
    const targets = await config.store.find<TargetRecord>(
      'provisioningTargets',
      input.tenantId ? { tenantId: input.tenantId } : undefined,
    );
    const runs: Record<string, ProvisioningRun> = {};
    for (const target of targets) runs[target.id] = await runOnce(target);
    return runs;
  }

  const basePath = (config.basePath ?? '/scim/provisioning').replace(/\/$/, '');
  const api = {
    /** Adds a downstream application (`iam:scim:targets:create`). The token is encrypted and never returned. */
    async createTarget(
      credential: CredentialInput,
      input: ProvisioningTargetInput & { tenantId: string },
    ): Promise<ProvisioningTarget> {
      const id = `scim-target-${randomBytes(8).toString('hex')}`;
      const principal = await authorized(credential, 'iam:scim:targets:create', input.tenantId, id);
      const values = settings(input);
      const sealedToken = seal(token(input.token));
      return config.store.transaction(async (tx) => {
        if (!(await tenantTreeActive(tx, input.tenantId)))
          throw new IamError('TENANT_INACTIVE', 'Tenant unavailable.', 403);
        const now = Date.now();
        const record: TargetRecord = {
          id,
          tenantId: input.tenantId,
          ...values,
          sealedToken,
          createdAt: now,
          updatedAt: now,
          tokenUpdatedAt: now,
        };
        await tx.insert('provisioningTargets', record);
        await audit(tx, input.tenantId, principal.identity.id, 'iam:scim:CreateTarget', id);
        return summary(record, tx);
      });
    },
    async listTargets(
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<ProvisioningTarget[]> {
      await authorized(credential, 'iam:scim:targets:read', input.tenantId, '*');
      const targets = await config.store.find<TargetRecord>('provisioningTargets', {
        tenantId: input.tenantId,
      });
      return Promise.all(
        targets
          .sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1))
          .map((t) => summary(t)),
      );
    },
    async getTarget(
      credential: CredentialInput,
      input: { tenantId: string; targetId: string },
    ): Promise<ProvisioningTarget> {
      await authorized(credential, 'iam:scim:targets:read', input.tenantId, input.targetId);
      return summary(await owned(config.store, input.tenantId, input.targetId));
    },
    /** Changes a target; a new `token` replaces the stored one. Scope changes apply at the next sync. */
    async updateTarget(
      credential: CredentialInput,
      input: Partial<ProvisioningTargetInput> & { tenantId: string; targetId: string },
    ): Promise<ProvisioningTarget> {
      const principal = await authorized(
        credential,
        'iam:scim:targets:update',
        input.tenantId,
        input.targetId,
      );
      return config.store.transaction(async (tx) => {
        const current = await owned(tx, input.tenantId, input.targetId);
        const now = Date.now();
        const record: TargetRecord = {
          ...current,
          ...settings(input, current),
          ...(input.token !== undefined
            ? { sealedToken: seal(token(input.token)), tokenUpdatedAt: now }
            : {}),
          updatedAt: now,
        };
        await tx.put('provisioningTargets', record);
        await audit(tx, input.tenantId, principal.identity.id, 'iam:scim:UpdateTarget', current.id);
        return summary(record, tx);
      });
    },
    /** Removes a target and its links. Downstream accounts are left as they are. */
    async deleteTarget(
      credential: CredentialInput,
      input: { tenantId: string; targetId: string },
    ): Promise<void> {
      const principal = await authorized(
        credential,
        'iam:scim:targets:delete',
        input.tenantId,
        input.targetId,
      );
      await config.store.transaction(async (tx) => {
        const current = await owned(tx, input.tenantId, input.targetId);
        for (const link of await tx.find<LinkRecord>('provisioningLinks', { targetId: current.id }))
          await tx.delete('provisioningLinks', link.id);
        for (const link of await tx.find('provisioningGroupLinks', { targetId: current.id }))
          await tx.delete('provisioningGroupLinks', link.id);
        await tx.delete('provisioningTargets', current.id);
        await audit(tx, input.tenantId, principal.identity.id, 'iam:scim:DeleteTarget', current.id);
      });
    },
    /** What a sync would change right now (`iam:scim:targets:read`); only read-only lookups reach the application. */
    async previewTarget(
      credential: CredentialInput,
      input: { tenantId: string; targetId: string },
    ): Promise<ProvisioningPreview> {
      await authorized(credential, 'iam:scim:targets:read', input.tenantId, input.targetId);
      return preview(await owned(config.store, input.tenantId, input.targetId));
    },
    /** Reconciles one target now (`iam:scim:targets:sync`) and returns the run. */ async syncTarget(
      credential: CredentialInput,
      input: { tenantId: string; targetId: string },
    ): Promise<ProvisioningRun> {
      const principal = await authorized(
        credential,
        'iam:scim:targets:sync',
        input.tenantId,
        input.targetId,
      );
      const target = await owned(config.store, input.tenantId, input.targetId);
      const run = await runOnce(target);
      await config.store.transaction((tx) =>
        audit(tx, input.tenantId, principal.identity.id, 'iam:scim:SyncTarget', target.id),
      );
      return run;
    },
    /**
     * Deployment operation for schedulers and event hooks: reconciles every target (optionally one tenant's). Runs
     * with no credential; do not expose it over HTTP.
     */
    syncAll,
    /**
     * Keeps targets current from IAM events: membership, identity, and tenant changes schedule a sync of the
     * tenant's targets after `debounceMs` (default 2 seconds). Returns the unsubscribe function.
     */
    subscribe(
      events: {
        subscribe(
          pattern: string[],
          handler: (event: { tenantId: string; action: string }) => unknown,
        ): () => void;
      },
      options: { debounceMs?: number; onError?(error: unknown): void } = {},
    ): () => void {
      const timers = new Map<string, ReturnType<typeof setTimeout>>();
      const unsubscribe = events.subscribe(
        [
          'iam:identities:*',
          'iam:groups:*',
          'iam:packages:*',
          'package:*',
          'group:*',
          'iam:tenants:*',
          'iam:scim:*',
          'identity:*',
          'tenant:*',
          'invitation:*',
        ],
        (event) => {
          // The provisioner's own management and sync events never schedule another run.
          if (/^iam:scim:\w+Target$/.test(event.action)) return;
          clearTimeout(timers.get(event.tenantId));
          const timer = setTimeout(() => {
            timers.delete(event.tenantId);
            syncAll({ tenantId: event.tenantId }).catch((error) => options.onError?.(error));
          }, options.debounceMs ?? 2000);
          timer.unref?.();
          timers.set(event.tenantId, timer);
        },
      );
      return () => {
        unsubscribe();
        for (const timer of timers.values()) clearTimeout(timer);
        timers.clear();
      };
    },
  };

  const routes: Record<string, (credential: CredentialInput, body: never) => Promise<unknown>> = {
    'targets/list': api.listTargets,
    'targets/get': api.getTarget,
    'targets/create': api.createTarget,
    'targets/update': api.updateTarget,
    'targets/delete': api.deleteTarget,
    'targets/sync': api.syncTarget,
    'targets/preview': api.previewTarget,
  };
  /**
   * JSON management API for browsers and scripts: `POST {basePath}/targets/…` with the caller's IAM cookie or bearer
   * token. Like the IAM API it requires `X-Better-IAM: 1` and a JSON body, so cross-site forms cannot call it, and it
   * answers `{ data }` or `{ error: { code, message } }`.
   */
  async function handler(request: Request): Promise<Response | undefined> {
    const url = new URL(request.url);
    if (!url.pathname.startsWith(`${basePath}/`)) return undefined;
    const route = routes[url.pathname.slice(basePath.length + 1)];
    const reply = (body: unknown, status = 200) =>
      Response.json(body, { status, headers: { 'cache-control': 'no-store' } });
    if (!route) return reply({ error: { code: 'NOT_FOUND', message: 'Unknown route.' } }, 404);
    try {
      if (request.method !== 'POST') throw new IamError('METHOD_NOT_ALLOWED', 'Use POST.', 405);
      if (
        request.headers.get('x-better-iam') !== '1' ||
        !request.headers.get('content-type')?.startsWith('application/json')
      )
        throw new IamError('CSRF_REJECTED', 'JSON requests require X-Better-IAM: 1.', 403);
      const text = await request.text();
      if (text.length > 64 * 1024) throw new IamError('INVALID_INPUT', 'Request too large.', 413);
      let body: unknown;
      try {
        body = text ? JSON.parse(text) : {};
      } catch {
        throw new IamError('INVALID_INPUT', 'The body must be JSON.', 400);
      }
      if (!body || typeof body !== 'object' || Array.isArray(body))
        throw new IamError('INVALID_INPUT', 'The body must be a JSON object.', 400);
      const data = await route({ headers: request.headers }, body as never);
      return reply({ data: data ?? null });
    } catch (error) {
      const known = error instanceof IamError;
      return reply(
        {
          error: {
            code: known ? error.code : 'INTERNAL_ERROR',
            message: known ? error.message : 'Provisioning request failed.',
          },
        },
        known ? error.status : 500,
      );
    }
  }
  /**
   * Deployment operation (not served over HTTP): re-seals every stored downstream token opened by
   * a previous key with `encryptionKey`, so the previous keys can be removed. Idempotent.
   */
  async function rotateKeys(): Promise<{ resealed: number; current: number; unreadable: number }> {
    const result = { resealed: 0, current: 0, unreadable: 0 };
    let after: string | undefined;
    for (;;) {
      const page = await config.store.transaction(async (tx) => {
        const targets = await tx.find<TargetRecord>(
          'provisioningTargets',
          {},
          {
            limit: 200,
            ...(after === undefined ? {} : { after }),
          },
        );
        for (const target of targets) {
          const opened = openWith(target.sealedToken);
          if (!opened) result.unreadable++;
          else if (opened.index === 0) result.current++;
          else {
            await tx.put('provisioningTargets', { ...target, sealedToken: seal(opened.value) });
            result.resealed++;
          }
        }
        return targets;
      });
      if (page.length < 200) return result;
      after = page.at(-1)!.id;
    }
  }

  return { ...api, basePath, handler, rotateKeys };
}

export type ScimProvisioner = ReturnType<typeof createScimProvisioner>;
