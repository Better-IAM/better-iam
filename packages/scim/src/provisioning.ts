import { randomUUID, timingSafeEqual } from 'node:crypto';
import {
  IamError,
  appendAuditEvent,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Tenant,
} from '@better-iam/core';
import {
  ENTERPRISE_SCHEMA,
  GROUP_SCHEMA,
  PATCH_SCHEMA,
  USER_SCHEMA,
  type Connection,
  type GroupLink,
  type ObjectValue,
  type ResourceType,
  type ScimConfig,
  type UserLink,
} from './types.js';
import { applyPatchOperation } from './patch.js';
import { activeTenant, bool, fields, hash, object, text } from './validation.js';

/** The enterprise extension's `manager.value`, trimmed, if any. */
function managerValue(enterprise: ObjectValue | undefined): string | undefined {
  const manager = enterprise?.manager;
  const value = manager && typeof manager === 'object' ? (manager as ObjectValue).value : undefined;
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}
/** Resolves a manager reference; `self` is the user holding it. */
type ManagerLookup = (value: string, self?: UserLink) => UserLink | undefined;
/**
 * Indexes a connection's users once, so resolving any number of manager references stays linear. A reference names
 * the user with that SCIM ID, else the case-exact `externalId`, else the `userName` ignoring case. At each step `self`
 * wins over other users (naming oneself names no manager, so resolution never falls through to someone else), then
 * the first matching user in `users`.
 */
function managerIndex(users: UserLink[]): ManagerLookup {
  const byId = new Map<string, UserLink>();
  const byExternalId = new Map<string, UserLink>();
  const byUserName = new Map<string, UserLink>();
  for (const row of users) {
    if (!byId.has(row.id)) byId.set(row.id, row);
    if (row.externalId !== undefined && !byExternalId.has(row.externalId))
      byExternalId.set(row.externalId, row);
    const userName = row.userName.toLowerCase();
    if (!byUserName.has(userName)) byUserName.set(userName, row);
  }
  return (value, self) => {
    const lower = value.toLowerCase();
    if (self?.id === value) return self;
    if (byId.has(value)) return byId.get(value);
    if (self?.externalId === value) return self;
    if (byExternalId.has(value)) return byExternalId.get(value);
    if (self?.userName.toLowerCase() === lower) return self;
    return byUserName.get(lower);
  };
}

/**
 * Provisioning logic shared by the connection API and the HTTP handler: connection authentication,
 * user and group persistence, membership and role-mapping synchronization, and PATCH application.
 */
export function createProvisioning(config: ScimConfig) {
  async function audit(
    tx: IamStore,
    connection: Connection,
    action: string,
    resourceId: string,
    actorId = `scim:${connection.id}`,
  ): Promise<void> {
    const event = {
      id: randomUUID(),
      tenantId: connection.tenantId,
      actorId,
      action,
      resourceId,
      timestamp: Date.now(),
      outcome: 'allow' as const,
    };
    // Through the host when it can fan events out (webhooks, subscribers such as an outbound provisioner).
    if (config.recordAudit) await config.recordAudit(tx, event);
    else await appendAuditEvent(tx, event);
  }
  async function authenticate(
    tx: IamStore,
    request: Request,
    connectionId: string,
  ): Promise<Connection> {
    const connection = await tx.get<Connection>('scimConnections', connectionId);
    const token = request.headers.get('authorization')?.match(/^Bearer (\S+)$/i)?.[1];
    if (
      !connection ||
      !token ||
      connection.revoked ||
      connection.expiresAt <= Date.now() ||
      !timingSafeEqual(Buffer.from(hash(token)), Buffer.from(connection.tokenHash))
    )
      throw new IamError('unauthorized', 'Invalid SCIM credential.', 401);
    await activeTenant(tx, connection.tenantId);
    const now = Date.now();
    if (!connection.lastUsedAt || now - connection.lastUsedAt >= 60_000) {
      connection.lastUsedAt = now;
      await tx.put('scimConnections', connection);
    }
    return connection;
  }
  /**
   * Ends everything that keeps a person signed in or lets them skip a step, as an administrator's disable does:
   * sessions (and those acting as them), remembered MFA devices and pending sign-in challenges.
   */
  async function revokeSessions(tx: IamStore, identityId: string): Promise<void> {
    for (const session of await tx.find('sessions', { identityId }))
      await tx.delete('sessions', session.id);
    for (const session of await tx.find('sessions', { originalIdentityId: identityId }))
      await tx.delete('sessions', session.id);
    for (const device of await tx.find('authDevices', { identityId }))
      await tx.delete('authDevices', device.id);
    for (const challenge of await tx.find('authChallenges', { identityId }))
      await tx.delete('authChallenges', challenge.id);
  }
  /** The tenant's plan limit (`Tenant.limits`) holds for SCIM as for every other way people and groups are added. */
  async function withinLimit(
    tx: IamStore,
    tenantId: string,
    key: 'identities' | 'groups',
  ): Promise<void> {
    const limit = (await tx.get<Tenant>('tenants', tenantId))?.limits?.[key];
    if (limit === undefined) return;
    const count =
      key === 'identities'
        ? (await tx.find<Identity>('identities', { tenantId, kind: 'user' })).filter(
            (item) => item.status !== 'deleted',
          ).length
        : (await tx.find('groups', { tenantId })).length;
    if (count >= limit)
      throw new IamError(
        'LIMIT_EXCEEDED',
        `This tenant has reached its ${key === 'identities' ? 'member' : 'group'} limit (${limit}).`,
        409,
      );
  }
  /** The local identity behind a SCIM user; owners and root administrators are never provisioning targets. */
  async function identity(tx: IamStore, link: UserLink): Promise<Identity> {
    const found = await tx.get<Identity>('identities', link.identityId);
    if (!found || found.tenantId !== link.tenantId || found.rootAdmin || found.owner)
      throw new IamError('mutability', 'SCIM cannot modify a protected identity.', 403);
    return found;
  }
  /** The identity a SCIM user update writes; one an administrator deleted stays a tombstone and is never revived. */
  async function updatable(tx: IamStore, link: UserLink): Promise<Identity> {
    const found = await identity(tx, link);
    if (found.status === 'deleted')
      throw new IamError('mutability', 'SCIM cannot modify a deleted identity.', 403);
    return found;
  }
  /**
   * The identity SCIM may make `report`'s manager: another identity of the tenant that is not deleted and does not
   * already report to `report` (directly or up to 100 levels up). Undefined skips the assignment; it is never an error.
   */
  async function assignableManager(
    tx: IamStore,
    report: Identity,
    manager: UserLink,
  ): Promise<string | undefined> {
    const found = await tx.get<Identity>('identities', manager.identityId);
    if (
      !found ||
      found.tenantId !== report.tenantId ||
      found.status === 'deleted' ||
      found.id === report.id
    )
      return undefined;
    let cursor: Identity | undefined = found;
    for (let depth = 0; cursor?.managerId && depth < 100; depth++) {
      if (cursor.managerId === report.id) return undefined;
      cursor = await tx.get<Identity>('identities', cursor.managerId);
    }
    return found.id;
  }
  /** Identities of reports whose provisioned `manager.value` resolves to `manager`, excluding protected ones. */
  async function reportsOf(
    tx: IamStore,
    users: UserLink[],
    manager: UserLink,
  ): Promise<Identity[]> {
    const result: Identity[] = [];
    const resolve = managerIndex(users);
    for (const row of users) {
      const value = managerValue(row.enterprise);
      if (row.id === manager.id || value === undefined || resolve(value, row)?.id !== manager.id)
        continue;
      const report = await tx.get<Identity>('identities', row.identityId);
      if (
        report &&
        report.tenantId === manager.tenantId &&
        report.status !== 'deleted' &&
        !report.owner &&
        !report.rootAdmin
      )
        result.push(report);
    }
    return result;
  }
  /** Back-fills the manager of reports provisioned before `manager`, unless they already have one. */
  async function adoptReports(
    tx: IamStore,
    connection: Connection,
    users: UserLink[],
    manager: UserLink,
  ): Promise<void> {
    for (const report of await reportsOf(tx, users, manager)) {
      if (report.managerId) continue;
      const managerId = await assignableManager(tx, report, manager);
      if (!managerId) continue;
      await tx.put('identities', { ...report, managerId });
      await audit(tx, connection, 'iam:scim:UpdateUser', report.id);
    }
  }
  async function members(tx: IamStore, connection: Connection, value: unknown): Promise<string[]> {
    if (!Array.isArray(value) || value.length > 1000)
      throw new IamError('invalidValue', 'members must contain at most 1000 User references.');
    const result: string[] = [];
    for (const item of value) {
      const data = object(item);
      fields(data, ['value', '$ref', 'display', 'type']);
      if (data.type !== undefined && data.type !== 'User')
        throw new IamError('invalidValue', 'Nested groups are not supported.');
      const id = text(data.value, 'member.value')!;
      const user = await tx.get<UserLink>('scimUsers', id);
      if (!user || user.connectionId !== connection.id || user.tenantId !== connection.tenantId)
        throw new IamError('invalidValue', 'Member is outside this SCIM connection.');
      await identity(tx, user);
      result.push(id);
    }
    return [...new Set(result)];
  }
  /** Reconciles local group membership with the SCIM group and applies administrator-configured role mappings. */
  async function syncGroup(
    tx: IamStore,
    connection: Connection,
    link: GroupLink,
    credential?: CredentialInput,
  ): Promise<void> {
    const desired = new Set<string>();
    for (const memberId of link.members) {
      const user = await tx.get<UserLink>('scimUsers', memberId);
      if (!user || user.connectionId !== connection.id || user.tenantId !== connection.tenantId)
        continue;
      // An identity an administrator deleted never regains memberships, nor the roles mapped to them.
      const local = await tx.get<Identity>('identities', user.identityId);
      if (local?.status !== 'deleted') desired.add(user.identityId);
    }
    for (const row of await tx.find('groupMembers', {
      tenantId: connection.tenantId,
      groupId: link.groupId,
    })) {
      if (!desired.delete(String(row.identityId))) await tx.delete('groupMembers', row.id);
    }
    for (const identityId of desired)
      await tx.insert('groupMembers', {
        id: randomUUID(),
        tenantId: connection.tenantId,
        groupId: link.groupId,
        identityId,
        uniqueKey: `${link.groupId}:${identityId}`,
      });
    const roleIds = connection.roleMappings[link.id] ?? [];
    if (roleIds.length && !config.syncRoleMappings)
      throw new IamError('configuration', 'Role mapping callback is missing.');
    if (config.syncRoleMappings) {
      const allMembers = await tx.find('groupMembers', {
        tenantId: connection.tenantId,
        groupId: link.groupId,
      });
      await config.syncRoleMappings(tx, {
        tenantId: connection.tenantId,
        connectionId: connection.id,
        groupId: link.groupId,
        identityIds: allMembers.map((row) => String(row.identityId)),
        roleIds,
        credential,
      });
    }
  }
  function validateEmails(emails: unknown): asserts emails is ObjectValue[] | undefined {
    if (emails === undefined) return;
    if (!Array.isArray(emails) || emails.length > 20)
      throw new IamError('invalidValue', 'emails must contain at most 20 email values.');
    for (const entry of emails) {
      const email = object(entry);
      fields(email, ['value', 'type', 'primary', 'display']);
      const value = text(email.value, 'email')!;
      if (value.length > 320 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value))
        throw new IamError('invalidValue', 'Invalid email address.');
      if (email.primary !== undefined && typeof email.primary !== 'boolean')
        throw new IamError('invalidValue', 'email.primary must be a boolean.');
    }
    if (emails.filter((value) => object(value).primary === true).length > 1)
      throw new IamError('invalidValue', 'Only one primary email is allowed.');
  }
  async function saveUser(
    tx: IamStore,
    connection: Connection,
    data: ObjectValue,
    existing?: UserLink,
  ): Promise<UserLink> {
    fields(data, [
      'schemas',
      'userName',
      'displayName',
      'externalId',
      'active',
      'emails',
      'name',
      'title',
      ENTERPRISE_SCHEMA,
    ]);
    if (
      data.schemas !== undefined &&
      (!Array.isArray(data.schemas) ||
        data.schemas.some((x) => x !== USER_SCHEMA && x !== ENTERPRISE_SCHEMA))
    )
      throw new IamError('invalidValue', 'Unsupported User schema.');
    const userName = text(data.userName, 'userName')!;
    const displayName = text(data.displayName, 'displayName', true) ?? userName;
    const externalId = text(data.externalId, 'externalId', true);
    const active = bool(data.active, true);
    const title = text(data.title, 'title', true);
    let enterprise: ObjectValue | undefined;
    if (data[ENTERPRISE_SCHEMA] !== undefined) {
      enterprise = { ...object(data[ENTERPRISE_SCHEMA]) };
      fields(enterprise, [
        'employeeNumber',
        'costCenter',
        'organization',
        'division',
        'department',
        'manager',
      ]);
      // Entra ID adds the manager as a bare ID (`path: "…:manager", value: "<id>"`).
      if (typeof enterprise.manager === 'string')
        enterprise.manager = { value: enterprise.manager };
      for (const [field, value] of Object.entries(enterprise))
        if (field === 'manager') {
          const manager = object(value);
          fields(manager, ['value', 'displayName', '$ref']);
          for (const [key, item] of Object.entries(manager)) text(item, `manager.${key}`, true);
        } else text(value, field, true);
    }
    const normalized = userName.toLowerCase();
    const others = (
      await tx.find<UserLink>('scimUsers', {
        tenantId: connection.tenantId,
        connectionId: connection.id,
      })
    ).filter((row) => row.id !== existing?.id);
    if (others.some((row) => row.userName.toLowerCase() === normalized))
      throw new IamError('uniqueness', 'userName already exists.', 409);
    // Provisioning never implicitly takes over an account based on email or name.
    const record: Identity = existing
      ? await updatable(tx, existing)
      : {
          id: randomUUID(),
          tenantId: connection.tenantId,
          kind: 'user',
          name: displayName,
          status: active ? 'active' : 'disabled',
          emailVerified: false,
          rootAdmin: false,
          owner: false,
          createdAt: Date.now(),
        };
    const emails = data.emails;
    validateEmails(emails);
    let name: ObjectValue | undefined;
    if (data.name !== undefined) {
      name = object(data.name);
      fields(name, [
        'formatted',
        'familyName',
        'givenName',
        'middleName',
        'honorificPrefix',
        'honorificSuffix',
      ]);
      for (const [field, value] of Object.entries(name)) text(value, `name.${field}`);
    }
    let addressChanged = false;
    const primaryEmail = emails
      ? (emails.find((value) => object(value).primary === true) ?? emails[0])
      : undefined;
    const email = primaryEmail
      ? text(object(primaryEmail).value, 'email')!.toLowerCase()
      : /^[^\s@]+@[^\s@]+$/.test(userName)
        ? normalized
        : undefined;
    if (email) {
      const collision = (
        await tx.find<Identity>('identities', { tenantId: connection.tenantId, email })
      ).find((row) => row.id !== record.id);
      if (collision)
        throw new IamError(
          'uniqueness',
          'Email belongs to an existing identity; automatic linking is disabled.',
          409,
        );
      // A new sign-in address ends what the old one opened, as an administrator's email change does.
      if (existing && record.email !== undefined && record.email !== email) addressChanged = true;
      if (record.email !== email) record.emailVerified = false;
      record.email = email;
      record.uniqueKey = `email:${email}`;
    }
    record.name = displayName;
    // SCIM owns `active` only when the IdP changes it: an update that leaves it alone never re-enables someone an
    // administrator disabled, and the IdP re-enables only an identity it disabled itself.
    if (!existing) record.status = active ? 'active' : 'disabled';
    else if (!active) record.status = 'disabled';
    else if (existing.active === false && record.status === 'disabled') record.status = 'active';
    if (config.mapAttributes) {
      const mapped = config.mapAttributes({
        userName,
        displayName,
        externalId,
        active,
        title,
        enterprise,
        emails,
        name,
      });
      if (mapped !== undefined)
        record.attributes = (
          config.validateIdentityAttributes ? config.validateIdentityAttributes(mapped) : mapped
        ) as Identity['attributes'];
    }
    const now = Date.now();
    const link: UserLink = {
      id: existing?.id ?? randomUUID(),
      tenantId: connection.tenantId,
      connectionId: connection.id,
      identityId: record.id,
      uniqueKey: hash(`${connection.id}:${normalized}`),
      userName,
      displayName,
      externalId,
      active,
      emails,
      name,
      version: (existing?.version ?? 0) + 1,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    if (title !== undefined) link.title = title;
    if (enterprise !== undefined) link.enterprise = enterprise;
    const value = managerValue(enterprise);
    const previous = managerValue(existing?.enterprise);
    if (config.mapManager !== false && (value !== undefined || previous !== undefined)) {
      // References resolve over all of the connection's users: the others plus this one as saved or as it was.
      const resolve = managerIndex(others);
      // SCIM owns the manager only while its previous reference still names it; admin-set managers stay.
      const owned =
        previous !== undefined &&
        record.managerId !== undefined &&
        resolve(previous, existing)?.identityId === record.managerId;
      const manager = value === undefined ? undefined : resolve(value, link);
      // A user naming themself resolves to themself, which `assignableManager` skips.
      const managerId = manager ? await assignableManager(tx, record, manager) : undefined;
      // A manager not provisioned yet is back-filled later; a SCIM-set one the IdP stopped naming is cleared.
      if (managerId) record.managerId = managerId;
      else if (owned && value !== previous) delete record.managerId;
    }
    if (existing) await tx.put('identities', record);
    else {
      await withinLimit(tx, connection.tenantId, 'identities');
      await tx.insert('identities', record);
    }
    if (record.status !== 'active' || addressChanged) await revokeSessions(tx, record.id);
    if (existing) await tx.put('scimUsers', link);
    else await tx.insert('scimUsers', link);
    await audit(
      tx,
      connection,
      existing ? 'iam:scim:UpdateUser' : 'iam:scim:CreateUser',
      record.id,
    );
    if (config.mapManager !== false) await adoptReports(tx, connection, [...others, link], link);
    return link;
  }
  async function saveGroup(
    tx: IamStore,
    connection: Connection,
    data: ObjectValue,
    existing?: GroupLink,
  ): Promise<GroupLink> {
    fields(data, ['schemas', 'displayName', 'externalId', 'members']);
    if (
      data.schemas !== undefined &&
      (!Array.isArray(data.schemas) || data.schemas.some((x) => x !== GROUP_SCHEMA))
    )
      throw new IamError('invalidValue', 'Unsupported Group schema.');
    const displayName = text(data.displayName, 'displayName')!;
    const externalId = text(data.externalId, 'externalId', true);
    const memberIds = await members(tx, connection, data.members ?? []);
    const now = Date.now();
    const link: GroupLink = {
      id: existing?.id ?? randomUUID(),
      tenantId: connection.tenantId,
      connectionId: connection.id,
      groupId: existing?.groupId ?? randomUUID(),
      displayName,
      externalId,
      members: memberIds,
      version: (existing?.version ?? 0) + 1,
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
    };
    if (existing)
      await tx.put('groups', {
        ...(await tx.get('groups', link.groupId)),
        id: link.groupId,
        tenantId: link.tenantId,
        name: displayName,
      });
    else {
      await withinLimit(tx, connection.tenantId, 'groups');
      await tx.insert('groups', {
        id: link.groupId,
        tenantId: link.tenantId,
        name: displayName,
        createdAt: now,
      });
    }
    if (existing) await tx.put('scimGroups', link);
    else await tx.insert('scimGroups', link);
    await syncGroup(tx, connection, link);
    await audit(
      tx,
      connection,
      existing ? 'iam:scim:UpdateGroup' : 'iam:scim:CreateGroup',
      link.groupId,
    );
    return link;
  }
  /** Applies a PatchOp to a materialized resource and saves it through the same validation as PUT. */
  async function patch(
    tx: IamStore,
    connection: Connection,
    type: ResourceType,
    row: UserLink | GroupLink,
    input: ObjectValue,
  ): Promise<UserLink | GroupLink> {
    fields(input, ['schemas', 'Operations']);
    if (
      !Array.isArray(input.schemas) ||
      input.schemas.length !== 1 ||
      input.schemas[0] !== PATCH_SCHEMA ||
      !Array.isArray(input.Operations) ||
      !input.Operations.length ||
      input.Operations.length > 100
    )
      throw new IamError(
        'invalidSyntax',
        'PATCH requires the PatchOp schema and 1–100 operations.',
      );
    const user = row as UserLink;
    // Cloned so a failed operation never mutates the stored row; every writable attribute round-trips.
    const data: ObjectValue = structuredClone(
      type === 'Users'
        ? {
            userName: user.userName,
            displayName: user.displayName,
            externalId: user.externalId,
            active: user.active,
            emails: user.emails,
            name: user.name,
            title: user.title,
            ...(user.enterprise ? { [ENTERPRISE_SCHEMA]: user.enterprise } : {}),
          }
        : {
            displayName: row.displayName,
            externalId: row.externalId,
            members: (row as GroupLink).members.map((value) => ({ value })),
          },
    );
    for (const item of input.Operations) {
      const op = object(item);
      fields(op, ['op', 'path', 'value']);
      const operation = typeof op.op === 'string' ? op.op.toLowerCase() : '';
      if (!['add', 'replace', 'remove'].includes(operation))
        throw new IamError('invalidSyntax', 'Unsupported PATCH operation.');
      const path = op.path === undefined ? undefined : text(op.path, 'path')!;
      applyPatchOperation(data, type, operation, path, op.value);
    }
    for (const key of Object.keys(data)) if (data[key] === undefined) delete data[key];
    if (type === 'Users' && data[ENTERPRISE_SCHEMA] !== undefined) {
      const extension = object(data[ENTERPRISE_SCHEMA]);
      if (!Object.keys(extension).length) delete data[ENTERPRISE_SCHEMA];
    }
    return type === 'Users'
      ? saveUser(tx, connection, data, row as UserLink)
      : saveGroup(tx, connection, data, row as GroupLink);
  }
  /**
   * Deactivates the local identity and removes the user from every SCIM group of the connection. Reports whose
   * manager SCIM set from this user lose it (it is back-filled if the user is provisioned again). An identity an
   * administrator deleted stays a tombstone; deletion already revoked its sessions and released its reports.
   */
  async function deleteUser(tx: IamStore, connection: Connection, row: UserLink): Promise<void> {
    const local = await identity(tx, row);
    if (local.status !== 'deleted') {
      await tx.put('identities', { ...local, status: 'disabled' });
      await revokeSessions(tx, local.id);
    }
    if (config.mapManager !== false && local.status !== 'deleted')
      for (const report of await reportsOf(
        tx,
        await tx.find<UserLink>('scimUsers', {
          tenantId: connection.tenantId,
          connectionId: connection.id,
        }),
        row,
      )) {
        if (report.managerId !== local.id) continue;
        const { managerId: _released, ...rest } = report;
        await tx.put<Identity>('identities', rest);
        await audit(tx, connection, 'iam:scim:UpdateUser', report.id);
      }
    for (const group of await tx.find<GroupLink>('scimGroups', {
      tenantId: connection.tenantId,
      connectionId: connection.id,
    })) {
      if (!group.members.includes(row.id)) continue;
      group.members = group.members.filter((id) => id !== row.id);
      group.version++;
      group.updatedAt = Date.now();
      await tx.put('scimGroups', group);
      await syncGroup(tx, connection, group);
    }
  }
  async function deleteGroup(tx: IamStore, connection: Connection, row: GroupLink): Promise<void> {
    row.members = [];
    await syncGroup(tx, connection, row);
    for (const binding of await tx.find('bindings', {
      tenantId: connection.tenantId,
      subjectType: 'group',
      subjectId: row.groupId,
      scimConnectionId: connection.id,
    }))
      await tx.delete('bindings', binding.id);
    await tx.delete('groups', row.groupId);
  }
  return { audit, authenticate, syncGroup, saveUser, saveGroup, patch, deleteUser, deleteGroup };
}
export type Provisioning = ReturnType<typeof createProvisioning>;
