import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Json,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import {
  departmentChain,
  departmentCode,
  departmentCollections,
  departmentDescendants,
  departmentMembership,
  loadDepartment,
  maxDepartmentDepth,
  maxDepartments,
  tenantDepartments,
  type Department,
  type DepartmentMember,
} from '../departments.js';
import {
  birthrightOptions,
  suggestBirthright,
  type BirthrightSuggestion,
} from '../org-insights.js';
import { packagesNaming } from '../org-rules.js';
import { actsInOwnRight } from '../session-kinds.js';
import { teamCollections, type Team } from '../teams.js';
import { id } from '../utils.js';
import { strings, text } from '../validation.js';
import { afterIdentityChange } from './package-automation.js';

export interface DepartmentInput {
  tenantId: string;
  name: string;
  code?: string;
  description?: string;
  parentId?: string;
  headId?: string;
  costCenter?: string;
}
export interface DepartmentUpdate {
  tenantId: string;
  departmentId: string;
  name?: string;
  /** null (or an empty string) clears the optional fields. */
  code?: string | null;
  description?: string | null;
  parentId?: string | null;
  headId?: string | null;
  costCenter?: string | null;
}
export interface DepartmentPerson {
  id: string;
  name: string;
  email?: string;
  status: Identity['status'];
}
export interface DepartmentRef {
  id: string;
  name: string;
  code?: string;
}
/** A department as lists return it. */
export interface DepartmentSummary {
  id: string;
  tenantId: string;
  name: string;
  code?: string;
  description?: string;
  parentId?: string;
  headId?: string;
  costCenter?: string;
  /** People in this department itself. */
  memberCount: number;
  /** People in it and in every department below it. */
  totalMemberCount: number;
  childCount: number;
  teamCount: number;
  createdAt: number;
  updatedAt: number;
}
export interface DepartmentDetail extends DepartmentSummary {
  /** Departments above it, top first. */
  path: DepartmentRef[];
  children: Array<DepartmentRef & { memberCount: number; totalMemberCount: number }>;
  head?: DepartmentPerson;
  teams: Array<{ id: string; name: string; slug: string }>;
}
/** A department with its sub-departments, as `tree` returns it. */
export interface DepartmentNode extends DepartmentSummary {
  head?: DepartmentPerson;
  children: DepartmentNode[];
}
export interface DepartmentMemberView extends DepartmentPerson {
  department: DepartmentRef;
  title?: string;
  since: number;
  /** Set when the person heads their department. */
  head?: true;
  managerId?: string;
}
/** A person's place in the org chart (`ofIdentity`, `mine`). */
export interface DepartmentPlacement {
  department: DepartmentRef;
  /** From the top department down to the person's own. */
  path: DepartmentRef[];
  title?: string;
  since: number;
  head?: DepartmentPerson;
  costCenter?: string;
}
/** The signed-in person's department and, for department heads, the people they lead (`departments.mine`). */
export interface MyDepartment {
  department: DepartmentPlacement | null;
  /** Departments the person heads, each with its people and those of every department below it. */
  leads: Array<{
    department: DepartmentRef;
    path: DepartmentRef[];
    people: DepartmentMemberView[];
  }>;
}
export interface DepartmentImportResult {
  dryRun: boolean;
  /** Departments created (or that would be) for attribute values no department matched. */
  created: string[];
  /** People placed in (or moved to) the department their attribute names. */
  assigned: number;
  /** People already in the matching department. */
  unchanged: number;
  /** Distinct attribute values that matched no department (only without `createMissing`). */
  unmatched: string[];
  /** Active people without the attribute. */
  missing: number;
}
export interface ManagerSyncResult {
  dryRun: boolean;
  /** People whose manager is (or would be) set to their department's head, with both names for display. */
  updated: Array<{ identityId: string; name: string; managerId: string; managerName: string }>;
  /** People left as they were because they already have another manager (without `overwrite`). */
  kept: number;
  /** People whose department (and the ones above it) has no head, or who head it with nobody above. */
  noHead: number;
}

const maxAssign = 100;

function optionalText(value: unknown, name: string, max: number): string | undefined {
  if (value === undefined || value === null || value === '') return undefined;
  return text(value, name, max).trim();
}
const person = (identity: Identity): DepartmentPerson => ({
  id: identity.id,
  name: identity.name,
  ...(identity.email ? { email: identity.email } : {}),
  status: identity.status,
});
const ref = (department: Department): DepartmentRef => ({
  id: department.id,
  name: department.name,
  ...(department.code ? { code: department.code } : {}),
});

/**
 * Departments: the organization's reporting structure (departments.ts). `iam:departments:read` lists and reads it,
 * `iam:departments:manage` changes it and places people. Policies see `principal.departmentId` and
 * `principal.departments`; `syncManagers` turns department heads into managers for approvals routed to managers.
 */
function departmentModule(ctx: ServerContext) {
  const { operation } = ctx.operations;

  /**
   * Runs a change, then (once it committed) re-evaluates the birthright access package rules of the people it touched:
   * rules may test identity.departments and identity.managerId. Never fails the change; the schedule catches up.
   */
  function reconciling<T>(
    tenantId: string,
    run: (touch: (identityIds: Iterable<string>) => void) => Promise<T>,
  ): Promise<T> {
    const touched = new Set<string>();
    return run((identityIds) => {
      for (const identityId of identityIds) touched.add(identityId);
    }).then((result) => afterIdentityChange(ctx, tenantId, [...touched], result));
  }

  /** The people placed in a department or any department below it. */
  async function peopleBelow(
    tx: IamStore,
    tenantId: string,
    departmentId: string,
  ): Promise<string[]> {
    const departments = await tenantDepartments(tx, tenantId);
    const scope = new Set([
      departmentId,
      ...departmentDescendants(departments.values(), departmentId).map((item) => item.id),
    ]);
    return (await tx.find<DepartmentMember>(departmentCollections.members, { tenantId }))
      .filter((placement) => scope.has(placement.departmentId))
      .map((placement) => placement.identityId);
  }

  async function audit(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    action: string,
    tenantId: string,
    resourceId: string,
    metadata: Record<string, Json>,
  ): Promise<void> {
    await ctx.events.audit(tx, principal, action, tenantId, resourceId, 'allow', false, metadata);
  }

  /** An active person of the tenant who can head a department or belong to one. */
  async function departmentPerson(
    tx: IamStore,
    tenantId: string,
    identityId: unknown,
  ): Promise<Identity> {
    const identity = await ctx.activeIdentity(tx, text(identityId, 'identityId', 128), tenantId);
    if (identity.kind !== 'user')
      throw new IamError(
        'INVALID_INPUT',
        'Departments hold people; service accounts and agents have none',
      );
    return identity;
  }

  async function assertUnique(
    tx: IamStore,
    tenantId: string,
    name: string,
    code: string | undefined,
    exceptId?: string,
  ): Promise<void> {
    for (const other of (await tenantDepartments(tx, tenantId)).values()) {
      if (other.id === exceptId) continue;
      if (other.name.toLowerCase() === name.toLowerCase())
        throw new IamError('CONFLICT', `A department named ${other.name} exists`, 409);
      if (code !== undefined && other.code?.toLowerCase() === code.toLowerCase())
        throw new IamError('CONFLICT', `The code ${code} is taken by ${other.name}`, 409);
    }
  }

  function depthCheck(
    departments: Map<string, Department>,
    parent: Department,
    subtreeHeight: number,
  ): void {
    if (departmentChain(departments, parent.id).length + subtreeHeight > maxDepartmentDepth)
      throw new IamError(
        'INVALID_INPUT',
        `Departments nest at most ${maxDepartmentDepth} levels deep`,
      );
  }

  async function summaries(
    tx: IamStore,
    tenantId: string,
  ): Promise<Map<string, DepartmentSummary>> {
    const departments = await tenantDepartments(tx, tenantId);
    const members = new Map<string, number>();
    for (const member of await tx.find<DepartmentMember>(departmentCollections.members, {
      tenantId,
    }))
      members.set(member.departmentId, (members.get(member.departmentId) ?? 0) + 1);
    const teams = new Map<string, number>();
    for (const team of await tx.find<Team>(teamCollections.teams, { tenantId }))
      if (team.departmentId) teams.set(team.departmentId, (teams.get(team.departmentId) ?? 0) + 1);
    const result = new Map<string, DepartmentSummary>();
    for (const department of departments.values()) {
      const { uniqueKey: _key, ...rest } = department;
      const below = departmentDescendants(departments.values(), department.id);
      result.set(department.id, {
        ...rest,
        memberCount: members.get(department.id) ?? 0,
        totalMemberCount: [department, ...below].reduce(
          (sum, item) => sum + (members.get(item.id) ?? 0),
          0,
        ),
        childCount: [...departments.values()].filter((other) => other.parentId === department.id)
          .length,
        teamCount: teams.get(department.id) ?? 0,
      });
    }
    return result;
  }

  async function headOf(
    tx: IamStore,
    department: Department,
  ): Promise<DepartmentPerson | undefined> {
    if (!department.headId) return undefined;
    const identity = await tx.get<Identity>('identities', department.headId);
    return identity && identity.tenantId === department.tenantId ? person(identity) : undefined;
  }

  async function detail(tx: IamStore, department: Department): Promise<DepartmentDetail> {
    const departments = await tenantDepartments(tx, department.tenantId);
    const all = await summaries(tx, department.tenantId);
    const children = [...departments.values()]
      .filter((other) => other.parentId === department.id)
      .sort((a, b) => a.name.localeCompare(b.name));
    const head = await headOf(tx, department);
    const teams = (await tx.find<Team>(teamCollections.teams, { tenantId: department.tenantId }))
      .filter((team) => team.departmentId === department.id)
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((team) => ({ id: team.id, name: team.name, slug: team.slug }));
    return {
      ...all.get(department.id)!,
      path: departmentChain(departments, department.id).slice(1).reverse().map(ref),
      children: children.map((child) => ({
        ...ref(child),
        memberCount: all.get(child.id)!.memberCount,
        totalMemberCount: all.get(child.id)!.totalMemberCount,
      })),
      ...(head ? { head } : {}),
      teams,
    };
  }

  /** Places a person in a department (moving them out of any other); returns false when they were already there. */
  async function place(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    department: Department,
    identity: Identity,
    title: string | undefined,
  ): Promise<boolean> {
    const existing = await departmentMembership(tx, department.tenantId, identity.id);
    if (existing?.departmentId === department.id && existing.title === title) return false;
    const record: DepartmentMember = {
      id: existing?.id ?? id(),
      tenantId: department.tenantId,
      uniqueKey: `identity:${identity.id}`,
      departmentId: department.id,
      identityId: identity.id,
      ...(title ? { title } : {}),
      since: existing?.departmentId === department.id ? existing.since : ctx.now(),
      assignedBy: principal.identity.id,
    };
    await (existing
      ? tx.put<DepartmentMember>(departmentCollections.members, record)
      : tx.insert<DepartmentMember>(departmentCollections.members, record));
    await audit(tx, principal, 'department:assign', department.tenantId, department.id, {
      identityId: identity.id,
      ...(existing && existing.departmentId !== department.id
        ? { previousDepartmentId: existing.departmentId }
        : {}),
      ...(title ? { title } : {}),
    });
    return true;
  }

  /** Creates a department; the caller has authorized `iam:departments:manage`. */
  async function createDepartment(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenant: Tenant,
    input: DepartmentInput,
  ): Promise<Department> {
    const departments = await tenantDepartments(tx, tenant.id);
    if (departments.size >= maxDepartments)
      throw new IamError('LIMIT_EXCEEDED', `At most ${maxDepartments} departments`, 409);
    const name = text(input.name, 'name', 100).trim();
    const code =
      input.code === undefined || input.code === '' ? undefined : departmentCode(input.code);
    await assertUnique(tx, tenant.id, name, code);
    let parentId: string | undefined;
    if (input.parentId !== undefined) {
      const parent = await loadDepartment(tx, tenant.id, input.parentId);
      depthCheck(departments, parent, 1);
      parentId = parent.id;
    }
    const headId =
      input.headId === undefined
        ? undefined
        : (await departmentPerson(tx, tenant.id, input.headId)).id;
    const description = optionalText(input.description, 'description', 512);
    const costCenter = optionalText(input.costCenter, 'costCenter', 64);
    const now = ctx.now();
    const department: Department = {
      id: id(),
      tenantId: tenant.id,
      uniqueKey: `name:${name.toLowerCase()}`,
      name,
      ...(code ? { code } : {}),
      ...(description ? { description } : {}),
      ...(parentId ? { parentId } : {}),
      ...(headId ? { headId } : {}),
      ...(costCenter ? { costCenter } : {}),
      createdAt: now,
      updatedAt: now,
    };
    await tx.insert<Department>(departmentCollections.departments, department);
    await audit(tx, principal, 'department:create', tenant.id, department.id, {
      name,
      ...(parentId ? { parentId } : {}),
    });
    return department;
  }

  /** Changes a department; the caller has authorized `iam:departments:manage` on it. */
  async function updateDepartment(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenant: Tenant,
    input: DepartmentUpdate,
  ): Promise<Department> {
    const department = await loadDepartment(tx, tenant.id, input.departmentId);
    const fields = (
      ['name', 'code', 'description', 'parentId', 'headId', 'costCenter'] as const
    ).filter((key) => input[key] !== undefined);
    if (!fields.length) throw new IamError('INVALID_INPUT', 'Nothing to update');
    const departments = await tenantDepartments(tx, tenant.id);
    const next: Department = { ...department, updatedAt: ctx.now() };
    if (input.name !== undefined) {
      next.name = text(input.name, 'name', 100).trim();
      next.uniqueKey = `name:${next.name.toLowerCase()}`;
    }
    if (input.code !== undefined) {
      delete next.code;
      if (input.code !== null && input.code !== '') next.code = departmentCode(input.code);
    }
    await assertUnique(tx, tenant.id, next.name, next.code, department.id);
    if (input.description !== undefined) {
      delete next.description;
      const description = optionalText(input.description, 'description', 512);
      if (description) next.description = description;
    }
    if (input.costCenter !== undefined) {
      delete next.costCenter;
      const costCenter = optionalText(input.costCenter, 'costCenter', 64);
      if (costCenter) next.costCenter = costCenter;
    }
    if (input.headId !== undefined) {
      delete next.headId;
      if (input.headId !== null && input.headId !== '')
        next.headId = (await departmentPerson(tx, tenant.id, input.headId)).id;
    }
    if (input.parentId !== undefined) {
      delete next.parentId;
      if (input.parentId !== null && input.parentId !== '') {
        const parent = await loadDepartment(tx, tenant.id, input.parentId);
        const below = departmentDescendants(departments.values(), department.id);
        if (parent.id === department.id || below.some((item) => item.id === parent.id))
          throw new IamError(
            'INVALID_INPUT',
            'A department cannot move under itself or a department below it',
          );
        const height = Math.max(
          1,
          ...below.map(
            (item) =>
              departmentChain(departments, item.id).findIndex((step) => step.id === department.id) +
              1,
          ),
        );
        depthCheck(departments, parent, height);
        next.parentId = parent.id;
      }
    }
    await tx.put<Department>(departmentCollections.departments, next);
    await audit(tx, principal, 'department:update', tenant.id, department.id, {
      fields: [...fields],
    });
    return next;
  }

  /** Deletes a department, unassigning its people and unfiling its teams. */
  async function deleteDepartment(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenant: Tenant,
    input: { tenantId: string; departmentId: string },
  ): Promise<{ unassigned: number; teams: number }> {
    const department = await loadDepartment(tx, tenant.id, input.departmentId);
    const departments = await tenantDepartments(tx, tenant.id);
    const children = [...departments.values()].filter((other) => other.parentId === department.id);
    if (children.length)
      throw new IamError(
        'RESOURCE_IN_USE',
        `Move or delete the departments below it first: ${children.map((child) => child.name).join(', ')}`,
        409,
      );
    // A department a birthright rule names stays until the package stops naming it (like groups).
    const naming = await packagesNaming(tx, tenant.id, 'identity.departments', [department.id]);
    if (naming.length)
      throw new IamError(
        'RESOURCE_IN_USE',
        `Access packages name it in a rule: ${naming.join(', ')}`,
        409,
      );
    let unassigned = 0;
    for (const member of await tx.find<DepartmentMember>(departmentCollections.members, {
      tenantId: tenant.id,
      departmentId: department.id,
    })) {
      await tx.delete(departmentCollections.members, member.id);
      unassigned++;
    }
    let teams = 0;
    for (const team of await tx.find<Team>(teamCollections.teams, { tenantId: tenant.id }))
      if (team.departmentId === department.id) {
        const { departmentId: _gone, ...rest } = team;
        await tx.put<Team>(teamCollections.teams, { ...rest, updatedAt: ctx.now() });
        teams++;
      }
    await tx.delete(departmentCollections.departments, department.id);
    await audit(tx, principal, 'department:delete', tenant.id, department.id, {
      name: department.name,
      unassigned,
      teams,
    });
    return { unassigned, teams };
  }

  const api = {
    /** Creates a department, optionally under a parent and with a head (an active person of the organization). */
    create: (credential: CredentialInput, input: DepartmentInput): Promise<DepartmentDetail> =>
      operation(
        credential,
        input.tenantId,
        'iam:departments:manage',
        input.tenantId,
        async ({ tx, principal, tenant }) => {
          return detail(tx, await createDepartment(tx, principal, tenant, input));
        },
      ),
    /** Renames, re-codes, moves (`parentId`, null for top level), or changes the head or cost center of a department. */
    update: (credential: CredentialInput, input: DepartmentUpdate): Promise<DepartmentDetail> =>
      reconciling(input.tenantId, (touch) =>
        operation(
          credential,
          input.tenantId,
          'iam:departments:manage',
          text(input.departmentId, 'departmentId', 128),
          async ({ tx, principal, tenant }) => {
            const updated = await updateDepartment(tx, principal, tenant, input);
            // A move changes identity.departments for everyone at or below it.
            if (input.parentId !== undefined) touch(await peopleBelow(tx, tenant.id, updated.id));
            return detail(tx, updated);
          },
        ),
      ),
    /**
     * Deletes a department. Its people become unassigned and teams filed under it lose the link; departments below it
     * must be moved or deleted first (RESOURCE_IN_USE).
     */
    delete: (credential: CredentialInput, input: { tenantId: string; departmentId: string }) =>
      reconciling(input.tenantId, (touch) =>
        operation(
          credential,
          input.tenantId,
          'iam:departments:manage',
          text(input.departmentId, 'departmentId', 128),
          async ({ tx, principal, tenant }) => {
            touch(await peopleBelow(tx, tenant.id, input.departmentId));
            return {
              deleted: true as const,
              ...(await deleteDepartment(tx, principal, tenant, input)),
            };
          },
        ),
      ),
    /** Every department with member counts, in name order. */
    list: (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<DepartmentSummary[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:departments:read',
        input.tenantId,
        async ({ tx }) =>
          [...(await summaries(tx, input.tenantId)).values()].sort(
            (a, b) => a.name.localeCompare(b.name) || (a.id < b.id ? -1 : 1),
          ),
      ),
    /** The department tree (org chart): top-level departments with their sub-departments and heads. */
    tree: (credential: CredentialInput, input: { tenantId: string }): Promise<DepartmentNode[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:departments:read',
        input.tenantId,
        async ({ tx }) => {
          const departments = await tenantDepartments(tx, input.tenantId);
          const all = await summaries(tx, input.tenantId);
          const heads = new Map<string, DepartmentPerson>();
          for (const department of departments.values()) {
            const head = await headOf(tx, department);
            if (head) heads.set(department.id, head);
          }
          const build = (parentId: string | undefined, depth: number): DepartmentNode[] =>
            depth > maxDepartmentDepth
              ? []
              : [...departments.values()]
                  .filter(
                    (department) =>
                      (department.parentId ?? undefined) === parentId ||
                      // A department whose parent is gone is shown at the top.
                      (parentId === undefined &&
                        department.parentId !== undefined &&
                        !departments.has(department.parentId)),
                  )
                  .sort((a, b) => a.name.localeCompare(b.name))
                  .map((department) => ({
                    ...all.get(department.id)!,
                    ...(heads.has(department.id) ? { head: heads.get(department.id)! } : {}),
                    children: build(department.id, depth + 1),
                  }));
          return build(undefined, 0);
        },
      ),
    /** One department with its path, sub-departments, head, and teams. */
    get: (credential: CredentialInput, input: { tenantId: string; departmentId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:departments:read',
        text(input.departmentId, 'departmentId', 128),
        async ({ tx }) => detail(tx, await loadDepartment(tx, input.tenantId, input.departmentId)),
      ),
    /** The people of a department (with `includeSubdepartments`, of every department below it too), by name. */
    listMembers: (
      credential: CredentialInput,
      input: { tenantId: string; departmentId: string; includeSubdepartments?: boolean },
    ): Promise<DepartmentMemberView[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:departments:read',
        text(input.departmentId, 'departmentId', 128),
        async ({ tx }) => {
          const department = await loadDepartment(tx, input.tenantId, input.departmentId);
          const departments = await tenantDepartments(tx, input.tenantId);
          const scope = [
            department,
            ...(input.includeSubdepartments
              ? departmentDescendants(departments.values(), department.id)
              : []),
          ];
          const views: DepartmentMemberView[] = [];
          for (const item of scope)
            for (const member of await tx.find<DepartmentMember>(departmentCollections.members, {
              tenantId: input.tenantId,
              departmentId: item.id,
            })) {
              const identity = await tx.get<Identity>('identities', member.identityId);
              if (!identity || identity.status === 'deleted') continue;
              views.push({
                ...person(identity),
                department: ref(item),
                ...(member.title ? { title: member.title } : {}),
                since: member.since,
                ...(item.headId === identity.id ? { head: true as const } : {}),
                ...(identity.managerId ? { managerId: identity.managerId } : {}),
              });
            }
          return views.sort(
            (a, b) =>
              Number(Boolean(b.head)) - Number(Boolean(a.head)) ||
              (a.email ?? a.name).localeCompare(b.email ?? b.name),
          );
        },
      ),
    /**
     * Places up to 100 people (`identityIds`, or one `identityId`) in a department, moving them out of their previous
     * one, with an optional `title`. Returns how many changed.
     */
    assign: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        departmentId: string;
        identityIds?: string[];
        identityId?: string;
        title?: string;
      },
    ) =>
      reconciling(input.tenantId, (touch) =>
        operation(
          credential,
          input.tenantId,
          'iam:departments:manage',
          text(input.departmentId, 'departmentId', 128),
          async ({ tx, principal }) => {
            const department = await loadDepartment(tx, input.tenantId, input.departmentId);
            if ((input.identityIds === undefined) === (input.identityId === undefined))
              throw new IamError('INVALID_INPUT', 'Provide identityIds or identityId');
            const identityIds = [
              ...new Set(
                input.identityIds !== undefined
                  ? strings(input.identityIds, 'identityIds')
                  : [text(input.identityId, 'identityId', 128)],
              ),
            ];
            if (!identityIds.length || identityIds.length > maxAssign)
              throw new IamError('INVALID_INPUT', `Provide 1-${maxAssign} identityIds`);
            const title = optionalText(input.title, 'title', 100);
            let assigned = 0;
            for (const identityId of identityIds)
              if (
                await place(
                  tx,
                  principal,
                  department,
                  await departmentPerson(tx, input.tenantId, identityId),
                  title,
                )
              ) {
                assigned++;
                touch([identityId]);
              }
            return { assigned, unchanged: identityIds.length - assigned };
          },
        ),
      ),
    /** Takes a person out of their department. */
    unassign: (credential: CredentialInput, input: { tenantId: string; identityId: string }) =>
      reconciling(input.tenantId, (touch) =>
        operation(
          credential,
          input.tenantId,
          'iam:departments:manage',
          text(input.identityId, 'identityId', 128),
          async ({ tx, principal }) => {
            const membership = await departmentMembership(tx, input.tenantId, input.identityId);
            if (!membership) throw new IamError('NOT_FOUND', 'Not in a department', 404);
            await tx.delete(departmentCollections.members, membership.id);
            await audit(
              tx,
              principal,
              'department:unassign',
              input.tenantId,
              membership.departmentId,
              { identityId: input.identityId },
            );
            touch([input.identityId]);
            return { deleted: true as const };
          },
        ),
      ),
    /** A person's department with the departments above it (top first), or null without one. */
    ofIdentity: (credential: CredentialInput, input: { tenantId: string; identityId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:departments:read',
        text(input.identityId, 'identityId', 128),
        async ({ tx }) => {
          await ctx.scoped<Identity>(tx, 'identities', input.identityId, input.tenantId);
          const membership = await departmentMembership(tx, input.tenantId, input.identityId);
          const departments = await tenantDepartments(tx, input.tenantId);
          const department = membership ? departments.get(membership.departmentId) : undefined;
          if (!membership || !department) return null;
          const head = await headOf(tx, department);
          return {
            department: ref(department),
            path: departmentChain(departments, department.id).reverse().map(ref),
            ...(membership.title ? { title: membership.title } : {}),
            since: membership.since,
            ...(head ? { head } : {}),
            ...(department.costCenter ? { costCenter: department.costCenter } : {}),
          };
        },
      ),
    /**
     * The caller's own department (with the departments above it, their title, and their head) and, for department
     * heads, the people of each department they head and of every department below it. Needs only an ordinary session
     * of a person in the organization.
     */
    mine: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<MyDepartment> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        if (
          !actsInOwnRight(principal.session) ||
          principal.session.tenantId !== tenantId ||
          principal.identity.tenantId !== tenantId ||
          principal.identity.kind !== 'user'
        )
          throw new IamError(
            'ACCESS_DENIED',
            'Departments are read from a person’s own session in their organization',
            403,
          );
        const me = principal.identity.id;
        const departments = await tenantDepartments(tx, tenantId);
        const membership = await departmentMembership(tx, tenantId, me);
        const own = membership ? departments.get(membership.departmentId) : undefined;
        let placement: DepartmentPlacement | null = null;
        if (membership && own) {
          const head = await headOf(tx, own);
          placement = {
            department: ref(own),
            path: departmentChain(departments, own.id).reverse().map(ref),
            ...(membership.title ? { title: membership.title } : {}),
            since: membership.since,
            ...(head ? { head } : {}),
            ...(own.costCenter ? { costCenter: own.costCenter } : {}),
          };
        }
        const leads: MyDepartment['leads'] = [];
        for (const department of [...departments.values()]
          .filter((item) => item.headId === me)
          .sort((a, b) => a.name.localeCompare(b.name))) {
          const people: DepartmentMemberView[] = [];
          for (const item of [
            department,
            ...departmentDescendants(departments.values(), department.id),
          ])
            for (const member of await tx.find<DepartmentMember>(departmentCollections.members, {
              tenantId,
              departmentId: item.id,
            })) {
              const identity = await tx.get<Identity>('identities', member.identityId);
              if (!identity || identity.status === 'deleted') continue;
              people.push({
                ...person(identity),
                department: ref(item),
                ...(member.title ? { title: member.title } : {}),
                since: member.since,
                ...(item.headId === identity.id ? { head: true as const } : {}),
                ...(identity.managerId ? { managerId: identity.managerId } : {}),
              });
            }
          leads.push({
            department: ref(department),
            path: departmentChain(departments, department.id).reverse().map(ref),
            people: people.sort(
              (a, b) =>
                Number(Boolean(b.head)) - Number(Boolean(a.head)) ||
                (a.email ?? a.name).localeCompare(b.email ?? b.name),
            ),
          });
        }
        return { department: placement, leads };
      });
    },
    /**
     * Builds department membership from a string identity attribute (such as `department`, which SCIM provisioning
     * fills): each active person moves to the department whose name or code equals the value (case-insensitive).
     * `createMissing` creates top-level departments for unmatched values; `dryRun` reports without changing anything.
     */
    importFromAttribute: (
      credential: CredentialInput,
      input: { tenantId: string; attribute: string; createMissing?: boolean; dryRun?: boolean },
    ): Promise<DepartmentImportResult> =>
      reconciling(input.tenantId, (touch) =>
        operation(
          credential,
          input.tenantId,
          'iam:departments:manage',
          input.tenantId,
          async ({ tx, principal, tenant }) => {
            const attribute = text(input.attribute, 'attribute', 64);
            if (ctx.catalog.identityAttributes[attribute] !== 'string')
              throw new IamError(
                'INVALID_INPUT',
                `${attribute} is not a declared string identity attribute (permissions.identityAttributes)`,
              );
            const dryRun = input.dryRun === true;
            const departments = await tenantDepartments(tx, tenant.id);
            const byKey = new Map<string, Department>();
            for (const department of departments.values()) {
              byKey.set(department.name.toLowerCase(), department);
              if (department.code) byKey.set(department.code.toLowerCase(), department);
            }
            const result: DepartmentImportResult = {
              dryRun,
              created: [],
              assigned: 0,
              unchanged: 0,
              unmatched: [],
              missing: 0,
            };
            const people = (await tx.find<Identity>('identities', { tenantId: tenant.id })).filter(
              (identity) => identity.kind === 'user' && identity.status === 'active',
            );
            const unmatched = new Set<string>();
            for (const identity of people) {
              const raw = identity.attributes?.[attribute];
              const value = typeof raw === 'string' ? raw.trim() : '';
              if (!value) {
                result.missing++;
                continue;
              }
              let department = byKey.get(value.toLowerCase());
              if (!department && input.createMissing) {
                if (departments.size + result.created.length >= maxDepartments)
                  throw new IamError(
                    'LIMIT_EXCEEDED',
                    `At most ${maxDepartments} departments`,
                    409,
                  );
                const name = value.slice(0, 100);
                const now = ctx.now();
                department = {
                  id: id(),
                  tenantId: tenant.id,
                  uniqueKey: `name:${name.toLowerCase()}`,
                  name,
                  createdAt: now,
                  updatedAt: now,
                };
                if (!dryRun) {
                  await tx.insert<Department>(departmentCollections.departments, department);
                  await audit(tx, principal, 'department:create', tenant.id, department.id, {
                    name,
                    source: `attribute:${attribute}`,
                  });
                }
                byKey.set(name.toLowerCase(), department);
                result.created.push(name);
              }
              if (!department) {
                unmatched.add(value);
                continue;
              }
              const current = await departmentMembership(tx, tenant.id, identity.id);
              if (current?.departmentId === department.id) {
                result.unchanged++;
                continue;
              }
              if (!dryRun) {
                await place(tx, principal, department, identity, current?.title);
                touch([identity.id]);
              }
              result.assigned++;
            }
            result.unmatched = [...unmatched].sort();
            return result;
          },
        ),
      ),
    /**
     * Makes department heads the managers (`Identity.managerId`) of their departments' people, so approvals routed to
     * managers follow the org chart: each person reports to their department's head, and a head to the nearest head
     * above. Without `overwrite` only people without a manager change; `departmentId` limits it to one department
     * (and the ones below it); `dryRun` reports only. Cycles are never created.
     */
    syncManagers: (
      credential: CredentialInput,
      input: { tenantId: string; departmentId?: string; overwrite?: boolean; dryRun?: boolean },
    ): Promise<ManagerSyncResult> =>
      reconciling(input.tenantId, (touch) =>
        operation(
          credential,
          input.tenantId,
          'iam:identities:update',
          input.departmentId === undefined
            ? input.tenantId
            : text(input.departmentId, 'departmentId', 128),
          async ({ tx, principal, tenant }) => {
            const denied = await ctx.decisions.decide(
              tx,
              principal,
              {
                tenantId: tenant.id,
                action: 'iam:departments:read',
                resource: { type: 'iam', id: tenant.id },
              },
              true,
            );
            if (!denied.allowed)
              throw new IamError(
                'ACCESS_DENIED',
                'Reading departments needs iam:departments:read',
                403,
              );
            const departments = await tenantDepartments(tx, tenant.id);
            const scope =
              input.departmentId === undefined
                ? [...departments.values()]
                : (() => {
                    const root = departments.get(input.departmentId);
                    if (!root) throw new IamError('NOT_FOUND', 'Department not found', 404);
                    return [root, ...departmentDescendants(departments.values(), root.id)];
                  })();
            const dryRun = input.dryRun === true;
            const result: ManagerSyncResult = { dryRun, updated: [], kept: 0, noHead: 0 };
            const identities = new Map(
              (await tx.find<Identity>('identities', { tenantId: tenant.id })).map((identity) => [
                identity.id,
                identity,
              ]),
            );
            const liveHead = (department: Department) => {
              const head = department.headId ? identities.get(department.headId) : undefined;
              return head?.status === 'active' ? head : undefined;
            };
            /** Whether `managerId`'s own chain of managers reaches `identityId` (which would close a cycle). */
            const reaches = (managerId: string, identityId: string) => {
              let cursor = identities.get(managerId);
              for (let depth = 0; cursor && depth < 100; depth++) {
                if (cursor.id === identityId) return true;
                cursor = cursor.managerId ? identities.get(cursor.managerId) : undefined;
              }
              return false;
            };
            for (const department of scope)
              for (const member of await tx.find<DepartmentMember>(departmentCollections.members, {
                tenantId: tenant.id,
                departmentId: department.id,
              })) {
                const identity = identities.get(member.identityId);
                if (!identity || identity.status !== 'active') continue;
                const manager = departmentChain(departments, department.id)
                  .map(liveHead)
                  .find((head) => head !== undefined && head.id !== identity.id);
                if (!manager) {
                  result.noHead++;
                  continue;
                }
                if (identity.managerId === manager.id) continue;
                if (identity.managerId && !input.overwrite) {
                  result.kept++;
                  continue;
                }
                if (reaches(manager.id, identity.id)) {
                  result.kept++;
                  continue;
                }
                result.updated.push({
                  identityId: identity.id,
                  name: identity.name,
                  managerId: manager.id,
                  managerName: manager.name,
                });
                const next: Identity = { ...identity, managerId: manager.id };
                identities.set(identity.id, next);
                if (!dryRun) await tx.put<Identity>('identities', next);
              }
            if (!dryRun && result.updated.length)
              await audit(tx, principal, 'department:sync-managers', tenant.id, tenant.id, {
                updated: result.updated.length,
                ...(input.departmentId ? { departmentId: input.departmentId } : {}),
              });
            // Rules may test identity.managerId.
            if (!dryRun) touch(result.updated.map((entry) => entry.identityId));
            return result;
          },
        ),
      ),
    /**
     * Birthright suggestions: roles and groups that at least `minShare` (default 0.8) of a department's people hold by
     * hand, for departments of at least `minPeople` (default 3) people, as a ready-made automatic access package whose
     * rule names the department. A department counts the people below it, and never repeats what is suggested for a
     * department above it or already granted by an automatic package naming it. `departmentId` limits the answer to one
     * department. Read-only; requires iam:analysis:read.
     */
    suggestBirthright: (
      credential: CredentialInput,
      input: { tenantId: string; departmentId?: string; minShare?: number; minPeople?: number },
    ): Promise<BirthrightSuggestion[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:analysis:read',
        input.tenantId,
        async ({ tx, tenant }) => {
          const options = birthrightOptions(input);
          if (input.departmentId !== undefined)
            await loadDepartment(tx, tenant.id, input.departmentId);
          return suggestBirthright(ctx, tx, tenant.id, 'department', {
            ...options,
            ...(input.departmentId !== undefined ? { unitId: input.departmentId } : {}),
          });
        },
      ),
  };
  return {
    api,
    helpers: { createDepartment, updateDepartment, deleteDepartment, place, departmentPerson },
  };
}

/** The `departments` API group. */
export function createDepartmentsApi(ctx: ServerContext) {
  return departmentModule(ctx).api;
}

/**
 * Transaction-level department changes for configuration sync (org-sync.ts): the same validation and audit events as
 * the API. Callers authorize each change first.
 */
export function departmentMutations(ctx: ServerContext) {
  return departmentModule(ctx).helpers;
}
