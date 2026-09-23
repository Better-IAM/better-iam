import { IamError, type IamStore, type StoredRecord } from '@better-iam/core';

/**
 * Departments: the organization's reporting structure. Departments nest (`parentId`), may name a head, and hold people;
 * each person belongs to at most one department (`departmentMembers`, uniqueKey `identity:{identityId}`). Policies see
 * `principal.departmentId` and `principal.departments` (the department and every department above it), teams may name
 * the department they belong to, and roll-ups (spend, reports) walk `departmentPath`.
 */

/** Collections owned by the departments module. */
export const departmentCollections = {
  departments: 'departments',
  members: 'departmentMembers',
} as const;

/** A department; names are unique per tenant (uniqueKey `name:{lowercase}`), codes too when set. */
export interface Department extends StoredRecord {
  name: string;
  /** A short reference such as `ENG` or `FIN-AP` (1-32 letters, digits, `-`, `_` or `.`), unique per tenant. */
  code?: string;
  description?: string;
  parentId?: string;
  /** The person who leads the department (an active person of the tenant). */
  headId?: string;
  /** Free-form cost-center reference printed on reports and statements. */
  costCenter?: string;
  createdAt: number;
  updatedAt: number;
}

/** A person's department (uniqueKey `identity:{identityId}`: one department per person). */
export interface DepartmentMember extends StoredRecord {
  departmentId: string;
  identityId: string;
  /** The person's title within the department (informational). */
  title?: string;
  since: number;
  assignedBy: string;
}

/** Deepest department nesting (a department and nineteen levels above it). */
export const maxDepartmentDepth = 20;
/** Departments per tenant. */
export const maxDepartments = 2000;
const codePattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/;

/** A department code: 1-32 letters, digits, `.`, `_` or `-`, starting with a letter or digit. */
export function departmentCode(value: unknown): string {
  if (typeof value !== 'string' || !codePattern.test(value))
    throw new IamError(
      'INVALID_INPUT',
      'code must use 1-32 letters, digits, dots, underscores, or hyphens',
    );
  return value;
}

/** Loads a department of the tenant or fails with NOT_FOUND. */
export async function loadDepartment(
  tx: IamStore,
  tenantId: string,
  departmentId: unknown,
): Promise<Department> {
  if (typeof departmentId !== 'string' || !departmentId)
    throw new IamError('INVALID_INPUT', 'Invalid departmentId');
  const department = await tx.get<Department>(departmentCollections.departments, departmentId);
  if (!department || department.tenantId !== tenantId)
    throw new IamError('NOT_FOUND', 'Department not found', 404);
  return department;
}

/** The department followed by the departments above it, nearest first; stops at a missing parent. */
export function departmentChain(
  departments: ReadonlyMap<string, Department>,
  departmentId: string,
): Department[] {
  const chain: Department[] = [];
  const seen = new Set<string>();
  let current = departments.get(departmentId);
  while (current && !seen.has(current.id) && chain.length <= maxDepartmentDepth) {
    chain.push(current);
    seen.add(current.id);
    current = current.parentId ? departments.get(current.parentId) : undefined;
  }
  return chain;
}

/** Every department below `departmentId`, not including the department itself. */
export function departmentDescendants(
  departments: Iterable<Department>,
  departmentId: string,
): Department[] {
  const children = new Map<string, Department[]>();
  for (const department of departments)
    if (department.parentId)
      children.set(department.parentId, [...(children.get(department.parentId) ?? []), department]);
  const result: Department[] = [];
  const seen = new Set([departmentId]);
  const queue = [...(children.get(departmentId) ?? [])];
  while (queue.length) {
    const next = queue.shift()!;
    if (seen.has(next.id)) continue;
    seen.add(next.id);
    result.push(next);
    queue.push(...(children.get(next.id) ?? []));
  }
  return result;
}

/** The tenant's departments by ID. */
export async function tenantDepartments(
  tx: IamStore,
  tenantId: string,
): Promise<Map<string, Department>> {
  return new Map(
    (await tx.find<Department>(departmentCollections.departments, { tenantId })).map(
      (department) => [department.id, department],
    ),
  );
}

/** The person's department membership record, if any. */
export async function departmentMembership(
  tx: IamStore,
  tenantId: string,
  identityId: string,
): Promise<DepartmentMember | undefined> {
  return (
    await tx.find<DepartmentMember>(departmentCollections.members, {
      tenantId,
      uniqueKey: `identity:${identityId}`,
    })
  )[0];
}

/** The ID of the department a person belongs to, if any. */
export async function departmentOf(
  tx: IamStore,
  tenantId: string,
  identityId: string,
): Promise<string | undefined> {
  const membership = await departmentMembership(tx, tenantId, identityId);
  if (!membership) return undefined;
  const department = await tx.get<Department>(
    departmentCollections.departments,
    membership.departmentId,
  );
  return department?.tenantId === tenantId ? department.id : undefined;
}

/** Department IDs from the top of the tree down to `departmentId` itself (for roll-ups); empty when unknown. */
export async function departmentPath(
  tx: IamStore,
  tenantId: string,
  departmentId: string,
): Promise<string[]> {
  return departmentChain(await tenantDepartments(tx, tenantId), departmentId)
    .map((department) => department.id)
    .reverse();
}

/**
 * The heads of a department (identity IDs): its own head and, with `includeAncestors`, the heads of the departments
 * above it, nearest first and without duplicates.
 */
export async function departmentHeads(
  tx: IamStore,
  tenantId: string,
  departmentId: string,
  options: { includeAncestors?: boolean } = {},
): Promise<string[]> {
  const chain = departmentChain(await tenantDepartments(tx, tenantId), departmentId);
  const heads: string[] = [];
  for (const department of options.includeAncestors ? chain : chain.slice(0, 1))
    if (department.headId && !heads.includes(department.headId)) heads.push(department.headId);
  return heads;
}

/** Removes a person from their department; true when they had one. */
export async function removeFromDepartment(
  tx: IamStore,
  tenantId: string,
  identityId: string,
): Promise<boolean> {
  const membership = await departmentMembership(tx, tenantId, identityId);
  if (membership) await tx.delete(departmentCollections.members, membership.id);
  return Boolean(membership);
}

/**
 * Offboarding and deletion: takes the person out of their department, and hands the departments they head to
 * `successorId` (or leaves them without a head). Returns what changed.
 */
export async function releaseDepartments(
  tx: IamStore,
  tenantId: string,
  identityId: string,
  now: number,
  successorId?: string,
): Promise<{ left: boolean; headsReassigned: number; headsCleared: number }> {
  const left = await removeFromDepartment(tx, tenantId, identityId);
  let headsReassigned = 0;
  let headsCleared = 0;
  for (const department of await tx.find<Department>(departmentCollections.departments, {
    tenantId,
    headId: identityId,
  })) {
    const { headId: _previous, ...rest } = department;
    await tx.put<Department>(departmentCollections.departments, {
      ...rest,
      ...(successorId ? { headId: successorId } : {}),
      updatedAt: now,
    });
    if (successorId) headsReassigned++;
    else headsCleared++;
  }
  return { left, headsReassigned, headsCleared };
}

/**
 * Policy context for a person in their own tenant: `principal.departmentId` (absent without a department) and
 * `principal.departments`, the department with every department above it.
 */
export async function departmentContext(
  tx: IamStore,
  tenantId: string,
  identityId: string,
): Promise<{ 'principal.departments': string[]; 'principal.departmentId'?: string }> {
  const departmentId = await departmentOf(tx, tenantId, identityId);
  if (!departmentId) return { 'principal.departments': [] };
  return {
    'principal.departmentId': departmentId,
    'principal.departments': (await departmentPath(tx, tenantId, departmentId)).sort(),
  };
}
