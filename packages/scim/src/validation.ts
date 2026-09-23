import { createHash } from 'node:crypto';
import { IamError, tenantTreeActive, type IamStore } from '@better-iam/core';
import type { ObjectValue } from './types.js';

export const hash = (value: string): string => createHash('sha256').update(value).digest('hex');

export function object(value: unknown): ObjectValue {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new IamError('invalidSyntax', 'Expected a JSON object.');
  return value as ObjectValue;
}
export function text(value: unknown, field: string, optional = false): string | undefined {
  if (optional && value === undefined) return undefined;
  if (typeof value !== 'string' || !value.trim() || value.length > 512)
    throw new IamError(
      'invalidValue',
      `${field} must be a nonempty string of at most 512 characters.`,
    );
  return value.trim();
}
/** SCIM rejects unknown or immutable attributes instead of ignoring them. */
export function fields(value: ObjectValue, allowed: string[]): void {
  if (Object.keys(value).some((key) => !allowed.includes(key)))
    throw new IamError('mutability', 'An unsupported or immutable attribute was supplied.');
}
export function bool(value: unknown, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== 'boolean') throw new IamError('invalidValue', 'active must be a boolean.');
  return value;
}
export async function activeTenant(store: Pick<IamStore, 'get'>, id: string): Promise<void> {
  if (!(await tenantTreeActive(store, id)))
    throw new IamError('unauthorized', 'Inactive tenant.', 401);
}
