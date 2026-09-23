import { IamError } from '@better-iam/core';
export function text(value: unknown, name: string, max = 256): string {
  if (
    typeof value !== 'string' ||
    !value.trim() ||
    value.length > max ||
    /[\u0000-\u001f]/.test(value)
  )
    throw new IamError('INVALID_INPUT', `Invalid ${name}`);
  return value;
}
export function email(value: unknown): string {
  const result = text(value, 'email', 254).trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(result))
    throw new IamError('INVALID_INPUT', 'Invalid email');
  return result;
}
export function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new IamError('INVALID_INPUT', 'Expected an object');
  return value as Record<string, unknown>;
}
export function integer(value: unknown, name: string, min: number, max: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max)
    throw new IamError('INVALID_INPUT', `Invalid ${name}`);
  return value;
}
export function strings(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || value.length > 100)
    throw new IamError('INVALID_INPUT', `Invalid ${name}`);
  return value.map((v) => text(v, name));
}
