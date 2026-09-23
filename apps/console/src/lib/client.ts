'use client';
import { createIamClient, IamClientError, type IamClient } from 'better-iam/client';
import type { Iam } from './iam';

let instance: IamClient<Iam> | undefined;

/** Typed browser client, inferred from the server instance. Created lazily so server-side rendering never touches window. */
export function iamClient(): IamClient<Iam> {
  // Request IDs make console errors traceable in the server's spans; short rate-limit waits retry by themselves.
  instance ??= createIamClient<Iam>({
    baseURL: window.location.origin,
    requestId: true,
    retryRateLimited: true,
  });
  return instance;
}

export function describeError(error: unknown): { code: string; message: string } {
  if (error instanceof IamClientError) return { code: error.code, message: error.message };
  if (error instanceof Error) return { code: 'ERROR', message: error.message };
  return { code: 'ERROR', message: 'Something went wrong' };
}

export { IamClientError };
