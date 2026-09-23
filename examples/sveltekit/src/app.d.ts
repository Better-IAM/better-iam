import type { IamLocals } from '@better-iam/svelte/kit';
import type { iam } from '$lib/server/iam';

declare global {
  namespace App {
    interface Locals {
      iam: IamLocals<typeof iam>;
    }
    interface Error {
      message: string;
      code?: string;
    }
  }
}

export {};
