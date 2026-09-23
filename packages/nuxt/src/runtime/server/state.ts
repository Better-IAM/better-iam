import * as instance from '#better-iam/instance';
import { createError, toWebRequest, useRuntimeConfig } from '#imports';
import { createIamH3, type IamLike, type RegisteredIam } from '../../h3.js';

function pick(): RegisteredIam {
  // Looked up dynamically: the file may export only one of the two names, and static access makes bundlers warn.
  const exports: Record<string, unknown> = instance;
  const candidate = ['iam', 'default']
    .map((name) => exports[name])
    .find((value) => value !== undefined) as Partial<IamLike> | undefined;
  if (!candidate || typeof candidate.handler !== 'function')
    throw new Error(
      'Better IAM: the instance module must export the betterIam() result as `iam` or as its default export',
    );
  return candidate as RegisteredIam;
}

let ready: Promise<RegisteredIam> | undefined;
/** The app's IAM instance, initialized (migrated) once on first use unless `betterIam.initialize` is false. */
export function resolveIam(): Promise<RegisteredIam> {
  ready ??= (async () => {
    const iam = pick();
    const options = useRuntimeConfig().betterIam as { initialize?: boolean } | undefined;
    if (options?.initialize !== false) await iam.initialize?.();
    return iam;
  })().catch((error: unknown) => {
    ready = undefined;
    throw error;
  });
  return ready;
}

export const iamH3 = createIamH3(resolveIam, { toRequest: toWebRequest, createError });
