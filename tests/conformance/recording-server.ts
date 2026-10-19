/**
 * `@better-iam/server` while traces are recorded (BETTER_IAM_RECORD set; see vitest.config.ts): the real package
 * source, with `betterIam()` returning recorded instances. Never used by a normal test run.
 */
import {
  betterIam as realBetterIam,
  type BetterIamOptions,
} from '../../packages/server/src/index.ts';
import { recordInstance } from './recorder.ts';

export * from '../../packages/server/src/index.ts';

export function betterIam(options: BetterIamOptions): ReturnType<typeof realBetterIam> {
  return recordInstance(realBetterIam, options);
}
