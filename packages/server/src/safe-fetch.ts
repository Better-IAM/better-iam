/**
 * The SSRF guard for URLs that tenants control lives in `@better-iam/auth` (shared with the SCIM and OAuth packages);
 * this module keeps the server's import path.
 */
export {
  checkFetchUrl,
  createGuardedFetch,
  fetchJsonSafely,
  isPublicAddress,
  SafeFetchError,
} from '@better-iam/auth';
export type {
  GuardedFetchOptions,
  SafeFetchAddressOptions,
  SafeFetchFailureReason,
  SafeFetchOptions,
} from '@better-iam/auth';
