// The session store is framework-agnostic and lives in the client package so every binding shares one implementation.
export { createSessionStore, isUnauthenticated } from '@better-iam/client/session';
export type {
  SessionClient,
  SessionOf,
  SessionSnapshot,
  SessionStatus,
  SessionStore,
} from '@better-iam/client/session';
