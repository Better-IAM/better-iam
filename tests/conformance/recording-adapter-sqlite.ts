/**
 * `@better-iam/adapter-sqlite` while traces are recorded (BETTER_IAM_RECORD set; see vitest.config.ts): the real
 * adapter, with every database it opens watched by the recorder, so what a test writes before it builds an instance
 * on the database is part of that instance's trace. Never used by a normal test run.
 */
import { sqliteAdapter as realSqliteAdapter } from '../../packages/adapter-sqlite/src/index.ts';
import { watchStore } from './recorder.ts';

export * from '../../packages/adapter-sqlite/src/index.ts';

export function sqliteAdapter(
  ...args: Parameters<typeof realSqliteAdapter>
): ReturnType<typeof realSqliteAdapter> {
  const database = realSqliteAdapter(...args);
  watchStore(database, args[0] as unknown as Record<string, unknown>);
  return database;
}
