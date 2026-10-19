/**
 * Vitest setup file registered only while traces are recorded (BETTER_IAM_RECORD=<dir>; see vitest.config.ts): names
 * the running test for the recorder and writes each test file's traces when the file finishes.
 */
import { afterAll, afterEach, beforeAll, beforeEach, expect } from 'vitest';
import { resolve } from 'node:path';
import { flushTraces, setCurrentTest } from './recorder.ts';

const directory = resolve(process.env.BETTER_IAM_RECORD!);
const root = resolve(import.meta.dirname, '..', '..');

function fullName(task: { name: string; suite?: { name: string; suite?: unknown } }): string {
  const names = [task.name];
  let suite = task.suite as { name: string; suite?: unknown } | undefined;
  while (suite) {
    if (suite.name) names.unshift(suite.name);
    suite = suite.suite as typeof suite;
  }
  return names.join(' > ');
}

// Instances created while the test file loads or in beforeAll hooks belong to the file, not to one test.
setCurrentTest('(file setup)', expect.getState().testPath);
beforeAll((suite) => {
  setCurrentTest('(beforeAll)', (suite as { filepath?: string }).filepath);
});

beforeEach((context) => {
  setCurrentTest(fullName(context.task as never), context.task.file?.filepath);
});

afterEach((context) => {
  setCurrentTest(`${fullName(context.task as never)} (afterEach)`);
});

afterAll((suite) => {
  const file = (suite as { filepath?: string }).filepath;
  setCurrentTest('(afterAll)', file);
  flushTraces(directory, root, file);
});
