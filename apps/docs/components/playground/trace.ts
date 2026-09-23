import {
  evaluatePolicy,
  matchPattern,
  validatePolicy,
  type Decision,
  type PolicyDocument,
  type PolicyStatement,
} from '@better-iam/core';

export interface ConditionTrace {
  operator: string;
  key: string;
  expected: unknown;
  actual: unknown;
  present: boolean;
  passed: boolean;
}

export interface StatementTrace {
  id: string;
  kind: 'grant' | 'boundary';
  document: number;
  index: number;
  sid?: string;
  effect: 'allow' | 'deny';
  actionMatched: boolean;
  resourceMatched: boolean;
  conditions: ConditionTrace[];
  matched: boolean;
}

export interface PlaygroundResult {
  decision?: Decision;
  error?: string;
  statements: StatementTrace[];
}

export interface ParsedDocument {
  document?: PolicyDocument;
  error?: string;
}

/** Parses and validates one policy document with the real validator (`validatePolicy`). */
export function parseDocument(text: string): ParsedDocument {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (error) {
    return { error: `JSON: ${(error as Error).message}` };
  }
  try {
    validatePolicy(value);
    return { document: value };
  } catch (error) {
    return { error: (error as Error).message };
  }
}

/**
 * Evaluates the request with `evaluatePolicy` from `@better-iam/core`, then explains it statement by statement.
 * Each condition is checked on its own by evaluating a single-condition statement with the same engine, so the
 * trace follows the engine's exact semantics (negation, typing, variables) instead of re-implementing them.
 */
export function evaluate(
  grants: PolicyDocument[],
  boundaries: PolicyDocument[],
  action: string,
  resource: string,
  context: Record<string, unknown>,
): PlaygroundResult {
  let decision: Decision;
  try {
    decision = evaluatePolicy({ action, resource, context, grants, boundaries });
  } catch (error) {
    return { error: (error as Error).message, statements: [] };
  }

  const statements: StatementTrace[] = [];
  const trace = (kind: 'grant' | 'boundary', documents: PolicyDocument[]) =>
    documents.forEach((document, documentIndex) =>
      document.statements.forEach((statement: PolicyStatement, index) => {
        const conditions: ConditionTrace[] = [];
        for (const [operator, entries] of Object.entries(statement.conditions ?? {})) {
          for (const [key, expected] of Object.entries(entries ?? {})) {
            const single = evaluatePolicy({
              action,
              resource,
              context,
              grants: [
                {
                  version: 1,
                  statements: [
                    {
                      effect: 'allow',
                      actions: ['*'],
                      resources: ['*'],
                      conditions: {
                        [operator]: { [key]: expected },
                      } as PolicyStatement['conditions'],
                    },
                  ],
                },
              ],
            });
            conditions.push({
              operator,
              key,
              expected,
              actual: context[key],
              present: Object.hasOwn(context, key) && context[key] !== undefined,
              passed: single.allowed,
            });
          }
        }
        const id = `${kind}:${documentIndex}:${statement.sid ?? index}`;
        statements.push({
          id,
          kind,
          document: documentIndex,
          index,
          sid: statement.sid,
          effect: statement.effect,
          actionMatched: statement.actions.some((pattern) => matchPattern(pattern, action)),
          resourceMatched: statement.resources.some((pattern) =>
            matchPattern(pattern, resource, context),
          ),
          conditions,
          matched: decision.matched.includes(id),
        });
      }),
    );
  trace('grant', grants);
  trace('boundary', boundaries);
  return { decision, statements };
}

export const reasons: Record<string, { title: string; text: string }> = {
  allowed: {
    title: 'Allowed',
    text: 'At least one grant statement allows the request, no statement denies it, and every boundary allows it.',
  },
  'explicit-deny': {
    title: 'Explicit deny',
    text: 'A matching deny statement (in a grant or a boundary) overrides every allow.',
  },
  'no-grant': {
    title: 'No grant',
    text: 'No grant statement matched the action, resource, and conditions. Access is denied by default.',
  },
  'boundary-deny': {
    title: 'Outside a boundary',
    text: 'A grant allows the request, but at least one boundary has no allow statement that matches it. Boundaries never grant access; they only limit it.',
  },
};
