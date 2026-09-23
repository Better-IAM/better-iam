import { IamError } from '@better-iam/core';

/**
 * A command-line failure: an `IamError` (same `code` contract) that may carry a hint, printed on its own line by
 * the `better-iam` binary, telling the person what to run or set next.
 */
export class CliError extends IamError {
  constructor(
    code: string,
    message: string,
    /** One sentence saying what to do next, such as the command or flag that fixes the problem. */
    readonly hint?: string,
  ) {
    super(code, message);
    this.name = 'CliError';
  }
}

/** A usage mistake (unknown flag, missing value, bad number): the binary exits with status 2 for these. */
export function usageError(message: string, hint?: string): CliError {
  return new CliError('INVALID_ARGUMENT', message, hint);
}

/** Codes that mean the command line itself was wrong, so the binary exits 2 (like most Unix tools). */
export const usageCodes = new Set(['INVALID_ARGUMENT', 'INVALID_COMMAND']);

/** The `code` of an `IamError`, an `IamClientError` from a remote call, or a Node system error. */
export function errorCode(error: unknown): string | undefined {
  if (!error || typeof error !== 'object' || !('code' in error)) return undefined;
  return typeof error.code === 'string' ? error.code : undefined;
}

/** Levenshtein distance, for "did you mean" suggestions on commands and flags. */
function distance(a: string, b: string): number {
  const row = Array.from({ length: b.length + 1 }, (_, index) => index);
  for (let i = 1; i <= a.length; i++) {
    let previous = row[0]!;
    row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const current = row[j]!;
      row[j] = Math.min(row[j]! + 1, row[j - 1]! + 1, previous + (a[i - 1] === b[j - 1] ? 0 : 1));
      previous = current;
    }
  }
  return row[b.length]!;
}

/** The closest candidates to a mistyped name: prefix matches first, then anything within two edits. */
export function suggest(input: string, candidates: Iterable<string>, limit = 3): string[] {
  const needle = input.toLowerCase();
  const scored: { name: string; score: number }[] = [];
  for (const name of new Set(candidates)) {
    const lower = name.toLowerCase();
    if (lower === needle) continue;
    const score =
      lower.startsWith(needle) || needle.startsWith(lower) ? 0 : distance(needle, lower);
    if (score <= Math.max(2, Math.floor(needle.length / 4))) scored.push({ name, score });
  }
  return scored
    .sort((a, b) => a.score - b.score || a.name.localeCompare(b.name))
    .slice(0, limit)
    .map((entry) => entry.name);
}

/** " Did you mean X or Y?" or an empty string. */
export function didYouMean(input: string, candidates: Iterable<string>, prefix = ''): string {
  const matches = suggest(input, candidates).map((name) => `${prefix}${name}`);
  if (!matches.length) return '';
  return ` Did you mean ${matches.length === 1 ? matches[0] : `${matches.slice(0, -1).join(', ')} or ${matches.at(-1)}`}?`;
}
