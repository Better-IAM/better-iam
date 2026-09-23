/** A package as `packages.list` returns it, reduced to what birthright lookups need. */
interface RulePackage {
  id: string;
  name: string;
  autoAssign?: { include: unknown[]; status: string };
}

/** The values a rule's include clauses test an array key for (`identity.teams`, `identity.departments`). */
export function ruleValues(rule: { include: unknown[] } | undefined, key: string): string[] {
  const found = new Set<string>();
  for (const clause of rule?.include ?? []) {
    if (!clause || typeof clause !== 'object') continue;
    for (const [operator, keys] of Object.entries(clause as Record<string, unknown>)) {
      if (operator !== 'ArrayContains' && operator !== 'ArrayContainsAll') continue;
      const expected = (keys as Record<string, unknown>)[key];
      for (const value of Array.isArray(expected) ? expected : [expected])
        if (typeof value === 'string') found.add(value);
    }
  }
  return [...found];
}

/**
 * The packages whose rule includes people of one of `ids` (a team or department and those above it, nearest first),
 * each with the ID its rule names. Other conditions of the rule may still leave some of them out.
 */
export function birthrightPackages<P extends RulePackage>(
  packages: P[] | undefined,
  key: 'identity.teams' | 'identity.departments',
  ids: string[],
): Array<{ pkg: P; via: string }> {
  const result: Array<{ pkg: P; via: string }> = [];
  for (const pkg of packages ?? []) {
    const named = ruleValues(pkg.autoAssign, key);
    const via = ids.find((id) => named.includes(id));
    if (via) result.push({ pkg, via });
  }
  return result.sort((a, b) => a.pkg.name.localeCompare(b.pkg.name));
}
