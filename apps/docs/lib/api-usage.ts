import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { source } from '@/lib/source';

export interface PageLink {
  title: string;
  url: string;
}

const kebabToCamel = (value: string) =>
  value.replace(/-([a-z])/g, (_, char: string) => char.toUpperCase());
const camelToKebab = (value: string) => value.replace(/[A-Z]/g, (char) => `-${char.toLowerCase()}`);

/** The API reference anchor of a `group.method` key. */
export function referenceUrl(key: string): string {
  const [group, method] = key.split('.') as [string, string];
  return `/docs/reference/api/${camelToKebab(group)}#${method.toLowerCase()}`;
}

/**
 * API methods a page mentions, as `group.method` keys: calls such as `iam.api.groups.addMember(` or
 * `client.groups.addMember(`, and links into the API reference such as `/docs/reference/api/groups#addmember`
 * (anchors are lowercase, so keys are compared case-insensitively against the known methods).
 */
export function methodsIn(text: string, known: Map<string, string>): Set<string> {
  const found = new Set<string>();
  for (const match of text.matchAll(/\b(?:iam\.api|client)\.([a-zA-Z]+)\.([a-zA-Z]+)\b/g)) {
    const key = known.get(`${match[1]}.${match[2]}`.toLowerCase());
    if (key) found.add(key);
  }
  for (const match of text.matchAll(/\/docs\/reference\/api\/([a-z-]+)#([a-z0-9]+)/g)) {
    const key = known.get(`${kebabToCamel(match[1]!)}.${match[2]}`.toLowerCase());
    if (key) found.add(key);
  }
  return found;
}

interface UsageIndex {
  /** Lowercased `group.method` to its canonical spelling, from the generated API catalog. */
  known: Map<string, string>;
  /** `group.method` to the guide pages that use it. */
  usedIn: Map<string, PageLink[]>;
}

let index: Promise<UsageIndex> | undefined;

/** Built once per server process from every non-reference page's processed Markdown. */
export function apiUsage(): Promise<UsageIndex> {
  index ??= (async () => {
    const shapes = JSON.parse(
      readFileSync(join(process.cwd(), 'generated', 'api-shapes.json'), 'utf8'),
    ) as { methods: Record<string, unknown> };
    const known = new Map(Object.keys(shapes.methods).map((key) => [key.toLowerCase(), key]));
    const usedIn = new Map<string, PageLink[]>();
    for (const page of source.getPages()) {
      if (page.slugs[0] === 'reference') continue;
      const text = await page.data.getText('processed');
      for (const key of methodsIn(text, known)) {
        const list = usedIn.get(key) ?? [];
        if (!list.some((entry) => entry.url === page.url))
          list.push({ title: page.data.title, url: page.url });
        usedIn.set(key, list);
      }
    }
    return { known, usedIn };
  })();
  return index;
}
