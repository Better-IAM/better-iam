# Better IAM documentation site

Next.js 16 + [Fumadocs](https://fumadocs.dev) 16. Content lives in `content/docs`, reference pages are generated
from the repository, and the site adds Twoslash type hovers, Mermaid diagrams, a policy playground that runs the
real `@better-iam/core` evaluator in the browser, section-filtered search, and LLM-friendly Markdown endpoints.

```sh
pnpm --filter @better-iam/docs generate   # after `pnpm build`: API/CLI/error/package data + generated pages
pnpm --filter @better-iam/docs dev        # http://localhost:4000
node apps/docs/scripts/check-content.mjs  # MDX syntax, components, frontmatter, links and #anchors
pnpm --filter @better-iam/docs build
```

| Path                                                                                            | What it is                                                                                             |
| ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| `content/docs/{guides,frameworks,federation,operations,reference}`                              | The five sidebar sections (folders with `"root": true`)                                                |
| `content/docs/reference/api/*`, `reference/{cli,errors,glossary}.mdx`, `reference/changelog.md` | Generated; do not edit                                                                                 |
| `descriptions/api/{group}.md`, `api/_instance.md`, `cli.md`, `errors.md`                        | Hand-written explanations merged into the generated reference (see `descriptions/README.md`)           |
| `descriptions/glossary.json`                                                                    | Glossary terms: the glossary page and every `<Term>` hover card                                        |
| `descriptions/fields.json`                                                                      | Plain-language descriptions of common field names for the API Input/Returns tables                     |
| `generated/*.json`                                                                              | Data extracted by `scripts/generate.mjs` (API catalog with JSON Schemas, errors, CLI, packages, stats) |
| `public/openapi.json`                                                                           | OpenAPI 3.1 description of the HTTP API, generated from the same types                                 |
| `source.config.ts`                                                                              | MDX pipeline: Twoslash, Mermaid, auto type tables, admonitions, npm tabs, last-modified dates          |
| `lib/source.ts`                                                                                 | Fumadocs loader, icons, status badges, `llms.txt` rendering                                            |
| `components/`                                                                                   | Site and MDX components (`playground/` is the policy playground, `home/` the landing page)             |
| `proxy.ts`                                                                                      | `/docs/x.md` and `Accept: text/markdown` serve a page's Markdown                                       |

## How the reference is generated

`scripts/generate.mjs` reads the repository, never a hand-maintained list:

- **API catalog** (`api`): a live in-memory `betterIam()` instance supplies the groups, methods, and route tables;
  the TypeScript checker reads `packages/server/dist/index.d.ts` for each method's signature, JSDoc, and input/result
  types, and converts those types to JSON Schema (named interfaces become shared components).
- **API pages** (`api-pages`, optionally `api-pages=groups,roles`): one page per group. Each method shows the
  curated summary and details from `descriptions/api/{group}.md`, its route and access badge, `<ApiShape>` field
  tables for its input and return value, and the TypeScript signature.
- **OpenAPI** (`openapi`): `public/openapi.json`, with curated summaries as operation descriptions.
- **Errors** (`errors`, `errors-page`): every `IamError` code thrown in `packages/*/src` (including subclasses),
  grouped by HTTP status, with the meaning and fix from `descriptions/errors.md`.
- **CLI** (`cli`, `cli-page`): usage lines from the CLI's help text (plus any command the dispatcher accepts but the
  help omits), with explanations from `descriptions/cli.md`.
- **Packages, changelog, glossary** (`packages`, `changelog`, `glossary`).

Set `DOCS_COVERAGE=1` to list functions, codes, and commands that still lack a curated description.

## Authoring conventions

**Files.** One `.mdx` file per page. A folder's `meta.json` sets its sidebar `title`, `icon`, and page order
(`"pages": ["index", "first", "second", "..."]`, where `"..."` is "everything else, alphabetically" and
`"---Label---"` is a separator). `index.mdx` is the folder's landing page.

**Frontmatter.**

```yaml
---
title: Just-in-time elevation # short, sentence case
description: Eligible bindings that people activate for a bounded time, with justification, MFA, and approval.
icon: KeyRound # optional, a canonical lucide icon name (see below)
status: new # optional: new | beta | experimental | deprecated (sidebar + header badge)
packages: ['@better-iam/server'] # optional: packages the page documents
sources: ['packages/server/src/api/bindings.ts'] # optional: repository files the page was written from
---
```

The description is one sentence, at most about 160 characters: it is the search snippet, the social card, and
the `llms.txt` summary.

**Voice.** Second person, present tense, short sentences. Explain what a feature is for before how to call it.
Sentence-case headings. `##` headings are the page's table of contents; use `###` below them. No marketing
language, no emoji.

**Accuracy.** The guides in the repository's `docs/*.md` and the package sources are the source of truth. Keep
every fact, option name, error code, action name (`iam:identities:create`), and limit; never invent an API. When
a guide is ambiguous, read the implementation in `packages/*/src` before writing.

**MDX safety.** Outside code, `{`, `}`, `<`, and `>` start JSX or expressions. Put identifiers and anything with
braces or angle brackets in backticks, write "less than" in words, or escape as `\{`. Comments are
`{/* like this */}`, never `<!-- -->`. Tags must be closed or self-closing.

**Components** available on every page without importing:

| Component                                                                            | Use                                                                                                                                                                       |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `<Callout type="info\|warn\|error\|success\|idea" title="...">`                      | Asides. Keep them rare and short.                                                                                                                                         |
| `<Cards>` / `<Card title href icon?>`                                                | Link grids ("Next steps").                                                                                                                                                |
| `<Tabs items={['A', 'B']} groupId? persist?>` / `<Tab value="A">`                    | Alternatives (frameworks, databases, server vs client).                                                                                                                   |
| `<Steps>` / `<Step>`                                                                 | Ordered procedures (or `### Title` headings inside `<Steps>`).                                                                                                            |
| `<Accordions type="single">` / `<Accordion title>`                                   | FAQs and optional detail.                                                                                                                                                 |
| `<Files>` / `<Folder name defaultOpen>` / `<File name>`                              | Project layouts.                                                                                                                                                          |
| `<TypeTable type={{ name: { type, description, default?, required? } }} />`          | Option and field tables.                                                                                                                                                  |
| `<FeatureGrid>` / `<Feature icon title href?>`                                       | Overview tiles.                                                                                                                                                           |
| `<PackageTable filter={['@better-iam/next']} />`                                     | Package cards generated from the workspace.                                                                                                                               |
| `<Term id="binding">bindings</Term>`                                                 | A glossary term with its definition in a hover card (ids in `descriptions/glossary.json`; unknown ids fail the checker). Use it on the first mention of jargon in a page. |
| `<TryInPlayground grants={[doc]} action="x:y" resource="type/id" context={{...}} />` | A button that opens `/playground` preloaded with the example, so readers can change it and watch the decision. Place it right under a policy example.                     |
| ` ```mermaid ` fences                                                                | Diagrams (flowcharts, sequence diagrams, state diagrams).                                                                                                                 |
| ` ```npm ` fences                                                                    | `npm i x` rendered as npm / pnpm / yarn / bun tabs.                                                                                                                       |

Icons for `Feature`/`Card` props come from `lucide-react` and must be imported at the top of the page:
`import { KeyRound } from 'lucide-react';`. For frontmatter and `meta.json` `icon` fields use names that exist in
lucide's canonical `icons` map (aliases such as `Building2` are not found; check with
`node -e "import('lucide-react').then(m => console.log(!!m.icons['KeyRound']))"` from `apps/docs`).

**Code blocks** always carry a language and, when it helps, a title: ` ```ts title="lib/iam.ts" `.
Shiki notation works in comments: `// [!code highlight]`, `// [!code ++]`, `// [!code --]`, `// [!code focus]`.
Add `twoslash` only to snippets that type-check against the real packages (the build fails otherwise); use
`// @noErrors` for fragments.

**Links** between pages are absolute: `/docs/guides/authorization/policies#conditions`. API methods link to the
generated reference: `/docs/reference/api/{group-in-kebab-case}#{method-in-lowercase}`, for example
`/docs/reference/api/service-accounts#create`.
