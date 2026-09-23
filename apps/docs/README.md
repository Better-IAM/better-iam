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

## Design system

The site is monochrome and built on [BoardUI](https://www.boardui.com): its components are source files in this
app (`npx boardui@latest add <name>` from `apps/docs` adds more), and every color is a BoardUI semantic token.

- `styles/theme.css`, `styles/typography.css`: BoardUI's tokens and type ramp, unmodified (`text-body-medium`,
  `bg-background-primary-default`, `border-border-button-default`, ...).
- `styles/monochrome.css`: the site's layer on top. It turns BoardUI's accent ramp neutral (black controls in light
  mode, white in dark), and maps Fumadocs' `--color-fd-*` palette onto the same tokens so the docs shell matches.
- `components/base/*`, `utils/cx.ts`: BoardUI components. Two local changes, marked in the source: the primary
  button label and the selected switch thumb read tokens, so they invert correctly in dark mode. Icons come from
  `react-icons/ri` (the same Remix Icon set BoardUI uses) instead of `@remixicon/react`.
- `components/application/theme/theme-toggle.tsx`: BoardUI's theme toggle, backed by next-themes.
- `components/site/*`: the marketing shell (header, footer, Lenis smooth scrolling, and the rail frame every
  landing band aligns to). `components/docs/*`: BoardUI versions of Fumadocs' `Callout` and `Card`.
- `lib/code-themes.ts`: grayscale Shiki themes for every code block.

No hues and no radial gradients: states are told apart by weight (solid ink, outline, dashed, hatched).

## Deploying

The package is private: `pnpm publish -r` skips it. [`Dockerfile`](Dockerfile) builds the site from the repository
root (install, `pnpm build` for the workspace packages, then `next build`) and runs `next start` on `$PORT`.

On Railway, create a service from this repository with no root directory: `/railway.json` selects that Dockerfile,
checks `/` as the health check, and redeploys only when the docs, the packages, or the workspace manifests change.
Generate a public domain; it becomes the site's canonical URL (sitemap, `llms.txt`, social cards) on the next
deploy. Optional service variables, read at build time:

| Variable                          | Default                                    | Purpose                                                                              |
| --------------------------------- | ------------------------------------------ | ------------------------------------------------------------------------------------ |
| `DOCS_SITE_URL`                   | `https://$RAILWAY_PUBLIC_DOMAIN`           | Canonical origin, for example a custom domain                                        |
| `NEXT_PUBLIC_DOCS_REPOSITORY_URL` | `https://github.com/Better-IAM/better-iam` | GitHub button, "Edit this page", source, and issue links                             |
| `DOCS_X_HANDLE`                   | unset                                      | The site's X account (`@name`) as `twitter:site` and `twitter:creator` on link cards |
| `DOCS_GOOGLE_SITE_VERIFICATION`   | unset                                      | Google Search Console ownership token                                                |
| `DOCS_BING_SITE_VERIFICATION`     | unset                                      | Bing Webmaster Tools ownership token (`msvalidate.01`)                               |
| `DOCS_YANDEX_VERIFICATION`        | unset                                      | Yandex Webmaster ownership token                                                     |

## Search and social metadata

Every page has a title, description, canonical URL, keywords, Open Graph and X card tags, and a 1200×630 social
card. Facebook, LinkedIn, X, Slack, Discord, iMessage, WhatsApp, Telegram, Bluesky, and Mastodon all read these
tags. Docs pages add `article:*` tags, Slack's "Section" and "Reading time" labels, and schema.org `TechArticle` and
`BreadcrumbList` data. The home page describes the site, the software, and its creator in JSON-LD.

| Path                                                                               | What it is                                                                                   |
| ---------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `lib/metadata.ts`                                                                  | Site title, description, and keywords; `pageMetadata()` for every page; JSON-LD builders     |
| `lib/docs-seo.ts`                                                                  | A docs page's document title, section trail, keywords, and breadcrumbs                       |
| `lib/og.tsx`, `lib/og-fonts.ts`                                                    | The social card renderer (Inter and JetBrains Mono, fetched from Google Fonts at build time) |
| `app/og/docs/[...slug]/route.tsx`, `app/og/[image]/route.tsx`                      | Cards for docs pages (`/og/docs/{slug}/image.png`), the home page, and the playground        |
| `app/manifest.ts`, `public/{favicon.ico,icon.svg,apple-touch-icon.png,icon-*.png}` | Web app manifest and icons                                                                   |

The icons are drawn from the logo mark in `components/logo.tsx`. After changing the mark, run
`node apps/docs/scripts/generate-icons.mjs` to redraw every icon for the docs site and the console.

### Search engine indexing

The site lives at `https://better-iam.com`, which Railway serves and `DOCS_SITE_URL` names as the canonical origin.

- `app/robots.ts` allows every crawler everywhere except `/api/` and points to `app/sitemap.ts`. The sitemap lists
  the home page, the playground, and every docs page.
- `next.config.mjs` sends `www.` and Railway's `*.up.railway.app` hosts to the canonical origin with a permanent
  redirect, so each page has one address. It also marks `llms.txt` and `llms-full.txt` `noindex`, and the Markdown
  copies (`/docs/x.md`) name their HTML page as canonical.
- Bing, Yandex, Seznam, and Naver learn about changed pages through [IndexNow](https://www.indexnow.org). The key
  is `public/<key>.txt`, and `.github/workflows/indexnow.yml` runs `scripts/indexnow.mjs --changed` after every
  successful Railway deploy. Run `node apps/docs/scripts/indexnow.mjs --all` to submit every URL in the sitemap.
- Google reads the sitemap from Search Console and `robots.txt`. It does not use IndexNow or sitemap pings.

Set up once, outside the repository:

1. DNS: add a `CNAME` record for `www` to the Railway target, and add `www.better-iam.com` as a custom domain on
   the Railway service. The app then redirects it to `https://better-iam.com`.
2. Google Search Console: add a Domain property for `better-iam.com` (verified with a DNS `TXT` record), or a
   URL-prefix property verified with `DOCS_GOOGLE_SITE_VERIFICATION`. Then submit `https://better-iam.com/sitemap.xml`.
3. Bing Webmaster Tools: import the site from Search Console, or add `https://better-iam.com` and verify it with
   `DOCS_BING_SITE_VERIFICATION`. Then submit the same sitemap.

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
metaTitle: Just-in-time privileged access # optional: tab, search result, and link-card title when `title` is too terse out of context
description: Eligible bindings that people activate for a bounded time, with justification, MFA, and approval.
icon: KeyRound # optional, a name exported from lib/icons.ts (see below)
status: new # optional: new | beta | experimental | deprecated (sidebar + header badge)
packages: ['@better-iam/server'] # optional: packages the page documents
sources: ['packages/server/src/api/bindings.ts'] # optional: repository files the page was written from
---
```

The description is one sentence, at most about 160 characters: it is the search snippet, the social card, and
the `llms.txt` summary. The document title is `metaTitle` (or `title`) plus " | Better IAM", so keep `metaTitle`
under about 47 characters. API reference groups are titled "{group} API" automatically.

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

Icons come from the site's registry, `lib/icons.ts`, which maps semantic names to react-icons (Remix Icon, the set
BoardUI is drawn with; Simple Icons for framework logos). Import them at the top of the page for `Feature`/`Card`
props: `import { KeyRound } from '@/lib/icons';`. Frontmatter and `meta.json` `icon` fields use the same names; an
unknown name logs `[icons] Unknown icon` during the build. To add one, export it from `lib/icons.ts`
(`RiXxxLine as Name` from `react-icons/ri`).

**Code blocks** always carry a language and, when it helps, a title: ` ```ts title="lib/iam.ts" `.
Shiki notation works in comments: `// [!code highlight]`, `// [!code ++]`, `// [!code --]`, `// [!code focus]`.
Add `twoslash` only to snippets that type-check against the real packages (the build fails otherwise); use
`// @noErrors` for fragments.

**Links** between pages are absolute: `/docs/guides/authorization/policies#conditions`. API methods link to the
generated reference: `/docs/reference/api/{group-in-kebab-case}#{method-in-lowercase}`, for example
`/docs/reference/api/service-accounts#create`.
