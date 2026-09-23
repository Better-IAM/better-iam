# Curated descriptions

Hand-written explanations that `scripts/generate.mjs` merges into the generated reference pages. The generator
supplies names, routes, and TypeScript signatures from the code; these files supply the human part: what each
function does, why it exists, when to use it, who may call it, and what can go wrong.

| File | Merged into | Sections |
| --- | --- | --- |
| `api/{group}.md` (group name exactly as in `iam.api`, e.g. `serviceAccounts.md`) | `content/docs/reference/api/{group-kebab}.mdx` | one `## method` per method |
| `api/_instance.md` | `content/docs/reference/api/index.mdx` | one `## function` per `betterIam()` instance function |
| `cli.md` | `content/docs/reference/cli.mdx` | one `## command` per CLI command |
| `errors.md` | `content/docs/reference/errors.mdx` | one `## CODE` per error code |
| `exports.md` | `content/docs/reference/exports.mdx` (and the MCP `lookup_export` tool) | `## {entry point} {name}`, e.g. `## @better-iam/react useSession`, for exports without a doc comment or whose doc comment explains how rather than what for; re-exports share the section of the entry point that declares them |
| `glossary.json` | `<Term>` hover cards and `content/docs/reference/glossary.mdx` | `{ id, term, definition, href }` entries |
| `fields.json` | Field tables (`<ApiShape>`, auto type tables) | field name to a one-line meaning, used when a field has no doc comment |

Regenerate and validate after editing (from `apps/docs`):

```sh
node scripts/generate.mjs api-pages=groups,roles   # or: api-pages, errors-page, cli-page, exports-page
node scripts/check-content.mjs reference
DOCS_COVERAGE=1 node scripts/generate.mjs api-pages errors-page cli-page exports-page   # lists what is still undocumented
```

Package exports come from the built declarations, so run `pnpm build` and `node scripts/generate.mjs exports` after
adding or renaming an export. A new package also needs `node scripts/generate.mjs packages` (the package table,
dependency graph, and the package descriptions on the exports page), and a new API group an entry in `groupInfo`
(icon and one-line summary) and a category in `scripts/generate.mjs`, or the API index lists it under "Other".

## File shape

```md
# groups

Overview: one or two short paragraphs. What this group manages, the problem it solves, and how it relates to the
rest of the model. The first sentence becomes the page description (keep it under 160 characters).

## How membership works

Any `##` section whose heading is not a method name is rendered as an overview section above the method table.
Use one or two for concepts the methods share (for example lifecycle, limits, or the permission model).

## addMember

Adds a person to a group so they receive every role bound to the group.        <- summary: ONE sentence

- **Permission:** `iam:groups:update` on the group, plus authority over each of the group's role bindings.
- **Audited as:** `iam:groups:update`.
- **Errors:** `CONFLICT` when the person is already a member; `NOT_FOUND` when the group or person is not in this tenant.

Why and when: a short paragraph in plain language. Mention behaviour a caller must know (limits, side effects,
what happens to related records, idempotency).

```ts
await iam.api.groups.addMember(credential, { tenantId, groupId, identityId, expiresAt: Date.now() + 30 * 86_400_000 });
```
```

Rules:

- The **first paragraph** of each section is the summary shown in the page's table. One sentence, present tense,
  starting with a verb ("Adds…", "Lists…", "Returns…"). Describe the effect, not the implementation.
- Then the facts list: **Permission** (the `iam:*` action and resource it is checked on, or "None: public" /
  "The caller's own session"), **Audited as**, and notable **Errors** (codes from `generated/errors.json`). Omit a
  line only when it does not apply.
- Then why/when prose, then an example when the call is not obvious. Examples use the real signature from
  `generated/api.json` and realistic values.
- Everything must be accurate: read the implementation in `packages/server/src/api/*.ts` (and `packages/auth/src`
  for `auth`) before writing. Never invent options, errors, or behaviour.
- The content is MDX: escape `{`, `}`, `<`, `>` outside code, and never use HTML comments.
- Define jargon on first use or link to the guide that does (`/docs/guides/...`).

## How operations are authorized and audited

Every group method (except public auth and discovery calls) runs through the same envelope: authenticate the
credential, re-validate the principal, authorize an `iam:{group}:{verb}` action on the internal resource
`iam/{id}` (the tenant id for tenant-wide actions such as create and list, or the record id for record actions),
run the change in one transaction, and append one audit event named after the action, with outcome `allow` or
`deny`. A denial commits only its audit record and throws `ACCESS_DENIED` (403).
