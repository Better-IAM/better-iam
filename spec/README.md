# spec/: the language-neutral contract

Everything in this directory except `BUILDOUT.md`, this README and `conformance/` is **generated from the
TypeScript implementation** by `scripts/spec/generate.mjs`. The TypeScript packages under `packages/` stay the
single source of truth; the Rust (`crates/`) and Go (`go/`) ports test themselves against these files. Never edit a
generated file by hand: change the TypeScript (or the generator) and regenerate.

## Regenerating

```bash
node node_modules/pnpm/bin/pnpm.cjs build        # the generators import packages/*/dist
node node_modules/pnpm/bin/pnpm.cjs spec         # rewrite spec/ (removes files no generator produces any more)
node node_modules/pnpm/bin/pnpm.cjs spec:check   # regenerate into a temporary directory, fail on any difference
```

`node scripts/spec/generate.mjs --only routes,vectors --out /tmp/spec` runs some steps into another directory. Run it
with the Node version the workspace's native modules were built for (better-sqlite3); CI uses Node 22 and 24.

Output is deterministic: metadata files have recursively sorted keys, nothing carries a timestamp, every file ends
with LF. Randomness inside the TypeScript code (IVs, salts, tokens, ids) is drawn from a seeded stream while vectors
are generated (`scripts/spec/lib/determinism.mjs`, reseeded per case), so random-looking values are stable. The one
exception is ECDSA (ES256) signatures, whose nonces come from OpenSSL: those cases are marked
`"nondeterministic"`, and regeneration keeps the checked-in token as long as the TypeScript verifier still accepts it.

## Artifacts

### `api/openapi.json`

The OpenAPI 3.1 document of the HTTP API, built by the docs site's generator (`apps/docs/scripts/generate.mjs`, steps
`api` and `openapi`, redirected into a temporary directory with `DOCS_GENERATED_DIR` / `DOCS_PUBLIC_DIR`) from the
TypeScript declarations: every `POST /{group}/{method}` operation with JSON Schemas for request and result
(`components.schemas`). Identical to the site's `/openapi.json` except that documentation links point at
`https://better-iam.com` and indentation is 2 spaces. Member order follows the TypeScript declarations (not sorted),
which is also the field order of records and results.

### `api/routes.json`

The route table of `packages/server/src/http.ts`:

- `sets`: the route sets exactly as declared (`publicAuthMethods`, `authenticatedAuthMethods`, `routeGroups`,
  `publicApiMethods`, `tenantBoundPublicMethods`, `sessionCookieRoutes`, `deviceTokenRoutes`), parsed from the source
  and checked against the module's runtime exports.
- `rpc`: every `POST {basePath}/{group}/{method}` route of a `betterIam()` instance with every optional module enabled
  (the surface is checked to be the same as a minimal instance's), with `credential` (`none` for public routes),
  `call` (how the handler invokes the method), `tenantBound`, `setsSessionCookie`, `readsDeviceCookie`. The list is
  cross-checked against `openapi.json` (same paths, same public/authenticated split).
- `special`: `authorize`, `authorizeMany`, `listAccessible`, `plugins/{pluginId}/{path}` and their body fields.
- `request` / `response` / `dispatch`: CSRF rules, CORS headers, body limits (64 KiB API bodies; 2 MiB for other
  paths on the Node transport), cookie names and attributes, the JSON envelopes, error mapping, and dispatch rules.
- `operational`: `GET {basePath}/health`, `GET {basePath}/.well-known/jwks.json`, `GET {basePath}/metrics`.
- `protocols`: the protocol mounts and their routes: OpenID4VCI issuer and Shared Signals push receiver (built into
  the server), the OAuth/OIDC provider (oidc-provider routes as configured), OAuth federated sign-in, SAML, SCIM
  (resources, `/.search`, `/Bulk`, the admin API), SSF transmitter and protected-resource metadata, and the LDAP
  gateway's operations. The curated parts are guarded: generation fails when the source fragments they describe
  change.

### `api/errors.json`

Every error code the code base raises, found with the TypeScript AST across `packages/*/src`: `new IamError(code,
message, status)`, subclasses with fixed codes (`OperationDenied`, `WrongRegionError`, ...), error classes with
their own `code`/`status` (`SessionTokenError`), and conditional codes. Each code lists its HTTP statuses, packages,
and every raise site (`file:line`, status, and the message as literal text, a template with `${...}` placeholders, or
the expression passed). `defaults` holds the constructor default status (400), the unknown-error answer
(`INTERNAL_ERROR` 500) and the storage driver error mapping (`CONFLICT` 409, `STORAGE_BUSY` 503, `STORAGE_ERROR` 500).
`dynamicSites` lists raise sites whose code is computed.

### `catalog/actions.json`

The permission catalog as `actions.list` and `resourceTypes.list` report its platform entries, in catalog order:
the built-in `iam:*` actions; what each optional module adds (`inference`, `ssh`, `verifiableCredentials`
actions and resource types; `clearances` reserved attribute names); the internal and reserved resource types;
reserved principal keys; and the name patterns and limits.

### `storage/collections.json`

The storage model: the `iam_records` table, `INDEXED_FIELDS`, `ORDERED_FIELDS`, `EXPIRY_FIELDS`,
`LOOKUP_INDEX_STEPS`, `QUERYABLE_FIELD`, `MAX_QUERY_CONDITIONS`, the jsonb escape key and identifier limits, and every
collection the packages use (found at `get`/`find`/`findOrdered`/`insert`/`put`/`delete` call sites, with collection
name constants resolved): its operations, packages, record types (the TypeScript type arguments), filter keys,
`findOrdered` fields, the expressions that build `uniqueKey`, and every call site. `unresolvedSites` are generic helpers
that receive the collection as a parameter (cascades, retention sweeps). The adapter conformance suite's fixture
collections are excluded.

### `storage/migrations/`

The exact SQL of each reference adapter, captured by running the real adapters' `migrate()` against recording
drivers (pg.Pool, better-sqlite3, the libSQL client):

- `{postgres,sqlite,libsql}/NNNN_<name>.sql`: one migration's statements, one per line, `;`-terminated. Execute them
  in order, each as one statement, inside the migration transaction.
- `{dialect}/bookkeeping.sql`: the `iam_schema_version` / `iam_migrations` statements of the runner.
- `{dialect}/runner.json`: everything the adapter sent, in order, with bound parameters, for a fresh database and for
  an up-to-date one (`kind`: `adapter`, `bookkeeping` or `migration`; `applied_at` is the migration clock, fixed to
  `1767225600000` here).
- `index.json`: migration names, statements per dialect, and the runner rules.

### `vectors/*.json`

Test vectors produced by calling the TypeScript implementation. Each file is
`{ "description", "source": "<package/file#function>", "notes"?, "cases": [{ "name", "input", "output" }] }`.
Ports must reproduce every `output` from its `input` byte for byte (or, where a case says so, verify it). Key order
inside vector files is preserved, not sorted: it is the order the TypeScript code saw (filters plan conditions in key
order, JSON bodies are signed as serialized).

| File                     | Covers                                                                                                 |
| ------------------------ | ------------------------------------------------------------------------------------------------------ |
| `jcs.json`               | RFC 8785 canonicalization (`canonicalizeJson`)                                                         |
| `canonical-json.json`    | `canonicalJson` (audit hashes, receipts): sorted keys with JavaScript integer-key order                |
| `audit-chain.json`       | audit event hashes, chaining with heads, chain verification and pruning checkpoints                    |
| `policy-evaluation.json` | `evaluatePolicy`: grants, denies, boundaries, globs, variables, matched lists, limits                  |
| `policy-conditions.json` | every condition operator against matching, mismatching, missing and wrongly typed values               |
| `policy-validation.json` | `validatePolicy` acceptance and every refusal message                                                  |
| `policy-patterns.json`   | `matchPattern`, policy variables, IP ranges, IPv4-mapped IPv6, counter keys                            |
| `plan.json`              | `planResources` filters, filter simplification, filter globs                                           |
| `filter-compilers.json`  | plan filters as SQLite / PostgreSQL SQL, Prisma, MongoDB, descriptions, in-memory matches              |
| `storage.json`           | `planQuery`, `matchesFilter`, `compareIds`, `storableString`, PostgreSQL value encoding                |
| `sql.json`               | record SELECT statements (text and values) for SQLite/libSQL and PostgreSQL                            |
| `snapshot.json`          | store snapshot export lines and import results and refusals                                            |
| `shared-signals.json`    | Security Event Token claims, subject identifiers, event types                                          |
| `classification.json`    | classification schemes, labels, joins, dominance, coverage                                             |
| `secrets.json`           | deployment-secret sealing (AES-256-GCM, key = SHA-256(secret)), opening with keyrings, contexts in use |
| `derivations.json`       | assertion keys, challenge digests, privacy subjects and receipts, fingerprints, VC nonces              |
| `tokens.json`            | credential token format and CRC-32 check, parsing, token hashes, other token formats                   |
| `oauth-artifacts.json`   | OAuth provider artifact sealing                                                                        |
| `assertions.json`        | HS256 assertion issuance (real `issue` with a stubbed envelope) and verification                       |
| `session-jwt.json`       | session JWT signing (EdDSA; ES256 verify-only), verification reasons, signer config errors             |
| `delegation-tokens.json` | delegation token claims checks, act chains, signing and verification                                   |
| `passwords.json`         | argon2id PHC hashes and verification, other parameters                                                 |
| `totp.json`              | TOTP codes at fixed times, windows, key URIs, the once-per-step acceptance rule                        |
| `webhooks.json`          | webhook bodies, delivery headers and signatures, signature verification                                |
| `scim-filter.json`       | SCIM filter parsing and evaluation, sorting, projection, attribute lists                               |

#### Values JSON cannot hold

Inputs and outputs that are not JSON values are written as one-key objects:

| Form                                                             | Meaning                                                                  |
| ---------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `{"$undefined": true}`                                           | JavaScript `undefined` (an absent argument or a member set to undefined) |
| `{"$number": "NaN" \| "Infinity" \| "-Infinity" \| "-0"}`        | a non-finite number or negative zero                                     |
| `{"$utf16": [55296, ...]}`                                       | a string with an unpaired surrogate, as UTF-16 code units                |
| `{"$bigint": "10"}`                                              | a bigint                                                                 |
| `{"$bytes": "<base64url>"}`                                      | a byte array                                                             |
| `{"$set": [...]}`                                                | a Set, members in insertion order                                        |
| `{"$error": {"name", "code"?, "status"?, "reason"?, "message"}}` | (outputs) the call threw                                                 |

Strings that are valid UTF-16 are plain JSON strings (with `\u` escapes where JSON needs them).

## What is not here yet

- `conformance/`: recorded API traces and the replay format (owned by the conformance work, see `BUILDOUT.md`).
- Vectors for the KMS envelope format, the private CA and SSH certificate formats, SD-JWT VC issuance, SAML and OIDC
  protocol messages: these are covered by the trace replay suite until dedicated vectors exist.
