# exports

Plain-language descriptions for the package exports reference (`/docs/reference/exports`). Each section is
`## {entry point} {export name}` and its first paragraph replaces the export's JSDoc summary. Add a section when an
export has no doc comment, or when its doc comment describes how it works rather than what it is for.

## @better-iam/adapter-libsql libsqlAdapter

Stores Better IAM's data in libSQL: a local file (optionally encrypted), an embedded replica that syncs with a remote
database, or a remote Turso or sqld database. Pass it as `database` to `betterIam()`.

## @better-iam/adapter-postgres postgresAdapter

Stores Better IAM's data in PostgreSQL, the usual choice for production. Pass it as `database` to `betterIam()`.
Transactions are serialized with a database advisory lock, so several application instances can share one database
safely.

## @better-iam/adapter-sqlite sqliteAdapter

Stores Better IAM's data in a SQLite file (through better-sqlite3): the simplest setup, for development, tests, and
single-server deployments. Pass it as `database` to `betterIam()`, and move to PostgreSQL when many processes write
at once.

## @better-iam/auth AuthService

The authentication service behind `iam.auth`: sign-in, sessions, account management, passwordless sign-in, MFA, and
passkeys. `betterIam()` creates it; `createAuth` creates one on its own.

## @better-iam/auth characterClasses

Counts how many kinds of character a password uses (lowercase, uppercase, digits, and everything else), from 0 to 4,
for password rules that require variety.

## @better-iam/auth encryptSecret

Encrypts a value with the deployment secret (authenticated encryption), so stored factors and queued messages can
be neither read nor altered without it. `decryptSecret` reverses it.

## @better-iam/auth newCredentialToken

Creates a new typed credential token (`biam_ses_…`, `biam_key_…`, `biam_rol_…`, `biam_sts_…`, or `biam_dlg_…`) with
a checksum at the end. Better IAM issues every session, API key, role session, session token, and delegated agent
session with it; custom credential issuers built on the auth package use it to produce tokens in the same format.

## @better-iam/auth parseCredentialToken

Recognizes a typed credential token and returns its type, or `undefined` when the shape or checksum is wrong, so a
mistyped or truncated token can be refused before any database lookup. The type is only a routing hint: the stored
session decides what a token is.

## @better-iam/auth credentialTokenKinds

Maps each credential token type to the session kind it must resolve to (`ses` to `user`, `key` to `api-key`, `rol` to
`role`, `sts` to `session-token`, `dlg` to `delegated`), so a token whose prefix disagrees with its stored session is
refused.

## @better-iam/auth credentialTokenScanPattern

A regular expression source that matches Better IAM credential tokens in text. Add it to your secret scanner, log
redaction, or pre-commit hook so leaked session tokens and API keys are caught before anyone uses them.

## @better-iam/cli runCli

Runs the `better-iam` command-line tool with the given arguments, exactly as the `better-iam` binary does, so scripts
and tests can call it in-process. It loads your configuration file as JavaScript, so point it only at trusted
configuration.

## @better-iam/client IamClientError

The error the typed client throws when the server refuses a call or the request fails. It carries the server's
`code` and `status`, the wait before a retry for `RATE_LIMITED`, and the request ID, but never the raw response body.

## @better-iam/client ClientError

Another name for `IamClientError`.

## @better-iam/client createIamClient

Creates the typed client for browsers and other services. Import your server instance as a type
(`createIamClient<typeof iam>()`) and every API group, method, input, and result is typed, without bundling any
server code.

## @better-iam/client/passkeys browserSupportsWebAuthn

True when the browser supports passkeys (WebAuthn), so you can decide whether to offer them.

## @better-iam/client/passkeys browserSupportsWebAuthnAutofill

True when the browser can suggest passkeys in the username field's autofill, for a sign-in form without a separate
passkey button.

## @better-iam/client/passkeys platformAuthenticatorIsAvailable

True when the device has a built-in authenticator (Touch ID, Windows Hello, an Android fingerprint sensor), a good
moment to suggest creating a passkey.

## @better-iam/client/passkeys startAuthentication

Asks the browser to sign in with a passkey, using the options your server returned. Send the result back to the server
to finish signing in.

## @better-iam/client/passkeys startRegistration

Asks the browser to create a passkey, using the options your server returned. Send the result back to the server to
save it.

## @better-iam/client/session isUnauthenticated

True when an error means the caller is not signed in any more or must confirm who they are (the server answered 401
or 403). Anything else is a network or server failure, worth a retry rather than a sign-in page.

## @better-iam/auth createAuth

Creates the authentication service (sign-in, sessions, MFA, passkeys, and recovery) on its own, without the rest of
the server. `betterIam()` creates one for you and exposes it as `iam.auth`, so you need this only to embed
authentication in a custom host.

## @better-iam/auth newId

Makes a new random record ID: the prefix you pass (default `id`), an underscore, and 22 random characters. IDs
carry 128 random bits, so they cannot be guessed or enumerated.

## @better-iam/auth newToken

Makes a new random secret token (256 bits, base64url). Tokens are shown to their owner once; only their hash is
stored.

## @better-iam/auth hashToken

The SHA-256 hash, in hex, under which a token is stored and looked up. Storing only hashes means a database leak does
not reveal usable session tokens or API keys.

## @better-iam/core IamError

The error every Better IAM operation throws when it refuses a request. `code` is a stable name such as
`ACCESS_DENIED`, `status` is the matching HTTP status, and `message` is for people. Check `code` in your own code;
the [error reference](/docs/reference/errors) lists every code and how to handle it.

## @better-iam/core SNAPSHOT_VERSION

The version of the snapshot format that `better-iam store-export` writes. `store-import` accepts only this version,
so a snapshot in another format is refused before anything is written.

## @better-iam/core matchPattern

Tests whether an action or resource name matches a policy pattern, exactly as policy evaluation does. The whole name
must match; `*` matches any run of characters (including `/` and `:`) and `?` exactly one, and `${...}` variables are
filled in from the optional context first. There are no regular expressions.

## @better-iam/core compareIds

Compares two IDs in the byte order databases use (SQLite's BINARY, PostgreSQL's "C" collation), so sorting in memory
agrees with `ORDER BY` in SQL.

## @better-iam/core definePolicy

Writes a policy document in TypeScript, with type checking. It validates the document when your code loads, so a
malformed policy fails at startup rather than when it is saved, and returns a detached copy.

## @better-iam/core evaluatePolicy

Decides whether a request is allowed by a set of policy documents, with the same engine the server uses. It needs no
database, so it runs anywhere (the [playground](/playground) uses it) and returns the decision, its reason, and the
statements that matched. Grants add up; each boundary can only narrow them.

## @better-iam/core RecordStore

The base class the reference storage adapters share. It implements the storage contract over one records table, so
SQLite, libSQL, and PostgreSQL behave identically; extend it to support another SQL database.

## @better-iam/core schemaMigrations

The schema steps for one SQL dialect, in order. `applyMigrations` runs the ones a database has not applied yet.

## @better-iam/core storageError

Turns a database failure into an `IamError` that is safe to show: a unique-key clash becomes `CONFLICT` (409), a
busy or deadlocked database `STORAGE_BUSY` (503, retry the whole operation), and no message reveals SQL or record
data.

## @better-iam/core validatePolicy

Checks that a value is a well-formed policy document and throws `INVALID_POLICY` describing the first problem. The
server runs it before storing a document and again before evaluating one.

## @better-iam/core/conformance ConformanceFailure

The error the storage conformance suite throws when an adapter behaves differently from the reference adapters. Its
message names the failing check, so a custom adapter's test run shows exactly what to fix.

## @better-iam/mcp createMcpGate

Puts Better IAM in front of a Model Context Protocol server that speaks Streamable HTTP and decides, tool by tool, who
may see and call what. `gate(request, next)` authenticates the caller (a Better IAM credential, including a delegated
agent session, or an OAuth access token when `oauth` is set), answers unauthenticated requests with a
`WWW-Authenticate` challenge naming the protected resource metadata it serves (RFC 9728), refuses `tools/call`
requests the caller may not make as an MCP tool error, and removes hidden tools from `tools/list` answers. Denied calls
are audited by the IAM server like any denied decision.

## @better-iam/mcp createMcpAuthorizer

The tool-level decisions of `createMcpGate` without the HTTP handling, for tool handlers written directly against an
MCP SDK: `authenticate(request)` identifies the caller, `canCall(caller, name, args)` decides one tool call, and
`visibleTools(caller, tools)` filters a tool list. Better IAM credentials are decided by the policy engine as each
tool's `action` on its `resource`; OAuth access tokens by the tool's `scopes`.

## @better-iam/middleware errorCode

Reads the `code` of an error (such as `ACCESS_DENIED`) without assuming it is an `IamError`; undefined for anything
else. Useful in your own error handlers, where the thrown value can be anything.

## @better-iam/middleware errorStatus

Reads the HTTP `status` of an error without assuming it is an `IamError`; undefined for anything else.

## @better-iam/nestjs IamFilterInterceptor

The interceptor behind `@FilterAccessible`: it removes items the caller may not act on from a list response. You apply
it through the decorator rather than directly.

## @better-iam/nestjs credentialOf

Turns a Nest request into the `{ headers }` credential that `iam.api` calls expect, so your own services can call the
API as the person making the request.

## @better-iam/nestjs isIamError

True when an error is an `IamError`. It checks the shape rather than the class, so errors from a second copy of
`@better-iam/core` in `node_modules` are recognized too.

## @better-iam/nuxt default

The Nuxt module. Add `'@better-iam/nuxt'` to `modules` in `nuxt.config.ts`: it mounts the IAM API in Nitro, installs
the Vue bindings with the session loaded during server rendering, and guards pages.

## @better-iam/oauth createOAuthLogin

Creates the "sign in with Google, GitHub, Microsoft, or your company's provider" flows: it sends people to an OAuth or
OpenID Connect provider and signs them in when they come back. Attach it with `iam.useProtocol(...)`.

## @better-iam/oauth createOAuthProvider

Turns Better IAM into an OAuth 2.0 and OpenID Connect provider, so your other applications and MCP servers can sign
people in with their account here and receive access tokens.

## @better-iam/saml createSamlCache

Remembers which SAML responses were already used, in the IAM database, so a captured response cannot be replayed.
The SAML service creates it for you.

## @better-iam/saml createSamlService

Creates the SAML service provider: the metadata, sign-in, and assertion endpoints that let organizations sign in with
their own identity provider. Attach it with `iam.useProtocol(...)`; see [SAML](/docs/federation/saml).

## @better-iam/saml certificateInfo

Reads an identity provider's PEM certificate and returns its SHA-256 fingerprint, subject, and validity dates, so an
administration screen can show which certificate is configured and when it expires.

## @better-iam/server betterIam

Creates your Better IAM instance from its options: the database, the deployment secret, the public URL, and the rest.
The instance carries the typed server API (`iam.api`), the HTTP handler, and the authorization helpers. Create it
once and import it wherever server code needs identity or access.

## @better-iam/server assertionKey

Derives, from the deployment secret, the shared key that signs and verifies assertions (`iam.assertionKey()` returns
the current one). Services that receive assertions verify them with it, so keep it as secret as the secret itself.

## @better-iam/server SessionTokenError

The error a session-token verifier throws for any token it rejects. `reason` says why, for logs and metrics; answer
the caller with a plain 401.

## @better-iam/server IamError

The same `IamError` class as `@better-iam/core`, re-exported so server code needs one import. Check `error.code` to
handle a specific refusal.

## @better-iam/server publicAuthMethods

The names of the `auth` methods the HTTP handler serves without a session, such as `signIn` and `resetPassword`.
Exported so tools and tests can see the route table the handler enforces.

## @better-iam/server authenticatedAuthMethods

The names of the `auth` methods the HTTP handler serves only to a signed-in caller, such as `signOut` and
`listSessions`.

## @better-iam/server routeGroups

The API groups the HTTP handler exposes under `{basePath}/{group}/{method}`. Groups not in this set are callable only
from server code.

## @better-iam/server publicApiMethods

The few API methods the HTTP handler serves without a credential, such as accepting an invitation (the emailed
token is the proof) or looking up a tenant by its alias.

## @better-iam/server createMetrics

Creates a standalone Prometheus-style metrics collector that you feed from your own `onSpan` hook. Most deployments
use the one built from the `metrics` option instead; see [observability](/docs/operations/observability).

## @better-iam/server createSessionTokenVerifier

Verifies session JWTs issued by Better IAM in your other services, offline, against the published keys
(`GET {basePath}/.well-known/jwks.json` or `iam.sessionTokens.jwks()`). Its `verify(token)` and
`verifyRequest(request)` return the token's claims or throw `SessionTokenError`, so any framework can protect a route
with a few lines. It sees revocation only when a token expires; call `sts.getCallerIdentity` when a service needs an
immediate answer.

## @better-iam/server looksLikeJwt

Tells a session JWT apart from an opaque token by its shape (three dot-separated segments), so code that accepts both
can route each to the right check. It proves nothing about validity.

## @better-iam/server SESSION_TOKEN_TYPE

The `typ` header every Better IAM session JWT carries, `biam-session+jwt`, which keeps session tokens from being
confused with assertions, OAuth access tokens, or tokens from other issuers.

## @better-iam/server SESSION_TOKEN_ALGORITHMS

The two signature algorithms session JWTs may use, EdDSA and ES256. Signing keys and verifiers accept nothing else.

## @better-iam/server publicTrust

Turns a stored trust into the record the API returns: every setting a reviewer needs, with `requiresExternalId` in
place of the stored external ID hash. Use it when you read trusts straight from storage, for example in a custom
export, so the hash never leaves the server.

## @better-iam/server publicOidcProvider

Turns a stored OIDC provider into the record the API returns, an explicit list of its public settings. Use it when you
read providers straight from storage.

## @better-iam/server webTrustTagClaims

Checks a web-identity trust's `tagClaims` mapping (session tag keys to `token.{claim}` names, at most 10) and returns
it cleaned, the same way `trust.create` and `trust.update` do, so tools that prepare trusts ahead of time fail early.

## @better-iam/server actsInOwnRight

Tells whether a session acts in its identity's own right (a signed-in person or an API key) rather than as a
temporary credential. Plugins and custom routes use it to refuse self-service actions, such as accepting terms,
from role sessions and session tokens, as the built-in APIs do.

## @better-iam/server temporarySessionKinds

The session kinds that are temporary credentials, `role`, `session-token`, and `delegated` (an AI agent acting for a
person): derived from a source, bounded by it, and never allowed to pass recent-authentication or self-service checks.

## @better-iam/server nextWatermark

Computes the next "revoke sessions issued before" time for a role, trust, or OIDC provider: it only ever moves
forward and never into the future. Custom revocation tools use it to match `roles.revokeSessions`.

## @better-iam/server revokedByWatermark

Tells whether a session created at a given time falls under any of the given "revoke sessions issued before" times,
the check IAM applies to role sessions on every use.

## @better-iam/server inferenceAction

The action that calling an AI model needs, `inference:invoke`, which the `inference` option adds to the catalog.
Policies grant it on `model/{name}`; use the constant in checks and policies you build in code so they match what the
inference gateway and `inference.check` decide.

## @better-iam/server inferenceResourceType

The resource type of AI models, `model`, which the `inference` option adds to the catalog. A model published with
`inference.createModel` is the resource `model/{name}`, with its tier, family, provider, and prices as attributes for
conditions.

## @better-iam/server createInferenceGateway

Builds the inference gateway, an HTTP handler that lets any Better IAM credential call AI models through the
Anthropic Messages and OpenAI Chat Completions APIs without holding a provider key. Applications call
`iam.inference.gateway(options)`, which passes the instance's own runtime; call this directly only to serve a runtime
of your own (the `GatewayRuntime` interface) behind the same routes.

## @better-iam/server/assertions createAssertionsApi

Builds the `iam.api.assertions` group from the server's internal context. `betterIam()` calls it for you; applications
use `iam.api.assertions`, and the other exports of this entry point verify assertions.

## @better-iam/server/session-tokens createSessionTokenVerifier

Verifies Better IAM session JWTs in downstream services without contacting IAM. This entry point imports nothing from
Node, so it runs in edge middleware, workers, Bun, and Deno as well as Node; point `jwks` at the IAM JWKS route or
pass the key set, and call `verifyRequest(request)` from any framework.

## @better-iam/server/session-tokens MAX_SESSION_TOKEN_LENGTH

The longest session JWT Better IAM issues or accepts, 4096 characters, so services can refuse oversized headers
before verifying them.
