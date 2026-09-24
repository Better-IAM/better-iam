# errors

Every failure in Better IAM is an `IamError` with three fields: a stable `code` such as `ACCESS_DENIED`, a
`message` written for people, and an HTTP `status`. Codes are part of the public contract and do not change between
releases. Messages may be reworded at any time and can contain names from your data, so show them to people but
never parse them: branch on `code`, never on `message`.

Over HTTP a refused call answers with that status and the body
`{ "error": { "code": "ACCESS_DENIED", "message": "Access denied" } }`. A `RATE_LIMITED` answer also carries
`retryAfterMs` in the body and a `Retry-After` header in seconds. An exception that is not an `IamError` becomes
`500 INTERNAL_ERROR` with a generic message, so internals never leak. The [browser client](/docs/frameworks/client#errors)
rethrows the envelope as `IamClientError` with the same `code` and `status`, plus `retryAfterMs` and, when you create
the client with `requestId`, the `requestId` it sent as `X-Request-Id`, which you can quote in support tickets and find
on the server's `http` spans. The [CLI](/docs/reference/cli) prints `CODE: message` to standard error and exits with
status 1.

Each code below says what went wrong, why it happens, and what the caller should do; codes are grouped by HTTP
status. On the server, catch `IamError` and compare its `code`:

## Handling errors in a UI

Map codes to what the person should do next, not to messages. A few groups cover most screens: sign in again
(`UNAUTHENTICATED`, `SESSION_NETWORK_MISMATCH`), step up (`MFA_REQUIRED`, `RECENT_AUTH_REQUIRED`), fix the form (`INVALID_INPUT`,
`INVALID_CREDENTIALS`, `WEAK_PASSWORD`, shown next to the field), wait (`RATE_LIMITED`), not allowed
(`ACCESS_DENIED`, where you can offer to request access), and reload because something changed (`CONFLICT`,
`VERSION_CONFLICT`, `INVALID_TRANSITION`). Show anything else as a generic failure with the request ID. The Next.js,
NestJS, SvelteKit, Nuxt, and Node middleware integrations already treat `UNAUTHENTICATED`, `MFA_REQUIRED`,
`EMAIL_UNVERIFIED`, `TENANT_INACTIVE`, and `TENANT_UNAVAILABLE` as a signed-out request (Next.js also the network
refusals `SESSION_NETWORK_MISMATCH`, `IP_BLOCKED`, and `IP_NOT_ALLOWED`).

```ts
import { IamClientError } from 'better-iam/client';

type NextStep =
  | { kind: 'sign-in' }
  | { kind: 'step-up'; code: string }
  | { kind: 'wait'; ms: number }
  | { kind: 'message'; text: string };

/** Decides what the UI does after a failed call. */
export function nextStep(error: unknown): NextStep {
  if (!(error instanceof IamClientError)) throw error; // a network failure or an aborted call
  switch (error.code) {
    case 'UNAUTHENTICATED':
    case 'SESSION_NETWORK_MISMATCH':
      return { kind: 'sign-in' };
    case 'MFA_REQUIRED':
    case 'RECENT_AUTH_REQUIRED':
      return { kind: 'step-up', code: error.code };
    case 'RATE_LIMITED':
      return { kind: 'wait', ms: error.retryAfterMs ?? 60_000 };
    case 'ACCESS_DENIED':
      return { kind: 'message', text: 'You do not have permission to do this.' };
    case 'CONFLICT':
    case 'VERSION_CONFLICT':
      return { kind: 'message', text: 'This changed in the meantime. Reload and try again.' };
    default:
      // requestId is set when the client was created with { requestId: true }.
      return { kind: 'message', text: `Something went wrong (reference ${error.requestId ?? 'none'}).` };
  }
}
```

## ACCESS_DENIED

The caller is signed in but is not allowed to perform this action.

Every API operation checks an `iam:*` permission (for example `iam:groups:update`) and, when no role or policy grants
it or a deny or boundary blocks it, records a `deny` audit event and fails with this code; `iam.require` and the
framework guards throw it for your own actions too. It also covers specific refusals: approving your own access
request, granting a role beyond your grant authority, changing a binding issued under a higher authority, cancelling
someone else's request, or acting from a session that is not an ordinary session of the tenant.

**How to fix:** ask an administrator for a role that grants the action. To see why a decision was made, use
[`policies.simulate`](/docs/reference/api/policies#simulate) or [`accessPaths.find`](/docs/reference/api/access-paths#find).

## ACCESS_EXPIRING

The access that allows this verifiable credential ends within a minute.

A self-service credential never outlives the grant that allowed `vc:request`: an expiring binding or group membership,
a just-in-time activation, an access window, or the assumed role or temporary credentials the request came from.

**How to fix:** renew the access (activate the eligible role again, or ask for the binding to be extended), then
request the credential.

## ACCOUNT_LINK_CONFLICT

The external account you are linking is already linked to a different account in this tenant.

It happens at the callback of an OAuth or SAML linking flow when the provider identity (provider, issuer, and
subject) already belongs to another identity. A provider identity links to one account at a time, and links never
move silently.

**How to fix:** sign in with that provider to reach the account it already belongs to
([link an existing account](/docs/federation/oauth-sign-in#link-an-existing-account)).

## ACCOUNT_LINK_REQUIRED

A first sign-in through an external provider used an email that already belongs to an account in this tenant, so the accounts must be linked explicitly.

Better IAM never merges accounts by email, because anyone who could set that address at some provider could
otherwise take over the account.

**How to fix:** sign in to the existing account (password, passkey, or another linked provider), reauthenticate, and
start the provider's linking flow from that session; later sign-ins with the provider then reach that account
([link an existing account](/docs/federation/oauth-sign-in#link-an-existing-account)).

## ALREADY_INITIALIZED

Bootstrap was run on a database that already has a root tenant.

[`bootstrap`](/docs/reference/api#bootstrap) and the `better-iam bootstrap` command create the root tenant and the
first root administrator exactly once.

**How to fix:** nothing needs creating. Sign in with an existing root administrator, or run
[`recover-root`](/docs/reference/cli#recover-root) if you lost access to all of them
([recovering root access](/docs/guides/authentication/recovery#recovering-root-access)).

## ARCHIVE_CONFLICT

The audit archive already holds a file for this batch of events with different contents.

The JSONL archive sink writes each batch once, named by tenant and sequence range, and never replaces an existing file.
A different batch under the same name means two deployments share one archive directory, or the database's audit
chain diverged from what was archived earlier (for example after restoring an old backup). `archiveAudit` reports it
per tenant in its `failed` list, and `audit-archive` then fails with `AUDIT_ARCHIVE_FAILED`.

**How to fix:** keep the existing file as evidence, give each deployment its own archive directory, and investigate
why the chain changed ([continuous audit archiving](/docs/operations/jobs#continuous-audit-archiving)).

## AUDIT_ARCHIVE_FAILED

The `audit-archive` command could not archive the audit events of one or more tenants.

The command prints its full result first and names each failed tenant with the error code it hit. Tenants that
succeeded are archived, and every tenant keeps its own archive position.

**How to fix:** resolve the listed errors (often the archive sink's storage or permissions) and run the command again;
it continues from each tenant's position ([continuous audit archiving](/docs/operations/jobs#continuous-audit-archiving)).

## AUDIT_ARCHIVE_INVALID

The `audit-verify-archive` command found that a tenant's archived audit chain does not verify.

The command checks the archive files alone, without the database: every sequence must appear once, hashes are
recomputed, and links must be intact. It also fails when two archived copies of the same sequence disagree, and prints
the result, including the failure reason and sequence, before it exits.

**How to fix:** treat it as a possible tampering or data-loss incident, and compare the failing range with the
database (`audit-verify`) and your backups ([audit chain](/docs/guides/events/audit-chain)).

## AUDIT_CHAIN_BROKEN

The `audit-verify` command found that a tenant's audit chain does not verify.

Each audit event carries a hash of the one before it, so a changed, removed, or reordered event breaks the chain. The
command prints the verification result, including where it failed, before it exits.

**How to fix:** treat it as a possible tampering or data-loss incident: find the failing sequence in the output,
compare it with your archive or backups, and review who can write to the database
([audit chain](/docs/guides/events/audit-chain)).

## AUTHORITY_UNAVAILABLE

A certificate authority cannot sign: it, or an authority above it, is disabled, revoked or expired.

[`pki.issueCertificate`](/docs/reference/api/pki#issuecertificate), `requestCertificate` and `createAuthority` (for a
parent) refuse. A revoked authority cannot be changed at all.

**How to fix:** re-enable a disabled authority with [`updateAuthority`](/docs/reference/api/pki#updateauthority), or
issue from another authority. A revoked or expired authority has to be replaced.

## BILLING_PERIOD_CLOSED

The month has already been invoiced for this billing account, so its usage and prices can no longer change.

`billing.record` (and `iam.billing.record`) refuse usage whose `occurredAt` falls in a month with a statement for the
account, and `billing.setPrice` refuses an `effectiveFrom` that reaches back into an invoiced month.

**How to fix:** record late usage in the current month, or have a root administrator void the statement
(`billing.voidStatement`), record the correction, and close the month again ([billing](/docs/reference/api/billing)).

## BREACHED_PASSWORD

The new password appears in a known data breach.

It is raised wherever a password is set (sign-up, password change, password reset, and other flows that set one) when
the deployment screens passwords with `authentication.passwordPolicy.isBreached`, for example the built-in
`pwnedPasswords()` client.

**How to fix:** ask the person to choose a different password, and show the message next to the password field
([password screening](/docs/guides/authentication/sign-in-methods#password-screening)).

## CATALOG_LOCKED

Organizations cannot register their own resource types or actions on this deployment.

`resourceTypes.register` and `actions.register` need `permissions.mode: 'tenant-defined'` in the server options; in
catalog mode only your configuration defines the catalog.

**How to fix:** declare the types and actions under `permissions` in your configuration, or switch to tenant-defined
mode if organizations should define their own ([catalog](/docs/guides/authorization/catalog)).

## CHECKOUT_REQUIRED

A vault secret is handed out only through check-outs, so it cannot be revealed directly.

Secrets with a check-out policy that has `required` (shared privileged credentials) refuse
[`vault.reveal`](/docs/reference/api/vault#reveal), so every use is time-limited, attributed and, when the policy says
so, explained. The holder of a live check-out may reveal the version they checked out.

**How to fix:** call [`vault.checkout`](/docs/reference/api/vault#checkout) (with a `reason` when the policy asks
for one) and [`checkin`](/docs/reference/api/vault#checkin) when done.

## CERTIFICATE_INVALID

`iam.pki.verify` refused a presented certificate.

The certificate was not issued by this deployment (or differs from the stored one), is revoked, expired or not yet
valid, is a CA certificate, does not allow the requested usage, or chains to an authority that is no longer active.

**How to fix:** present a current certificate issued by the tenant's authority, with its usage matching the side of
the connection, and renew certificates before they expire.

## CLAIM_UNAVAILABLE

A verifiable credential type requires a claim this person has no value for.

Claims marked `required` in the credential type are never left out, so issuing is refused instead (for example, a
`title` taken from an identity attribute that was never set).

**How to fix:** set the value on the person (such as the identity attribute), or make the claim optional with
[`verifiableCredentials.updateType`](/docs/reference/api/verifiable-credentials#updatetype).

## CONFIG_DRIFT

`config-plan --fail-on-drift` found differences between the tenant and the configuration file.

The command prints the full plan first; the count covers the items it would create, update, or delete. The flag exists
so a CI job fails when someone changed production outside the reviewed file.

**How to fix:** review the plan, then apply the file with `config-apply` or update the file to the intended state
([configuration as code](/docs/guides/privileged-access/config-as-code)).

## CONFIG_EXISTS

`better-iam init` found an existing configuration file and left it untouched.

**How to fix:** edit the existing file, or pass `--config` with a new path to generate a fresh one.

## CONFIRMATION_INVALID

The link that confirms a public data-subject request is wrong, already used, or expired.

[`privacy.confirmPublic`](/docs/reference/api/privacy#confirmpublic) accepts the token emailed to the requester once,
within seven days of the request, and only while the request still waits for confirmation. Unknown request IDs get the
same answer, so the call reveals nothing about which requests exist. Attempts are rate limited per request.

**How to fix:** open the latest confirmation email and use its link. If the request lapsed or was already confirmed,
file a new one with [`privacy.submitPublic`](/docs/reference/api/privacy#submitpublic)
([privacy guide](/docs/guides/governance/privacy)).

## CONFLICT

The request conflicts with a record that already exists or with the record's current state.

Typical causes are a duplicate (an agreement, invariant, access package, resource type, or action with the same name,
a resource or domain that is already registered or claimed, a binding or group membership that already exists, an
identical pending request), acting on a certification campaign that is closed, and reusing an invitation that was
consumed or revoked. The storage layer also raises it for any duplicate id or tenant-unique key and for an attempt to
move a record to another tenant.

**How to fix:** reload the current state and decide again; for a duplicate, use the existing record or choose another
name.

## CREDENTIAL_CHAINING_DISABLED

A session token cannot be minted from a credential that is itself temporary.

`sts.getSessionToken` accepts only a signed-in session or an API key as its source. Role sessions and other session
tokens are refused, so a temporary credential can never be renewed or extended by deriving a new one from it.

**How to fix:** call `sts.getSessionToken` with the person's own session or the service account's API key
([sts](/docs/reference/api/sts#getsessiontoken)).

## CSRF

A protocol endpoint that acts on a signed-in session was called without a trusted `Origin` or the `X-Better-IAM` header.

The OAuth and SAML sign-in handlers start account linking only for a `POST` with an `Origin` from `trustedOrigins`,
the `X-Better-IAM: 1` header, and a JSON content type, and the OAuth provider's `completeInteraction` requires a
trusted `Origin` on its consent `POST`. This stops other sites from starting these flows with the person's cookies.

**How to fix:** send the request with `fetch` from your own origin (the browser sets `Origin`), include the header,
and list the origin in `trustedOrigins` ([CSRF and Origin checks](/docs/guides/authentication/http#csrf-and-origin-checks)).

## CSRF_REJECTED

The request did not carry the headers that prove it came from your application rather than another site.

API calls must be `POST` requests with `Content-Type: application/json` and `X-Better-IAM: 1`, and a request that
carries cookies must also send an `Origin` header. The SCIM administration handler additionally rejects cross-origin
requests, and the Next.js, NestJS, and middleware integrations apply the same cookie rule to your own routes.

**How to fix:** call the API through the browser client, which sets both headers, or add them yourself
([CSRF and Origin checks](/docs/guides/authentication/http#csrf-and-origin-checks)).

## DATABASE_IN_USE

Code running inside a transaction tried to use the same SQLite or libSQL database through a second adapter instance.

The adapters refuse it instead of waiting forever for a lock their own caller holds. Copying a database onto itself
is the usual cause, which `copyStore` reports as `SAME_DATABASE`.

**How to fix:** inside a transaction, read and write through the transaction's store, and share one adapter instance
per database file.

## DELEGATION_EXISTS

An AI agent and a person already have a pending request or an active delegation between them.

One live delegation links an agent and a person at a time. `delegations.grant` refuses a new one while the agent's
request waits for the person's decision or while the person already delegates to the agent, and
`delegations.request` refuses a second request.

**How to fix:** approve or deny the pending request, or revoke the existing delegation before granting a new one
([delegations](/docs/reference/api/delegations)).

## DELEGATION_INACTIVE

The delegation can no longer be used to open delegated sessions.

`delegations.assume` refuses a delegation that was denied or revoked, a request that lapsed undecided, a delegation
past its end, and one whose person is no longer an active, unexpired member of the tenant.

**How to fix:** have the person grant a new delegation, or ask for one with `delegations.request`;
[`delegations.get`](/docs/reference/api/delegations#get) shows the `status` and whether it `expired`.

## DELEGATION_NOT_ALLOWED

The AI agent does not accept delegation.

Its profile sets `delegable: false`, so `delegations.grant`, `delegations.request`, `delegations.approve`, and
`delegations.assume` refuse it, and its existing delegated sessions are refused (as `UNAUTHENTICATED`) until
delegation is turned back on.

**How to fix:** an administrator sets `delegable: true` with [`agents.update`](/docs/reference/api/agents#update).

It also answers delegation limits that are not the agent's switch: a hand-off the person did not allow
([`delegations.handoff`](/docs/reference/api/delegations#handoff)), and a delegation token for an audience outside the
`tokenAudiences` of an agent in the chain, or for a scope some limit on the session does not allow outright
([`delegations.issueToken`](/docs/reference/api/delegations#issuetoken)). Name an allowed audience or narrower
`scopes`, or have an administrator add the audience to the agents' profiles.

## DELEGATION_PENDING

The person has not approved this delegation yet.

`delegations.assume` answers it for a request the person is still deciding; a request waits up to seven days.

**How to fix:** poll [`delegations.get`](/docs/reference/api/delegations#get) until `status` becomes `active` (or
`denied`), then call `assume` again.

## DELEGATION_TOKEN_INVALID

A delegation token did not verify, or the delegation behind it has ended.

`iam.a2a.verifyDelegationToken` answers it (401) when the token is not a `biam-delegation+jwt` signed with the
deployment's card keys, when its issuer, audience, organization, or times do not match, or when it lives longer than an
hour. With `live: true` it also answers it when anything the token stands on has changed:

- the delegation or one above it was revoked or has expired;
- the person or an agent in the chain is no longer in good standing;
- the acting agent's API key was revoked, or the agent no longer accepts delegation;
- the audience left an agent's `tokenAudiences`;
- a limit no longer allows a scope.

It also answers it when a `replay` check refuses a token seen before.

**How to fix:** the agent gets a new token with
[`delegations.issueToken`](/docs/reference/api/delegations#issuetoken) for the right `audience`; when the delegation
has ended, the person grants a new one.

## DELIVERY_REQUIRED

The operation sends email, but the deployment has no email delivery callback.

Organization and member invitations (`tenants.create`, `identities.invite`, and their resend calls), certification
reminders (`certifications.remind`), the access digest, and expiry reminders enqueue email and refuse to run without
`authentication.sendEmail`.

**How to fix:** configure `sendEmail` in the server options
([configuration](/docs/operations/deployment/configuration)); in tests, a callback that records messages is enough.

## DOCTOR_FINDINGS

`doctor --strict` found problems more serious than informational notes.

`doctor` checks the schema, durability settings, secrets, delivery transports, and scheduled jobs, and prints every
finding; with `--strict`, any finding above `info` severity fails the run.

**How to fix:** fix each check named in the output, or run without `--strict` while you work through them
([doctor](/docs/operations/storage#doctor)).

## DOMAIN_NOT_ALLOWED

The domain belongs to a shared mailbox provider, so no organization can claim it.

`domains.add` refuses consumer email domains (a default block list, replaced by the `domains.blockedDomains` option),
because verifying one would route everyone with such an address to a single organization.

**How to fix:** claim the organization's own domain instead.

## DOMAIN_TAKEN

Another organization has already verified this email domain.

A verified domain belongs to exactly one tenant, so `domains.add` and `domains.verify` refuse it once another tenant
verified it first.

**How to fix:** if the domain is yours, the other organization must release it with `domains.delete` before you can
verify it.

## EMAIL_UNVERIFIED

The account's email address is not verified, and this deployment requires verification before sign-in.

With `authentication.requireEmailVerification` (on by default when self-registration is enabled), sign-in, session
issue, and every later use of a session refuse unverified identities.

**How to fix:** have the person open the verification link from their email (`auth.verifyEmail`), or send a new one
with `auth.requestEmailVerification` ([email verification](/docs/guides/authentication/recovery#email-verification)).

## ENGINE_FAILED

A dynamic secret's engine failed to issue or renew a credential.

[`vault.lease`](/docs/reference/api/vault#lease) asks the engine configured on the deployment (`vault.engines`) to
mint a credential for the caller; the engine threw, timed out (`vault.callTimeoutMs`, 30 seconds by default), or
returned something that does not fit the secret's format. No lease is left behind, and credentials minted for a lease
that was revoked meanwhile are revoked at once.

**How to fix:** check the system the engine talks to and the engine's logs, then call `lease` again. The lease's
`vault:lease` audit event (outcome `deny`) carries the error.

## FEATURE_DISABLED

The feature this call needs is turned off or not configured on this deployment or for this organization.

Examples: self-registration without `signUpEnabled`, password sign-in or recovery with `emailPassword: false` or no
`sendEmail`, a passwordless channel or passkeys that are not configured, passkey sign-in for an account without a
passkey, emailed MFA codes the sign-in does not offer, a delivery kind without its callback, impersonation in a tenant
whose policy does not set `allowImpersonation`, session JWTs without `sts.jwt`, custom hostnames without
`hosts.customHostnames`, passkeys on a custom hostname outside the passkey domain (the RP ID), and the `inference`
API group and `iam.inference` without the `inference` option.

**How to fix:** enable the option in your [configuration](/docs/operations/deployment/configuration) or the tenant's
[authentication policy](/docs/guides/authentication/tenant-policy), or hide the feature in your UI while it is off.

## FEATURE_LOCKED

A tenant tried to choose its own value for a feature flag (`features.setOverride`) that the flag's owners decide for
it.

The flag does not allow tenants to choose (`tenantOverridable` is off), or a locked target set by the tenant that
defines the flag covers this tenant or one of its ancestors. Withdrawing an earlier choice (`value: null`) is always
allowed.

**How to fix:** ask the flag's managers (root administrators for a platform flag) to allow overrides or to lift the
lock. [`features.list`](/docs/reference/api/features#list) shows `overridable` and `locked` for each flag.

## FINDINGS

`analyze --fail-on` found access findings at or above the chosen severity.

The command prints the report first; the count covers unsuppressed findings at the `--fail-on` level or higher, so a
CI job fails when new risk appears.

**How to fix:** fix the findings, or record accepted ones with `analysis.suppress` so they stop failing the run
([scan for risky configuration](/docs/guides/authorization/reviews#scan-for-risky-configuration)).

## FORBIDDEN

Self-registration was attempted in the root tenant, where only administrators create accounts.

`auth.signUp` refuses the platform's root tenant, because anyone who registered there would join the tenant that
operates the whole platform.

**How to fix:** sign people up in an organization tenant, and create root identities with `bootstrap`,
`recover-root`, or an administrator.

## GRANT_AUTHORITY_REQUIRED

The caller has permission for the action but holds no active grant authority to issue access under.

Operations that grant access or create grantable records (bindings, roles, policies, group memberships, invitations,
organizations, API keys) record the [grant authority](/docs/guides/authorization/roles#grant-authorities) they were
issued under. A non-root administrator needs one that is not revoked and whose delegation chain is intact.

**How to fix:** ask a root administrator, or someone holding a broader authority, to delegate one with
[`authorities.create`](/docs/reference/api/authorities#create).

## HOSTNAME_NOT_ALLOWED

The hostname belongs to the deployment itself, so no organization can claim it.

`hostnames.add` refuses the deployment's base URL host, its trusted origins, and every name in its organization
subdomain space (anything matching or under a `hosts.patterns` template), because those addresses already route to
the deployment or to other organizations.

**How to fix:** claim a hostname on the organization's own domain, such as `login.acme.com`.

## HOSTNAME_TAKEN

Another organization has already verified this custom hostname.

A verified hostname belongs to exactly one organization, so `hostnames.add` and `hostnames.verify` refuse it once
another organization verified it first.

**How to fix:** if the hostname is yours, the other organization must release it with
[`hostnames.delete`](/docs/reference/api/hostnames#delete) before you can verify it.

## HOST_KEY_CHANGED

The host key sent with an SSH host's renewal token is not the key the host enrolled with.

`ssh.syncHost` never moves a host to another key, so a stolen renewal token cannot produce a host certificate for an
attacker's key.

**How to fix:** after rebuilding a server, re-enroll it: get a new join token with
[`ssh.resetJoinToken`](/docs/reference/api/ssh#resetjointoken) and run `better-iam ssh-host-enroll`.

## HOST_KEY_IN_USE

The SSH host key is another enrolled host's key.

Each host's key identifies it to clients, and revoking a host publishes its key as revoked, so two hosts never share
one (a cloned image, or a key copied from another server).

**How to fix:** generate a fresh host key on the server (`ssh-keygen -A` after removing the copied keys), then enroll.

## HOST_MISMATCH

The request arrived on one organization's sign-in address but names or authenticates as another organization.

With organization addresses (`hosts`), a request on `acme.signin.example.com` or Acme's custom hostname is pinned
to Acme: a sign-in call naming another `tenantId`, a session or API key of another organization, and a page on one
organization's address calling the API on another's are all refused. Root administrators sign in at the
deployment's own address, not an organization's.

**How to fix:** send the person to their own organization's address (its `signInUrl` from
[`tenants.lookup`](/docs/reference/api/tenants#lookup)), or leave `tenantId` out and let the address decide
([sign-in addresses](/docs/operations/deployment/hosts-and-regions)).

## HOST_NAME_TAKEN

Another SSH host of the organization already uses this name or address.

A host certificate vouches for every name and address of its host, so each belongs to one host only.

**How to fix:** remove the address from the other host with [`ssh.updateHost`](/docs/reference/api/ssh#updatehost), or use
another name.

## HOST_OUTSIDE_PATTERNS

An SSH host name or address falls outside the organization's host patterns.

When `hostPatterns` is set in the SSH settings, the host authority only vouches for names matching it, so
`ssh.createHost` and `ssh.updateHost` refuse other names and addresses, and `ssh.updateSettings` refuses patterns
that would leave an existing host uncovered.

**How to fix:** use a name inside the patterns, or widen them with
[`ssh.updateSettings`](/docs/reference/api/ssh#updatesettings).

## IDENTITY_EXISTS

An identity with this email address already exists in the tenant.

Emails are unique within a tenant (another tenant may have its own identity with the same address), so sign-up,
`identities.create`, `identities.createMany`, `identities.invite`, and email changes refuse a duplicate.

**How to fix:** use the existing identity or another address; a person who already has an account should sign in or
reset their password instead of signing up again.

## IDENTITY_INACTIVE

Credentials are issued to active members only.

The person the credential or offer is for is disabled, deleted, past their scheduled account expiry, or not a member of
this organization.

**How to fix:** reactivate the account first, or offer the credential to someone else.

## IMPERSONATION_RESTRICTED

The operation is not available while an administrator is impersonating a member.

An impersonation ("view as") session never counts as recently authenticated, so every operation that needs
[recent authentication](/docs/guides/authentication/sessions#recent-authentication) refuses it. Decisions made in the
member's name are refused too: approving requests or activations, reviewing access, accepting agreements, granting
OAuth consent, requesting packages, assuming roles, change previews, and starting another impersonation.

**How to fix:** end the impersonation and act from your own session
([impersonation](/docs/guides/authentication/impersonation)).

## INSUFFICIENT_SCOPE

The OAuth access token is valid but lacks a scope the resource requires.

Resource servers built with `createAccessTokenVerifier` or `createResourceGuard` check the scopes they were
configured with and answer with a `WWW-Authenticate` challenge naming `insufficient_scope`; the message lists the
missing scopes.

**How to fix:** have the client request the missing scopes in a new authorization, and make sure it is allowed to
([resource servers](/docs/federation/oauth-resource-servers)).

## INTERNAL_ERROR

Something failed on the server that Better IAM does not describe to the caller.

Over HTTP, any exception that is not an `IamError` (a bug, or one of your callbacks such as `resolveResource`
throwing) is answered with this code and a generic message so internals never leak; direct server calls throw the
original error instead. The NestJS middleware and the SCIM handlers do the same, and `accessPaths.find` and
`impact.preview` use it if their read-only simulation ends abnormally.

**How to fix:** retry once, then find the request in your logs or `http` spans by its request ID and report it
([observability](/docs/operations/observability)).

## INVALID_ACTION

The action name is not in the catalog, or a tenant-defined action is malformed.

Policy documents, `listAccessible`, access paths, invariants, `policies.whoCan`, and impact previews accept only
actions the catalog knows (wildcards excepted). `actions.register` needs the `{resourceType}:{verb}` form under a
tenant-defined resource type that is registered first.

**How to fix:** check the spelling, then declare the action in `permissions.actions` or register it
([catalog](/docs/guides/authorization/catalog)).

## INVALID_ARGUMENT

A `better-iam` command received a flag it does not accept, a missing value, or a value out of range.

The message names the problem, for example a required `--tenant` or `--output`, a flag used with the wrong command, or
a number outside its allowed range; the command stops before it changes anything.

**How to fix:** correct the flags using the command's usage line in the [CLI reference](/docs/reference/cli).

## INVALID_ASSERTION

A stateless assertion failed verification.

`verifyAssertion` (and the Next.js edge and NestJS assertion helpers) refuses a token that is malformed, signed with
another key, meant for another audience or issuer, expired, or not yet valid.

**How to fix:** issue a fresh assertion with [`assertions.issue`](/docs/reference/api/assertions#issue) for the right
audience, and verify with every current key from `iam.assertionKeys()` while a secret rotates
([stateless assertions](/docs/operations/security#stateless-assertions)).

## INVALID_CHALLENGE

A one-time link, code, or sign-in step is wrong, expired, or already used.

It covers email verification, password-reset, and email-change links, passwordless and phone verification codes, the
sign-in challenge between the password and the second factor, MFA enrollment, and passkey ceremonies. A passwordless
code also fails when the email or phone changed after it was sent.

**How to fix:** start the step again to get a new link or code; retrying the same one fails the same way.

## INVALID_CIPHERTEXT

A key management ciphertext could not be decrypted.

[`keys.decrypt`](/docs/reference/api/keys#decrypt) and `reEncrypt` refuse a ciphertext that is malformed, was
modified, was produced by another key than the `keyId` you insisted on, or is presented with a different encryption
context than it was encrypted with. The reasons are deliberately indistinguishable. A failure after the call was
authorized is audited as a denied `iam:kms:decrypt` with `reason: 'invalid-ciphertext'`.

**How to fix:** pass exactly the encryption context the data was encrypted with (the same keys and values), and store
ciphertexts unchanged.

## INVALID_COMMAND

The CLI does not know the command you typed.

**How to fix:** run `better-iam help` for the list of commands, or check the [CLI reference](/docs/reference/cli).

## INVALID_CONFIG

The server, a storage adapter, or the CLI was given an invalid configuration.

It surfaces at startup: when you call `betterIam()`, create an adapter, or when a CLI command loads your configuration
file. Examples are a missing `database`, a plain-HTTP `baseURL` outside localhost, an unsupported database URL, or
email features enabled without `sendEmail`; the browser client raises it too (with status `0`) for a bad `baseURL` or
`basePath`.

**How to fix:** correct the option the message names ([configuration](/docs/operations/deployment/configuration)).

## INVALID_CREDENTIAL

The credential id passed to a `credentials` method does not refer to an API key.

`credentials.get`, `credentials.update`, `credentials.revoke`, and `credentials.rotate` manage service-account API
keys only, so the id of a user session or temporary credential is refused.

**How to fix:** pass an API key id from `credentials.list`; end user sessions with `identities.revokeSessions`
instead.

## INVALID_CREDENTIALS

The email and password, or the current password, are wrong, or the account cannot sign in.

`auth.signIn` gives the same answer for an unknown email, a wrong password, and a disabled account, so responses never
reveal which accounts exist; `auth.changePassword` and `auth.reauthenticate` use it for a wrong password. Failed
attempts count toward rate limits and are recorded.

**How to fix:** show a generic "email or password is incorrect" message on the form and let the person retry or
reset their password.

## INVALID_CSR

A certificate request could not be used.

[`pki.issueCertificate`](/docs/reference/api/pki#issuecertificate) and `requestCertificate` need a PEM PKCS#10 request
signed by its own key. The request is refused when it is not valid DER, its signature does not verify, it uses an
unsupported algorithm (such as RSA-PSS), or its key is not ECDSA P-256/P-384, Ed25519 or RSA of 2048 to 8192 bits.

**How to fix:** build the request with `createCertificateRequest` from `better-iam`, or with OpenSSL
(`openssl req -new -key key.pem`).

## INVALID_FILTER

A storage query was given an invalid filter, ordering, or pagination.

It comes from `IamStore.find` and `findOrdered`: the filter must be a plain JSON object, `limit` and `offset`
nonnegative safe integers, the `after` cursor an id, and ordering needs a top-level field, `asc` or `desc`, and
finite bounds. You meet it when a plugin or adapter works with the store directly.

**How to fix:** correct the query arguments ([adapter contract](/docs/operations/extensions#adapter-contract)).

## INVALID_HIERARCHY

The tenant hierarchy does not allow this parent and child, or the stored hierarchy is broken.

`tenants.create` and `tenants.reparent` refuse a child type that the parent's type does not allow in
`hierarchy.types`, and a move under the tenant's own subtree. With status 500 it means a stored ancestry has a cycle
or exceeds the maximum depth, which points to data changed outside Better IAM.

**How to fix:** choose a permitted parent or adjust `hierarchy` in your configuration; for the 500 case, repair the
tenants' `parentId` values ([tenants and identities](/docs/guides/concepts/tenants-and-identities)).

## INVALID_IDENTITY

The identity involved is not in a state that allows this operation.

`accessRequests.approve` refuses a request whose requester is no longer active, and `credentials.create` issues API
keys only to active, unexpired service accounts and to AI agents in good standing. `delegations.grant` and
`delegations.approve` (409) refuse an agent that is not in good standing: suspended, expired, or with a sponsor who is
no longer an active person.

**How to fix:** re-enable the identity (or extend its expiry) first, or issue the key to a service account rather
than a person. For an agent, check [`agents.standing`](/docs/reference/api/agents#standing), then resume it or name
an active sponsor with `agents.update`.

## INVALID_INPUT

A field in the request is missing, has the wrong type, or is out of range.

It is the general validation error of every package: an empty name, a malformed email or id, a `limit` outside its
range, a body that is not a JSON object, or options that cannot be combined; the message names the field. A few
handlers use it with status 413 for an oversized body.

**How to fix:** correct the input; sending the same request again fails the same way.

## INVALID_LINK

The identities cannot be linked, or the link or linking proof is no longer valid.

[`links.create`](/docs/reference/api/links#create) links only ordinary user identities of two different tenants, and
linked onboarding needs an ordinary user session. `links.switch` refuses a link that no longer holds, and a federated
linking callback refuses a proof whose session or identity changed.

**How to fix:** link from two signed-in user sessions in different tenants, and start a linking flow again if its
session ended.

## INVALID_MFA

The authenticator code or recovery code is wrong, expired, or already used.

Authenticator (TOTP) codes must be six digits and each time step is accepted once, so a replayed code fails; emailed
codes expire, and each recovery code works once. Failures count toward the sign-in rate limit.

**How to fix:** enter a fresh code from the authenticator app or email, or an unused recovery code
([MFA](/docs/guides/authentication/mfa)).

## INVALID_NONCE

The holder proof names no valid nonce.

Every proof must carry a fresh nonce from
[`verifiableCredentials.nonce`](/docs/reference/api/verifiable-credentials#nonce) (or the issuer's nonce endpoint). Nonces
work once, for five minutes, for one organization.

**How to fix:** fetch a new nonce, sign a new proof with it, and send the request again.

## INVALID_PASSKEY

The passkey response could not be verified or does not belong to this account.

Registration and sign-in responses are checked against the stored challenge, the relying party, user verification,
and the registered credential; a passkey registered for another identity or organization is refused.

**How to fix:** start the ceremony again and use a passkey registered for this account in this organization
([passkeys](/docs/guides/authentication/passkeys)).

## INVALID_POLICY

A policy document or access-package rule does not follow the policy grammar.

Policies, boundaries, ceilings, API key session policies, and package rules are validated when saved; the message
says what is wrong, and for package rules it starts with the path of the failing clause.

**How to fix:** correct the document; [`analysis.lintPolicy`](/docs/reference/api/analysis#lintpolicy) checks one
before you save it ([policies](/docs/guides/authorization/policies)).

## INVALID_PROOF

The holder proof does not verify.

A proof is an `openid4vci-proof+jwt` signed with the holder key (ES256, ES384 or EdDSA) whose public half is in the
`jwk` header, with the organization's issuer URL as `aud` and an `iat` within the last five minutes.

**How to fix:** sign the proof with the key the credential should be bound to, for the right issuer URL.

## INVALID_RECORD

A record written to storage is not plain JSON or breaks a storage limit.

A stored record must be a JSON object whose collection name, `id`, `tenantId`, and `uniqueKey` are nonempty strings of
at most 512 UTF-8 bytes, nested at most 64 levels, without symbols, cycles, or unpaired surrogates, and under one
million characters. You meet it when a plugin or your own code writes to `iam.store`.

**How to fix:** store only plain JSON values within these limits
([adapter contract](/docs/operations/extensions#rules-every-adapter-must-keep)).

## INVALID_REQUEST

A policy evaluation input or an HTTP request target could not be understood.

`evaluatePolicy` from `@better-iam/core` needs an action, a resource, and a `grants` array (with optional
`boundaries` and `context`), and the Node.js handler refuses a request URL it cannot parse.

**How to fix:** pass a complete evaluation input, or fix the client or proxy that produced the URL.

## INVALID_RESOURCE_TYPE

The resource type is unknown, reserved, or cannot be used this way.

`resourceTypes.register` refuses a name the platform already defines and a parent that is not an existing managed
type. Registering resources, creating relationships, and policy documents need a known type, and only managed types
hold registered resources; other types are resolved by your `resolveResource` callback.

**How to fix:** declare or register the type first, and check whether it is managed
([resources and catalog](/docs/guides/concepts/resources-and-catalog)).

## INVALID_SEALED_VALUE

A stored secret could not be decrypted with the configured secrets.

Better IAM seals sensitive values at rest (webhook signing secrets, queued delivery payloads, downstream SCIM tokens,
and others) with the deployment `secret`. When that secret changed and the old one is not in `previousSecrets`, or the
stored value was damaged, the value cannot be opened.

**How to fix:** add the secret that sealed the value to `previousSecrets`, then run `rotate-secrets` to re-seal
everything under the current secret ([secrets](/docs/operations/deployment/secrets)).

## INVALID_SESSION

OAuth consent was attempted with a credential that is not a person's signed-in session.

The OAuth provider's `completeInteraction` requires a user session, so API keys and temporary credentials cannot grant
consent on anyone's behalf.

**How to fix:** sign the person in to the client's organization and pass their session cookie or token
([OAuth provider](/docs/federation/oauth-provider)).

## INVALID_SPONSOR

The AI agent's sponsor is missing or is not an active person of the agent's tenant.

Every agent needs a sponsor, an active and unexpired person of the same tenant who answers for it. `agents.create`
makes the caller the sponsor only when the caller is a person in their own session, so an API key or a temporary
credential must name one with `sponsorId`. `agents.create` and `agents.update` refuse a sponsor who is a service
account or another agent, disabled, deleted, expired, or in another tenant.

**How to fix:** pass the `sponsorId` of an active member of the agent's tenant
([`agents.create`](/docs/reference/api/agents#create)).

## INVALID_TENANT_TREE

The organization's chain of parent tenants contains a cycle, so authentication refuses it.

Before sign-in and on every session use, the authentication service walks the tenant and its ancestors; a tenant that
is its own ancestor can only come from data changed outside Better IAM. The Next.js integration treats it as a
signed-out request.

**How to fix:** repair the tenants' `parentId` values (for example from a backup), then sign in again.

## INVALID_TICKET

The inference ticket given to `inference.record` is unknown, already used, expired, or its caller no longer exists.

An allowed [`inference.check`](/docs/reference/api/inference#check) returns a single-use ticket that is valid for one
hour and names the caller, their session, and the model. An external gateway redeems it once with the call's token
counts; a ticket of another tenant is refused too.

**How to fix:** meter each call once, within the hour, with the ticket its own check returned; when a ticket is lost,
the call cannot be metered through `record`, so check again before the next call.

## INVALID_TOKEN

The OAuth access token, or its DPoP proof, is missing, invalid, or expired.

Resource servers built with `createAccessTokenVerifier` or `createResourceGuard` refuse a missing or expired token, a
replayed or mismatched DPoP proof, and a sender-constrained token sent without its proof, and answer with a
`WWW-Authenticate` challenge naming `invalid_token`. The browser client also raises it, before sending, for a
configured bearer token with an invalid format.

**How to fix:** obtain a new access token (refresh it or sign in again) and send it with the right scheme
([resource servers](/docs/federation/oauth-resource-servers)).

## INVALID_TRANSITION

The record is not in a state that allows this step.

Examples: deciding or cancelling an access request, activation, or package request that is no longer pending;
activating a binding that is not eligible or that nobody can approve; re-enabling an expired identity or service
account before extending `expiresAt`; changing a deleted tenant or making a status change its lifecycle does not
allow; pinging or redelivering through a paused webhook; and ending a rule-based package assignment by hand.

**How to fix:** reload the record, check its current status, and take a step that status allows.

## INVARIANTS_BROKEN

`check-invariants --fail-on-broken` found invariants that are broken or cannot be evaluated.

The command prints the full run first, then fails so a CI job or scheduler notices.

**How to fix:** review the violations and errors in the output, then correct the access or the invariant
([access invariants](/docs/guides/governance/change-safety#access-invariants)).

## INVARIANT_VIOLATION

The change would break an enforced access invariant, so it was rolled back.

Access-changing operations (role, policy, binding, group, package, relationship, and configuration changes, among
others) re-evaluate the tenant's invariants in `enforce` mode inside their transaction. They refuse a change that
creates a new violation or makes an invariant impossible to evaluate (for example by deleting the group it names); the
message names the invariant and the person affected.

**How to fix:** preview the change with [`impact.preview`](/docs/reference/api/impact#preview), then adjust the
change or the invariant ([access invariants](/docs/guides/governance/change-safety#access-invariants)).

## INVITATION_INVALID

The invitation link is invalid, expired, already used, or revoked.

`tenants.acceptInvitation` and `identities.acceptInvitation` refuse a token that matches no open invitation, an
organization that is no longer pending, and an invitation whose inviter's grant authority was revoked after it was
sent.

**How to fix:** ask an administrator to send a new invitation with `tenants.resendInvitation` or
`identities.resendInvitation`.

## IP_BLOCKED

Requests from this network are blocked for the organization or for the whole platform.

Administrators block networks with `security.blockNetwork`. A blocked address is refused before any credential is
checked (so no rate-limit counter moves), and existing sessions from it stop working at their next use.

**How to fix:** connect from another network, or ask an administrator to lift the block with
`security.unblockNetwork` or wait for it to expire ([network blocks](/docs/guides/authentication/tenant-policy#network-blocks)).

## IP_NOT_ALLOWED

The organization only allows sign-in from certain networks, and this address is not one of them.

A tenant's `authPolicy.allowedIpRanges` is checked when a session is issued and on every later use, including role
sessions derived from it; requests without a known client address are not judged.

**How to fix:** connect from an allowed network (for example the company VPN), or ask an administrator to add the
range ([IP allowlist](/docs/guides/authentication/tenant-policy#ip-allowlist)).

## KEY_MANAGED

A key management key belongs to another module.

Keys a certificate authority signs with (`managedBy: 'pki'`) and keys a data protection profile encrypts with
(`managedBy: 'protection'`) are used only by that module. The keys API refuses to encrypt, decrypt, sign, generate
data keys or MACs with them, or grant them, so nobody can sign a certificate body or open a value the module did not
decide on. Binding such a key to another authority or profile is refused too.

**How to fix:** use a key of your own, or go through the module ([`pki.issueCertificate`](/docs/reference/api/pki#issuecertificate),
[`protection.detokenize`](/docs/reference/api/protection#detokenize)). The key can still be disabled or scheduled for
deletion, which stops the module.

## KEY_MATERIAL_UNAVAILABLE

A key management key's material, or a value it protects, could not be opened.

Key material is sealed under the deployment `secret`. This error means none of the configured secrets (`secret` and
`previousSecrets`) opens it: the secret that sealed it was removed before `iam.rotateSecrets()` re-sealed everything.
Data protection also reports a stored value that fails authentication (altered in storage) this way.

**How to fix:** put the old secret back in `previousSecrets`, run `iam.rotateSecrets()` until it reports `done`, and
only then remove it. A stored value that was altered cannot be recovered: restore it from a backup or delete the
token.

## KEY_STATE_INVALID

A key management key is not in a state that allows the call.

Cryptographic calls ([`keys.encrypt`](/docs/reference/api/keys#encrypt), `decrypt`, `sign`, `verify`, the MAC and
token calls) need an enabled key; a disabled key or a key pending deletion refuses them. State changes are refused
when they do not apply, such as enabling a key pending deletion or rotating a disabled one.

**How to fix:** [`enable`](/docs/reference/api/keys#enable) the key, or
[`cancelDeletion`](/docs/reference/api/keys#canceldeletion) first (the key then comes back disabled).

## LAST_AUTHENTICATOR

Deleting this passkey would leave the account with no way to sign in.

`auth.deletePasskey` refuses the last passkey when the account has no password and no verified email or phone that
the deployment's passwordless sign-in could use.

**How to fix:** add another sign-in method first (a password or a second passkey), then delete the old passkey.

## LAST_OWNER

The operation would leave the organization without an active owner.

Deleting, disabling, offboarding, or setting an expiry on the last active owner, or removing their owner flag with
`identities.setOwner`, is refused.

**How to fix:** make someone else an owner with [`identities.setOwner`](/docs/reference/api/identities#setowner)
first, then retry.

## LAST_ROOT_ADMIN

The operation would leave the platform without an active root administrator.

Deleting, disabling, or offboarding the last root administrator, or removing their root flag with
`root.setAdministrator`, is refused so the platform always keeps a way in.

**How to fix:** grant root to another person with [`root.setAdministrator`](/docs/reference/api/root#setadministrator)
first.

## LDAP_BASE_TAKEN

Another organization of this deployment already publishes its LDAP directory under this base DN.

The LDAP gateway finds the organization of a bind or search by its base DN, so each base DN belongs to one
organization.

**How to fix:** choose a base DN of your own, such as your domain (`dc=acme,dc=com`).

## LEGAL_HOLD

The person or subject is under a legal hold, so they cannot be erased or deleted.

A [legal hold](/docs/reference/api/privacy#placehold) keeps a subject's data while litigation or an investigation
needs it. While it is live, fulfilling an erasure request is refused, and so is every deletion of the person's
account, because identity deletion checks for holds itself: both `identities.delete` and an erasure request stop
here. Offboarding and SCIM deprovisioning only disable an account, so they still work and keep the data.

**How to fix:** release the hold with [`privacy.releaseHold`](/docs/reference/api/privacy#releasehold) once it is no
longer needed, or wait for its `expiresAt`. To refuse an erasure request because the data must be kept, reject it with
reason `exempt` ([privacy guide](/docs/guides/governance/privacy#legal-holds)).

## LIMIT_EXCEEDED

The tenant has reached a limit on how many of these records it may have.

Root administrators set plan limits per tenant with `tenants.setLimits` (members, service accounts, groups, roles,
policies, registered resources, and webhooks), and every creation path checks them, including invitations, sign-up,
federation, and SCIM. Fixed caps also apply: 50 webhooks, 50 agreements, and 100 invariants per tenant, and 5,000
bindings per certification campaign.

**How to fix:** remove records you no longer need, ask the platform operator to raise the limit, or narrow the
campaign by role or subject type; `tenants.usage` shows the current counts.

## LINKING_DISABLED

Account linking is turned off on this deployment.

`links.create`, and accepting an organization invitation with a link to an existing account, need
`onboarding: { mode: 'linked' }` in the server options.

**How to fix:** enable linked onboarding in your [configuration](/docs/operations/deployment/configuration), or
accept the invitation without linking.

## MAX_DEPTH

Creating or moving this tenant would make the hierarchy deeper than allowed.

`tenants.create` and `tenants.reparent` enforce `hierarchy.maxDepth`, eight levels by default.

**How to fix:** attach the tenant higher in the tree, or raise `maxDepth` in your configuration if deeper nesting is
intended.

## METER_ARCHIVED

The billing meter is archived and accepts no new usage.

Archiving (`billing.updateMeter` with `archived: true`) keeps a meter's history and prices but stops `billing.record`
and `iam.billing.record` from adding to it.

**How to fix:** record on the meter that replaced it, or restore the meter with `archived: false`
([billing](/docs/reference/api/billing)).

## METHOD_NOT_ALLOWED

The organization does not permit this sign-in method, or the HTTP method is not supported on this route.

With status 403 it comes from a tenant's `authPolicy.allowedMethods`, for example a tenant that allows only federated
sign-in refusing a password. With status 405 an API, SCIM, or webhook route was called with an unsupported HTTP
method; API calls are `POST`.

**How to fix:** offer the person a method the organization allows
([restricting sign-in methods](/docs/guides/authentication/tenant-policy#restricting-sign-in-methods)), or send the
request as `POST`.

## MFA_ALREADY_ENABLED

The person already has an authenticator app enrolled.

`auth.beginMfa` starts a new authenticator enrollment only when none is active.

**How to fix:** to replace the authenticator, disable MFA with `auth.disableMfa` where the tenant allows it, then
enroll again ([managing factors](/docs/guides/authentication/mfa#managing-factors)).

## MFA_NOT_ENROLLED

The operation needs a second factor, but the person has not enrolled one.

`auth.verifyMfa` refuses a code when the person has no authenticator app and no emailed code was requested for
this sign-in. Regenerating recovery codes, and an MFA step-up on an existing credential (such as a temporary
credential requested with an MFA code), need an enrolled authenticator app.

**How to fix:** enroll a factor first with `auth.beginMfa` and `auth.confirmMfa`
([MFA](/docs/guides/authentication/mfa)).

## MFA_REQUIRED

The session has not completed multi-factor authentication, and this action or organization requires it.

It is raised when the deployment or tenant requires MFA and a session without it is issued or used (for example after
the organization turned the requirement on), when activating an eligible role whose rules require an MFA-verified
session, when disabling MFA or regenerating recovery codes, when impersonating a member who needs MFA, and by
framework step-up guards.

**How to fix:** send the person through the second-factor step and retry; framework integrations treat it as a
signed-out request ([step-up](/docs/guides/authentication/mfa#step-up)).

## MISSING_ENV

A CLI command needs an environment variable that is not set.

Commands that act as a member (`config-export`, `config-plan`, `config-apply`, `analyze`, `report`,
`check-invariants`, `mine-roles`) read a session token or API key from `BETTER_IAM_TOKEN`; `bootstrap` and
`recover-root` read `BETTER_IAM_ROOT_EMAIL` and `BETTER_IAM_ROOT_PASSWORD`. Secrets never go on the command line.

**How to fix:** export the variable the message names and run the command again.

## NOT_FOUND

The record does not exist in this tenant.

Better IAM also answers 404 for records that belong to another tenant, so responses never reveal what exists
elsewhere. Deleted identities, unregistered managed resources, unknown routes, and the public `tenants.lookup` and
`domains.discover` calls for unknown or inactive organizations answer the same way.

**How to fix:** check the id and the `tenantId` you passed, and refresh lists that may be stale.

## NOT_INITIALIZED

Root recovery was attempted before the platform was bootstrapped.

[`recoverRoot`](/docs/reference/api#recoverroot) and `better-iam recover-root` add a root administrator to the
existing root tenant, so one must exist.

**How to fix:** run `bootstrap` first ([recovering root access](/docs/guides/authentication/recovery#recovering-root-access)).

## NAME_NOT_PERMITTED

A certificate would name something its authority may not certify.

Every name on a certificate must fit the name constraints (`permitted`) of the issuing authority and every authority
above it, and a SPIFFE ID must be in the authority's trust domain. This holds for everyone, owners and root
administrators included.

**How to fix:** request names within the constraints, or issue from an authority whose constraints cover them.

## NO_AUDIT_ARCHIVE

Audit archiving was requested, but no archive destination is configured.

[`archiveAudit`](/docs/reference/api#archiveaudit) and the `audit-archive` command need the `auditArchive` option, for
example `createJsonlAuditArchive({ directory })`.

**How to fix:** configure an archive sink ([continuous audit archiving](/docs/operations/jobs#continuous-audit-archiving)).

## OAUTH_CALLBACK

The OAuth sign-in callback arrived at a URL that does not match the connection's redirect URI.

The callback's origin and path must equal the connection's `redirectUri`, so a response meant for another route is
never accepted.

**How to fix:** make the redirect URI registered with the provider, the connection's `redirectUri`, and the route
that handles the callback identical ([OAuth sign-in](/docs/federation/oauth-sign-in)).

## OAUTH_CLIENT

The OAuth client is unknown, revoked, or belongs to an organization that is not active.

When Better IAM acts as an OAuth provider, it refuses authorization, consent, and client changes for such clients.

**How to fix:** check the `client_id`, register a new client if it was revoked, or reactivate the organization
([OAuth provider](/docs/federation/oauth-provider)).

## OAUTH_DISCOVERY

The Microsoft Entra ID metadata for a sign-in connection could not be fetched or is not trustworthy.

Before a Microsoft sign-in, Better IAM downloads the directory's OpenID configuration and checks that the issuer and
every endpoint belong to the expected authority; a network failure or unexpected metadata stops the sign-in.

**How to fix:** retry later if Microsoft was unreachable; otherwise check the connection's directory settings
([Microsoft Entra ID](/docs/federation/oauth-sign-in#microsoft-entra-id)).

## OAUTH_PROFILE

The identity provider's answer did not identify the person.

The sign-in fails when the profile request fails or returns something unusable, when the profile or OIDC ID token
names no subject, or when a Microsoft ID token names no directory.

**How to fix:** retry the sign-in; if it keeps failing, check the connection's provider settings, scopes, and any
`mapProfile` function ([providers](/docs/federation/oauth-sign-in#providers)).

## OAUTH_STATE

The OAuth sign-in could not be matched to the browser that started it.

The callback needs the `state` parameter and the browser-binding cookie set when the sign-in began. State that is
missing, expired (after ten minutes), already used, or from another browser is refused, which blocks login CSRF and
replayed callbacks.

**How to fix:** start the sign-in again in the same browser, and check that the binding cookie reaches the callback
route.

## OAUTH_TENANT

The person's Microsoft directory is not allowed to sign in through this connection.

A Microsoft connection with `allowedMicrosoftTenants` accepts ID tokens only from those directory ids.

**How to fix:** add the directory id to the connection's list if it should be accepted, or sign in with an account
from an allowed directory.

## OWNER_INACTIVE

The owner of a lifecycle workflow run is no longer active, so the run cannot go on.

A workflow run uses the rights of the workflow's owner when it started (or of whoever last retried it), and every
step checks first that this owner is still active and unexpired. A step reached after the owner was disabled,
offboarded, deleted, or passed their `expiresAt` fails its run with this code (recorded on the run and as
`workflow:run:fail`); no call returns it. New runs fail the same way until someone takes the workflow over.

**How to fix:** an administrator who holds the steps' permissions retries the failed runs with
[`workflows.retryRun`](/docs/reference/api/workflows#retryrun), which makes them the runs' owner, or cancels them,
and saves the workflow with [`workflows.update`](/docs/reference/api/workflows#update) so new runs start with an
active owner ([lifecycle workflows](/docs/guides/governance/workflows#authority)).

## PASSKEY_EXISTS

This passkey is already registered.

A passkey credential can be registered once for this relying party, even across organizations.

**How to fix:** sign in with the existing passkey, or create a new passkey on the device and register that one.

## PASSWORD_CHECK_UNAVAILABLE

The breached-password service could not be reached, and the deployment refuses passwords it cannot check.

`pwnedPasswords({ failClosed: true })` rejects a new password when the breach lookup fails or times out; without
`failClosed`, the password is accepted instead.

**How to fix:** retry shortly; if it persists, check the server's outbound network access
([password screening](/docs/guides/authentication/sign-in-methods#password-screening)).

## PASSWORD_EXPIRED

The password is correct but older than the organization's maximum password age.

A tenant's `authPolicy.passwordMaxAgeDays` makes sign-in refuse a password that was not changed within that many
days.

**How to fix:** send the person through password reset (`auth.requestPasswordReset`, then `auth.resetPassword`)
([password reset](/docs/guides/authentication/recovery#password-reset)).

## PASSWORD_REUSED

The new password matches one of the person's recent passwords.

A tenant's `authPolicy.passwordHistory` refuses the last that many passwords when a password is changed or reset.

**How to fix:** ask the person to choose a password they have not used recently
([password rules](/docs/guides/authentication/tenant-policy#password-rules)).

## PAYLOAD_TOO_LARGE

The request body is larger than the endpoint accepts.

API calls and the SCIM administration handler accept up to 64 KiB of JSON, and the Next.js webhook handler accepts
1 MiB by default.

**How to fix:** send less per call, for example by splitting a batch into several requests.

## PHONE_EXISTS

Another person in this organization has already verified this phone number.

`auth.confirmPhoneVerification` keeps verified phone numbers unique within a tenant, so SMS codes and SMS sign-in
reach exactly one account.

**How to fix:** verify a different number.

## PROTECTED_IDENTITY

A root administrator cannot be linked during organization onboarding.

Accepting an organization invitation with linked onboarding refuses a link credential that belongs to a root
administrator, so platform identities stay separate from customer organizations.

**How to fix:** accept the invitation without linking, or link an ordinary account.

## PROTECTED_OPERATION

An OAuth client was about to be stored outside the authenticated registration path.

Better IAM's OAuth provider stores clients only through `issuer.registerClient()`, which checks the caller's
permission, or through a dynamic registration admitted for the same tenant; any other attempt to write a client is
refused.

**How to fix:** register clients with `registerClient` ([OAuth provider](/docs/federation/oauth-provider)).

## PROTECTED_RESOURCE

The target is a protected owner role or policy, or belongs to a higher grant authority, and cannot be changed this way.

Owner roles cannot be requested, approved, bound, packaged, inherited, or assumed through trust, and protected roles
and the owner policy cannot be edited or deleted; ownership moves only through
[`identities.setOwner`](/docs/reference/api/identities#setowner). Roles and policies created under a superior
authority can be edited only by that authority. Lifecycle workflows fail a run with it when a step that takes access
away, or sets attributes or an expiry, reaches an owner or a root administrator: workflows never disable, delete, sign
out, strip, or edit them.

**How to fix:** use owner transfer for ownership, and ask the administrator whose authority created the role or
policy to make the change.

## QUOTA_EXCEEDED

The caller's usage plan does not allow this much use of the meter right now.

`iam.quotas.enforce` refuses a call that would go over the plan's throttle (its token bucket is empty) or one of its
period limits (the day's or month's allowance is spent), counting nothing. The error carries `retryAfterMs`, when the
bucket has refilled enough or the window starts over, and the HTTP response a `Retry-After` header. It has no
`retryAfterMs` when the call's cost is larger than the plan could ever allow. The plan that applies is the one assigned
to the API key, the agent, the person or one of their groups, else the organization's default plan for the meter
([`quotas`](/docs/reference/api/quotas)).

**How to fix:** wait for `Retry-After` and retry; show the caller their allowance with
[`quotas.status`](/docs/reference/api/quotas#status), or have an administrator assign a larger plan with
[`quotas.assign`](/docs/reference/api/quotas#assign).

## RATE_LIMITED

There were too many attempts in a short time, so the caller must wait before trying again.

Sign-in, sign-up, recovery, verification, and MFA flows count attempts per person (and per client IP when
`ipAttempts` is set) within a window from `authentication.rateLimits`, 15 minutes by default, which a tenant's
`authPolicy.maxAttempts` can tighten. The error carries `retryAfterMs`, the window length and so the longest you may
need to wait, and the HTTP response a `Retry-After` header.

**How to fix:** wait and tell the person when to try again; an administrator can clear a locked-out person's
counters with `identities.unlock`
([failed attempts and lockouts](/docs/guides/authentication/sign-in-methods#failed-attempts-and-lockouts)).

## RECENT_AUTH_REQUIRED

The operation is sensitive, and the session was not authenticated recently enough.

Password, email, factor, session, credential, ownership, and policy changes, impersonation, and similar operations
need a session established within `authentication.recentAuthenticationMs` (five minutes by default). Temporary
credentials such as assumed-role sessions and session tokens never qualify, and OAuth or SAML account linking needs a
sign-in within the last five minutes.

**How to fix:** reauthenticate (for example `auth.reauthenticate` with the password, completing MFA if asked) and
retry ([recent authentication](/docs/guides/authentication/sessions#recent-authentication)).

## RECONCILE_ATTENTION

`reconcile --fail-on-attention` found access-package rules that need attention.

The count covers package rules that failed or were suspended, runs stopped by the safety brake until someone confirms
them, and tenants that could not be processed; the full result is printed first.

**How to fix:** review the listed packages, fix their rules, and confirm braked changes with
`reconcile --tenant ID --package ID --confirm`
([automatic assignment](/docs/guides/privileged-access/automatic-assignment)).

## RESOURCE_IN_USE

The record is still referenced by other records, so it cannot be deleted or changed this way.

Examples: a role that other roles inherit or packages include, a policy still attached to a role, a group that
packages grant or that approves requests, a resource type with registered resources, relationships, or child types, a
resource with child resources, a package that is still assigned, and an action still used by policies and roles.

**How to fix:** remove or repoint the references the message names, then retry.

## RESOURCE_MISMATCH

Your `resolveResource` callback returned nothing, or a resource that does not match the one being authorized.

For application resource types, Better IAM asks your callback for the resource and requires the returned `tenantId`,
`type`, and `id` to equal the request's, so a faulty lookup can never authorize one tenant's request with another
tenant's record. The request is refused instead.

**How to fix:** return exactly the requested resource from `resolveResource`
([resources and catalog](/docs/guides/concepts/resources-and-catalog)).

## RESOURCE_RESOLVER_REQUIRED

An authorization check names an application resource type, but no `resolveResource` callback is configured.

Managed resource types are registered with IAM and read from its storage; for every other type Better IAM needs your
`resolveResource` option to load the resource and its attributes.

**How to fix:** configure `resolveResource`, or declare the type as managed and register its resources with
`resources.register` ([resources and catalog](/docs/guides/concepts/resources-and-catalog)).

## ROLE_CHAINING_DISABLED

A role cannot be assumed from a session that is itself an assumed role.

`roles.assume` refuses role sessions as the source, so temporary access can never be extended by chaining one role
into another. A session token from `sts.getSessionToken` is accepted as a source, because it is the same identity with
the same or fewer grants.

**How to fix:** assume the role from the original user session or API key
([assumed roles](/docs/guides/authentication/sign-in-methods#assumed-roles)).

## ROLLBACK

A deliberate signal inside the storage conformance suite that discards a test transaction.

The suite throws it to prove that an adapter rolls back uncommitted writes; the API never returns it.

**How to fix:** nothing, unless a conformance check around it fails, which means your adapter did not roll the
transaction back as required ([conformance suite](/docs/operations/extensions#conformance-suite)).

## ROOT_SSH_RESTRICTED

A platform root administrator asked for an SSH certificate into another organization.

The root override never opens an organization's servers: SSH access there needs a role in that organization, like
anyone else's. Only the root tenant's own hosts are the root administrators'.

**How to fix:** grant the person `ssh:login` through a role in the organization.

## ROTATION_FAILED

A vault secret's rotator failed to apply the new value.

[`vault.rotate`](/docs/reference/api/vault#rotate) (and the scheduled `iam.vault.rotateDue`) stage a new version
as `pending` and call the secret's rotator to apply it to the system it unlocks; the rotator threw or timed out. The
current version stays current and the pending one is kept, so the next attempt passes the rotator the same value. The
error is recorded on the secret (`rotation.lastFailure`, with secret values redacted) and in a `vault:rotate`
audit event with outcome `deny`; scheduled retries back off from one hour to a day.

**How to fix:** fix what the rotator reported, then rotate again. Rotators must be idempotent.

## SAME_DATABASE

The source and target of a store copy are the same database.

`store-copy` and `copyStore` would otherwise read and overwrite one database in the same run.

**How to fix:** point `--target-config` at the configuration of a different, empty database
([snapshots](/docs/operations/storage#snapshots-and-moving-between-databases)).

## SAML_INVALID

The SAML response could not be accepted.

Better IAM rejects responses that are unsafe or malformed XML, fail the signature, issuer, audience, destination,
recipient, or age checks, were already used, are unsolicited when the connection does not allow IdP-initiated
sign-in, or lack a required encrypted assertion. The assertion consumer service answers every such failure the same
way, so an attacker learns nothing from it.

**How to fix:** start the sign-in again from your application; if it keeps failing, compare the identity provider's
settings (entity ID, ACS URL, certificates, encryption) with the connection ([SAML](/docs/federation/saml)).

## SCHEMA_VERSION

The database was created by an incompatible version of Better IAM.

The SQL adapters record a schema version and refuse to run against a database whose version they do not support.

**How to fix:** run the Better IAM version that created the database, or restore a backup made for this version
([database operations](/docs/operations/deployment/database)).

## SECRET_CHECKED_OUT

Someone already holds an exclusive check-out of this vault secret, or you hold one yourself.

An exclusive check-out policy hands a shared credential to one holder at a time; a caller who already holds a
check-out of the secret gets this code too rather than a second check-out.

**How to fix:** wait until the holder checks it in or the check-out expires (`vault.get` shows the holder and when),
renew your own with [`renewLease`](/docs/reference/api/vault#renewlease), or have an administrator end the other
check-out with [`revokeLease`](/docs/reference/api/vault#revokelease).

## SECRET_PENDING_DELETION

The vault secret is scheduled for deletion, so it cannot be read, changed, or leased.

[`vault.delete`](/docs/reference/api/vault#delete) keeps a secret for a recovery window of 7 to 30 days before
`iam.vault.purgeDeleted` removes it; meanwhile only `get`, `restore`, and an immediate `delete` work, and the
name stays taken.

**How to fix:** [`restore`](/docs/reference/api/vault#restore) the secret if it is still needed.

## SECURITY_KEY_REQUIRED

The organization only certifies hardware security keys for SSH.

With `requireSecurityKey` in the SSH settings, `ssh.issueCertificate` accepts only FIDO keys
(`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`).

**How to fix:** create one with `ssh-keygen -t ed25519-sk` and request the certificate for it.

## SELF_REVIEW

A reviewer tried to certify their own access in an access review.

Certification campaigns refuse a reviewer's decision on an item that grants the reviewer access, directly or through
one of their groups.

**How to fix:** leave the item to another reviewer of the campaign
([certifications](/docs/guides/governance/certifications)).

## SESSION_EXPIRING

The session asking for an SSH certificate ends within a minute.

A certificate never outlives the session that requested it.

**How to fix:** sign in again, then request the certificate.

## SESSION_NETWORK_MISMATCH

The session is bound to the network it was signed in from and was used from a different one.

A tenant's `authPolicy.bindSessionsToIp` makes a user session usable only from the client IP it was issued from, so a
stolen session cookie or token does not work elsewhere; the refused attempt is recorded. Requests without a recorded
client IP are not judged.

**How to fix:** sign in again from the current network; the browser client calls its `onUnauthenticated` hook for
this code ([binding sessions to their network](/docs/guides/authentication/tenant-policy#binding-sessions-to-their-network)).

## SIGNAL_REJECTED

The Shared Signals receiver refused a security event token.

`iam.signals.receive` throws it as a `SignalRejectedError` whose `err` is the RFC 8935 error code: `invalid_key` (a
key, algorithm, or signature problem), `invalid_issuer`, `invalid_audience`, or `invalid_request` (the token type, its
age, its claims, its subject, or its size). The message says which check failed. The push endpoint answers the same
refusal as `400` with `{ "err", "description" }`, and polling reports it to the provider in `setErrs`, so providers
never see this code itself. `temporary: true` means the source's keys could not be fetched: the same token may pass
later, so pushes answer `503` and polled events stay unacknowledged.

**How to fix:** compare the token with the source (`signals.getSource` shows the refusal as `lastError`): its issuer
and aliases, audiences, keys, algorithms, and `requireTyp`, then fix the source with `signals.updateSource` or the
provider's configuration ([verification](/docs/reference/api/signals#verification)). A temporary refusal needs no
change once the provider's key set is reachable again.

## SLUG_TAKEN

Another organization already uses this slug.

Slugs are globally unique aliases that sign-in screens use to find an organization; `tenants.create`,
`tenants.setSlug`, and `bootstrap` claim them.

**How to fix:** choose a different slug.

## SNAPSHOT_INVALID

The file given to `store-import` is not a valid Better IAM snapshot.

Every line must be a JSON object: a header naming the snapshot format and version, one record per line, and a trailer
with counts. An unsupported version or content after the trailer is refused, and nothing is imported.

**How to fix:** import a file written by `store-export`, unmodified
([snapshots](/docs/operations/storage#snapshots-and-moving-between-databases)).

## SNAPSHOT_TRUNCATED

The snapshot ended early, or its record counts do not match its trailer.

`store-import` checks the trailer that `store-export` writes last; a missing trailer or a count mismatch means the
file was cut off or edited, so nothing is imported.

**How to fix:** export the snapshot again and copy it completely
([snapshots](/docs/operations/storage#snapshots-and-moving-between-databases)).

## SOD_CONFLICT

The change would give one person a combination of roles that a separation-of-duties rule forbids.

Operations that grant roles (bindings, group membership, identity creation, access-request and package approvals,
package assignments, and configuration apply) check the tenant's `prevent` rules inside their transaction and roll
back when they create a new conflict. Conflicts that already existed never block unrelated work.

**How to fix:** remove one of the conflicting roles from the person first, or grant a different role
([separation of duties](/docs/guides/authorization/separation-of-duties)).

## SOURCE_ADDRESS_UNKNOWN

The organization binds SSH certificates to the caller's address, and the server could not determine it.

With `bindSourceAddress`, every certificate carries a `source-address` option with the IP it was requested from. The
IP comes from `http.clientInfo`, which must be configured to read it (behind a proxy you trust).

**How to fix:** configure `http.clientInfo` to return `ip`, or turn `bindSourceAddress` off.

## SPEND_LIMIT_REACHED

An enforced spend budget that covers this usage is already spent (status 402).

`billing.record` and `iam.billing.record` with `enforceBudgets: true` check the enforced budgets that cover the usage:
tenant budgets up the tree, the person's own, and their teams' and department's. Budget standings may lag recorded
usage by up to 30 seconds.

**How to fix:** raise or disable the budget (`billing.updateBudget`), wait for the next budget window, or ask the
budget's owners; `billing.check` tells callers in advance ([billing](/docs/reference/api/billing)).

## SSH_NOT_CONFIGURED

The organization has no SSH certificate authority yet.

**How to fix:** create the authorities with [`ssh.setup`](/docs/reference/api/ssh#setup) (before registering hosts).

## STORAGE_BUSY

The database was too busy to complete the operation in time.

Lock timeouts, serialization failures, deadlocks, cancelled statements, and busy or locked SQLite files are reported
with this code, and the whole transaction is rolled back.

**How to fix:** retry the complete operation after a short pause; if it happens often, raise `lockTimeoutMs`
(PostgreSQL) or `busyTimeoutMs` (SQLite, libSQL), or shorten long transactions such as large imports
([storage adapters](/docs/operations/storage)).

## STORAGE_CORRUPT

A stored record could not be decoded.

The adapters refuse rows whose JSON or escaped values are invalid, or whose columns disagree with the record's own
id, tenant, or key, which points to data changed outside Better IAM or damaged storage.

**How to fix:** restore the affected data from a backup and find what wrote to the IAM tables directly
([database operations](/docs/operations/deployment/database)).

## STORAGE_ERROR

A database operation failed for a reason other than a conflict or a busy database.

Adapters map driver errors to this code with a generic message, so SQL text and record data never reach responses;
lost connections, missing tables, and full disks end up here.

**How to fix:** check the database's own logs and connectivity, and run `better-iam migrate` if the schema may be
missing ([database operations](/docs/operations/deployment/database)).

## STORE_CLOSED

The storage adapter was used after it was closed.

After `close()`, every read and transaction is refused; usually shutdown code closed the store while requests or jobs
were still running.

**How to fix:** close the store only after in-flight work finishes, and create a new adapter if you need the database
again.

## STORE_NOT_EMPTY

The target database of an import or copy already holds records.

`store-import` and `store-copy` load a whole deployment in one transaction, and only into an empty, migrated database,
so two deployments never mix.

**How to fix:** point the target configuration at a new, empty database
([snapshots](/docs/operations/storage#snapshots-and-moving-between-databases)).

## TEAM_MANAGED

The group belongs to a team, and its members come from the team.

Every team owns a backing group (`team:{slug}`) holding the members of the team and of the teams below it. Only the
[`teams`](/docs/reference/api/teams) API changes who is in it: `groups.addMember`, `groups.updateMember`,
`groups.removeMember`, and `groups.delete` refuse it, and access packages, invitations, and onboarding flows cannot
name it. Lifecycle workflow group steps cannot name it either.

**How to fix:** add or remove people with `teams.addMember` / `teams.removeMember`, or delete the team with
`teams.delete`. Binding roles to the backing group with `bindings.create` is how a team gets access, and is allowed.

## TENANT_INACTIVE

The organization, or one of its parent tenants, is suspended, pending, or deleted.

Every API call re-checks the caller's tenant ancestry, so suspending an organization stops its sessions at their next
request. Creating identities or invitations, opening access requests, moving a tenant under an inactive parent, and
the OAuth, SAML, SCIM, and shared-signals endpoints refuse inactive tenants too; framework integrations treat it as a
signed-out request.

**How to fix:** reactivate the organization and its parents with `tenants.setStatus`, or finish onboarding a pending
one.

## TENANT_MISMATCH

The signed-in person belongs to a different organization than the OAuth client asking for consent.

The OAuth provider's `completeInteraction` accepts consent only from a user session in the client's tenant.

**How to fix:** sign the person in to the client's organization before the consent step
([OAuth provider](/docs/federation/oauth-provider)).

## TENANT_NOT_FOUND

An identity was about to be created in a tenant that does not exist.

It is a safety check inside the low-level identity creation that sign-up, invitations, federation, and root recovery
share. Those flows check the tenant first and normally answer `TENANT_UNAVAILABLE` or `NOT_FOUND` instead.

**How to fix:** check the `tenantId` you passed.

## TENANT_UNAVAILABLE

The organization is not active, so nobody can sign in to it.

Authentication checks the tenant and every ancestor before sign-in, sign-up, and recovery and on every session use; a
missing, suspended, pending, or deleted tenant anywhere in the chain is refused. Framework integrations treat it as a
signed-out request.

**How to fix:** check that the person chose the right organization, and ask the platform operator to reactivate it
if it was suspended.

## TOO_MANY_HOSTS

An SSH certificate would name more hosts or principals than allowed.

One certificate names at most `ssh.maxHostsPerCertificate` hosts (64 by default) and 256 principals.

**How to fix:** name the hosts you need with `hosts` (and `logins`) in
[`ssh.issueCertificate`](/docs/reference/api/ssh#issuecertificate).

## TOO_MANY_REQUESTS

The person already has too many pending access requests.

`accessRequests.create` allows 20 open requests per requester so reviewers are not flooded. Unlike `RATE_LIMITED`,
waiting alone does not help.

**How to fix:** wait for pending requests to be decided, or cancel ones no longer needed with
[`accessRequests.cancel`](/docs/reference/api/access-requests#cancel), then open the new one.

## TRANSACTION_ABORTED

A database operation failed inside a transaction, so the whole transaction was rolled back.

Once a statement fails, the adapters mark the transaction as doomed: catching the error and continuing does not save
it, and the transaction ends with this code instead of committing partial work. You meet it in plugins or custom code
that swallow storage errors inside a transaction.

**How to fix:** let storage errors propagate, or check for the condition before writing
([adapter contract](/docs/operations/extensions#rules-every-adapter-must-keep)).

## TRANSACTION_ACTIVE

A storage adapter was closed from inside one of its own transactions.

**How to fix:** close the store only after the transaction's callback has returned, typically at process shutdown.

## TRANSACTION_CLOSED

A transaction handle was used after its transaction finished.

The `tx` store passed to a transaction callback is valid only until the callback settles; keeping it for later, or
not awaiting work started inside the callback, leads here.

**How to fix:** await every storage call inside the callback, and never keep `tx` beyond it.

## TRANSACTION_REQUIRED

A write was attempted outside a transaction.

Every `insert`, `put`, and `delete` must run inside `store.transaction()`, so writes are serialized and related changes
commit together.

**How to fix:** wrap the writes in `store.transaction(async (tx) => { ... })` and write through `tx`
([adapter contract](/docs/operations/extensions#rules-every-adapter-must-keep)).

## TYPE_DISABLED

The credential type is disabled.

Disabled types issue no new credentials and are left out of the issuer metadata. Credentials issued earlier are not
affected.

**How to fix:** enable the type with [`verifiableCredentials.updateType`](/docs/reference/api/verifiable-credentials#updatetype).

## UNAUTHENTICATED

The request has no valid credential, or its credential has expired or been revoked.

It covers a missing or malformed session cookie or bearer token, an expired or idle session, a revoked session or API
key, a disabled or expired identity, a role session or session token whose source was revoked, and an impersonation
session whose administrator's session ended.

**How to fix:** send the person to sign in again; the browser client calls its `onUnauthenticated` hook for this
code, and framework integrations treat the request as signed out ([sessions](/docs/guides/authentication/sessions)).

## UNREADABLE_SECRETS

`rotate-secrets` found stored values that none of the configured secrets can open.

The command re-seals values encrypted with `previousSecrets` under the current `secret` and reports any it cannot
open, which means the secret that sealed them is missing from the configuration.

**How to fix:** add that secret to `previousSecrets` and run the command again; keep old secrets until it passes
([secrets](/docs/operations/deployment/secrets)).

## UNSUPPORTED

The storage adapter cannot list its collections, which a snapshot or copy needs.

`store-export`, `store-copy`, and `exportStore` and `copyStore` in code discover what to copy with the store's
`collections()` method, which a custom adapter may not implement.

**How to fix:** implement `collections()` in the adapter, or pass the collections to copy explicitly to `exportStore`
or `copyStore` ([optional adapter methods](/docs/operations/extensions#optional-methods)).

## UNSUPPORTED_FILTER

A query plan's filter uses a condition the chosen target cannot express.

[`iam.planResources`](/docs/reference/api#planresources) returns a filter with the policy engine's full
semantics; `filterToSql` has no equivalent for IP address and array conditions, and `filterToPrisma` and
`filterToMongo` lack some of dates, IP addresses, and wildcard patterns that are not a prefix, suffix or substring.
Compiling refuses rather than returning a filter that would include or leave out the wrong rows.

**How to fix:** fetch candidate rows with a coarser query and keep those that pass `filterMatches(plan.filter, row)`,
which supports every filter exactly, or check each row with `authorize`
([filters](/docs/reference/api/filters)).

## UNTRUSTED_ORIGIN

The request came from a browser origin that the deployment does not trust.

A request with an `Origin` header must name an exact origin from `trustedOrigins` (the origin of `baseURL` is always
included); the Next.js and middleware integrations apply the same rule to cookie requests on your routes.

**How to fix:** add the origin (scheme, host, and port) to `trustedOrigins` in your
[configuration](/docs/operations/deployment/configuration).

## VERIFIED_EMAIL_REQUIRED

A first sign-in through an external provider did not come with a verified email address.

Enrolling a new account from an OAuth, OpenID Connect, or SAML sign-in needs an email the provider asserts as verified,
because the account is created with that email already verified.

**How to fix:** have the person verify their email at the provider, or configure the connection to release a
verified email; a person with an existing account can link the provider to it instead
([first sign-in](/docs/federation/oauth-sign-in#first-sign-in-and-account-linking)).

## VERSION_CONFLICT

The record changed since you read it, so your change or acceptance was refused.

`policies.update` takes the `version` you edited and refuses it when someone saved a newer one, so edits never
overwrite each other. `agreements.accept` refuses a version that is no longer current, so nobody accepts terms they
have not seen.

**How to fix:** reload the record, show the current version, and let the person decide or accept again.

## VERSION_DESTROYED

The version's value was destroyed (HTTP 410 Gone).

[`vault.destroyVersion`](/docs/reference/api/vault#destroyversion) erases a version's value for good and keeps its
record as history, so it can never be revealed or made current again.

**How to fix:** use another version; `vault.listVersions` lists them with their state.

## VERSION_DISABLED

The version is disabled, so it cannot be revealed or made current.

[`vault.setVersionState`](/docs/reference/api/vault#setversionstate) disables a version without erasing it, for
example while an old credential is being retired.

**How to fix:** enable it again with `setVersionState`, or use another version.

## WEAK_PASSWORD

The new password does not meet the password rules.

Every password needs at least 12 characters. A tenant can add a longer minimum, required character classes, and a
ban on the person's name or email; the built-in screen refuses common and keyboard-pattern passwords; and a custom
`passwordPolicy.check` can add its own rule and message.

**How to fix:** show the message next to the password field and let the person choose a stronger password
([password rules](/docs/guides/authentication/tenant-policy#password-rules)).

## WEAK_TRUST_CONDITIONS

A web-identity trust must name exactly which workload may use it, and these conditions do not.

Web-identity federation lets tokens from an OpenID Connect provider, such as a CI platform, be exchanged for a role
session. Its trust conditions must pin the token's subject with a `StringEquals` or `StringLike` entry on `token.sub`
whose values are nonempty and do not start with a wildcard; otherwise every workload the provider issues tokens for
could assume the role.

**How to fix:** add a `token.sub` condition naming the specific subject, for example one repository and branch
([web-identity federation](/docs/operations/deployment/configuration#web-identity-federation)).

## WEBHOOK_REJECTED

A webhook endpoint answered a delivery with a non-success HTTP status.

Deliveries run from the outbox, so this code never reaches the call that caused the event: it is recorded as the
delivery's last error, and the delivery is retried with growing delays until its attempts run out.

**How to fix:** make the endpoint return a 2xx status, read the recorded error with `webhooks.listDeliveries`, and
use `webhooks.redeliver` once it is fixed ([retries](/docs/guides/events/webhooks#retries)).

## WEB_IDENTITY_REJECTED

The external token was not accepted by `sts.assumeRoleWithWebIdentity`, for a reason the response deliberately does
not name.

The public exchange answers every refusal that depends on stored state or on the token with this same 403 body: an
unknown or revoked trust, a disabled provider, a bad signature, issuer, audience, type, or lifetime, a token that is
expired or too old, unmet trust conditions, a missing source identity claim, a token already redeemed, an inactive
service account, a revoked authority, or an inactive tenant. Keeping them identical stops callers from discovering
which trusts, roles, and providers exist.

**How to fix:** an administrator runs [`trust.evaluateWebIdentity`](/docs/reference/api/trust#evaluatewebidentity)
with the same token, which reports the reason and each failing condition, and checks the audit log for
`role:assumed-with-web-identity` denials, whose metadata carries the reason.

## WRONG_REGION

The organization is served by another region's deployment (HTTP 421 Misdirected Request).

In a multi-region deployment (`regions`), each organization has a home region, and sign-in for it is served only
there: `tenants.lookup`, `domains.discover`, public sign-in calls naming its tenant, and requests on its address
answer this code everywhere else. An address that names the wrong region (`acme.signin.eu-west-1.example.com` for an
organization homed in `us-east-1`) gets it too. The error carries `region` and, when one can be built, `location`:
the organization's sign-in URL in its own region (`IamClientError.region` and `.location` in the client).

**How to fix:** redirect the person to `location`. See
[sign-in addresses and regions](/docs/operations/deployment/hosts-and-regions).
