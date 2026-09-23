# Shared application and enterprise protocols

The SQLite and PostgreSQL examples share one application configuration and HTTP server. All public management operations call Better IAM's authenticated services. The document resolver loads resource ownership from application storage. Rendering and identity-provider interaction pages are application-owned.

After building the workspace, run `node examples/shared/smoke.mjs` for a real HTTP integration exercise covering root MFA, owner and member invitations, organization aliases, permission-based roles, tenant-defined resource types, IAM-managed resources with batch authorization, custom policy enforcement, OAuth authorization/consent/PKCE, and SCIM deactivation. It uses an in-memory SQLite database, an ephemeral loopback port, and temporary keys under `work` that are removed on completion.

To run the identical smoke exercise against PostgreSQL, set `BETTER_IAM_EXAMPLE_POSTGRES_URL` to an **empty, isolated test database** connection string. The smoke exercise creates an installation root, tenants, identities, and protocol records and leaves those database records intact; it never drops or clears an existing database. Use a fresh database for each run.

## Enable OAuth and OpenID Connect

Create private signing/encryption keys once and store the file outside version control. From the repository root:

```powershell
node examples/shared/generate-oidc-keys.mjs ./work/example-oidc-keys.json
$env:OIDC_KEY_FILE = (Resolve-Path ./work/example-oidc-keys.json).Path
pnpm --filter @better-iam/example-sqlite start
```

Create the `work` directory first if needed. The key generator refuses to overwrite an existing file and creates an RSA signing key, cookie keys, and a separate encryption key. Preserve this file across restarts. Use your secret manager or a protected mounted file for deployment.

The default issuer is `http://localhost:3000/oauth`; discovery is available at `/oauth/.well-known/openid-configuration`. The provider is disabled unless `OIDC_KEY_FILE` is set. Its protocol state uses the selected database; no temporary in-memory provider adapter is substituted.

1. Sign in as an organization owner. In **OAuth and OpenID Connect**, register the public browser client for that tenant. The registered redirect URI is exactly `http://localhost:3000/oidc/callback` for the default origin.
2. Select **Sign in through OAuth with PKCE**. The example creates a random state value and S256 PKCE challenge and starts the actual authorization flow.
3. On the application's interaction page, sign into the same tenant as the client, complete MFA when required, and approve the requested scopes. `interactionDetails()` obtains the immutable tenant/client binding; `completeInteraction()` authenticates the IAM cookie and validates its tenant before completing the flow.
4. The callback verifies state and exchanges the code with its PKCE verifier. The page reports the token metadata without persisting access, ID, or refresh tokens. Only the short-lived state/verifier transaction is temporarily kept in browser session storage for full-page navigation.

Changing the organization identifier in a form cannot switch the tenant bound to an OAuth client or grant. Public client registration is exposed only through the authenticated example management endpoint; dynamic OAuth client registration remains disabled.

For device authorization, use the discovered `device_authorization_endpoint` with the public client ID and a requested scope. The response includes `verification_uri`, `user_code`, and the polling interval. Open the verification URI and follow the application's code entry, login, and confirmation pages. Poll the discovered token endpoint using grant type `urn:ietf:params:oauth:grant-type:device_code`, respecting `authorization_pending` and `slow_down`. The provider renders its CSRF-protected forms inside application-owned pages through `renderDevicePage`.

The discovered end-session endpoint uses the application's `renderLogoutPage` wrapper. Keep provider-generated form markup intact: it contains protocol CSRF fields. The provider also offers introspection and revocation for confidential clients; confidential client registration is available through the library's authenticated `registerClient()` service.

`GET /app/oauth/clients?tenantId=…` lists the tenant's clients without secrets. `GET /app/oauth/grants?tenantId=…` lists the signed-in account's connected apps (its OAuth consents), and `DELETE /app/oauth/grants` with `{ "tenantId", "clientId" }` disconnects one app, revoking its refresh and access tokens.

## Try SCIM provisioning

As a tenant administrator, use **SCIM provisioning** to create a one-hour credential. Save its returned `path` and bearer `token`; the credential is shown once and stored only as a hash.

Use your returned values for these requests:

```http
POST /scim/v2/CONNECTION_ID/Users
Authorization: Bearer SCIM_TOKEN
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "provisioned@example.com",
  "displayName": "Provisioned user",
  "active": true
}
```

List with `GET /scim/v2/CONNECTION_ID/Users?filter=userName%20eq%20%22provisioned%40example.com%22`. Deactivate the returned user ID with:

```http
PATCH /scim/v2/CONNECTION_ID/Users/USER_ID
Authorization: Bearer SCIM_TOKEN
Content-Type: application/scim+json

{
  "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
  "Operations": [{"op": "replace", "path": "active", "value": false}]
}
```

SCIM Users and Groups remain within the connection's tenant. Deactivation revokes its identity's sessions. Provisioning a group grants no role automatically. The library's explicit administrator-controlled group-role mapping callback is intentionally not configured in this example. Discovery documents advertise the implemented filter, PATCH, and pagination capabilities; bulk is unsupported.

## Application routes

| Route                              | Behavior                                                                             |
| ---------------------------------- | ------------------------------------------------------------------------------------ |
| `POST /api/iam/{group}/{method}`   | Better IAM's regular service API                                                     |
| `POST /app/documents`              | Create after `documents:write` authorization on `document-collection/{tenantId}`     |
| `GET /app/documents?tenantId=...`  | Return only documents authorized by `documents:read`                                 |
| `GET /app/documents/{id}`          | Resolve stored ownership and enforce `documents:read`                                |
| `POST /app/workspaces`             | Register an IAM-managed `workspace` resource (IAM authorizes `iam:resources:create`) |
| `GET /app/workspaces?tenantId=...` | List workspaces with the caller's allowed actions from one `authorizeMany` batch     |
| `POST /app/oauth/clients`          | Register a public tenant-bound OAuth client                                          |
| `POST /app/scim/connections`       | Create a tenant-bound SCIM credential                                                |
| `GET /dev/inbox`                   | Loopback-only, explicitly enabled development delivery inbox                         |

Application mutation routes enforce the same-origin JSON and `X-Better-IAM` boundary. OAuth interactions use signed provider cookies, trusted Origins, verified IAM credentials, and explicit approval. Error responses contain stable codes and omit raw assertions, database records, and tokens.
