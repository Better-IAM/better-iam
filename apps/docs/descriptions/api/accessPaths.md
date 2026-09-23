# accessPaths

Access paths tell a denied person what they can do on their own to be allowed, such as stepping up to MFA or
requesting a package. When your application refuses an action, `accessPaths.find` lists those options, so the error
page can offer a button instead of "contact your administrator". See the
[access paths guide](/docs/guides/governance/access-paths).

## How paths are verified

Each candidate path is applied inside a transaction that is always rolled back, and the ordinary authorization
decision is run again. A path is listed only when that decision then allows the action, so the list never promises
access that would still be refused:

- **`mfa`**: step up to multi-factor authentication, when the session has no MFA and an MFA session would be allowed.
- **`accept-agreements`**: accept the required [agreements](/docs/reference/api/agreements) the person still owes,
  listed with the versions to accept.
- **`activate`**: activate one of the person's eligible
  [just-in-time bindings](/docs/guides/privileged-access/elevation), held directly or through a group, with the
  binding's activation settings (`requireApproval`, `requireJustification`, `requireMfa`, `maxActivationMs`). Listed
  only when the person holds `iam:bindings:activate` on the role.
- **`request-package`**: request a requestable [access package](/docs/reference/api/packages#request). Listed only
  when the person holds `iam:packages:request` on the package. The request still needs an approver's decision.

Each path is tested on its own, so when only a combination would help (MFA and an activation, for example) neither
is listed. At most 50 eligible bindings and 50 requestable packages are tried. An empty list means nothing the
person can do alone would help: they need an administrator.

## find

Lists what you could do yourself to be allowed an action on a resource you are denied.

- **Permission:** None beyond your own ordinary session of the tenant (not an assumed role, another tenant's
  session, or impersonation).
- **Audited as:** Not audited; nothing is saved.
- **Errors:** `ACCESS_DENIED` from a role session or another tenant's session; `IMPERSONATION_RESTRICTED` from an
  impersonation session; `INVALID_ACTION` for an action the catalog does not know; `INVALID_INPUT` when the action or
  resource is missing.

When you are already allowed, the result is `allowed: true` with the decision reason and no paths. When you are
denied, `reason` is always `ACCESS_DENIED`: like `authorize`, the call does not reveal which statement refused you.
Call it from the code path that handles a denial, with the same action and resource you just checked.
`useAccessPaths` wraps it for React and Vue apps.

```ts
const result = await iam.api.accessPaths.find(credential, {
  tenantId,
  action: 'documents:delete',
  resource: { type: 'document', id: 'doc_42' },
});
for (const path of result.paths) {
  if (path.kind === 'mfa') showStepUpButton();
  if (path.kind === 'activate') showActivateButton(path.bindingId, path.role.name);
  if (path.kind === 'request-package') showRequestButton(path.package.id, path.requireJustification);
  if (path.kind === 'accept-agreements') showTermsDialog(path.agreements);
}
```
