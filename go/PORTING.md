# Porting the server modules to Go

This guide is for the agents and people who fill in the Go server skeleton in `go/server`. Read `spec/BUILDOUT.md`
first for the parity contract, and `crates/PORTING.md` for the Rust side: the rules are the same. The TypeScript
source under `packages/server/src` is the specification. Port it line by line, keeping:

- the same validation order
- the same error codes, messages and statuses
- the same defaults
- the same record shapes (camelCase JSON, same member order)
- the same audit event names

## Where things are

| TypeScript                                | Go                                                     |
| ----------------------------------------- | ------------------------------------------------------ |
| `packages/server/src/<module>.ts`         | `go/server/<module>.go` (`-` becomes `_`)              |
| `packages/server/src/api/<file>.ts`       | `go/server/api_<file>.go`                              |
| the API route table                       | `go/server/api_routes_gen.go` (generated)              |
| request/response types                    | `go/apitypes` (generated from `spec/`)                 |
| `scripts/conformance/serve.mjs`           | `go/cmd/better-iam-server` (`--conformance`)           |

**Finished modules to copy the style from:**

- `decisions.go`
- `operations.go`
- `principals.go`
- `http.go`
- `index.go`
- `api_catalog.go`: the `actions` and `resourceTypes` API groups
- `api_values.go`
- `events.go`
- `guarded.go`
- `secrets.go`
- `validation.go`

**Test harness:** `support_test.go` (`newKernel`, `newStore`, `obj`, `expectError`, ...).

## The skeleton

Every exported item other modules use already exists, with its final signature. Its body is:

```go
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *TeamsRuntime) TeamChain(...) (result X, err error) {
	err = notImplemented("teams.ts teamChain")
	return
}
```

To port an item:

1. Replace the body with the port of the TypeScript function.
2. Delete the `STUB:` comment line.
3. Add the module's private helpers.

Keep the signatures, because other modules and the generated route table already call them. You may refine a
signature (for example, a placeholder `any` becoming a struct) only if you update every caller in the same change
(`grep` the name across `go/`).

**API groups:** each group is a struct (`RolesAPI`) with one method per route:

```go
func (api *RolesAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.RolesCreateInput]) (Out[apitypes.RolesCreateOutput], error)
```

- Read the raw JSON body with `input.Get("name")`.
- Validate in the TypeScript order with the helpers in `validation.go`.
- Wrap mutations in `Operate(ctx, api.server.Operations, credential, tenantID, action, resourceID, fn, rootOnly)`,
  the operation envelope. It authenticates, authorizes, runs the SoD and invariant checks, executes `fn` in a
  transaction, and writes the audit event.
- Refuse with `NewOperationDenied("...")`.
- Errors are `core.NewIamError(code, message, status)`.

## Records and JSON

- Records are `*core.Object`, an insertion-ordered JSON object. Use `core.NewObject(k, v, ...)`, `Get`, `Set` and
  `Delete`.
- For read-modify-write, change the raw record and put it back. That way member order and unknown members survive:
  TypeScript, Rust and Go replicas share one database.
- A member TypeScript leaves `undefined` is `core.Undefined`, which is omitted on encode.
- Numbers follow JavaScript formatting.
- Use the injected clock (`server.Now()`) where TypeScript uses `ctx.now()` / `authentication.now()`, and
  `DateNow()` where TypeScript uses `Date.now()`. The conformance server controls them separately.

## Tests and checks

- Port the TypeScript tests of the module into `go/server/<module>_test.go`.
- Run from `go/`:

  ```sh
  gofmt -l . && go vet ./... && go build ./... && go test ./server/ -run <YourTests>
  ```

## Replay

Build the conformance server and replay the traces of your API group:

```sh
cd go && go build -o ../work/go-server.exe ./cmd/better-iam-server && cd ..
node scripts/conformance/replay.mjs \
  --server '"work/go-server.exe" --conformance --config {config} --port {port}' \
  --filter group:<apiGroup> --jobs 4 --keep-going
```

A step that answers `NOT_IMPLEMENTED` names the stub it reached. If that stub is in another module, report it rather
than porting that module.

## Fidelity checklist

- Same validation order and messages, and the same `IamError` code, message and status.
- Same records: collection names, member names and order, `uniqueKey` formats.
- Same audit events: action names, outcomes, metadata members.
- No silent gaps: whatever you cannot finish stays `notImplemented(...)` and is reported.
