// Package server is the Go port of @better-iam/server (packages/server/src). It is one package on purpose: the
// kernel (options, context, catalog, events, observability, decisions, operations, principals, the HTTP router),
// every server module and every API group (api_<group>.go) live side by side, so modules reach each other through
// the ServerContext at call time exactly as the TypeScript modules do, without import cycles.
//
// File names mirror the TypeScript modules (options.ts -> options.go, context-keys.ts -> context_keys.go,
// api/roles.ts -> api_roles.go). Records are *core.Object values with the TypeScript field names (see go/core
// json.go), so a Go server reads and writes exactly the rows a TypeScript server does (a mixed fleet). Errors are
// *core.IamError with the TypeScript codes, messages and statuses.
//
// Kernel A (this step) ports options, models, define, utils, validation, client-info, safe-fetch, plugins, context,
// context-keys, session-kinds, catalog, events, observe, metrics, tenant-policy, access-policy, grant-deadline,
// assertions, guarded and secrets, plus the configuration half of hosts.ts and the standalone JSON configuration
// reader (spec/conformance/CONFIG.md). The services kernel B ports (decisions, operations, principals, flows,
// usage, token signing, web identity, hosts, billing hooks) are declared as interfaces in contracts.go.
package server
