package server

// Skeleton of packages/server/src/self-check.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// CreateSelfCheck (self-check.ts createSelfCheck): the deployment self-check (schema, durability, secrets, transports,
// scheduled jobs). countDue and sampleSecrets are the retention and secret-rotation dry runs it reports on.
//
// STUB: the returned check returns NOT_IMPLEMENTED until the module is ported.
func CreateSelfCheck(server *ServerContext, countDue func(context.Context, *core.Object) (*core.Object, error), sampleSecrets func(context.Context, float64) (*SecretRotationResult, error)) func(ctx context.Context, options *core.Object) (*core.Object, error) {
	return func(ctx context.Context, options *core.Object) (*core.Object, error) {
		return nil, notImplemented("self-check.ts selfCheck")
	}
}
