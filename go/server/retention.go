package server

// Skeleton of packages/server/src/retention.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// Retention is retention.ts createRetention().
type Retention struct {
	server *ServerContext
}

// SweepExpired (retention.ts createRetention().sweepExpired): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *Retention) SweepExpired(ctx context.Context, options *core.Object) (result *core.Object, err error) {
	err = notImplemented("retention.ts createRetention().sweepExpired")
	return
}

// CountDue (retention.ts createRetention().countDue): Records a sweep with these settings would delete that have
// been due for at least `overdueMs`, per collection, counting at most `cap` per collection. Reads only; `selfCheck`
// uses it to spot a sweep that is not running or not keeping up.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *Retention) CountDue(ctx context.Context, options *core.Object) (result *core.Object, err error) {
	err = notImplemented("retention.ts createRetention().countDue")
	return
}

// CreateRetention builds the Retention (retention.ts createRetention). Its methods are stubs until the module is ported.
func CreateRetention(server *ServerContext) *Retention {
	return &Retention{server: server}
}
