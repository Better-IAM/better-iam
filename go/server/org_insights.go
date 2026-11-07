package server

// Skeleton of packages/server/src/org-insights.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// BirthrightOptions (org-insights.ts birthrightOptions): Validates the API input of the `suggestBirthright` methods.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func BirthrightOptions(input *core.Object) (result *core.Object, err error) {
	err = notImplemented("org-insights.ts birthrightOptions")
	return
}

// SuggestBirthright (org-insights.ts suggestBirthright): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SuggestBirthright(ctx context.Context, server *ServerContext, reader core.IamStore, tenantID string, kind string, options *core.Object) (result []*core.Object, err error) {
	err = notImplemented("org-insights.ts suggestBirthright")
	return
}
