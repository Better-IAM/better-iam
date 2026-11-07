package server

// Skeleton of packages/server/src/inference-gateway.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"
	"net/http"

	"github.com/Better-IAM/better-iam/go/core"
)

// CreateInferenceGateway (inference-gateway.ts createInferenceGateway): Builds the gateway handler over the
// inference runtime (see `InferenceGatewayOptions`).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CreateInferenceGateway(runtime *GatewayRuntime, options *core.Object) (result func(context.Context, *http.Request) (*http.Response, error), err error) {
	err = notImplemented("inference-gateway.ts createInferenceGateway")
	return
}

// GatewayRuntime is inference-gateway.ts GatewayRuntime.
type GatewayRuntime struct {
	server *ServerContext
}

// Authorize (inference-gateway.ts GatewayRuntime.authorize): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *GatewayRuntime) Authorize(ctx context.Context, credential core.CredentialInput, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("inference-gateway.ts GatewayRuntime.authorize")
	return
}

// Record (inference-gateway.ts GatewayRuntime.record): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *GatewayRuntime) Record(ctx context.Context, permit *core.Object, usage *core.Object) (result any, err error) {
	err = notImplemented("inference-gateway.ts GatewayRuntime.record")
	return
}

// Models (inference-gateway.ts GatewayRuntime.models): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *GatewayRuntime) Models(ctx context.Context, credential core.CredentialInput) (result []*core.Object, err error) {
	err = notImplemented("inference-gateway.ts GatewayRuntime.models")
	return
}

// OwnsResponse (inference-gateway.ts GatewayRuntime.ownsResponse): Whether an OpenAI Responses API response id was
// created through the gateway by the same caller (the same person, through the same agent if any) at the permit's
// provider. Without it the gateway refuses `previous_response_id`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *GatewayRuntime) OwnsResponse(ctx context.Context, permit *core.Object, responseID string) (result bool, err error) {
	err = notImplemented("inference-gateway.ts GatewayRuntime.ownsResponse")
	return
}
