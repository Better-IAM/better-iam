package server

// Skeleton of packages/server/src/inference.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// AssertInference (inference.ts assertInference): Refuses inference calls on deployments that did not enable it.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssertInference(server *core.Object) (err error) {
	err = notImplemented("inference.ts assertInference")
	return
}

// BaseURL (inference.ts baseUrl): A provider base URL: https without credentials, query or fragment (http on
// loopback only with `allowInsecureLocalhost`); the trailing slash is removed.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func BaseURL(value any, settings *core.Object) (result string, err error) {
	err = notImplemented("inference.ts baseUrl")
	return
}

// BudgetStandings (inference.ts budgetStandings): The standing of every budget covering a subject's use of a model,
// in the current windows.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func BudgetStandings(ctx context.Context, server *ServerContext, tx core.IamStore, subject *core.Object, model string) (result []*core.Object, err error) {
	err = notImplemented("inference.ts budgetStandings")
	return
}

// BudgetWindow (inference.ts budgetWindow): The current window of a period (UTC), as [start, end).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func BudgetWindow(period string, now int64) (result *core.Object, err error) {
	err = notImplemented("inference.ts budgetWindow")
	return
}

// CheckInvocation (inference.ts checkInvocation): Whether a principal may call a model now: the model must be
// visible and enabled, `inference:invoke` on `model/{name}` must be allowed (denials are audited like any decision),
// and no covering budget may be exhausted (`estimatedTokens`, when given, must fit in what remains, priced at the
// model's input price). The first refusal of a budget in a window is audited as `inference:budget-exceeded`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CheckInvocation(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("inference.ts checkInvocation")
	return
}

// DelegationSpendStanding (inference.ts delegationSpendStanding): How much of a delegation's spending cap is used in
// the current window (undefined without a cap).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DelegationSpendStanding(ctx context.Context, tx core.IamStore, delegation *core.Object, now int64) (result *core.Object, err error) {
	err = notImplemented("inference.ts delegationSpendStanding")
	return
}

// InferenceEnabled (inference.ts inferenceEnabled): Whether the deployment enabled inference (`inference` option).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func InferenceEnabled(server *core.Object) (result bool, err error) {
	err = notImplemented("inference.ts inferenceEnabled")
	return
}

// InferencePlugins (inference.ts inferencePlugins): the catalog entries the inference module contributes when
// enabled (the `model` type and `inference:invoke`); none when it is off.
//
// STUB: returns NOT_IMPLEMENTED when inference is enabled, until the module is ported.
func InferencePlugins(options *BetterIamOptions) (result []*core.IamPlugin, err error) {
	if !options.Inference.IsOn() {
		return nil, nil
	}
	err = notImplemented("inference.ts inferencePlugins")
	return
}

// InferenceSettings (inference.ts inferenceSettings): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func InferenceSettings(server *core.Object) (result *core.Object, err error) {
	err = notImplemented("inference.ts inferenceSettings")
	return
}

// ModelName (inference.ts modelName): A public model name.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ModelName(value any) (result string, err error) {
	err = notImplemented("inference.ts modelName")
	return
}

// OwnsInferenceResponse (inference.ts ownsInferenceResponse): Whether `responseId` was created through the gateway
// in `tenantId` by the same caller as `principal`, at the provider `providerId` (so a provider that echoes someone
// else's response id cannot claim it for another provider's key).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func OwnsInferenceResponse(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string, responseID string, providerID string) (result bool, err error) {
	err = notImplemented("inference.ts ownsInferenceResponse")
	return
}

// Price (inference.ts price): A non-negative price in dollars per million tokens (at most 10 000).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func Price(value any, name string) (result float64, err error) {
	err = notImplemented("inference.ts price")
	return
}

// ProviderCredential (inference.ts providerCredential): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ProviderCredential(ctx context.Context, server *ServerContext, tx core.IamStore, provider *core.Object) (result *core.Object, err error) {
	err = notImplemented("inference.ts providerCredential")
	return
}

// ProviderKey (inference.ts providerKey): A provider key: 8 to 4096 printable characters without whitespace.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ProviderKey(value any) (result string, err error) {
	err = notImplemented("inference.ts providerKey")
	return
}

// PublicModel (inference.ts publicModel): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PublicModel(model *core.Object, provider *core.Object, tenantID string) (result *core.Object, err error) {
	err = notImplemented("inference.ts publicModel")
	return
}

// RecordInvocation (inference.ts recordInvocation): Meters one call: stores a usage record (cost from the model's
// prices) and adds it to every covering budget's counter. A counter crossing a budget's `alertAtPercent` is audited
// once per window as `inference:budget-alert`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RecordInvocation(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("inference.ts recordInvocation")
	return
}

// ResolveModel (inference.ts resolveModel): The nearest definition of a model name for a tenant (its own, else the
// closest ancestor's), with its provider.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ResolveModel(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, name string) (result *core.Object, err error) {
	err = notImplemented("inference.ts resolveModel")
	return
}

// ResolveModelResource (inference.ts resolveModelResource): the decision engine's resolver for `model/{name}` (and
// `model-tool/{kind}`) when inference is enabled; nil for other types or when inference is off.
//
// PARTIAL: the guard is ported; resolving a model (resolveModel, modelAttributes) is a stub.
func ResolveModelResource(ctx context.Context, server *ServerContext, tx core.IamStore, reference core.ResourceRef) (*ResolvedResource, error) {
	if reference.Type != "model" && reference.Type != "model-tool" {
		return nil, nil
	}
	if !server.Options.Inference.IsOn() {
		return nil, nil
	}
	return nil, notImplemented("inference.ts resolveModelResource")
}

// SealProviderKey (inference.ts sealProviderKey): Seals a provider key for storage with the current deployment
// secret.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SealProviderKey(secret string, providerID string, key string) (result string, err error) {
	err = notImplemented("inference.ts sealProviderKey")
	return
}

// StandingOf (inference.ts standingOf): A budget's standing in a window, from its counter (absent: nothing used
// yet).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func StandingOf(budget *core.Object, window *core.Object, counter *core.Object) (result *core.Object, err error) {
	err = notImplemented("inference.ts standingOf")
	return
}

// UsageSubject (inference.ts usageSubject): The subject of a principal's calls in `tenantId`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func UsageSubject(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string) (result *core.Object, err error) {
	err = notImplemented("inference.ts usageSubject")
	return
}

// VisibleModels (inference.ts visibleModels): Every model visible from a tenant: its own and inherited ones, the
// nearest definition of each name winning.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func VisibleModels(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string) (result []*core.Object, err error) {
	err = notImplemented("inference.ts visibleModels")
	return
}

// VisibleProvider (inference.ts visibleProvider): A provider visible from a tenant: its own or an ancestor's.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func VisibleProvider(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, providerID string) (result *core.Object, err error) {
	err = notImplemented("inference.ts visibleProvider")
	return
}

// VisibleProviders (inference.ts visibleProviders): Every provider a tenant may use (its own and its ancestors'),
// nearest first.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func VisibleProviders(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string) (result []*core.Object, err error) {
	err = notImplemented("inference.ts visibleProviders")
	return
}

// InferenceAction is inference.ts inferenceAction.
const InferenceAction = "inference:invoke"

// InferenceResourceType is inference.ts inferenceResourceType.
const InferenceResourceType = "model"

// ProviderBaseURLs is inference.ts providerBaseUrls.
var ProviderBaseURLs = mustObject(`{"anthropic":"https://api.anthropic.com","openai":"https://api.openai.com"}`)

// ProviderKinds is inference.ts providerKinds.
var ProviderKinds = []string{"anthropic", "openai", "openai-compatible"}

// ProviderToolsModes is inference.ts providerToolsModes.
var ProviderToolsModes = []string{"allow", "deny", "policy"}
