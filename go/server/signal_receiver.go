package server

// Skeleton of packages/server/src/signal-receiver.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"
	"net/http"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// ApplySignal (signal-receiver.ts applySignal): Handles one event inside the caller's transaction. Control events
// touch only the source: `verification` records `lastVerifiedAt`; `stream-updated` to paused or disabled records the
// transmitter's status in `lastError`. Unknown event types are ignored. Otherwise the subject is mapped
// (`resolveSubject`); for a match with the action `revoke-sessions` configured for the event type, the person's
// sessions end (`signal:revoke-sessions`), except for a root administrator unless the source belongs to the root
// tenant (ignored, reason `protected`).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ApplySignal(ctx context.Context, server *ServerContext, tx core.IamStore, source *core.Object, signal *core.Object) (result *core.Object, err error) {
	err = notImplemented("signal-receiver.ts applySignal")
	return
}

// CreateSignalsProtocol (signal-receiver.ts createSignalsProtocol): the Shared Signals push endpoint
// (`{signals.pushPath}/{sourceId}`, RFC 8935), always mounted.
//
// STUB: until the module is ported, the mount answers every request under the push path with 501 and the RFC 8935
// error shape { err: "not_implemented", description }, and passes every other request on.
func CreateSignalsProtocol(server *ServerContext) ProtocolMount {
	pushPath := strings.TrimSuffix(server.Config.Signals.PushPath, "/")
	return ProtocolMount{Handle: func(w http.ResponseWriter, r *http.Request) bool {
		if !strings.HasPrefix(r.URL.EscapedPath(), pushPath+"/") {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNotImplemented)
		_, _ = w.Write([]byte(`{"err":"not_implemented","description":"The Shared Signals receiver (signal-receiver.ts) is not implemented in the Go port yet"}`))
		return true
	}}
}

// IamSignals is signal-receiver.ts IamSignals.
type IamSignals struct {
	server *ServerContext
}

// Poll (signal-receiver.ts IamSignals.poll): Polls every active poll source (or one): acknowledges what earlier runs
// committed, then fetches, verifies and records events, following `moreAvailable` for at most five requests per
// source. A scheduler job; run it every minute or so.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamSignals) Poll(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("signal-receiver.ts IamSignals.poll")
	return
}

// Receive (signal-receiver.ts IamSignals.receive): Verifies and records one compact security event token for a
// source, as the push endpoint does: for custom transports and tests. Throws `SignalRejectedError` for a refused
// token and NOT_FOUND for an unknown or disabled source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamSignals) Receive(ctx context.Context, sourceID string, set string) (result *core.Object, err error) {
	err = notImplemented("signal-receiver.ts IamSignals.receive")
	return
}

// CreateSignalsRuntime builds the IamSignals (signal-receiver.ts createSignalsRuntime). Its methods are stubs until the module is ported.
func CreateSignalsRuntime(server *ServerContext) *IamSignals {
	return &IamSignals{server: server}
}

// RecordSignalReceived (signal-receiver.ts recordSignalReceived): Audits a received (or reprocessed) event as
// `signal:received` for threat detection: actor `signal:{sourceId}`, the matched identity (else the source) as
// resource, and `{ sourceId, eventType, jti, status, identityId?, reasonAdmin?, currentLevel?, credentialType? }`
// (`currentLevel` upper-cased, for `risk-level-change`).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RecordSignalReceived(ctx context.Context, server *ServerContext, tx core.IamStore, source *core.Object, record *core.Object, event *core.Object) (err error) {
	err = notImplemented("signal-receiver.ts recordSignalReceived")
	return
}

// SealPollToken (signal-receiver.ts sealPollToken): Seals a poll source's bearer token with the current deployment
// secret.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SealPollToken(server *ServerContext, sourceID string, token string) (result string, err error) {
	err = notImplemented("signal-receiver.ts sealPollToken")
	return
}

// SignalReceiver is signal-receiver.ts SignalReceiver.
type SignalReceiver struct {
	server *ServerContext
}

// Verify (signal-receiver.ts SignalReceiver.verify): Verifies a compact SET for a source (signature, issuer,
// audience, type, age, claims) or throws `SignalRejectedError`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *SignalReceiver) Verify(ctx context.Context, source *core.Object, set any) (result *core.Object, err error) {
	err = notImplemented("signal-receiver.ts SignalReceiver.verify")
	return
}

// Accept (signal-receiver.ts SignalReceiver.accept): Verifies and processes a SET; a refusal is noted on the source
// as `lastError`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *SignalReceiver) Accept(ctx context.Context, source *core.Object, set any) (result *core.Object, err error) {
	err = notImplemented("signal-receiver.ts SignalReceiver.accept")
	return
}

// Poll (signal-receiver.ts SignalReceiver.poll): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *SignalReceiver) Poll(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("signal-receiver.ts SignalReceiver.poll")
	return
}

// Forget (signal-receiver.ts SignalReceiver.forget): Drops the cached keys of a source (after an update or
// deletion).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *SignalReceiver) Forget(sourceID string) (err error) {
	err = notImplemented("signal-receiver.ts SignalReceiver.forget")
	return
}

// Handle (signal-receiver.ts SignalReceiver.handle): The RFC 8935 push endpoint.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *SignalReceiver) Handle(ctx context.Context, request *http.Request) (result *http.Response, err error) {
	err = notImplemented("signal-receiver.ts SignalReceiver.handle")
	return
}

// SignalReceiverOf builds the SignalReceiver (signal-receiver.ts signalReceiverOf). Its methods are stubs until the module is ported.
func SignalReceiverOf(server *ServerContext) *SignalReceiver {
	return &SignalReceiver{server: server}
}

// DefaultSignalAlgorithms is signal-receiver.ts DEFAULT_SIGNAL_ALGORITHMS.
var DefaultSignalAlgorithms = []string{"RS256", "ES256", "PS256", "EdDSA"}

// MaxSignalSourcesPerTenant is signal-receiver.ts maxSignalSourcesPerTenant.
const MaxSignalSourcesPerTenant = 20

// SignalCollections is signal-receiver.ts signalCollections.
var SignalCollections = struct {
	Sources string
	Events  string
}{"signalSources", "signalEvents"}
