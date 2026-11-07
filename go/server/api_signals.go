package server

// Skeleton of packages/server/src/api/signals.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// SignalsAPI is the `signals` API group (packages/server/src/api/signals.ts createSignalsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/signals/{method} onto it.
type SignalsAPI struct {
	server *ServerContext
}

// CreateSignalsAPI builds the `signals` API group.
func CreateSignalsAPI(server *ServerContext) *SignalsAPI {
	return &SignalsAPI{server: server}
}

// CreateSource is POST {basePath}/signals/createSource. Registers an identity provider as a signal source for the organization.
//
// STUB: returns NOT_IMPLEMENTED until api/signals.ts is ported.
func (api *SignalsAPI) CreateSource(ctx context.Context, credential core.CredentialInput, input In[apitypes.SignalsCreateSourceInput]) (Out[apitypes.SignalsCreateSourceOutput], error) {
	return Out[apitypes.SignalsCreateSourceOutput]{}, notImplemented("signals.createSource")
}

// DeleteSource is POST {basePath}/signals/deleteSource. Deletes a signal source; the events it sent stay until they expire.
//
// STUB: returns NOT_IMPLEMENTED until api/signals.ts is ported.
func (api *SignalsAPI) DeleteSource(ctx context.Context, credential core.CredentialInput, input In[apitypes.SignalsDeleteSourceInput]) (Out[apitypes.SignalsDeleteSourceOutput], error) {
	return Out[apitypes.SignalsDeleteSourceOutput]{}, notImplemented("signals.deleteSource")
}

// GetEvent is POST {basePath}/signals/getEvent. Returns one received security event.
//
// STUB: returns NOT_IMPLEMENTED until api/signals.ts is ported.
func (api *SignalsAPI) GetEvent(ctx context.Context, credential core.CredentialInput, input In[apitypes.SignalsGetEventInput]) (Out[apitypes.SignalsGetEventOutput], error) {
	return Out[apitypes.SignalsGetEventOutput]{}, notImplemented("signals.getEvent")
}

// GetSource is POST {basePath}/signals/getSource. Returns one signal source with its health.
//
// STUB: returns NOT_IMPLEMENTED until api/signals.ts is ported.
func (api *SignalsAPI) GetSource(ctx context.Context, credential core.CredentialInput, input In[apitypes.SignalsGetSourceInput]) (Out[apitypes.SignalsGetSourceOutput], error) {
	return Out[apitypes.SignalsGetSourceOutput]{}, notImplemented("signals.getSource")
}

// ListEvents is POST {basePath}/signals/listEvents. Lists received events, newest first, optionally narrowed by source, status, identity, and event type.
//
// STUB: returns NOT_IMPLEMENTED until api/signals.ts is ported.
func (api *SignalsAPI) ListEvents(ctx context.Context, credential core.CredentialInput, input In[apitypes.SignalsListEventsInput]) (Out[apitypes.SignalsListEventsOutput], error) {
	return Out[apitypes.SignalsListEventsOutput]{}, notImplemented("signals.listEvents")
}

// ListSources is POST {basePath}/signals/listSources. Lists the organization's signal sources, oldest first.
//
// STUB: returns NOT_IMPLEMENTED until api/signals.ts is ported.
func (api *SignalsAPI) ListSources(ctx context.Context, credential core.CredentialInput, input In[apitypes.SignalsListSourcesInput]) (Out[apitypes.SignalsListSourcesOutput], error) {
	return Out[apitypes.SignalsListSourcesOutput]{}, notImplemented("signals.listSources")
}

// Poll is POST {basePath}/signals/poll. Polls one poll source now, as the scheduled iam.signals.poll() does, and returns what it did.
//
// STUB: returns NOT_IMPLEMENTED until api/signals.ts is ported.
func (api *SignalsAPI) Poll(ctx context.Context, credential core.CredentialInput, input In[apitypes.SignalsPollInput]) (Out[apitypes.SignalsPollOutput], error) {
	return Out[apitypes.SignalsPollOutput]{}, notImplemented("signals.poll")
}

// Reprocess is POST {basePath}/signals/reprocess. Maps an unmatched or failed event again and runs the source's action for it, after the mapping or the directory changed.
//
// STUB: returns NOT_IMPLEMENTED until api/signals.ts is ported.
func (api *SignalsAPI) Reprocess(ctx context.Context, credential core.CredentialInput, input In[apitypes.SignalsReprocessInput]) (Out[apitypes.SignalsReprocessOutput], error) {
	return Out[apitypes.SignalsReprocessOutput]{}, notImplemented("signals.reprocess")
}

// RotatePushToken is POST {basePath}/signals/rotatePushToken. Replaces a push source's bearer token and returns the new one, shown only once.
//
// STUB: returns NOT_IMPLEMENTED until api/signals.ts is ported.
func (api *SignalsAPI) RotatePushToken(ctx context.Context, credential core.CredentialInput, input In[apitypes.SignalsRotatePushTokenInput]) (Out[apitypes.SignalsRotatePushTokenOutput], error) {
	return Out[apitypes.SignalsRotatePushTokenOutput]{}, notImplemented("signals.rotatePushToken")
}

// UpdateSource is POST {basePath}/signals/updateSource. Changes a signal source: names, aliases, audiences, keys, algorithms, poll settings, mapping, actions, type check, or status.
//
// STUB: returns NOT_IMPLEMENTED until api/signals.ts is ported.
func (api *SignalsAPI) UpdateSource(ctx context.Context, credential core.CredentialInput, input In[apitypes.SignalsUpdateSourceInput]) (Out[apitypes.SignalsUpdateSourceOutput], error) {
	return Out[apitypes.SignalsUpdateSourceOutput]{}, notImplemented("signals.updateSource")
}
