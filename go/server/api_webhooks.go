package server

// Skeleton of packages/server/src/api/webhooks.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// WebhooksAPI is the `webhooks` API group (packages/server/src/api/webhooks.ts createWebhooksApi): every method runs through the
// operation envelope; the router maps POST {basePath}/webhooks/{method} onto it.
type WebhooksAPI struct {
	server *ServerContext
}

// CreateWebhooksAPI builds the `webhooks` API group.
func CreateWebhooksAPI(server *ServerContext) *WebhooksAPI {
	return &WebhooksAPI{server: server}
}

// Create is POST {basePath}/webhooks/create. Subscribes an HTTPS endpoint to the tenant's audit events and returns the signing secret, which is shown only once.
//
// STUB: returns NOT_IMPLEMENTED until api/webhooks.ts is ported.
func (api *WebhooksAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.WebhooksCreateInput]) (Out[apitypes.WebhooksCreateOutput], error) {
	return Out[apitypes.WebhooksCreateOutput]{}, notImplemented("webhooks.create")
}

// Delete is POST {basePath}/webhooks/delete. Deletes a subscription and discards the deliveries still waiting to be sent.
//
// STUB: returns NOT_IMPLEMENTED until api/webhooks.ts is ported.
func (api *WebhooksAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.WebhooksDeleteInput]) (Out[apitypes.WebhooksDeleteOutput], error) {
	return Out[apitypes.WebhooksDeleteOutput]{}, notImplemented("webhooks.delete")
}

// Get is POST {basePath}/webhooks/get. Returns one subscription without its secret.
//
// STUB: returns NOT_IMPLEMENTED until api/webhooks.ts is ported.
func (api *WebhooksAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.WebhooksGetInput]) (Out[apitypes.WebhooksGetOutput], error) {
	return Out[apitypes.WebhooksGetOutput]{}, notImplemented("webhooks.get")
}

// List is POST {basePath}/webhooks/list. Lists every subscription of the tenant, without secrets.
//
// STUB: returns NOT_IMPLEMENTED until api/webhooks.ts is ported.
func (api *WebhooksAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.WebhooksListInput]) (Out[apitypes.WebhooksListOutput], error) {
	return Out[apitypes.WebhooksListOutput]{}, notImplemented("webhooks.list")
}

// ListDeliveries is POST {basePath}/webhooks/listDeliveries. Returns the delivery history of one subscription, newest first, with status, attempt count, and the last error.
//
// STUB: returns NOT_IMPLEMENTED until api/webhooks.ts is ported.
func (api *WebhooksAPI) ListDeliveries(ctx context.Context, credential core.CredentialInput, input In[apitypes.WebhooksListDeliveriesInput]) (Out[apitypes.WebhooksListDeliveriesOutput], error) {
	return Out[apitypes.WebhooksListDeliveriesOutput]{}, notImplemented("webhooks.listDeliveries")
}

// Ping is POST {basePath}/webhooks/ping. Queues a synthetic webhook:ping delivery so you can check an endpoint and its signature verification end to end.
//
// STUB: returns NOT_IMPLEMENTED until api/webhooks.ts is ported.
func (api *WebhooksAPI) Ping(ctx context.Context, credential core.CredentialInput, input In[apitypes.WebhooksPingInput]) (Out[apitypes.WebhooksPingOutput], error) {
	return Out[apitypes.WebhooksPingOutput]{}, notImplemented("webhooks.ping")
}

// Redeliver is POST {basePath}/webhooks/redeliver. Queues the event behind an earlier delivery again, rebuilt from the audit log and signed with the current secret.
//
// STUB: returns NOT_IMPLEMENTED until api/webhooks.ts is ported.
func (api *WebhooksAPI) Redeliver(ctx context.Context, credential core.CredentialInput, input In[apitypes.WebhooksRedeliverInput]) (Out[apitypes.WebhooksRedeliverOutput], error) {
	return Out[apitypes.WebhooksRedeliverOutput]{}, notImplemented("webhooks.redeliver")
}

// RotateSecret is POST {basePath}/webhooks/rotateSecret. Replaces a subscription's signing secret and returns the new one, which is shown only once.
//
// STUB: returns NOT_IMPLEMENTED until api/webhooks.ts is ported.
func (api *WebhooksAPI) RotateSecret(ctx context.Context, credential core.CredentialInput, input In[apitypes.WebhooksRotateSecretInput]) (Out[apitypes.WebhooksRotateSecretOutput], error) {
	return Out[apitypes.WebhooksRotateSecretOutput]{}, notImplemented("webhooks.rotateSecret")
}

// Update is POST {basePath}/webhooks/update. Changes a subscription's URL, event patterns, filters, description, or active flag.
//
// STUB: returns NOT_IMPLEMENTED until api/webhooks.ts is ported.
func (api *WebhooksAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.WebhooksUpdateInput]) (Out[apitypes.WebhooksUpdateOutput], error) {
	return Out[apitypes.WebhooksUpdateOutput]{}, notImplemented("webhooks.update")
}

// AuditAPI is the `audit` API group (packages/server/src/api/webhooks.ts createAuditApi): every method runs through the
// operation envelope; the router maps POST {basePath}/audit/{method} onto it.
type AuditAPI struct {
	server *ServerContext
}

// CreateAuditAPI builds the `audit` API group.
func CreateAuditAPI(server *ServerContext) *AuditAPI {
	return &AuditAPI{server: server}
}

// Export is POST {basePath}/audit/export. Returns a page of the tenant's audit events in chain order as JSON Lines, ready to archive.
//
// STUB: returns NOT_IMPLEMENTED until api/webhooks.ts is ported.
func (api *AuditAPI) Export(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuditExportInput]) (Out[apitypes.AuditExportOutput], error) {
	return Out[apitypes.AuditExportOutput]{}, notImplemented("audit.export")
}

// List is POST {basePath}/audit/list. Searches the tenant's audit events, newest first, by actor, action, resource, outcome, and time range.
//
// STUB: returns NOT_IMPLEMENTED until api/webhooks.ts is ported.
func (api *AuditAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuditListInput]) (Out[apitypes.AuditListOutput], error) {
	return Out[apitypes.AuditListOutput]{}, notImplemented("audit.list")
}

// Verify is POST {basePath}/audit/verify. Checks the tenant's audit hash chain and reports whether any stored event was altered, reordered, or removed.
//
// STUB: returns NOT_IMPLEMENTED until api/webhooks.ts is ported.
func (api *AuditAPI) Verify(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuditVerifyInput]) (Out[apitypes.AuditVerifyOutput], error) {
	return Out[apitypes.AuditVerifyOutput]{}, notImplemented("audit.verify")
}
