package a2a

// The gate's view of a composed server (betterIam()): TypeScript passes the instance itself, whose authenticate,
// authorize, authorizeMany and api.delegations the gate calls; Server(iam) adapts a *server.BetterIam to Iam and
// Delegations.

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

// ServerIam adapts a composed server to Iam and Delegations.
type ServerIam struct {
	*server.BetterIam
}

// Server adapts a composed server for the gate.
func Server(iam *server.BetterIam) *ServerIam { return &ServerIam{BetterIam: iam} }

var (
	_ Iam         = (*ServerIam)(nil)
	_ Delegations = (*ServerIam)(nil)
)

func memberString(object *core.Object, key string) string {
	if object == nil {
		return ""
	}
	text, _ := object.Get(key).(string)
	return text
}

// Authenticate is iam.authenticate.
func (s *ServerIam) Authenticate(ctx context.Context, credential core.CredentialInput) (*Principal, error) {
	principal, err := s.BetterIam.Authenticate(ctx, credential)
	if err != nil {
		return nil, err
	}
	return &Principal{
		Identity: PrincipalIdentity{ID: memberString(principal.Identity, "id"), TenantID: memberString(principal.Identity, "tenantId"),
			Kind: memberString(principal.Identity, "kind")},
		Session: PrincipalSession{ID: memberString(principal.Session, "id"), TenantID: memberString(principal.Session, "tenantId"),
			Kind: memberString(principal.Session, "kind"), AgentID: memberString(principal.Session, "agentId"),
			DelegationID: memberString(principal.Session, "delegationId")},
	}, nil
}

// Authorize is iam.authorize.
func (s *ServerIam) Authorize(ctx context.Context, request AuthorizeRequest) (Decision, error) {
	decision, err := s.BetterIam.Authorize(ctx, server.AuthorizationRequest{Credential: request.Credential, TenantID: request.TenantID,
		Action: request.Action, Resource: server.ResourceTarget{Type: request.Resource.Type, ID: request.Resource.ID}})
	if err != nil {
		return Decision{}, err
	}
	return Decision{Allowed: decision.Allowed, Reason: decision.Reason}, nil
}

// AuthorizeMany is iam.authorizeMany.
func (s *ServerIam) AuthorizeMany(ctx context.Context, request AuthorizeManyRequest) ([]Decision, error) {
	batch := server.BatchAuthorizationRequest{Credential: request.Credential, TenantID: request.TenantID}
	for _, check := range request.Checks {
		batch.Checks = append(batch.Checks, server.AuthorizationCheck{Action: check.Action,
			Resource: server.ResourceTarget{Type: check.Resource.Type, ID: check.Resource.ID}})
	}
	answer, err := s.BetterIam.AuthorizeMany(ctx, batch)
	if err != nil {
		return nil, err
	}
	results, _ := answer.Get("results").([]any)
	decisions := make([]Decision, len(results))
	for index, item := range results {
		if result, ok := plain(item); ok {
			decisions[index] = Decision{Allowed: result.Get("allowed") == true, Reason: memberString(result, "reason")}
		}
	}
	return decisions, nil
}

// DelegationConfirm is api.delegations.get's confirm.
func (s *ServerIam) DelegationConfirm(ctx context.Context, credential core.CredentialInput, tenantID, delegationID string) ([]string, error) {
	answer, err := s.API.Delegations.Get(ctx, credential, server.Input[apitypes.DelegationsGetInput](
		core.NewObject("tenantId", tenantID, "delegationId", delegationID)))
	if err != nil {
		return nil, err
	}
	model, err := server.ToModel(answer.Value)
	if err != nil {
		return nil, err
	}
	delegation, _ := plain(model)
	if delegation == nil {
		return nil, nil
	}
	list, _ := delegation.Get("confirm").([]any)
	var confirm []string
	for _, item := range list {
		if pattern, ok := item.(string); ok {
			confirm = append(confirm, pattern)
		}
	}
	return confirm, nil
}

// RequestConfirmation is api.delegations.requestConfirmation.
func (s *ServerIam) RequestConfirmation(ctx context.Context, credential core.CredentialInput, input ConfirmationInput) (ConfirmationRequest, error) {
	answer, err := s.API.Delegations.RequestConfirmation(ctx, credential, server.Input[apitypes.DelegationsRequestConfirmationInput](
		core.NewObject("tenantId", input.TenantID, "action", input.Action,
			"resource", core.NewObject("type", input.Resource.Type, "id", input.Resource.ID), "reason", input.Reason)))
	if err != nil {
		return ConfirmationRequest{}, err
	}
	model, err := server.ToModel(answer.Value)
	if err != nil {
		return ConfirmationRequest{}, err
	}
	request, _ := plain(model)
	expiresAt, _ := request.Get("expiresAt").(float64)
	return ConfirmationRequest{ID: memberString(request, "id"), Status: memberString(request, "status"), ExpiresAt: expiresAt}, nil
}
