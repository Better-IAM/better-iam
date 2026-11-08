package middleware

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

// ServerIAM adapts a composed server (betterIam()) to IAM and its optional interfaces: it is the middleware's view of
// a `betterIam()` instance (handler, nodeHandler, api.auth.getSession, api.assertions.issue, require, authorizeMany,
// listAccessible, planResources, endpoint, hosts).
type ServerIAM struct {
	*server.BetterIam
}

// Server adapts a composed server for the middleware.
func Server(iam *server.BetterIam) *ServerIAM { return &ServerIAM{BetterIam: iam} }

// GetSession is api.auth.getSession.
func (s *ServerIAM) GetSession(ctx context.Context, credential core.CredentialInput) (*core.Object, error) {
	answer, err := s.API.Auth.GetSession(ctx, credential, server.Input[apitypes.AuthGetSessionInput](nil))
	if err != nil {
		return nil, err
	}
	session, _ := answer.Value.(*core.Object)
	return session, nil
}

// IssueAssertion is api.assertions.issue.
func (s *ServerIAM) IssueAssertion(ctx context.Context, credential core.CredentialInput, input *core.Object) (*core.Object, error) {
	return s.API.Assertions.Issue(ctx, credential, input)
}

// IamEndpoint is the instance's endpoint.
func (s *ServerIAM) IamEndpoint() server.Endpoint { return s.Endpoint }

// ResolveHost is hosts.resolve.
func (s *ServerIAM) ResolveHost(ctx context.Context, host string) (*server.HostMatch, error) {
	return s.Hosts.Resolve(ctx, host)
}

var (
	_ IAM              = (*ServerIAM)(nil)
	_ NodeHandler      = (*ServerIAM)(nil)
	_ AccessibleLister = (*ServerIAM)(nil)
	_ ResourcePlanner  = (*ServerIAM)(nil)
	_ AssertionIssuer  = (*ServerIAM)(nil)
	_ EndpointProvider = (*ServerIAM)(nil)
	_ HostResolver     = (*ServerIAM)(nil)
)
