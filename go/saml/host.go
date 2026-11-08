package saml

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

// HostOptions is `{ ...iam.protocolHost }`: the store and the trusted callbacks of a composed server (authenticate,
// authorize, completeAuthentication, assertTrustChange), and its wall clock. Add ServiceProvider or Connections and
// pass the result to CreateSamlService, then mount the service with iam.UseProtocol(service.Protocol()).
func HostOptions(iam *server.BetterIam) SamlConfigOptions {
	host, _ := iam.ProtocolHost.(*server.ProtocolHost)
	options := SamlConfigOptions{Store: iam.Store, Now: iam.Context.Wall}
	if host == nil {
		return options
	}
	options.Store = host.Store
	options.Authenticate = func(ctx context.Context, credential core.CredentialInput) (*Principal, error) {
		principal, err := host.Authenticate(ctx, credential)
		if err != nil {
			return nil, err
		}
		return &Principal{Identity: principal.Identity, Session: principal.Session}, nil
	}
	options.Authorize = host.Authorize
	options.CompleteAuthentication = func(ctx context.Context, input *core.Object) (any, error) {
		result, err := host.CompleteAuthentication(ctx, input)
		if err != nil {
			return nil, err
		}
		return result, nil
	}
	options.AssertTrustChange = host.AssertTrustChange
	return options
}

// Protocol is the service as a protocol mount (`iam.useProtocol(saml)`): its base path and fetch-style handler.
func (s *SamlService) Protocol() server.ProtocolService {
	return server.ProtocolService{BasePath: s.basePath, Handler: s.Handler}
}
