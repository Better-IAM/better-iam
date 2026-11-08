package ldap

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

// betterIam adapts a composed server to LdapIam (the TypeScript gateway takes the `betterIam()` instance itself).
type betterIam struct{ iam *server.BetterIam }

// FromBetterIam is the LdapIam of a composed server: its auth and ldap API groups, authenticate, auth.withClient
// and the ldap runtime.
func FromBetterIam(iam *server.BetterIam) LdapIam { return &betterIam{iam: iam} }

func (b *betterIam) SignIn(ctx context.Context, tenantID, email, password string) (any, error) {
	out, err := b.iam.API.Auth.SignIn(ctx, server.Input[apitypes.AuthSignInInput](core.NewObject("tenantId", tenantID,
		"email", email, "password", password)))
	return out.Value, err
}

func (b *betterIam) VerifyMfa(ctx context.Context, tenantID, challenge, code string) (any, error) {
	out, err := b.iam.API.Auth.VerifyMfa(ctx, server.Input[apitypes.AuthVerifyMfaInput](core.NewObject("tenantId", tenantID,
		"challenge", challenge, "code", code)))
	return out.Value, err
}

func (b *betterIam) SignOut(ctx context.Context, credential core.CredentialInput) error {
	_, err := b.iam.API.Auth.SignOut(ctx, credential, server.Input[apitypes.AuthSignOutInput](nil))
	return err
}

func (b *betterIam) Directory(ctx context.Context, credential core.CredentialInput, tenantID string) (any, error) {
	out, err := b.iam.API.Ldap.Directory(ctx, credential, server.Input[apitypes.LdapDirectoryInput](core.NewObject("tenantId", tenantID)))
	if err != nil {
		return nil, err
	}
	return server.ToModel(out.Value)
}

func (b *betterIam) Authenticate(ctx context.Context, credential core.CredentialInput) (*core.Object, *core.Object, error) {
	principal, err := b.iam.Authenticate(ctx, credential)
	if err != nil {
		return nil, nil, err
	}
	return principal.Identity, principal.Session, nil
}

func (b *betterIam) WithClient(ctx context.Context, client *core.SessionClientInfo) context.Context {
	return b.iam.Auth.WithClient(ctx, client)
}

func (b *betterIam) TenantForBase(ctx context.Context, normalizedBaseDn string) (*core.Object, error) {
	return b.iam.Ldap.TenantForBase(ctx, normalizedBaseDn)
}

func (b *betterIam) ResolveBindName(ctx context.Context, tenantID, kind, value string) (*core.Object, error) {
	return b.iam.Ldap.ResolveBindName(ctx, tenantID, kind, value)
}
