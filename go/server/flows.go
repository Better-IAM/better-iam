package server

// Skeleton of packages/server/src/flows.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// AssertMemberInvitationGrantable (flows.ts assertMemberInvitationGrantable): A member invitation grants no more
// than its inviter could bind directly, now as when it was sent: the inviter must still be active and still hold
// iam:identities:create, iam:bindings:create on each role and iam:groups:update on each group (and
// iam:licenses:assign when a license product is assigned to one of the groups, then or since), and the authorities
// behind the invitation and each group's bindings must still be theirs. Demoting or disabling the inviter ends the
// invitations they sent. Throws INVITATION_INVALID otherwise. Acceptance checks it, and so does
// `identities.resendInvitation`, so only an invitation that can still be accepted goes out again.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssertMemberInvitationGrantable(ctx context.Context, server *ServerContext, tx core.IamStore, invitation *core.Object, tenantID string) (err error) {
	err = notImplemented("flows.ts assertMemberInvitationGrantable")
	return
}

// FlowService is flows.ts FlowService.
type FlowService struct {
	server *ServerContext
}

// AcceptOwnerInvitation (flows.ts FlowService.acceptOwnerInvitation): Public: redeems an owner invitation, activates
// the pending tenant, and signs the owner in.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *FlowService) AcceptOwnerInvitation(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("flows.ts FlowService.acceptOwnerInvitation")
	return
}

// AcceptMemberInvitation (flows.ts FlowService.acceptMemberInvitation): Public: redeems a member invitation, applies
// its bindings under the inviter's authority, and signs the member in.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *FlowService) AcceptMemberInvitation(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("flows.ts FlowService.acceptMemberInvitation")
	return
}

// LinkIdentities (flows.ts FlowService.linkIdentities): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *FlowService) LinkIdentities(ctx context.Context, leftCredential core.CredentialInput, rightCredential core.CredentialInput) (result *core.Object, err error) {
	err = notImplemented("flows.ts FlowService.linkIdentities")
	return
}

// SwitchIdentity (flows.ts FlowService.switchIdentity): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *FlowService) SwitchIdentity(ctx context.Context, credential core.CredentialInput, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("flows.ts FlowService.switchIdentity")
	return
}

// AssumeRole (flows.ts FlowService.assumeRole): AssumeRole: exchanges a user session (not impersonated), API key or
// session token for a role session of the trust's tenant, with an optional session name, source identity, tags,
// scope-down policy and JWT format. Role sessions cannot assume roles (ROLE_CHAINING_DISABLED). Audited as
// `iam:roles:assume` in the source tenant and `role:assumed` in the target tenant. The issuing client is recorded on
// the session; a `{ headers }` credential with no client scope set gets the client derived from those headers, as
// `sts.getSessionToken` does.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *FlowService) AssumeRole(ctx context.Context, credential core.CredentialInput, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("flows.ts FlowService.assumeRole")
	return
}

// CreateFlows builds the FlowService (flows.ts createFlows). Its methods are stubs until the module is ported.
func CreateFlows(server *ServerContext) *FlowService {
	return &FlowService{server: server}
}

// TrustPassesSourceAttributes (flows.ts trustPassesSourceAttributes): whether a stored trust passes the source
// identity's attributes into its role sessions: legacy trusts without the field pass them, and a malformed
// (non-boolean) value fails closed and passes nothing.
func TrustPassesSourceAttributes(trust *core.Object) bool {
	value := trust.Get("passSourceAttributes")
	if flag, ok := value.(bool); ok {
		return flag
	}
	return isUndefined(value)
}

// TrustRequiresMfa (flows.ts trustRequiresMfa): whether a stored trust requires MFA of the source session, read
// fail-closed: only the boolean false waives it.
func TrustRequiresMfa(trust *core.Object) bool {
	return trust.Get("requireMfa") != false
}
