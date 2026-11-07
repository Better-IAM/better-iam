package server

// Port of tests/network-blocks.test.ts: the `security` API group (blockNetwork, listBlocks, unblockNetwork) and how
// the blocks it records stop sign-ins and live sessions.

import (
	"context"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

func (f *opsFixture) blockNetwork(credential core.CredentialInput, body *core.Object) (*core.Object, error) {
	out, err := f.iam.API.Security.BlockNetwork(f.ctx, credential, Input[apitypes.SecurityBlockNetworkInput](body))
	result, _ := out.Value.(*core.Object)
	return result, err
}

func (f *opsFixture) listBlocks(credential core.CredentialInput, tenantID string) ([]any, error) {
	out, err := f.iam.API.Security.ListBlocks(f.ctx, credential, Input[apitypes.SecurityListBlocksInput](core.NewObject("tenantId", tenantID)))
	result, _ := out.Value.([]any)
	return result, err
}

func (f *opsFixture) memberSignIn(ctx context.Context, name string) (*core.Object, error) {
	return f.signInResult(ctx, f.tenantID, name+"@acme.test", opsMemberPassword)
}

func TestNetworkBlocksLetRootBlockANetworkPlatformWide(t *testing.T) {
	f := newOpsFixture(t, nil)
	root := f.rootCredential()
	alice := f.member("alice")
	early := must(f.memberSignIn(f.from("198.51.100.9"), "alice"))
	block := must(f.blockNetwork(root, core.NewObject(
		"tenantId", f.rootTenantID, "network", "198.51.100.0/24", "reason", "credential stuffing", "durationMs", 3_600_000, "platform", true,
	)))
	if block.Get("network") != "198.51.100.0/24" || block.Get("platform") != true || block.Get("expiresAt") != float64(f.now()+3_600_000) || block.Get("active") != true {
		t.Fatalf("block: %s", core.MustStringify(block))
	}
	// Refused before any credential or counter is examined, in every tenant and flow.
	_, err := f.memberSignIn(f.from("198.51.100.9"), "alice")
	if known := expectCode(t, err, "IP_BLOCKED"); known.Status != 403 {
		t.Fatalf("status %d", known.Status)
	}
	_, err = f.iam.API.Auth.RequestPasswordReset(f.from("198.51.100.200"), Input[apitypes.AuthRequestPasswordResetInput](core.NewObject("tenantId", f.tenantID, "email", "alice@acme.test")))
	expectCode(t, err, "IP_BLOCKED")
	_, err = f.signInResult(f.from("198.51.100.200"), f.rootTenantID, "root@example.test", "a strong root test password")
	expectCode(t, err, "IP_BLOCKED")
	for _, event := range f.find("audit", core.NewObject("tenantId", f.tenantID)) {
		if event.Get("action") == "auth:signin:fail" && event.Get("actorId") == alice.Get("id") {
			t.Fatal("a blocked sign-in counted as a failure")
		}
	}
	// The session established from that network before the block stops working; others are untouched.
	_, err = f.iam.API.Auth.GetSession(f.ctx, core.CredentialInput{Token: jsString(early.Get("token"))}, Input[apitypes.AuthGetSessionInput](core.NewObject()))
	expectCode(t, err, "IP_BLOCKED")
	if elsewhere := must(f.memberSignIn(f.from("203.0.113.7"), "alice")); !elsewhere.Has("token") {
		t.Fatal("a sign-in from elsewhere was refused")
	}
	// Root sees the block on the root tenant; an organization sees only its own.
	blocks := must(f.listBlocks(root, f.rootTenantID))
	if len(blocks) != 1 || member(blocks[0], "id") != block.Get("id") || member(blocks[0], "active") != true || member(blocks[0], "reason") != "credential stuffing" {
		t.Fatalf("root blocks: %s", core.MustStringify(blocks))
	}
	expectJSON(t, must(f.listBlocks(f.owner, f.tenantID)), `[]`)
	// Lifting it restores the network at once.
	lifted, err := f.iam.API.Security.UnblockNetwork(f.ctx, root, Input[apitypes.SecurityUnblockNetworkInput](core.NewObject("tenantId", f.rootTenantID, "blockId", block.Get("id"))))
	if err != nil {
		t.Fatal(err)
	}
	expectJSON(t, lifted.Value, `{"success":true}`)
	if again := must(f.memberSignIn(f.from("198.51.100.9"), "alice")); !again.Has("token") {
		t.Fatal("the lifted block still applies")
	}
	// A timed block lapses by itself.
	short := must(f.blockNetwork(root, core.NewObject(
		"tenantId", f.rootTenantID, "network", "198.51.100.9", "reason", "one minute", "durationMs", 60_000, "platform", true,
	)))
	_, err = f.memberSignIn(f.from("198.51.100.9"), "alice")
	expectCode(t, err, "IP_BLOCKED")
	f.advance(61_000)
	if lapsed := must(f.memberSignIn(f.from("198.51.100.9"), "alice")); !lapsed.Has("token") {
		t.Fatal("the lapsed block still applies")
	}
	blocks = must(f.listBlocks(root, f.rootTenantID))
	if len(blocks) != 1 || member(blocks[0], "id") != short.Get("id") || member(blocks[0], "active") != false {
		t.Fatalf("root blocks: %s", core.MustStringify(blocks))
	}
	// Everything was audited with the network named.
	var events []string
	for _, event := range f.find("audit", core.NewObject("tenantId", f.rootTenantID)) {
		if action := jsString(event.Get("action")); strings.HasPrefix(action, "security:network-") {
			events = append(events, action+" "+jsString(member(event.Get("metadata"), "network")))
		}
	}
	joined := strings.Join(events, "|")
	for _, want := range []string{"security:network-block 198.51.100.0/24", "security:network-unblock 198.51.100.0/24", "security:network-block 198.51.100.9"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("audit lacks %q: %s", want, joined)
		}
	}
}

func TestNetworkBlocksLetAnOrganizationBlockNetworksForItself(t *testing.T) {
	f := newOpsFixture(t, nil)
	f.member("alice")
	owner := core.CredentialInput{Token: jsString(must(f.signInResult(f.from("10.0.0.5"), f.tenantID, "owner@acme.test", opsMemberPassword)).Get("token"))}
	block := must(f.blockNetwork(owner, core.NewObject("tenantId", f.tenantID, "network", "192.0.2.0/24", "reason", "scanner")))
	if block.Get("network") != "192.0.2.0/24" || block.Get("active") != true || block.Has("platform") || block.Has("expiresAt") {
		t.Fatalf("block: %s", core.MustStringify(block))
	}
	_, err := f.memberSignIn(f.from("192.0.2.5"), "alice")
	expectCode(t, err, "IP_BLOCKED")
	// The block is the organization's: the root tenant still accepts that network.
	rootAttempt := must(f.signInResult(f.from("192.0.2.5"), f.rootTenantID, "root@example.test", "a strong root test password"))
	if !rootAttempt.Has("mfaRequired") {
		t.Fatalf("root attempt: %s", core.MustStringify(rootAttempt))
	}
	// Renewing the same network updates the record instead of adding one.
	renewed := must(f.blockNetwork(owner, core.NewObject("tenantId", f.tenantID, "network", "192.0.2.0/24", "reason", "scanner, again", "durationMs", 120_000)))
	if renewed.Get("id") != block.Get("id") {
		t.Fatal("renewal added a block")
	}
	if blocks := must(f.listBlocks(owner, f.tenantID)); len(blocks) != 1 {
		t.Fatalf("blocks: %d", len(blocks))
	}
	var renewal *core.Object
	for _, event := range f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "security:network-block")) {
		if member(event.Get("metadata"), "renewed") == true {
			renewal = event
		}
	}
	if renewal == nil {
		t.Fatal("the renewal was not audited as renewed")
	}
	expectJSON(t, renewal.Get("metadata"), `{"network":"192.0.2.0/24","reason":"scanner, again","platform":false,"expiresAt":`+core.NumberString(float64(f.now()+120_000))+`,"renewed":true}`)
	// Validation: platform blocks are root's, networks must parse, and the caller cannot block themselves.
	_, err = f.blockNetwork(owner, core.NewObject("tenantId", f.tenantID, "network", "203.0.113.0/24", "reason", "x", "platform", true))
	expectError(t, err, "ACCESS_DENIED", "Platform-wide blocks are set by root administrators on the root tenant")
	_, err = f.blockNetwork(owner, core.NewObject("tenantId", f.tenantID, "network", "not-a-network", "reason", "x"))
	expectError(t, err, "INVALID_INPUT", "network must be an IPv4/IPv6 address or CIDR block")
	_, err = f.blockNetwork(owner, core.NewObject("tenantId", f.tenantID, "network", "10.0.0.0/8", "reason", "would lock me out"))
	expectError(t, err, "INVALID_INPUT", "That network includes your own address")
	// The address the request comes from counts too.
	_, err = f.iam.API.Security.BlockNetwork(f.from("198.18.0.1"), owner, Input[apitypes.SecurityBlockNetworkInput](core.NewObject("tenantId", f.tenantID, "network", "198.18.0.0/15", "reason", "x")))
	expectError(t, err, "INVALID_INPUT", "That network includes your own address")
	_, err = f.blockNetwork(owner, core.NewObject("tenantId", f.tenantID, "network", "203.0.113.1", "reason", "x", "durationMs", 1_000))
	expectError(t, err, "INVALID_INPUT", "Invalid durationMs")
	_, err = f.blockNetwork(owner, core.NewObject("tenantId", f.tenantID, "network", "203.0.113.1", "reason", "   "))
	expectError(t, err, "INVALID_INPUT", "Invalid reason")
	_, err = f.iam.API.Security.UnblockNetwork(f.ctx, owner, Input[apitypes.SecurityUnblockNetworkInput](core.NewObject("tenantId", f.tenantID, "blockId", "missing")))
	expectError(t, err, "NOT_FOUND", "Resource not found")
	// Blocks on the root tenant are root administrators' alone.
	rootOwner := f.rootTenantMember()
	_, err = f.blockNetwork(rootOwner, core.NewObject("tenantId", f.rootTenantID, "network", "203.0.113.0/24", "reason", "x"))
	expectError(t, err, "ACCESS_DENIED", "Blocks on the root tenant are set by root administrators")
	// A member without the permission can neither read nor manage blocks.
	alice := core.CredentialInput{Token: jsString(must(f.memberSignIn(f.from("203.0.113.9"), "alice")).Get("token"))}
	_, err = f.listBlocks(alice, f.tenantID)
	expectCode(t, err, "ACCESS_DENIED")
}

// rootTenantMember is a member of the root tenant (not a root administrator) holding every permission there.
func (f *opsFixture) rootTenantMember() core.CredentialInput {
	f.t.Helper()
	authorityID := "authority-" + ID()
	f.put("grantAuthorities", core.NewObject("id", authorityID, "tenantId", f.rootTenantID, "identityId", f.rootID, "ceiling", All(), "revoked", false))
	staff := f.createIdentity("staff@example.test", "Staff", opsMemberPassword)
	role := f.put("roles", core.NewObject("id", "role-"+ID(), "tenantId", f.rootTenantID, "name", "Staff", "uniqueKey", "name:staff",
		"document", allowDocument("*"), "authorityId", authorityID))
	f.put("bindings", core.NewObject("id", "binding-"+ID(), "tenantId", f.rootTenantID, "uniqueKey", "staff", "subjectType", "identity",
		"subjectId", staff.Get("id"), "roleId", role.Get("id"), "authorityId", authorityID))
	result := must(f.signInResult(f.ctx, f.rootTenantID, "staff@example.test", opsMemberPassword))
	token, _ := result.Get("token").(string)
	if token == "" {
		f.t.Fatalf("staff sign-in: %s", core.MustStringify(result))
	}
	return core.CredentialInput{Token: token}
}
