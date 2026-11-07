package auth

// Ports of tests/network-blocks.test.ts, tests/session-binding.test.ts and tests/ip-allowlist.test.ts (the
// authentication service part). Blocks are written to authBlocks as security.blockNetwork does; policies to the
// tenant record as tenants.setAuthPolicy does.

import (
	"context"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func (f *fixture) from(ip string) context.Context {
	return f.auth.WithClient(f.ctx, &core.SessionClientInfo{IP: ip, UserAgent: "test"})
}

func (f *fixture) signInFrom(ctx context.Context, name string) (*core.Object, error) {
	return f.auth.SignIn(ctx, core.NewObject("tenantId", "org", "email", name+"@acme.test", "password", "a strong "+name+" password"))
}

func (f *fixture) block(tenantID, network string, durationMs int64, platform bool) string {
	f.t.Helper()
	id := NewID("blk")
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		record := core.NewObject("id", id, "tenantId", tenantID, "network", network, "reason", "test", "createdAt", float64(f.now()),
			"createdBy", "usr_root", "expiresAt", float64(f.now()+durationMs))
		if platform {
			record.Set("platform", true)
		}
		_, err := tx.Insert(ctx, "authBlocks", record)
		return err
	})
	f.auth.InvalidateNetworkBlocks()
	return id
}

func TestPlatformNetworkBlocks(t *testing.T) {
	f := orgFixture(t)
	alice := f.member("alice")
	f.identity("root", true, "root@example.test")
	early := must[*core.Object](t)(f.signInFrom(f.from("198.51.100.9"), "alice"))
	blockID := f.block("root", "198.51.100.0/24", 3_600_000, true)
	_, err := f.signInFrom(f.from("198.51.100.9"), "alice")
	if expectCode(t, err, "IP_BLOCKED").Status != 403 {
		t.Error("status")
	}
	_, err = f.auth.RequestPasswordReset(f.from("198.51.100.200"), core.NewObject("tenantId", "org", "email", "alice@acme.test"))
	expectCode(t, err, "IP_BLOCKED")
	_, err = f.auth.SignIn(f.from("198.51.100.200"), core.NewObject("tenantId", "root", "email", "root@example.test", "password", testPassword))
	expectCode(t, err, "IP_BLOCKED")
	f.auth.SettleBookkeeping()
	for _, event := range f.find("audit", core.NewObject("tenantId", "org", "actorId", alice.Get("id"))) {
		if str(event, "action") == "auth:signin:fail" {
			t.Error("a blocked attempt was recorded as a failure")
		}
	}
	_, err = f.auth.GetSession(f.ctx, token(str(early, "token")))
	expectCode(t, err, "IP_BLOCKED")
	session(t, must[*core.Object](t)(f.signInFrom(f.from("203.0.113.7"), "alice")))
	// Lifting it restores the network at once.
	f.tx(func(ctx context.Context, tx core.IamStore) error { return tx.Delete(ctx, "authBlocks", blockID) })
	f.auth.InvalidateNetworkBlocks()
	session(t, must[*core.Object](t)(f.signInFrom(f.from("198.51.100.9"), "alice")))
	// A timed block lapses by itself.
	f.block("root", "198.51.100.9", 60_000, true)
	_, err = f.signInFrom(f.from("198.51.100.9"), "alice")
	expectCode(t, err, "IP_BLOCKED")
	f.advance(61_000)
	session(t, must[*core.Object](t)(f.signInFrom(f.from("198.51.100.9"), "alice")))
}

func TestOrganizationNetworkBlocksApplyToThatOrganizationOnly(t *testing.T) {
	f := orgFixture(t)
	f.member("alice")
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		_, err := f.auth.CreateIdentity(ctx, tx, CreateIdentityInput{TenantID: "sibling", Email: "sam@acme.test", Name: "Sam",
			Password: "a strong sam password", HasPassword: true})
		return err
	})
	f.block("org", "2001:db8::/32", 3_600_000, false)
	_, err := f.signInFrom(f.from("2001:db8::1"), "alice")
	expectCode(t, err, "IP_BLOCKED")
	// The IPv4-mapped spelling and an IPv6 neighbour are caught too.
	_, err = f.signInFrom(f.from("2001:db8:ffff::9"), "alice")
	expectCode(t, err, "IP_BLOCKED")
	sibling := must[*core.Object](t)(f.auth.SignIn(f.from("2001:db8::1"), core.NewObject("tenantId", "sibling", "email", "sam@acme.test", "password", "a strong sam password")))
	session(t, sibling)
	// Requests without a known client are never judged.
	session(t, f.memberSignIn("alice"))
	if blocked, _ := f.auth.BlockedNetwork(f.ctx, f.store, "org", ""); blocked != nil {
		t.Error("an unknown IP was blocked")
	}
}

func TestSessionsBoundToTheSignInNetwork(t *testing.T) {
	f := orgFixture(t)
	f.member("alice")
	signedIn := must[*core.Object](t)(f.signInFrom(f.from("203.0.113.7"), "alice"))
	value, id := str(signedIn, "token"), str(child(signedIn, "session"), "id")
	use := func(ip, value string) (*core.Object, error) {
		ctx := f.ctx
		if ip != "" {
			ctx = f.from(ip)
		}
		return f.auth.GetSession(ctx, token(value))
	}
	if current := must[*core.Object](t)(use("198.51.100.9", value)); str(child(current, "session"), "id") != id {
		t.Error("a roaming session was refused while binding is off")
	}
	f.setOrgPolicy(core.NewObject("bindSessionsToIp", true))
	must[*core.Object](t)(use("203.0.113.7", value))
	_, err := use("198.51.100.9", value)
	if expectCode(t, err, "SESSION_NETWORK_MISMATCH").Status != 401 {
		t.Error("status")
	}
	events := must[[]*core.Object](t)(f.auth.ListSecurityEvents(f.from("203.0.113.7"), token(value), core.NewObject("limit", 5.0)))
	found := false
	for _, event := range events {
		if str(event, "action") == "auth:session:mismatch" {
			found = true
			if core.MustStringify(event.Get("metadata")) != `{"sessionId":"`+id+`","sessionIp":"203.0.113.7","ip":"198.51.100.9","userAgent":"test"}` {
				t.Errorf("metadata %s", core.MustStringify(event.Get("metadata")))
			}
		}
	}
	if !found {
		t.Error("the mismatch is not in the trail")
	}
	away := must[*core.Object](t)(f.signInFrom(f.from("198.51.100.9"), "alice"))
	must[*core.Object](t)(use("198.51.100.9", str(away, "token")))
	_, err = use("203.0.113.7", str(away, "token"))
	expectCode(t, err, "SESSION_NETWORK_MISMATCH")
	bare := session(t, f.memberSignIn("alice"))
	must[*core.Object](t)(use("198.51.100.9", bare))
	must[*core.Object](t)(use("", value))
}

func TestTenantIPAllowlists(t *testing.T) {
	if !core.IsIPRange("203.0.113.0/24") || !core.IsIPRange("2001:db8::/32") || core.IsIPRange("office") || core.IsIPRange("203.0.113.0/33") {
		t.Error("isIpRange")
	}
	f := orgFixture(t)
	f.member("alice")
	outside := must[*core.Object](t)(f.signInFrom(f.from("198.51.100.7"), "alice"))
	f.setOrgPolicy(core.NewObject("allowedIpRanges", []any{"203.0.113.0/24", "2001:db8::/32"}))
	_, err := f.signInFrom(f.from("198.51.100.7"), "alice")
	if expectCode(t, err, "IP_NOT_ALLOWED").Status != 403 {
		t.Error("status")
	}
	inside := must[*core.Object](t)(f.signInFrom(f.from("203.0.113.42"), "alice"))
	if str(child(child(inside, "session"), "client"), "ip") != "203.0.113.42" {
		t.Error("client ip")
	}
	session(t, must[*core.Object](t)(f.signInFrom(f.from("2001:db8:cafe::1"), "alice")))
	session(t, f.memberSignIn("alice"))
	_, err = f.auth.GetSession(f.ctx, token(str(outside, "token")))
	expectCode(t, err, "IP_NOT_ALLOWED")
	must[*core.Object](t)(f.auth.GetSession(f.ctx, token(str(inside, "token"))))
	f.update("tenants", "org", func(tenant *core.Object) { tenant.Delete("authPolicy") })
	must[*core.Object](t)(f.auth.GetSession(f.ctx, token(str(outside, "token"))))
}
