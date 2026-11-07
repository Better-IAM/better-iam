package server

// Custom sign-in hostnames, after tests/custom-hostnames.test.ts.

import (
	"regexp"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

type hostnameFixture struct {
	*directoryFixture
	tenantID string
	owner    core.CredentialInput
}

func newHostnameFixture(t *testing.T, customHostnames bool) *hostnameFixture {
	t.Helper()
	f := newDirectoryFixture(t, func(options *BetterIamOptions) {
		options.Hosts = &HostOptions{Patterns: []string{"{tenant}.localhost:3000"}, CustomHostnames: flag(customHostnames),
			CnameTarget: str("custom.signin.example.com")}
	})
	tenantID, owner := f.organization("Acme", "owner@acme.test", "slug", "acme")
	f.person(tenantID, "alice")
	return &hostnameFixture{directoryFixture: f, tenantID: tenantID, owner: owner}
}

func (f *hostnameFixture) add(credential core.CredentialInput, tenantID, hostname string) (Out[apitypes.HostnamesAddOutput], error) {
	return f.iam.API.Hostnames.Add(f.ctx, credential, Input[apitypes.HostnamesAddInput](body("tenantId", tenantID, "hostname", hostname)))
}

func (f *hostnameFixture) verify(credential core.CredentialInput, tenantID string, hostnameID any) (Out[apitypes.HostnamesVerifyOutput], error) {
	return f.iam.API.Hostnames.Verify(f.ctx, credential, Input[apitypes.HostnamesVerifyInput](body("tenantId", tenantID, "hostnameId", hostnameID)))
}

// verified claims and verifies a hostname for Acme.
func (f *hostnameFixture) verified(hostname string) *core.Object {
	f.t.Helper()
	claimed := answerObject(f.add(f.owner, f.tenantID, hostname))
	record := member(claimed.Get("dnsRecords"), "verification")
	f.setDNS(jsString(member(record, "name")), []string{jsString(member(record, "value"))})
	return answerObject(f.verify(f.owner, f.tenantID, claimed.Get("id"))).Get("hostname").(*core.Object)
}

func TestHostnamesAreOffUnlessEnabled(t *testing.T) {
	f := newHostnameFixture(t, false)
	_, err := f.add(f.owner, f.tenantID, "login.acme.test")
	expectCode(t, err, "FEATURE_DISABLED")
	_, err = f.verify(f.owner, f.tenantID, "x")
	expectCode(t, err, "FEATURE_DISABLED")
	_, err = f.iam.API.Hostnames.SetPrimary(f.ctx, f.owner, Input[apitypes.HostnamesSetPrimaryInput](body("tenantId", f.tenantID, "hostnameId", nil)))
	expectCode(t, err, "FEATURE_DISABLED")
}

func TestHostnamesClaimReturnsVerificationAndRoutingRecords(t *testing.T) {
	f := newHostnameFixture(t, true)
	claimed := answerObject(f.add(f.owner, f.tenantID, "Login.Acme.Test."))
	records := claimed.Get("dnsRecords").(*core.Object)
	verification := records.Get("verification").(*core.Object)
	if claimed.Get("hostname") != "login.acme.test" || claimed.Get("status") != "pending" || claimed.Get("primary") != false ||
		claimed.Get("url") != "http://login.acme.test/" || verification.Get("type") != "TXT" ||
		verification.Get("name") != "_better-iam-challenge.login.acme.test" ||
		stringify(records.Get("routing")) != `{"type":"CNAME","name":"login.acme.test","value":"custom.signin.example.com"}` {
		t.Fatalf("claimed = %s", stringify(claimed))
	}
	if claimed.Has("verifiedAt") || claimed.Has("lastCheckedAt") {
		t.Fatalf("unset members present: %s", stringify(claimed))
	}
	if !regexp.MustCompile(`^better-iam-hostname=[\w-]{24}$`).MatchString(jsString(verification.Get("value"))) {
		t.Fatalf("verification value %v", verification.Get("value"))
	}
	for _, refused := range [][2]string{
		{"login.acme.test", "CONFLICT"},
		{"localhost", "INVALID_INPUT"},
		// The deployment's own subdomain space cannot be claimed.
		{"globex.localhost", "HOSTNAME_NOT_ALLOWED"},
		{"deep.acme.localhost", "HOSTNAME_NOT_ALLOWED"},
	} {
		_, err := f.add(f.owner, f.tenantID, refused[0])
		expectCode(t, err, refused[1])
	}
	// Pending hostnames resolve to nothing.
	if match, err := f.iam.Context.Hosts.Resolve(f.ctx, "login.acme.test", nil); err != nil || match != nil {
		t.Fatalf("pending hostname resolved: %+v %v", match, err)
	}
	listed := answerList(f.iam.API.Hostnames.List(f.ctx, f.owner, Input[apitypes.HostnamesListInput](body("tenantId", f.tenantID))))
	if got := pluck(listed, "hostname"); len(got) != 1 || got[0] != "login.acme.test" {
		t.Fatalf("list = %v", got)
	}
}

func TestHostnamesVerifyThroughDNSAndPinTheOrganization(t *testing.T) {
	f := newHostnameFixture(t, true)
	claimed := answerObject(f.add(f.owner, f.tenantID, "login.acme.test"))
	pending := answerObject(f.verify(f.owner, f.tenantID, claimed.Get("id")))
	if pending.Get("verified") != false || member(pending.Get("hostname"), "status") != "pending" {
		t.Fatalf("pending = %s", stringify(pending))
	}
	if _, ok := member(pending.Get("hostname"), "lastCheckedAt").(float64); !ok {
		t.Fatalf("lastCheckedAt missing: %s", stringify(pending))
	}
	verification := member(claimed.Get("dnsRecords"), "verification")
	f.setDNS(jsString(member(verification, "name")), []string{jsString(member(verification, "value"))})
	verified := answerObject(f.verify(f.owner, f.tenantID, claimed.Get("id")))
	if verified.Get("verified") != true || member(verified.Get("hostname"), "status") != "verified" {
		t.Fatalf("verified = %s", stringify(verified))
	}
	match, err := f.iam.Context.Hosts.Resolve(f.ctx, "login.acme.test", nil)
	if err != nil || match == nil || match.TenantID != f.tenantID || match.Via != "custom" {
		t.Fatalf("resolve = %+v %v", match, err)
	}
	if allowed, err := f.iam.Context.Hosts.Allowed(f.ctx, "login.acme.test"); err != nil || !allowed {
		t.Fatalf("allowed = %v %v", allowed, err)
	}
	if owner := f.record("hostnameOwners", "login.acme.test"); owner == nil || owner.Get("tenantId") != f.tenantID || owner.Get("hostnameId") != claimed.Get("id") {
		t.Fatalf("hostname owner = %s", stringify(owner))
	}

	// Another organization cannot take a verified hostname, even with its own TXT record.
	globex, globexOwner := f.organization("Globex", "owner@globex.test", "slug", "globex")
	_, err = f.add(globexOwner, globex, "login.acme.test")
	expectCode(t, err, "HOSTNAME_TAKEN")
	// Nor can it read or release Acme's claim.
	_, err = f.iam.API.Hostnames.Delete(f.ctx, globexOwner, Input[apitypes.HostnamesDeleteInput](body("tenantId", globex, "hostnameId", claimed.Get("id"))))
	expectStatus(t, err, 404)
}

func TestHostnamesPrimaryAddressAndRelease(t *testing.T) {
	f := newHostnameFixture(t, true)
	hostnames := f.iam.API.Hostnames
	setPrimary := func(hostnameID any) (Out[apitypes.HostnamesSetPrimaryOutput], error) {
		return hostnames.SetPrimary(f.ctx, f.owner, Input[apitypes.HostnamesSetPrimaryInput](body("tenantId", f.tenantID, "hostnameId", hostnameID)))
	}
	pending := answerObject(f.add(f.owner, f.tenantID, "sso.acme.test"))
	_, err := setPrimary(pending.Get("id"))
	expectError(t, err, "INVALID_INPUT", "Verify the hostname before making it primary")
	_, err = hostnames.SetPrimary(f.ctx, f.owner, Input[apitypes.HostnamesSetPrimaryInput](body("tenantId", f.tenantID)))
	expectError(t, err, "INVALID_INPUT", "Invalid hostnameId")
	hostname := f.verified("login.acme.test")
	primary := answerObject(setPrimary(hostname.Get("id")))
	if member(primary.Get("primary"), "hostname") != "login.acme.test" || member(primary.Get("primary"), "primary") != true ||
		primary.Get("signInUrl") != "http://login.acme.test/" {
		t.Fatalf("setPrimary = %s", stringify(primary))
	}
	if url, err := f.iam.Context.Hosts.SignInURL(f.ctx, f.tenantID, nil); err != nil || url != "http://login.acme.test/" {
		t.Fatalf("signInUrl = %q %v", url, err)
	}
	if stored := f.record("tenantHostnames", jsString(hostname.Get("id"))); stored.Get("primary") != true {
		t.Fatalf("stored = %s", stringify(stored))
	}
	back := answerObject(setPrimary(nil))
	if stringify(back) != `{"primary":null,"signInUrl":"http://acme.localhost:3000/"}` {
		t.Fatalf("back to the subdomain = %s", stringify(back))
	}
	if stored := f.record("tenantHostnames", jsString(hostname.Get("id"))); stored.Has("primary") {
		t.Fatalf("primary kept: %s", stringify(stored))
	}
	answer(hostnames.Delete(f.ctx, f.owner, Input[apitypes.HostnamesDeleteInput](body("tenantId", f.tenantID, "hostnameId", hostname.Get("id")))))
	if match, err := f.iam.Context.Hosts.Resolve(f.ctx, "login.acme.test", nil); err != nil || match != nil {
		t.Fatalf("released hostname resolved: %+v %v", match, err)
	}
	if allowed, err := f.iam.Context.Hosts.Allowed(f.ctx, "login.acme.test"); err != nil || allowed {
		t.Fatalf("released hostname allowed: %v %v", allowed, err)
	}
	if owner := f.record("hostnameOwners", "login.acme.test"); owner != nil {
		t.Fatalf("hostname owner kept: %s", stringify(owner))
	}
}

func TestHostnamesLimitPerOrganization(t *testing.T) {
	f := newHostnameFixture(t, true)
	for index := 0; index < maxHostnames; index++ {
		answer(f.add(f.owner, f.tenantID, "h"+jsString(float64(index))+".acme.test"))
	}
	_, err := f.add(f.owner, f.tenantID, "one-more.acme.test")
	expectError(t, err, "LIMIT_EXCEEDED", "An organization can claim at most 20 hostnames")
}
