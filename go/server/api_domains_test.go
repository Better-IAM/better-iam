package server

// Verified domains and home-realm discovery, after tests/domains.test.ts.

import (
	"regexp"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

func domainsInput(pairs ...any) In[apitypes.DomainsAddInput] {
	return Input[apitypes.DomainsAddInput](body(pairs...))
}

func TestDomainsClaimVerifyAndDiscover(t *testing.T) {
	f := newDirectoryFixture(t, nil)
	domains := f.iam.API.Domains
	acme, owner := f.organization("Acme", "owner@acme.test")
	claimed := answerObject(domains.Add(f.ctx, owner, domainsInput("tenantId", acme, "domain", "Acme.Example.")))
	record := claimed.Get("dnsRecord").(*core.Object)
	if claimed.Get("domain") != "acme.example" || claimed.Get("status") != "pending" || record.Get("type") != "TXT" ||
		record.Get("name") != "_better-iam-challenge.acme.example" {
		t.Fatalf("claimed = %s", stringify(claimed))
	}
	if !regexp.MustCompile(`^better-iam-verification=[\w-]{24}$`).MatchString(jsString(record.Get("value"))) {
		t.Fatalf("verification value %v", record.Get("value"))
	}
	for _, refused := range [][2]string{
		{"gmail.com", "DOMAIN_NOT_ALLOWED"},
		{"not a domain", "INVALID_INPUT"},
		{"localhost", "INVALID_INPUT"},
		{"10.0.0.1", "INVALID_INPUT"},
		{"-bad.example", "INVALID_INPUT"},
		{"acme.example", "CONFLICT"},
	} {
		_, err := domains.Add(f.ctx, owner, domainsInput("tenantId", acme, "domain", refused[0]))
		expectCode(t, err, refused[1])
	}

	// Pending domains are not discoverable, and a missing record leaves the claim pending.
	_, err := domains.Discover(f.ctx, Input[apitypes.DomainsDiscoverInput](body("email", "jane@acme.example")))
	expectStatus(t, err, 404)
	verify := func(credential core.CredentialInput, tenantID string, domainID any) (Out[apitypes.DomainsVerifyOutput], error) {
		return domains.Verify(f.ctx, credential, Input[apitypes.DomainsVerifyInput](body("tenantId", tenantID, "domainId", domainID)))
	}
	pending := answerObject(verify(owner, acme, claimed.Get("id")))
	if pending.Get("verified") != false {
		t.Fatalf("pending = %s", stringify(pending))
	}
	if _, ok := member(pending.Get("domain"), "lastCheckedAt").(float64); !ok {
		t.Fatalf("lastCheckedAt missing: %s", stringify(pending))
	}

	// TXT records may arrive split into chunks; the joined value must match exactly.
	value := jsString(record.Get("value"))
	f.setDNS(jsString(record.Get("name")), []string{"unrelated"}, []string{value[:10], value[10:]})
	verified := answerObject(verify(owner, acme, claimed.Get("id")))
	if verified.Get("verified") != true || member(verified.Get("domain"), "status") != "verified" {
		t.Fatalf("verified = %s", stringify(verified))
	}
	discovered := answerObject(domains.Discover(f.ctx, Input[apitypes.DomainsDiscoverInput](body("email", "Jane@ACME.example"))))
	if want := `{"domain":"acme.example","tenantId":"` + acme + `","name":"Acme","type":"organization","allowedMethods":null,"requireMfa":false}`; stringify(discovered) != want {
		t.Fatalf("discover = %s, want %s", stringify(discovered), want)
	}
	// Re-verifying a verified domain does not query DNS again.
	lookups := f.lookupCount()
	answer(verify(owner, acme, claimed.Get("id")))
	if f.lookupCount() != lookups {
		t.Fatal("a verified domain was looked up again")
	}
	listed := answerList(domains.List(f.ctx, owner, Input[apitypes.DomainsListInput](body("tenantId", acme))))
	if got := pluck(listed, "domain"); len(got) != 1 || got[0] != "acme.example" {
		t.Fatalf("list = %v", got)
	}

	// Discovery reflects the tenant's sign-in requirements.
	f.patch("tenants", acme, body("authPolicy", body("requireMfa", true, "allowedMethods", items("passkey"))))
	discovered = answerObject(domains.Discover(f.ctx, Input[apitypes.DomainsDiscoverInput](body("domain", "acme.example"))))
	if stringify(discovered.Get("allowedMethods")) != `["passkey"]` || discovered.Get("requireMfa") != true {
		t.Fatalf("discover with policy = %s", stringify(discovered))
	}
}

func TestDomainsKeepOneOwnerAndIsolateTenants(t *testing.T) {
	f := newDirectoryFixture(t, nil)
	domains := f.iam.API.Domains
	acme, acmeOwner := f.organization("Acme", "owner@acme.test")
	rival, rivalOwner := f.organization("Rival", "owner@rival.test")
	acmeClaim := answerObject(domains.Add(f.ctx, acmeOwner, domainsInput("tenantId", acme, "domain", "shared.example")))
	// Two organizations may hold pending claims; only the one that proves DNS control wins.
	rivalClaim := answerObject(domains.Add(f.ctx, rivalOwner, domainsInput("tenantId", rival, "domain", "shared.example")))
	acmeRecord, rivalRecord := acmeClaim.Get("dnsRecord").(*core.Object), rivalClaim.Get("dnsRecord").(*core.Object)
	if acmeRecord.Get("value") == rivalRecord.Get("value") {
		t.Fatal("two claims share a verification token")
	}
	verify := func(credential core.CredentialInput, tenantID string, domainID any) (Out[apitypes.DomainsVerifyOutput], error) {
		return domains.Verify(f.ctx, credential, Input[apitypes.DomainsVerifyInput](body("tenantId", tenantID, "domainId", domainID)))
	}
	f.setDNS(jsString(acmeRecord.Get("name")), []string{jsString(acmeRecord.Get("value"))})
	answer(verify(acmeOwner, acme, acmeClaim.Get("id")))
	// The rival's own token is not published, so it stays pending; publishing it cannot steal ownership.
	if result := answerObject(verify(rivalOwner, rival, rivalClaim.Get("id"))); result.Get("verified") != false {
		t.Fatalf("rival verify = %s", stringify(result))
	}
	f.setDNS(jsString(acmeRecord.Get("name")), []string{jsString(rivalRecord.Get("value"))})
	_, err := verify(rivalOwner, rival, rivalClaim.Get("id"))
	expectCode(t, err, "DOMAIN_TAKEN")
	answer(domains.Add(f.ctx, rivalOwner, domainsInput("tenantId", rival, "domain", "other.example")))
	_, err = domains.Add(f.ctx, rivalOwner, domainsInput("tenantId", rival, "domain", "shared.example"))
	expectCode(t, err, "CONFLICT")
	// Cross-tenant access to another organization's claim is not found.
	_, err = domains.Delete(f.ctx, rivalOwner, Input[apitypes.DomainsDeleteInput](body("tenantId", rival, "domainId", acmeClaim.Get("id"))))
	expectStatus(t, err, 404)

	discover := func() (Out[apitypes.DomainsDiscoverOutput], error) {
		return domains.Discover(f.ctx, Input[apitypes.DomainsDiscoverInput](body("email", "a@shared.example")))
	}
	if found := answerObject(discover()); found.Get("tenantId") != acme {
		t.Fatalf("discover = %s", stringify(found))
	}
	f.patch("tenants", acme, body("status", "suspended"))
	_, err = discover()
	expectStatus(t, err, 404)
	f.patch("tenants", acme, body("status", "active"))
	answer(domains.Delete(f.ctx, acmeOwner, Input[apitypes.DomainsDeleteInput](body("tenantId", acme, "domainId", acmeClaim.Get("id")))))
	_, err = discover()
	expectStatus(t, err, 404)
	if owners := f.find("domainOwners", body()); len(owners) != 0 {
		t.Fatalf("domain owners left: %d", len(owners))
	}
	// Released: the rival can now verify its pending claim.
	if result := answerObject(verify(rivalOwner, rival, rivalClaim.Get("id"))); result.Get("verified") != true {
		t.Fatalf("rival verify after release = %s", stringify(result))
	}
}

func TestDomainsServeDiscoveryPubliclyWhileManagementRequiresPermission(t *testing.T) {
	f := newDirectoryFixture(t, nil)
	domains := f.iam.API.Domains
	acme, owner := f.organization("Acme", "owner@acme.test")
	claim := answerObject(domains.Add(f.ctx, owner, domainsInput("tenantId", acme, "domain", "web.example")))
	record := claim.Get("dnsRecord").(*core.Object)
	f.setDNS(jsString(record.Get("name")), []string{jsString(record.Get("value"))})
	answer(domains.Verify(f.ctx, owner, Input[apitypes.DomainsVerifyInput](body("tenantId", acme, "domainId", claim.Get("id")))))
	call := func(path, payload string) *Response {
		return f.post(directoryOrigin, path, payload, map[string]string{"origin": directoryOrigin})
	}
	discovered := call("domains/discover", `{"email":"x@web.example"}`)
	if discovered.Status != 200 || member(jsonBody(t, discovered).Get("data"), "tenantId") != acme {
		t.Fatalf("discover over HTTP: %d %s", discovered.Status, discovered.Body)
	}
	if status := call("domains/discover", `{"email":"nobody"}`).Status; status != 400 {
		t.Fatalf("discover without @: %d", status)
	}
	if status := call("domains/discover", `{"email":"x@unknown.example"}`).Status; status != 404 {
		t.Fatalf("discover unknown: %d", status)
	}
	if status := call("domains/list", `{"tenantId":"`+acme+`"}`).Status; status != 401 {
		t.Fatalf("list without a credential: %d", status)
	}
	// A member without iam:domains:* cannot manage domains.
	_, memberCredential := f.person(acme, "member")
	_, err := domains.Add(f.ctx, memberCredential, domainsInput("tenantId", acme, "domain", "x.example"))
	expectStatus(t, err, 403)
	_, err = domains.List(f.ctx, memberCredential, Input[apitypes.DomainsListInput](body("tenantId", acme)))
	expectStatus(t, err, 403)
	// Verification is decided ahead of the DNS query: a refused caller causes no lookup.
	lookups := f.lookupCount()
	other := answerObject(domains.Add(f.ctx, owner, domainsInput("tenantId", acme, "domain", "late.example")))
	_, err = domains.Verify(f.ctx, memberCredential, Input[apitypes.DomainsVerifyInput](body("tenantId", acme, "domainId", other.Get("id"))))
	expectStatus(t, err, 403)
	if f.lookupCount() != lookups {
		t.Fatal("a refused caller caused a DNS lookup")
	}
}

func TestDomainNameAndRecordNameValidation(t *testing.T) {
	for input, want := range map[string]string{
		"Example.COM.": "example.com", " sub.example.org ": "sub.example.org", "xn--bcher-kva.example": "xn--bcher-kva.example",
	} {
		if got, err := DomainName(input); err != nil || got != want {
			t.Errorf("DomainName(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []any{"example", "exa_mple.com", "example.c0m", "example.-com", core.Undefined, 5.0} {
		if _, err := DomainName(input); err == nil {
			t.Errorf("DomainName(%v) accepted", input)
		}
	}
	options := &BetterIamOptions{Database: newStore(t), Secret: testSecret, BaseURL: directoryOrigin,
		Domains: &DomainOptions{RecordName: str("two.labels")}}
	_, err := New(options)
	expectError(t, err, "INVALID_CONFIG", "domains.recordName must be a single DNS label")
}
