package server

// spec/vectors/assertions.json: every issue case (the operation envelope stubbed as the vector generator stubs it:
// principal, tenant, grant sources and clock from the input) reproduces the TypeScript token byte for byte, and every
// verify case gives the same claims or error.

import (
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/spectest"
)

func TestAssertionVectors(t *testing.T) {
	file := spectest.Load(t, "assertions")
	key := AssertionKey("deployment-secret-A-with-at-least-32-characters")
	issued, verified := 0, 0
	for _, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if strings.HasPrefix(c.Name, "issue") {
				issued++
				request, _ := c.Input.Object("request")
				principalInput, _ := c.Input.Object("principal")
				principal := &Principal{Identity: principalInput.Get("identity").(*core.Object), Session: principalInput.Get("session").(*core.Object)}
				tenant := core.NewObject("id", request.Get("tenantId"))
				sources := func() (*GrantSources, error) {
					result := &GrantSources{}
					for _, id := range c.Input.Get("groupIds").([]any) {
						result.GroupIDs = append(result.GroupIDs, id.(string))
					}
					for _, id := range c.Input.Get("roleIds").([]any) {
						result.Bindings = append(result.Bindings, core.NewObject("roleId", id))
					}
					return result, nil
				}
				jti := ID()
				if output, ok := c.Output.(*core.Object); ok && !spectest.IsError(output) {
					jti = jsString(member(output.Get("claims"), "jti"))
				}
				result, err := func() (*core.Object, error) {
					audience, err := assertionAudience(request.Get("audience"))
					if err != nil {
						return nil, err
					}
					return issueAssertion(principal, tenant, sources, audience, request, int64(c.Input.Get("now").(float64)),
						jsString(c.Input.Get("baseURL")), key, func() string { return jti })
				}()
				spectest.Check(t, c, spectest.Outcome(result, err))
				if err == nil {
					// The issued token verifies with the derived key.
					claims, err := VerifyAssertion(result.Get("token"), VerifyAssertionOptions{Key: key, Audience: jsString(request.Get("audience")), Now: float(c.Input.Get("now").(float64))})
					if err != nil || core.MustStringify(claims) != core.MustStringify(result.Get("claims")) {
						t.Fatalf("round trip: %v", err)
					}
				}
				return
			}
			verified++
			options, _ := c.Input.Object("options")
			verify := VerifyAssertionOptions{Key: options.Get("key"), Audience: jsString(options.Get("audience"))}
			if issuer, ok := options.Get("issuer").(string); ok {
				verify.Issuer = &issuer
			}
			if now, ok := options.Get("now").(float64); ok {
				verify.Now = &now
			}
			if tolerance, ok := options.Get("toleranceSeconds").(float64); ok {
				verify.ToleranceSeconds = &tolerance
			}
			claims, err := VerifyAssertion(c.Input.Get("token"), verify)
			spectest.Check(t, c, spectest.Outcome(claims, err))
		})
	}
	if issued != 11 || verified != 17 {
		t.Fatalf("ran %d issue and %d verify cases", issued, verified)
	}
}

func TestVerifyAssertionRejectsNonStrings(t *testing.T) {
	_, err := VerifyAssertion(5.0, VerifyAssertionOptions{Key: AssertionKey("s"), Audience: "svc"})
	expectError(t, err, "INVALID_ASSERTION", "Malformed assertion")
	_, err = VerifyAssertion(assertionHeader+".e30.x", VerifyAssertionOptions{Key: 5.0, Audience: "svc"})
	expectError(t, err, "INVALID_ASSERTION", "Invalid verification key")
	if assertionHeader != "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" {
		t.Fatal(assertionHeader)
	}
}

func TestIssueAssertionRefusesPrototypeNames(t *testing.T) {
	principal := &Principal{Identity: core.NewObject("id", "i", "name", "n"), Session: core.NewObject("kind", "user", "mfa", false)}
	sources := func() (*GrantSources, error) { return &GrantSources{}, nil }
	_, err := issueAssertion(principal, core.NewObject("id", "t"), sources, "svc", parse(t, `{"claims":{"toString":1}}`).(*core.Object), 0, "https://iam", AssertionKey("s"), ID)
	expectError(t, err, "INVALID_INPUT", "claims cannot redefine toString")
	result := must(issueAssertion(principal, core.NewObject("id", "t"), sources, "svc", core.NewObject(), 1_000_000, "https://iam", AssertionKey("s"), ID))
	claims := result.Get("claims").(*core.Object)
	if core.MustStringify(claims.Get("roles")) != "[]" || core.MustStringify(claims.Get("groups")) != "[]" || result.Get("expiresAt") != 1300.0*1000 {
		t.Fatal(core.MustStringify(result))
	}
}
