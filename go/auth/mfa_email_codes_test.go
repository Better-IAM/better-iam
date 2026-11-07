package auth

// Port of tests/mfa-email-codes.test.ts.

import (
	"context"
	"regexp"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

type emailCodeFixture struct {
	*fixture
}

func newEmailCodeFixture(t *testing.T, deploymentDefault *bool) *emailCodeFixture {
	f := orgFixture(t, func(o *Options) {
		if deploymentDefault != nil {
			o.MfaEmailCodes = *deploymentDefault
		}
	})
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		if _, err := f.auth.CreateIdentity(ctx, tx, CreateIdentityInput{TenantID: "root", Email: "alice@example.test", Name: "Alice",
			Password: "a strong alice password", HasPassword: true, EmailVerified: true}); err != nil {
			return err
		}
		_, err := f.auth.CreateIdentity(ctx, tx, CreateIdentityInput{TenantID: "root", Email: "root@example.test", Name: "Root",
			Password: "a strong root test password", HasPassword: true, EmailVerified: true, RootAdmin: true})
		return err
	})
	return &emailCodeFixture{f}
}

func (f *emailCodeFixture) setPolicy(policy *core.Object) {
	f.update("tenants", "root", func(tenant *core.Object) {
		tenant.Delete("authPolicy")
		if policy != nil {
			tenant.Set("authPolicy", policy)
		}
	})
}

func (f *emailCodeFixture) signInAs(email, password string) *core.Object {
	return must[*core.Object](f.t)(f.auth.SignIn(f.ctx, core.NewObject("tenantId", "root", "email", email, "password", password)))
}

func (f *emailCodeFixture) alice() *core.Object {
	return f.signInAs("alice@example.test", "a strong alice password")
}

func (f *emailCodeFixture) lastCode() string {
	return f.lastMessage("mfa-code").Payload["code"]
}

func (f *emailCodeFixture) request(challenge string) (*core.Object, error) {
	return f.auth.RequestMfaCode(f.ctx, core.NewObject("tenantId", "root", "challenge", challenge))
}

func (f *emailCodeFixture) verify(challenge, code string, remember ...bool) (*core.Object, error) {
	input := core.NewObject("tenantId", "root", "challenge", challenge, "code", code)
	if len(remember) > 0 {
		input.Set("rememberDevice", remember[0])
	}
	return f.auth.VerifyMfa(f.ctx, input)
}

func TestEmailedCodeCompletesRequiredMfaOnce(t *testing.T) {
	f := newEmailCodeFixture(t, nil)
	f.setPolicy(core.NewObject("requireMfa", true))
	plain := f.alice()
	if !isTrue(plain, "enrollmentRequired") || plain.Has("emailCodeAvailable") {
		t.Fatalf("plain %s", core.MustStringify(plain))
	}
	_, err := f.request(challengeOf(t, plain))
	expectCode(t, err, "FEATURE_DISABLED")
	f.setPolicy(core.NewObject("requireMfa", true, "mfaEmailCodes", true))
	offered := f.alice()
	if !isTrue(offered, "enrollmentRequired") || !isTrue(offered, "emailCodeAvailable") {
		t.Fatalf("offered %s", core.MustStringify(offered))
	}
	challenge := challengeOf(t, offered)
	_, err = f.verify(challenge, "000000")
	expectCode(t, err, "MFA_NOT_ENROLLED")
	requested := must[*core.Object](t)(f.request(challenge))
	if numOr(requested, "expiresAt", 0) > float64(f.now()+5*60_000) || !isTrue(requested, "success") {
		t.Errorf("requested %s", core.MustStringify(requested))
	}
	f.dispatch()
	code := f.lastCode()
	if !regexp.MustCompile(`^\d{6}$`).MatchString(code) {
		t.Fatalf("code %q", code)
	}
	other := "111111"
	if code == other {
		other = "222222"
	}
	_, err = f.verify(challenge, other)
	expectCode(t, err, "INVALID_MFA")
	must[*core.Object](t)(f.request(challenge))
	f.dispatch()
	fresh := f.lastCode()
	if fresh != code {
		_, err = f.verify(challenge, code)
		expectCode(t, err, "INVALID_MFA")
	}
	result := must[*core.Object](t)(f.verify(challenge, fresh, true))
	if !isTrue(child(result, "session"), "mfa") || !result.Has("deviceToken") {
		t.Errorf("result %s", core.MustStringify(result))
	}
	_, err = f.verify(challenge, fresh)
	expectCode(t, err, "INVALID_CHALLENGE")
	later := challengeOf(t, f.alice())
	timed := must[*core.Object](t)(f.request(later))
	if numOr(timed, "expiresAt", 0) > float64(f.now()+5*60_000) {
		t.Error("a code outlives its challenge")
	}
	f.dispatch()
	expiring := f.lastCode()
	f.advance(5*60_000 + 1_000)
	_, err = f.verify(later, expiring)
	expectCode(t, err, "INVALID_CHALLENGE")
}

func TestEmailedCodesNeverReplaceAuthenticatorsOrRootFactors(t *testing.T) {
	on := true
	f := newEmailCodeFixture(t, &on)
	f.setPolicy(core.NewObject("requireMfa", true))
	alice := f.alice()
	if !isTrue(alice, "emailCodeAvailable") {
		t.Fatalf("alice %s", core.MustStringify(alice))
	}
	root := f.signInAs("root@example.test", "a strong root test password")
	if root.Has("emailCodeAvailable") {
		t.Error("root was offered an emailed code")
	}
	_, err := f.request(challengeOf(t, root))
	expectCode(t, err, "FEATURE_DISABLED")
	must[*core.Object](t)(f.request(str(alice, "challenge")))
	f.dispatch()
	first := must[*core.Object](t)(f.verify(str(alice, "challenge"), f.lastCode()))
	credential := MfaCredential{Credentials: &core.CredentialInput{Token: str(first, "token")}}
	enrollment := must[*core.Object](t)(f.auth.BeginMfa(f.ctx, credential))
	must[*core.Object](t)(f.auth.ConfirmMfa(f.ctx, ConfirmMfaInput{Credential: credential, Code: f.totp(str(enrollment, "secret"))}))
	enrolled := f.alice()
	if flag(enrolled, "enrollmentRequired") || enrolled.Has("emailCodeAvailable") {
		t.Fatalf("enrolled %s", core.MustStringify(enrolled))
	}
	_, err = f.request(str(enrolled, "challenge"))
	expectCode(t, err, "FEATURE_DISABLED")
	f.setPolicy(core.NewObject("requireMfa", true, "mfaEmailCodes", false))
	f.tx(func(ctx context.Context, tx core.IamStore) error {
		return tx.Delete(ctx, "authMfa", str(child(first, "session"), "identityId"))
	})
	if off := f.alice(); off.Has("emailCodeAvailable") {
		t.Error("the tenant could not switch the deployment default off")
	}
}
