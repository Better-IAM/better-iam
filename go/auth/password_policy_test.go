package auth

// Port of tests/password-policy.test.ts (the authentication service part; validating setAuthPolicy input and
// deleting history with an identity belong to the server port).

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestPasswordScreeningRules(t *testing.T) {
	for _, weak := range []string{"password1234", "P@ssw0rd1234", "aaaaaaaaaaaaaa", "abababababab", "qwertyuiopasdf", "abcdefghijklmnop",
		"987654321098", "Correct Horse Battery Staple"} {
		if !IsCommonPassword(weak) {
			t.Errorf("%q is not screened", weak)
		}
	}
	for _, fine := range []string{"a strong alice password", "twelve chars!", "Tr0ub4dor&3xyz"} {
		if IsCommonPassword(fine) {
			t.Errorf("%q is screened", fine)
		}
	}
	if CharacterClasses("abc") != 1 || CharacterClasses("aB3!") != 4 || CharacterClasses("a strong password") != 2 {
		t.Error("characterClasses")
	}
}

func TestPwnedPasswordsUsesKAnonymity(t *testing.T) {
	password := "a password from a breach"
	sum := sha1.Sum([]byte(password))
	digest := strings.ToUpper(hex.EncodeToString(sum[:]))
	var requested []string
	corpus := func(count string) *http.Client {
		return &http.Client{Transport: roundTrip(func(request *http.Request) (*http.Response, error) {
			requested = append(requested, request.URL.String())
			body := "0000000000000000000000000000000000A:1\r\n" + digest[5:] + ":" + count + "\r\n"
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{}}, nil
		})}
	}
	ctx := context.Background()
	if found, _ := PwnedPasswords(PwnedPasswordsOptions{Client: corpus("3")})(ctx, password); !found {
		t.Error("breached password not found")
	}
	if requested[0] != "https://api.pwnedpasswords.com/range/"+digest[:5] || strings.Contains(requested[0], digest[5:]) {
		t.Errorf("requested %s", requested[0])
	}
	ten := 10.0
	if found, _ := PwnedPasswords(PwnedPasswordsOptions{Client: corpus("3"), Threshold: &ten})(ctx, password); found {
		t.Error("threshold ignored")
	}
	if found, _ := PwnedPasswords(PwnedPasswordsOptions{Client: corpus("3")})(ctx, "an entirely different one"); found {
		t.Error("another password matched")
	}
	offline := &http.Client{Transport: roundTrip(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })}
	if found, err := PwnedPasswords(PwnedPasswordsOptions{Client: offline})(ctx, password); found || err != nil {
		t.Error("offline must fail open")
	}
	_, err := PwnedPasswords(PwnedPasswordsOptions{Client: offline, FailClosed: true})(ctx, password)
	if expectCode(t, err, "PASSWORD_CHECK_UNAVAILABLE").Status != 503 {
		t.Error("fail closed status")
	}
}

func (f *fixture) create(name, password string) error {
	email := strings.ToLower(strings.Join(strings.Fields(name), ".")) + "@acme.test"
	return f.store.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
		_, err := f.auth.CreateIdentity(ctx, tx, CreateIdentityInput{TenantID: "org", Email: email, Name: name, Password: password, HasPassword: true})
		return err
	})
}

func (f *fixture) setOrgPolicy(policy *core.Object) {
	f.update("tenants", "org", func(tenant *core.Object) { tenant.Set("authPolicy", policy) })
}

func TestDeploymentScreeningAppliesToEveryPasswordPath(t *testing.T) {
	f := orgFixture(t, func(o *Options) {
		o.PasswordPolicy = &PasswordPolicyOptions{
			IsBreached: func(_ context.Context, password string) (bool, error) {
				return password == "a breached but long password", nil
			},
			Check: func(_ context.Context, password string, context PasswordCheckContext) (string, error) {
				if strings.Contains(strings.ToLower(password), "acme") && context.TenantID != "" {
					return "Do not use the company name", nil
				}
				return "", nil
			},
		}
	})
	expectCode(t, f.create("Bob", "a breached but long password"), "BREACHED_PASSWORD")
	if err := expectCode(t, f.create("Bob", "my acme password is long"), "WEAK_PASSWORD"); err.Message != "Do not use the company name" {
		t.Errorf("message %s", err.Message)
	}
	expectCode(t, f.create("Bob", "password1234"), "WEAK_PASSWORD")
	if err := f.create("Bob", "a strong bob password"); err != nil {
		t.Fatal(err)
	}
	bob := session(t, f.signIn("org", "bob@acme.test", "a strong bob password"))
	_, err := f.auth.ChangePassword(f.ctx, token(bob), core.NewObject("currentPassword", "a strong bob password", "password", "a breached but long password"))
	expectCode(t, err, "BREACHED_PASSWORD")
}

func TestTenantComplexityAndPersonalInformationRules(t *testing.T) {
	f := orgFixture(t)
	f.setOrgPolicy(core.NewObject("passwordMinClasses", 3.0))
	expectCode(t, f.create("Dave", "a strong dave password"), "WEAK_PASSWORD")
	if err := f.create("Dave", "Strong Pass For D 42"); err != nil {
		t.Fatal(err)
	}
	f.setOrgPolicy(core.NewObject("passwordRejectPersonalInfo", true))
	expectCode(t, f.create("Erin Walsh", "walsh has a long password"), "WEAK_PASSWORD")
	expectCode(t, f.create("Frank", "my name is frank really"), "WEAK_PASSWORD")
	if err := f.create("Erin Walsh", "a long unrelated passphrase"); err != nil {
		t.Fatal(err)
	}
	f.setOrgPolicy(core.NewObject("minPasswordLength", 20.0))
	if err := expectCode(t, f.create("Gus", "only nineteen chars"), "WEAK_PASSWORD"); err.Message != "Password must contain at least 20 characters in this organization" {
		t.Errorf("message %s", err.Message)
	}
}

func TestPasswordHistoryRefusesReuseAndStaysBounded(t *testing.T) {
	f := orgFixture(t)
	f.setOrgPolicy(core.NewObject("passwordHistory", 2.0))
	if err := f.create("Alice", "first alice passphrase"); err != nil {
		t.Fatal(err)
	}
	change := func(from, to string) error {
		credential := token(session(t, f.signIn("org", "alice@acme.test", from)))
		_, err := f.auth.ChangePassword(f.ctx, credential, core.NewObject("currentPassword", from, "password", to))
		return err
	}
	if err := change("first alice passphrase", "second alice passphrase"); err != nil {
		t.Fatal(err)
	}
	if err := expectCode(t, change("second alice passphrase", "first alice passphrase"), "PASSWORD_REUSED"); err.Message != "Password must differ from your last 2 passwords" {
		t.Errorf("message %s", err.Message)
	}
	expectCode(t, change("second alice passphrase", "second alice passphrase"), "PASSWORD_REUSED")
	if err := change("second alice passphrase", "third alice passphrase"); err != nil {
		t.Fatal(err)
	}
	if err := change("third alice passphrase", "first alice passphrase"); err != nil {
		t.Fatal(err)
	}
	alice := f.find("identities", core.NewObject("email", "alice@acme.test"))[0]
	if history := f.find("passwordHistory", core.NewObject("identityId", alice.Get("id"))); len(history) != 3 {
		t.Fatalf("%d history rows", len(history))
	}
	if _, ok := num(alice, "passwordChangedAt"); !ok {
		t.Error("passwordChangedAt")
	}
	// The newest 24 previous hashes are kept.
	f.setOrgPolicy(core.NewObject())
	previous := "first alice passphrase"
	for index := 0; index < 24; index++ {
		next := "rotating alice passphrase " + itoa(index)
		f.advance(16 * 60_000) // past the sign-in and password-change rate limits
		if err := change(previous, next); err != nil {
			t.Fatal(err)
		}
		previous = next
	}
	if history := f.find("passwordHistory", core.NewObject("identityId", alice.Get("id"))); len(history) != 24 {
		t.Fatalf("%d history rows kept", len(history))
	}
}

func TestPasswordsExpireAndRecoverThroughReset(t *testing.T) {
	f := orgFixture(t)
	f.setOrgPolicy(core.NewObject("passwordMaxAgeDays", 30.0))
	if err := f.create("Gina", "a strong gina password"); err != nil {
		t.Fatal(err)
	}
	session(t, f.signIn("org", "gina@acme.test", "a strong gina password"))
	f.advance(31 * 86_400_000)
	_, err := f.auth.SignIn(f.ctx, core.NewObject("tenantId", "org", "email", "gina@acme.test", "password", "a strong gina password"))
	if expectCode(t, err, "PASSWORD_EXPIRED").Status != 403 {
		t.Error("PASSWORD_EXPIRED status")
	}
	_, err = f.auth.SignIn(f.ctx, core.NewObject("tenantId", "org", "email", "gina@acme.test", "password", "not the right password"))
	expectCode(t, err, "INVALID_CREDENTIALS")
	gina := f.find("identities", core.NewObject("email", "gina@acme.test"))[0]
	f.tx(func(ctx context.Context, tx core.IamStore) error { return f.auth.IssuePasswordReset(ctx, tx, gina) })
	f.dispatch()
	reset := f.lastMessage("password-reset").Payload["token"]
	must[*core.Object](t)(f.auth.ResetPassword(f.ctx, core.NewObject("tenantId", "org", "token", reset, "password", "a renewed gina password")))
	session(t, f.signIn("org", "gina@acme.test", "a renewed gina password"))
}
