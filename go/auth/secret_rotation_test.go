package auth

// The authentication part of tests/secret-rotation.test.ts: values sealed and links issued under a previous secret
// keep working while it is listed in PreviousSecrets (re-sealing, rotateSecrets, is the server's).

import (
	"context"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

const (
	oldSecret   = "rotation-test-old-secret-with-plenty-of-characters-1"
	newSecret   = "rotation-test-new-secret-with-plenty-of-characters-2"
	otherSecret = "rotation-test-unrelated-secret-with-many-characters-3"
)

func TestSecretRotationKeepsSealedValuesAndLinksWorking(t *testing.T) {
	f := orgFixture(t, func(o *Options) { o.Secret = oldSecret })
	instance := func(secret string, previous ...string) *Service {
		options := f.auth.Options()
		options.Secret, options.PreviousSecrets = secret, previous
		return must[*Service](t)(New(options))
	}
	f.identity("root", true, "root@example.test")
	credential := MfaCredential{TenantID: "root", Challenge: challengeOf(t, f.signIn("root", "root@example.test", testPassword))}
	enrollment := must[*core.Object](t)(f.auth.BeginMfa(f.ctx, credential))
	secret := str(enrollment, "secret")
	confirmed := must[*core.Object](t)(f.auth.ConfirmMfa(f.ctx, ConfirmMfaInput{Credential: credential, Code: f.totp(secret)}))
	must[*core.Object](t)(f.auth.RequestPasswordReset(f.ctx, core.NewObject("tenantId", "root", "email", "root@example.test")))

	f.advance(60_000)
	during := instance(newSecret, oldSecret)
	// Sessions are hashed without the secret: nobody is signed out by the rotation itself.
	must[*core.Object](t)(during.GetSession(f.ctx, token(str(confirmed, "token"))))
	if result, err := during.DispatchOutbox(f.ctx, 100); err != nil || result.Delivered != 1 {
		t.Fatalf("dispatch %+v %v", result, err)
	}
	reset := f.lastMessage("password-reset").Payload["token"]
	must[*core.Object](t)(during.ResetPassword(f.ctx, core.NewObject("tenantId", "root", "token", reset, "password", "a rotated root test password")))
	f.advance(60_000)
	signInRoot := func(service *Service) (*core.Object, error) {
		challenge, err := service.SignIn(f.ctx, core.NewObject("tenantId", "root", "email", "root@example.test", "password", "a rotated root test password"))
		if err != nil {
			return nil, err
		}
		return service.VerifyMfa(f.ctx, core.NewObject("tenantId", "root", "challenge", challengeOf(t, challenge), "code", f.totp(secret)))
	}
	session(t, must[*core.Object](t)(signInRoot(during)))
	// New values are sealed with the current secret only.
	must[*core.Object](t)(during.RequestPasswordReset(f.ctx, core.NewObject("tenantId", "root", "email", "root@example.test")))
	pending := 0
	for _, message := range f.find("outbox", core.NewObject("template", "password-reset")) {
		sealed := str(child(message, "payload"), "sealed")
		if sealed == "" {
			continue
		}
		pending++
		if _, ok := OpenSecret(sealed, []string{oldSecret}, "outbox:"+str(message, "id")); ok {
			t.Error("a new value was sealed with the previous secret")
		}
		if _, ok := OpenSecret(sealed, []string{newSecret}, "outbox:"+str(message, "id")); !ok {
			t.Error("a new value does not open with the current secret")
		}
	}
	if pending != 1 {
		t.Fatalf("%d pending messages", pending)
	}

	// The authenticator secret is still sealed with OLD: without it listed, MFA cannot be checked.
	f.advance(60_000)
	after := instance(newSecret)
	_, err := signInRoot(after)
	expectCode(t, err, "INVALID_SEALED_VALUE")
	// Re-sealed (as rotateSecrets does), the deployment runs on the new secret alone.
	f.update("authMfa", str(child(confirmed, "session"), "identityId"), func(record *core.Object) {
		plain, err := DecryptSecret(str(record, "encryptedSecret"), []string{oldSecret}, "mfa:"+str(record, "identityId"))
		if err != nil {
			t.Fatal(err)
		}
		record.Set("encryptedSecret", EncryptSecret(plain, newSecret, "mfa:"+str(record, "identityId")))
	})
	f.advance(30_000)
	session(t, must[*core.Object](t)(signInRoot(after)))
	if result, err := after.DispatchOutbox(f.ctx, 100); err != nil || result.Delivered != 1 {
		t.Fatalf("dispatch on the new secret %+v %v", result, err)
	}
}

func TestPreviousSecretsAreValidated(t *testing.T) {
	store := newStore(t)
	defer store.Close(context.Background())
	for _, previous := range [][]string{
		{"short"},
		{newSecret},
		{oldSecret, oldSecret},
		{oldSecret, otherSecret, oldSecret + "a", oldSecret + "b", oldSecret + "c", oldSecret + "d"},
	} {
		_, err := New(Options{Store: store, Secret: newSecret, PreviousSecrets: previous, BaseURL: "http://localhost:3000"})
		if err == nil || !strings.Contains(err.Error(), "previousSecrets") {
			t.Errorf("%v accepted: %v", previous, err)
		}
	}
	if _, err := New(Options{Store: store, Secret: "too short", BaseURL: "http://localhost:3000"}); err == nil {
		t.Error("a short secret was accepted")
	}
	service := must[*Service](t)(New(Options{Store: store, Secret: newSecret, PreviousSecrets: []string{oldSecret}, BaseURL: "http://localhost:3000"}))
	if strings.Join(service.Secrets, ",") != newSecret+","+oldSecret {
		t.Errorf("secrets %v", service.Secrets)
	}
}
