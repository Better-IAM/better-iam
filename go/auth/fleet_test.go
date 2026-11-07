package auth

// Mixed fleet: the TypeScript auth service (testdata/fleet.mjs) and the Go one take turns on one SQLite file. Each
// side signs in with the other's password hashes, sessions, sealed authenticator secrets, remembered devices,
// passkeys (stored COSE keys), outbox messages and challenge links, and the audit chain they extend together
// verifies on both sides. Skipped when Node or the built workspace is unavailable, unless BETTER_IAM_FLEET=required.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"

	"github.com/Better-IAM/better-iam/go/adapters/sqlite"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/spectest"
)

const (
	fleetSecret = "fleet-test-secret-with-at-least-32-characters"
	fleetNow    = int64(1767225600000)
)

func fleetNode() string {
	if node := os.Getenv("BETTER_IAM_NODE"); node != "" {
		return node
	}
	return "node"
}

func runFleet(t *testing.T, args ...string) *core.Object {
	t.Helper()
	root, err := spectest.Root()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	command := exec.Command(fleetNode(), append([]string{filepath.Join(root, "go", "auth", "testdata", "fleet.mjs")}, args...)...)
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		message := "fleet script failed: " + err.Error() + "\n" + stderr.String()
		if args[0] == "create" && os.Getenv("BETTER_IAM_FLEET") != "required" {
			t.Skip(message + "\n(set BETTER_IAM_NODE to a Node with the workspace built; BETTER_IAM_FLEET=required makes this fatal)")
		}
		t.Fatal(message)
	}
	parsed, err := core.ParseJSON(bytes.TrimSpace(stdout.Bytes()))
	if err != nil {
		t.Fatalf("fleet output: %v\n%s", err, stdout.String())
	}
	return parsed.(*core.Object)
}

func importedAuthenticator(t *testing.T, credentialID, pkcs8 string) *virtualAuthenticator {
	t.Helper()
	der, _ := base64.StdEncoding.DecodeString(pkcs8)
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := base64.RawURLEncoding.DecodeString(credentialID)
	return &virtualAuthenticator{credentialID: id, key: key.(*ecdsa.PrivateKey), rpHash: sha256.Sum256([]byte("iam.example.com")), origin: "https://iam.example.com"}
}

func TestMixedFleetWithTheTypeScriptAuthService(t *testing.T) {
	file := filepath.Join(t.TempDir(), "fleet.db")
	ts := runFleet(t, "create", file)
	store, err := sqlite.New(sqlite.Options{Filename: file})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	clock := fleetNow + 60_000
	var inbox []DeliveryMessage
	service := must[*Service](t)(New(Options{
		Store: store, Secret: fleetSecret, BaseURL: "https://iam.example.com",
		SendEmail: func(_ context.Context, message DeliveryMessage) error { inbox = append(inbox, message); return nil },
		Passkeys:  &PasskeyOptions{RPID: "iam.example.com"},
		Now:       func() int64 { return clock },
	}))
	code := func(secret string) string { return must[string](t)(GenerateTotp(secret, clock)) }
	signIn := func(email, password string, extra ...any) *core.Object {
		input := core.NewObject("tenantId", "org", "email", email, "password", password)
		for index := 0; index+1 < len(extra); index += 2 {
			input.Set(extra[index].(string), extra[index+1])
		}
		return must[*core.Object](t)(service.SignIn(ctx, input))
	}
	aliceID := str(ts, "identityId")
	tsSecret := str(ts, "totpSecret")

	// TypeScript's session, password hash, sealed authenticator secret, device and recovery codes work in Go.
	if principal := must[*Principal](t)(service.Authenticate(ctx, token(str(ts, "sessionToken")))); str(principal.Identity, "id") != aliceID || !isTrue(principal.Session, "mfa") {
		t.Fatalf("TypeScript session %s", core.MustStringify(principal.Session))
	}
	if !strings_HasPrefix(str(ts, "passwordHash"), "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Fatalf("TypeScript hash %s", str(ts, "passwordHash"))
	}
	challenge := challengeOf(t, signIn("alice@example.test", "alice typescript password"))
	must[*core.Object](t)(service.VerifyMfa(ctx, core.NewObject("tenantId", "org", "challenge", challenge, "code", code(tsSecret))))
	remembered := signIn("alice@example.test", "alice typescript password", "deviceToken", str(ts, "deviceToken"))
	if str(child(remembered, "session"), "trustedDeviceId") == "" {
		t.Fatal("the TypeScript device did not vouch")
	}
	recovery := challengeOf(t, signIn("alice@example.test", "alice typescript password"))
	must[*core.Object](t)(service.RecoverMfa(ctx, core.NewObject("tenantId", "org", "challenge", recovery, "code", ts.Get("recoveryCodes").([]any)[0])))
	// TypeScript's passkey (its stored COSE key) verifies a Go-made assertion.
	passkey := child(ts, "passkey")
	tsKey := importedAuthenticator(t, str(passkey, "credentialId"), str(passkey, "pkcs8"))
	begun := must[*core.Object](t)(service.BeginPasskeyAuthentication(ctx, core.NewObject("tenantId", "org", "email", "alice@example.test")))
	passkeySession := must[*core.Object](t)(service.FinishPasskeyAuthentication(ctx, core.NewObject("tenantId", "org", "challengeId", begun.Get("challengeId"),
		"response", tsKey.assert(str(child(begun, "options"), "challenge"), aliceID))))
	if str(child(passkeySession, "session"), "method") != "passkey" {
		t.Fatal("passkey session")
	}
	// TypeScript's sealed outbox message is delivered by Go, and its reset link (TypeScript's digest) works.
	if result := must[DispatchResult](t)(service.DispatchOutbox(ctx, 100)); result.Delivered != 1 {
		t.Fatalf("dispatch %+v", result)
	}
	if len(inbox) != 1 || inbox[0].Template != "password-reset" {
		t.Fatalf("inbox %+v", inbox)
	}
	must[*core.Object](t)(service.ResetPassword(ctx, core.NewObject("tenantId", "org", "token", inbox[0].Payload["token"], "password", "alice reset by go")))
	clock += 30_000
	challenge = challengeOf(t, signIn("alice@example.test", "alice reset by go"))
	must[*core.Object](t)(service.VerifyMfa(ctx, core.NewObject("tenantId", "org", "challenge", challenge, "code", code(tsSecret))))

	// Go writes Bob: a Go argon2 hash, a Go-sealed authenticator, a remembered device, a passkey, a queued reset.
	bob := must[*core.Object](t)(core.Transact(ctx, store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return service.CreateIdentity(ctx, tx, CreateIdentityInput{TenantID: "org", Email: "bob@example.test", Name: "Bob",
			Password: "bob go password long", HasPassword: true, EmailVerified: true})
	}))
	first := session(t, signIn("bob@example.test", "bob go password long"))
	credential := MfaCredential{Credentials: &core.CredentialInput{Token: first}}
	enrollment := must[*core.Object](t)(service.BeginMfa(ctx, credential))
	enabled := must[*core.Object](t)(service.ConfirmMfa(ctx, ConfirmMfaInput{Credential: credential, Code: code(str(enrollment, "secret")), RememberDevice: true}))
	bobKey := newVirtualAuthenticator("iam.example.com", "https://iam.example.com")
	registration := must[*core.Object](t)(service.BeginPasskeyRegistration(ctx, token(str(enabled, "token"))))
	must[*core.Object](t)(service.FinishPasskeyRegistration(ctx, token(str(enabled, "token")), core.NewObject("challengeId", registration.Get("challengeId"),
		"response", bobKey.register(str(child(registration, "options"), "challenge")))))
	must[*core.Object](t)(service.RequestPasswordReset(ctx, core.NewObject("tenantId", "org", "email", "bob@example.test")))
	service.SettleBookkeeping()
	if err := store.Close(ctx); err != nil {
		t.Fatal(err)
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(bobKey.key)
	goState := core.NewObject(
		"now", float64(clock),
		"bob", core.NewObject(
			"identityId", bob.Get("id"),
			"password", "bob go password long",
			"sessionToken", enabled.Get("token"),
			"totpSecret", enrollment.Get("secret"),
			"deviceToken", enabled.Get("deviceToken"),
			"passkey", core.NewObject("credentialId", bobKey.id(), "pkcs8", base64.StdEncoding.EncodeToString(pkcs8)),
		),
		"alice", core.NewObject("password", "alice reset by go", "totpSecret", tsSecret),
	)
	goFile := filepath.Join(t.TempDir(), "go.json")
	if err := os.WriteFile(goFile, []byte(core.MustStringify(goState)), 0o600); err != nil {
		t.Fatal(err)
	}

	// TypeScript uses what Go wrote.
	checks := runFleet(t, "verify", file, goFile)
	want := map[string]any{"goSession": "bob@example.test", "goTotp": true, "goDevice": true, "goPasskey": "passkey", "goReset": true, "alice": true}
	for key, value := range want {
		if !core.StrictEquals(checks.Get(key), value) {
			t.Errorf("%s: %s", key, core.MustStringify(checks.Get(key)))
		}
	}
	if delivered := numOr(child(checks, "dispatch"), "delivered", 0); delivered != 1 {
		t.Errorf("TypeScript delivered %v Go-sealed messages", delivered)
	}
	if chain := child(checks, "chain"); !isTrue(chain, "valid") || numOr(chain, "checked", 0) != numOr(checks, "events", -1) {
		t.Errorf("audit chain %s", core.MustStringify(chain))
	}
	// And the chain verifies in Go too.
	reopened := must[*sqlite.Store](t)(sqlite.New(sqlite.Options{Filename: file}))
	defer reopened.Close(ctx)
	events := must[[]*core.Object](t)(reopened.Find(ctx, "audit", core.NewObject("tenantId", "org"), nil))
	sort.Slice(events, func(i, j int) bool { return numOr(events[i], "sequence", 0) < numOr(events[j], "sequence", 0) })
	head := must[*core.Object](t)(reopened.Get(ctx, "auditChains", "org"))
	result := core.VerifyAuditChain(events, core.VerifyAuditChainOptions{Head: &core.AuditChainHeadRef{Sequence: numOr(head, "sequence", 0), Hash: str(head, "hash")}})
	if !result.Valid || result.Checked != len(events) {
		t.Errorf("Go chain verification %+v", result)
	}
}

func strings_HasPrefix(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
