package cli

// Port of tests/cli-remote.test.ts: the CLI against a running server (the fixture's HTTP handler through an injected
// fetch), with a private credentials file per test.

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

const testURL = "http://localhost:3000"

type harness struct {
	f           *organization
	folder      string
	credentials string
	r           *recorder
	hosts       *[]string
}

func newHarness(t *testing.T, f *organization) *harness {
	folder := t.TempDir()
	return &harness{f: f, folder: folder, credentials: filepath.Join(folder, "credentials.json"), r: newRecorder(folder)}
}

func (h *harness) io(env map[string]string, more ...func(*CliIO)) *CliIO {
	io := h.r.io(merge(map[string]string{"BETTER_IAM_CREDENTIALS": h.credentials}, env), more...)
	if io.Fetch == nil {
		io.Fetch = h.f.fetch(h.hosts)
	}
	return io
}

func (h *harness) run(argv []string, env map[string]string, more ...func(*CliIO)) error {
	return run(argv, h.io(env, more...))
}

type readerSetup struct {
	alice, bob           *core.Object
	aliceToken, bobToken string
}

func readers(t *testing.T, f *organization) readerSetup {
	role := callRoute(t, f.iam, f.owner, "roles/create", core.NewObject("tenantId", f.tenantID, "name", "Reader", "permissions", []any{"documents:read"}))
	group := callRoute(t, f.iam, f.owner, "groups/create", core.NewObject("tenantId", f.tenantID, "name", "Readers"))
	callRoute(t, f.iam, f.owner, "bindings/create", core.NewObject("tenantId", f.tenantID, "roleId", at(role, "id"), "subjectType", "group", "subjectId", at(group, "id")))
	alice := f.member(t, "alice")
	bob := f.member(t, "bob")
	callRoute(t, f.iam, f.owner, "groups/addMember", core.NewObject("tenantId", f.tenantID, "groupId", at(group, "id"), "identityId", alice.Get("id")))
	return readerSetup{alice: alice, bob: bob, aliceToken: f.signIn(t, "alice"), bobToken: f.signIn(t, "bob")}
}

func TestRemoteApiCalls(t *testing.T) {
	f := newOrganization(t)
	h := newHarness(t, f)
	asOwner := map[string]string{"BETTER_IAM_TOKEN": f.owner}
	tenant := []string{"--url", testURL, "--tenant", f.tenantID}
	with := func(argv ...string) []string { return append(argv, tenant...) }

	if err := h.run(with("api", "roles.create", "name=Reader", `permissions:=["documents:read"]`), asOwner); err != nil {
		t.Fatal(err)
	}
	if at(h.r.last(t), "name") != "Reader" || at(h.r.last(t), "tenantId") != f.tenantID {
		t.Fatalf("role %s", h.r.lastLine(t))
	}
	if err := h.run(with("api", "roles.list", "--query", "[].name"), asOwner); err != nil {
		t.Fatal(err)
	}
	expectContains(t, h.r.lastLine(t), "Reader")
	if err := h.run(with("api", "roles.list", "--format", "table"), asOwner); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^ID\s+TENANTID\s+NAME`).MatchString(h.r.lastLine(t)) {
		t.Fatalf("table %s", h.r.lastLine(t))
	}

	if err := os.WriteFile(filepath.Join(h.folder, "group.json"), []byte(`{"name":"Writers","description":"From a file"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := h.run(with("api", "groups.create", "--data", "@group.json"), asOwner); err != nil {
		t.Fatal(err)
	}
	if at(h.r.last(t), "name") != "Writers" || at(h.r.last(t), "description") != "From a file" {
		t.Fatalf("group %s", h.r.lastLine(t))
	}
	if err := h.run(with("api", "groups.create", "--data", "-", "description=Overridden"), asOwner, withStdin(`{"name":"Piped","description":"stdin"}`)); err != nil {
		t.Fatal(err)
	}
	if at(h.r.last(t), "name") != "Piped" || at(h.r.last(t), "description") != "Overridden" {
		t.Fatalf("group %s", h.r.lastLine(t))
	}

	// Top-level routes and nested keys; tenantId comes from --tenant.
	if err := h.run(with("api", "authorize", "action=documents:read", "resource.type=documents", "resource.id=a"), asOwner); err != nil {
		t.Fatal(err)
	}
	if _, ok := at(h.r.last(t), "allowed").(bool); !ok {
		t.Fatalf("authorize %s", h.r.lastLine(t))
	}

	// Public routes need no token at all.
	callRoute(t, f.iam, f.ownerSignIn(t), "tenants/setSlug", core.NewObject("tenantId", f.tenantID, "slug", "acme"))
	if err := h.run([]string{"api", "tenants.lookup", "slug=acme", "--url", testURL}, nil); err != nil {
		t.Fatal(err)
	}
	if at(h.r.last(t), "tenantId") != f.tenantID || at(h.r.last(t), "slug") != "acme" {
		t.Fatalf("lookup %s", h.r.lastLine(t))
	}

	// The route table, readable and machine-readable, without a token.
	if err := h.run([]string{"api", "--list", "roles", "--url", testURL}, nil); err != nil {
		t.Fatal(err)
	}
	expectContains(t, h.r.lastLine(t), "roles.create")
	expectContains(t, h.r.lastLine(t), "POST /api/iam/roles/create")
	if err := h.run([]string{"api", "--list", "--url", testURL, "--format", "json"}, nil); err != nil {
		t.Fatal(err)
	}
	expectContains(t, h.r.lastLine(t), `{
    "method": "tenants.lookup",
    "access": "public",
    "http": "POST /api/iam/tenants/lookup"
  }`)

	printed := len(h.r.output)
	for _, item := range []struct {
		argv []string
		code string
	}{
		{with("api", "roles.nope"), "NOT_FOUND"},
		{with("api", "roles"), "INVALID_ARGUMENT"},
		{with("api", "../etc"), "INVALID_ARGUMENT"},
		{with("api", "roles.create", "name"), "INVALID_ARGUMENT"},
		{with("api", "roles.create", "__proto__.polluted=1"), "INVALID_ARGUMENT"},
		{with("api", "roles.create", "limit:=not-json"), "INVALID_ARGUMENT"},
		{with("api", "roles.create", "--data", "[1]"), "INVALID_ARGUMENT"},
		{[]string{"api", "--list", "nothing", "--url", testURL}, "NOT_FOUND"},
		{[]string{"api", "roles.list", "--url", "ftp://example.test", "--tenant", f.tenantID}, "INVALID_ARGUMENT"},
	} {
		expectCode(t, h.run(item.argv, asOwner), item.code)
	}
	expectCode(t, h.run(with("api", "roles.list"), nil), "MISSING_ENV")
	if len(h.r.output) != printed {
		t.Fatal("a failed command printed")
	}
}

func TestRemoteAccessQuestions(t *testing.T) {
	f := newOrganization(t)
	h := newHarness(t, f)
	people := readers(t, f)
	tenant := []string{"--url", testURL, "--tenant", f.tenantID}
	with := func(argv ...string) []string { return append(argv, tenant...) }

	if err := h.run(with("can", "documents:read", "documents/a"), map[string]string{"BETTER_IAM_TOKEN": people.aliceToken}); err != nil {
		t.Fatal(err)
	}
	if at(h.r.last(t), "allowed") != true {
		t.Fatal("alice may read")
	}
	expectCode(t, h.run(with("can", "documents:read", "documents:a"), map[string]string{"BETTER_IAM_TOKEN": people.bobToken}), "ACCESS_DENIED")
	if at(h.r.last(t), "allowed") != false {
		t.Fatal("the denied decision is printed")
	}
	expectCode(t, h.run(with("can", "documents:read", "no-separator"), map[string]string{"BETTER_IAM_TOKEN": people.bobToken}), "INVALID_ARGUMENT")
	expectCode(t, h.run(with("can", "documents:read"), map[string]string{"BETTER_IAM_TOKEN": people.bobToken}), "INVALID_ARGUMENT")

	asOwner := map[string]string{"BETTER_IAM_TOKEN": f.owner}
	if err := h.run(with("explain", "documents:read", "documents/a", "--identity", "bob@acme.test"), asOwner); err != nil {
		t.Fatal(err)
	}
	if at(h.r.last(t), "allowed") != false {
		t.Fatal("bob may not read")
	}
	if err := h.run(with("explain", "documents:read", "documents/a", "--identity", people.alice.Get("id").(string)), asOwner); err != nil {
		t.Fatal(err)
	}
	if at(h.r.last(t), "allowed") != true {
		t.Fatal("alice may read")
	}
	expectCode(t, h.run(with("explain", "documents:read", "documents/a", "--identity", "nobody@acme.test"), asOwner), "NOT_FOUND")

	if err := h.run(with("who-can", "documents:read", "documents/a", "--query", "identities[].identityId"), asOwner); err != nil {
		t.Fatal(err)
	}
	holders := core.MustStringify(h.r.last(t))
	expectContains(t, holders, people.alice.Get("id").(string))
	if strings.Contains(holders, people.bob.Get("id").(string)) {
		t.Fatal("bob is listed")
	}
}

func TestRemoteLoginAndProfiles(t *testing.T) {
	f := newOrganization(t)
	h := newHarness(t, f)
	people := readers(t, f)
	password := map[string]string{"BETTER_IAM_PASSWORD": "a strong alice password"}
	login := []string{"login", "--url", testURL, "--tenant", f.tenantID, "--email", "alice@acme.test"}

	expectCode(t, h.run(login, nil), "MISSING_ENV")
	expectCode(t, h.run(login, map[string]string{"BETTER_IAM_PASSWORD": "not her password at all"}), "INVALID_CREDENTIALS")
	if err := h.run(login, password); err != nil {
		t.Fatal(err)
	}
	if at(h.r.last(t), "profile") != "default" || at(h.r.last(t), "url") != testURL+"/api/iam" ||
		at(h.r.last(t), "tenantId") != f.tenantID || at(h.r.last(t), "identityId") != people.alice.Get("id") {
		t.Fatalf("login %s", h.r.lastLine(t))
	}
	text, _ := os.ReadFile(h.credentials)
	file, _ := core.ParseJSON(text)
	if at(file, "version") != 1.0 || at(file, "current") != "default" || at(file, "profiles", "default", "email") != "alice@acme.test" ||
		at(file, "profiles", "default", "kind") != "user" {
		t.Fatalf("credentials %s", text)
	}
	if strings.Contains(string(text), "a strong alice password") {
		t.Fatal("the password was saved")
	}
	savedToken := at(file, "profiles", "default", "token").(string)
	if strings.Contains(strings.Join(h.r.output, "\n"), savedToken) {
		t.Fatal("the token was printed")
	}

	// No token, URL, or tenant: the profile supplies all three.
	if err := h.run([]string{"whoami"}, nil); err != nil {
		t.Fatal(err)
	}
	if at(h.r.last(t), "identityId") != people.alice.Get("id") || at(h.r.last(t), "tenantId") != f.tenantID {
		t.Fatalf("whoami %s", h.r.lastLine(t))
	}
	if err := h.run([]string{"can", "documents:read", "documents/a"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.run([]string{"token"}, nil); err != nil {
		t.Fatal(err)
	}
	if h.r.lastLine(t) != savedToken {
		t.Fatal("token printed another token")
	}

	// A second profile from a token on standard input.
	if err := h.run([]string{"login", "--with-token", "--url", testURL, "--profile", "ops"}, nil, withStdin(f.ownerSignIn(t)+"\n")); err != nil {
		t.Fatal(err)
	}
	if at(h.r.last(t), "profile") != "ops" || at(h.r.last(t), "identityId") != f.ownerID {
		t.Fatalf("login %s", h.r.lastLine(t))
	}
	for _, item := range []struct {
		argv []string
		env  map[string]string
		id   any
	}{
		{[]string{"whoami"}, nil, f.ownerID},
		{[]string{"whoami", "--profile", "default"}, nil, people.alice.Get("id")},
		{[]string{"whoami"}, map[string]string{"BETTER_IAM_PROFILE": "default"}, people.alice.Get("id")},
	} {
		if err := h.run(item.argv, item.env); err != nil {
			t.Fatal(err)
		}
		if at(h.r.last(t), "identityId") != item.id {
			t.Fatalf("%v acted as %v", item.argv, at(h.r.last(t), "identityId"))
		}
	}
	if err := h.run([]string{"profiles", "--format", "json"}, nil); err != nil {
		t.Fatal(err)
	}
	listed := h.r.last(t)
	if at(listed, "0", "name") != "default" || at(listed, "0", "current") != false || at(listed, "1", "name") != "ops" || at(listed, "1", "current") != true {
		t.Fatalf("profiles %s", h.r.lastLine(t))
	}
	if strings.Contains(h.r.lastLine(t), "token") {
		t.Fatal("profiles printed a token")
	}
	if err := h.run([]string{"profiles"}, nil); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`NAME\s+CURRENT`).MatchString(h.r.lastLine(t)) {
		t.Fatalf("profiles table %s", h.r.lastLine(t))
	}

	// An explicit token wins over every profile.
	if err := h.run([]string{"whoami", "--url", testURL}, map[string]string{"BETTER_IAM_TOKEN": f.signIn(t, "bob")}); err != nil {
		t.Fatal(err)
	}
	if at(h.r.last(t), "identityId") == f.ownerID {
		t.Fatal("the profile beat BETTER_IAM_TOKEN")
	}

	if err := h.run([]string{"profiles", "use", "default"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.run([]string{"logout"}, nil); err != nil {
		t.Fatal(err)
	}
	expectEqual(t, h.r.last(t), core.NewObject("profile", "default", "revoked", true, "forgotten", true))
	expectCode(t, h.run([]string{"whoami", "--url", testURL}, map[string]string{"BETTER_IAM_TOKEN": savedToken}), "UNAUTHENTICATED")
	expectCode(t, h.run([]string{"whoami"}, nil), "MISSING_ENV")
	if err := h.run([]string{"profiles", "use", "ops"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.run([]string{"whoami"}, nil); err != nil {
		t.Fatal(err)
	}
	expectCode(t, h.run([]string{"profiles", "use", "missing"}, nil), "NOT_FOUND")
	expectCode(t, h.run([]string{"profiles", "use", "../escape"}, nil), "INVALID_ARGUMENT")
	expectCode(t, h.run([]string{"logout", "--profile", "missing"}, nil), "NOT_FOUND")

	// A saved session past its end is refused before any request.
	text, _ = os.ReadFile(h.credentials)
	saved, _ := core.ParseJSON(text)
	at(saved, "profiles", "ops").(*core.Object).Set("expiresAt", 1.0)
	if err := os.WriteFile(h.credentials, []byte(core.MustStringify(saved)), 0o600); err != nil {
		t.Fatal(err)
	}
	expectCode(t, h.run([]string{"whoami"}, nil), "SESSION_EXPIRED")
	if err := h.run([]string{"profiles", "remove", "ops"}, nil); err != nil {
		t.Fatal(err)
	}
	expectEqual(t, h.r.last(t), core.NewObject("removed", "ops"))

	// Organizations by slug.
	callRoute(t, f.iam, f.ownerSignIn(t), "tenants/setSlug", core.NewObject("tenantId", f.tenantID, "slug", "acme"))
	if err := h.run([]string{"login", "--url", testURL, "--org", "acme", "--email", "bob@acme.test"}, map[string]string{"BETTER_IAM_PASSWORD": "a strong bob password"}); err != nil {
		t.Fatal(err)
	}
	if at(h.r.last(t), "tenantId") != f.tenantID || at(h.r.last(t), "profile") != "default" {
		t.Fatalf("login by slug %s", h.r.lastLine(t))
	}
	expectCode(t, h.run([]string{"login", "--url", testURL, "--org", "acme", "--tenant", f.tenantID}, password), "INVALID_ARGUMENT")
}

func TestRemoteSessionsStayWithTheirDeployment(t *testing.T) {
	f := newOrganization(t)
	h := newHarness(t, f)
	readers(t, f)
	hosts := []string{}
	h.hosts = &hosts
	password := map[string]string{"BETTER_IAM_PASSWORD": "a strong alice password"}
	if err := h.run([]string{"login", "--url", testURL, "--tenant", f.tenantID, "--email", "alice@acme.test"}, password); err != nil {
		t.Fatal(err)
	}
	hosts = hosts[:0]
	for _, item := range []struct {
		argv []string
		env  map[string]string
	}{
		{[]string{"whoami", "--url", "http://other.localhost:3000"}, nil},
		{[]string{"api", "roles.list"}, map[string]string{"BETTER_IAM_URL": "http://other.localhost:3000"}},
		{[]string{"whoami", "--url", testURL + "/other/base"}, nil},
	} {
		err := h.run(item.argv, item.env)
		expectCode(t, err, "MISSING_ENV")
		expectContains(t, hintOf(err), "belongs to http://localhost:3000/api/iam")
	}
	if len(hosts) != 0 {
		t.Fatalf("a request went out: %v", hosts)
	}
	// The same server written differently is the same deployment.
	if err := h.run([]string{"whoami", "--url", "http://localhost:3000/api/iam/"}, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Join(hosts, ",") != "localhost:3000" {
		t.Fatalf("hosts %v", hosts)
	}

	// A login elsewhere never replaces the saved session silently; it needs its own profile name.
	bob := map[string]string{"BETTER_IAM_PASSWORD": "a strong bob password"}
	expectCode(t, h.run([]string{"login", "--url", "http://other.localhost:3000", "--tenant", f.tenantID, "--email", "bob@acme.test"}, bob), "PROFILE_IN_USE")
	if strings.Join(hosts, ",") != "localhost:3000" {
		t.Fatalf("hosts %v", hosts)
	}
	if err := h.run([]string{"login", "--url", "http://other.localhost:3000", "--tenant", f.tenantID, "--email", "bob@acme.test", "--profile", "other"}, bob); err != nil {
		t.Fatal(err)
	}
	if at(h.r.last(t), "profile") != "other" || at(h.r.last(t), "url") != "http://other.localhost:3000/api/iam" {
		t.Fatalf("login %s", h.r.lastLine(t))
	}

	// Environment defaults never conflict with what the command line says.
	if err := h.run([]string{"login", "--with-token", "--url", testURL, "--profile", "ci"}, map[string]string{"BETTER_IAM_TENANT": "ignored"}, withStdin(f.signIn(t, "bob"))); err != nil {
		t.Fatal(err)
	}
	if at(h.r.last(t), "profile") != "ci" || at(h.r.last(t), "tenantId") != f.tenantID {
		t.Fatalf("login %s", h.r.lastLine(t))
	}
	callRoute(t, f.iam, f.ownerSignIn(t), "tenants/setSlug", core.NewObject("tenantId", f.tenantID, "slug", "acme"))
	if err := h.run([]string{"login", "--url", testURL, "--org", "acme", "--email", "alice@acme.test", "--profile", "default"},
		merge(password, map[string]string{"BETTER_IAM_TENANT": "not-a-tenant"})); err != nil {
		t.Fatal(err)
	}
	if at(h.r.last(t), "tenantId") != f.tenantID {
		t.Fatalf("login %s", h.r.lastLine(t))
	}

	// Clear text is for local development only.
	token := map[string]string{"BETTER_IAM_TOKEN": strings.Repeat("x", 43)}
	expectCode(t, h.run([]string{"whoami", "--url", "http://iam.example.test"}, token), "INVALID_ARGUMENT")
	expectCode(t, h.run([]string{"whoami", "--url", testURL, "--config", "x.json"}, token), "INVALID_ARGUMENT")

	// Enrolling an authenticator for your own session goes through api with your token.
	if err := h.run([]string{"api", "auth.beginMfa", "--profile", "default"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := at(h.r.last(t), "secret").(string); !ok {
		t.Fatalf("beginMfa %s", h.r.lastLine(t))
	}
}

func TestRemoteEmailedMfaCode(t *testing.T) {
	f := newOrganization(t)
	h := newHarness(t, f)
	alice := f.member(t, "alice")
	ctx := context.Background()
	// Emailed codes go to verified addresses only.
	err := f.iam.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		realm, err := tx.Get(ctx, "tenants", f.tenantID)
		if err != nil {
			return err
		}
		if _, err := tx.Put(ctx, "tenants", realm.Clone().Set("authPolicy", core.NewObject("requireMfa", true, "mfaEmailCodes", true))); err != nil {
			return err
		}
		person, err := tx.Get(ctx, "identities", alice.Get("id").(string))
		if err != nil {
			return err
		}
		_, err = tx.Put(ctx, "identities", person.Clone().Set("emailVerified", true))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	login := []string{"login", "--url", testURL, "--tenant", f.tenantID, "--email", "alice@acme.test"}
	password := map[string]string{"BETTER_IAM_PASSWORD": "a strong alice password"}
	expectCode(t, h.run(login, password), "MFA_ENROLLMENT_REQUIRED")

	var questions []string
	prompt := func(io *CliIO) {
		io.Prompt = func(question string, hidden bool) (string, error) {
			questions = append(questions, question)
			if _, err := f.iam.Auth.DispatchOutbox(ctx, 0); err != nil {
				return "", err
			}
			code := ""
			f.mu.Lock()
			for _, message := range f.inbox {
				if message.Template == "mfa-code" {
					code = message.Payload["code"]
				}
			}
			f.mu.Unlock()
			return code, nil
		}
	}
	if err := h.run(append(login, "--email-code"), password, prompt); err != nil {
		t.Fatal(err)
	}
	if strings.Join(questions, "|") != "Emailed code: " {
		t.Fatalf("questions %v", questions)
	}
	if at(h.r.last(t), "identityId") != alice.Get("id") {
		t.Fatalf("login %s", h.r.lastLine(t))
	}
	if err := h.run([]string{"whoami"}, nil); err != nil {
		t.Fatal(err)
	}
	if at(h.r.last(t), "identityId") != alice.Get("id") || at(h.r.last(t), "mfa") != true {
		t.Fatalf("whoami %s", h.r.lastLine(t))
	}
}
