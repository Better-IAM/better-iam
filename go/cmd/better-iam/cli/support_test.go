package cli

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/adapters/sqlite"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

const testSecret = "cli-go-testing-secret-with-32-characters!"

var rootEnv = map[string]string{
	"BETTER_IAM_ROOT_EMAIL":    "root@example.test",
	"BETTER_IAM_ROOT_NAME":     "Root",
	"BETTER_IAM_ROOT_PASSWORD": "a strong cli root password",
}

func merge(maps ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range maps {
		for key, value := range m {
			out[key] = value
		}
	}
	return out
}

type recorder struct {
	mu     sync.Mutex
	output []string
	notes  []string
	cwd    string
}

func newRecorder(cwd string) *recorder { return &recorder{cwd: cwd} }

func (r *recorder) io(env map[string]string, more ...func(*CliIO)) *CliIO {
	if env == nil {
		env = map[string]string{}
	}
	io := &CliIO{
		Out: func(message string) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.output = append(r.output, message)
		},
		Err: func(message string) {
			r.mu.Lock()
			defer r.mu.Unlock()
			r.notes = append(r.notes, message)
		},
		Env: env,
		Cwd: r.cwd,
	}
	if r.cwd == "" {
		io.Cwd, _ = os.Getwd()
	}
	for _, apply := range more {
		apply(io)
	}
	return io
}

func (r *recorder) lastLine(t *testing.T) string {
	t.Helper()
	if len(r.output) == 0 {
		t.Fatal("nothing was printed")
	}
	return r.output[len(r.output)-1]
}

func (r *recorder) last(t *testing.T) any {
	t.Helper()
	parsed, err := core.ParseJSONString(r.lastLine(t))
	if err != nil {
		t.Fatalf("last output is not JSON: %v\n%s", err, r.lastLine(t))
	}
	return parsed
}

func (r *recorder) lastObject(t *testing.T) *core.Object {
	t.Helper()
	object, ok := r.last(t).(*core.Object)
	if !ok {
		t.Fatalf("last output is not an object: %s", r.lastLine(t))
	}
	return object
}

func withStdin(text string) func(*CliIO) {
	return func(io *CliIO) { io.Stdin = func() (string, error) { return text, nil } }
}

func run(argv []string, io *CliIO) error { return RunCli(context.Background(), argv, io) }

func mustRun(t *testing.T, argv []string, io *CliIO) {
	t.Helper()
	if err := run(argv, io); err != nil {
		t.Fatalf("better-iam %s: %v", strings.Join(argv, " "), err)
	}
}

func codeOf(err error) string {
	if err == nil {
		return ""
	}
	code, _ := errorCode(err)
	return code
}

func expectCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got success", code)
	}
	if got := codeOf(err); got != code {
		t.Fatalf("expected %s, got %s: %v", code, got, err)
	}
}

func hintOf(err error) string {
	var cliErr *CliError
	if errors.As(err, &cliErr) {
		return cliErr.Hint
	}
	return ""
}

// at walks a JSON value by keys and indexes ("0").
func at(value any, keys ...string) any {
	for _, key := range keys {
		switch typed := value.(type) {
		case *core.Object:
			value = typed.Get(key)
		case []any:
			index := 0
			for _, c := range key {
				index = index*10 + int(c-'0')
			}
			if index >= len(typed) {
				return core.Undefined
			}
			value = typed[index]
		default:
			return core.Undefined
		}
	}
	return value
}

func expectEqual(t *testing.T, got, want any) {
	t.Helper()
	left, right := core.MustStringify(jsonValue(got)), core.MustStringify(jsonValue(want))
	if left != right {
		t.Fatalf("got %s, want %s", left, right)
	}
}

func expectContains(t *testing.T, text, fragment string) {
	t.Helper()
	if !strings.Contains(text, fragment) {
		t.Fatalf("%q does not contain %q", text, fragment)
	}
}

// writeJSONConfig writes a better-iam.json on its own SQLite file in folder, with extra top-level members.
func writeJSONConfig(t *testing.T, folder, name string, extra ...any) string {
	t.Helper()
	document := core.NewObject(
		"store", core.NewObject("kind", "sqlite", "path", filepath.Join(folder, "iam.db")),
		"secret", testSecret,
		"baseURL", "http://localhost:3000",
		"permissions", core.NewObject("actions", []any{"documents:read"}),
	)
	for index := 0; index+1 < len(extra); index += 2 {
		document.Set(extra[index].(string), extra[index+1])
	}
	path := filepath.Join(folder, name)
	if err := os.WriteFile(path, []byte(core.MustStringify(document)), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func callRoute(t *testing.T, iam *server.BetterIam, token, route string, input *core.Object) any {
	t.Helper()
	answer, err := LocalTransport(iam, "test", token).Call(context.Background(), route, input)
	if err != nil {
		t.Fatalf("%s: %v", route, err)
	}
	return answer
}

// rootMfaSession signs root in with a password and enrolls TOTP, returning the session token.
func rootMfaSession(t *testing.T, iam *server.BetterIam, tenantID, email, password string) string {
	t.Helper()
	challenge := callRoute(t, iam, "", "auth/signIn", core.NewObject("tenantId", tenantID, "email", email, "password", password))
	if at(challenge, "mfaRequired") != true {
		t.Fatal("root must require MFA")
	}
	code := at(challenge, "challenge").(string)
	enrollment := callRoute(t, iam, "", "auth/beginMfa", core.NewObject("tenantId", tenantID, "challenge", code))
	totp, err := auth.GenerateTotp(at(enrollment, "secret").(string), time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	session := callRoute(t, iam, "", "auth/confirmMfa", core.NewObject(
		"credential", core.NewObject("tenantId", tenantID, "challenge", code), "code", totp))
	return at(session, "token").(string)
}

// rootSession migrates and bootstraps a configuration through the CLI, then signs root in with MFA (a separate
// connection).
func rootSession(t *testing.T, config string) (string, string) {
	t.Helper()
	r := newRecorder(filepath.Dir(config))
	mustRun(t, []string{"migrate", "--config", config}, r.io(rootEnv))
	mustRun(t, []string{"bootstrap", "--config", config}, r.io(rootEnv))
	tenantID := at(r.last(t), "tenant", "id").(string)
	iam, err := LoadConfig(context.Background(), LoadConfigOptions{Config: config, Env: map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	defer closeInstance(context.Background(), iam)
	return tenantID, rootMfaSession(t, iam, tenantID, rootEnv["BETTER_IAM_ROOT_EMAIL"], rootEnv["BETTER_IAM_ROOT_PASSWORD"])
}

// organization is the Go counterpart of tests/support/organization.ts: an instance with a root administrator, an
// organization with an owner, and an inbox.
type organization struct {
	iam      *server.BetterIam
	mu       sync.Mutex
	inbox    []auth.DeliveryMessage
	rootID   string
	root     string
	tenantID string
	owner    string
	ownerID  string
	clock    atomic.Int64
}

func newOrganization(t *testing.T, mutate ...func(*server.BetterIamOptions)) *organization {
	return organizationAt(t, ":memory:", "", "root@example.test", "a strong root test password", mutate...)
}

// organizationAt builds the fixture on a database file; with rootID, the database was already migrated and
// bootstrapped (by the CLI) with that root tenant and root's email and password.
func organizationAt(t *testing.T, filename, rootID, rootEmail, rootPassword string, mutate ...func(*server.BetterIamOptions)) *organization {
	t.Helper()
	ctx := context.Background()
	store, err := sqlite.New(sqlite.Options{Filename: filename})
	if err != nil {
		t.Fatal(err)
	}
	f := &organization{}
	week := int64(7 * 86400000)
	options := &server.BetterIamOptions{
		Database:    store,
		Secret:      testSecret,
		BaseURL:     "http://localhost:3000",
		Permissions: &core.PermissionsConfig{Actions: []string{"documents:read", "documents:write"}},
		ResolveResource: func(_ context.Context, reference core.ResourceRef) (*server.ResolvedResource, error) {
			return &server.ResolvedResource{TenantID: reference.TenantID, Type: reference.Type, ID: reference.ID}, nil
		},
		Authentication: &auth.Options{
			SendEmail: func(_ context.Context, message auth.DeliveryMessage) error {
				f.mu.Lock()
				defer f.mu.Unlock()
				f.inbox = append(f.inbox, message)
				return nil
			},
			SessionLifetimeMs:    &week,
			SessionIdleTimeoutMs: &week,
			Now:                  f.now,
		},
		WallClock: f.now,
	}
	for _, apply := range mutate {
		apply(options)
	}
	iam, err := server.New(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeInstance(context.Background(), iam) })
	f.iam = iam
	f.rootID = rootID
	if rootID == "" {
		if err := iam.Initialize(ctx); err != nil {
			t.Fatal(err)
		}
		rootTenant, err := iam.Bootstrap(ctx, core.NewObject("email", rootEmail, "name", "Root", "password", rootPassword))
		if err != nil {
			t.Fatal(err)
		}
		f.rootID = at(rootTenant, "tenant", "id").(string)
	}
	f.root = rootMfaSession(t, iam, f.rootID, rootEmail, rootPassword)
	created := callRoute(t, iam, f.root, "tenants/create", core.NewObject("parentId", f.rootID, "name", "Acme",
		"type", "organization", "ownerEmail", "owner@acme.test"))
	f.tenantID = at(created, "tenant", "id").(string)
	if _, err := iam.Auth.DispatchOutbox(ctx, 0); err != nil {
		t.Fatal(err)
	}
	invitation := ""
	for _, message := range f.inbox {
		if message.TenantID == f.tenantID && message.Template == "owner-invitation" {
			invitation = message.Payload["token"]
		}
	}
	owner := callRoute(t, iam, "", "tenants/acceptInvitation", core.NewObject("tenantId", f.tenantID, "token", invitation,
		"name", "Owner", "password", "a strong tenant owner password"))
	f.owner = at(owner, "token").(string)
	f.ownerID = at(callRoute(t, iam, f.owner, "auth/getSession", nil), "identity", "id").(string)
	return f
}

func (f *organization) member(t *testing.T, name string) *core.Object {
	t.Helper()
	return callRoute(t, f.iam, f.owner, "identities/create", core.NewObject("tenantId", f.tenantID,
		"email", name+"@acme.test", "name", name, "password", "a strong "+name+" password")).(*core.Object)
}

func (f *organization) signIn(t *testing.T, name string) string {
	t.Helper()
	result := callRoute(t, f.iam, "", "auth/signIn", core.NewObject("tenantId", f.tenantID, "email", name+"@acme.test",
		"password", "a strong "+name+" password"))
	return at(result, "token").(string)
}

func (f *organization) ownerSignIn(t *testing.T) string {
	t.Helper()
	result := callRoute(t, f.iam, "", "auth/signIn", core.NewObject("tenantId", f.tenantID, "email", "owner@acme.test",
		"password", "a strong tenant owner password"))
	return at(result, "token").(string)
}

// fetch serves remote CLI calls with the instance's HTTP handler, as a running server would.
func (f *organization) fetch(hosts *[]string) func(*http.Request) (*http.Response, error) {
	return func(request *http.Request) (*http.Response, error) {
		if hosts != nil {
			*hosts = append(*hosts, request.URL.Host)
		}
		recorder := httptest.NewRecorder()
		f.iam.ServeHTTP(recorder, request)
		return recorder.Result(), nil
	}
}

// now is the fixture's clock (both server clocks): real time plus what advance added.
func (f *organization) now() int64 { return time.Now().UnixMilli() + f.clock.Load() }

// advance moves the fixture's clock forward.
func (f *organization) advance(ms int64) { f.clock.Add(ms) }
