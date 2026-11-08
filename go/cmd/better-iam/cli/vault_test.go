package cli

// Port of tests/vault-cli.test.ts.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

// TestHelperProcess is the child vault-run starts in these tests: it writes its environment to the file named by
// VAULT_RUN_DUMP and exits with VAULT_RUN_EXIT.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	if dump := os.Getenv("VAULT_RUN_DUMP"); dump != "" {
		env := map[string]string{}
		for _, entry := range os.Environ() {
			for index := 0; index < len(entry); index++ {
				if entry[index] == '=' && index > 0 {
					env[entry[:index]] = entry[index+1:]
					break
				}
			}
		}
		data, _ := json.Marshal(env)
		_ = os.WriteFile(dump, data, 0o600)
	}
	if os.Getenv("VAULT_RUN_EXIT") == "3" {
		os.Exit(3)
	}
	os.Exit(0)
}

type vaultDeployment struct {
	folder   string
	config   string
	tenantID string
	r        *recorder
	env      map[string]string
}

// newVaultDeployment is a migrated deployment with one organization, its owner's token, and three secrets.
func newVaultDeployment(t *testing.T) *vaultDeployment {
	folder := t.TempDir()
	config := writeJSONConfig(t, folder, "better-iam.json")
	setup := newRecorder(folder)
	mustRun(t, []string{"migrate", "--config", config}, setup.io(rootEnv))
	mustRun(t, []string{"bootstrap", "--config", config}, setup.io(rootEnv))
	rootID := at(setup.last(t), "tenant", "id").(string)
	f := organizationAt(t, filepath.Join(folder, "iam.db"), rootID, rootEnv["BETTER_IAM_ROOT_EMAIL"], rootEnv["BETTER_IAM_ROOT_PASSWORD"])
	callRoute(t, f.iam, f.owner, "vault/create", core.NewObject("tenantId", f.tenantID, "name", "app/db-password", "value", "the-database-password"))
	callRoute(t, f.iam, f.owner, "vault/create", core.NewObject("tenantId", f.tenantID, "name", "app/smtp", "format", "json",
		"fields", core.NewObject("host", "smtp.acme.test", "password", "mail-password")))
	callRoute(t, f.iam, f.owner, "vault/create", core.NewObject("tenantId", f.tenantID, "name", "app/signing-key", "value", "k1",
		"rotation", core.NewObject("intervalDays", 1.0, "generator", core.NewObject("length", 16.0))))
	return &vaultDeployment{folder: folder, config: config, tenantID: f.tenantID, r: newRecorder(folder),
		env: map[string]string{"BETTER_IAM_TOKEN": f.owner, "BETTER_IAM_TENANT": f.tenantID, "KEEP_ME": "yes"}}
}

func TestSecretEnvName(t *testing.T) {
	for _, item := range [][3]string{
		{"prod/app/db-password", "prod/app/", "DB_PASSWORD"},
		{"prod/app/v2.api-key", "prod/", "APP_V2_API_KEY"},
		{"prod/app/1st", "prod/app/", "_1ST"},
	} {
		if got := SecretEnvName(item[0], item[1]); got != item[2] {
			t.Fatalf("%s under %s is %s", item[0], item[1], got)
		}
	}
}

func TestVaultPutGetRun(t *testing.T) {
	d := newVaultDeployment(t)
	mustRun(t, []string{"vault-put", "app/db-password", "--config", d.config}, d.r.io(d.env, withStdin("rotated-by-cli\n")))
	if at(d.r.last(t), "version") != 2.0 || core.MustStringify(at(d.r.last(t), "stages")) != `["current"]` {
		t.Fatalf("put %s", d.r.lastLine(t))
	}
	mustRun(t, []string{"vault-get", "app/db-password", "--config", d.config}, d.r.io(d.env))
	if d.r.lastLine(t) != "rotated-by-cli" {
		t.Fatalf("get %s", d.r.lastLine(t))
	}
	mustRun(t, []string{"vault-get", "app/smtp", "--field", "host", "--config", d.config}, d.r.io(d.env))
	if d.r.lastLine(t) != "smtp.acme.test" {
		t.Fatalf("get %s", d.r.lastLine(t))
	}
	expectCode(t, run([]string{"vault-get", "app/smtp", "--field", "nope", "--config", d.config}, d.r.io(d.env)), "NOT_FOUND")
	expectCode(t, run([]string{"vault-get", "app/smtp", "--version", "1", "--stage", "current", "--config", d.config}, d.r.io(d.env)), "INVALID_ARGUMENT")

	dump := filepath.Join(d.folder, "env.json")
	child := merge(d.env, map[string]string{"GO_WANT_HELPER_PROCESS": "1", "VAULT_RUN_DUMP": dump})
	mustRun(t, []string{"vault-run", "--config", d.config, "--env", "DATABASE_PASSWORD=app/db-password,MAIL_HOST=app/smtp#host",
		"--prefix", "app/", "--", os.Args[0], "-test.run=TestHelperProcess"}, d.r.io(child))
	data, err := os.ReadFile(dump)
	if err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"DATABASE_PASSWORD": "rotated-by-cli", "MAIL_HOST": "smtp.acme.test", "DB_PASSWORD": "rotated-by-cli",
		"SMTP_HOST": "smtp.acme.test", "SMTP_PASSWORD": "mail-password", "SIGNING_KEY": "k1", "KEEP_ME": "yes",
	} {
		if env[key] != want {
			t.Fatalf("%s is %q, want %q", key, env[key], want)
		}
	}
	// The IAM token does not travel to the child.
	if _, ok := env["BETTER_IAM_TOKEN"]; ok {
		t.Fatal("the token reached the child")
	}

	// The command's exit status comes back.
	err = run([]string{"vault-run", "--config", d.config, "--env", "X=app/db-password", "--", os.Args[0], "-test.run=TestHelperProcess"},
		d.r.io(merge(d.env, map[string]string{"GO_WANT_HELPER_PROCESS": "1", "VAULT_RUN_EXIT": "3"})))
	expectCode(t, err, "COMMAND_FAILED")
	if cliErr, ok := err.(*CliError); !ok || cliErr.ExitStatus != 3 {
		t.Fatalf("exit status %v", err)
	}
	expectCode(t, run([]string{"vault-run", "--config", d.config, "--", os.Args[0]}, d.r.io(d.env)), "INVALID_ARGUMENT")
	expectCode(t, run([]string{"vault-run", "--config", d.config, "--env", "1BAD=app/x", "--", os.Args[0]}, d.r.io(d.env)), "INVALID_ARGUMENT")
	expectCode(t, run([]string{"vault-run", "--config", d.config, "--env", "X=app/db-password", "--", filepath.Join(d.folder, "no-such-command")}, d.r.io(d.env)), "COMMAND_NOT_FOUND")
}

func TestVaultJobs(t *testing.T) {
	d := newVaultDeployment(t)
	mustRun(t, []string{"vault-rotate-due", "--config", d.config}, d.r.io(d.env))
	expectEqual(t, d.r.last(t), core.NewObject("rotated", []any{}, "failed", []any{}, "reminded", []any{}))
	mustRun(t, []string{"vault-expire-leases", "--config", d.config}, d.r.io(d.env))
	if at(d.r.last(t), "expired") != 0.0 {
		t.Fatalf("expire %s", d.r.lastLine(t))
	}
	mustRun(t, []string{"vault-purge-deleted", "--config", d.config}, d.r.io(d.env))
	expectEqual(t, d.r.last(t), core.NewObject("purged", 0.0))
}
