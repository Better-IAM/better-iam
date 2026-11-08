package configfile_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Better-IAM/better-iam/go/configfile"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

// An application loads the file `better-iam init` writes ("cli" member included): the relative SQLite path resolves
// against Cwd, {"env": NAME} reads Env, and the instance works once initialized.
func TestLoadBuildsTheInstanceAConfigurationFileDescribes(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	document := `{
  "store": { "kind": "sqlite", "path": "./iam.db" },
  "baseURL": "http://localhost:3000",
  "secret": { "env": "APP_IAM_SECRET" },
  "cli": { "defaults": { "sweep": { "retention-days": 30 } } }
}`
	if err := os.WriteFile(filepath.Join(directory, "better-iam.json"), []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	options := configfile.Options{Cwd: directory, Env: map[string]string{"APP_IAM_SECRET": "configfile-test-secret-with-at-least-32-characters"}}
	iam, err := configfile.Load(ctx, "better-iam.json", options)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = iam.Store.Close(ctx) }()
	defer iam.Close()
	if err := iam.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := iam.Bootstrap(ctx, core.NewObject("email", "root@example.test", "name", "Root", "password", "a strong root test password")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory, "iam.db")); err != nil {
		t.Fatalf("the SQLite path did not resolve against Cwd: %v", err)
	}

	// The reader's refusals are the standalone reader's.
	_, err = configfile.Parse([]byte(`{"baseURL":"http://localhost:3000","secret":{"env":"MISSING"}}`), configfile.Options{Env: map[string]string{}})
	if known, ok := err.(*core.IamError); !ok || known.Message != "Invalid better-iam.json: secret names environment variable MISSING, which is not set" {
		t.Fatalf("refusal: %v", err)
	}
	if _, err := configfile.LoadOptions("missing.json", options); !os.IsNotExist(err) {
		t.Fatalf("missing file: %v", err)
	}

	// Adapters plug into the standalone reader too.
	standalone, err := server.LoadStandaloneConfig([]byte(`{"baseURL":"http://localhost:3000","secret":"configfile-test-secret-with-at-least-32-characters"}`),
		server.ConfigRuntime{Adapters: configfile.Adapters(directory)})
	if err != nil {
		t.Fatal(err)
	}
	_ = standalone.Database.Close(ctx)
}
