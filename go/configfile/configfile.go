// Package configfile loads a better-iam.json configuration file (spec/conformance/CONFIG.md) in an application:
// the Go counterpart of loadConfig, which the TypeScript CLI package exports (packages/cli/src/config.ts, also
// `better-iam/cli`) so an application can build the instance its CLI configuration describes.
//
//	iam, err := configfile.Load(ctx, "better-iam.json", configfile.Options{})
//	if err != nil { ... }
//	defer iam.Store.Close(ctx)
//	defer iam.Close()
//
// The TypeScript loader imports a JavaScript module; a Go program reads the JSON form every implementation shares,
// with the store adapters the better-iam CLI uses (Adapters). Like the TypeScript loader, which ignores the module's
// named `cli` export, Load and LoadOptions ignore the "cli" member the Go CLI keeps its flag defaults in, so the file
// `better-iam init` writes loads as it is. (The standalone server, better-iam-server, refuses that member.)
package configfile

import (
	"context"
	"net/http"
	"os"
	"path/filepath"

	"github.com/Better-IAM/better-iam/go/adapters/libsql"
	"github.com/Better-IAM/better-iam/go/adapters/postgres"
	"github.com/Better-IAM/better-iam/go/adapters/sqlite"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

// Options configure Load and LoadOptions; empty fields default to the process's.
type Options struct {
	// Cwd is the directory a relative configuration path and relative SQLite store paths resolve against ("": the
	// working directory).
	Cwd string
	// Env resolves {"env": "NAME"} references (nil: the process environment).
	Env map[string]string
	// Log writes `log` deliveries (nil: a line on stdout).
	Log func(line string)
	// HTTPClient sends `http` deliveries (nil: http.DefaultClient).
	HTTPClient *http.Client
}

// Adapters are the store adapters a configuration's "store" member names (sqlite, postgres, libsql), as the
// better-iam CLI opens them: relative SQLite paths resolve against cwd ("": the working directory). Pass them as
// server.ConfigRuntime.Adapters to read a configuration with server.LoadStandaloneConfig or OptionsFromConfig.
func Adapters(cwd string) server.ConfigAdapters {
	return server.ConfigAdapters{
		SQLite: func(store server.StoreConfig) (core.IamStore, error) {
			path := store.Path
			if path == "" {
				path = ":memory:"
			}
			if path != ":memory:" {
				path = resolvePath(cwd, path)
			}
			return storeOf(sqlite.New(sqlite.Options{Filename: path, BusyTimeoutMs: store.BusyTimeoutMs, JournalMode: store.JournalMode, Durability: store.Durability}))
		},
		Postgres: func(store server.StoreConfig) (core.IamStore, error) {
			return storeOf(postgres.New(postgres.Options{ConnectionString: store.URL, PoolSize: store.PoolSize, LockTimeoutMs: store.LockTimeoutMs}))
		},
		LibSQL: func(store server.StoreConfig) (core.IamStore, error) {
			return storeOf(libsql.New(libsql.Options{URL: store.URL, AuthToken: store.AuthToken, EncryptionKey: store.EncryptionKey, SyncURL: store.SyncURL, SyncInterval: store.SyncInterval}))
		},
	}
}

// Parse reads a better-iam.json document into options (the database opened); a "cli" member is ignored.
func Parse(data []byte, options Options) (*server.BetterIamOptions, error) {
	parsed, err := core.ParseJSON(data)
	if err != nil {
		return nil, err
	}
	if object, ok := parsed.(*core.Object); ok && object != nil && object.Has("cli") {
		object = object.Clone()
		object.Delete("cli")
		parsed = object
	}
	return server.OptionsFromConfig(parsed, server.ConfigRuntime{
		Adapters: Adapters(options.Cwd), Env: options.Env, Log: options.Log, HTTPClient: options.HTTPClient,
	})
}

// LoadOptions reads the configuration file at path into options (the database opened); a "cli" member is ignored.
func LoadOptions(path string, options Options) (*server.BetterIamOptions, error) {
	data, err := os.ReadFile(resolvePath(options.Cwd, path))
	if err != nil {
		return nil, err
	}
	return Parse(data, options)
}

// Load creates the instance the configuration file at path describes (loadConfig({ config: path })), closing the
// database it opened when creation fails. Like the TypeScript instance, it is not initialized (call Initialize to run
// the migrations) and its Close leaves the store open: close iam.Store yourself.
func Load(ctx context.Context, path string, options Options) (*server.BetterIam, error) {
	configuration, err := LoadOptions(path, options)
	if err != nil {
		return nil, err
	}
	iam, err := server.New(configuration)
	if err != nil {
		if configuration.Database != nil {
			_ = configuration.Database.Close(ctx)
		}
		return nil, err
	}
	return iam, nil
}

func resolvePath(cwd, value string) string {
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	if absolute, err := filepath.Abs(cwd); err == nil {
		cwd = absolute
	}
	return filepath.Join(cwd, value)
}

// storeOf keeps a failed constructor's typed nil out of the interface.
func storeOf[T core.IamStore](store T, err error) (core.IamStore, error) {
	if err != nil {
		return nil, err
	}
	return store, nil
}
