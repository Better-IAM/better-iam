package server

// Port of packages/server/src/define.ts.

import (
	"context"
	"os"
	"strings"
)

// IamConfigContext is what a configuration factory receives when the better-iam CLI (or your code) calls it.
type IamConfigContext struct {
	// Command is the CLI command being run (migrate, api, a project command); "" when your server calls the factory.
	Command string
	Env     map[string]string
	Cwd     string
}

// IamConfigFactory computes a deployment configuration on demand, so loading it has no side effects.
type IamConfigFactory func(ctx context.Context, config IamConfigContext) (*BetterIamOptions, error)

// IamConfig is a deployment configuration: options, or a factory of them.
type IamConfig interface {
	*BetterIamOptions | IamConfigFactory
}

// DefineConfig types a deployment configuration; it returns its argument unchanged.
func DefineConfig[T IamConfig](config T) T { return config }

// ProcessConfigContext is the default context: this process's environment and working directory.
func ProcessConfigContext() IamConfigContext {
	env := map[string]string{}
	for _, entry := range os.Environ() {
		if name, value, ok := strings.Cut(entry, "="); ok && name != "" {
			env[name] = value
		}
	}
	cwd, _ := os.Getwd()
	return IamConfigContext{Env: env, Cwd: cwd}
}

// ConfigOptions are the options a DefineConfig value stands for: a factory is called with configContext (nil: the
// process environment and working directory), plain options are returned as they are.
func ConfigOptions[T IamConfig](ctx context.Context, config T, configContext *IamConfigContext) (*BetterIamOptions, error) {
	switch value := any(config).(type) {
	case IamConfigFactory:
		if configContext == nil {
			defaults := ProcessConfigContext()
			configContext = &defaults
		}
		return value(ctx, *configContext)
	case *BetterIamOptions:
		return value, nil
	}
	return nil, nil
}

// TenantConfigFactoryContext is what a tenant-configuration factory receives from config-plan / config-apply.
type TenantConfigFactoryContext struct {
	// TenantID is the tenant being planned or applied (--tenant).
	TenantID string
	Env      map[string]string
}

// DefineTenantConfig types a tenant's configuration as code (a TenantConfig of sync.go, or a factory of one); it
// returns its argument unchanged.
func DefineTenantConfig[T any](config T) T { return config }
