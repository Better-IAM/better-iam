package cli

// Port of packages/cli/src/tenant-config.ts.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

// TenantConfigContext is what a tenant-configuration factory receives: the tenant being planned or applied and the
// environment.
type TenantConfigContext = server.TenantConfigFactoryContext

var moduleExtensions = map[string]bool{".mjs": true, ".js": true, ".cjs": true, ".ts": true, ".mts": true}

// LoadTenantConfig reads a desired tenant configuration for config-plan / config-apply / config-validate: a JSON
// file. JavaScript/TypeScript modules (which the TypeScript CLI imports) cannot run in Go and are refused with
// CONFIG_LOAD_FAILED.
func LoadTenantConfig(path string, context TenantConfigContext) (any, error) {
	if moduleExtensions[strings.ToLower(filepath.Ext(path))] {
		return nil, NewCliError("CONFIG_LOAD_FAILED", "The Go better-iam CLI cannot load the JavaScript module "+path,
			"Write the tenant configuration as .json (better-iam config-export --output tenant.json), or run the TypeScript CLI (npx better-iam).")
	}
	text, err := os.ReadFile(path)
	if err != nil {
		return nil, systemError(err)
	}
	return core.ParseJSON(text)
}

// TenantConfigLint is the result of LintTenantConfig: valid, the item counts, and references to names the file
// does not define (they must already exist in the tenant, or planning fails).
type TenantConfigLint struct {
	Items    *core.Object
	Warnings []string
}

// Model is the lint as printed: { valid: true, items, warnings }.
func (l TenantConfigLint) Model() *core.Object {
	warnings := make([]any, len(l.Warnings))
	for index, warning := range l.Warnings {
		warnings[index] = warning
	}
	return core.NewObject("valid", true, "items", l.Items, "warnings", warnings)
}

func objectsOf(value any) []*core.Object {
	list, _ := value.([]any)
	out := make([]*core.Object, 0, len(list))
	for _, item := range list {
		if object, ok := item.(*core.Object); ok && object != nil {
			out = append(out, object)
		}
	}
	return out
}

func stringsOf(value any) []string {
	list, _ := value.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

// LintTenantConfig runs the offline checks: the shape (ValidateTenantConfig) plus cross-references between the
// file's own items.
func LintTenantConfig(value any) (TenantConfigLint, error) {
	config, err := server.ValidateTenantConfig(value)
	if err != nil {
		return TenantConfigLint{}, err
	}
	names := func(key string) map[string]bool {
		set := map[string]bool{}
		for _, item := range objectsOf(config.Get(key)) {
			if name, ok := item.Get("name").(string); ok {
				set[name] = true
			}
		}
		return set
	}
	policies, roles, groups := names("policies"), names("roles"), names("groups")
	warnings := []string{}
	expect := func(set map[string]bool, kind string, name any, where string) {
		text, ok := name.(string)
		if ok && !set[text] {
			warnings = append(warnings, where+" names "+kind+` "`+text+`", which this file does not define`)
		}
	}
	for _, role := range objectsOf(config.Get("roles")) {
		where := `Role "` + jsString(role.Get("name")) + `"`
		for _, policy := range stringsOf(role.Get("policies")) {
			expect(policies, "policy", policy, where)
		}
		for _, parent := range stringsOf(role.Get("inherits")) {
			expect(roles, "role", parent, where)
		}
	}
	for _, binding := range objectsOf(config.Get("bindings")) {
		where := "Binding " + jsString(binding.Get("group")) + " -> " + jsString(binding.Get("role"))
		expect(groups, "group", binding.Get("group"), where)
		expect(roles, "role", binding.Get("role"), where)
		expect(groups, "group", binding.Get("approverGroup"), where)
	}
	for _, item := range objectsOf(config.Get("packages")) {
		where := `Package "` + jsString(item.Get("name")) + `"`
		for _, role := range stringsOf(item.Get("roles")) {
			expect(roles, "role", role, where)
		}
		for _, group := range stringsOf(item.Get("groups")) {
			expect(groups, "group", group, where)
		}
		expect(groups, "group", item.Get("approverGroup"), where)
	}
	for _, invariant := range objectsOf(config.Get("invariants")) {
		if subject, ok := invariant.Get("subject").(*core.Object); ok && subject != nil && subject.Has("group") {
			expect(groups, "group", subject.Get("group"), `Invariant "`+jsString(invariant.Get("name"))+`"`)
		}
	}
	items := core.NewObject()
	for _, key := range []string{"resourceTypes", "policies", "roles", "groups", "bindings", "packages", "invariants", "agreements"} {
		if list, ok := config.Get(key).([]any); ok {
			items.Set(key, float64(len(list)))
		}
	}
	if accessPolicy := config.Get("accessPolicy"); accessPolicy != nil && !core.IsUndefined(accessPolicy) {
		items.Set("accessPolicy", 1.0)
	}
	return TenantConfigLint{Items: items, Warnings: warnings}, nil
}

var typescriptModule = regexp.MustCompile(`(?i)\.m?ts$`)

// tenantConfigModule is `config-export --output tenant.config.ts|mjs`: the configuration as a typed module instead
// of JSON.
func tenantConfigModule(config any, path string) string {
	body := stringifyIndented(jsonValue(config), "  ", "")
	pieces := regexp.MustCompile(`[\\/]`).Split(path, -1)
	name := pieces[len(pieces)-1]
	header := "// Generated by better-iam config-export. Apply it with: better-iam config-apply --input"
	if typescriptModule.MatchString(path) {
		return header + " " + name + "\nimport { defineTenantConfig } from 'better-iam/server';\n\nexport default defineTenantConfig(" + body + ");\n"
	}
	return header + " " + name + "\n/** @type {import('better-iam/server').TenantConfig} */\nexport default " + body + ";\n"
}
