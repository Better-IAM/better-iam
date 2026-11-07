package server

// Port of packages/server/src/plugins.ts.

import (
	"regexp"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

var pluginPathPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*$`)

// ValidatePlugins validates plugins once at construction: unique IDs, registered actions, and well-formed POST
// endpoints.
func ValidatePlugins(plugins []*core.IamPlugin, catalog *Catalog) error {
	ids := map[string]bool{}
	for _, plugin := range plugins {
		ids[plugin.ID] = true
	}
	if len(ids) != len(plugins) {
		return invalidConfig("Duplicate plugin ID")
	}
	for _, plugin := range plugins {
		if plugin.ValidateConfig != nil {
			if err := plugin.ValidateConfig(); err != nil {
				return err
			}
		}
		paths := map[string]bool{}
		for _, endpoint := range plugin.Endpoints {
			if !catalog.Actions.Has(endpoint.Action) {
				return invalidConfig("Plugin endpoint action must be registered")
			}
			path := strings.TrimPrefix(endpoint.Path, "/")
			valid := endpoint.Method == "POST" && pluginPathPattern.MatchString(path) && !paths[path] &&
				endpoint.Validate != nil && endpoint.Handler != nil
			if !valid {
				return invalidConfig("Plugin endpoints require unique paths, POST, validation, and a handler")
			}
			paths[path] = true
		}
	}
	return nil
}
