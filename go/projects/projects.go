// Package projects is the reference Projects plugin of better-iam (port of packages/projects/src/index.ts):
// tenant-scoped project records.
//
//	iam, err := server.New(&server.BetterIamOptions{
//		// ...
//		Plugins: []*core.IamPlugin{projects.NewPlugin()},
//	})
//
// Registering the plugin adds the projects:read and projects:write actions to the action catalog and mounts
// POST {basePath}/plugins/projects/{create|list|get|update|archive|restore}. Every endpoint runs in the server's
// transactional authorization service: root override, tenant scope, ancestry boundaries, policies and audit records
// apply unchanged. Project records live in the projects collection and never cross tenants.
package projects

import (
	"context"
	"crypto/rand"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

// Collection is the collection holding project records.
const Collection = "projects"

const (
	nameMaxLength        = 100
	descriptionMaxLength = 500
)

// Project is a tenant-scoped project record owned by this plugin (a typed view of the stored record).
type Project struct {
	ID          string  `json:"id"`
	TenantID    string  `json:"tenantId"`
	Name        string  `json:"name"`
	Description *string `json:"description,omitzero"`
	// Status is "active" or "archived".
	Status    string  `json:"status"`
	CreatedBy string  `json:"createdBy"`
	CreatedAt float64 `json:"createdAt"`
	UpdatedAt float64 `json:"updatedAt"`
}

var projectIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func invalidInput(message string) error { return core.NewIamError("INVALID_INPUT", message) }

func object(input any) (*core.Object, error) {
	value, ok := input.(*core.Object)
	if !ok || value == nil {
		return nil, invalidInput("A JSON object is required")
	}
	return value, nil
}

func rejectUnknown(input *core.Object, allowed ...string) error {
	for _, key := range input.Keys() {
		known := false
		for _, name := range allowed {
			if key == name {
				known = true
				break
			}
		}
		if !known {
			return invalidInput("Unexpected field " + key)
		}
	}
	return nil
}

func text(value any, field string) (string, error) {
	raw, ok := value.(string)
	if !ok {
		return "", invalidInput(field + " is required")
	}
	trimmed := core.JSTrim(raw)
	if trimmed == "" || core.UTF16Len(trimmed) > nameMaxLength {
		return "", invalidInput(fmt.Sprintf("%s must be 1-%d characters", field, nameMaxLength))
	}
	return trimmed, nil
}

// optionalText answers ok false for an absent, null or blank value.
func optionalText(value any, field string) (string, bool, error) {
	if value == nil || core.IsUndefined(value) {
		return "", false, nil
	}
	raw, isString := value.(string)
	if !isString {
		return "", false, invalidInput(field + " must be text")
	}
	trimmed := core.JSTrim(raw)
	if trimmed == "" {
		return "", false, nil
	}
	if core.UTF16Len(trimmed) > descriptionMaxLength {
		return "", false, invalidInput(fmt.Sprintf("%s must be at most %d characters", field, descriptionMaxLength))
	}
	return trimmed, true, nil
}

// projectID checks a project id. Project ids are generated UUIDs; anything else (wildcards, slashes) could never name
// one and must not reach the resource the endpoint is authorized on.
func projectID(input any) (string, error) {
	value, ok := input.(string)
	if !ok || !projectIDPattern.MatchString(value) {
		return "", invalidInput("projectId is required")
	}
	return value, nil
}

// onProject: endpoints on one project are authorized on iam/project/{id}, so policies about that project apply.
func onProject(input *core.Object) string { return "project/" + jsString(input.Get("projectId")) }

func load(ctx context.Context, store core.IamStore, id, tenantID string) (*core.Object, error) {
	project, err := store.Get(ctx, Collection, id)
	if err != nil {
		return nil, err
	}
	if project == nil || project.Get("tenantId") != tenantID {
		return nil, core.NewIamError("NOT_FOUND", "Project not found", 404)
	}
	return project, nil
}

func assertNameAvailable(ctx context.Context, store core.IamStore, tenantID, name string, exceptID any) error {
	projects, err := store.Find(ctx, Collection, core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return err
	}
	for _, project := range projects {
		if project.Get("name") == name && !core.StrictEquals(project.Get("id"), exceptID) {
			return core.NewIamError("CONFLICT", "A project with this name already exists", 409)
		}
	}
	return nil
}

func scoped(input *core.Object, projectIDValue string) *core.Object {
	return core.NewObject("tenantId", input.Get("tenantId"), "projectId", projectIDValue)
}

// NewPlugin returns the projects plugin (createProjectsPlugin).
func NewPlugin() *core.IamPlugin {
	return &core.IamPlugin{
		ID:      "projects",
		Actions: []string{"projects:read", "projects:write"},
		Endpoints: []core.PluginEndpoint{
			{
				Method: "POST", Path: "create", Action: "projects:write",
				Validate: func(value any) (*core.Object, error) {
					input, err := object(value)
					if err != nil {
						return nil, err
					}
					if err := rejectUnknown(input, "tenantId", "name", "description"); err != nil {
						return nil, err
					}
					name, err := text(input.Get("name"), "name")
					if err != nil {
						return nil, err
					}
					validated := core.NewObject("tenantId", input.Get("tenantId"), "name", name)
					description, ok, err := optionalText(input.Get("description"), "description")
					if err != nil {
						return nil, err
					}
					if ok {
						validated.Set("description", description)
					}
					return validated, nil
				},
				Handler: func(ctx context.Context, endpoint core.PluginEndpointContext, input *core.Object) (any, error) {
					name := jsString(input.Get("name"))
					if err := assertNameAvailable(ctx, endpoint.Store, endpoint.TenantID, name, core.Undefined); err != nil {
						return nil, err
					}
					now := float64(time.Now().UnixMilli())
					record := core.NewObject("id", randomUUID(), "tenantId", endpoint.TenantID, "name", name)
					if truthy(input.Get("description")) {
						record.Set("description", jsString(input.Get("description")))
					}
					record.Set("status", "active")
					record.Set("createdBy", endpoint.Principal.Identity.ID)
					record.Set("createdAt", now)
					record.Set("updatedAt", now)
					return endpoint.Store.Insert(ctx, Collection, record)
				},
			},
			{
				Method: "POST", Path: "list", Action: "projects:read",
				Validate: func(value any) (*core.Object, error) {
					input, err := object(value)
					if err != nil {
						return nil, err
					}
					if err := rejectUnknown(input, "tenantId", "status"); err != nil {
						return nil, err
					}
					status := input.Get("status")
					given := status != nil && !core.IsUndefined(status)
					if given {
						if text := jsString(status); text != "active" && text != "archived" {
							return nil, invalidInput("status must be active or archived")
						}
					}
					validated := core.NewObject("tenantId", input.Get("tenantId"))
					if given {
						validated.Set("status", jsString(status))
					}
					return validated, nil
				},
				Handler: func(ctx context.Context, endpoint core.PluginEndpointContext, input *core.Object) (any, error) {
					filter := core.NewObject("tenantId", endpoint.TenantID)
					if truthy(input.Get("status")) {
						filter.Set("status", jsString(input.Get("status")))
					}
					projects, err := endpoint.Store.Find(ctx, Collection, filter, nil)
					if err != nil {
						return nil, err
					}
					sorted := append([]*core.Object(nil), projects...)
					sort.SliceStable(sorted, func(i, j int) bool {
						a, b := jsNumber(sorted[i].Get("createdAt")), jsNumber(sorted[j].Get("createdAt"))
						if a != b {
							return a < b
						}
						return lessUTF16(jsString(sorted[i].Get("id")), jsString(sorted[j].Get("id")))
					})
					return sorted, nil
				},
			},
			{
				Method: "POST", Path: "get", Action: "projects:read", Resource: onProject,
				Validate: projectInput,
				Handler: func(ctx context.Context, endpoint core.PluginEndpointContext, input *core.Object) (any, error) {
					return load(ctx, endpoint.Store, jsString(input.Get("projectId")), endpoint.TenantID)
				},
			},
			{
				Method: "POST", Path: "update", Action: "projects:write", Resource: onProject,
				Validate: func(value any) (*core.Object, error) {
					input, err := object(value)
					if err != nil {
						return nil, err
					}
					if err := rejectUnknown(input, "tenantId", "projectId", "name", "description"); err != nil {
						return nil, err
					}
					if core.IsUndefined(input.Get("name")) && core.IsUndefined(input.Get("description")) {
						return nil, invalidInput("Provide a name or description")
					}
					id, err := projectID(input.Get("projectId"))
					if err != nil {
						return nil, err
					}
					validated := scoped(input, id)
					if !core.IsUndefined(input.Get("name")) {
						name, err := text(input.Get("name"), "name")
						if err != nil {
							return nil, err
						}
						validated.Set("name", name)
					}
					if !core.IsUndefined(input.Get("description")) {
						description, ok, err := optionalText(input.Get("description"), "description")
						if err != nil {
							return nil, err
						}
						// An explicit empty description clears the field; absent leaves it unchanged.
						if ok {
							validated.Set("description", description)
						} else {
							validated.Set("clearDescription", true)
						}
					}
					return validated, nil
				},
				Handler: func(ctx context.Context, endpoint core.PluginEndpointContext, input *core.Object) (any, error) {
					project, err := load(ctx, endpoint.Store, jsString(input.Get("projectId")), endpoint.TenantID)
					if err != nil {
						return nil, err
					}
					if !core.IsUndefined(input.Get("name")) {
						if err := assertNameAvailable(ctx, endpoint.Store, endpoint.TenantID, jsString(input.Get("name")), project.Get("id")); err != nil {
							return nil, err
						}
					}
					next := project.Clone()
					if !core.IsUndefined(input.Get("name")) {
						next.Set("name", jsString(input.Get("name")))
					}
					if truthy(input.Get("clearDescription")) {
						next.Delete("description")
					} else if !core.IsUndefined(input.Get("description")) {
						next.Set("description", jsString(input.Get("description")))
					}
					next.Set("updatedAt", float64(time.Now().UnixMilli()))
					return endpoint.Store.Put(ctx, Collection, next)
				},
			},
			{
				Method: "POST", Path: "archive", Action: "projects:write", Resource: onProject,
				Validate: projectInput,
				Handler:  transition("active", "archived", "Project is not active"),
			},
			{
				Method: "POST", Path: "restore", Action: "projects:write", Resource: onProject,
				Validate: projectInput,
				Handler:  transition("archived", "active", "Project is not archived"),
			},
		},
		// Purge runs inside the server's purge transaction before tenant records are removed.
		Purge: func(ctx context.Context, store core.IamStore, tenantIDs []string) error {
			for _, tenantID := range tenantIDs {
				projects, err := store.Find(ctx, Collection, core.NewObject("tenantId", tenantID), nil)
				if err != nil {
					return err
				}
				for _, project := range projects {
					if err := store.Delete(ctx, Collection, jsString(project.Get("id"))); err != nil {
						return err
					}
				}
			}
			return nil
		},
	}
}

// projectInput validates { tenantId, projectId }.
func projectInput(value any) (*core.Object, error) {
	input, err := object(value)
	if err != nil {
		return nil, err
	}
	if err := rejectUnknown(input, "tenantId", "projectId"); err != nil {
		return nil, err
	}
	id, err := projectID(input.Get("projectId"))
	if err != nil {
		return nil, err
	}
	return scoped(input, id), nil
}

func transition(from, to, refusal string) func(ctx context.Context, endpoint core.PluginEndpointContext, input *core.Object) (any, error) {
	return func(ctx context.Context, endpoint core.PluginEndpointContext, input *core.Object) (any, error) {
		project, err := load(ctx, endpoint.Store, jsString(input.Get("projectId")), endpoint.TenantID)
		if err != nil {
			return nil, err
		}
		if project.Get("status") != from {
			return nil, core.NewIamError("INVALID_TRANSITION", refusal)
		}
		next := project.Clone()
		next.Set("status", to)
		next.Set("updatedAt", float64(time.Now().UnixMilli()))
		return endpoint.Store.Put(ctx, Collection, next)
	}
}

// truthy is JavaScript truthiness for model values.
func truthy(value any) bool {
	switch v := value.(type) {
	case nil, core.UndefinedType:
		return false
	case bool:
		return v
	case string:
		return v != ""
	case float64:
		return v != 0 && v == v
	}
	return true
}

// jsString is JavaScript's String(value) for model values.
func jsString(value any) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case core.UndefinedType:
		return "undefined"
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		return core.NumberString(v)
	case []any:
		parts := make([]string, len(v))
		for index, item := range v {
			if item != nil && !core.IsUndefined(item) {
				parts[index] = jsString(item)
			}
		}
		return strings.Join(parts, ",")
	case *core.Object:
		return "[object Object]"
	}
	return fmt.Sprint(value)
}

// jsNumber is the numeric value of a record field (NaN-free: non-numbers count as 0).
func jsNumber(value any) float64 {
	number, _ := value.(float64)
	return number
}

// lessUTF16 compares strings by UTF-16 code units, as JavaScript's < does.
func lessUTF16(a, b string) bool {
	left, right := core.ToUTF16(a), core.ToUTF16(b)
	for index := 0; index < len(left) && index < len(right); index++ {
		if left[index] != right[index] {
			return left[index] < right[index]
		}
	}
	return len(left) < len(right)
}

// randomUUID is crypto.randomUUID(): a random (version 4) UUID in lowercase.
func randomUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
