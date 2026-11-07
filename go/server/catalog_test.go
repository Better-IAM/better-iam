package server

// Catalog checks against spec/catalog/actions.json (the TypeScript Catalog as generated), the context key
// registries against packages/server/src/context-keys.ts, and the catalog rules (configured and tenant actions,
// resource types, attribute schemas, policy validation).

import (
	"context"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/spectest"
)

func catalogSpec(t *testing.T) *core.Object {
	t.Helper()
	data, err := os.ReadFile(spectest.Path(t, "catalog", "actions.json"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := core.ParseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.(*core.Object)
}

func stringsIn(value any) []string {
	list, _ := value.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		out = append(out, jsString(item))
	}
	return out
}

func TestCatalogMatchesTheSpec(t *testing.T) {
	spec := catalogSpec(t)
	if !reflect.DeepEqual(BuiltInActions, stringsIn(spec.Get("builtInActions"))) {
		t.Fatalf("built-in actions differ from spec/catalog/actions.json:\n go %v\nspec %v", BuiltInActions, stringsIn(spec.Get("builtInActions")))
	}
	for name, got := range map[string][]string{
		"internalResourceTypes":        InternalResourceTypes.Values(),
		"reservedResourceTypes":        ReservedResourceTypes.Values(),
		"reservedPrincipalKeys":        ReservedPrincipalKeys.Values(),
		"clearancePrincipalNames":      ClearancePrincipalNames.Values(),
		"classificationAttributeNames": ClassificationAttributeNames.Values(),
	} {
		if !reflect.DeepEqual(got, stringsIn(spec.Get(name))) {
			t.Fatalf("%s: go %v spec %v", name, got, stringsIn(spec.Get(name)))
		}
	}
	patterns, _ := spec.Object("patterns")
	for name, pattern := range map[string]*regexp.Regexp{
		"resourceTypeName": ResourceTypeName, "tenantAction": tenantActionPattern,
		"relationName": relationNamePattern, "attributeName": attributeNamePattern,
	} {
		if pattern.String() != jsString(patterns.Get(name)) {
			t.Fatalf("pattern %s: %s vs %s", name, pattern, jsString(patterns.Get(name)))
		}
	}
	// The default catalog (no options): built-in actions, no resource types, namespace iam.
	defaults, _ := spec.Object("default")
	catalog := must(NewCatalog(optionsValue(t, ""), nil, must(resolve(t, ""))))
	var names []string
	for _, entry := range defaults.Get("actions").([]any) {
		names = append(names, jsString(member(entry, "name")))
		if member(entry, "source") != "platform" {
			t.Fatalf("unexpected source %v", entry)
		}
	}
	if !reflect.DeepEqual(catalog.Actions.Values(), names) || len(catalog.ResourceTypeNames) != 0 ||
		!reflect.DeepEqual(catalog.Namespaces.Values(), stringsIn(defaults.Get("namespaces"))) || catalog.ReservedAttributes != nil {
		t.Fatalf("default catalog differs: %d actions, namespaces %v", catalog.Actions.Len(), catalog.Namespaces.Values())
	}
	// The clearances module reserves the classification attribute names.
	modules, _ := spec.Object("modules")
	clearances, _ := modules.Object("clearances")
	withClearances := must(NewCatalog(optionsValue(t, `{"clearances":{}}`), nil, must(resolve(t, `{"clearances":{}}`))))
	if !reflect.DeepEqual(withClearances.ReservedAttributes.Values(), stringsIn(clearances.Get("reservedAttributes"))) {
		t.Fatalf("clearances reserved attributes %v vs %v", withClearances.ReservedAttributes.Values(), clearances.Get("reservedAttributes"))
	}
}

// TestContextKeysMatchTheTypeScriptRegistry reads packages/server/src/context-keys.ts so the Go registries cannot
// drift from it.
func TestContextKeysMatchTheTypeScriptRegistry(t *testing.T) {
	root, err := spectest.Root()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(root + "/packages/server/src/context-keys.ts")
	if err != nil {
		t.Skip("TypeScript source not available:", err)
	}
	text := string(source)
	section := func(start, end string) string {
		from := strings.Index(text, start)
		to := strings.Index(text[from:], end)
		return text[from : from+to]
	}
	entry := regexp.MustCompile(`\['([a-zA-Z.]+)', '([a-z]+)'\]`)
	quoted := regexp.MustCompile(`'([a-zA-Z.]+)'`)
	compare := func(name string, got []ContextKey, block string) {
		var want []ContextKey
		for _, match := range entry.FindAllStringSubmatch(block, -1) {
			want = append(want, ContextKey{match[1], match[2]})
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s differs:\n go %v\n ts %v", name, got, want)
		}
	}
	compare("principalServerKeys", PrincipalServerKeys.Entries(), section("export const principalServerKeys", "export const resourceServerKeys"))
	compare("resourceServerKeys", ResourceServerKeys.Entries(), section("export const resourceServerKeys", "export const optionalResourceServerKeys"))
	compare("tenantServerKeys", TenantServerKeys.Entries(), section("export const tenantServerKeys", "export const optionalPrincipalServerKeys"))
	var optional []string
	for _, match := range quoted.FindAllStringSubmatch(section("export const optionalPrincipalServerKeys", "export const sessionTagPrefix"), -1) {
		optional = append(optional, match[1])
	}
	if !reflect.DeepEqual(OptionalPrincipalServerKeys.Values(), optional) {
		t.Fatalf("optionalPrincipalServerKeys differ:\n go %v\n ts %v", OptionalPrincipalServerKeys.Values(), optional)
	}
	var reserved []string
	for _, match := range quoted.FindAllStringSubmatch(section("export const reservedSessionPrincipalNames", "export const sessionScopedPrincipalKeys"), -1) {
		reserved = append(reserved, match[1])
	}
	if !reflect.DeepEqual(ReservedSessionPrincipalNames, reserved) {
		t.Fatalf("reservedSessionPrincipalNames differ:\n go %v\n ts %v", ReservedSessionPrincipalNames, reserved)
	}
}

func TestCatalogConfiguration(t *testing.T) {
	config := must(resolve(t, ""))
	build := func(members string) (*Catalog, error) {
		return NewCatalog(optionsValue(t, members), nil, config)
	}
	for _, action := range []string{`"iam:own"`, `"tenant/x"`, `"docs:*"`, `"docs read"`, `"docs read"`} {
		_, err := build(`{"permissions":{"actions":[` + action + `]}}`)
		expectError(t, err, "INVALID_CONFIG", "Reserved or invalid action")
	}
	_, err := build(`{"permissions":{"actions":[""]}}`)
	expectError(t, err, "INVALID_INPUT", "Invalid action")
	_, err = build(`{"permissions":{"identityAttributes":{"groups":"string"}}}`)
	expectError(t, err, "INVALID_CONFIG", "identityAttributes cannot redefine principal.groups")
	_, err = build(`{"permissions":{"identityAttributes":{"level":"date"}}}`)
	expectError(t, err, "INVALID_CONFIG", "identityAttributes: Attribute level must be string, number, or boolean")
	_, err = build(`{"permissions":{"identityAttributes":{"sessionTags":"string"}}}`)
	expectError(t, err, "INVALID_CONFIG", "identityAttributes cannot redefine principal.sessionTags")
	clearances := must(resolve(t, `{"clearances":{}}`))
	_, err = NewCatalog(optionsValue(t, `{"permissions":{"identityAttributes":{"clearanceRank":"number"}}}`), nil, clearances)
	expectError(t, err, "INVALID_CONFIG", "identityAttributes cannot redefine principal.clearanceRank")
	if _, err := build(`{"permissions":{"identityAttributes":{"clearanceRank":"number"}}}`); err != nil {
		t.Fatalf("clearance names are free without clearances: %v", err)
	}
	_, err = NewCatalog(optionsValue(t, `{"permissions":{"resourceTypes":{"document":{"attributes":{"noforn":"boolean"}}}}}`), nil, clearances)
	expectError(t, err, "INVALID_CONFIG", "Resource type document: Attribute name noforn is reserved")
	for members, message := range map[string]string{
		`{"permissions":{"resourceTypes":{"Doc":{}}}}`:                                             "Invalid or reserved resource type name Doc",
		`{"permissions":{"resourceTypes":{"tenant":{}}}}`:                                          "Invalid or reserved resource type name tenant",
		`{"permissions":{"resourceTypes":{"doc":{"parent":"folder"}}}}`:                            "Resource type doc has an invalid parent chain",
		`{"permissions":{"resourceTypes":{"doc":{"parent":"doc"}}}}`:                               "Resource type doc has an invalid parent chain",
		`{"permissions":{"resourceTypes":{"doc":{"relations":["Bad"]}}}}`:                          "Resource type doc: relations must contain at most 32 lowercase identifiers",
		`{"permissions":{"resourceTypes":{"doc":{"attributes":{"tenantId":"string"}}}}}`:           "Resource type doc: Invalid attribute name tenantId",
		`{"permissions":{"resourceTypes":{"folder":{},"doc":{"parent":"folder","managed":true}}}}`: "Managed resource type doc requires a managed parent",
		`{"permissions":{"resourceTypes":{"doc":{"actions":["iam:x"]}}}}`:                          "Reserved or invalid action",
	} {
		_, err := build(members)
		expectError(t, err, "INVALID_CONFIG", message)
	}
	_, err = build(`{"permissions":{"resourceTypes":{"doc":"x"}}}`)
	expectError(t, err, "INVALID_INPUT", "Expected an object")
	catalog := must(build(`{"permissions":{"actions":["reports:run"],"resourceTypes":{"folder":{"managed":true,"actions":["folder:read"]},"doc":{"parent":"folder","managed":true,"description":"A document","actions":["doc:read","folder:read"],"attributes":{"owner":"string","pages":"number"},"relations":["editor","viewer","editor"]}}}}`))
	if catalog.ActionTypes["folder:read"] != "folder" || catalog.ActionTypes["doc:read"] != "doc" || catalog.ActionTypes["reports:run"] != "" {
		t.Fatalf("action types %v", catalog.ActionTypes)
	}
	doc := catalog.ResourceTypes["doc"]
	if !reflect.DeepEqual(doc.Relations, []string{"editor", "viewer"}) || core.MustStringify(doc.Attributes) != `{"owner":"string","pages":"number"}` ||
		doc.Description != "A document" || !doc.Managed || doc.Parent != "folder" {
		t.Fatalf("doc %+v", doc)
	}
	if !reflect.DeepEqual(catalog.Namespaces.Values(), []string{"iam", "reports", "folder", "doc"}) {
		t.Fatalf("namespaces %v", catalog.Namespaces.Values())
	}
	plugin := &core.IamPlugin{ID: "p", Actions: []string{"p:act"}, ResourceTypes: []core.NamedResourceType{{Name: "widget", Definition: core.ResourceTypeDefinition{Actions: []string{"widget:spin"}}}}}
	withPlugin := must(NewCatalog(optionsValue(t, ""), []*core.IamPlugin{plugin}, config))
	if !withPlugin.Actions.Has("p:act") || withPlugin.ActionTypes["widget:spin"] != "widget" {
		t.Fatal("plugin actions and types")
	}
}

func TestAttributeValues(t *testing.T) {
	schema := core.NewObject("owner", "string", "pages", "number", "draft", "boolean")
	values := must(AttributeValues(schema, parse(t, `{"owner":"ada","pages":3,"draft":false}`)))
	if core.MustStringify(values) != `{"owner":"ada","pages":3,"draft":false}` {
		t.Fatal(core.MustStringify(values))
	}
	_, err := AttributeValues(schema, parse(t, `{"colour":"red"}`))
	expectError(t, err, "INVALID_INPUT", "Attribute colour is not declared for this resource type")
	_, err = AttributeValues(schema, parse(t, `{"pages":"3"}`))
	expectError(t, err, "INVALID_INPUT", "Attribute pages must be a number")
	_, err = AttributeValues(schema, core.NewObject("owner", strings.Repeat("x", 2049)))
	expectError(t, err, "INVALID_INPUT", "Attribute owner must be a string")
	_, err = AttributeSchema(core.NewObject(), nil)
	if err != nil {
		t.Fatal(err)
	}
	many := core.NewObject()
	for index := 0; index < 65; index++ {
		many.Set("a"+core.NumberString(float64(index)), "string")
	}
	_, err = AttributeSchema(many, nil)
	expectError(t, err, "INVALID_INPUT", "At most 64 attributes may be declared")
}

func TestCatalogTenantActionsAndPolicyValidation(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	locked := must(NewCatalog(optionsValue(t, ""), nil, must(resolve(t, ""))))
	err := store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		_, err := locked.RegisterTenantAction(ctx, tx, "t1", "doc:read", core.Undefined)
		return err
	})
	expectError(t, err, "CATALOG_LOCKED", "Tenant-defined actions are disabled")
	config := must(resolve(t, `{"permissions":{"mode":"tenant-defined","resourceTypes":{"folder":{"managed":true}}}}`))
	catalog := must(NewCatalog(optionsValue(t, `{"permissions":{"mode":"tenant-defined","resourceTypes":{"folder":{"managed":true}}}}`), nil, config))
	err = store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		_, err := catalog.RegisterTenantAction(ctx, tx, "t1", "doc:read", core.Undefined)
		expectError(t, err, "INVALID_ACTION", "Register resource type doc before its actions")
		_, err = catalog.RegisterTenantAction(ctx, tx, "t1", "iam:read", core.Undefined)
		expectError(t, err, "INVALID_ACTION", "Tenant actions must be {resourceType}:{verb} under a tenant-defined resource type")
		if _, err := tx.Insert(ctx, "resourceTypes", core.NewObject("id", "rt1", "tenantId", "t1", "uniqueKey", "doc", "name", "doc",
			"attributes", core.NewObject("owner", "string"), "relations", []any{"editor"}, "createdAt", 1.0)); err != nil {
			return err
		}
		action, err := catalog.RegisterTenantAction(ctx, tx, "t1", "doc:read", "Read documents")
		if err != nil {
			return err
		}
		if action.Get("name") != "doc:read" || action.Get("resourceType") != "doc" || action.Get("description") != "Read documents" || action.Get("uniqueKey") != "doc:read" {
			t.Fatalf("action %s", core.MustStringify(action))
		}
		_, err = catalog.RegisterTenantAction(ctx, tx, "t1", "doc:read", core.Undefined)
		expectError(t, err, "CONFLICT", "Action already exists")
		definition, err := catalog.ResourceTypeDefinition(ctx, tx, "t1", "doc")
		if err != nil || definition.Source != "tenant" || !reflect.DeepEqual(definition.Actions, []string{"doc:read"}) || !definition.Managed ||
			!reflect.DeepEqual(definition.Relations, []string{"editor"}) {
			t.Fatalf("definition %+v %v", definition, err)
		}
		if _, err := catalog.ManagedDefinition(ctx, tx, "t1", "folder"); err != nil {
			t.Fatal(err)
		}
		_, err = catalog.ManagedDefinition(ctx, tx, "t1", "nothing")
		expectError(t, err, "INVALID_RESOURCE_TYPE", "Unknown resource type")
		// Policies may only name actions and types that exist; wildcards are not resolved.
		ok := parse(t, `{"version":1,"statements":[{"effect":"allow","actions":["doc:read","iam:groups:*"],"resources":["doc/*","iam/*","*"]}]}`)
		if err := catalog.Validate(ctx, tx, "t1", ok); err != nil {
			t.Fatal(err)
		}
		err = catalog.Validate(ctx, tx, "t1", parse(t, `{"version":1,"statements":[{"effect":"allow","actions":["doc:write"],"resources":["*"]}]}`))
		expectError(t, err, "INVALID_ACTION", "Unknown action doc:write")
		err = catalog.Validate(ctx, tx, "t1", parse(t, `{"version":1,"statements":[{"effect":"allow","actions":["doc:read"],"resources":["photo/1"]}]}`))
		expectError(t, err, "INVALID_RESOURCE_TYPE", "Unknown resource type photo")
		err = catalog.Validate(ctx, tx, "t1", parse(t, `{"version":2,"statements":[]}`))
		expectErrorPrefix(t, err, "INVALID_POLICY", "")
		if _, err := tx.Insert(ctx, "policies", core.NewObject("id", "p1", "tenantId", "t1", "name", "P", "version", 1.0, "document", ok)); err != nil {
			return err
		}
		err = catalog.AssertActionUnused(ctx, tx, "t1", "doc:read")
		expectError(t, err, "RESOURCE_IN_USE", "Remove the action from policies and roles first")
		return catalog.AssertActionUnused(ctx, tx, "t1", "doc:delete")
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestManagedResourceHelpers(t *testing.T) {
	record := core.NewObject("id", "r1", "tenantId", "t1", "type", "doc", "resourceId", "d1", "uniqueKey", "doc/d1",
		"attributes", core.NewObject("pages", 3.0), "ownerId", "i1", "parentType", "folder", "parentId", "f1", "createdAt", 1.0, "updatedAt", 1.0)
	resolved := ResolvedManaged(record)
	if resolved.TenantID != "t1" || resolved.Type != "doc" || resolved.ID != "d1" ||
		core.MustStringify(resolved.Attributes) != `{"pages":3,"ownerId":"i1","parentId":"f1","parentType":"folder"}` {
		t.Fatalf("%+v %s", resolved, core.MustStringify(resolved.Attributes))
	}
	store := newStore(t)
	ctx := context.Background()
	if err := store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		_, err := tx.Insert(ctx, "resources", record)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	found := must(ManagedResource(ctx, store, "t1", "doc", "d1"))
	if found == nil || found.Get("id") != "r1" {
		t.Fatal("managed resource not found")
	}
	if missing := must(ManagedResource(ctx, store, "t1", "doc", "d2")); missing != nil {
		t.Fatal("unexpected resource")
	}
}
