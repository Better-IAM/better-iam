package apitypes

import (
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/spectest"
)

func readSpecJSON(t *testing.T, out any, parts ...string) {
	t.Helper()
	data, err := os.ReadFile(spectest.Path(t, parts...))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		t.Fatal(err)
	}
}

// TestOperationTableMatchesRoutes checks the operation table against spec/api/routes.json: every RPC route, in order,
// with its flags, then the special routes.
func TestOperationTableMatchesRoutes(t *testing.T) {
	var routes struct {
		BasePath string `json:"basePath"`
		RPC      []struct {
			Path              string `json:"path"`
			Group             string `json:"group"`
			Method            string `json:"method"`
			Credential        string `json:"credential"`
			Call              string `json:"call"`
			TenantBound       bool   `json:"tenantBound"`
			SetsSessionCookie bool   `json:"setsSessionCookie"`
			ReadsDeviceCookie bool   `json:"readsDeviceCookie"`
		} `json:"rpc"`
		Special []struct {
			Path       string `json:"path"`
			Credential string `json:"credential"`
		} `json:"special"`
	}
	readSpecJSON(t, &routes, "api", "routes.json")
	if DefaultBasePath != routes.BasePath {
		t.Errorf("DefaultBasePath = %q, routes.json has %q", DefaultBasePath, routes.BasePath)
	}
	ops := Operations()
	var special []string
	for _, entry := range routes.Special {
		if !strings.Contains(entry.Path, "{") {
			special = append(special, entry.Path)
		}
	}
	if len(ops) != len(routes.RPC)+len(special) {
		t.Fatalf("%d operations, routes.json has %d RPC and %d special routes", len(ops), len(routes.RPC), len(special))
	}
	for index, route := range routes.RPC {
		op := ops[index]
		want := Operation{
			Path: route.Path, OperationID: route.Group + "." + route.Method, Group: route.Group, Method: route.Method,
			Public: route.Credential == "none", Call: route.Call, TenantBound: route.TenantBound,
			SetsSessionCookie: route.SetsSessionCookie, ReadsDeviceCookie: route.ReadsDeviceCookie,
			Input: op.Input, Output: op.Output,
		}
		if *op != want {
			t.Errorf("operation %d: got %+v, want %+v", index, *op, want)
		}
		if found, ok := LookupOperation(route.Path); !ok || found != op {
			t.Errorf("LookupOperation(%q) does not find the table row", route.Path)
		}
		if route.Credential != "none" && route.Credential != "required" {
			t.Errorf("%s: unexpected credential %q", route.Path, route.Credential)
		}
	}
	for offset, path := range special {
		op := ops[len(routes.RPC)+offset]
		if op.Path != path || !op.Special || op.Public || op.Call != "request" {
			t.Errorf("special route %d: got %+v, want %s", offset, *op, path)
		}
	}
	for _, op := range ops {
		if op.Input == nil || op.Output == nil {
			t.Errorf("%s: missing Input or Output type", op.Path)
		}
		if _, ok := op.NewInput().(interface{}); !ok {
			t.Errorf("%s: NewInput", op.Path)
		}
	}
	if _, ok := LookupOperation("plugins/x/y"); ok {
		t.Error("plugin routes must not be in the table")
	}
	// A typed descriptor points at its row.
	if OpRolesCreate.Path != "roles/create" || OpRolesCreate.Input != reflect.TypeFor[RolesCreateInput]() {
		t.Errorf("OpRolesCreate = %+v", *OpRolesCreate.Operation)
	}
	if OpAuthorize.Path != "authorize" || OpAuthorize.Output != reflect.TypeFor[Decision]() {
		t.Errorf("OpAuthorize = %+v", *OpAuthorize.Operation)
	}
}

type openAPIDocument struct {
	Components struct {
		Schemas map[string]map[string]any `json:"schemas"`
	} `json:"components"`
}

// TestSchemaRegistry checks that every components/schemas entry has a Go type and nothing else does.
func TestSchemaRegistry(t *testing.T) {
	var doc openAPIDocument
	readSpecJSON(t, &doc, "api", "openapi.json")
	for name := range doc.Components.Schemas {
		if _, ok := SchemaType(name); !ok {
			t.Errorf("components/schemas/%s has no Go type", name)
		}
	}
	for name := range schemaTypes {
		if _, ok := doc.Components.Schemas[name]; !ok {
			t.Errorf("%s is not a components/schemas entry", name)
		}
	}
}

type jsonField struct {
	name  string
	omit  bool
	typ   reflect.Type
	field string
}

// jsonFields lists the members encoding/json writes for a struct type, with embedded structs flattened.
func jsonFields(t reflect.Type) []jsonField {
	var out []jsonField
	for index := 0; index < t.NumField(); index++ {
		field := t.Field(index)
		tag := field.Tag.Get("json")
		if tag == "-" || (!field.IsExported() && !field.Anonymous) {
			continue
		}
		name, options, _ := strings.Cut(tag, ",")
		if field.Anonymous && name == "" && field.Type.Kind() == reflect.Struct {
			out = append(out, jsonFields(field.Type)...)
			continue
		}
		if name == "" {
			name = field.Name
		}
		omit := strings.Contains(","+options+",", ",omitempty,") || strings.Contains(","+options+",", ",omitzero,")
		out = append(out, jsonField{name: name, omit: omit, typ: field.Type, field: field.Name})
	}
	return out
}

// coreSchemaDifferences are the known, accepted differences between a go/core type and its components/schemas entry.
var coreSchemaDifferences = map[string]string{}

// TestCoreTypesMatchSchemas checks that every schema mapped to a go/core type has the schema's members, and that
// required members are always written and optional ones are omitted when unset.
func TestCoreTypesMatchSchemas(t *testing.T) {
	var doc openAPIDocument
	readSpecJSON(t, &doc, "api", "openapi.json")
	marshaler := reflect.TypeFor[json.Marshaler]()
	var problems []string
	checked := 0
	for _, name := range CoreSchemas() {
		typ, _ := SchemaType(name)
		schema := doc.Components.Schemas[name]
		properties, _ := schema["properties"].(map[string]any)
		if typ.Kind() != reflect.Struct || properties == nil {
			continue // enums, unions and aliases of strings or any
		}
		if typ.Implements(marshaler) || reflect.PointerTo(typ).Implements(marshaler) {
			continue // core encodes these itself (ClassificationLabel, ResourceFilter, ...)
		}
		checked++
		required := map[string]bool{}
		if list, ok := schema["required"].([]any); ok {
			for _, item := range list {
				required[item.(string)] = true
			}
		}
		fields := map[string]jsonField{}
		for _, field := range jsonFields(typ) {
			fields[field.name] = field
		}
		var names []string
		for member := range properties {
			names = append(names, member)
		}
		sort.Strings(names)
		for _, member := range names {
			field, ok := fields[member]
			if !ok {
				problems = append(problems, name+"."+member+": no Go field")
				continue
			}
			nullable := isNullable(properties[member])
			switch {
			case required[member] && field.omit && !nullable:
				problems = append(problems, name+"."+member+": required, but the Go field is omitted when empty")
			case !required[member] && !field.omit:
				problems = append(problems, name+"."+member+": optional, but the Go field is always written")
			}
		}
		for member := range fields {
			if _, ok := properties[member]; !ok {
				problems = append(problems, name+"."+member+": the Go field is not in the schema")
			}
		}
	}
	t.Logf("compared %d go/core struct types with their schemas", checked)
	if checked < 15 {
		t.Errorf("only %d go/core struct types were compared", checked)
	}
	var unexpected []string
	for _, problem := range problems {
		if _, ok := coreSchemaDifferences[problem]; !ok {
			unexpected = append(unexpected, problem)
		}
	}
	if len(unexpected) > 0 {
		t.Errorf("go/core types differ from their schemas:\n  %s", strings.Join(unexpected, "\n  "))
	}
	for _, name := range []string{"Tenant", "Identity", "Session", "AuditEvent", "PolicyDocument", "Decision"} {
		if !slices.Contains(CoreSchemas(), name) {
			t.Errorf("%s is not mapped to go/core", name)
		}
	}
	if reflect.TypeFor[Tenant]() != reflect.TypeFor[core.Tenant]() {
		t.Error("Tenant is not core.Tenant")
	}
}

func isNullable(schema any) bool {
	object, _ := schema.(map[string]any)
	variants, _ := object["anyOf"].([]any)
	for _, variant := range variants {
		if v, ok := variant.(map[string]any); ok && v["type"] == "null" {
			return true
		}
	}
	return object["type"] == "null"
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// TestMemberPresence covers absent versus null versus a value.
func TestMemberPresence(t *testing.T) {
	// bindings/update: startsAt and expiresAt are optional and nullable (null clears them).
	var input BindingsUpdateInput
	if err := json.Unmarshal([]byte(`{"tenantId":"t","bindingId":"b","startsAt":null}`), &input); err != nil {
		t.Fatal(err)
	}
	if !input.StartsAt.Set || input.StartsAt.Value != nil {
		t.Errorf("startsAt null decoded as %+v", input.StartsAt)
	}
	if input.ExpiresAt.Set {
		t.Errorf("absent expiresAt decoded as set: %+v", input.ExpiresAt)
	}
	if got := mustJSON(t, input); got != `{"tenantId":"t","bindingId":"b","startsAt":null}` {
		t.Errorf("re-encoded as %s", got)
	}
	ms := 5.0
	input.ExpiresAt = Some(&ms)
	input.StartsAt = Optional[*float64]{}
	if got := mustJSON(t, input); got != `{"tenantId":"t","bindingId":"b","expiresAt":5}` {
		t.Errorf("encoded as %s", got)
	}
	input.StartsAt = Null[float64]()
	if got := mustJSON(t, input); got != `{"tenantId":"t","bindingId":"b","startsAt":null,"expiresAt":5}` {
		t.Errorf("encoded as %s", got)
	}

	// An optional string keeps "" apart from absent; a required nullable member writes null.
	empty := ""
	found := AccessPathRequestPackagePackage{ID: "p", Name: "n", Description: &empty}
	if got := mustJSON(t, found); got != `{"id":"p","name":"n","description":""}` {
		t.Errorf("encoded as %s", got)
	}
	tenant := Tenant{Name: "a", Type: "org", Status: TenantStatusActive}
	if got := mustJSON(t, tenant); !strings.Contains(got, `"parentId":null`) {
		t.Errorf("a required nullable member must be written as null: %s", got)
	}
	// An empty list is written; an unset one is not.
	result := AccessPathsResult{Allowed: true, Reason: "allowed", Paths: []AccessPath{}}
	if got := mustJSON(t, result); got != `{"allowed":true,"reason":"allowed","paths":[]}` {
		t.Errorf("encoded as %s", got)
	}
}

// TestUnions covers tagged and untagged unions.
func TestUnions(t *testing.T) {
	var path AccessPath
	if err := json.Unmarshal([]byte(`{"kind":"activate","bindingId":"b","role":{"id":"r","name":"R"},"requireApproval":false,"requireJustification":true,"requireMfa":false}`), &path); err != nil {
		t.Fatal(err)
	}
	if path.Activate == nil || path.Activate.BindingID != "b" || path.Mfa != nil {
		t.Fatalf("decoded %+v", path)
	}
	if err := json.Unmarshal([]byte(`{"kind":"mfa"}`), &path); err != nil || path.Mfa == nil || path.Activate != nil {
		t.Fatalf("decoded %+v (%v)", path, err)
	}
	if err := json.Unmarshal([]byte(`{"kind":"nope"}`), &path); err == nil {
		t.Error("an unknown discriminator must not decode")
	}
	if _, err := json.Marshal(AccessPath{}); err == nil {
		t.Error("an empty union must not encode")
	}

	// A primitive union: string | number | boolean | unknown[].
	var value TenantConfigAutoAssignIncludeItemStringEqualsValue
	for _, text := range []string{`"x"`, `12.5`, `true`, `["a",1,[false]]`} {
		if err := json.Unmarshal([]byte(text), &value); err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		if got := mustJSON(t, value); got != text {
			t.Errorf("%s re-encoded as %s", text, got)
		}
	}
	if value.Array == nil || len(*value.Array) != 3 {
		t.Errorf("nested array decoded as %+v", value)
	}

	// Untagged object variants told apart by their required members.
	var result SignInResult
	if err := json.Unmarshal([]byte(`{"mfaRequired":true,"challenge":"c","enrollmentRequired":false}`), &result); err != nil {
		t.Fatal(err)
	}
	if result.MfaRequired == nil {
		t.Errorf("decoded %+v", result)
	}
}

// TestExtraMembers covers objects that keep members the schema does not list.
func TestExtraMembers(t *testing.T) {
	text := `{"name":"Readers","policyIds":[],"protected":false,"id":"r","tenantId":"t","custom":{"a":[1,2]},"z":null}`
	var role Role
	if err := json.Unmarshal([]byte(text), &role); err != nil {
		t.Fatal(err)
	}
	if len(role.Extra) != 2 {
		t.Fatalf("Extra = %v", role.Extra)
	}
	again, err := json.Marshal(role)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := canonical([]byte(text))
	got, _ := canonical(again)
	if got != want {
		t.Errorf("re-encoded as %s", again)
	}
}
