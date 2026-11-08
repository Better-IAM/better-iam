package scim

// Port of packages/scim/src/resources.ts: SCIM responses, resource rendering and the discovery documents.

import (
	"net/http"

	"github.com/Better-IAM/better-iam/go/core"
)

// Response is what the fetch-style handler answers (a TypeScript Response).
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// Write sends the response.
func (r *Response) Write(w http.ResponseWriter) {
	for key, values := range r.Header {
		w.Header()[key] = append([]string(nil), values...)
	}
	w.WriteHeader(r.Status)
	if len(r.Body) > 0 {
		_, _ = w.Write(r.Body)
	}
}

// stringify is JSON.stringify for an answer body (undefined renders as no body).
func stringify(body any) []byte {
	text, ok, err := core.Stringify(body)
	if err != nil || !ok {
		return nil
	}
	return []byte(text)
}

// response is a SCIM JSON answer; 204 and 304 carry no body.
func response(body any, status int, headers map[string]string) *Response {
	header := http.Header{}
	header.Set("Content-Type", "application/scim+json")
	header.Set("Cache-Control", "no-store")
	for key, value := range headers {
		header.Set(key, value)
	}
	var data []byte
	if status != 204 && status != 304 {
		data = stringify(body)
	}
	return &Response{Status: status, Header: header, Body: data}
}

func listResponse(resources []any, totalResults int, startIndex int) *core.Object {
	return core.NewObject(
		"schemas", []any{ListSchema},
		"totalResults", float64(totalResults),
		"startIndex", float64(startIndex),
		"itemsPerPage", float64(len(resources)),
		"Resources", resources,
	)
}

// meta is a resource's `meta` member.
func meta(link *core.Object, resourceType, location string) (*core.Object, error) {
	created, err := isoString(link.Get("createdAt"))
	if err != nil {
		return nil, err
	}
	lastModified, err := isoString(link.Get("updatedAt"))
	if err != nil {
		return nil, err
	}
	return core.NewObject(
		"resourceType", resourceType,
		"created", created,
		"lastModified", lastModified,
		"version", `W/"`+jsString(link.Get("version"))+`"`,
		"location", location,
	), nil
}

func userResource(link *core.Object, base string) (*core.Object, error) {
	enterprise := link.Get("enterprise")
	schemas := []any{UserSchema}
	if truthy(enterprise) {
		schemas = []any{UserSchema, EnterpriseSchema}
	}
	id, err := encodeURIComponent(jsString(link.Get("id")))
	if err != nil {
		return nil, err
	}
	resource := core.NewObject()
	resource.SetRaw("schemas", schemas)
	for _, key := range []string{"id", "externalId", "userName", "displayName", "active", "emails", "name", "title"} {
		resource.SetRaw(key, link.Get(key))
	}
	if truthy(enterprise) {
		resource.SetRaw(EnterpriseSchema, enterprise)
	}
	metadata, err := meta(link, "User", base+"/Users/"+id)
	if err != nil {
		return nil, err
	}
	resource.SetRaw("meta", metadata)
	return resource, nil
}

func groupResource(link *core.Object, base string) (*core.Object, error) {
	values, ok := link.Get("members").([]any)
	if !ok {
		return nil, &core.TypeError{Message: "link.members.map is not a function"}
	}
	members := make([]any, len(values))
	for index, value := range values {
		encoded, err := encodeURIComponent(jsString(value))
		if err != nil {
			return nil, err
		}
		members[index] = core.NewObject("value", value, "$ref", base+"/Users/"+encoded, "type", "User")
	}
	id, err := encodeURIComponent(jsString(link.Get("id")))
	if err != nil {
		return nil, err
	}
	resource := core.NewObject()
	resource.SetRaw("schemas", []any{GroupSchema})
	resource.SetRaw("id", link.Get("id"))
	resource.SetRaw("externalId", link.Get("externalId"))
	resource.SetRaw("displayName", link.Get("displayName"))
	resource.SetRaw("members", members)
	metadata, err := meta(link, "Group", base+"/Groups/"+id)
	if err != nil {
		return nil, err
	}
	resource.SetRaw("meta", metadata)
	return resource, nil
}

// serviceProviderConfig describes exactly the implemented subset: filtering, sorting, PATCH, bulk, ETags,
// pagination; no password changes.
func serviceProviderConfig() *core.Object {
	return core.NewObject(
		"schemas", []any{"urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"},
		"patch", core.NewObject("supported", true),
		"bulk", core.NewObject("supported", true, "maxOperations", BulkMaxOperations, "maxPayloadSize", MaxPayloadSize),
		"filter", core.NewObject("supported", true, "maxResults", 200),
		"changePassword", core.NewObject("supported", false),
		"sort", core.NewObject("supported", true),
		"etag", core.NewObject("supported", true),
		"authenticationSchemes", []any{core.NewObject(
			"type", "oauthbearertoken",
			"name", "Scoped SCIM bearer token",
			"description", "Connection-scoped bearer token",
			"specUri", "https://www.rfc-editor.org/rfc/rfc6750",
			"primary", true,
		)},
	)
}

func attribute(name string, overrides ...any) *core.Object {
	return core.NewObject(
		"name", name, "type", "string", "multiValued", false, "required", false, "mutability", "readWrite", "returned", "default",
	).Assign(core.NewObject(overrides...))
}

func resourceTypeDocuments() []*core.Object {
	var documents []*core.Object
	for _, name := range []string{"User", "Group"} {
		schema := GroupSchema
		if name == "User" {
			schema = UserSchema
		}
		document := core.NewObject(
			"schemas", []any{"urn:ietf:params:scim:schemas:core:2.0:ResourceType"},
			"id", name,
			"name", name,
			"endpoint", "/"+name+"s",
			"schema", schema,
		)
		if name == "User" {
			document.Set("schemaExtensions", []any{core.NewObject("schema", EnterpriseSchema, "required", false)})
		}
		documents = append(documents, document)
	}
	return documents
}

func schemaDocuments() []*core.Object {
	var userAttributes []any
	for _, name := range []string{"userName", "displayName", "externalId", "active", "title"} {
		kind := "string"
		if name == "active" {
			kind = "boolean"
		}
		uniqueness := "none"
		if name == "userName" {
			uniqueness = "server"
		}
		userAttributes = append(userAttributes, attribute(name, "type", kind, "required", name == "userName", "uniqueness", uniqueness, "caseExact", name == "externalId"))
	}
	var nameAttributes []any
	for _, name := range []string{"formatted", "familyName", "givenName", "middleName", "honorificPrefix", "honorificSuffix"} {
		nameAttributes = append(nameAttributes, attribute(name))
	}
	userAttributes = append(userAttributes, attribute("name", "type", "complex", "subAttributes", nameAttributes))
	var emailAttributes []any
	for _, name := range []string{"value", "type", "display", "primary"} {
		kind := "string"
		if name == "primary" {
			kind = "boolean"
		}
		emailAttributes = append(emailAttributes, attribute(name, "type", kind, "required", name == "value"))
	}
	userAttributes = append(userAttributes, attribute("emails", "type", "complex", "multiValued", true, "subAttributes", emailAttributes))

	var enterpriseAttributes []any
	for _, name := range []string{"employeeNumber", "costCenter", "organization", "division", "department"} {
		enterpriseAttributes = append(enterpriseAttributes, attribute(name))
	}
	var managerAttributes []any
	for _, name := range []string{"value", "displayName", "$ref"} {
		managerAttributes = append(managerAttributes, attribute(name))
	}
	enterpriseAttributes = append(enterpriseAttributes, attribute("manager", "type", "complex", "subAttributes", managerAttributes))

	schemaKind := []any{"urn:ietf:params:scim:schemas:core:2.0:Schema"}
	return []*core.Object{
		core.NewObject("id", UserSchema, "name", "User", "schemas", schemaKind, "attributes", userAttributes),
		core.NewObject("id", EnterpriseSchema, "name", "EnterpriseUser", "schemas", schemaKind, "attributes", enterpriseAttributes),
		core.NewObject("id", GroupSchema, "name", "Group", "schemas", schemaKind, "attributes", []any{
			attribute("displayName", "required", true, "uniqueness", "none"),
			attribute("members", "type", "complex", "multiValued", true, "subAttributes", []any{core.NewObject(
				"name", "value", "type", "string", "required", true, "mutability", "immutable", "returned", "default",
			)}),
		}),
	}
}
