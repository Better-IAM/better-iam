package scim

// Port of packages/scim/src/index.ts: the SCIM 2.0 provisioning service (createScimService): connection-scoped
// bearer tokens, Users and Groups with RFC 7644 filtering, sorting, attribute projection, `/.search`, PATCH value
// paths, `/Bulk`, ETags and pagination, explicit administrator-controlled group-to-role mappings, and the JSON
// administration API for connections.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// outcome is a SCIM operation's result before it becomes an HTTP response or a bulk operation entry.
type outcome struct {
	status  int
	body    any
	headers map[string]string
}

// scimRequest is one Users/Groups/discovery request, from HTTP or from a bulk operation.
type scimRequest struct {
	method       string
	resourceType string
	// resourceID is "" when absent.
	resourceID string
	// body is nil when absent.
	body        *core.Object
	ifMatch     *string
	ifNoneMatch *string
	// query is the query string (filter, sorting, paging, projection); bulk operations have none (nil).
	query searchParams
}

type listQuery struct {
	filter             string
	startIndex         int
	count              int
	sortBy             string
	sortOrder          string
	attributes         []string
	excludedAttributes []string
}

// searchParams is a parsed URLSearchParams; nil is no query at all.
type searchParams [][2]string

// parseSearchParams is the application/x-www-form-urlencoded parser URLSearchParams uses.
func parseSearchParams(raw string) searchParams {
	out := searchParams{}
	for _, sequence := range strings.Split(raw, "&") {
		if sequence == "" {
			continue
		}
		name, value := sequence, ""
		if at := strings.IndexByte(sequence, '='); at >= 0 {
			name, value = sequence[:at], sequence[at+1:]
		}
		out = append(out, [2]string{formDecode(name), formDecode(value)})
	}
	return out
}

// formDecode replaces '+' with a space and percent-decodes (malformed escapes stay as they are), then decodes UTF-8.
func formDecode(s string) string {
	s = strings.ReplaceAll(s, "+", " ")
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			high, ok1 := hexDigit(s[i+1])
			low, ok2 := hexDigit(s[i+2])
			if ok1 && ok2 {
				out = append(out, high<<4|low)
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return decodeUTF8(out)
}

// get is URLSearchParams#get: the first value, ok false for null.
func (p searchParams) get(name string) (string, bool) {
	for _, pair := range p {
		if pair[0] == name {
			return pair[1], true
		}
	}
	return "", false
}

// value is get as a model value (null when absent).
func (p searchParams) value(name string) any {
	if value, ok := p.get(name); ok {
		return value
	}
	return nil
}

func errorOutcome(err error) outcome {
	var known *core.IamError
	var syntax *core.SyntaxError
	status := 500
	scimType := "invalidSyntax"
	detail := "The SCIM operation failed."
	switch {
	case errors.As(err, &known):
		status, scimType, detail = known.Status, known.Code, known.Message
	case errors.As(err, &syntax):
		status, detail = 400, "Invalid JSON."
	}
	return outcome{status: status, body: core.NewObject(
		"schemas", []any{ErrorSchema},
		"status", core.NumberString(float64(status)),
		"scimType", scimType,
		"detail", detail,
	)}
}

func toResponse(result outcome) *Response { return response(result.body, result.status, result.headers) }

const adminMaxBody = 64 * 1024

// limitedText reads a request body, refusing it once it exceeds limit bytes.
func limitedText(request *http.Request, limit int64) (string, error) {
	if request.Body == nil || request.Body == http.NoBody {
		return "", nil
	}
	data, err := io.ReadAll(io.LimitReader(request.Body, limit+1))
	if err != nil {
		return "", err
	}
	if int64(len(data)) > limit {
		return "", core.NewIamError("PAYLOAD_TOO_LARGE", "Request body is too large.", 413)
	}
	return decodeUTF8(data), nil
}

func pagination(startIndex, count any) (int, int, error) {
	start := 1.0
	if !nullish(startIndex) {
		start = jsNumber(startIndex)
	}
	size := 100.0
	if !nullish(count) {
		size = jsNumber(count)
	}
	if !isInteger(start) || start < 1 || !isInteger(size) || size < 0 {
		return 0, 0, core.NewIamError("invalidValue", "Invalid pagination.")
	}
	if size > 200 {
		size = 200
	}
	if start > 1e15 {
		start = 1e15
	}
	return int(start), int(size), nil
}

func queryFromURL(params searchParams) (*listQuery, error) {
	query := &listQuery{}
	query.filter, _ = params.get("filter")
	var err error
	if query.startIndex, query.count, err = pagination(params.value("startIndex"), params.value("count")); err != nil {
		return nil, err
	}
	query.sortBy, _ = params.get("sortBy")
	query.sortOrder, _ = params.get("sortOrder")
	if query.attributes, _, err = AttributeList(params.value("attributes")); err != nil {
		return nil, err
	}
	if query.excludedAttributes, _, err = AttributeList(params.value("excludedAttributes")); err != nil {
		return nil, err
	}
	return query, nil
}

// queryFromBody reads POST `/.search` (RFC 7644 §3.4.3), which carries the query in a SearchRequest body.
func queryFromBody(body *core.Object) (*listQuery, error) {
	if err := fields(body, "schemas", "filter", "startIndex", "count", "sortBy", "sortOrder", "attributes", "excludedAttributes"); err != nil {
		return nil, err
	}
	schemas, ok := body.Get("schemas").([]any)
	if !ok || len(schemas) != 1 || schemas[0] != SearchSchema {
		return nil, core.NewIamError("invalidSyntax", "A SearchRequest body is required.")
	}
	for _, key := range []string{"filter", "sortBy", "sortOrder"} {
		if value := body.Get(key); !core.IsUndefined(value) {
			if _, isString := value.(string); !isString {
				return nil, core.NewIamError("invalidValue", key+" must be a string.")
			}
		}
	}
	query := &listQuery{}
	query.filter, _ = body.Get("filter").(string)
	var err error
	if query.startIndex, query.count, err = pagination(body.Get("startIndex"), body.Get("count")); err != nil {
		return nil, err
	}
	query.sortBy, _ = body.Get("sortBy").(string)
	query.sortOrder, _ = body.Get("sortOrder").(string)
	if query.attributes, _, err = AttributeList(body.Get("attributes")); err != nil {
		return nil, err
	}
	if query.excludedAttributes, _, err = AttributeList(body.Get("excludedAttributes")); err != nil {
		return nil, err
	}
	return query, nil
}

// Service is the SCIM 2.0 provisioning service (createScimService).
type Service struct {
	// BasePath is where the SCIM protocol is served.
	BasePath string
	// AdminBasePath is where the JSON administration API is served.
	AdminBasePath string
	config        *Config
	store         core.IamStore
	provisioning  *provisioning
}

// NewService builds the SCIM service (createScimService).
func NewService(config Config) (*Service, error) {
	basePath := config.BasePath
	if basePath == "" {
		basePath = "/scim/v2"
	}
	basePath = strings.TrimSuffix(basePath, "/")
	if !strings.HasPrefix(basePath, "/") {
		return nil, core.NewIamError("configuration", "SCIM basePath must be absolute.")
	}
	adminBasePath := config.AdminBasePath
	if adminBasePath == "" {
		adminBasePath = "/scim/admin"
	}
	adminBasePath = strings.TrimSuffix(adminBasePath, "/")
	if !strings.HasPrefix(adminBasePath, "/") {
		return nil, core.NewIamError("configuration", "SCIM adminBasePath must be absolute.")
	}
	if adminBasePath == basePath || strings.HasPrefix(adminBasePath, basePath+"/") || strings.HasPrefix(basePath, adminBasePath+"/") {
		return nil, core.NewIamError("configuration", "SCIM adminBasePath must not overlap basePath.")
	}
	stored := config
	provisioning, err := newProvisioning(&stored)
	if err != nil {
		return nil, err
	}
	return &Service{BasePath: basePath, AdminBasePath: adminBasePath, config: &stored, store: config.Store, provisioning: provisioning}, nil
}

// missingBody is the TypeError reading an absent body throws (Object.keys(undefined)).
func missingBody() error { return typeError("Cannot convert undefined or null to object") }

func (s *Service) perform(ctx context.Context, tx core.IamStore, connection *core.Object, base string, request scimRequest) (outcome, error) {
	method, resourceType, resourceID := request.method, request.resourceType, request.resourceID
	if method == "GET" && resourceType == "ServiceProviderConfig" {
		return outcome{status: 200, body: serviceProviderConfig()}, nil
	}
	if method == "GET" && (resourceType == "ResourceTypes" || resourceType == "Schemas") {
		resources := schemaDocuments()
		if resourceType == "ResourceTypes" {
			resources = resourceTypeDocuments()
		}
		if resourceID != "" {
			for _, resource := range resources {
				if resource.Get("id") == resourceID {
					return outcome{status: 200, body: resource}, nil
				}
			}
			return outcome{}, core.NewIamError("notFound", "Schema not found.", 404)
		}
		list := make([]any, len(resources))
		for index, resource := range resources {
			list[index] = resource
		}
		return outcome{status: 200, body: listResponse(list, len(list), 1)}, nil
	}
	if resourceType != "Users" && resourceType != "Groups" {
		return outcome{}, core.NewIamError("notFound", "Unsupported SCIM resource.", 404)
	}
	collection := "scimGroups"
	if resourceType == "Users" {
		collection = "scimUsers"
	}
	render := func(row *core.Object) (*core.Object, error) {
		if resourceType == "Users" {
			return userResource(row, base)
		}
		return groupResource(row, base)
	}
	var projectionAttributes, projectionExcluded []string
	if request.query != nil {
		var err error
		if projectionAttributes, _, err = AttributeList(request.query.value("attributes")); err != nil {
			return outcome{}, err
		}
		if projectionExcluded, _, err = AttributeList(request.query.value("excludedAttributes")); err != nil {
			return outcome{}, err
		}
	}
	present := func(row *core.Object) (*core.Object, error) {
		rendered, err := render(row)
		if err != nil {
			return nil, err
		}
		return ProjectResource(rendered, projectionAttributes, projectionExcluded)
	}

	search := resourceID == ".search"
	if (method == "GET" && resourceID == "") || (method == "POST" && search) {
		var query *listQuery
		var err error
		if search {
			if request.body == nil {
				return outcome{}, missingBody()
			}
			query, err = queryFromBody(request.body)
		} else {
			query, err = queryFromURL(request.query)
		}
		if err != nil {
			return outcome{}, err
		}
		rows, err := tx.Find(ctx, collection, core.NewObject("tenantId", connection.Get("tenantId"), "connectionId", connection.Get("id")), nil)
		if err != nil {
			return outcome{}, err
		}
		sort.SliceStable(rows, func(i, j int) bool {
			return localeCompare(jsString(rows[i].Get("id")), jsString(rows[j].Get("id"))) < 0
		})
		rendered := make([]*core.Object, len(rows))
		for index, row := range rows {
			if rendered[index], err = render(row); err != nil {
				return outcome{}, err
			}
		}
		predicate, err := ParseScimFilter(query.filter)
		if err != nil {
			return outcome{}, err
		}
		var filtered []*core.Object
		for _, resource := range rendered {
			if predicate(resource) {
				filtered = append(filtered, resource)
			}
		}
		matches, err := SortResources(filtered, query.sortBy, query.sortOrder)
		if err != nil {
			return outcome{}, err
		}
		start := query.startIndex - 1
		if start > len(matches) {
			start = len(matches)
		}
		end := start + query.count
		if end > len(matches) {
			end = len(matches)
		}
		page := make([]any, 0, end-start)
		for _, resource := range matches[start:end] {
			projected, err := ProjectResource(resource, query.attributes, query.excludedAttributes)
			if err != nil {
				return outcome{}, err
			}
			page = append(page, projected)
		}
		return outcome{status: 200, body: listResponse(page, len(matches), query.startIndex)}, nil
	}
	if search {
		return outcome{}, core.NewIamError("invalidMethod", "/.search accepts POST only.", 405)
	}

	var row *core.Object
	if resourceID != "" {
		found, err := tx.Get(ctx, collection, resourceID)
		if err != nil {
			return outcome{}, err
		}
		if found == nil || found.Get("tenantId") != connection.Get("tenantId") || found.Get("connectionId") != connection.Get("id") {
			return outcome{}, core.NewIamError("notFound", "Resource not found.", 404)
		}
		row = found
	}
	if row != nil && request.ifMatch != nil && *request.ifMatch != "" && *request.ifMatch != "*" && *request.ifMatch != `W/"`+jsString(row.Get("version"))+`"` {
		return outcome{}, core.NewIamError("invalidVers", "Version conflict.", 412)
	}
	if method == "GET" && row != nil {
		etag := `W/"` + jsString(row.Get("version")) + `"`
		if request.ifNoneMatch != nil && (*request.ifNoneMatch == etag || *request.ifNoneMatch == "*") {
			return outcome{status: 304, body: nil, headers: map[string]string{"etag": etag}}, nil
		}
		presented, err := present(row)
		if err != nil {
			return outcome{}, err
		}
		return outcome{status: 200, body: presented, headers: map[string]string{"etag": etag}}, nil
	}
	saved := func(status int, link *core.Object) (outcome, error) {
		presented, err := present(link)
		if err != nil {
			return outcome{}, err
		}
		return outcome{status: status, body: presented, headers: map[string]string{
			"location": base + "/" + resourceType + "/" + jsString(link.Get("id")),
			"etag":     `W/"` + jsString(link.Get("version")) + `"`,
		}}, nil
	}
	if method == "POST" && resourceID == "" {
		if request.body == nil {
			return outcome{}, missingBody()
		}
		var link *core.Object
		var err error
		if resourceType == "Users" {
			link, err = s.provisioning.saveUser(ctx, tx, connection, request.body, nil)
		} else {
			link, err = s.provisioning.saveGroup(ctx, tx, connection, request.body, nil)
		}
		if err != nil {
			return outcome{}, err
		}
		return saved(201, link)
	}
	if row != nil && (method == "PUT" || method == "PATCH") {
		if request.body == nil {
			return outcome{}, missingBody()
		}
		var link *core.Object
		var err error
		switch {
		case method == "PATCH":
			link, err = s.provisioning.patch(ctx, tx, connection, resourceType, row, request.body)
		case resourceType == "Users":
			link, err = s.provisioning.saveUser(ctx, tx, connection, request.body, row)
		default:
			link, err = s.provisioning.saveGroup(ctx, tx, connection, request.body, row)
		}
		if err != nil {
			return outcome{}, err
		}
		return saved(200, link)
	}
	if row != nil && method == "DELETE" {
		var err error
		if resourceType == "Users" {
			err = s.provisioning.deleteUser(ctx, tx, connection, row)
		} else {
			err = s.provisioning.deleteGroup(ctx, tx, connection, row)
		}
		if err != nil {
			return outcome{}, err
		}
		if err := tx.Delete(ctx, collection, jsString(row.Get("id"))); err != nil {
			return outcome{}, err
		}
		action := "iam:scim:DeleteGroup"
		if resourceType == "Users" {
			action = "iam:scim:DeleteUser"
		}
		if err := s.provisioning.audit(ctx, tx, connection, action, row.Get("id"), ""); err != nil {
			return outcome{}, err
		}
		return outcome{status: 204, body: nil}, nil
	}
	return outcome{}, core.NewIamError("invalidMethod", "Method is not supported for this resource.", 405)
}

// run runs one request in its own transaction, so a failed bulk operation never leaves partial writes.
func (s *Service) run(ctx context.Context, header http.Header, connectionID, base string, request scimRequest) (outcome, error) {
	return core.Transact(ctx, s.store, func(ctx context.Context, tx core.IamStore) (outcome, error) {
		connection, err := s.provisioning.authenticate(ctx, tx, header, connectionID)
		if err != nil {
			return outcome{}, err
		}
		return s.perform(ctx, tx, connection, base, request)
	})
}

type bulkOperation struct {
	method  string
	bulkID  *string
	path    string
	data    any
	version *string
}

var bulkIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
var bulkReference = regexp.MustCompile(`bulkId:([A-Za-z0-9_.-]+)`)
var bulkPath = regexp.MustCompile(`^/(Users|Groups)(?:/([^/?]+))?$`)

// bulk is RFC 7644 §3.7 bulk: each operation commits independently; `bulkId:` references resolve to resources created
// earlier in the request in any order, and `failOnErrors` stops processing after that many failures.
func (s *Service) bulk(ctx context.Context, header http.Header, connectionID, base string, body *core.Object) (outcome, error) {
	if body == nil {
		return outcome{}, missingBody()
	}
	if err := fields(body, "schemas", "Operations", "failOnErrors"); err != nil {
		return outcome{}, err
	}
	schemas, ok := body.Get("schemas").([]any)
	if !ok || len(schemas) != 1 || schemas[0] != BulkRequestSchema {
		return outcome{}, core.NewIamError("invalidSyntax", "A BulkRequest body is required.")
	}
	items, ok := body.Get("Operations").([]any)
	if !ok || len(items) == 0 {
		return outcome{}, core.NewIamError("invalidSyntax", "Bulk requests require at least one operation.")
	}
	if len(items) > BulkMaxOperations {
		return outcome{}, core.NewIamError("tooMany", "Bulk requests accept at most "+core.NumberString(BulkMaxOperations)+" operations.", 413)
	}
	failOnErrors := body.Get("failOnErrors")
	if !core.IsUndefined(failOnErrors) && (!isInteger(failOnErrors) || failOnErrors.(float64) < 1) {
		return outcome{}, core.NewIamError("invalidValue", "failOnErrors must be a positive integer.")
	}
	// An invalid credential fails the whole request rather than every operation individually.
	if err := s.store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		_, err := s.provisioning.authenticate(ctx, tx, header, connectionID)
		return err
	}); err != nil {
		return outcome{}, err
	}

	declared := map[string]bool{}
	operations := make([]*bulkOperation, 0, len(items))
	for index, item := range items {
		op, err := object(item)
		if err != nil {
			return outcome{}, err
		}
		if err := fields(op, "method", "bulkId", "path", "data", "version"); err != nil {
			return outcome{}, err
		}
		method := ""
		if name, ok := op.Get("method").(string); ok {
			method = upperMethod(name)
		}
		if method != "POST" && method != "PUT" && method != "PATCH" && method != "DELETE" {
			return outcome{}, core.NewIamError("invalidSyntax", "Operation "+core.NumberString(float64(index+1))+" has an unsupported method.")
		}
		path, err := requiredText(op.Get("path"), "path")
		if err != nil {
			return outcome{}, err
		}
		var bulkID *string
		if raw := op.Get("bulkId"); !core.IsUndefined(raw) {
			if bulkID, err = text(raw, "bulkId"); err != nil {
				return outcome{}, err
			}
		}
		if bulkID != nil {
			if !bulkIDPattern.MatchString(*bulkID) || declared[*bulkID] {
				return outcome{}, core.NewIamError("invalidValue", `bulkId "`+*bulkID+`" is invalid or duplicated.`)
			}
			declared[*bulkID] = true
		}
		if method == "POST" && bulkID == nil {
			return outcome{}, core.NewIamError("invalidSyntax", "POST operations require a bulkId.")
		}
		if method != "DELETE" && core.IsUndefined(op.Get("data")) {
			return outcome{}, core.NewIamError("invalidSyntax", method+" operations require data.")
		}
		var version *string
		if raw := op.Get("version"); !core.IsUndefined(raw) {
			if version, err = text(raw, "version"); err != nil {
				return outcome{}, err
			}
		}
		operations = append(operations, &bulkOperation{method: method, bulkID: bulkID, path: path, data: op.Get("data"), version: version})
	}

	created := map[string]string{}
	failed := map[string]bool{}
	results := []any{}
	errorCount := 0
	pending := operations
	record := func(operation *bulkOperation, result outcome) {
		entry := core.NewObject("method", operation.method, "status", core.NumberString(float64(result.status)))
		if operation.bulkID != nil {
			entry.Set("bulkId", *operation.bulkID)
		}
		if location := result.headers["location"]; location != "" {
			entry.Set("location", location)
		}
		if etag := result.headers["etag"]; etag != "" {
			entry.Set("version", etag)
		}
		if result.status >= 400 {
			entry.SetRaw("response", result.body)
			errorCount++
			if operation.bulkID != nil {
				failed[*operation.bulkID] = true
			}
		} else if operation.method == "POST" && operation.bulkID != nil {
			created[*operation.bulkID] = jsString(member(result.body, "id"))
		}
		results = append(results, entry)
	}
	stopped := func() bool {
		limit, isNumber := failOnErrors.(float64)
		return isNumber && float64(errorCount) >= limit
	}
	for len(pending) > 0 && !stopped() {
		var deferred []*bulkOperation
		for _, operation := range pending {
			if stopped() {
				break
			}
			data := operation.data
			if core.IsUndefined(data) {
				data = nil
			}
			serialized := core.MustStringify(core.NewObject("path", operation.path, "data", data))
			var references []string
			for _, match := range bulkReference.FindAllStringSubmatch(serialized, -1) {
				references = append(references, match[1])
			}
			unknown, broken := "", ""
			for _, reference := range references {
				if !declared[reference] {
					unknown = reference
					break
				}
			}
			for _, reference := range references {
				if failed[reference] {
					broken = reference
					break
				}
			}
			if unknown != "" || broken != "" {
				message, status := `Referenced operation "`+broken+`" failed.`, 409
				if unknown != "" {
					message, status = `Unknown bulkId reference "`+unknown+`".`, 400
				}
				record(operation, errorOutcome(core.NewIamError("invalidValue", message, status)))
				continue
			}
			waiting := false
			for _, reference := range references {
				if _, ok := created[reference]; !ok {
					waiting = true
				}
			}
			if waiting {
				deferred = append(deferred, operation)
				continue
			}
			replaced := bulkReference.ReplaceAllStringFunc(serialized, func(match string) string {
				return created[match[len("bulkId:"):]]
			})
			result := func() (result outcome) {
				parsed, err := core.ParseJSONString(replaced)
				if err != nil {
					return errorOutcome(err)
				}
				resolved := parsed.(*core.Object)
				resolvedPath := jsString(resolved.Get("path"))
				match := bulkPath.FindStringSubmatch(resolvedPath)
				hasID := match != nil && match[2] != ""
				if match == nil || (operation.method == "POST") == hasID {
					return errorOutcome(core.NewIamError("invalidPath", `Invalid bulk operation path "`+operation.path+`".`))
				}
				request := scimRequest{method: operation.method, resourceType: match[1], ifMatch: operation.version}
				if hasID {
					if request.resourceID, err = decodeURIComponent(match[2]); err != nil {
						return errorOutcome(err)
					}
				}
				if resolvedData := resolved.Get("data"); resolvedData != nil {
					if request.body, err = object(resolvedData); err != nil {
						return errorOutcome(err)
					}
				}
				result, err = s.run(ctx, header, connectionID, base, request)
				if err != nil {
					return errorOutcome(err)
				}
				if operation.method == "DELETE" {
					result.headers = map[string]string{"location": base + resolvedPath}
				}
				return result
			}()
			record(operation, result)
		}
		if len(deferred) == len(pending) {
			// Nothing progressed: the remaining operations reference each other in a cycle.
			for _, operation := range deferred {
				record(operation, errorOutcome(core.NewIamError("invalidValue", "Circular bulkId references cannot be resolved.", 409)))
			}
			break
		}
		pending = deferred
	}
	return outcome{status: 200, body: core.NewObject("schemas", []any{BulkResponseSchema}, "Operations", results)}, nil
}

func (s *Service) summary(connection *core.Object, users, groups int) *core.Object {
	return core.NewObject(
		"id", connection.Get("id"),
		"tenantId", connection.Get("tenantId"),
		"name", connection.Get("name"),
		"path", s.BasePath+"/"+jsString(connection.Get("id")),
		"expiresAt", connection.Get("expiresAt"),
		"revoked", connection.Get("revoked"),
		"createdAt", connection.Get("createdAt"),
		"lastUsedAt", connection.Get("lastUsedAt"),
		"rotatedAt", connection.Get("rotatedAt"),
		"users", users,
		"groups", groups,
		"roleMappings", connection.Get("roleMappings"),
	)
}

func lifetime(expiresIn any) (float64, error) {
	seconds := coalesceValue(expiresIn, float64(90*86400))
	value, ok := seconds.(float64)
	if !isInteger(seconds) || !ok || value < 60 || value > 365*86400 {
		return 0, core.NewIamError("invalidValue", "Credential lifetime must be between 60 seconds and one year.")
	}
	return value, nil
}

func (s *Service) authorize(ctx context.Context, credential core.CredentialInput, action, tenantID, id string) error {
	return s.config.Authorize(ctx, credential, action, core.ResourceRef{TenantID: tenantID, Type: "scim", ID: id})
}

// CreateConnectionInput is the input of CreateConnection.
type CreateConnectionInput struct {
	TenantID string
	Name     string
	// ExpiresIn is the token lifetime in seconds (default 90 days).
	ExpiresIn *float64
}

// CreateConnection issues a connection-scoped bearer token; the plaintext is returned once and stored only as a hash.
// The result is `{ id, tenantId, token, expiresAt, path }`.
func (s *Service) CreateConnection(ctx context.Context, credential core.CredentialInput, input CreateConnectionInput) (*core.Object, error) {
	return s.createConnection(ctx, credential, input.TenantID, input.Name, optionalNumber(input.ExpiresIn))
}

func optionalNumber(value *float64) any {
	if value == nil {
		return core.Undefined
	}
	return *value
}

func (s *Service) createConnection(ctx context.Context, credential core.CredentialInput, tenantID string, nameValue, expiresInValue any) (*core.Object, error) {
	name, err := requiredText(nameValue, "name")
	if err != nil {
		return nil, err
	}
	expiresIn, err := lifetime(expiresInValue)
	if err != nil {
		return nil, err
	}
	token := base64url(randomBytes(32))
	connection := core.NewObject(
		"id", randomUUID(),
		"tenantId", tenantID,
		"name", name,
		"tokenHash", hash(token),
		"expiresAt", s.config.now()+expiresIn*1000,
		"revoked", false,
		"roleMappings", core.NewObject(),
		"createdAt", s.config.now(),
	)
	if err := s.store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		if err := s.authorize(ctx, credential, "iam:scim:connections:create", tenantID, "*"); err != nil {
			return err
		}
		actorID, err := s.config.Authenticate(ctx, credential)
		if err != nil {
			return err
		}
		if err := activeTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		if _, err := tx.Insert(ctx, "scimConnections", connection); err != nil {
			return err
		}
		return s.provisioning.audit(ctx, tx, connection, "iam:scim:CreateConnection", connection.Get("id"), actorID)
	}); err != nil {
		return nil, err
	}
	return core.NewObject(
		"id", connection.Get("id"),
		"tenantId", connection.Get("tenantId"),
		"token", token,
		"expiresAt", connection.Get("expiresAt"),
		"path", s.BasePath+"/"+jsString(connection.Get("id")),
	), nil
}

// ListConnections answers a tenant's connections with usage metadata and provisioned counts; tokens are never
// returned.
func (s *Service) ListConnections(ctx context.Context, credential core.CredentialInput, tenantID string) ([]*core.Object, error) {
	return core.Transact(ctx, s.store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
		if err := s.authorize(ctx, credential, "iam:scim:connections:read", tenantID, "*"); err != nil {
			return nil, err
		}
		byTenant := core.NewObject("tenantId", tenantID)
		connections, err := tx.Find(ctx, "scimConnections", byTenant, nil)
		if err != nil {
			return nil, err
		}
		users, err := tx.Find(ctx, "scimUsers", byTenant, nil)
		if err != nil {
			return nil, err
		}
		groups, err := tx.Find(ctx, "scimGroups", byTenant, nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(connections, func(i, j int) bool {
			a, b := connections[i], connections[j]
			difference := jsNumber(coalesceValue(a.Get("createdAt"), 0.0)) - jsNumber(coalesceValue(b.Get("createdAt"), 0.0))
			if difference != 0 && difference == difference {
				return difference < 0
			}
			return localeCompare(jsString(a.Get("id")), jsString(b.Get("id"))) < 0
		})
		result := make([]*core.Object, len(connections))
		for index, connection := range connections {
			userCount, groupCount := 0, 0
			for _, row := range users {
				if row.Get("connectionId") == connection.Get("id") {
					userCount++
				}
			}
			for _, row := range groups {
				if row.Get("connectionId") == connection.Get("id") {
					groupCount++
				}
			}
			result[index] = s.summary(connection, userCount, groupCount)
		}
		return result, nil
	})
}

// RotateTokenInput is the input of RotateToken.
type RotateTokenInput struct {
	TenantID     string
	ConnectionID string
	// ExpiresIn is the new token's lifetime in seconds (default 90 days).
	ExpiresIn *float64
}

// RotateToken replaces the connection's bearer token: the old token stops working immediately, provisioned users,
// groups and role mappings are kept, and the new token is returned once.
func (s *Service) RotateToken(ctx context.Context, credential core.CredentialInput, input RotateTokenInput) (*core.Object, error) {
	return s.rotateToken(ctx, credential, input.TenantID, input.ConnectionID, optionalNumber(input.ExpiresIn))
}

func (s *Service) rotateToken(ctx context.Context, credential core.CredentialInput, tenantID, connectionID string, expiresInValue any) (*core.Object, error) {
	expiresIn, err := lifetime(expiresInValue)
	if err != nil {
		return nil, err
	}
	token := base64url(randomBytes(32))
	return core.Transact(ctx, s.store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		if err := s.authorize(ctx, credential, "iam:scim:credentials:create", tenantID, connectionID); err != nil {
			return nil, err
		}
		actorID, err := s.config.Authenticate(ctx, credential)
		if err != nil {
			return nil, err
		}
		connection, err := tx.Get(ctx, "scimConnections", connectionID)
		if err != nil {
			return nil, err
		}
		if connection == nil || connection.Get("tenantId") != tenantID {
			return nil, core.NewIamError("notFound", "Connection not found.", 404)
		}
		if truthy(connection.Get("revoked")) {
			return nil, core.NewIamError("CONFLICT", "A revoked connection cannot be rotated.", 409)
		}
		if err := activeTenant(ctx, tx, tenantID); err != nil {
			return nil, err
		}
		now := s.config.now()
		rotated := connection.Spread(core.NewObject("tokenHash", hash(token), "expiresAt", now+expiresIn*1000, "rotatedAt", now))
		if _, err := tx.Put(ctx, "scimConnections", rotated); err != nil {
			return nil, err
		}
		if err := s.provisioning.audit(ctx, tx, rotated, "iam:scim:RotateToken", rotated.Get("id"), actorID); err != nil {
			return nil, err
		}
		return core.NewObject(
			"id", rotated.Get("id"),
			"tenantId", rotated.Get("tenantId"),
			"token", token,
			"expiresAt", rotated.Get("expiresAt"),
			"path", s.BasePath+"/"+jsString(rotated.Get("id")),
		), nil
	})
}

// RevokeConnection invalidates the token immediately and removes the bindings its role mappings created.
func (s *Service) RevokeConnection(ctx context.Context, credential core.CredentialInput, tenantID, connectionID string) error {
	return s.store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		if err := s.authorize(ctx, credential, "iam:scim:connections:delete", tenantID, connectionID); err != nil {
			return err
		}
		actorID, err := s.config.Authenticate(ctx, credential)
		if err != nil {
			return err
		}
		connection, err := tx.Get(ctx, "scimConnections", connectionID)
		if err != nil {
			return err
		}
		if connection == nil || connection.Get("tenantId") != tenantID {
			return core.NewIamError("notFound", "Connection not found.", 404)
		}
		if _, err := tx.Put(ctx, "scimConnections", connection.Spread(core.NewObject("revoked", true))); err != nil {
			return err
		}
		if err := deleteAll(ctx, tx, "bindings", core.NewObject("tenantId", tenantID, "scimConnectionId", connection.Get("id"))); err != nil {
			return err
		}
		return s.provisioning.audit(ctx, tx, connection, "iam:scim:RevokeConnection", connection.Get("id"), actorID)
	})
}

// ListGroups answers the groups the IdP pushed through a connection, by name, with member counts and mapped roles:
// `{ id, groupId, displayName, externalId?, members, roleIds }`.
func (s *Service) ListGroups(ctx context.Context, credential core.CredentialInput, tenantID, connectionID string) ([]*core.Object, error) {
	return core.Transact(ctx, s.store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
		if err := s.authorize(ctx, credential, "iam:scim:connections:read", tenantID, connectionID); err != nil {
			return nil, err
		}
		connection, err := tx.Get(ctx, "scimConnections", connectionID)
		if err != nil {
			return nil, err
		}
		if connection == nil || connection.Get("tenantId") != tenantID {
			return nil, core.NewIamError("notFound", "Connection not found.", 404)
		}
		groups, err := tx.Find(ctx, "scimGroups", core.NewObject("tenantId", tenantID, "connectionId", connection.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(groups, func(i, j int) bool {
			if order := localeCompare(jsString(groups[i].Get("displayName")), jsString(groups[j].Get("displayName"))); order != 0 {
				return order < 0
			}
			return localeCompare(jsString(groups[i].Get("id")), jsString(groups[j].Get("id"))) < 0
		})
		result := make([]*core.Object, len(groups))
		for index, group := range groups {
			summary := core.NewObject("id", group.Get("id"), "groupId", group.Get("groupId"), "displayName", group.Get("displayName"))
			if externalID := group.Get("externalId"); !core.IsUndefined(externalID) {
				summary.Set("externalId", externalID)
			}
			members, _ := group.Get("members").([]any)
			summary.Set("members", len(members))
			roleIDs := roleIDsOf(connection, jsString(group.Get("id")))
			if roleIDs == nil {
				roleIDs = []string{}
			}
			summary.Set("roleIds", stringList(roleIDs))
			result[index] = summary
		}
		return result, nil
	})
}

// SetRoleMappingsInput is the input of SetRoleMappings.
type SetRoleMappingsInput struct {
	TenantID     string
	ConnectionID string
	GroupID      string
	RoleIDs      []string
}

// SetRoleMappings maps a SCIM group to roles; the administrator must hold `iam:bindings:create` on every role.
func (s *Service) SetRoleMappings(ctx context.Context, credential core.CredentialInput, input SetRoleMappingsInput) error {
	roleIDs := []any{}
	for _, roleID := range input.RoleIDs {
		roleIDs = append(roleIDs, roleID)
	}
	return s.setRoleMappings(ctx, credential, input.TenantID, input.ConnectionID, input.GroupID, roleIDs)
}

func (s *Service) setRoleMappings(ctx context.Context, credential core.CredentialInput, tenantID, connectionID, groupID string, roleIDsValue any) error {
	if s.config.SyncRoleMappings == nil {
		return core.NewIamError("configuration", "Role mapping callback is required.")
	}
	list, ok := roleIDsValue.([]any)
	invalid := !ok || len(list) > 100
	roleIDs := make([]string, 0, len(list))
	for _, item := range list {
		roleID, isString := item.(string)
		if !isString || roleID == "" {
			invalid = true
		}
		roleIDs = append(roleIDs, roleID)
	}
	if invalid {
		return core.NewIamError("invalidValue", "roleIds must list at most 100 role IDs.")
	}
	return s.store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		if err := s.authorize(ctx, credential, "iam:scim:mappings:update", tenantID, connectionID); err != nil {
			return err
		}
		actorID, err := s.config.Authenticate(ctx, credential)
		if err != nil {
			return err
		}
		connection, err := tx.Get(ctx, "scimConnections", connectionID)
		if err != nil {
			return err
		}
		group, err := tx.Get(ctx, "scimGroups", groupID)
		if err != nil {
			return err
		}
		if connection == nil || connection.Get("tenantId") != tenantID || group == nil || group.Get("connectionId") != connection.Get("id") {
			return core.NewIamError("notFound", "Connection or group not found.", 404)
		}
		for _, roleID := range roleIDs {
			role, err := tx.Get(ctx, "roles", roleID)
			if err != nil {
				return err
			}
			if role == nil || role.Get("tenantId") != tenantID || role.Get("protected") == true {
				return core.NewIamError("invalidValue", "Role is unavailable.")
			}
			if err := s.config.Authorize(ctx, credential, "iam:bindings:create", core.ResourceRef{TenantID: tenantID, Type: "iam", ID: roleID}); err != nil {
				return err
			}
		}
		mappings := core.NewObject()
		if current, ok := connection.Get("roleMappings").(*core.Object); ok && current != nil {
			mappings = current.Spread()
		}
		mappings.Set(groupID, stringList(uniqueStrings(roleIDs)))
		connection.Set("roleMappings", mappings)
		if _, err := tx.Put(ctx, "scimConnections", connection); err != nil {
			return err
		}
		if err := s.provisioning.syncGroup(ctx, tx, connection, group, &credential); err != nil {
			return err
		}
		return s.provisioning.audit(ctx, tx, connection, "iam:scim:SetRoleMappings", group.Get("id"), actorID)
	})
}

// requestOrigin is `new URL(request.url).origin`.
func requestOrigin(r *http.Request) string {
	scheme, host := r.URL.Scheme, r.URL.Host
	if scheme == "" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
	}
	if host == "" {
		host = r.Host
	}
	parsed, err := auth.ParseFetchURL(scheme + "://" + host + "/")
	if err != nil {
		return "null"
	}
	origin := parsed.Protocol + "//" + parsed.Hostname
	if parsed.Port != "" {
		origin += ":" + parsed.Port
	}
	return origin
}

// jsonContentType is /application\/(scim\+)?json/i.test(contentType).
func jsonContentType(value string) bool {
	lower := strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, value)
	return strings.Contains(lower, "application/json") || strings.Contains(lower, "application/scim+json")
}

// Handle is the fetch handler (handler) for `{basePath}/{connectionId}/{Users|Groups|ServiceProviderConfig|
// ResourceTypes|Schemas}[/{id}]`, `{Users|Groups}/.search`, and `Bulk`, plus the JSON administration API under
// `{adminBasePath}/connections/…`. It answers nil for requests outside both paths.
func (s *Service) Handle(r *http.Request) *Response {
	pathname := r.URL.EscapedPath()
	if strings.HasPrefix(pathname, s.AdminBasePath+"/") {
		return s.admin(r, pathname)
	}
	if !strings.HasPrefix(pathname, s.BasePath+"/") {
		return nil
	}
	result, err := s.handle(r, pathname)
	if err != nil {
		return toResponse(errorOutcome(err))
	}
	return toResponse(result)
}

// Handler is Handle as a protocol mount (server.ProtocolService.Handler): it answers and returns true, or returns
// false for requests outside the service's paths.
func (s *Service) Handler(w http.ResponseWriter, r *http.Request) bool {
	answer := s.Handle(r)
	if answer == nil {
		return false
	}
	answer.Write(w)
	return true
}

func (s *Service) handle(r *http.Request, pathname string) (outcome, error) {
	ctx := r.Context()
	raw := strings.Split(pathname[len(s.BasePath)+1:], "/")
	parts := make([]string, len(raw))
	for index, part := range raw {
		decoded, err := decodeURIComponent(part)
		if err != nil {
			return outcome{}, err
		}
		parts[index] = decoded
	}
	connectionID, resourceType, resourceID := parts[0], "", ""
	if len(parts) > 1 {
		resourceType = parts[1]
	}
	if len(parts) > 2 {
		resourceID = parts[2]
	}
	if connectionID == "" || resourceType == "" || len(parts) > 3 {
		return outcome{}, core.NewIamError("notFound", "SCIM resource not found.", 404)
	}
	// Body is parsed before opening a database transaction; network input cannot hold the writer lock.
	var body *core.Object
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		if contentType, ok := headerGet(r.Header, "content-type"); !ok || !jsonContentType(contentType) {
			return outcome{}, core.NewIamError("invalidSyntax", "A JSON content type is required.", 415)
		}
		// Read with a cap: the body arrives before the connection's token is checked.
		text, err := limitedText(r, MaxPayloadSize)
		if err != nil {
			var known *core.IamError
			if errors.As(err, &known) && known.Status == 413 {
				return outcome{}, core.NewIamError("tooLarge", "Request body is too large.", 413)
			}
			return outcome{}, err
		}
		parsed, err := core.ParseJSONString(text)
		if err != nil {
			return outcome{}, err
		}
		if body, err = object(parsed); err != nil {
			return outcome{}, err
		}
	}
	base := requestOrigin(r) + s.BasePath + "/" + mustEncode(connectionID)
	if resourceType == "Bulk" {
		if r.Method != "POST" || resourceID != "" {
			return outcome{}, core.NewIamError("invalidMethod", "Bulk accepts POST only.", 405)
		}
		return s.bulk(ctx, r.Header, connectionID, base, body)
	}
	request := scimRequest{method: r.Method, resourceType: resourceType, resourceID: resourceID, body: body, query: parseSearchParams(r.URL.RawQuery)}
	if value, ok := headerGet(r.Header, "if-match"); ok {
		request.ifMatch = &value
	}
	if value, ok := headerGet(r.Header, "if-none-match"); ok {
		request.ifNoneMatch = &value
	}
	return s.run(ctx, r.Header, connectionID, base, request)
}

// adminRoutes are the JSON administration routes.
var adminRoutes = map[string]func(s *Service, ctx context.Context, credential core.CredentialInput, body *core.Object) (any, error){
	"connections/list": func(s *Service, ctx context.Context, credential core.CredentialInput, body *core.Object) (any, error) {
		tenantID, err := requiredText(body.Get("tenantId"), "tenantId")
		if err != nil {
			return nil, err
		}
		return s.ListConnections(ctx, credential, tenantID)
	},
	"connections/create": func(s *Service, ctx context.Context, credential core.CredentialInput, body *core.Object) (any, error) {
		tenantID, err := requiredText(body.Get("tenantId"), "tenantId")
		if err != nil {
			return nil, err
		}
		return s.createConnection(ctx, credential, tenantID, body.Get("name"), body.Get("expiresIn"))
	},
	"connections/rotate": func(s *Service, ctx context.Context, credential core.CredentialInput, body *core.Object) (any, error) {
		tenantID, err := requiredText(body.Get("tenantId"), "tenantId")
		if err != nil {
			return nil, err
		}
		connectionID, err := requiredText(body.Get("connectionId"), "connectionId")
		if err != nil {
			return nil, err
		}
		return s.rotateToken(ctx, credential, tenantID, connectionID, body.Get("expiresIn"))
	},
	"connections/revoke": func(s *Service, ctx context.Context, credential core.CredentialInput, body *core.Object) (any, error) {
		tenantID, err := requiredText(body.Get("tenantId"), "tenantId")
		if err != nil {
			return nil, err
		}
		connectionID, err := requiredText(body.Get("connectionId"), "connectionId")
		if err != nil {
			return nil, err
		}
		return nil, s.RevokeConnection(ctx, credential, tenantID, connectionID)
	},
	"connections/groups": func(s *Service, ctx context.Context, credential core.CredentialInput, body *core.Object) (any, error) {
		tenantID, err := requiredText(body.Get("tenantId"), "tenantId")
		if err != nil {
			return nil, err
		}
		connectionID, err := requiredText(body.Get("connectionId"), "connectionId")
		if err != nil {
			return nil, err
		}
		return s.ListGroups(ctx, credential, tenantID, connectionID)
	},
	"connections/mappings": func(s *Service, ctx context.Context, credential core.CredentialInput, body *core.Object) (any, error) {
		tenantID, err := requiredText(body.Get("tenantId"), "tenantId")
		if err != nil {
			return nil, err
		}
		connectionID, err := requiredText(body.Get("connectionId"), "connectionId")
		if err != nil {
			return nil, err
		}
		groupID, err := requiredText(body.Get("groupId"), "groupId")
		if err != nil {
			return nil, err
		}
		return nil, s.setRoleMappings(ctx, credential, tenantID, connectionID, groupID, body.Get("roleIds"))
	},
}

// jsonReply is Response.json(body, { status, headers }).
func jsonReply(body any, status int, header http.Header) *Response {
	header.Set("Content-Type", "application/json")
	return &Response{Status: status, Header: header, Body: stringify(body)}
}

// objectList converts records to a model array.
func objectList(records []*core.Object) []any {
	out := make([]any, len(records))
	for index, record := range records {
		out[index] = record
	}
	return out
}

// admin is the JSON administration API for consoles and scripts: `POST {adminBasePath}/connections/…` with the
// caller's IAM credential. Like the IAM API it requires `X-Better-IAM: 1`, a JSON object body, and a same-origin
// `Origin` when one is sent, and answers `{ data }` or `{ error: { code, message } }`.
func (s *Service) admin(r *http.Request, pathname string) *Response {
	reply := func(body any, status int) *Response {
		header := http.Header{}
		header.Set("Cache-Control", "no-store")
		header.Set("X-Content-Type-Options", "nosniff")
		return jsonReply(body, status, header)
	}
	route, ok := adminRoutes[pathname[len(s.AdminBasePath)+1:]]
	if !ok {
		return reply(core.NewObject("error", core.NewObject("code", "NOT_FOUND", "message", "Unknown route.")), 404)
	}
	data, err := func() (any, error) {
		if r.Method != "POST" {
			return nil, core.NewIamError("METHOD_NOT_ALLOWED", "Use POST.", 405)
		}
		marker, _ := headerGet(r.Header, "x-better-iam")
		contentType, _ := headerGet(r.Header, "content-type")
		if marker != "1" || !strings.HasPrefix(core.JSLower(contentType), "application/json") {
			return nil, core.NewIamError("CSRF_REJECTED", "JSON requests require X-Better-IAM: 1.", 403)
		}
		if origin, present := headerGet(r.Header, "origin"); present && origin != requestOrigin(r) {
			return nil, core.NewIamError("CSRF_REJECTED", "Cross-origin requests are rejected.", 403)
		}
		raw, err := limitedText(r, adminMaxBody)
		if err != nil {
			return nil, err
		}
		parsed, err := core.ParseJSONString(raw)
		if err != nil {
			return nil, core.NewIamError("INVALID_INPUT", "The body must be JSON.")
		}
		body, ok := parsed.(*core.Object)
		if !ok || body == nil {
			return nil, core.NewIamError("INVALID_INPUT", "The body must be a JSON object.")
		}
		result, err := route(s, r.Context(), core.CredentialInput{Headers: r.Header}, body)
		if err != nil {
			return nil, err
		}
		if records, isList := result.([]*core.Object); isList {
			return objectList(records), nil
		}
		if record, isRecord := result.(*core.Object); isRecord && record == nil {
			return nil, nil
		}
		return result, nil
	}()
	if err != nil {
		var known *core.IamError
		if errors.As(err, &known) {
			return reply(core.NewObject("error", core.NewObject("code", known.Code, "message", known.Message)), known.Status)
		}
		return reply(core.NewObject("error", core.NewObject("code", "INTERNAL_ERROR", "message", "The SCIM administration request failed.")), 500)
	}
	return reply(core.NewObject("data", data), 200)
}
