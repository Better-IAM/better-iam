package scim

// Port of packages/scim/src/outbound.ts: outbound SCIM 2.0 provisioning (createScimProvisioner). It keeps downstream
// applications' user directories in step with a tenant's members: each target receives the active members in scope
// (all members, or members of chosen groups) as SCIM users keyed by `externalId`; people who leave scope, are
// disabled, or are deleted are deactivated (or deleted) downstream.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

var loopbackHosts = []string{"localhost", "127.0.0.1", "[::1]"}

// provisioningAttributes are the SCIM user attributes the provisioner can fill from declared identity attributes.
var provisioningAttributes = []string{"title", "department", "division", "employeeNumber"}

// ProvisioningConfig configures the outbound provisioner (ProvisioningConfig).
type ProvisioningConfig struct {
	Store core.IamStore
	// Authorize checks `iam:scim:targets:*` on `scim/outbound/{targetId}` (and `iam:identities:read`).
	Authorize func(ctx context.Context, credential core.CredentialInput, action string, resource core.ResourceRef) error
	// Authenticate resolves a credential to the ID of its identity.
	Authenticate func(ctx context.Context, credential core.CredentialInput) (identityID string, err error)
	// EncryptionKey is a base64-encoded 32-byte key that encrypts downstream bearer tokens at rest.
	EncryptionKey string
	// PreviousEncryptionKeys are keys being rotated out (base64, 32 bytes each): tokens sealed with them still open,
	// and RotateKeys re-seals them with EncryptionKey.
	PreviousEncryptionKeys []string
	// AllowInsecureLocalhost allows `http://` targets on loopback addresses, for local development and tests only.
	AllowInsecureLocalhost bool
	// AllowPrivateNetworks lets targets resolve to private and reserved addresses. Off by default: tenant
	// administrators choose target URLs, so without this they could make the server call into its own network.
	AllowPrivateNetworks bool
	// TimeoutMs is the per-request timeout for downstream calls (0: 10 seconds).
	TimeoutMs int64
	// Fetch replaces the default transport, which enforces the address rules above and refuses redirects; a
	// replacement must enforce its own.
	Fetch func(request *http.Request) (*http.Response, error)
	// RecordAudit records an audit event and fans it out (webhooks, subscribers).
	RecordAudit func(ctx context.Context, tx core.IamStore, event *core.Object) error
	// BasePath is where Handle serves the JSON management API (`{basePath}/targets/{list,get,create,update,delete,
	// sync,preview}`), default "/scim/provisioning" ("" means the default).
	BasePath string
	// Now is Go-only: the wall clock the TypeScript package reads with Date.now(), in milliseconds.
	Now func() float64
}

// DownstreamError is a failed call to a downstream SCIM service.
type DownstreamError struct {
	Message string
	// Status is the downstream HTTP status, 0 when there was none.
	Status int
}

func (e *DownstreamError) Error() string { return e.Message }

// Provisioner is the outbound SCIM provisioner (createScimProvisioner).
type Provisioner struct {
	// BasePath is where Handle serves the management API.
	BasePath     string
	config       ProvisioningConfig
	key          []byte
	previousKeys [][]byte
	addressRules auth.SafeFetchAddressOptions
	fetch        func(request *http.Request) (*http.Response, error)
	timeout      time.Duration
	mu           sync.Mutex
	running      map[string]*runCall
}

type runCall struct {
	done chan struct{}
	run  *core.Object
	err  error
}

// NewProvisioner builds the outbound provisioner.
func NewProvisioner(config ProvisioningConfig) (*Provisioner, error) {
	key := nodeBase64Decode(config.EncryptionKey)
	if len(key) != 32 {
		return nil, core.NewIamError("configuration", "Provisioning encryptionKey must encode exactly 32 bytes.")
	}
	var previous [][]byte
	for _, value := range config.PreviousEncryptionKeys {
		decoded := nodeBase64Decode(value)
		if len(decoded) != 32 {
			return nil, core.NewIamError("configuration", "Each previous provisioning encryption key must encode exactly 32 bytes.")
		}
		previous = append(previous, decoded)
	}
	// Tenant administrators choose target URLs, so the default transport refuses private and reserved addresses at
	// connect time (a hostname cannot be re-pointed at the internal network after validation) and bounds responses.
	rules := auth.SafeFetchAddressOptions{AnyPort: true, AllowInsecureLocalhost: config.AllowInsecureLocalhost, AllowPrivateNetworks: config.AllowPrivateNetworks}
	fetch := config.Fetch
	if fetch == nil {
		maxBytes := int64(1_000_000)
		fetch = auth.CreateGuardedFetch(auth.GuardedFetchOptions{SafeFetchAddressOptions: rules, MaxBytes: &maxBytes}).DoRedirectError
	}
	timeoutMs := config.TimeoutMs
	if timeoutMs == 0 {
		timeoutMs = 10_000
	}
	basePath := config.BasePath
	if basePath == "" {
		basePath = "/scim/provisioning"
	}
	return &Provisioner{
		BasePath:     strings.TrimSuffix(basePath, "/"),
		config:       config,
		key:          key,
		previousKeys: previous,
		addressRules: rules,
		fetch:        fetch,
		timeout:      time.Duration(timeoutMs) * time.Millisecond,
		running:      map[string]*runCall{},
	}, nil
}

func (p *Provisioner) now() float64 {
	if p.config.Now != nil {
		return p.config.Now()
	}
	return wallClock()
}

func (p *Provisioner) seal(value string) string {
	block, _ := aes.NewCipher(p.key)
	gcm, _ := cipher.NewGCM(block)
	iv := randomBytes(12)
	sealed := gcm.Seal(nil, iv, utf8Bytes(value), nil)
	return base64.StdEncoding.EncodeToString(append(iv, sealed...))
}

// openWith opens a sealed token with the current key or a previous one; index 0 is the current key.
func (p *Provisioner) openWith(value string) (string, int, bool) {
	buffer := nodeBase64Decode(value)
	if len(buffer) < 28 {
		return "", 0, false
	}
	for index, candidate := range append([][]byte{p.key}, p.previousKeys...) {
		block, err := aes.NewCipher(candidate)
		if err != nil {
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			continue
		}
		plain, err := gcm.Open(nil, buffer[:12], buffer[12:], nil)
		if err != nil {
			continue
		}
		return decodeUTF8(plain), index, true
	}
	return "", 0, false
}

func (p *Provisioner) open(value string) (string, error) {
	opened, _, ok := p.openWith(value)
	if !ok {
		return "", core.NewIamError("INVALID_SEALED_VALUE", "The stored downstream token cannot be opened.")
	}
	return opened, nil
}

func invalidTargetInput(message string) error { return core.NewIamError("INVALID_INPUT", message) }

func (p *Provisioner) baseURL(value any) (string, error) {
	const absolute = "The SCIM base URL must be an absolute HTTPS URL."
	parsed, err := auth.ParseFetchURL(jsString(value))
	if err != nil {
		return "", invalidTargetInput(absolute)
	}
	local := p.config.AllowInsecureLocalhost && parsed.Protocol == "http:" && containsString(loopbackHosts, parsed.Hostname)
	username, password := "", ""
	if parsed.User != nil {
		username = parsed.User.Username()
		password, _ = parsed.User.Password()
	}
	if (parsed.Protocol != "https:" && !local) || username != "" || password != "" || parsed.Fragment != "" || parsed.RawQuery != "" {
		return "", invalidTargetInput(absolute)
	}
	// IP literals are judged now; hostnames are judged by the transport each time it connects.
	if _, err := auth.CheckFetchURL(parsed.Href, p.addressRules); err != nil {
		return "", invalidTargetInput("The SCIM base URL must point at a public address (see allowPrivateNetworks).")
	}
	origin := parsed.Protocol + "//" + parsed.Hostname
	if parsed.Port != "" {
		origin += ":" + parsed.Port
	}
	return origin + strings.TrimSuffix(parsed.URL.EscapedPath(), "/"), nil
}

var mappingSourcePattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]{0,63}$`)

// lengthOf is `value.length` (undefined: -1).
func lengthOf(value any) int {
	switch v := value.(type) {
	case []any:
		return len(v)
	case string:
		return utf16Len(v)
	}
	return -1
}

// settings validates a target's settings (the input over the current record): `{ name, baseUrl, groupIds,
// deprovision, attributeMapping, pushGroups, enabled }`.
func (p *Provisioner) settings(input, current *core.Object) (*core.Object, error) {
	from := func(key string, fallback any) any {
		value := input.Get(key)
		if nullish(value) && current != nil {
			value = current.Get(key)
		}
		return coalesceValue(value, fallback)
	}
	name := input.Get("name")
	if nullish(name) && current != nil {
		name = current.Get("name")
	}
	groupIDs := from("groupIds", []any{})
	deprovision := from("deprovision", "deactivate")
	mapping := from("attributeMapping", core.NewObject())
	enabled := from("enabled", true)
	pushGroups := from("pushGroups", false)
	push, pushIsBool := pushGroups.(bool)
	if !pushIsBool || (push && lengthOf(groupIDs) <= 0) {
		return nil, invalidTargetInput("pushGroups needs the groups to push in groupIds.")
	}
	nameText, nameIsText := name.(string)
	if !nameIsText || core.JSTrim(nameText) == "" || utf16Len(nameText) > 200 {
		return nil, invalidTargetInput("A target name of at most 200 characters is required.")
	}
	groupList, groupsAreList := groupIDs.([]any)
	invalidGroups := !groupsAreList || len(groupList) > 50
	var groups []string
	for _, id := range groupList {
		text, isText := id.(string)
		if !isText || text == "" {
			invalidGroups = true
		}
		groups = append(groups, text)
	}
	if invalidGroups {
		return nil, invalidTargetInput("groupIds must list at most 50 group IDs.")
	}
	if deprovision != "deactivate" && deprovision != "delete" {
		return nil, invalidTargetInput("deprovision must be deactivate or delete.")
	}
	const mappingMessage = "attributeMapping maps title, department, division, or employeeNumber to identity attributes."
	mappingCopy := core.NewObject()
	switch value := mapping.(type) {
	case *core.Object:
		if value == nil {
			return nil, invalidTargetInput(mappingMessage)
		}
		for _, attribute := range value.Keys() {
			source, isText := value.Get(attribute).(string)
			if !containsString(provisioningAttributes, attribute) || !isText || !mappingSourcePattern.MatchString(source) {
				return nil, invalidTargetInput(mappingMessage)
			}
		}
		mappingCopy = value.Spread()
	case []any:
		if len(value) > 0 {
			return nil, invalidTargetInput(mappingMessage)
		}
	default:
		return nil, invalidTargetInput(mappingMessage)
	}
	if _, enabledIsBool := enabled.(bool); !enabledIsBool {
		return nil, invalidTargetInput("enabled must be a boolean.")
	}
	trimmed := core.JSTrim(nameText)
	base := input.Get("baseUrl")
	if nullish(base) && current != nil {
		base = current.Get("baseUrl")
	}
	baseURL, err := p.baseURL(base)
	if err != nil {
		return nil, err
	}
	if groups == nil {
		groups = []string{}
	}
	return core.NewObject(
		"name", trimmed,
		"baseUrl", baseURL,
		"groupIds", stringList(uniqueStrings(groups)),
		"deprovision", deprovision,
		"attributeMapping", mappingCopy,
		"pushGroups", push,
		"enabled", enabled,
	), nil
}

func downstreamToken(value any) (string, error) {
	text, ok := value.(string)
	if !ok || utf16Len(text) < 8 || utf16Len(text) > 4096 || hasJSSpace(text) {
		return "", invalidTargetInput("A downstream bearer token is required.")
	}
	return text, nil
}

func (p *Provisioner) summary(ctx context.Context, target *core.Object, store core.IamStore) (*core.Object, error) {
	if store == nil {
		store = p.config.Store
	}
	links, err := store.Find(ctx, "provisioningLinks", core.NewObject("targetId", target.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	provisioned := 0
	for _, link := range links {
		if truthy(link.Get("active")) {
			provisioned++
		}
	}
	groupIDs, _ := target.Get("groupIds").([]any)
	mapping := core.NewObject()
	if value, ok := target.Get("attributeMapping").(*core.Object); ok && value != nil {
		mapping = value.Spread()
	}
	result := core.NewObject(
		"id", target.Get("id"),
		"tenantId", target.Get("tenantId"),
		"name", target.Get("name"),
		"baseUrl", target.Get("baseUrl"),
		"groupIds", append([]any{}, groupIDs...),
		"deprovision", target.Get("deprovision"),
		"attributeMapping", mapping,
		"pushGroups", target.Get("pushGroups") == true,
		"enabled", target.Get("enabled"),
		"createdAt", target.Get("createdAt"),
		"updatedAt", target.Get("updatedAt"),
		"tokenUpdatedAt", target.Get("tokenUpdatedAt"),
		"provisioned", provisioned,
	)
	if lastRun := target.Get("lastRun"); truthy(lastRun) {
		result.Set("lastRun", lastRun)
	}
	return result, nil
}

// tenantText is a tenant ID as a string for the authorization callback ("" for anything else).
func tenantText(value any) string {
	text, _ := value.(string)
	return text
}

func (p *Provisioner) authorized(ctx context.Context, credential core.CredentialInput, action string, tenantID, targetID any) (string, error) {
	if err := p.config.Authorize(ctx, credential, action, core.ResourceRef{TenantID: tenantText(tenantID), Type: "scim", ID: "outbound/" + jsString(targetID)}); err != nil {
		return "", err
	}
	// Configuring, syncing and previewing a target send (or show) every member in scope: name, email, mapped
	// attributes and groups. That is reading the directory, so it needs that permission too, not only the target's.
	if action != "iam:scim:targets:read" && action != "iam:scim:targets:delete" {
		if err := p.config.Authorize(ctx, credential, "iam:identities:read", core.ResourceRef{TenantID: tenantText(tenantID), Type: "iam", ID: tenantText(tenantID)}); err != nil {
			return "", err
		}
	}
	return p.config.Authenticate(ctx, credential)
}

func (p *Provisioner) owned(ctx context.Context, store core.IamStore, tenantID, targetID any) (*core.Object, error) {
	var target *core.Object
	if id, ok := targetID.(string); ok && id != "" {
		var err error
		if target, err = store.Get(ctx, "provisioningTargets", id); err != nil {
			return nil, err
		}
	}
	if target == nil || !strictEqual(target.Get("tenantId"), tenantID) {
		return nil, core.NewIamError("NOT_FOUND", "Provisioning target not found.", 404)
	}
	return target, nil
}

func (p *Provisioner) audit(ctx context.Context, tx core.IamStore, tenantID any, actorID, action string, resourceID any) error {
	event := core.NewObject(
		"id", randomUUID(),
		"tenantId", tenantID,
		"actorId", actorID,
		"action", action,
		"resourceId", resourceID,
		"timestamp", p.now(),
		"outcome", "allow",
	)
	// Through the host when it fans events out to webhooks and subscribers; Subscribe ignores these itself.
	if p.config.RecordAudit != nil {
		return p.config.RecordAudit(ctx, tx, event)
	}
	_, err := core.AppendAuditEvent(ctx, tx, event)
	return err
}

// callResult is a downstream answer: its status and parsed JSON (core.Undefined when empty or not JSON).
type callResult struct {
	status int
	json   any
}

// call is one downstream SCIM call with the target's bearer token.
func (p *Provisioner) call(ctx context.Context, target *core.Object, method, path string, body any) (callResult, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	unreachable := &DownstreamError{Message: "The SCIM service is unreachable."}
	token, err := p.open(jsString(target.Get("sealedToken")))
	if err != nil {
		return callResult{}, unreachable
	}
	var payload io.Reader
	if truthy(body) {
		payload = bytes.NewReader(stringify(body))
	}
	request, err := http.NewRequestWithContext(ctx, method, jsString(target.Get("baseUrl"))+path, payload)
	if err != nil {
		return callResult{}, unreachable
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/scim+json")
	if truthy(body) {
		request.Header.Set("Content-Type", "application/scim+json")
	}
	response, err := p.fetch(request)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return callResult{}, &DownstreamError{Message: "The SCIM service did not answer in time."}
		}
		return callResult{}, unreachable
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return callResult{}, &DownstreamError{Message: "The SCIM response is too large or was cut off."}
	}
	text := strings.TrimPrefix(decodeUTF8(data), string(rune(0xFEFF)))
	if utf16Len(text) > 1_000_000 {
		return callResult{}, &DownstreamError{Message: "The SCIM response is too large."}
	}
	var parsed any = core.Undefined
	if text != "" {
		if value, err := core.ParseJSONString(text); err == nil {
			parsed = value
		}
	}
	return callResult{status: response.StatusCode, json: parsed}, nil
}

func failure(result callResult, what string) error {
	detail := ""
	if text, ok := member(result.json, "detail").(string); ok {
		detail = ": " + sliceUTF16(text, 0, 200)
	}
	return &DownstreamError{Message: what + " failed with HTTP " + core.NumberString(float64(result.status)) + detail, Status: result.status}
}

// inheritedMembers are the members a plain object inherits whose names are valid attribute-mapping sources, as
// String() renders them.
var inheritedMembers = map[string]string{
	"constructor":          objectConstructorSource,
	"toString":             "function toString() { [native code] }",
	"valueOf":              "function valueOf() { [native code] }",
	"hasOwnProperty":       "function hasOwnProperty() { [native code] }",
	"isPrototypeOf":        "function isPrototypeOf() { [native code] }",
	"propertyIsEnumerable": "function propertyIsEnumerable() { [native code] }",
	"toLocaleString":       "function toLocaleString() { [native code] }",
}

// attributeText is `identity.attributes?.[source]` rendered with String(), ok false when it is nullish.
func attributeText(attributes any, source string) (string, bool) {
	record, isObject := attributes.(*core.Object)
	if !isObject || record == nil {
		if text, isText := attributes.(string); isText && source == "length" {
			return core.NumberString(float64(utf16Len(text))), true
		}
		return "", false
	}
	if value, own := record.Lookup(source); own {
		if nullish(value) {
			return "", false
		}
		return jsString(value), true
	}
	if inherited, ok := inheritedMembers[source]; ok {
		return inherited, true
	}
	return "", false
}

// user is the SCIM representation of an in-scope member.
func (p *Provisioner) user(target, identity *core.Object) *core.Object {
	enterprise := core.NewObject()
	var title *string
	if mapping, ok := target.Get("attributeMapping").(*core.Object); ok && mapping != nil {
		for _, attribute := range mapping.Keys() {
			value, present := attributeText(identity.Get("attributes"), jsString(mapping.Get(attribute)))
			if !present {
				continue
			}
			if attribute == "title" {
				text := value
				title = &text
			} else {
				enterprise.Set(attribute, value)
			}
		}
	}
	schemas := []any{UserSchema}
	if enterprise.Len() > 0 {
		schemas = append(schemas, EnterpriseSchema)
	}
	email := identity.Get("email")
	result := core.NewObject()
	result.SetRaw("schemas", schemas)
	result.SetRaw("externalId", identity.Get("id"))
	result.SetRaw("userName", email)
	result.SetRaw("displayName", identity.Get("name"))
	result.SetRaw("name", core.NewObject().SetRaw("formatted", identity.Get("name")))
	result.SetRaw("emails", []any{core.NewObject().SetRaw("value", email).SetRaw("type", "work").SetRaw("primary", true)})
	if title != nil {
		result.SetRaw("title", *title)
	}
	result.SetRaw("active", true)
	if enterprise.Len() > 0 {
		result.SetRaw(EnterpriseSchema, enterprise)
	}
	return result
}

// lookup answers the single downstream resource matching one of the filters, if any ("" for none).
func (p *Provisioner) lookup(ctx context.Context, target *core.Object, resource string, filters []string) (string, error) {
	lower := strings.ToLower(resource)
	for _, filter := range filters {
		found, err := p.call(ctx, target, "GET", "/"+resource+"?filter="+formEncode(filter)+"&count=2", nil)
		if err != nil {
			return "", err
		}
		if found.status != 200 {
			return "", failure(found, "Looking up "+lower)
		}
		resources, _ := member(found.json, "Resources").([]any)
		if len(resources) > 1 {
			return "", &DownstreamError{Message: "Several downstream " + lower + " match."}
		}
		if len(resources) == 1 {
			if id, ok := member(resources[0], "id").(string); ok {
				return id, nil
			}
		}
	}
	return "", nil
}

// quoted is a filter value (RFC 7644 compValue, a JSON string): escaped, never stripped, so it matches only itself.
func quoted(value any) string { return core.MustStringify(value) }

// adopt answers an existing downstream user for the same person, so a first sync adopts instead of duplicating: the
// one this target created for them (`externalId`), or, only when their address is verified, the account whose
// `userName` is that address. Someone who merely typed another person's address never takes over their downstream
// account, and an account another person's link already holds is never adopted twice.
func (p *Provisioner) adopt(ctx context.Context, target, identity *core.Object) (string, error) {
	filters := []string{"externalId eq " + quoted(identity.Get("id"))}
	if identity.Get("emailVerified") == true && truthy(identity.Get("email")) {
		filters = append(filters, "userName eq "+quoted(identity.Get("email")))
	}
	remoteID, err := p.lookup(ctx, target, "Users", filters)
	if err != nil || remoteID == "" {
		return "", err
	}
	holders, err := p.config.Store.Find(ctx, "provisioningLinks", core.NewObject("targetId", target.Get("id"), "remoteId", remoteID), nil)
	if err != nil {
		return "", err
	}
	for _, link := range holders {
		if link.Get("identityId") != identity.Get("id") {
			return "", &DownstreamError{Message: "The matching downstream account is linked to someone else."}
		}
	}
	return remoteID, nil
}

// liveMembership: temporary and access-package memberships stop counting at `expiresAt`, before the purge worker
// removes them.
func (p *Provisioner) liveMembership(membership *core.Object) bool {
	expiresAt, isNumber := membership.Get("expiresAt").(float64)
	return !isNumber || expiresAt > p.now()
}

// provisioningRun is a ProvisioningRun under construction.
type provisioningRun struct {
	startedAt, finishedAt                                   float64
	created, updated, deactivated, deleted, unchanged, fail int
	groupsCreated, groupsUpdated, groupsDeleted             int
	groupsUnchanged                                         int
	errors                                                  []any
}

func (r *provisioningRun) value() *core.Object {
	return core.NewObject(
		"startedAt", r.startedAt,
		"finishedAt", r.finishedAt,
		"created", r.created,
		"updated", r.updated,
		"deactivated", r.deactivated,
		"deleted", r.deleted,
		"unchanged", r.unchanged,
		"failed", r.fail,
		"groups", core.NewObject("created", r.groupsCreated, "updated", r.groupsUpdated, "deleted", r.groupsDeleted, "unchanged", r.groupsUnchanged),
		"errors", append([]any{}, r.errors...),
	)
}

// failureEntry is an error entry: `{ [subject]: id, status?, message }`.
func failureEntry(subject, id string, err error, fallback string) *core.Object {
	entry := core.NewObject(subject, id)
	var downstream *DownstreamError
	if errors.As(err, &downstream) {
		if downstream.Status != 0 {
			entry.Set("status", downstream.Status)
		}
		entry.Set("message", downstream.Message)
	} else {
		entry.Set("message", fallback)
	}
	return entry
}

// saveLink writes a link record, inserting it when it is new.
func saveLink(ctx context.Context, store core.IamStore, collection string, record *core.Object) error {
	return store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		existing, err := tx.Get(ctx, collection, jsString(record.Get("id")))
		if err != nil {
			return err
		}
		if existing != nil {
			_, err = tx.Put(ctx, collection, record)
		} else {
			_, err = tx.Insert(ctx, collection, record)
		}
		return err
	})
}

func deleteRecord(ctx context.Context, store core.IamStore, collection string, id any) error {
	return store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		return tx.Delete(ctx, collection, jsString(id))
	})
}

// sha is the lowercase hex SHA-256 of the UTF-8 text.
func sha(text string) string { return hash(text) }

// pushGroups: with `pushGroups`, each scoped group exists downstream (adopted by `externalId` or `displayName`) with
// the provisioned users as members; groups that leave scope or disappear are deleted downstream.
func (p *Provisioner) pushGroups(ctx context.Context, target *core.Object, live bool, run *provisioningRun, fail func(id string, err error, subject string)) error {
	store := p.config.Store
	rows, err := store.Find(ctx, "provisioningGroupLinks", core.NewObject("targetId", target.Get("id")), nil)
	if err != nil {
		return err
	}
	var order []string
	links := map[string]*core.Object{}
	for _, link := range rows {
		groupID := jsString(link.Get("groupId"))
		if _, seen := links[groupID]; !seen {
			order = append(order, groupID)
		}
		links[groupID] = link
	}
	pushing := target.Get("pushGroups") == true
	if !pushing && len(links) == 0 {
		return nil
	}
	userLinks, err := store.Find(ctx, "provisioningLinks", core.NewObject("targetId", target.Get("id")), nil)
	if err != nil {
		return err
	}
	remoteUsers := map[string]any{}
	for _, link := range userLinks {
		if truthy(link.Get("active")) {
			remoteUsers[jsString(link.Get("identityId"))] = link.Get("remoteId")
		}
	}
	wanted := map[string]bool{}
	var scoped []any
	if live && pushing {
		scoped, _ = target.Get("groupIds").([]any)
	}
	for _, item := range scoped {
		groupID := jsString(item)
		group, err := store.Get(ctx, "groups", groupID)
		if err != nil {
			return err
		}
		groupName, hasName := member(group, "name").(string)
		if group == nil || group.Get("tenantId") != target.Get("tenantId") || !hasName {
			continue
		}
		wanted[groupID] = true
		memberships, err := store.Find(ctx, "groupMembers", core.NewObject("tenantId", target.Get("tenantId"), "groupId", groupID), nil)
		if err != nil {
			return err
		}
		var remoteIDs []any
		for _, membership := range memberships {
			if !p.liveMembership(membership) {
				continue
			}
			if remoteID := remoteUsers[jsString(membership.Get("identityId"))]; truthy(remoteID) {
				remoteIDs = append(remoteIDs, remoteID)
			}
		}
		sort.SliceStable(remoteIDs, func(i, j int) bool { return compareUTF16(jsString(remoteIDs[i]), jsString(remoteIDs[j])) < 0 })
		members := make([]any, len(remoteIDs))
		for index, remoteID := range remoteIDs {
			members[index] = core.NewObject().SetRaw("value", remoteID)
		}
		payload := core.NewObject("schemas", []any{GroupSchema}, "externalId", groupID, "displayName", groupName, "members", members)
		fingerprint := sha(core.MustStringify(payload))
		link := links[groupID]
		err = func() error {
			if link != nil && link.Get("fingerprint") == fingerprint {
				run.groupsUnchanged++
				return nil
			}
			var remoteID any
			if link != nil {
				remoteID = link.Get("remoteId")
			}
			if nullish(remoteID) {
				found, err := p.lookup(ctx, target, "Groups", []string{"externalId eq " + quoted(groupID), "displayName eq " + quoted(groupName)})
				if err != nil {
					return err
				}
				remoteID = core.Undefined
				if found != "" {
					remoteID = found
				}
			}
			created := false
			if truthy(remoteID) {
				encoded, err := encodeURIComponent(jsString(remoteID))
				if err != nil {
					return err
				}
				replaced, err := p.call(ctx, target, "PUT", "/Groups/"+encoded, payload.Spread(core.NewObject().SetRaw("id", remoteID)))
				if err != nil {
					return err
				}
				if replaced.status == 404 {
					remoteID = core.Undefined
				} else if replaced.status < 200 || replaced.status >= 300 {
					return failure(replaced, "Updating the group")
				}
			}
			if !truthy(remoteID) {
				posted, err := p.call(ctx, target, "POST", "/Groups", payload)
				if err != nil {
					return err
				}
				if posted.status != 201 && posted.status != 200 {
					return failure(posted, "Creating the group")
				}
				id, ok := member(posted.json, "id").(string)
				if !ok {
					return &DownstreamError{Message: "The SCIM service returned no group ID."}
				}
				remoteID = id
				created = true
			}
			record := core.NewObject()
			record.SetRaw("id", sha(jsString(target.Get("id"))+":group:"+groupID))
			record.SetRaw("tenantId", target.Get("tenantId"))
			record.SetRaw("targetId", target.Get("id"))
			record.SetRaw("groupId", groupID)
			record.SetRaw("remoteId", remoteID)
			record.SetRaw("fingerprint", fingerprint)
			record.SetRaw("syncedAt", p.now())
			if err := saveLink(ctx, store, "provisioningGroupLinks", record); err != nil {
				return err
			}
			if created {
				run.groupsCreated++
			} else {
				run.groupsUpdated++
			}
			return nil
		}()
		if err != nil {
			fail(groupID, err, "groupId")
		}
	}
	for _, groupID := range order {
		if wanted[groupID] {
			continue
		}
		link := links[groupID]
		err := func() error {
			encoded, err := encodeURIComponent(jsString(link.Get("remoteId")))
			if err != nil {
				return err
			}
			removed, err := p.call(ctx, target, "DELETE", "/Groups/"+encoded, nil)
			if err != nil {
				return err
			}
			if removed.status != 204 && removed.status != 200 && removed.status != 404 {
				return failure(removed, "Deleting the group")
			}
			if err := deleteRecord(ctx, store, "provisioningGroupLinks", link.Get("id")); err != nil {
				return err
			}
			run.groupsDeleted++
			return nil
		}()
		if err != nil {
			fail(groupID, err, "groupId")
		}
	}
	return nil
}

// scope is who should exist downstream now, and what the target has provisioned so far.
type scope struct {
	active    bool
	inScope   []*core.Object
	scopeIDs  map[string]bool
	links     map[string]*core.Object
	linkOrder []string
}

func (p *Provisioner) scopeOf(ctx context.Context, target *core.Object) (*scope, error) {
	store := p.config.Store
	active, err := core.TenantTreeActive(ctx, store, jsString(target.Get("tenantId")))
	if err != nil {
		return nil, err
	}
	groupIDs, _ := target.Get("groupIds").([]any)
	members := map[string]bool{}
	for _, groupID := range groupIDs {
		memberships, err := store.Find(ctx, "groupMembers", core.NewObject("tenantId", target.Get("tenantId"), "groupId", groupID), nil)
		if err != nil {
			return nil, err
		}
		for _, membership := range memberships {
			if p.liveMembership(membership) {
				members[jsString(membership.Get("identityId"))] = true
			}
		}
	}
	result := &scope{active: active, scopeIDs: map[string]bool{}, links: map[string]*core.Object{}}
	if active && truthy(target.Get("enabled")) {
		identities, err := store.Find(ctx, "identities", core.NewObject("tenantId", target.Get("tenantId")), nil)
		if err != nil {
			return nil, err
		}
		for _, identity := range identities {
			expiresAt, expires := identity.Get("expiresAt").(float64)
			id := jsString(identity.Get("id"))
			if identity.Get("kind") == "user" && identity.Get("status") == "active" && truthy(identity.Get("email")) &&
				(!expires || expiresAt > p.now()) && (len(groupIDs) == 0 || members[id]) {
				if !result.scopeIDs[id] {
					result.inScope = append(result.inScope, identity)
				} else {
					for index, existing := range result.inScope {
						if jsString(existing.Get("id")) == id {
							result.inScope[index] = identity
						}
					}
				}
				result.scopeIDs[id] = true
			}
		}
	}
	links, err := store.Find(ctx, "provisioningLinks", core.NewObject("targetId", target.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	for _, link := range links {
		identityID := jsString(link.Get("identityId"))
		if _, seen := result.links[identityID]; !seen {
			result.linkOrder = append(result.linkOrder, identityID)
		}
		result.links[identityID] = link
	}
	return result, nil
}

// preview is the plan of the next sync: it never writes downstream or to the store.
func (p *Provisioner) preview(ctx context.Context, target *core.Object) (*core.Object, error) {
	current, err := p.scopeOf(ctx, target)
	if err != nil {
		return nil, err
	}
	counts := core.NewObject("create", 0, "adopt", 0, "update", 0, "reactivate", 0, "deactivate", 0, "delete", 0, "unchanged", 0)
	changes := []any{}
	lookupErrors := []any{}
	plan := func(identityID string, email any, action string) {
		counts.Set(action, counts.Get(action).(float64)+1)
		if len(changes) < 200 {
			change := core.NewObject("identityId", identityID)
			if email != nil {
				change.SetRaw("email", email)
			}
			change.Set("action", action)
			changes = append(changes, change)
		}
	}
	for _, identity := range current.inScope {
		identityID := jsString(identity.Get("id"))
		if link := current.links[identityID]; link != nil {
			switch {
			case !truthy(link.Get("active")):
				plan(identityID, identity.Get("email"), "reactivate")
			case link.Get("fingerprint") != sha(core.MustStringify(p.user(target, identity))):
				plan(identityID, identity.Get("email"), "update")
			default:
				counts.Set("unchanged", counts.Get("unchanged").(float64)+1)
			}
			continue
		}
		existing, err := p.adopt(ctx, target, identity)
		if err != nil {
			if len(lookupErrors) < 20 {
				lookupErrors = append(lookupErrors, failureEntry("identityId", identityID, err, "Lookup failed."))
			}
			continue
		}
		if existing != "" {
			plan(identityID, identity.Get("email"), "adopt")
		} else {
			plan(identityID, identity.Get("email"), "create")
		}
	}
	for _, identityID := range current.linkOrder {
		if current.scopeIDs[identityID] {
			continue
		}
		if target.Get("deprovision") == "delete" {
			plan(identityID, nil, "delete")
		} else if truthy(current.links[identityID].Get("active")) {
			plan(identityID, nil, "deactivate")
		}
	}
	return core.NewObject("counts", counts, "changes", changes, "errors", lookupErrors), nil
}

func (p *Provisioner) reconcile(ctx context.Context, target *core.Object) (*core.Object, error) {
	run := &provisioningRun{startedAt: p.now()}
	fail := func(id string, err error, subject string) {
		run.fail++
		if len(run.errors) < 20 {
			run.errors = append(run.errors, failureEntry(subject, id, err, "Provisioning failed unexpectedly."))
		}
	}
	store := p.config.Store
	current, err := p.scopeOf(ctx, target)
	if err != nil {
		return nil, err
	}
	for _, identity := range current.inScope {
		identityID := jsString(identity.Get("id"))
		payload := p.user(target, identity)
		fingerprint := sha(core.MustStringify(payload))
		link := current.links[identityID]
		err := func() error {
			if link != nil && truthy(link.Get("active")) && link.Get("fingerprint") == fingerprint {
				run.unchanged++
				return nil
			}
			var remoteID any = core.Undefined
			if link != nil {
				remoteID = link.Get("remoteId")
			}
			if nullish(remoteID) {
				adopted, err := p.adopt(ctx, target, identity)
				if err != nil {
					return err
				}
				remoteID = core.Undefined
				if adopted != "" {
					remoteID = adopted
				}
			}
			created := false
			if truthy(remoteID) {
				encoded, err := encodeURIComponent(jsString(remoteID))
				if err != nil {
					return err
				}
				replaced, err := p.call(ctx, target, "PUT", "/Users/"+encoded, payload.Spread(core.NewObject().SetRaw("id", remoteID)))
				if err != nil {
					return err
				}
				if replaced.status == 404 {
					remoteID = core.Undefined
				} else if replaced.status < 200 || replaced.status >= 300 {
					return failure(replaced, "Updating the user")
				}
			}
			if !truthy(remoteID) {
				posted, err := p.call(ctx, target, "POST", "/Users", payload)
				if err != nil {
					return err
				}
				if posted.status != 201 && posted.status != 200 {
					return failure(posted, "Creating the user")
				}
				id, ok := member(posted.json, "id").(string)
				if !ok {
					return &DownstreamError{Message: "The SCIM service returned no user ID."}
				}
				remoteID = id
				created = true
			}
			record := core.NewObject()
			record.SetRaw("id", sha(jsString(target.Get("id"))+":"+identityID))
			record.SetRaw("tenantId", target.Get("tenantId"))
			record.SetRaw("targetId", target.Get("id"))
			record.SetRaw("identityId", identityID)
			record.SetRaw("remoteId", remoteID)
			record.SetRaw("fingerprint", fingerprint)
			record.SetRaw("active", true)
			record.SetRaw("syncedAt", p.now())
			if err := saveLink(ctx, store, "provisioningLinks", record); err != nil {
				return err
			}
			if created {
				run.created++
			} else {
				run.updated++
			}
			return nil
		}()
		if err != nil {
			fail(identityID, err, "identityId")
		}
	}
	for _, identityID := range current.linkOrder {
		if current.scopeIDs[identityID] {
			continue
		}
		link := current.links[identityID]
		err := func() error {
			encoded, err := encodeURIComponent(jsString(link.Get("remoteId")))
			if target.Get("deprovision") == "delete" {
				if err != nil {
					return err
				}
				removed, err := p.call(ctx, target, "DELETE", "/Users/"+encoded, nil)
				if err != nil {
					return err
				}
				if removed.status != 204 && removed.status != 200 && removed.status != 404 {
					return failure(removed, "Deleting the user")
				}
				if err := deleteRecord(ctx, store, "provisioningLinks", link.Get("id")); err != nil {
					return err
				}
				run.deleted++
				return nil
			}
			if !truthy(link.Get("active")) {
				return nil
			}
			if err != nil {
				return err
			}
			patched, err := p.call(ctx, target, "PATCH", "/Users/"+encoded, core.NewObject(
				"schemas", []any{PatchSchema},
				"Operations", []any{core.NewObject("op", "replace", "value", core.NewObject("active", false))},
			))
			if err != nil {
				return err
			}
			if patched.status == 404 {
				return deleteRecord(ctx, store, "provisioningLinks", link.Get("id"))
			}
			if patched.status < 200 || patched.status >= 300 {
				return failure(patched, "Deactivating the user")
			}
			if err := saveLink(ctx, store, "provisioningLinks", link.Spread(core.NewObject("active", false, "fingerprint", "", "syncedAt", p.now()))); err != nil {
				return err
			}
			run.deactivated++
			return nil
		}()
		if err != nil {
			fail(identityID, err, "identityId")
		}
	}
	if err := p.pushGroups(ctx, target, current.active && truthy(target.Get("enabled")), run, fail); err != nil {
		return nil, err
	}
	run.finishedAt = p.now()
	result := run.value()
	if err := store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		stored, err := tx.Get(ctx, "provisioningTargets", jsString(target.Get("id")))
		if err != nil || stored == nil {
			return err
		}
		_, err = tx.Put(ctx, "provisioningTargets", stored.Spread(core.NewObject("lastRun", result)))
		return err
	}); err != nil {
		return nil, err
	}
	return result, nil
}

// runOnce runs one reconciliation per target at a time; concurrent requests share the running one.
func (p *Provisioner) runOnce(ctx context.Context, target *core.Object) (*core.Object, error) {
	id := jsString(target.Get("id"))
	p.mu.Lock()
	if pending, ok := p.running[id]; ok {
		p.mu.Unlock()
		<-pending.done
		return pending.run, pending.err
	}
	call := &runCall{done: make(chan struct{})}
	p.running[id] = call
	p.mu.Unlock()
	call.run, call.err = p.reconcile(ctx, target)
	p.mu.Lock()
	delete(p.running, id)
	p.mu.Unlock()
	close(call.done)
	return call.run, call.err
}

// SyncAll is the deployment operation for schedulers and event hooks: it reconciles every target (tenantID "": all
// tenants') and answers the runs by target ID. It runs with no credential; do not expose it over HTTP.
func (p *Provisioner) SyncAll(ctx context.Context, tenantID string) (*core.Object, error) {
	var filter *core.Object
	if tenantID != "" {
		filter = core.NewObject("tenantId", tenantID)
	}
	targets, err := p.config.Store.Find(ctx, "provisioningTargets", filter, nil)
	if err != nil {
		return nil, err
	}
	runs := core.NewObject()
	for _, target := range targets {
		run, err := p.runOnce(ctx, target)
		if err != nil {
			return nil, err
		}
		runs.Set(jsString(target.Get("id")), run)
	}
	return runs, nil
}

// TargetInput is the input of the target operations. Absent members are nil.
type TargetInput struct {
	TenantID string
	// TargetID names the target (every operation but CreateTarget).
	TargetID string
	Name     *string
	// BaseURL is the downstream SCIM 2.0 base URL (the one ending before `/Users`).
	BaseURL *string
	// Token is the bearer token the downstream service issued for provisioning. Write-only.
	Token *string
	// GroupIDs limits provisioning to members of these groups; empty means every active member of the tenant.
	GroupIDs []string
	// Deprovision is "deactivate" (default) or "delete".
	Deprovision *string
	// AttributeMapping maps SCIM attributes (title, department, division, employeeNumber) to identity attributes.
	AttributeMapping *core.Object
	// PushGroups also maintains the scoped GroupIDs downstream as SCIM groups.
	PushGroups *bool
	Enabled    *bool
}

func (input TargetInput) value(withTarget bool) *core.Object {
	out := core.NewObject("tenantId", input.TenantID)
	if withTarget {
		out.Set("targetId", input.TargetID)
	}
	if input.Name != nil {
		out.Set("name", *input.Name)
	}
	if input.BaseURL != nil {
		out.Set("baseUrl", *input.BaseURL)
	}
	if input.Token != nil {
		out.Set("token", *input.Token)
	}
	if input.GroupIDs != nil {
		out.Set("groupIds", stringList(input.GroupIDs))
	}
	if input.Deprovision != nil {
		out.Set("deprovision", *input.Deprovision)
	}
	if input.AttributeMapping != nil {
		out.Set("attributeMapping", input.AttributeMapping)
	}
	if input.PushGroups != nil {
		out.Set("pushGroups", *input.PushGroups)
	}
	if input.Enabled != nil {
		out.Set("enabled", *input.Enabled)
	}
	return out
}

// CreateTarget adds a downstream application (`iam:scim:targets:create`). The token is encrypted and never returned.
func (p *Provisioner) CreateTarget(ctx context.Context, credential core.CredentialInput, input TargetInput) (*core.Object, error) {
	return p.createTarget(ctx, credential, input.value(false))
}

func (p *Provisioner) createTarget(ctx context.Context, credential core.CredentialInput, input *core.Object) (*core.Object, error) {
	id := "scim-target-" + hex.EncodeToString(randomBytes(8))
	tenantID := input.Get("tenantId")
	actorID, err := p.authorized(ctx, credential, "iam:scim:targets:create", tenantID, id)
	if err != nil {
		return nil, err
	}
	values, err := p.settings(input, nil)
	if err != nil {
		return nil, err
	}
	token, err := downstreamToken(input.Get("token"))
	if err != nil {
		return nil, err
	}
	sealedToken := p.seal(token)
	return core.Transact(ctx, p.config.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		active, err := core.TenantTreeActive(ctx, tx, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		if !active {
			return nil, core.NewIamError("TENANT_INACTIVE", "Tenant unavailable.", 403)
		}
		now := p.now()
		record := core.NewObject()
		record.SetRaw("id", id)
		record.SetRaw("tenantId", tenantID)
		record.Assign(values)
		record.SetRaw("sealedToken", sealedToken)
		record.SetRaw("createdAt", now)
		record.SetRaw("updatedAt", now)
		record.SetRaw("tokenUpdatedAt", now)
		if _, err := tx.Insert(ctx, "provisioningTargets", record); err != nil {
			return nil, err
		}
		if err := p.audit(ctx, tx, tenantID, actorID, "iam:scim:CreateTarget", id); err != nil {
			return nil, err
		}
		return p.summary(ctx, record, tx)
	})
}

// ListTargets answers a tenant's targets (`iam:scim:targets:read`).
func (p *Provisioner) ListTargets(ctx context.Context, credential core.CredentialInput, tenantID string) ([]*core.Object, error) {
	return p.listTargets(ctx, credential, core.NewObject("tenantId", tenantID))
}

func (p *Provisioner) listTargets(ctx context.Context, credential core.CredentialInput, input *core.Object) ([]*core.Object, error) {
	if _, err := p.authorized(ctx, credential, "iam:scim:targets:read", input.Get("tenantId"), "*"); err != nil {
		return nil, err
	}
	targets, err := p.config.Store.Find(ctx, "provisioningTargets", core.NewObject("tenantId", input.Get("tenantId")), nil)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(targets, func(i, j int) bool {
		difference := jsNumber(targets[i].Get("createdAt")) - jsNumber(targets[j].Get("createdAt"))
		if difference != 0 && !math.IsNaN(difference) {
			return difference < 0
		}
		return compareUTF16(jsString(targets[i].Get("id")), jsString(targets[j].Get("id"))) < 0
	})
	result := make([]*core.Object, len(targets))
	for index, target := range targets {
		if result[index], err = p.summary(ctx, target, nil); err != nil {
			return nil, err
		}
	}
	return result, nil
}

// GetTarget answers one target (`iam:scim:targets:read`).
func (p *Provisioner) GetTarget(ctx context.Context, credential core.CredentialInput, tenantID, targetID string) (*core.Object, error) {
	return p.getTarget(ctx, credential, core.NewObject("tenantId", tenantID, "targetId", targetID))
}

func (p *Provisioner) getTarget(ctx context.Context, credential core.CredentialInput, input *core.Object) (*core.Object, error) {
	if _, err := p.authorized(ctx, credential, "iam:scim:targets:read", input.Get("tenantId"), input.Get("targetId")); err != nil {
		return nil, err
	}
	target, err := p.owned(ctx, p.config.Store, input.Get("tenantId"), input.Get("targetId"))
	if err != nil {
		return nil, err
	}
	return p.summary(ctx, target, nil)
}

// UpdateTarget changes a target; a new Token replaces the stored one. Scope changes apply at the next sync.
func (p *Provisioner) UpdateTarget(ctx context.Context, credential core.CredentialInput, input TargetInput) (*core.Object, error) {
	return p.updateTarget(ctx, credential, input.value(true))
}

func (p *Provisioner) updateTarget(ctx context.Context, credential core.CredentialInput, input *core.Object) (*core.Object, error) {
	tenantID := input.Get("tenantId")
	actorID, err := p.authorized(ctx, credential, "iam:scim:targets:update", tenantID, input.Get("targetId"))
	if err != nil {
		return nil, err
	}
	return core.Transact(ctx, p.config.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		current, err := p.owned(ctx, tx, tenantID, input.Get("targetId"))
		if err != nil {
			return nil, err
		}
		now := p.now()
		values, err := p.settings(input, current)
		if err != nil {
			return nil, err
		}
		// The stored token is write-only: pointing the target somewhere else must not send it along, so a new base
		// URL needs the token again (whoever sets it proves they hold a credential for the new service).
		if values.Get("baseUrl") != current.Get("baseUrl") && core.IsUndefined(input.Get("token")) {
			return nil, invalidTargetInput("Changing the SCIM base URL needs the downstream token again.")
		}
		record := current.Spread(values)
		if !core.IsUndefined(input.Get("token")) {
			token, err := downstreamToken(input.Get("token"))
			if err != nil {
				return nil, err
			}
			record.Set("sealedToken", p.seal(token))
			record.Set("tokenUpdatedAt", now)
		}
		record.Set("updatedAt", now)
		if _, err := tx.Put(ctx, "provisioningTargets", record); err != nil {
			return nil, err
		}
		if err := p.audit(ctx, tx, tenantID, actorID, "iam:scim:UpdateTarget", current.Get("id")); err != nil {
			return nil, err
		}
		return p.summary(ctx, record, tx)
	})
}

// DeleteTarget removes a target and its links. Downstream accounts are left as they are.
func (p *Provisioner) DeleteTarget(ctx context.Context, credential core.CredentialInput, tenantID, targetID string) error {
	_, err := p.deleteTarget(ctx, credential, core.NewObject("tenantId", tenantID, "targetId", targetID))
	return err
}

func (p *Provisioner) deleteTarget(ctx context.Context, credential core.CredentialInput, input *core.Object) (any, error) {
	tenantID := input.Get("tenantId")
	actorID, err := p.authorized(ctx, credential, "iam:scim:targets:delete", tenantID, input.Get("targetId"))
	if err != nil {
		return nil, err
	}
	return nil, p.config.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		current, err := p.owned(ctx, tx, tenantID, input.Get("targetId"))
		if err != nil {
			return err
		}
		byTarget := core.NewObject("targetId", current.Get("id"))
		if err := deleteAll(ctx, tx, "provisioningLinks", byTarget); err != nil {
			return err
		}
		if err := deleteAll(ctx, tx, "provisioningGroupLinks", byTarget); err != nil {
			return err
		}
		if err := tx.Delete(ctx, "provisioningTargets", jsString(current.Get("id"))); err != nil {
			return err
		}
		return p.audit(ctx, tx, tenantID, actorID, "iam:scim:DeleteTarget", current.Get("id"))
	})
}

// PreviewTarget answers what a sync would change right now (`iam:scim:targets:read`); only read-only lookups reach
// the application. The result is `{ counts, changes, errors }`.
func (p *Provisioner) PreviewTarget(ctx context.Context, credential core.CredentialInput, tenantID, targetID string) (*core.Object, error) {
	return p.previewTarget(ctx, credential, core.NewObject("tenantId", tenantID, "targetId", targetID))
}

func (p *Provisioner) previewTarget(ctx context.Context, credential core.CredentialInput, input *core.Object) (*core.Object, error) {
	tenantID := input.Get("tenantId")
	if _, err := p.authorized(ctx, credential, "iam:scim:targets:read", tenantID, input.Get("targetId")); err != nil {
		return nil, err
	}
	// The preview lists members' addresses and looks them up downstream: reading the directory.
	if err := p.config.Authorize(ctx, credential, "iam:identities:read", core.ResourceRef{TenantID: tenantText(tenantID), Type: "iam", ID: tenantText(tenantID)}); err != nil {
		return nil, err
	}
	target, err := p.owned(ctx, p.config.Store, tenantID, input.Get("targetId"))
	if err != nil {
		return nil, err
	}
	return p.preview(ctx, target)
}

// SyncTarget reconciles one target now (`iam:scim:targets:sync`) and answers the run.
func (p *Provisioner) SyncTarget(ctx context.Context, credential core.CredentialInput, tenantID, targetID string) (*core.Object, error) {
	return p.syncTarget(ctx, credential, core.NewObject("tenantId", tenantID, "targetId", targetID))
}

func (p *Provisioner) syncTarget(ctx context.Context, credential core.CredentialInput, input *core.Object) (*core.Object, error) {
	tenantID := input.Get("tenantId")
	actorID, err := p.authorized(ctx, credential, "iam:scim:targets:sync", tenantID, input.Get("targetId"))
	if err != nil {
		return nil, err
	}
	target, err := p.owned(ctx, p.config.Store, tenantID, input.Get("targetId"))
	if err != nil {
		return nil, err
	}
	run, err := p.runOnce(ctx, target)
	if err != nil {
		return nil, err
	}
	if err := p.config.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		return p.audit(ctx, tx, tenantID, actorID, "iam:scim:SyncTarget", target.Get("id"))
	}); err != nil {
		return nil, err
	}
	return run, nil
}

// EventSource is the in-process event surface the provisioner subscribes to (*server.EventsRuntime, iam.events).
type EventSource interface {
	Subscribe(pattern any, handler func(ctx context.Context, event *core.Object) error) (func(), error)
}

// SubscribeOptions configure Subscribe.
type SubscribeOptions struct {
	// DebounceMs is how long after the last event a tenant's targets sync (nil: 2 seconds).
	DebounceMs *float64
	// OnError receives the errors of scheduled syncs.
	OnError func(err error)
}

var subscriptionPatterns = []string{
	"iam:identities:*", "iam:groups:*", "iam:packages:*", "package:*", "group:*", "iam:tenants:*", "iam:scim:*",
	"identity:*", "tenant:*", "invitation:*",
}

var ownTargetEvent = regexp.MustCompile(`^iam:scim:[A-Za-z0-9_]+Target$`)

// Subscribe keeps targets current from IAM events: membership, identity, and tenant changes schedule a sync of the
// tenant's targets after DebounceMs (default 2 seconds). It answers the unsubscribe function.
func (p *Provisioner) Subscribe(events EventSource, options SubscribeOptions) (func(), error) {
	var mu sync.Mutex
	timers := map[string]*time.Timer{}
	debounce := 2000.0
	if options.DebounceMs != nil {
		debounce = *options.DebounceMs
	}
	unsubscribe, err := events.Subscribe(subscriptionPatterns, func(_ context.Context, event *core.Object) error {
		// The provisioner's own management and sync events never schedule another run.
		if ownTargetEvent.MatchString(jsString(event.Get("action"))) {
			return nil
		}
		tenant := event.Get("tenantId")
		tenantID, _ := tenant.(string)
		key := "v:" + jsString(tenant)
		if _, isText := tenant.(string); isText {
			key = "s:" + tenantID
		}
		mu.Lock()
		defer mu.Unlock()
		if timer := timers[key]; timer != nil {
			timer.Stop()
		}
		timers[key] = time.AfterFunc(time.Duration(debounce*float64(time.Millisecond)), func() {
			mu.Lock()
			delete(timers, key)
			mu.Unlock()
			if _, err := p.SyncAll(context.Background(), tenantID); err != nil && options.OnError != nil {
				options.OnError(err)
			}
		})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return func() {
		unsubscribe()
		mu.Lock()
		defer mu.Unlock()
		for key, timer := range timers {
			timer.Stop()
			delete(timers, key)
		}
	}, nil
}

// provisioningRoutes are the JSON management routes.
var provisioningRoutes = map[string]func(p *Provisioner, ctx context.Context, credential core.CredentialInput, body *core.Object) (any, error){
	"targets/list": func(p *Provisioner, ctx context.Context, credential core.CredentialInput, body *core.Object) (any, error) {
		targets, err := p.listTargets(ctx, credential, body)
		return objectList(targets), err
	},
	"targets/get": func(p *Provisioner, ctx context.Context, credential core.CredentialInput, body *core.Object) (any, error) {
		return p.getTarget(ctx, credential, body)
	},
	"targets/create": func(p *Provisioner, ctx context.Context, credential core.CredentialInput, body *core.Object) (any, error) {
		return p.createTarget(ctx, credential, body)
	},
	"targets/update": func(p *Provisioner, ctx context.Context, credential core.CredentialInput, body *core.Object) (any, error) {
		return p.updateTarget(ctx, credential, body)
	},
	"targets/delete": func(p *Provisioner, ctx context.Context, credential core.CredentialInput, body *core.Object) (any, error) {
		return p.deleteTarget(ctx, credential, body)
	},
	"targets/sync": func(p *Provisioner, ctx context.Context, credential core.CredentialInput, body *core.Object) (any, error) {
		return p.syncTarget(ctx, credential, body)
	},
	"targets/preview": func(p *Provisioner, ctx context.Context, credential core.CredentialInput, body *core.Object) (any, error) {
		return p.previewTarget(ctx, credential, body)
	},
}

// Handle is the JSON management API for browsers and scripts: `POST {basePath}/targets/…` with the caller's IAM
// cookie or bearer token. Like the IAM API it requires `X-Better-IAM: 1` and a JSON body, so cross-site forms cannot
// call it, and it answers `{ data }` or `{ error: { code, message } }`. It answers nil outside its base path.
func (p *Provisioner) Handle(r *http.Request) *Response {
	pathname := r.URL.EscapedPath()
	if !strings.HasPrefix(pathname, p.BasePath+"/") {
		return nil
	}
	reply := func(body any, status int) *Response {
		header := http.Header{}
		header.Set("Cache-Control", "no-store")
		return jsonReply(body, status, header)
	}
	route, ok := provisioningRoutes[pathname[len(p.BasePath)+1:]]
	if !ok {
		return reply(core.NewObject("error", core.NewObject("code", "NOT_FOUND", "message", "Unknown route.")), 404)
	}
	data, err := func() (any, error) {
		if r.Method != "POST" {
			return nil, core.NewIamError("METHOD_NOT_ALLOWED", "Use POST.", 405)
		}
		marker, _ := headerGet(r.Header, "x-better-iam")
		contentType, _ := headerGet(r.Header, "content-type")
		if marker != "1" || !strings.HasPrefix(contentType, "application/json") {
			return nil, core.NewIamError("CSRF_REJECTED", "JSON requests require X-Better-IAM: 1.", 403)
		}
		text, err := limitedText(r, 64*1024)
		if err != nil {
			var known *core.IamError
			if errors.As(err, &known) && known.Status == 413 {
				return nil, core.NewIamError("INVALID_INPUT", "Request too large.", 413)
			}
			return nil, err
		}
		var parsed any = core.NewObject()
		if text != "" {
			if parsed, err = core.ParseJSONString(text); err != nil {
				return nil, core.NewIamError("INVALID_INPUT", "The body must be JSON.", 400)
			}
		}
		body, ok := parsed.(*core.Object)
		if !ok || body == nil {
			return nil, core.NewIamError("INVALID_INPUT", "The body must be a JSON object.", 400)
		}
		result, err := route(p, r.Context(), core.CredentialInput{Headers: r.Header}, body)
		if err != nil {
			return nil, err
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
		return reply(core.NewObject("error", core.NewObject("code", "INTERNAL_ERROR", "message", "Provisioning request failed.")), 500)
	}
	return reply(core.NewObject("data", data), 200)
}

// Handler is Handle as a protocol mount (server.ProtocolService.Handler).
func (p *Provisioner) Handler(w http.ResponseWriter, r *http.Request) bool {
	answer := p.Handle(r)
	if answer == nil {
		return false
	}
	answer.Write(w)
	return true
}

// RotateKeys is the deployment operation (not served over HTTP) that re-seals every stored downstream token opened by
// a previous key with EncryptionKey, so the previous keys can be removed. Idempotent. The result is `{ resealed,
// current, unreadable }`.
func (p *Provisioner) RotateKeys(ctx context.Context) (*core.Object, error) {
	resealed, current, unreadable := 0, 0, 0
	var after *string
	limit := 200
	for {
		page, err := core.Transact(ctx, p.config.Store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
			targets, err := tx.Find(ctx, "provisioningTargets", core.NewObject(), &core.FindOptions{Limit: &limit, After: after})
			if err != nil {
				return nil, err
			}
			for _, target := range targets {
				opened, index, ok := p.openWith(jsString(target.Get("sealedToken")))
				switch {
				case !ok:
					unreadable++
				case index == 0:
					current++
				default:
					if _, err := tx.Put(ctx, "provisioningTargets", target.Spread(core.NewObject("sealedToken", p.seal(opened)))); err != nil {
						return nil, err
					}
					resealed++
				}
			}
			return targets, nil
		})
		if err != nil {
			return nil, err
		}
		if len(page) < 200 {
			return core.NewObject("resealed", resealed, "current", current, "unreadable", unreadable), nil
		}
		last := jsString(page[len(page)-1].Get("id"))
		after = &last
	}
}
