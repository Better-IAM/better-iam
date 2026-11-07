package server

// Port of packages/server/src/context.ts: the ServerContext every service module shares (configuration, storage,
// authentication, the catalog, the services attached by the composition root) and the record helpers.

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	_ "time/tzdata" // IANA time zones for access windows on every platform, as ICU has them built in

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// Principal is core's AuthenticatedPrincipal with the identity and session as stored records.
type Principal struct {
	Identity *core.Object
	Session  *core.Object
	// DeviceProof is the unverified device proof the request carried (x-better-iam-device), "" when none.
	DeviceProof string
	// proofBinding is the session the device proof is bound to when it is not this principal's own (devices.go
	// WithRequestDevice).
	proofBinding *ProofBinding
}

// PrincipalFromAuth wraps a principal the auth service verified.
func PrincipalFromAuth(principal *auth.Principal) *Principal {
	if principal == nil {
		return nil
	}
	return &Principal{Identity: principal.Identity, Session: principal.Session}
}

// Auth is the principal as the auth service's type.
func (p *Principal) Auth() *auth.Principal {
	return &auth.Principal{Identity: p.Identity, Session: p.Session}
}

// EventSubscriber is an in-process audit event subscriber.
type EventSubscriber struct {
	Patterns []string
	Handler  func(ctx context.Context, event *core.Object) error
}

// subscriberSet is a Set of subscribers (insertion order, identity membership).
type subscriberSet struct {
	mu    sync.Mutex
	items []*EventSubscriber
}

func (s *subscriberSet) add(subscriber *EventSubscriber) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, item := range s.items {
		if item == subscriber {
			return
		}
	}
	s.items = append(s.items, subscriber)
}

func (s *subscriberSet) remove(subscriber *EventSubscriber) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for index, item := range s.items {
		if item == subscriber {
			s.items = append(s.items[:index], s.items[index+1:]...)
			return
		}
	}
}

// Size is the number of subscribers.
func (s *subscriberSet) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// snapshot is `[...subscribers]`.
func (s *subscriberSet) snapshot() []*EventSubscriber {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*EventSubscriber(nil), s.items...)
}

// ServerContext is everything the service modules share. Service modules are attached after construction (by the
// composition root) and reached through this object at call time, which keeps the modules free of import cycles.
type ServerContext struct {
	Options          *BetterIamOptions
	Config           *ServerConfig
	Store            core.IamStore
	Auth             *auth.Service
	Plugins          []*core.IamPlugin
	Catalog          *Catalog
	Subscribers      *subscriberSet
	MountedProtocols []ProtocolMount
	Observe          *Observer
	// NowFunc is the injected clock (authentication.now, the auth service's clock); Now reads it.
	NowFunc func() int64
	// WallFunc is the wall clock (Date.now() in TypeScript); Wall reads it.
	WallFunc func() int64

	Events     *EventService
	Decisions  DecisionService
	Principals PrincipalService
	Operations OperationService
	Flows      *FlowService
	Usage      UsageRecorder
	// SessionTokens signs and verifies IAM session JWTs; nil unless sts.jwt is configured.
	SessionTokens *SessionTokenSigner
	// WebIdentity verifies external OIDC tokens; nil unless sts.webIdentity is enabled.
	WebIdentity *WebIdentityVerifier
	// Hosts is the organization sign-in address service.
	Hosts *HostService
	// Billing is the billing ledger's hooks (nil until attached).
	Billing *BillingHooks
}

// ContextBase is what createContext receives.
type ContextBase struct {
	Options *BetterIamOptions
	Config  *ServerConfig
	Store   core.IamStore
	Auth    *auth.Service
	Plugins []*core.IamPlugin
	Catalog *Catalog
	Now     func() int64
	Observe *Observer
}

// CreateContext builds the context with its record helpers; the composition root attaches the services.
func CreateContext(base ContextBase) *ServerContext {
	wall := func() int64 { return time.Now().UnixMilli() }
	if base.Options != nil && base.Options.WallClock != nil {
		wall = base.Options.WallClock
	}
	now := base.Now
	if now == nil {
		now = wall
	}
	var protocols []ProtocolMount
	if base.Options != nil {
		protocols = append(protocols, base.Options.Protocols...)
	}
	return &ServerContext{
		Options: base.Options, Config: base.Config, Store: base.Store, Auth: base.Auth, Plugins: base.Plugins,
		Catalog: base.Catalog, Observe: base.Observe, NowFunc: now, WallFunc: wall,
		Subscribers: &subscriberSet{}, MountedProtocols: protocols,
	}
}

// Now is the injected clock (epoch milliseconds).
func (c *ServerContext) Now() int64 { return c.NowFunc() }

// Wall is the wall clock (Date.now()).
func (c *ServerContext) Wall() int64 { return c.WallFunc() }

var weekdays = map[time.Weekday]int{time.Sunday: 0, time.Monday: 1, time.Tuesday: 2, time.Wednesday: 3, time.Thursday: 4, time.Friday: 5, time.Saturday: 6}
var clockPattern = regexp.MustCompile(`^([01]\d|2[0-3]):([0-5]\d)$`)

func minutesOf(value any) (int, error) {
	text, _ := value.(string)
	match := clockPattern.FindStringSubmatch(text)
	if match == nil {
		return 0, invalidInput("Window times must be HH:MM")
	}
	hours, _ := strconv.Atoi(match[1])
	minutes, _ := strconv.Atoi(match[2])
	return hours*60 + minutes, nil
}

var offsetZone = regexp.MustCompile(`^([+-])([01]\d|2[0-3])(?::?([0-5]\d))?$`)
var locations sync.Map

// LoadTimeZone resolves a time zone as Intl.DateTimeFormat does: IANA names (case-insensitively, aliases included)
// and UTC offsets (±HH, ±HHMM, ±HH:MM). It fails with a RangeError-like error for anything else.
func LoadTimeZone(name string) (*time.Location, error) {
	if cached, ok := locations.Load(name); ok {
		return cached.(*time.Location), nil
	}
	var location *time.Location
	if match := offsetZone.FindStringSubmatch(name); match != nil {
		hours, _ := strconv.Atoi(match[2])
		minutes := 0
		if match[3] != "" {
			minutes, _ = strconv.Atoi(match[3])
		}
		offset := hours*3600 + minutes*60
		if match[1] == "-" {
			offset = -offset
		}
		location = time.FixedZone(name, offset)
	} else if canonical, ok := timeZoneNames[strings.ToLower(name)]; ok {
		loaded, err := time.LoadLocation(canonical)
		if err != nil {
			return nil, &rangeError{"Invalid time zone specified: " + name}
		}
		location = loaded
	} else {
		return nil, &rangeError{"Invalid time zone specified: " + name}
	}
	locations.Store(name, location)
	return location, nil
}

// rangeError mirrors a JavaScript RangeError.
type rangeError struct{ message string }

func (e *rangeError) Error() string { return e.message }

// Name is the JavaScript error name.
func (e *rangeError) Name() string { return "RangeError" }

// localTime is the local weekday and minute of day of an instant in a time zone.
func localTime(at float64, timeZone string) (day int, minutes int, err error) {
	location, err := LoadTimeZone(timeZone)
	if err != nil {
		return 0, 0, err
	}
	if at != at || at > 8.64e15 || at < -8.64e15 {
		return 0, 0, &rangeError{"Invalid time value"}
	}
	local := time.UnixMilli(int64(at)).In(location)
	return weekdays[local.Weekday()], local.Hour()*60 + local.Minute(), nil
}

// InsideWindow reports whether an instant lies inside a recurring window (an AccessWindow model value); overnight
// windows count as the day they start on.
func InsideWindow(window *core.Object, at float64) (bool, error) {
	day, minutes, err := localTime(at, jsString(window.Get("timeZone")))
	if err != nil {
		return false, err
	}
	from, err := minutesOf(window.Get("from"))
	if err != nil {
		return false, err
	}
	to, err := minutesOf(window.Get("to"))
	if err != nil {
		return false, err
	}
	days := []any{0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0}
	if listed := window.Get("days"); !nullish(listed) {
		days, _ = listed.([]any)
	}
	includes := func(value int) bool {
		for _, item := range days {
			if item == float64(value) {
				return true
			}
		}
		return false
	}
	if from < to {
		return minutes >= from && minutes < to && includes(day), nil
	}
	// Wraps past midnight: the evening part belongs to today, the early part to the day the window started.
	if minutes >= from {
		return includes(day), nil
	}
	if minutes < to {
		return includes((day + 6) % 7), nil
	}
	return false, nil
}

var limitLabels = map[string]string{
	"identities": "member", "serviceAccounts": "service account", "agents": "agent", "groups": "group",
	"roles": "role", "policies": "policy", "resources": "resource", "webhooks": "webhook",
}

var slugPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Slug validates a tenant alias.
func Slug(value any) (string, error) {
	text, err := Text(value, "slug", 63)
	if err != nil {
		return "", err
	}
	result := core.JSLower(text)
	if !slugPattern.MatchString(result) {
		return "", invalidInput("Slug must use 1-63 lowercase letters, digits, or hyphens")
	}
	return result, nil
}

// Tenant reads a tenant (NOT_FOUND when it does not exist).
func (c *ServerContext) Tenant(ctx context.Context, tx core.IamStore, tenantID any) (*core.Object, error) {
	id, err := Text(tenantID, "tenantId")
	if err != nil {
		return nil, err
	}
	found, err := tx.Get(ctx, "tenants", id)
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, core.NewIamError("NOT_FOUND", "Tenant not found", 404)
	}
	return found, nil
}

// Ancestry is the tenant and its ancestors up to the root; it rejects cycles and excessive depth.
func (c *ServerContext) Ancestry(ctx context.Context, tx core.IamStore, target *core.Object) ([]*core.Object, error) {
	list := []*core.Object{target}
	seen := map[string]bool{jsString(target.Get("id")): true}
	for {
		last := list[len(list)-1]
		parentID := last.Get("parentId")
		if !truthy(parentID) {
			return list, nil
		}
		parent, err := c.Tenant(ctx, tx, parentID)
		if err != nil {
			return nil, err
		}
		parentKey := jsString(parent.Get("id"))
		if seen[parentKey] || len(list) > c.Config.MaxDepth {
			return nil, core.NewIamError("INVALID_HIERARCHY", "Invalid tenant hierarchy", 500)
		}
		list = append(list, parent)
		seen[parentKey] = true
	}
}

// AncestorIDs are the ancestor tenant IDs (the tenant first), tolerant of tenants that no longer exist.
func (c *ServerContext) AncestorIDs(ctx context.Context, tx core.IamStore, tenantID string) ([]string, error) {
	var ids []string
	current := tenantID
	for current != "" && len(ids) <= c.Config.MaxDepth && !containsString(ids, current) {
		ids = append(ids, current)
		realm, err := tx.Get(ctx, "tenants", current)
		if err != nil {
			return nil, err
		}
		current = ""
		if realm != nil {
			current, _ = realm.Get("parentId").(string)
		}
	}
	return ids, nil
}

// RootPrincipal is the protected universal authority: a root-tenant human with the root capability in an MFA user
// session.
func (c *ServerContext) RootPrincipal(ctx context.Context, tx core.IamStore, principal *Principal) (bool, error) {
	realm, err := c.Tenant(ctx, tx, principal.Identity.Get("tenantId"))
	if err != nil {
		return false, err
	}
	return realm.Get("type") == "root" && realm.Has("parentId") && realm.Get("parentId") == nil &&
		truthy(principal.Identity.Get("rootAdmin")) && principal.Session.Get("kind") == "user" &&
		truthy(principal.Session.Get("mfa")), nil
}

// AuthorityChain is the ceilings of an authority and its parents; ok is false when any link is revoked or missing.
func (c *ServerContext) AuthorityChain(ctx context.Context, tx core.IamStore, authorityID string) (policies []any, ok bool, err error) {
	policies = []any{}
	seen := map[string]bool{}
	current := authorityID
	for current != "" {
		if seen[current] || len(seen) > 100 {
			return nil, false, nil
		}
		seen[current] = true
		authority, err := tx.Get(ctx, "grantAuthorities", current)
		if err != nil {
			return nil, false, err
		}
		if authority == nil || truthy(authority.Get("revoked")) {
			return nil, false, nil
		}
		policies = append(policies, authority.Get("ceiling"))
		parent := authority.Get("parentAuthorityId")
		if !truthy(parent) {
			break
		}
		current = jsString(parent)
	}
	return policies, true, nil
}

// Scoped reads a record of a collection that must belong to the tenant (NOT_FOUND otherwise).
func (c *ServerContext) Scoped(ctx context.Context, tx core.IamStore, collection string, recordID any, tenantID string) (*core.Object, error) {
	id, err := Text(recordID, "id")
	if err != nil {
		return nil, err
	}
	record, err := tx.Get(ctx, collection, id)
	if err != nil {
		return nil, err
	}
	if record == nil || record.Get("tenantId") != tenantID {
		return nil, core.NewIamError("NOT_FOUND", "Resource not found", 404)
	}
	return record, nil
}

// ActiveIdentity is a tenant identity that is not deleted; deleted identities remain readable as historical
// principals only.
func (c *ServerContext) ActiveIdentity(ctx context.Context, tx core.IamStore, identityID any, tenantID string) (*core.Object, error) {
	identity, err := c.Scoped(ctx, tx, "identities", identityID, tenantID)
	if err != nil {
		return nil, err
	}
	if identity.Get("status") == "deleted" {
		return nil, core.NewIamError("NOT_FOUND", "Identity has been deleted", 404)
	}
	return identity, nil
}

// ServiceAccount is a tenant identity of kind service.
func (c *ServerContext) ServiceAccount(ctx context.Context, tx core.IamStore, identityID any, tenantID string) (*core.Object, error) {
	account, err := c.Scoped(ctx, tx, "identities", identityID, tenantID)
	if err != nil {
		return nil, err
	}
	if account.Get("kind") != "service" {
		return nil, core.NewIamError("NOT_FOUND", "Service account not found", 404)
	}
	return account, nil
}

// ClaimSlug reserves a global sign-in alias for a tenant.
func (c *ServerContext) ClaimSlug(ctx context.Context, tx core.IamStore, tenantID string, value any) (string, error) {
	alias, err := Slug(value)
	if err != nil {
		return "", err
	}
	existing, err := tx.Get(ctx, "tenantAliases", alias)
	if err != nil {
		return "", err
	}
	if existing != nil {
		return "", core.NewIamError("SLUG_TAKEN", "This slug is already in use", 409)
	}
	if _, err := tx.Insert(ctx, "tenantAliases", core.NewObject("id", alias, "tenantId", tenantID, "createdAt", float64(c.Wall()))); err != nil {
		return "", err
	}
	return alias, nil
}

// ProtectLastOwner refuses removing the final active owner or root administrator.
func (c *ServerContext) ProtectLastOwner(ctx context.Context, tx core.IamStore, identity *core.Object) error {
	if identity.Get("status") != "active" {
		return nil
	}
	if truthy(identity.Get("owner")) {
		owners, err := tx.Find(ctx, "identities", core.NewObject("tenantId", identity.Get("tenantId"), "owner", true, "status", "active"), nil)
		if err != nil {
			return err
		}
		if len(owners) <= 1 {
			return core.NewIamError("LAST_OWNER", "Cannot remove the final active owner", 409)
		}
	}
	if truthy(identity.Get("rootAdmin")) {
		admins, err := tx.Find(ctx, "identities", core.NewObject("tenantId", identity.Get("tenantId"), "rootAdmin", true, "status", "active"), nil)
		if err != nil {
			return err
		}
		if len(admins) <= 1 {
			return core.NewIamError("LAST_ROOT_ADMIN", "Cannot remove the final root administrator", 409)
		}
	}
	return nil
}

// RevokeAll revokes every session an identity holds directly or through role assumption.
func (c *ServerContext) RevokeAll(ctx context.Context, tx core.IamStore, identityID string) error {
	if err := c.Auth.RevokeIdentity(ctx, tx, identityID); err != nil {
		return err
	}
	sessions, err := tx.Find(ctx, "sessions", core.NewObject("originalIdentityId", identityID), nil)
	if err != nil {
		return err
	}
	for _, session := range sessions {
		if err := tx.Delete(ctx, "sessions", jsString(session.Get("id"))); err != nil {
			return err
		}
	}
	return nil
}

// GrantingAuthority is the authority a caller grants under: an explicit one they own (authorityID; "" for none), a
// root-issued one, or their active delegated authority.
func (c *ServerContext) GrantingAuthority(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, authorityID string) (*core.Object, error) {
	// A "view as" session would spend the member's authority, not the administrator's: nobody grants, edits
	// grant-bearing records, or adds people to granting groups while impersonating.
	if truthy(principal.Session.Get("impersonatorId")) {
		return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "Access cannot be granted while impersonating", 403)
	}
	identityID := principal.Identity.Get("id")
	if authorityID != "" {
		authority, err := c.Scoped(ctx, tx, "grantAuthorities", authorityID, tenantID)
		if err != nil {
			return nil, err
		}
		usable := !truthy(authority.Get("revoked"))
		if usable && authority.Get("identityId") != identityID {
			if usable, err = c.RootPrincipal(ctx, tx, principal); err != nil {
				return nil, err
			}
		}
		if usable {
			_, chained, err := c.AuthorityChain(ctx, tx, jsString(authority.Get("id")))
			if err != nil {
				return nil, err
			}
			usable = chained
		}
		if usable {
			return authority, nil
		}
		return nil, core.NewIamError("ACCESS_DENIED", "Cannot use another administrator’s grant authority", 403)
	}
	root, err := c.RootPrincipal(ctx, tx, principal)
	if err != nil {
		return nil, err
	}
	if root {
		found, err := tx.Find(ctx, "grantAuthorities", core.NewObject("tenantId", tenantID, "identityId", identityID, "rootIssued", true), nil)
		if err != nil {
			return nil, err
		}
		if len(found) > 0 {
			return found[0], nil
		}
		return tx.Insert(ctx, "grantAuthorities", core.NewObject(
			"id", ID(), "tenantId", tenantID, "identityId", identityID, "rootIssued", true, "ceiling", All(), "revoked", false,
		))
	}
	candidates, err := tx.Find(ctx, "grantAuthorities", core.NewObject("tenantId", tenantID, "identityId", identityID, "revoked", false), nil)
	if err != nil {
		return nil, err
	}
	for _, authority := range candidates {
		_, chained, err := c.AuthorityChain(ctx, tx, jsString(authority.Get("id")))
		if err != nil {
			return nil, err
		}
		if chained {
			return authority, nil
		}
	}
	return nil, core.NewIamError("GRANT_AUTHORITY_REQUIRED", "An active delegated grant authority is required", 403)
}

// CanEditGrantResource allows editing grant-bearing records (roles, policies) only to their issuing authority or
// root.
func (c *ServerContext) CanEditGrantResource(ctx context.Context, tx core.IamStore, principal *Principal, record *core.Object) error {
	root, err := c.RootPrincipal(ctx, tx, principal)
	if err != nil || root {
		return err
	}
	authorityID, ok := record.Get("authorityId").(string)
	if !ok {
		return core.NewIamError("PROTECTED_RESOURCE", "This resource is controlled by a superior authority", 403)
	}
	_, err = c.GrantingAuthority(ctx, tx, principal, jsString(record.Get("tenantId")), authorityID)
	return err
}

// OwnerSetup creates the protected Owner policy, role, and binding for a newly activated tenant.
func (c *ServerContext) OwnerSetup(ctx context.Context, tx core.IamStore, realm, identity, authority *core.Object) error {
	tenantID := realm.Get("id")
	policy := core.NewObject("id", ID(), "tenantId", tenantID, "name", "Owner", "uniqueKey", "system:owner", "document", All(), "version", 1.0)
	role := core.NewObject("id", ID(), "tenantId", tenantID, "name", "Owner", "uniqueKey", "system:owner",
		"policyIds", []any{policy.Get("id")}, "protected", true)
	if _, err := tx.Insert(ctx, "policies", policy); err != nil {
		return err
	}
	if _, err := tx.Insert(ctx, "roles", role); err != nil {
		return err
	}
	if _, err := tx.Put(ctx, "grantAuthorities", authority.Spread(core.NewObject("identityId", identity.Get("id")))); err != nil {
		return err
	}
	_, err := tx.Insert(ctx, "bindings", core.NewObject(
		"id", ID(), "tenantId", tenantID, "subjectType", "identity", "subjectId", identity.Get("id"),
		"roleId", role.Get("id"), "authorityId", authority.Get("id"),
	))
	return err
}

// EnforceLimit rejects with LIMIT_EXCEEDED when adding records would exceed the tenant's plan limit for key.
// adding defaults to 1.
func (c *ServerContext) EnforceLimit(ctx context.Context, tx core.IamStore, tenant *core.Object, key string, count func(ctx context.Context) (int, error), adding ...int) error {
	limit := member(tenant.Get("limits"), key)
	if isUndefined(limit) {
		return nil
	}
	add := 1
	if len(adding) > 0 {
		add = adding[0]
	}
	current, err := count(ctx)
	if err != nil {
		return err
	}
	if float64(current+add) > jsNumber(limit) {
		return core.NewIamError("LIMIT_EXCEEDED", "This tenant has reached its "+limitLabels[key]+" limit ("+jsString(limit)+")", 409)
	}
	return nil
}

// LiveBinding is a binding that grants right now: started (startsAt) and not expired.
func (c *ServerContext) LiveBinding(binding *core.Object) bool {
	now := float64(c.Now())
	startsAt, expiresAt := binding.Get("startsAt"), binding.Get("expiresAt")
	return (isUndefined(startsAt) || jsNumber(startsAt) <= now) && (isUndefined(expiresAt) || jsNumber(expiresAt) > now)
}

// ExpiredBinding is a temporary binding past its end; future-dated bindings are not expired.
func (c *ServerContext) ExpiredBinding(binding *core.Object) bool {
	expiresAt := binding.Get("expiresAt")
	return !isUndefined(expiresAt) && jsNumber(expiresAt) <= float64(c.Now())
}

// LiveMembership is a group membership that counts right now (no expiry, or one still ahead).
func (c *ServerContext) LiveMembership(member *core.Object) bool {
	expiresAt := member.Get("expiresAt")
	return isUndefined(expiresAt) || jsNumber(expiresAt) > float64(c.Now())
}

const tenYearsMs = 10 * 365 * 86400000

// BindingStart validates a future start (epoch milliseconds, not in the past, within ten years).
func (c *ServerContext) BindingStart(value any) (float64, error) {
	startsAt, err := Integer(value, "startsAt", 0, maxSafeInteger)
	if err != nil {
		return 0, err
	}
	now := float64(c.Now())
	if startsAt < now-60_000 {
		return 0, invalidInput("startsAt must not be in the past")
	}
	if startsAt > now+tenYearsMs {
		return 0, invalidInput("startsAt must be within ten years")
	}
	return startsAt, nil
}

// BindingExpiry validates an end in the future, within ten years.
func (c *ServerContext) BindingExpiry(value any) (float64, error) {
	expiresAt, err := Integer(value, "expiresAt", 0, maxSafeInteger)
	if err != nil {
		return 0, err
	}
	now := float64(c.Now())
	if expiresAt <= now {
		return 0, invalidInput("expiresAt must be in the future")
	}
	if expiresAt > now+tenYearsMs {
		return 0, invalidInput("expiresAt must be within ten years")
	}
	return expiresAt, nil
}

// IdentityExpired is true once an identity's scheduled deactivation has passed.
func (c *ServerContext) IdentityExpired(identity *core.Object) bool {
	expiresAt, ok := identity.Get("expiresAt").(float64)
	return ok && expiresAt <= float64(c.Now())
}

// AccessWindow validates a recurring access window (days, HH:MM bounds, an IANA time zone) and returns it with its
// members in the TypeScript order (from, to, timeZone, days).
func (c *ServerContext) AccessWindow(value any) (*core.Object, error) {
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	from, err := Text(input.Get("from"), "window.from", 5)
	if err != nil {
		return nil, err
	}
	to, err := Text(input.Get("to"), "window.to", 5)
	if err != nil {
		return nil, err
	}
	timeZone, err := Text(input.Get("timeZone"), "window.timeZone", 64)
	if err != nil {
		return nil, err
	}
	window := core.NewObject("from", from, "to", to, "timeZone", timeZone)
	fromMinutes, err := minutesOf(from)
	if err != nil {
		return nil, err
	}
	toMinutes, err := minutesOf(to)
	if err != nil {
		return nil, err
	}
	if fromMinutes == toMinutes {
		return nil, invalidInput("Window must not be empty")
	}
	if _, err := LoadTimeZone(timeZone); err != nil {
		return nil, invalidInput("Unknown window.timeZone")
	}
	if listed := input.Get("days"); !isUndefined(listed) {
		days, ok := listed.([]any)
		if !ok || len(days) == 0 || len(days) > 7 {
			return nil, invalidInput("window.days must list 1-7 weekdays")
		}
		seen := map[float64]bool{}
		var unique []float64
		for _, item := range days {
			day, err := Integer(item, "window.days", 0, 6)
			if err != nil {
				return nil, err
			}
			if !seen[day] {
				seen[day] = true
				unique = append(unique, day)
			}
		}
		// [...new Set(days)].sort(): the default sort compares the numbers' strings, which for 0-6 is numeric.
		for i := 1; i < len(unique); i++ {
			for j := i; j > 0 && unique[j] < unique[j-1]; j-- {
				unique[j], unique[j-1] = unique[j-1], unique[j]
			}
		}
		list := make([]any, len(unique))
		for index, day := range unique {
			list[index] = day
		}
		window.Set("days", list)
	}
	return window, nil
}

// WithinWindow is true when a binding has no window or the time (default now) falls inside it.
func (c *ServerContext) WithinWindow(binding *core.Object, at ...float64) (bool, error) {
	window := binding.Get("window")
	if isUndefined(window) {
		return true, nil
	}
	moment := float64(c.Now())
	if len(at) > 0 {
		moment = at[0]
	}
	object, ok := window.(*core.Object)
	if !ok {
		return false, &core.TypeError{Message: "Cannot read properties of window"}
	}
	return InsideWindow(object, moment)
}
