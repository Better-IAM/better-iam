package server

// Port of packages/server/src/ldap.ts: the server side of the LDAP directory gateway (`@better-iam/ldap`). Each
// tenant can publish its directory under a base DN of its own; this module holds the settings, the deployment-wide
// base DN index (`ldapBases`, one tenant per normalized base DN), and the directory view a bound account may read.

import (
	"context"
	"regexp"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// ldapCollections are the collections of the gateway (ldap.ts ldapCollections).
var ldapCollections = []string{"ldapSettings", "ldapBases"}

// ldapComponent is one `attr=value` component of a base DN.
var ldapComponent = regexp.MustCompile(`^[` + jsWhitespace + `]*([a-zA-Z][a-zA-Z0-9-]{0,31})[` + jsWhitespace + `]*=[` + jsWhitespace + `]*([a-zA-Z0-9](?:[a-zA-Z0-9 ._-]{0,126}[a-zA-Z0-9])?)[` + jsWhitespace + `]*$`)

// ldapSpaces is /\s+/g inside a component value (whose only whitespace is the space).
var ldapSpaces = regexp.MustCompile(`[` + jsWhitespace + `]+`)

// NormalizeBaseDn (ldap.ts normalizeBaseDn): Validates a base DN and returns its comparison form: `attr=value`
// components of letters, digits, spaces, `.`, `_` and `-` (no escapes), lowercased with spaces collapsed, exactly as
// `@better-iam/ldap` normalizes DNs. The answer is `{ baseDn, normalized }`.
func NormalizeBaseDn(value any) (*core.Object, error) {
	text, ok := value.(string)
	if !ok || core.JSTrim(text) == "" || utf16Len(text) > 512 {
		return nil, invalidInput("Enter a base DN such as dc=acme,dc=com")
	}
	parts := strings.Split(text, ",")
	if len(parts) > 10 {
		return nil, invalidInput("A base DN has at most 10 components")
	}
	normalized := make([]string, len(parts))
	for index, part := range parts {
		match := ldapComponent.FindStringSubmatch(part)
		if match == nil {
			return nil, invalidInput(`Base DN components are attr=value with letters, digits, spaces, ".", "_" or "-"`)
		}
		normalized[index] = core.JSLower(match[1]) + "=" + core.JSLower(ldapSpaces.ReplaceAllString(match[2], " "))
	}
	switch normalized[0] {
	case "ou=people", "ou=groups", "ou=services":
		return nil, invalidInput("The base DN cannot itself be ou=people, ou=groups or ou=services")
	}
	trimmed := make([]string, len(parts))
	for index, part := range parts {
		trimmed[index] = core.JSTrim(part)
	}
	return core.NewObject("baseDn", strings.Join(trimmed, ","), "normalized", strings.Join(normalized, ",")), nil
}

// ldapSlug lowercases value, turns every UTF-16 code unit outside [a-z0-9-] into one `-` and trims leading and
// trailing dashes (the slug step of defaultLdapSettings).
func ldapSlug(value string) string {
	units := core.ToUTF16(core.JSLower(value))
	out := make([]byte, 0, len(units))
	for _, unit := range units {
		if (unit >= 'a' && unit <= 'z') || (unit >= '0' && unit <= '9') || unit == '-' {
			out = append(out, byte(unit))
		} else {
			out = append(out, '-')
		}
	}
	return strings.Trim(string(out), "-")
}

// defaultLdapSettings are a tenant's settings before anyone saved any (ldap.ts defaultLdapSettings).
func defaultLdapSettings(tenant *core.Object) *core.Object {
	slug := ldapSlug(jsString(coalesce(tenant.Get("slug"), tenant.Get("id"))))
	if slug == "" {
		slug = "tenant"
	}
	baseDn := "o=" + slug
	return core.NewObject(
		"id", tenant.Get("id"), "tenantId", tenant.Get("id"), "enabled", false, "baseDn", baseDn,
		"normalizedBaseDn", baseDn, "uid", "email", "peopleBind", true, "serviceBind", true, "requireTls", true,
		"mfaSuffix", "auto", "includeServiceAccounts", false, "attributes", []any{}, "groups", "all",
		"groupIds", []any{}, "updatedAt", 0, "updatedBy", "",
	)
}

// LoadLdapSettings (ldap.ts loadLdapSettings): the tenant's stored gateway settings over the defaults, or the
// defaults when none are stored.
func LoadLdapSettings(ctx context.Context, tx core.IamStore, tenant *core.Object) (*core.Object, error) {
	stored, err := tx.Get(ctx, "ldapSettings", jsString(tenant.Get("id")))
	if err != nil {
		return nil, err
	}
	if stored != nil && stored.Get("tenantId") == tenant.Get("id") {
		return defaultLdapSettings(tenant).Spread(stored), nil
	}
	return defaultLdapSettings(tenant), nil
}

// SaveLdapSettings (ldap.ts saveLdapSettings): Stores settings and keeps the base DN index in step (a base DN
// belongs to one tenant).
func SaveLdapSettings(ctx context.Context, tx core.IamStore, settings *core.Object, previous *core.Object) (*core.Object, error) {
	tenantID := settings.Get("tenantId")
	normalized := jsString(settings.Get("normalizedBaseDn"))
	if previous != nil && previous.Get("normalizedBaseDn") != settings.Get("normalizedBaseDn") {
		old, err := tx.Get(ctx, "ldapBases", jsString(previous.Get("normalizedBaseDn")))
		if err != nil {
			return nil, err
		}
		if old != nil && old.Get("tenantId") == tenantID {
			if err := tx.Delete(ctx, "ldapBases", jsString(old.Get("id"))); err != nil {
				return nil, err
			}
		}
	}
	owner, err := tx.Get(ctx, "ldapBases", normalized)
	if err != nil {
		return nil, err
	}
	if truthy(settings.Get("enabled")) {
		if owner != nil && owner.Get("tenantId") != tenantID {
			return nil, core.NewIamError("LDAP_BASE_TAKEN", "Another organization publishes its directory under this base DN", 409)
		}
		if owner == nil {
			if _, err := tx.Insert(ctx, "ldapBases", core.NewObject("id", normalized, "tenantId", tenantID, "settingsId", settings.Get("id"))); err != nil {
				return nil, err
			}
		}
	} else if owner != nil && owner.Get("tenantId") == tenantID {
		if err := tx.Delete(ctx, "ldapBases", jsString(owner.Get("id"))); err != nil {
			return nil, err
		}
	}
	existing, err := tx.Get(ctx, "ldapSettings", jsString(settings.Get("id")))
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return tx.Put(ctx, "ldapSettings", settings)
	}
	return tx.Insert(ctx, "ldapSettings", settings)
}

// ldapLive is an identity that is active and not past its scheduled deactivation.
func ldapLive(server *ServerContext, identity *core.Object) bool {
	return identity.Get("status") == "active" && !server.IdentityExpired(identity)
}

// ldapUids is each person's `uid`: email, local part (the email where local parts collide), or identity ID.
func ldapUids(people []*core.Object, mode any) map[string]string {
	result := map[string]string{}
	local := func(identity *core.Object) string {
		return core.JSLower(strings.SplitN(jsString(coalesce(identity.Get("email"), identity.Get("id"))), "@", 2)[0])
	}
	counts := map[string]int{}
	if mode == "localPart" {
		for _, person := range people {
			counts[local(person)]++
		}
	}
	for _, person := range people {
		id := jsString(person.Get("id"))
		switch {
		case mode == "id":
			result[id] = id
		case mode == "localPart" && counts[local(person)] == 1:
			result[id] = local(person)
		default:
			result[id] = core.JSLower(jsString(coalesce(person.Get("email"), person.Get("id"))))
		}
	}
	return result
}

// ldapIncludes is `list.includes(value)` over a model array.
func ldapIncludes(list any, value any) bool {
	items, _ := list.([]any)
	for _, item := range items {
		if item == value {
			return true
		}
	}
	return false
}

// ldapSortBy sorts views by a string member (`a[key] < b[key] ? -1 : 1`).
func ldapSortBy(views []*core.Object, key string) []any {
	sortStable(views, func(a, b *core.Object) int {
		return compareUTF16(jsString(a.Get(key)), jsString(b.Get(key)))
	})
	out := make([]any, len(views))
	for index, view := range views {
		out[index] = view
	}
	return out
}

// BuildLdapDirectory (ldap.ts buildLdapDirectory): Builds the directory view of a tenant: active people, published
// groups and (optionally) service accounts. With `self`, only the caller's own entry, and their groups with only
// themselves as a member.
func BuildLdapDirectory(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object, settings *core.Object, self *Principal) (*core.Object, error) {
	all, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenant.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	identities := []*core.Object{}
	for _, identity := range all {
		if ldapLive(server, identity) {
			identities = append(identities, identity)
		}
	}
	people, machines := []*core.Object{}, []*core.Object{}
	for _, identity := range identities {
		if identity.Get("kind") == "user" {
			people = append(people, identity)
		} else {
			machines = append(machines, identity)
		}
	}
	uidOf := ldapUids(people, settings.Get("uid"))
	groups, err := tx.Find(ctx, "groups", core.NewObject("tenantId", tenant.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	if settings.Get("groups") == "selected" {
		selected := []*core.Object{}
		for _, group := range groups {
			if ldapIncludes(settings.Get("groupIds"), group.Get("id")) {
				selected = append(selected, group)
			}
		}
		groups = selected
	}
	members := map[string][]string{}
	memberships := map[string][]string{}
	for _, group := range groups {
		groupID := jsString(group.Get("id"))
		rows, err := tx.Find(ctx, "groupMembers", core.NewObject("groupId", group.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		ids := []string{}
		for _, row := range rows {
			if server.LiveMembership(row) {
				ids = append(ids, jsString(row.Get("identityId")))
			}
		}
		members[groupID] = ids
		for _, identityID := range ids {
			memberships[identityID] = append(append([]string(nil), memberships[identityID]...), groupID)
		}
	}
	alive := map[string]bool{}
	for _, identity := range identities {
		alive[jsString(identity.Get("id"))] = true
	}
	groupIDsOf := func(identityID string) []any {
		return stringsOf(memberships[identityID])
	}
	attributeNames, _ := settings.Get("attributes").([]any)
	personViews := []*core.Object{}
	for _, person := range people {
		id := jsString(person.Get("id"))
		view := core.NewObject("id", id, "uid", uidOf[id])
		if email := person.Get("email"); truthy(email) {
			view.Set("email", email)
		}
		if name := person.Get("name"); truthy(name) {
			view.Set("name", name)
		}
		view.Set("emailVerified", person.Get("emailVerified") == true)
		attributes := core.NewObject()
		for _, rawName := range attributeNames {
			name := jsString(rawName)
			value := member(person.Get("attributes"), name)
			if nullish(value) {
				continue
			}
			attributes.Set(name, value)
		}
		view.Set("attributes", attributes)
		view.Set("groupIds", groupIDsOf(id))
		personViews = append(personViews, view)
	}
	groupViews := []*core.Object{}
	for _, group := range groups {
		view := core.NewObject("id", group.Get("id"), "name", group.Get("name"))
		if description, ok := group.Get("description").(string); ok {
			view.Set("description", description)
		}
		memberIDs := []string{}
		for _, identityID := range members[jsString(group.Get("id"))] {
			if alive[identityID] {
				memberIDs = append(memberIDs, identityID)
			}
		}
		view.Set("memberIds", stringsOf(memberIDs))
		groupViews = append(groupViews, view)
	}
	services := []*core.Object{}
	if truthy(settings.Get("includeServiceAccounts")) {
		for _, machine := range machines {
			services = append(services, core.NewObject(
				"id", machine.Get("id"), "name", coalesce(machine.Get("name"), machine.Get("id")), "kind", machine.Get("kind"),
				"groupIds", groupIDsOf(jsString(machine.Get("id"))),
			))
		}
	}
	scope := "full"
	if self != nil {
		scope = "self"
		// Only the caller's own entry, and their groups with only themselves as a member.
		me := self.Identity.Get("id")
		mine := []*core.Object{}
		for _, person := range personViews {
			if person.Get("id") == me {
				mine = append(mine, person)
			}
		}
		personViews = mine
		ownServices := []*core.Object{}
		for _, service := range services {
			if service.Get("id") == me {
				ownServices = append(ownServices, service)
			}
		}
		services = ownServices
		ownGroups := []*core.Object{}
		for _, group := range groupViews {
			if ldapIncludes(group.Get("memberIds"), me) {
				ownGroups = append(ownGroups, group.Spread(core.NewObject("memberIds", []any{me})))
			}
		}
		groupViews = ownGroups
	}
	return core.NewObject(
		"tenantId", tenant.Get("id"), "tenantName", tenant.Get("name"), "baseDn", settings.Get("baseDn"),
		"uid", settings.Get("uid"), "scope", scope,
		"people", ldapSortBy(personViews, "uid"),
		"groups", ldapSortBy(groupViews, "name"),
		"services", ldapSortBy(services, "name"),
		"generatedAt", server.Now(),
	), nil
}

// LdapRuntime is ldap.ts createLdapRuntime(): the deployment-side lookups the gateway needs before anyone is bound
// (no credential; no secrets).
type LdapRuntime struct {
	server *ServerContext
}

// CreateLdapRuntime builds the LdapRuntime (ldap.ts createLdapRuntime).
func CreateLdapRuntime(server *ServerContext) *LdapRuntime {
	return &LdapRuntime{server: server}
}

// tenantFor is the active tenant publishing under a normalized base DN, with its settings (nil, nil when none).
func (s *LdapRuntime) tenantFor(ctx context.Context, tx core.IamStore, normalizedBaseDn string) (*core.Object, *core.Object, error) {
	base, err := tx.Get(ctx, "ldapBases", normalizedBaseDn)
	if err != nil || base == nil {
		return nil, nil, err
	}
	tenant, err := tx.Get(ctx, "tenants", jsString(base.Get("tenantId")))
	if err != nil || tenant == nil {
		return nil, nil, err
	}
	ancestry, err := s.server.Ancestry(ctx, tx, tenant)
	if err != nil {
		return nil, nil, err
	}
	for _, item := range ancestry {
		if item.Get("status") != "active" {
			return nil, nil, nil
		}
	}
	settings, err := LoadLdapSettings(ctx, tx, tenant)
	if err != nil {
		return nil, nil, err
	}
	if !truthy(settings.Get("enabled")) || settings.Get("normalizedBaseDn") != normalizedBaseDn {
		return nil, nil, nil
	}
	return tenant, settings, nil
}

// TenantForBase (ldap.ts createLdapRuntime().tenantForBase): The tenant publishing its directory under a normalized
// base DN, with its gateway settings; nil when none does, it is off, or the organization is not active.
func (s *LdapRuntime) TenantForBase(ctx context.Context, normalizedBaseDn string) (*core.Object, error) {
	tenant, settings, err := s.tenantFor(ctx, s.server.Store, normalizedBaseDn)
	if err != nil || tenant == nil {
		return nil, err
	}
	return core.NewObject(
		"tenantId", tenant.Get("id"), "tenantName", tenant.Get("name"), "baseDn", settings.Get("baseDn"),
		"normalizedBaseDn", settings.Get("normalizedBaseDn"), "uid", settings.Get("uid"),
		"peopleBind", settings.Get("peopleBind"), "serviceBind", settings.Get("serviceBind"),
		"requireTls", settings.Get("requireTls"), "mfaSuffix", settings.Get("mfaSuffix"),
	), nil
}

// ResolveBindName (ldap.ts createLdapRuntime().resolveBindName): The sign-in email of the person a people RDN value
// names (`uid` as the tenant configured it), or the service account a name (or, when names collide, an ID) names;
// nil when nobody matches. Only active members resolve. `mfa` says how a person's bind must authenticate: `none`
// (the password), `totp` (the password followed by the current authenticator code) or `unavailable` (MFA is
// required but no authenticator is enrolled, which LDAP cannot satisfy), so the gateway makes exactly one sign-in
// attempt per bind. kind is `person` or `service`.
func (s *LdapRuntime) ResolveBindName(ctx context.Context, tenantID string, kind string, value string) (*core.Object, error) {
	store := s.server.Store
	tenant, err := store.Get(ctx, "tenants", tenantID)
	if err != nil || tenant == nil {
		return nil, err
	}
	settings, err := LoadLdapSettings(ctx, store, tenant)
	if err != nil {
		return nil, err
	}
	wanted := core.JSLower(value)
	all, err := store.Find(ctx, "identities", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	identities := []*core.Object{}
	for _, identity := range all {
		if ldapLive(s.server, identity) {
			identities = append(identities, identity)
		}
	}
	if kind == "service" {
		machines := []*core.Object{}
		for _, identity := range identities {
			if identity.Get("kind") != "user" {
				machines = append(machines, identity)
			}
		}
		named := []*core.Object{}
		for _, identity := range machines {
			if core.JSLower(jsString(coalesce(identity.Get("name"), ""))) == wanted {
				named = append(named, identity)
			}
		}
		if len(named) == 1 {
			return core.NewObject("identityId", named[0].Get("id")), nil
		}
		for _, identity := range machines {
			if core.JSLower(jsString(identity.Get("id"))) == wanted {
				return core.NewObject("identityId", identity.Get("id")), nil
			}
		}
		return nil, nil
	}
	people := []*core.Object{}
	for _, identity := range identities {
		if identity.Get("kind") == "user" {
			people = append(people, identity)
		}
	}
	uidOf := ldapUids(people, settings.Get("uid"))
	var person *core.Object
	for _, identity := range people {
		if uid, ok := uidOf[jsString(identity.Get("id"))]; ok && uid == wanted {
			person = identity
			break
		}
	}
	if person == nil {
		return nil, nil
	}
	mfa := "none"
	required, err := s.server.Auth.MfaRequired(ctx, store, person)
	if err != nil {
		return nil, err
	}
	if required {
		enrolled, err := store.Get(ctx, "authMfa", jsString(person.Get("id")))
		if err != nil {
			return nil, err
		}
		if enrolled != nil && truthy(enrolled.Get("enabled")) {
			mfa = "totp"
		} else {
			mfa = "unavailable"
		}
	}
	result := core.NewObject("identityId", person.Get("id"))
	if email := person.Get("email"); truthy(email) {
		result.Set("email", email)
	}
	result.Set("mfa", mfa)
	return result, nil
}
