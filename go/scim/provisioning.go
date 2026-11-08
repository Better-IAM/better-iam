package scim

// Port of packages/scim/src/provisioning.ts: provisioning logic shared by the connection API and the HTTP handler:
// connection authentication, user and group persistence, membership and role-mapping synchronization, and PATCH
// application.

import (
	"context"
	"crypto/subtle"
	"errors"
	"math"
	"net/http"

	"github.com/Better-IAM/better-iam/go/core"
)

// managerValue is the enterprise extension's `manager.value`, trimmed, if any ("" when none).
func managerValue(enterprise any) (string, bool) {
	manager := member(enterprise, "manager")
	if !truthy(manager) || typeOf(manager) != "object" {
		return "", false
	}
	value, ok := member(manager, "value").(string)
	if !ok || core.JSTrim(value) == "" {
		return "", false
	}
	return core.JSTrim(value), true
}

// managerLookup resolves a manager reference; self is the user holding it (nil for none).
type managerLookup func(value string, self *core.Object) *core.Object

// managerIndex indexes a connection's users once, so resolving any number of manager references stays linear. A
// reference names the user with that SCIM ID, else the case-exact `externalId`, else the `userName` ignoring case. At
// each step self wins over other users (naming oneself names no manager, so resolution never falls through to someone
// else), then the first matching user in users.
func managerIndex(users []*core.Object) managerLookup {
	byID := map[string]*core.Object{}
	byExternalID := map[string]*core.Object{}
	byUserName := map[string]*core.Object{}
	for _, row := range users {
		if id, ok := row.Get("id").(string); ok {
			if _, seen := byID[id]; !seen {
				byID[id] = row
			}
		}
		if externalID, ok := row.Get("externalId").(string); ok {
			if _, seen := byExternalID[externalID]; !seen {
				byExternalID[externalID] = row
			}
		}
		userName := core.JSLower(jsString(row.Get("userName")))
		if _, seen := byUserName[userName]; !seen {
			byUserName[userName] = row
		}
	}
	return func(value string, self *core.Object) *core.Object {
		lower := core.JSLower(value)
		if self != nil && self.Get("id") == value {
			return self
		}
		if found, ok := byID[value]; ok {
			return found
		}
		if self != nil && self.Get("externalId") == value {
			return self
		}
		if found, ok := byExternalID[value]; ok {
			return found
		}
		if self != nil && core.JSLower(jsString(self.Get("userName"))) == lower {
			return self
		}
		return byUserName[lower]
	}
}

// orderedSet is a JavaScript Set of strings.
type orderedSet struct {
	items []string
	index map[string]bool
}

func newOrderedSet() *orderedSet { return &orderedSet{index: map[string]bool{}} }

func (s *orderedSet) add(item string) {
	if !s.index[item] {
		s.index[item] = true
		s.items = append(s.items, item)
	}
}

func (s *orderedSet) remove(item string) bool {
	if !s.index[item] {
		return false
	}
	delete(s.index, item)
	for i, candidate := range s.items {
		if candidate == item {
			s.items = append(s.items[:i], s.items[i+1:]...)
			break
		}
	}
	return true
}

// provisioning is createProvisioning(config).
type provisioning struct {
	config  *Config
	lenient bool
}

func newProvisioning(config *Config) (*provisioning, error) {
	if config.UnsupportedAttributes != "" && config.UnsupportedAttributes != "ignore" && config.UnsupportedAttributes != "reject" {
		return nil, core.NewIamError("configuration", "SCIM unsupportedAttributes must be 'ignore' or 'reject'.")
	}
	return &provisioning{config: config, lenient: config.UnsupportedAttributes != "reject"}, nil
}

func (p *provisioning) mapManager() bool { return p.config.MapManager == nil || *p.config.MapManager }

// audit records an event, through the host when it can fan events out (webhooks, subscribers such as an outbound
// provisioner); actorID "" is the connection itself.
func (p *provisioning) audit(ctx context.Context, tx core.IamStore, connection *core.Object, action string, resourceID any, actorID string) error {
	if actorID == "" {
		actorID = "scim:" + jsString(connection.Get("id"))
	}
	event := core.NewObject(
		"id", randomUUID(),
		"tenantId", connection.Get("tenantId"),
		"actorId", actorID,
		"action", action,
		"resourceId", resourceID,
		"timestamp", p.config.now(),
		"outcome", "allow",
	)
	if p.config.RecordAudit != nil {
		return p.config.RecordAudit(ctx, tx, event)
	}
	_, err := core.AppendAuditEvent(ctx, tx, event)
	return err
}

// bearerToken is `authorization.match(/^Bearer (\S+)$/i)?.[1]`.
func bearerToken(header http.Header) (string, bool) {
	value, ok := headerGet(header, "authorization")
	if !ok || len(value) < 8 || !asciiFold(value[:7], "bearer ") || value[6] != ' ' {
		return "", false
	}
	token := value[7:]
	if token == "" || hasJSSpace(token) {
		return "", false
	}
	return token, true
}

func (p *provisioning) authenticate(ctx context.Context, tx core.IamStore, header http.Header, connectionID string) (*core.Object, error) {
	connection, err := tx.Get(ctx, "scimConnections", connectionID)
	if err != nil {
		return nil, err
	}
	token, hasToken := bearerToken(header)
	invalid := connection == nil || !hasToken || truthy(connection.Get("revoked")) || jsNumber(connection.Get("expiresAt")) <= p.config.now()
	if !invalid {
		stored, ok := connection.Get("tokenHash").(string)
		if !ok {
			return nil, typeError(`The first argument must be of type string or an instance of Buffer, ArrayBuffer, or Array or an Array-like Object.`)
		}
		presented := []byte(hash(token))
		expected := utf8Bytes(stored)
		if len(presented) != len(expected) {
			return nil, errors.New("Input buffers must have the same byte length")
		}
		invalid = subtle.ConstantTimeCompare(presented, expected) != 1
	}
	if invalid {
		return nil, core.NewIamError("unauthorized", "Invalid SCIM credential.", 401)
	}
	if err := activeTenant(ctx, tx, jsString(connection.Get("tenantId"))); err != nil {
		return nil, err
	}
	now := p.config.now()
	if lastUsed := connection.Get("lastUsedAt"); !truthy(lastUsed) || now-jsNumber(lastUsed) >= 60_000 {
		connection.Set("lastUsedAt", now)
		if _, err := tx.Put(ctx, "scimConnections", connection); err != nil {
			return nil, err
		}
	}
	return connection, nil
}

// deleteAll deletes every record of a collection matching filter.
func deleteAll(ctx context.Context, tx core.IamStore, collection string, filter *core.Object) error {
	rows, err := tx.Find(ctx, collection, filter, nil)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if err := tx.Delete(ctx, collection, jsString(row.Get("id"))); err != nil {
			return err
		}
	}
	return nil
}

// revokeSessions ends everything that keeps a person signed in or lets them skip a step, as an administrator's
// disable does: sessions (and those acting as them), remembered MFA devices and pending sign-in challenges.
func revokeSessions(ctx context.Context, tx core.IamStore, identityID any) error {
	if err := deleteAll(ctx, tx, "sessions", core.NewObject("identityId", identityID)); err != nil {
		return err
	}
	if err := deleteAll(ctx, tx, "sessions", core.NewObject("originalIdentityId", identityID)); err != nil {
		return err
	}
	if err := deleteAll(ctx, tx, "authDevices", core.NewObject("identityId", identityID)); err != nil {
		return err
	}
	return deleteAll(ctx, tx, "authChallenges", core.NewObject("identityId", identityID))
}

// withinLimit holds the tenant's plan limit (`Tenant.limits`) for SCIM as for every other way people and groups are
// added.
func withinLimit(ctx context.Context, tx core.IamStore, tenantID any, key string) error {
	tenant, err := tx.Get(ctx, "tenants", jsString(tenantID))
	if err != nil {
		return err
	}
	var limit any = core.Undefined
	if tenant != nil {
		limit = member(tenant.Get("limits"), key)
	}
	if core.IsUndefined(limit) {
		return nil
	}
	count := 0
	if key == "identities" {
		rows, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "kind", "user"), nil)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if row.Get("status") != "deleted" {
				count++
			}
		}
	} else {
		rows, err := tx.Find(ctx, "groups", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return err
		}
		count = len(rows)
	}
	if bound := jsNumber(limit); !math.IsNaN(bound) && float64(count) >= bound {
		noun := "group"
		if key == "identities" {
			noun = "member"
		}
		return core.NewIamError("LIMIT_EXCEEDED", "This tenant has reached its "+noun+" limit ("+jsString(limit)+").", 409)
	}
	return nil
}

// identity is the local identity behind a SCIM user; owners and root administrators are never provisioning targets.
func identity(ctx context.Context, tx core.IamStore, link *core.Object) (*core.Object, error) {
	found, err := tx.Get(ctx, "identities", jsString(link.Get("identityId")))
	if err != nil {
		return nil, err
	}
	if found == nil || found.Get("tenantId") != link.Get("tenantId") || truthy(found.Get("rootAdmin")) || truthy(found.Get("owner")) {
		return nil, core.NewIamError("mutability", "SCIM cannot modify a protected identity.", 403)
	}
	return found, nil
}

// updatable is the identity a SCIM user update writes; one an administrator deleted stays a tombstone and is never
// revived.
func updatable(ctx context.Context, tx core.IamStore, link *core.Object) (*core.Object, error) {
	found, err := identity(ctx, tx, link)
	if err != nil {
		return nil, err
	}
	if found.Get("status") == "deleted" {
		return nil, core.NewIamError("mutability", "SCIM cannot modify a deleted identity.", 403)
	}
	return found, nil
}

// assignableManager is the identity SCIM may make report's manager: another identity of the tenant that is not
// deleted and does not already report to report (directly or up to 100 levels up). "" skips the assignment; it is
// never an error.
func assignableManager(ctx context.Context, tx core.IamStore, report, manager *core.Object) (string, error) {
	found, err := tx.Get(ctx, "identities", jsString(manager.Get("identityId")))
	if err != nil {
		return "", err
	}
	if found == nil || found.Get("tenantId") != report.Get("tenantId") || found.Get("status") == "deleted" || found.Get("id") == report.Get("id") {
		return "", nil
	}
	cursor := found
	for depth := 0; cursor != nil && truthy(cursor.Get("managerId")) && depth < 100; depth++ {
		if cursor.Get("managerId") == report.Get("id") {
			return "", nil
		}
		if cursor, err = tx.Get(ctx, "identities", jsString(cursor.Get("managerId"))); err != nil {
			return "", err
		}
	}
	return jsString(found.Get("id")), nil
}

// reportsOf answers the identities of reports whose provisioned `manager.value` resolves to manager, excluding
// protected ones.
func reportsOf(ctx context.Context, tx core.IamStore, users []*core.Object, manager *core.Object) ([]*core.Object, error) {
	var result []*core.Object
	resolve := managerIndex(users)
	for _, row := range users {
		value, ok := managerValue(row.Get("enterprise"))
		if row.Get("id") == manager.Get("id") || !ok {
			continue
		}
		if resolved := resolve(value, row); resolved == nil || resolved.Get("id") != manager.Get("id") {
			continue
		}
		report, err := tx.Get(ctx, "identities", jsString(row.Get("identityId")))
		if err != nil {
			return nil, err
		}
		if report != nil && report.Get("tenantId") == manager.Get("tenantId") && report.Get("status") != "deleted" &&
			!truthy(report.Get("owner")) && !truthy(report.Get("rootAdmin")) {
			result = append(result, report)
		}
	}
	return result, nil
}

// adoptReports back-fills the manager of reports provisioned before manager, unless they already have one.
func (p *provisioning) adoptReports(ctx context.Context, tx core.IamStore, connection *core.Object, users []*core.Object, manager *core.Object) error {
	reports, err := reportsOf(ctx, tx, users, manager)
	if err != nil {
		return err
	}
	for _, report := range reports {
		if truthy(report.Get("managerId")) {
			continue
		}
		managerID, err := assignableManager(ctx, tx, report, manager)
		if err != nil {
			return err
		}
		if managerID == "" {
			continue
		}
		if _, err := tx.Put(ctx, "identities", report.Spread(core.NewObject("managerId", managerID))); err != nil {
			return err
		}
		if err := p.audit(ctx, tx, connection, "iam:scim:UpdateUser", report.Get("id"), ""); err != nil {
			return err
		}
	}
	return nil
}

func (p *provisioning) members(ctx context.Context, tx core.IamStore, connection *core.Object, value any) ([]string, error) {
	list, ok := value.([]any)
	if !ok || len(list) > 1000 {
		return nil, core.NewIamError("invalidValue", "members must contain at most 1000 User references.")
	}
	var result []string
	for _, item := range list {
		data, err := object(item)
		if err != nil {
			return nil, err
		}
		if err := fields(data, "value", "$ref", "display", "type"); err != nil {
			return nil, err
		}
		if kind := data.Get("type"); !core.IsUndefined(kind) && kind != "User" {
			return nil, core.NewIamError("invalidValue", "Nested groups are not supported.")
		}
		id, err := requiredText(data.Get("value"), "member.value")
		if err != nil {
			return nil, err
		}
		user, err := tx.Get(ctx, "scimUsers", id)
		if err != nil {
			return nil, err
		}
		if user == nil || user.Get("connectionId") != connection.Get("id") || user.Get("tenantId") != connection.Get("tenantId") {
			return nil, core.NewIamError("invalidValue", "Member is outside this SCIM connection.")
		}
		if _, err := identity(ctx, tx, user); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return uniqueStrings(result), nil
}

// roleIDsOf is `connection.roleMappings[groupId] ?? []`.
func roleIDsOf(connection *core.Object, groupID string) []string {
	var roleIDs []string
	if list, ok := member(connection.Get("roleMappings"), groupID).([]any); ok {
		for _, item := range list {
			roleIDs = append(roleIDs, jsString(item))
		}
	}
	return roleIDs
}

// syncGroup reconciles local group membership with the SCIM group and applies administrator-configured role
// mappings.
func (p *provisioning) syncGroup(ctx context.Context, tx core.IamStore, connection, link *core.Object, credential *core.CredentialInput) error {
	desired := newOrderedSet()
	memberIDs, _ := link.Get("members").([]any)
	for _, memberID := range memberIDs {
		user, err := tx.Get(ctx, "scimUsers", jsString(memberID))
		if err != nil {
			return err
		}
		if user == nil || user.Get("connectionId") != connection.Get("id") || user.Get("tenantId") != connection.Get("tenantId") {
			continue
		}
		// An identity an administrator deleted never regains memberships, nor the roles mapped to them.
		local, err := tx.Get(ctx, "identities", jsString(user.Get("identityId")))
		if err != nil {
			return err
		}
		if local == nil || local.Get("status") != "deleted" {
			desired.add(jsString(user.Get("identityId")))
		}
	}
	byGroup := core.NewObject("tenantId", connection.Get("tenantId"), "groupId", link.Get("groupId"))
	rows, err := tx.Find(ctx, "groupMembers", byGroup, nil)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if !desired.remove(jsString(row.Get("identityId"))) {
			if err := tx.Delete(ctx, "groupMembers", jsString(row.Get("id"))); err != nil {
				return err
			}
		}
	}
	for _, identityID := range desired.items {
		if _, err := tx.Insert(ctx, "groupMembers", core.NewObject(
			"id", randomUUID(),
			"tenantId", connection.Get("tenantId"),
			"groupId", link.Get("groupId"),
			"identityId", identityID,
			"uniqueKey", jsString(link.Get("groupId"))+":"+identityID,
		)); err != nil {
			return err
		}
	}
	roleIDs := roleIDsOf(connection, jsString(link.Get("id")))
	if len(roleIDs) > 0 && p.config.SyncRoleMappings == nil {
		return core.NewIamError("configuration", "Role mapping callback is missing.")
	}
	if p.config.SyncRoleMappings != nil {
		all, err := tx.Find(ctx, "groupMembers", byGroup, nil)
		if err != nil {
			return err
		}
		identityIDs := make([]string, len(all))
		for index, row := range all {
			identityIDs[index] = jsString(row.Get("identityId"))
		}
		if roleIDs == nil {
			roleIDs = []string{}
		}
		return p.config.SyncRoleMappings(ctx, tx, RoleMappingInput{
			TenantID:     jsString(connection.Get("tenantId")),
			ConnectionID: jsString(connection.Get("id")),
			GroupID:      jsString(link.Get("groupId")),
			IdentityIDs:  identityIDs,
			RoleIDs:      roleIDs,
			Credential:   credential,
		})
	}
	return nil
}

func validateEmails(emails any) error {
	if core.IsUndefined(emails) {
		return nil
	}
	list, ok := emails.([]any)
	if !ok || len(list) > 20 {
		return core.NewIamError("invalidValue", "emails must contain at most 20 email values.")
	}
	for _, entry := range list {
		email, err := object(entry)
		if err != nil {
			return err
		}
		if err := fields(email, "value", "type", "primary", "display"); err != nil {
			return err
		}
		value, err := requiredText(email.Get("value"), "email")
		if err != nil {
			return err
		}
		if utf16Len(value) > 320 || !emailShaped(value, true) {
			return core.NewIamError("invalidValue", "Invalid email address.")
		}
		if primary := email.Get("primary"); !core.IsUndefined(primary) {
			if _, isBool := primary.(bool); !isBool {
				return core.NewIamError("invalidValue", "email.primary must be a boolean.")
			}
		}
	}
	primaries := 0
	for _, entry := range list {
		if entry.(*core.Object).Get("primary") == true {
			primaries++
		}
	}
	if primaries > 1 {
		return core.NewIamError("invalidValue", "Only one primary email is allowed.")
	}
	return nil
}

// nextVersion is `(existing?.version ?? 0) + 1`.
func nextVersion(existing *core.Object) any {
	if existing == nil {
		return 1.0
	}
	switch version := existing.Get("version").(type) {
	case nil, core.UndefinedType:
		return 1.0
	case float64:
		return version + 1
	case string:
		return version + "1"
	case bool:
		if version {
			return 2.0
		}
		return 1.0
	default:
		return jsString(version) + "1"
	}
}

// coalesceValue is `value ?? fallback`.
func coalesceValue(value any, fallback any) any {
	if nullish(value) {
		return fallback
	}
	return value
}

func optionalValue(value *string) any {
	if value == nil {
		return core.Undefined
	}
	return *value
}

func (p *provisioning) saveUser(ctx context.Context, tx core.IamStore, connection, body, existing *core.Object) (*core.Object, error) {
	data := withoutIgnored(body, "Users", p.lenient)
	if err := fields(data, "schemas", "userName", "displayName", "externalId", "active", "emails", "name", "title", EnterpriseSchema); err != nil {
		return nil, err
	}
	if schemas := data.Get("schemas"); !core.IsUndefined(schemas) {
		list, ok := schemas.([]any)
		unsupported := !ok
		for _, schema := range list {
			if schema != UserSchema && schema != EnterpriseSchema {
				unsupported = true
			}
		}
		if unsupported {
			return nil, core.NewIamError("invalidValue", "Unsupported User schema.")
		}
	}
	userName, err := requiredText(data.Get("userName"), "userName")
	if err != nil {
		return nil, err
	}
	displayNameValue, err := text(data.Get("displayName"), "displayName", true)
	if err != nil {
		return nil, err
	}
	displayName := userName
	if displayNameValue != nil {
		displayName = *displayNameValue
	}
	externalID, err := text(data.Get("externalId"), "externalId", true)
	if err != nil {
		return nil, err
	}
	active, err := boolean(data.Get("active"), true)
	if err != nil {
		return nil, err
	}
	title, err := text(data.Get("title"), "title", true)
	if err != nil {
		return nil, err
	}
	var enterprise *core.Object
	if extension := data.Get(EnterpriseSchema); !core.IsUndefined(extension) {
		source, err := object(extension)
		if err != nil {
			return nil, err
		}
		enterprise = source.Spread()
		if err := fields(enterprise, "employeeNumber", "costCenter", "organization", "division", "department", "manager"); err != nil {
			return nil, err
		}
		// Entra ID adds the manager as a bare ID (`path: "…:manager", value: "<id>"`).
		if manager, ok := enterprise.Get("manager").(string); ok {
			enterprise.Set("manager", core.NewObject("value", manager))
		}
		for _, field := range enterprise.Keys() {
			value := enterprise.Get(field)
			if field == "manager" {
				manager, err := object(value)
				if err != nil {
					return nil, err
				}
				if err := fields(manager, "value", "displayName", "$ref"); err != nil {
					return nil, err
				}
				for _, key := range manager.Keys() {
					if _, err := text(manager.Get(key), "manager."+key, true); err != nil {
						return nil, err
					}
				}
			} else if _, err := text(value, field, true); err != nil {
				return nil, err
			}
		}
	}
	normalized := core.JSLower(userName)
	rows, err := tx.Find(ctx, "scimUsers", core.NewObject("tenantId", connection.Get("tenantId"), "connectionId", connection.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	var others []*core.Object
	for _, row := range rows {
		if existing == nil || row.Get("id") != existing.Get("id") {
			others = append(others, row)
		}
	}
	for _, row := range others {
		if core.JSLower(jsString(row.Get("userName"))) == normalized {
			return nil, core.NewIamError("uniqueness", "userName already exists.", 409)
		}
	}
	// Provisioning never implicitly takes over an account based on email or name.
	var record *core.Object
	if existing != nil {
		if record, err = updatable(ctx, tx, existing); err != nil {
			return nil, err
		}
	} else {
		status := "disabled"
		if active {
			status = "active"
		}
		record = core.NewObject(
			"id", randomUUID(),
			"tenantId", connection.Get("tenantId"),
			"kind", "user",
			"name", displayName,
			"status", status,
			"emailVerified", false,
			"rootAdmin", false,
			"owner", false,
			"createdAt", p.config.now(),
		)
	}
	var previousStatus any = core.Undefined
	if existing != nil {
		previousStatus = record.Get("status")
	}
	emails := data.Get("emails")
	if err := validateEmails(emails); err != nil {
		return nil, err
	}
	var name *core.Object
	if value := data.Get("name"); !core.IsUndefined(value) {
		if name, err = object(value); err != nil {
			return nil, err
		}
		if err := fields(name, "formatted", "familyName", "givenName", "middleName", "honorificPrefix", "honorificSuffix"); err != nil {
			return nil, err
		}
		for _, field := range name.Keys() {
			if _, err := requiredText(name.Get(field), "name."+field); err != nil {
				return nil, err
			}
		}
	}
	addressChanged := false
	var primaryEmail any = core.Undefined
	emailList, _ := emails.([]any)
	if emails != nil && !core.IsUndefined(emails) {
		for _, entry := range emailList {
			if entry.(*core.Object).Get("primary") == true {
				primaryEmail = entry
				break
			}
		}
		if core.IsUndefined(primaryEmail) && len(emailList) > 0 {
			primaryEmail = emailList[0]
		}
	}
	email := ""
	if truthy(primaryEmail) {
		value, err := requiredText(primaryEmail.(*core.Object).Get("value"), "email")
		if err != nil {
			return nil, err
		}
		email = core.JSLower(value)
	} else if emailShaped(userName, false) {
		email = normalized
	}
	if email != "" {
		matches, err := tx.Find(ctx, "identities", core.NewObject("tenantId", connection.Get("tenantId"), "email", email), nil)
		if err != nil {
			return nil, err
		}
		for _, row := range matches {
			if row.Get("id") != record.Get("id") {
				return nil, core.NewIamError("uniqueness", "Email belongs to an existing identity; automatic linking is disabled.", 409)
			}
		}
		// A new sign-in address ends what the old one opened, as an administrator's email change does.
		current := record.Get("email")
		if existing != nil && !core.IsUndefined(current) && current != email {
			addressChanged = true
		}
		if current != email {
			record.Set("emailVerified", false)
		}
		record.Set("email", email)
		record.Set("uniqueKey", "email:"+email)
	}
	record.Set("name", displayName)
	// SCIM owns `active` only when the IdP changes it: an update that leaves it alone never re-enables someone an
	// administrator disabled, and the IdP re-enables only an identity it disabled itself.
	switch {
	case existing == nil:
		if active {
			record.Set("status", "active")
		} else {
			record.Set("status", "disabled")
		}
	case !active:
		record.Set("status", "disabled")
	case existing.Get("active") == false && record.Get("status") == "disabled":
		record.Set("status", "active")
	}
	if p.config.MapAttributes != nil {
		mapped := p.config.MapAttributes(ProvisionedUser{
			UserName: userName, DisplayName: displayName, ExternalID: externalID, Active: active, Title: title,
			Enterprise: enterprise, Emails: emailList, Name: name,
		})
		if mapped != nil {
			if p.config.ValidateIdentityAttributes != nil {
				if mapped, err = p.config.ValidateIdentityAttributes(mapped); err != nil {
					return nil, err
				}
			}
			record.Set("attributes", mapped)
		}
	}
	now := p.config.now()
	linkID := any(randomUUID())
	createdAt := any(now)
	if existing != nil {
		linkID = coalesceValue(existing.Get("id"), linkID)
		createdAt = coalesceValue(existing.Get("createdAt"), now)
	}
	var nameValue any = core.Undefined
	if name != nil {
		nameValue = name
	}
	link := core.NewObject()
	link.SetRaw("id", linkID)
	link.SetRaw("tenantId", connection.Get("tenantId"))
	link.SetRaw("connectionId", connection.Get("id"))
	link.SetRaw("identityId", record.Get("id"))
	link.SetRaw("uniqueKey", hash(jsString(connection.Get("id"))+":"+normalized))
	link.SetRaw("userName", userName)
	link.SetRaw("displayName", displayName)
	link.SetRaw("externalId", optionalValue(externalID))
	link.SetRaw("active", active)
	link.SetRaw("emails", emails)
	link.SetRaw("name", nameValue)
	link.SetRaw("version", nextVersion(existing))
	link.SetRaw("createdAt", createdAt)
	link.SetRaw("updatedAt", now)
	if title != nil {
		link.SetRaw("title", *title)
	}
	if enterprise != nil {
		link.SetRaw("enterprise", enterprise)
	}
	value, hasValue := managerValue(optionalObject(enterprise))
	var previousEnterprise any = core.Undefined
	if existing != nil {
		previousEnterprise = existing.Get("enterprise")
	}
	previous, hasPrevious := managerValue(previousEnterprise)
	if p.mapManager() && (hasValue || hasPrevious) {
		// References resolve over all of the connection's users: the others plus this one as saved or as it was.
		resolve := managerIndex(others)
		// SCIM owns the manager only while its previous reference still names it; admin-set managers stay.
		owned := false
		if hasPrevious && !core.IsUndefined(record.Get("managerId")) {
			if resolved := resolve(previous, existing); resolved != nil && resolved.Get("identityId") == record.Get("managerId") {
				owned = true
			}
		}
		managerID := ""
		if hasValue {
			// A user naming themself resolves to themself, which assignableManager skips.
			if manager := resolve(value, link); manager != nil {
				if managerID, err = assignableManager(ctx, tx, record, manager); err != nil {
					return nil, err
				}
			}
		}
		// A manager not provisioned yet is back-filled later; a SCIM-set one the IdP stopped naming is cleared.
		if managerID != "" {
			record.Set("managerId", managerID)
		} else if owned && (!hasValue || value != previous) {
			record.Delete("managerId")
		}
	}
	if existing != nil {
		if _, err := tx.Put(ctx, "identities", record); err != nil {
			return nil, err
		}
	} else {
		if err := withinLimit(ctx, tx, connection.Get("tenantId"), "identities"); err != nil {
			return nil, err
		}
		if _, err := tx.Insert(ctx, "identities", record); err != nil {
			return nil, err
		}
	}
	if record.Get("status") != "active" || addressChanged {
		if err := revokeSessions(ctx, tx, record.Get("id")); err != nil {
			return nil, err
		}
	}
	// A deactivation or reactivation moves what follows the status (license seats) at once; new users hold nothing.
	if existing != nil && !strictEqual(record.Get("status"), previousStatus) && p.config.IdentityStatusChanged != nil {
		if err := p.config.IdentityStatusChanged(ctx, tx, IdentityStatusChange{
			TenantID: jsString(connection.Get("tenantId")), ConnectionID: jsString(connection.Get("id")), IdentityID: jsString(record.Get("id")),
		}); err != nil {
			return nil, err
		}
	}
	if existing != nil {
		if _, err := tx.Put(ctx, "scimUsers", link); err != nil {
			return nil, err
		}
	} else if _, err := tx.Insert(ctx, "scimUsers", link); err != nil {
		return nil, err
	}
	action := "iam:scim:CreateUser"
	if existing != nil {
		action = "iam:scim:UpdateUser"
	}
	if err := p.audit(ctx, tx, connection, action, record.Get("id"), ""); err != nil {
		return nil, err
	}
	if p.mapManager() {
		if err := p.adoptReports(ctx, tx, connection, append(append([]*core.Object{}, others...), link), link); err != nil {
			return nil, err
		}
	}
	return link, nil
}

// optionalObject is an object or undefined.
func optionalObject(value *core.Object) any {
	if value == nil {
		return core.Undefined
	}
	return value
}

func (p *provisioning) saveGroup(ctx context.Context, tx core.IamStore, connection, body, existing *core.Object) (*core.Object, error) {
	data := withoutIgnored(body, "Groups", p.lenient)
	if err := fields(data, "schemas", "displayName", "externalId", "members"); err != nil {
		return nil, err
	}
	if schemas := data.Get("schemas"); !core.IsUndefined(schemas) {
		list, ok := schemas.([]any)
		unsupported := !ok
		for _, schema := range list {
			if schema != GroupSchema {
				unsupported = true
			}
		}
		if unsupported {
			return nil, core.NewIamError("invalidValue", "Unsupported Group schema.")
		}
	}
	displayName, err := requiredText(data.Get("displayName"), "displayName")
	if err != nil {
		return nil, err
	}
	externalID, err := text(data.Get("externalId"), "externalId", true)
	if err != nil {
		return nil, err
	}
	memberIDs, err := p.members(ctx, tx, connection, coalesceValue(data.Get("members"), []any{}))
	if err != nil {
		return nil, err
	}
	now := p.config.now()
	linkID, groupID, createdAt := any(randomUUID()), any(nil), any(now)
	if existing != nil {
		linkID = coalesceValue(existing.Get("id"), linkID)
		groupID = existing.Get("groupId")
		createdAt = coalesceValue(existing.Get("createdAt"), now)
	}
	if nullish(groupID) {
		groupID = randomUUID()
	}
	link := core.NewObject()
	link.SetRaw("id", linkID)
	link.SetRaw("tenantId", connection.Get("tenantId"))
	link.SetRaw("connectionId", connection.Get("id"))
	link.SetRaw("groupId", groupID)
	link.SetRaw("displayName", displayName)
	link.SetRaw("externalId", optionalValue(externalID))
	link.SetRaw("members", stringList(memberIDs))
	link.SetRaw("version", nextVersion(existing))
	link.SetRaw("createdAt", createdAt)
	link.SetRaw("updatedAt", now)
	if existing != nil {
		current, err := tx.Get(ctx, "groups", jsString(groupID))
		if err != nil {
			return nil, err
		}
		group := core.NewObject()
		if current != nil {
			group = current.Spread()
		}
		group.Set("id", groupID).Set("tenantId", link.Get("tenantId")).Set("name", displayName)
		if _, err := tx.Put(ctx, "groups", group); err != nil {
			return nil, err
		}
	} else {
		if err := withinLimit(ctx, tx, connection.Get("tenantId"), "groups"); err != nil {
			return nil, err
		}
		if _, err := tx.Insert(ctx, "groups", core.NewObject("id", groupID, "tenantId", link.Get("tenantId"), "name", displayName, "createdAt", now)); err != nil {
			return nil, err
		}
	}
	if existing != nil {
		if _, err := tx.Put(ctx, "scimGroups", link); err != nil {
			return nil, err
		}
	} else if _, err := tx.Insert(ctx, "scimGroups", link); err != nil {
		return nil, err
	}
	if err := p.syncGroup(ctx, tx, connection, link, nil); err != nil {
		return nil, err
	}
	action := "iam:scim:CreateGroup"
	if existing != nil {
		action = "iam:scim:UpdateGroup"
	}
	if err := p.audit(ctx, tx, connection, action, link.Get("groupId"), ""); err != nil {
		return nil, err
	}
	return link, nil
}

// patch applies a PatchOp to a materialized resource and saves it through the same validation as PUT.
func (p *provisioning) patch(ctx context.Context, tx core.IamStore, connection *core.Object, resourceType ResourceType, row, input *core.Object) (*core.Object, error) {
	if err := fields(input, "schemas", "Operations"); err != nil {
		return nil, err
	}
	schemas, schemasOK := input.Get("schemas").([]any)
	operations, operationsOK := input.Get("Operations").([]any)
	if !schemasOK || len(schemas) != 1 || schemas[0] != PatchSchema || !operationsOK || len(operations) == 0 || len(operations) > 100 {
		return nil, core.NewIamError("invalidSyntax", "PATCH requires the PatchOp schema and 1–100 operations.")
	}
	// Cloned so a failed operation never mutates the stored row; every writable attribute round-trips.
	var data *core.Object
	if resourceType == "Users" {
		data = core.NewObject()
		for _, key := range []string{"userName", "displayName", "externalId", "active", "emails", "name", "title"} {
			data.SetRaw(key, core.CloneValue(row.Get(key)))
		}
		if enterprise := row.Get("enterprise"); truthy(enterprise) {
			data.SetRaw(EnterpriseSchema, core.CloneValue(enterprise))
		}
	} else {
		values, ok := row.Get("members").([]any)
		if !ok {
			return nil, typeError("row.members.map is not a function")
		}
		members := make([]any, len(values))
		for index, value := range values {
			members[index] = core.NewObject().SetRaw("value", core.CloneValue(value))
		}
		data = core.NewObject()
		data.SetRaw("displayName", core.CloneValue(row.Get("displayName")))
		data.SetRaw("externalId", core.CloneValue(row.Get("externalId")))
		data.SetRaw("members", members)
	}
	for _, item := range operations {
		op, err := object(item)
		if err != nil {
			return nil, err
		}
		if err := fields(op, "op", "path", "value"); err != nil {
			return nil, err
		}
		operation := ""
		if name, ok := op.Get("op").(string); ok {
			operation = core.JSLower(name)
		}
		if operation != "add" && operation != "replace" && operation != "remove" {
			return nil, core.NewIamError("invalidSyntax", "Unsupported PATCH operation.")
		}
		var path *string
		if raw := op.Get("path"); !core.IsUndefined(raw) {
			if path, err = text(raw, "path"); err != nil {
				return nil, err
			}
		}
		if err := applyPatchOperation(data, resourceType, operation, path, op.Get("value"), func(name string, explicitPath bool) bool {
			return ignoredAttribute(name, resourceType, p.lenient, !explicitPath)
		}); err != nil {
			return nil, err
		}
	}
	for _, key := range data.Keys() {
		if core.IsUndefined(data.Get(key)) {
			data.Delete(key)
		}
	}
	if extension := data.Get(EnterpriseSchema); resourceType == "Users" && !core.IsUndefined(extension) {
		record, err := object(extension)
		if err != nil {
			return nil, err
		}
		if record.Len() == 0 {
			data.Delete(EnterpriseSchema)
		}
	}
	if resourceType == "Users" {
		return p.saveUser(ctx, tx, connection, data, row)
	}
	return p.saveGroup(ctx, tx, connection, data, row)
}

// deleteUser deactivates the local identity and removes the user from every SCIM group of the connection. Reports
// whose manager SCIM set from this user lose it (it is back-filled if the user is provisioned again). An identity an
// administrator deleted stays a tombstone; deletion already revoked its sessions and released its reports.
func (p *provisioning) deleteUser(ctx context.Context, tx core.IamStore, connection, row *core.Object) error {
	local, err := identity(ctx, tx, row)
	if err != nil {
		return err
	}
	status := local.Get("status")
	if status != "deleted" {
		if _, err := tx.Put(ctx, "identities", local.Spread(core.NewObject("status", "disabled"))); err != nil {
			return err
		}
		if err := revokeSessions(ctx, tx, local.Get("id")); err != nil {
			return err
		}
	}
	byConnection := core.NewObject("tenantId", connection.Get("tenantId"), "connectionId", connection.Get("id"))
	if p.mapManager() && status != "deleted" {
		users, err := tx.Find(ctx, "scimUsers", byConnection, nil)
		if err != nil {
			return err
		}
		reports, err := reportsOf(ctx, tx, users, row)
		if err != nil {
			return err
		}
		for _, report := range reports {
			if report.Get("managerId") != local.Get("id") {
				continue
			}
			rest := report.Spread()
			rest.Delete("managerId")
			if _, err := tx.Put(ctx, "identities", rest); err != nil {
				return err
			}
			if err := p.audit(ctx, tx, connection, "iam:scim:UpdateUser", report.Get("id"), ""); err != nil {
				return err
			}
		}
	}
	groups, err := tx.Find(ctx, "scimGroups", byConnection, nil)
	if err != nil {
		return err
	}
	for _, group := range groups {
		members, _ := group.Get("members").([]any)
		found := false
		kept := make([]any, 0, len(members))
		for _, id := range members {
			if strictEqual(id, row.Get("id")) {
				found = true
			} else {
				kept = append(kept, id)
			}
		}
		if !found {
			continue
		}
		group.Set("members", kept)
		group.Set("version", jsNumber(group.Get("version"))+1)
		group.Set("updatedAt", p.config.now())
		if _, err := tx.Put(ctx, "scimGroups", group); err != nil {
			return err
		}
		if err := p.syncGroup(ctx, tx, connection, group, nil); err != nil {
			return err
		}
	}
	// Seats held through a direct assignment go with the deactivation too, not only those of the SCIM groups.
	if status == "active" && p.config.IdentityStatusChanged != nil {
		return p.config.IdentityStatusChanged(ctx, tx, IdentityStatusChange{
			TenantID: jsString(connection.Get("tenantId")), ConnectionID: jsString(connection.Get("id")), IdentityID: jsString(local.Get("id")),
		})
	}
	return nil
}

func (p *provisioning) deleteGroup(ctx context.Context, tx core.IamStore, connection, row *core.Object) error {
	row.Set("members", []any{})
	if err := p.syncGroup(ctx, tx, connection, row, nil); err != nil {
		return err
	}
	if err := deleteAll(ctx, tx, "bindings", core.NewObject(
		"tenantId", connection.Get("tenantId"),
		"subjectType", "group",
		"subjectId", row.Get("groupId"),
		"scimConnectionId", connection.Get("id"),
	)); err != nil {
		return err
	}
	// What the server gave the group (license assignments) must not outlive its record.
	if p.config.GroupDeleted != nil {
		if err := p.config.GroupDeleted(ctx, tx, GroupDeletion{
			TenantID: jsString(connection.Get("tenantId")), ConnectionID: jsString(connection.Get("id")), GroupID: jsString(row.Get("groupId")),
		}); err != nil {
			return err
		}
	}
	return tx.Delete(ctx, "groups", jsString(row.Get("groupId")))
}
