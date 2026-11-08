package server

// Port of packages/server/src/api/packages.ts: access packages, bundles of roles and groups granted together by one
// assignment (manually, through self-service requests and approvals, or automatically by a package rule), with
// shared-membership hand-over, retiming, and the request workflow. Actions `iam:packages:*` on `iam/{packageId}` and
// `iam/{tenantId}`.

import (
	"context"
	"math"
	"slices"
	"strconv"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// PackagesAPI is the `packages` API group (packages/server/src/api/packages.ts createPackagesApi): every method runs through the
// operation envelope; the router maps POST {basePath}/packages/{method} onto it.
type PackagesAPI struct {
	server *ServerContext
}

// CreatePackagesAPI builds the `packages` API group.
func CreatePackagesAPI(server *ServerContext) *PackagesAPI {
	return &PackagesAPI{server: server}
}

const packageMaxContents = 50
const packageTenYears = 315360000000

var packageRequestStatuses = newOrderedSet("pending", "approved", "denied", "cancelled", "expired")

// packageNameKey is the unique key of a package name: `name:` and the trimmed, lowercased name.
func packageNameKey(name string) string { return "name:" + core.JSLower(core.JSTrim(name)) }

// packageByName orders by name (`a.name.localeCompare(b.name, 'en')`).
func packageByName(a, b *core.Object) int {
	return localeCompare(jsString(a.Get("name")), jsString(b.Get("name")))
}

// packageSameIDs is sameIds: the same members, ignoring order (a has no duplicates).
func packageSameIDs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	return newOrderedSet(append(append([]string(nil), a...), b...)...).Len() == newOrderedSet(a...).Len()
}

// packageBoolean (api/packages.ts boolean) requires a boolean.
func packageBoolean(value any, name string) (bool, error) {
	flag, ok := value.(bool)
	if !ok {
		return false, invalidInput(name + " must be boolean")
	}
	return flag, nil
}

// packageText is a string member, "" for anything else.
func packageText(value any) string {
	text, _ := value.(string)
	return text
}

// packageFirst is `(await tx.find(...))[0]`.
func packageFirst(ctx context.Context, tx core.IamStore, collection string, filter *core.Object) (*core.Object, error) {
	records, err := tx.Find(ctx, collection, filter, nil)
	if err != nil || len(records) == 0 {
		return nil, err
	}
	return records[0], nil
}

// LiveAssignment (api/packages.ts liveAssignment): Whether an assignment still applies; an ended one grants nothing
// and waits for the purge worker.
func LiveAssignment(server *ServerContext, assignment *core.Object) (result bool, err error) {
	return liveAssignment(server, assignment), nil
}

func liveAssignment(server *ServerContext, assignment *core.Object) bool {
	expiresAt := assignment.Get("expiresAt")
	return isUndefined(expiresAt) || jsNumber(expiresAt) > float64(server.Now())
}

// pendingRequest (api/packages.ts pendingRequest): a request that still waits for a decision.
func pendingRequest(request *core.Object, now float64) bool {
	return request.Get("status") == "pending" && jsNumber(request.Get("expiresAt")) > now
}

// EndOf (api/packages.ts endOf): Ends compare with "no end" last.
func EndOf(expiresAt *float64) (result float64, err error) {
	if expiresAt == nil {
		return math.Inf(1), nil
	}
	return *expiresAt, nil
}

// endOf is EndOf over a record member (a number, or undefined for no end).
func endOf(expiresAt any) float64 {
	if nullish(expiresAt) {
		return math.Inf(1)
	}
	return jsNumber(expiresAt)
}

// packageEndPointer is a number-or-undefined end as RetimeAssignment takes it.
func packageEndPointer(end any) *float64 {
	if value, ok := end.(float64); ok {
		return &value
	}
	return nil
}

// packageContents (api/packages.ts contents): the roles and groups a package bundles must exist in the tenant, and
// protected roles are never packaged.
func packageContents(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, roleIDs, groupIDs []string) error {
	if len(roleIDs) > packageMaxContents || len(groupIDs) > packageMaxContents {
		return invalidInput("A package holds at most " + strconv.Itoa(packageMaxContents) + " roles and " + strconv.Itoa(packageMaxContents) + " groups")
	}
	if len(roleIDs) == 0 && len(groupIDs) == 0 {
		return invalidInput("A package needs at least one role or group")
	}
	for _, roleID := range roleIDs {
		role, err := server.Scoped(ctx, tx, "roles", roleID, tenantID)
		if err != nil {
			return err
		}
		if truthy(role.Get("protected")) {
			return core.NewIamError("PROTECTED_RESOURCE", "Protected roles cannot be packaged", 403)
		}
	}
	// A team's backing group takes its members from the team only (teams.ts).
	for _, groupID := range groupIDs {
		group, err := server.Scoped(ctx, tx, "groups", groupID, tenantID)
		if err != nil {
			return err
		}
		if err := AssertNotTeamGroup(group); err != nil {
			return err
		}
	}
	return nil
}

// packageWithName (api/packages.ts packageByName) is the tenant's package with this name.
func packageWithName(ctx context.Context, tx core.IamStore, tenantID string, name string) (*core.Object, error) {
	return packageFirst(ctx, tx, "accessPackages", core.NewObject("tenantId", tenantID, "uniqueKey", packageNameKey(name)))
}

// Allow (api/packages.ts allow): Every part of an assignment is authorized like the direct call, so a package never
// widens what its assigner may grant.
func Allow(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string, action string, resourceID string, what string) (err error) {
	decision, err := server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
		TenantID: tenantID, Action: action, Resource: ResourceTarget{Type: "iam", ID: resourceID},
	}, true)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return core.NewIamError("ACCESS_DENIED", "Not allowed to "+what+" ("+action+")", 403)
	}
	return nil
}

// AuthorizePackage (api/packages.ts authorizePackage): The rights assigning a package by hand needs:
// iam:bindings:create on each role and iam:groups:update on each group, and (with `groupAuthorities`) the use of
// every grant authority behind the groups' own bindings, which membership confers. A packaged group that carries
// license seats (a product is assigned to it, or to a team it syncs into) needs iam:licenses:assign too, refused
// with `OperationDenied` (api/groups.ts): so assigning or approving the package, lengthening an assignment,
// confirming a rule's held-back changes, and saving or running a rule (its owner; `ruleHealth` suspends the rule's
// additions in advance) all need it. Returns the caller's grant authority when the package has roles (or
// `requireAuthority`). Callers outside a transaction must pass `authorityId`: the root path of grantingAuthority
// writes a record. options (nil: none) are `{ groupAuthorities?, authorityId?, requireAuthority? }`; the result is
// nil when no authority is needed.
func AuthorizePackage(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, pkg *core.Object, options *core.Object) (result *core.Object, err error) {
	tenantID := packageText(pkg.Get("tenantId"))
	roleIDs := flowStrings(pkg.Get("roleIds"))
	for _, roleID := range roleIDs {
		if err := Allow(ctx, server, tx, principal, tenantID, "iam:bindings:create", roleID, "grant a packaged role"); err != nil {
			return nil, err
		}
	}
	groupIDs := flowStrings(pkg.Get("groupIds"))
	for _, groupID := range groupIDs {
		if err := Allow(ctx, server, tx, principal, tenantID, "iam:groups:update", groupID, "add to a packaged group"); err != nil {
			return nil, err
		}
		if truthy(options.Get("groupAuthorities")) {
			bindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", groupID), nil)
			if err != nil {
				return nil, err
			}
			for _, binding := range bindings {
				if _, err := server.GrantingAuthority(ctx, tx, principal, tenantID, packageText(binding.Get("authorityId"))); err != nil {
					return nil, err
				}
			}
		}
	}
	if err := AssertMayClaimLicenses(ctx, server, tx, principal, tenantID, groupIDs,
		"A group this package includes carries license seats; granting it needs iam:licenses:assign"); err != nil {
		return nil, err
	}
	authorityID := options.Get("authorityId")
	if len(roleIDs) == 0 && !truthy(options.Get("requireAuthority")) && !truthy(authorityID) {
		return nil, nil
	}
	return server.GrantingAuthority(ctx, tx, principal, tenantID, packageText(authorityID))
}

// RuleEnvironment (api/packages.ts ruleEnvironment): What a rule of this package may name: the deployment's declared
// attributes and the tenant's groups, teams, and departments. The result is `{ identityAttributes, groups,
// packagedGroups, org }`, the sets as lists of distinct IDs.
func RuleEnvironment(ctx context.Context, server *ServerContext, reader core.IamStore, pkg *core.Object) (result *core.Object, err error) {
	tenantID := packageText(pkg.Get("tenantId"))
	groups, err := reader.Find(ctx, "groups", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	groupIDs := newOrderedSet()
	for _, group := range groups {
		groupIDs.Add(jsString(group.Get("id")))
	}
	org, err := OrgRuleEnvironment(ctx, reader, tenantID)
	if err != nil {
		return nil, err
	}
	var attributes any = core.Undefined
	if server.Catalog != nil {
		attributes = server.Catalog.IdentityAttributes
	}
	return core.NewObject(
		"identityAttributes", attributes,
		"groups", stringsOf(groupIDs.Values()),
		"packagedGroups", stringsOf(unique(flowStrings(pkg.Get("groupIds")))),
		"org", org,
	), nil
}

// authorRule (api/packages.ts authorRule): the owner checks of a rule: an ordinary session or API key (never a role
// session, session token or impersonation), iam:packages:assign on the package, the rights assigning by hand needs
// including the groups' authorities, and a grant authority. The same owner re-saving keeps their authority when it is
// still usable, to avoid re-issuing every binding. The result is `{ ownerId, authorityId }`.
func authorRule(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, pkg *core.Object, previous *core.Object) (*core.Object, error) {
	if !ActsInOwnRight(principal.Session) {
		return nil, invalidInput("Package rules are set from an ordinary session or API key of the tenant")
	}
	if truthy(principal.Session.Get("impersonatorId")) {
		return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "Package rules cannot be set while impersonating", 403)
	}
	tenantID := packageText(pkg.Get("tenantId"))
	if err := Allow(ctx, server, tx, principal, tenantID, "iam:packages:assign", jsString(pkg.Get("id")), "assign this package automatically"); err != nil {
		return nil, err
	}
	var keep any = core.Undefined
	if previous != nil && core.StrictEquals(previous.Get("ownerId"), principal.Identity.Get("id")) {
		keep = previous.Get("authorityId")
	}
	if truthy(keep) {
		if _, err := server.GrantingAuthority(ctx, tx, principal, tenantID, packageText(keep)); err != nil {
			keep = core.Undefined
		}
	}
	options := core.NewObject("groupAuthorities", true, "requireAuthority", true)
	if truthy(keep) {
		options.Set("authorityId", keep)
	}
	authority, err := AuthorizePackage(ctx, server, tx, principal, pkg, options)
	if err != nil {
		return nil, err
	}
	return core.NewObject("ownerId", principal.Identity.Get("id"), "authorityId", member(authority, "id")), nil
}

// packageRuleMetadata (api/packages.ts applyRuleChange ruleMetadata) is the audit metadata of a stored rule.
func packageRuleMetadata(rule *core.Object) *core.Object {
	metadata := core.NewObject(
		"revision", rule.Get("revision"),
		"ownerId", rule.Get("ownerId"),
		"authorityId", rule.Get("authorityId"),
		"include", rule.Get("include"),
	)
	if truthy(rule.Get("exclude")) {
		metadata.Set("exclude", rule.Get("exclude"))
	}
	for _, key := range []string{"graceMs", "maxGrants", "maxRemovals"} {
		if value := rule.Get(key); !isUndefined(value) {
			metadata.Set(key, value)
		}
	}
	return metadata
}

// applyRuleChange (api/packages.ts applyRuleChange): sets, changes, takes over, or clears a package's rule while the
// package is created or updated. Changing a rule package's roles or groups re-authorizes the editor, who becomes the
// owner: someone holding only iam:packages:update cannot add a role that is then granted under another
// administrator's authority. input is the autoAssign value (undefined: unchanged, null: clear).
func applyRuleChange(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, previous *core.Object, next *core.Object, input any, keep bool) error {
	old, _ := member(previous, "autoAssign").(*core.Object)
	contentsChanged := false
	if previous != nil {
		contentsChanged = !packageSameIDs(flowStrings(previous.Get("roleIds")), flowStrings(next.Get("roleIds"))) ||
			!packageSameIDs(flowStrings(previous.Get("groupIds")), flowStrings(next.Get("groupIds")))
	}
	requirePrincipal := func() (*Principal, error) {
		if principal == nil {
			return nil, invalidInput("A principal is required to change a package rule")
		}
		return principal, nil
	}
	tenantID := packageText(next.Get("tenantId"))
	audit := func(change string, metadata *core.Object) error {
		caller, err := requirePrincipal()
		if err != nil {
			return err
		}
		return server.Events.Audit(ctx, tx, caller, "package:auto-rule", tenantID, jsString(next.Get("id")), "allow", false,
			core.NewObject("packageId", next.Get("id"), "packageName", next.Get("name"), "change", change).Assign(metadata))
	}
	switch {
	case input == nil:
		if old == nil {
			if keep {
				return invalidInput("keepAutomaticAssignments needs a rule to clear")
			}
		} else {
			caller, err := requirePrincipal()
			if err != nil {
				return err
			}
			if err := Allow(ctx, server, tx, caller, tenantID, "iam:packages:assign", jsString(next.Get("id")), "stop assigning this package automatically"); err != nil {
				return err
			}
			next.Delete("autoAssign")
			kept := 0
			if keep {
				assignments, err := packageAssignments(ctx, server, tx, next, false)
				if err != nil {
					return err
				}
				var automatic []*core.Object
				for _, assignment := range assignments {
					if !isUndefined(assignment.Get("ruleRevision")) {
						automatic = append(automatic, assignment)
					}
				}
				if len(automatic) > 5000 {
					return invalidInput("More than 5000 automatic holders; clear the rule without keepAutomaticAssignments")
				}
				for _, assignment := range automatic {
					rest := assignment.Spread()
					rest.Delete("ruleRevision")
					if _, err := tx.Put(ctx, "packageAssignments", rest); err != nil {
						return err
					}
					kept++
				}
			}
			issues, err := tx.Find(ctx, "packageRuleIssues", core.NewObject("tenantId", tenantID, "packageId", next.Get("id")), nil)
			if err != nil {
				return err
			}
			for _, issue := range issues {
				if err := tx.Delete(ctx, "packageRuleIssues", jsString(issue.Get("id"))); err != nil {
					return err
				}
			}
			metadata := core.NewObject("revision", old.Get("revision"), "ownerId", old.Get("ownerId"))
			if keep {
				metadata.Set("kept", kept)
			}
			if err := audit("clear", metadata); err != nil {
				return err
			}
		}
	case keep:
		return invalidInput("keepAutomaticAssignments applies only with autoAssign: null")
	case !isUndefined(input):
		env, err := RuleEnvironment(ctx, server, tx, next)
		if err != nil {
			return err
		}
		parsed, err := ParseAutoAssign(input, env, "autoAssign")
		if err != nil {
			return err
		}
		caller, err := requirePrincipal()
		if err != nil {
			return err
		}
		author, err := authorRule(ctx, server, tx, caller, next, old)
		if err != nil {
			return err
		}
		moved := old != nil && (!core.StrictEquals(author.Get("ownerId"), old.Get("ownerId")) ||
			!core.StrictEquals(author.Get("authorityId"), old.Get("authorityId")))
		revision := 1.0
		if old != nil {
			revision = jsNumber(old.Get("revision"))
			if moved || contentsChanged {
				revision++
			}
		}
		rule := parsed.Spread(author, core.NewObject("revision", revision, "updatedAt", float64(server.Now())))
		next.Set("autoAssign", rule)
		change := "change"
		if old == nil {
			change = "set"
		} else if moved {
			change = "owner"
		}
		metadata := packageRuleMetadata(rule)
		if moved {
			metadata.Set("previousOwnerId", old.Get("ownerId"))
		}
		if err := audit(change, metadata); err != nil {
			return err
		}
	case old != nil && contentsChanged:
		env, err := RuleEnvironment(ctx, server, tx, next)
		if err != nil {
			return err
		}
		problem, err := RuleProblem(old, env)
		if err != nil {
			return err
		}
		if problem != "" {
			return invalidInput("The package rule no longer fits the new contents: " + problem)
		}
		caller, err := requirePrincipal()
		if err != nil {
			return err
		}
		author, err := authorRule(ctx, server, tx, caller, next, old)
		if err != nil {
			return err
		}
		ruleInput, err := RuleInput(old)
		if err != nil {
			return err
		}
		rule := ruleInput.Spread(author, core.NewObject("revision", jsNumber(old.Get("revision"))+1, "updatedAt", float64(server.Now())))
		next.Set("autoAssign", rule)
		metadata := packageRuleMetadata(rule)
		if !core.StrictEquals(author.Get("ownerId"), old.Get("ownerId")) {
			metadata.Set("previousOwnerId", old.Get("ownerId"))
		}
		if err := audit("contents", metadata); err != nil {
			return err
		}
	}
	if truthy(next.Get("autoAssign")) && !isUndefined(next.Get("maxDurationMs")) {
		return invalidInput("A package with an automatic-assignment rule cannot have a maximum duration; use graceMs for a delayed end")
	}
	return nil
}

// CreatePackage (api/packages.ts createPackage): Creates a package; shared by `packages.create` and configuration
// sync. principal may be nil (configuration sync without a rule).
func CreatePackage(ctx context.Context, server *ServerContext, tx core.IamStore, input *core.Object, principal *Principal) (result *core.Object, err error) {
	tenantID := packageText(input.Get("tenantId"))
	name, err := Text(input.Get("name"), "name", 128)
	if err != nil {
		return nil, err
	}
	existing, err := packageWithName(ctx, tx, tenantID, name)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, core.NewIamError("CONFLICT", "A package with this name exists", 409)
	}
	roleIDs := []string{}
	if value := input.Get("roleIds"); !isUndefined(value) {
		list, err := Strings(value, "roleIds")
		if err != nil {
			return nil, err
		}
		roleIDs = unique(list)
	}
	groupIDs := []string{}
	if value := input.Get("groupIds"); !isUndefined(value) {
		list, err := Strings(value, "groupIds")
		if err != nil {
			return nil, err
		}
		groupIDs = unique(list)
	}
	if err := packageContents(ctx, server, tx, tenantID, roleIDs, groupIDs); err != nil {
		return nil, err
	}
	now := float64(server.Now())
	record := core.NewObject(
		"id", ID(),
		"tenantId", tenantID,
		"uniqueKey", packageNameKey(name),
		"name", name,
		"roleIds", stringsOf(roleIDs),
		"groupIds", stringsOf(groupIDs),
		"createdAt", now,
		"updatedAt", now,
	)
	if value := input.Get("description"); !isUndefined(value) {
		description, err := Text(value, "description", 512)
		if err != nil {
			return nil, err
		}
		record.Set("description", description)
	}
	if value := input.Get("maxDurationMs"); !isUndefined(value) {
		maxDuration, err := Integer(value, "maxDurationMs", 60_000, packageTenYears)
		if err != nil {
			return nil, err
		}
		record.Set("maxDurationMs", maxDuration)
	}
	for _, flag := range []string{"requireJustification", "requestable"} {
		if value := input.Get(flag); !isUndefined(value) {
			set, err := packageBoolean(value, flag)
			if err != nil {
				return nil, err
			}
			if set {
				record.Set(flag, true)
			}
		}
	}
	if value := input.Get("approverGroupId"); !nullish(value) {
		if _, err := server.Scoped(ctx, tx, "groups", value, tenantID); err != nil {
			return nil, err
		}
		record.Set("approverGroupId", value)
	}
	if value := input.Get("managerApproval"); !isUndefined(value) {
		set, err := packageBoolean(value, "managerApproval")
		if err != nil {
			return nil, err
		}
		if set {
			record.Set("managerApproval", true)
		}
	}
	if value := input.Get("autoAssign"); !isUndefined(value) {
		if err := applyRuleChange(ctx, server, tx, principal, nil, record, value, false); err != nil {
			return nil, err
		}
	}
	return tx.Insert(ctx, "accessPackages", record)
}

// UpdatePackage (api/packages.ts updatePackage): Changes a package's contents and rules; existing manual assignments
// keep what they were given. Changing the contents of a package without a rule needs no rights over what is added or
// removed because it grants nothing: extending an assignment lengthens only what the package still bundles (and the
// extender is authorized for), and handing a shared membership over never lengthens it. principal may be nil
// (configuration sync without a rule).
func UpdatePackage(ctx context.Context, server *ServerContext, tx core.IamStore, existing *core.Object, input *core.Object, principal *Principal) (result *core.Object, err error) {
	tenantID := packageText(existing.Get("tenantId"))
	updated := existing.Spread(core.NewObject("updatedAt", float64(server.Now())))
	if value := input.Get("name"); !isUndefined(value) {
		name, err := Text(value, "name", 128)
		if err != nil {
			return nil, err
		}
		other, err := packageWithName(ctx, tx, tenantID, name)
		if err != nil {
			return nil, err
		}
		if other != nil && !core.StrictEquals(other.Get("id"), existing.Get("id")) {
			return nil, core.NewIamError("CONFLICT", "A package with this name exists", 409)
		}
		updated.Set("name", name)
		updated.Set("uniqueKey", packageNameKey(name))
	}
	if value := input.Get("description"); value == nil {
		updated.Delete("description")
	} else if !isUndefined(value) {
		description, err := Text(value, "description", 512)
		if err != nil {
			return nil, err
		}
		updated.Set("description", description)
	}
	if value := input.Get("roleIds"); !isUndefined(value) {
		list, err := Strings(value, "roleIds")
		if err != nil {
			return nil, err
		}
		updated.Set("roleIds", stringsOf(unique(list)))
	}
	if value := input.Get("groupIds"); !isUndefined(value) {
		list, err := Strings(value, "groupIds")
		if err != nil {
			return nil, err
		}
		updated.Set("groupIds", stringsOf(unique(list)))
	}
	if !isUndefined(input.Get("roleIds")) || !isUndefined(input.Get("groupIds")) {
		if err := packageContents(ctx, server, tx, tenantID, flowStrings(updated.Get("roleIds")), flowStrings(updated.Get("groupIds"))); err != nil {
			return nil, err
		}
	}
	if value := input.Get("maxDurationMs"); value == nil {
		updated.Delete("maxDurationMs")
	} else if !isUndefined(value) {
		maxDuration, err := Integer(value, "maxDurationMs", 60_000, packageTenYears)
		if err != nil {
			return nil, err
		}
		updated.Set("maxDurationMs", maxDuration)
	}
	for _, flag := range []string{"requireJustification", "requestable"} {
		if value := input.Get(flag); !isUndefined(value) {
			set, err := packageBoolean(value, flag)
			if err != nil {
				return nil, err
			}
			if set {
				updated.Set(flag, true)
			} else {
				updated.Delete(flag)
			}
		}
	}
	if value := input.Get("approverGroupId"); value == nil {
		updated.Delete("approverGroupId")
	} else if !isUndefined(value) {
		if _, err := server.Scoped(ctx, tx, "groups", value, tenantID); err != nil {
			return nil, err
		}
		updated.Set("approverGroupId", value)
	}
	if value := input.Get("managerApproval"); !isUndefined(value) {
		set, err := packageBoolean(value, "managerApproval")
		if err != nil {
			return nil, err
		}
		if set {
			updated.Set("managerApproval", true)
		} else {
			updated.Delete("managerApproval")
		}
	}
	if value := input.Get("keepAutomaticAssignments"); !isUndefined(value) {
		if _, err := packageBoolean(value, "keepAutomaticAssignments"); err != nil {
			return nil, err
		}
	}
	if err := applyRuleChange(ctx, server, tx, principal, existing, updated, input.Get("autoAssign"), input.Get("keepAutomaticAssignments") == true); err != nil {
		return nil, err
	}
	// Pending requests the tightened rules no longer allow could never be approved; they are cancelled with the reason.
	now := float64(server.Now())
	requests, err := tx.Find(ctx, "packageRequests", core.NewObject("tenantId", tenantID, "packageId", existing.Get("id"), "status", "pending"), nil)
	if err != nil {
		return nil, err
	}
	for _, request := range requests {
		// A request that already lapsed keeps its history; the purge worker marks it expired.
		if !pendingRequest(request, now) {
			continue
		}
		reason := ""
		switch {
		case !truthy(updated.Get("requestable")):
			reason = "The package can no longer be requested"
		case truthy(updated.Get("requireJustification")) && isUndefined(request.Get("justification")):
			reason = "The package now requires a justification"
		case !isUndefined(updated.Get("maxDurationMs")) &&
			(isUndefined(request.Get("desiredExpiresAt")) ||
				jsNumber(request.Get("desiredExpiresAt")) > now+jsNumber(updated.Get("maxDurationMs"))):
			reason = "The requested end no longer fits the package"
		}
		if reason != "" {
			if _, err := tx.Put(ctx, "packageRequests", request.Spread(core.NewObject(
				"status", "cancelled",
				"decidedAt", now,
				"note", reason,
			))); err != nil {
				return nil, err
			}
		}
	}
	return tx.Put(ctx, "accessPackages", updated)
}

// packageAssignments (api/packages.ts packageAssignments): the assignments of a package, live ones only unless
// `includeExpired`.
func packageAssignments(ctx context.Context, server *ServerContext, tx core.IamStore, pkg *core.Object, includeExpired bool) ([]*core.Object, error) {
	records, err := tx.Find(ctx, "packageAssignments", core.NewObject("tenantId", pkg.Get("tenantId"), "packageId", pkg.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	out := make([]*core.Object, 0, len(records))
	for _, assignment := range records {
		if includeExpired || liveAssignment(server, assignment) {
			out = append(out, assignment)
		}
	}
	return out, nil
}

// DeletePackage (api/packages.ts deletePackage): Deletes a package nobody holds, with its request history; shared by
// `packages.delete` and configuration sync.
func DeletePackage(ctx context.Context, server *ServerContext, tx core.IamStore, pkg *core.Object) (err error) {
	live, err := packageAssignments(ctx, server, tx, pkg, false)
	if err != nil {
		return err
	}
	if held := len(live); held > 0 {
		suffix := "ies"
		if held == 1 {
			suffix = "y"
		}
		message := "Still assigned to " + strconv.Itoa(held) + " identit" + suffix + "; revoke first"
		if truthy(pkg.Get("autoAssign")) {
			message = "Still assigned to " + strconv.Itoa(held) + " identit" + suffix + "; set autoAssign to null so reconciliation removes the automatic assignments, and revoke the manual ones"
		}
		return core.NewIamError("RESOURCE_IN_USE", message, 409)
	}
	ended, err := packageAssignments(ctx, server, tx, pkg, true)
	if err != nil {
		return err
	}
	for _, assignment := range ended {
		if err := tx.Delete(ctx, "packageAssignments", jsString(assignment.Get("id"))); err != nil {
			return err
		}
	}
	for _, collection := range []string{"packageRequests", "packageRuleIssues"} {
		records, err := tx.Find(ctx, collection, core.NewObject("tenantId", pkg.Get("tenantId"), "packageId", pkg.Get("id")), nil)
		if err != nil {
			return err
		}
		for _, record := range records {
			if err := tx.Delete(ctx, collection, jsString(record.Get("id"))); err != nil {
				return err
			}
		}
	}
	return tx.Delete(ctx, "accessPackages", jsString(pkg.Get("id")))
}

// assignmentEnd (api/packages.ts assignmentEnd): the end an assignment or request asks for (a number, or undefined),
// validated against the package's cap.
func assignmentEnd(server *ServerContext, pkg *core.Object, value any) (any, error) {
	var expiresAt any = core.Undefined
	if !isUndefined(value) {
		end, err := server.BindingExpiry(value)
		if err != nil {
			return nil, err
		}
		expiresAt = end
	}
	if maxDuration := pkg.Get("maxDurationMs"); !isUndefined(maxDuration) {
		if isUndefined(expiresAt) {
			return nil, invalidInput("This package requires an end date (expiresAt)")
		}
		if jsNumber(expiresAt) > float64(server.Now())+jsNumber(maxDuration) {
			return nil, invalidInput("expiresAt exceeds the maximum duration of this package")
		}
	}
	return expiresAt, nil
}

// justificationFor (api/packages.ts justificationFor): the justification (a string, or undefined), required when the
// package says so.
func justificationFor(pkg *core.Object, value any) (any, error) {
	var justification any = core.Undefined
	if !isUndefined(value) {
		text, err := Text(value, "justification", 2048)
		if err != nil {
			return nil, err
		}
		justification = text
	}
	if truthy(pkg.Get("requireJustification")) && isUndefined(justification) {
		return nil, invalidInput("This package requires a justification")
	}
	return justification, nil
}

// assignmentBroken (api/packages.ts assignmentBroken): an assignment whose bindings no longer grant (the issuing
// authority was revoked, for example when the assigner was offboarded, or a binding was removed or taken over by
// hand) is broken: it may be replaced by a new one.
func assignmentBroken(ctx context.Context, server *ServerContext, tx core.IamStore, assignment *core.Object) (bool, error) {
	for _, bindingID := range flowStrings(assignment.Get("bindingIds")) {
		binding, err := tx.Get(ctx, "bindings", bindingID)
		if err != nil {
			return false, err
		}
		if binding == nil || !core.StrictEquals(binding.Get("packageAssignmentId"), assignment.Get("id")) {
			return true, nil
		}
		_, ok, err := server.AuthorityChain(ctx, tx, packageText(binding.Get("authorityId")))
		if err != nil {
			return false, err
		}
		if !ok {
			return true, nil
		}
	}
	return false, nil
}

// nextOwner (api/packages.ts nextOwner): the longest-lived other live assignment of the identity whose package
// includes the group.
func nextOwner(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID any, identityID any, groupID string, excludeID any) (*core.Object, error) {
	var best *core.Object
	others, err := tx.Find(ctx, "packageAssignments", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	for _, other := range others {
		if core.StrictEquals(other.Get("id"), excludeID) || !liveAssignment(server, other) {
			continue
		}
		pkg, err := tx.Get(ctx, "accessPackages", jsString(other.Get("packageId")))
		if err != nil {
			return nil, err
		}
		if pkg == nil || !containsString(flowStrings(pkg.Get("groupIds")), groupID) {
			continue
		}
		if best == nil || endOf(other.Get("expiresAt")) > endOf(best.Get("expiresAt")) {
			best = other
		}
	}
	return best, nil
}

// handOver (api/packages.ts handOver): a group has one membership record per person, so packages that share a group
// share it: the record belongs to the assignment that needs it longest. Handing it over moves its tag and end to the
// new owner, but never lengthens it: the new owner's package may have gained the group after that assignment was
// made (packages.update grants nothing), so the owner's end was never authorized for this group. Every assignment
// that did receive the group already ends no later than the record (materialize and retimeAssignment keep the
// longest end on it).
func handOver(ctx context.Context, tx core.IamStore, groupMember *core.Object, ownerID string) error {
	owner, err := tx.Get(ctx, "packageAssignments", ownerID)
	if err != nil || owner == nil {
		return err
	}
	next := groupMember.Spread()
	next.Delete("expiresAt")
	end := math.Min(endOf(groupMember.Get("expiresAt")), endOf(owner.Get("expiresAt")))
	if !math.IsInf(end, 1) {
		next.Set("expiresAt", end)
	}
	next.Set("packageAssignmentId", owner.Get("id"))
	if _, err := tx.Put(ctx, "groupMembers", next); err != nil {
		return err
	}
	membershipIDs := flowStrings(owner.Get("membershipIds"))
	memberID := jsString(groupMember.Get("id"))
	if !containsString(membershipIDs, memberID) {
		if _, err := tx.Put(ctx, "packageAssignments", owner.Spread(core.NewObject(
			"membershipIds", append(stringsOf(membershipIDs), groupMember.Get("id")),
		))); err != nil {
			return err
		}
	}
	return nil
}

// packageIDList is a JavaScript array of IDs that materialize grows in place (push) or replaces (a new array), so a
// caller holding the array it passed in sees exactly the pushes JavaScript's aliasing shows (refreshAssignment counts
// against it).
type packageIDList struct {
	items []string
}

func (l *packageIDList) includes(item string) bool { return containsString(l.items, item) }
func (l *packageIDList) push(item string)          { l.items = append(l.items, item) }

// packageLists are an assignment's `bindingIds` and `membershipIds` while materialize fills them.
type packageLists struct {
	bindings    *packageIDList
	memberships *packageIDList
}

// materialize (api/packages.ts materialize): creates what an assignment is missing: a binding of its own for each
// role (under `authority`, never depending on or replacing a binding granted another way) and a membership for each
// group. A membership the person already holds for at least as long is left alone and reported in the returned
// `skipped`; a shorter one is extended and becomes the assignment's. Idempotent: what the assignment already holds is
// kept.
func materialize(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, pkg *core.Object, identityID string, assignmentID any, lists *packageLists, authority *core.Object, expiresAt any) ([]string, error) {
	tenantID := pkg.Get("tenantId")
	skipped := []string{}
	window := core.NewObject()
	if !isUndefined(expiresAt) {
		window.Set("expiresAt", expiresAt)
	}
	roleIDs := flowStrings(pkg.Get("roleIds"))
	if len(roleIDs) > 0 {
		bindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "identity", "subjectId", identityID), nil)
		if err != nil {
			return nil, err
		}
		var own []*core.Object
		for _, binding := range bindings {
			if core.StrictEquals(binding.Get("packageAssignmentId"), assignmentID) {
				own = append(own, binding)
			}
		}
		for _, roleID := range roleIDs {
			var held []*core.Object
			for _, binding := range own {
				if binding.Get("roleId") == roleID && core.StrictEquals(binding.Get("authorityId"), member(authority, "id")) {
					held = append(held, binding)
				}
			}
			live := false
			for _, binding := range held {
				if !server.ExpiredBinding(binding) {
					live = true
					break
				}
			}
			if live {
				for _, binding := range held {
					if bindingID := jsString(binding.Get("id")); !lists.bindings.includes(bindingID) {
						lists.bindings.push(bindingID)
					}
				}
				continue
			}
			// A dead binding of the same key (the assignment's own, expired) is replaced.
			for _, binding := range held {
				if err := removeTaggedBinding(ctx, tx, binding); err != nil {
					return nil, err
				}
			}
			binding, err := CreateBinding(ctx, server, tx, principal, core.NewObject(
				"tenantId", tenantID,
				"roleId", roleID,
				"subjectType", "identity",
				"subjectId", identityID,
				"authorityId", member(authority, "id"),
			).Assign(window), core.NewObject("packageAssignmentId", assignmentID))
			if err != nil {
				return nil, err
			}
			replaced := []string{}
			for _, existing := range lists.bindings.items {
				dead := false
				for _, binding := range held {
					if jsString(binding.Get("id")) == existing {
						dead = true
						break
					}
				}
				if !dead {
					replaced = append(replaced, existing)
				}
			}
			lists.bindings = &packageIDList{items: append(replaced, jsString(binding.Get("id")))}
		}
	}
	for _, groupID := range flowStrings(pkg.Get("groupIds")) {
		existing, err := packageFirst(ctx, tx, "groupMembers", core.NewObject("tenantId", tenantID, "uniqueKey", groupID+":"+identityID))
		if err != nil {
			return nil, err
		}
		var groupMember *core.Object
		if existing != nil && server.LiveMembership(existing) {
			if core.StrictEquals(existing.Get("packageAssignmentId"), assignmentID) {
				if memberID := jsString(existing.Get("id")); !lists.memberships.includes(memberID) {
					lists.memberships.push(memberID)
				}
				continue
			}
			if endOf(existing.Get("expiresAt")) >= endOf(expiresAt) {
				group, err := tx.Get(ctx, "groups", groupID)
				if err != nil {
					return nil, err
				}
				label := groupID
				if name := member(group, "name"); !nullish(name) {
					label = jsString(name)
				}
				var owner *core.Object
				if ownerID := existing.Get("packageAssignmentId"); truthy(ownerID) {
					owner, err = tx.Get(ctx, "packageAssignments", jsString(ownerID))
					if err != nil {
						return nil, err
					}
				}
				var through any = core.Undefined
				if owner != nil {
					ownerPackage, err := tx.Get(ctx, "accessPackages", jsString(owner.Get("packageId")))
					if err != nil {
						return nil, err
					}
					through = member(ownerPackage, "name")
				}
				line := "already a member of group " + label
				if truthy(through) {
					line += " (through package " + jsString(through) + ")"
				}
				skipped = append(skipped, line)
				continue
			}
			// A shorter membership is extended to the assignment's end and becomes the assignment's.
			var end any = expiresAt
			if isUndefined(end) {
				end = nil
			}
			groupMember, err = UpdateGroupMember(ctx, server, tx, principal, core.NewObject(
				"tenantId", tenantID,
				"groupId", groupID,
				"identityId", identityID,
				"expiresAt", end,
			))
			if err != nil {
				return nil, err
			}
		} else {
			groupMember, err = AddGroupMember(ctx, server, tx, principal, core.NewObject(
				"tenantId", tenantID,
				"groupId", groupID,
				"identityId", identityID,
			).Assign(window))
			if err != nil {
				return nil, err
			}
		}
		if _, err := tx.Put(ctx, "groupMembers", groupMember.Spread(core.NewObject("packageAssignmentId", assignmentID))); err != nil {
			return nil, err
		}
		if memberID := jsString(groupMember.Get("id")); !lists.memberships.includes(memberID) {
			lists.memberships.push(memberID)
		}
	}
	return skipped, nil
}

// AssignPackage (api/packages.ts assignPackage): Grants a package to an identity: every role becomes an identity
// binding of the assignment's own and every group a membership, all ending at `expiresAt`, created under the
// caller's grant authority and tagged with the assignment (see materialize). A live automatic assignment is taken
// over (revoked and replaced by this manual one); a broken one is replaced. The identity's pending request for the
// package is marked approved (cancelled, for an automatic assignment). With `automatic`, the rule engine assigns
// under the rule owner's authority. input is `{ identityId, expiresAt?, justification? }`, automatic (nil: a manual
// assignment) `{ authority, ruleRevision }`; the result is `{ assignment, skipped, replacedAutomatic }`.
func AssignPackage(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, pkg *core.Object, input *core.Object, automatic *core.Object) (result *core.Object, err error) {
	tenantID := packageText(pkg.Get("tenantId"))
	identity, err := server.ActiveIdentity(ctx, tx, input.Get("identityId"), tenantID)
	if err != nil {
		return nil, err
	}
	identityID := jsString(identity.Get("id"))
	packageID := jsString(pkg.Get("id"))
	now := float64(server.Now())
	replacedAutomatic := false
	previous, err := packageFirst(ctx, tx, "packageAssignments", core.NewObject("tenantId", tenantID, "uniqueKey", packageID+":"+identityID))
	if err != nil {
		return nil, err
	}
	if previous != nil {
		if liveAssignment(server, previous) {
			if !isUndefined(previous.Get("ruleRevision")) && automatic == nil {
				// An administrator takes an automatic assignment over; it becomes manual under their authority.
				if _, err := RevokeAssignment(ctx, server, tx, previous); err != nil {
					return nil, err
				}
				replacedAutomatic = true
			} else {
				broken, err := assignmentBroken(ctx, server, tx, previous)
				if err != nil {
					return nil, err
				}
				if !broken {
					return nil, core.NewIamError("CONFLICT", "This package is already assigned to the identity", 409)
				}
				// A broken assignment grants nothing any more: clear what is left of it and start over.
				if _, err := RevokeAssignment(ctx, server, tx, previous); err != nil {
					return nil, err
				}
			}
		} else if err := tx.Delete(ctx, "packageAssignments", jsString(previous.Get("id"))); err != nil {
			return nil, err
		}
	}
	var expiresAt any = core.Undefined
	if automatic == nil {
		expiresAt, err = assignmentEnd(server, pkg, input.Get("expiresAt"))
		if err != nil {
			return nil, err
		}
	}
	justificationInput := input.Get("justification")
	if automatic != nil {
		justificationInput = AutomaticJustification
	}
	justification, err := justificationFor(pkg, justificationInput)
	if err != nil {
		return nil, err
	}
	var authority *core.Object
	if automatic != nil {
		authority, _ = automatic.Get("authority").(*core.Object)
	} else {
		authority, err = AuthorizePackage(ctx, server, tx, principal, pkg, nil)
		if err != nil {
			return nil, err
		}
	}
	assignment := core.NewObject(
		"id", ID(),
		"tenantId", tenantID,
		"uniqueKey", packageID+":"+identityID,
		"packageId", pkg.Get("id"),
		"identityId", identity.Get("id"),
		"assignedBy", principal.Identity.Get("id"),
		"assignedAt", now,
	)
	if !isUndefined(expiresAt) {
		assignment.Set("expiresAt", expiresAt)
	}
	if !isUndefined(justification) {
		assignment.Set("justification", justification)
	}
	if automatic != nil {
		assignment.Set("ruleRevision", automatic.Get("ruleRevision"))
	}
	assignment.Set("bindingIds", []any{})
	assignment.Set("membershipIds", []any{})
	lists := &packageLists{bindings: &packageIDList{items: []string{}}, memberships: &packageIDList{items: []string{}}}
	skipped, err := materialize(ctx, server, tx, principal, pkg, identityID, assignment.Get("id"), lists, authority, expiresAt)
	if err != nil {
		return nil, err
	}
	assignment.Set("bindingIds", stringsOf(lists.bindings.items))
	assignment.Set("membershipIds", stringsOf(lists.memberships.items))
	inserted, err := tx.Insert(ctx, "packageAssignments", assignment)
	if err != nil {
		return nil, err
	}
	// A request for the same package is fulfilled by the assignment.
	requests, err := tx.Find(ctx, "packageRequests", core.NewObject(
		"tenantId", tenantID, "packageId", pkg.Get("id"), "identityId", identity.Get("id"), "status", "pending",
	), nil)
	if err != nil {
		return nil, err
	}
	for _, request := range requests {
		var decided *core.Object
		if automatic != nil {
			decided = request.Spread(core.NewObject(
				"status", "cancelled",
				"decidedAt", now,
				"note", "Assigned automatically by the package rule",
			))
		} else {
			decided = request.Spread(core.NewObject(
				"status", "approved",
				"decidedBy", principal.Identity.Get("id"),
				"decidedAt", now,
				"assignmentId", inserted.Get("id"),
			))
		}
		if _, err := tx.Put(ctx, "packageRequests", decided); err != nil {
			return nil, err
		}
	}
	return core.NewObject("assignment", inserted, "skipped", stringsOf(skipped), "replacedAutomatic", replacedAutomatic), nil
}

// removeTaggedBinding (api/packages.ts removeTaggedBinding): removes one of an assignment's bindings with its
// activations.
func removeTaggedBinding(ctx context.Context, tx core.IamStore, binding *core.Object) error {
	activations, err := tx.Find(ctx, "bindingActivations", core.NewObject("tenantId", binding.Get("tenantId"), "bindingId", binding.Get("id")), nil)
	if err != nil {
		return err
	}
	for _, activation := range activations {
		if err := tx.Delete(ctx, "bindingActivations", jsString(activation.Get("id"))); err != nil {
			return err
		}
	}
	return tx.Delete(ctx, "bindings", jsString(binding.Get("id")))
}

// removeTaggedMembership (api/packages.ts removeTaggedMembership): removes one of an assignment's memberships, unless
// another live package of the person includes the group: then that assignment takes it over. Removing ends the
// person's activations of the group's eligible bindings, as groups.removeMember does. Returns whether the membership
// was removed.
func removeTaggedMembership(ctx context.Context, server *ServerContext, tx core.IamStore, groupMember *core.Object, assignmentID any) (bool, error) {
	owner, err := nextOwner(ctx, server, tx, groupMember.Get("tenantId"), groupMember.Get("identityId"), jsString(groupMember.Get("groupId")), assignmentID)
	if err != nil {
		return false, err
	}
	if owner != nil {
		if err := handOver(ctx, tx, groupMember, jsString(owner.Get("id"))); err != nil {
			return false, err
		}
		return false, nil
	}
	groupBindings, err := tx.Find(ctx, "bindings", core.NewObject(
		"tenantId", groupMember.Get("tenantId"), "subjectType", "group", "subjectId", groupMember.Get("groupId"),
	), nil)
	if err != nil {
		return false, err
	}
	for _, groupBinding := range groupBindings {
		activations, err := tx.Find(ctx, "bindingActivations", core.NewObject(
			"tenantId", groupMember.Get("tenantId"), "bindingId", groupBinding.Get("id"), "identityId", groupMember.Get("identityId"),
		), nil)
		if err != nil {
			return false, err
		}
		for _, activation := range activations {
			if err := tx.Delete(ctx, "bindingActivations", jsString(activation.Get("id"))); err != nil {
				return false, err
			}
		}
	}
	if err := tx.Delete(ctx, "groupMembers", jsString(groupMember.Get("id"))); err != nil {
		return false, err
	}
	return true, nil
}

// RevokeAssignment (api/packages.ts revokeAssignment): Removes exactly the bindings and memberships an assignment
// created, then the assignment. The assignment owns those records whichever authority issued them, so revoking needs
// only the right to manage the package. The result is `{ bindings, memberships }`, the counts removed.
func RevokeAssignment(ctx context.Context, server *ServerContext, tx core.IamStore, assignment *core.Object) (result *core.Object, err error) {
	bindings, memberships := 0, 0
	for _, bindingID := range flowStrings(assignment.Get("bindingIds")) {
		binding, err := tx.Get(ctx, "bindings", bindingID)
		if err != nil {
			return nil, err
		}
		if binding == nil || !core.StrictEquals(binding.Get("packageAssignmentId"), assignment.Get("id")) {
			continue
		}
		if err := removeTaggedBinding(ctx, tx, binding); err != nil {
			return nil, err
		}
		bindings++
	}
	groups := newOrderedSet()
	for _, membershipID := range flowStrings(assignment.Get("membershipIds")) {
		groupMember, err := tx.Get(ctx, "groupMembers", membershipID)
		if err != nil {
			return nil, err
		}
		if groupMember == nil || !core.StrictEquals(groupMember.Get("packageAssignmentId"), assignment.Get("id")) {
			continue
		}
		groups.Add(jsString(groupMember.Get("groupId")))
		removed, err := removeTaggedMembership(ctx, server, tx, groupMember, assignment.Get("id"))
		if err != nil {
			return nil, err
		}
		if removed {
			memberships++
		}
	}
	if err := tx.Delete(ctx, "packageAssignments", jsString(assignment.Get("id"))); err != nil {
		return nil, err
	}
	// Teams that sync their members from these groups follow (teams.ts).
	tenantID := packageText(assignment.Get("tenantId"))
	for _, groupID := range groups.Values() {
		if _, err := SyncTeamsFromGroups(ctx, server, tx, tenantID, core.NewObject("groupId", groupID, "actorId", "access-package")); err != nil {
			return nil, err
		}
	}
	return core.NewObject("bindings", bindings, "memberships", memberships), nil
}

// RetimeAssignment (api/packages.ts retimeAssignment): Moves the end of an assignment and of exactly its records
// (undefined: no end). Shortening a shared membership hands it to the package that still needs it longer;
// lengthening extends a shorter membership of the package's groups (held by hand or through another package) and
// makes it the assignment's. Authorization is the caller's, for the package's current contents: lengthening
// therefore reaches only records of roles and groups the package still bundles, and those it no longer bundles
// (removed by packages.update since) keep their end. A caller nobody authorized for the current contents (a guest's
// renewal, api/guests.ts) passes `lengthenOnly`: lengthening then reaches only those memberships of the assignment,
// takes no other membership over, and leaves the rest as they are. expiresAt nil is no end; lengthenOnly nil is
// undefined (a non-nil empty list is an empty set).
func RetimeAssignment(ctx context.Context, server *ServerContext, tx core.IamStore, pkg *core.Object, assignment *core.Object, expiresAt *float64, lengthenOnly []string) (result *core.Object, err error) {
	var end any = core.Undefined
	if expiresAt != nil {
		end = *expiresAt
	}
	tenantID := assignment.Get("tenantId")
	retime := func(record *core.Object) *core.Object {
		rest := record.Spread()
		rest.Delete("expiresAt")
		if isUndefined(end) {
			return rest
		}
		return rest.Set("expiresAt", end)
	}
	roleIDs := flowStrings(pkg.Get("roleIds"))
	groupIDs := flowStrings(pkg.Get("groupIds"))
	lengthening := endOf(end) > endOf(assignment.Get("expiresAt"))
	for _, bindingID := range flowStrings(assignment.Get("bindingIds")) {
		binding, err := tx.Get(ctx, "bindings", bindingID)
		if err != nil {
			return nil, err
		}
		if !core.StrictEquals(member(binding, "packageAssignmentId"), assignment.Get("id")) {
			continue
		}
		if lengthening && !containsString(roleIDs, jsString(binding.Get("roleId"))) {
			continue
		}
		if _, err := tx.Put(ctx, "bindings", retime(binding)); err != nil {
			return nil, err
		}
	}
	current := assignment
	// The memberships the assignment holds, plus the person's memberships of the package's current groups.
	order := newOrderedSet()
	members := map[string]*core.Object{}
	remember := func(groupMember *core.Object) {
		memberID := jsString(groupMember.Get("id"))
		order.Add(memberID)
		members[memberID] = groupMember
	}
	for _, membershipID := range flowStrings(assignment.Get("membershipIds")) {
		groupMember, err := tx.Get(ctx, "groupMembers", membershipID)
		if err != nil {
			return nil, err
		}
		if core.StrictEquals(member(groupMember, "packageAssignmentId"), assignment.Get("id")) {
			remember(groupMember)
		}
	}
	if lengthenOnly == nil {
		for _, groupID := range groupIDs {
			groupMember, err := packageFirst(ctx, tx, "groupMembers", core.NewObject(
				"tenantId", tenantID, "uniqueKey", groupID+":"+jsString(assignment.Get("identityId")),
			))
			if err != nil {
				return nil, err
			}
			if groupMember != nil {
				remember(groupMember)
			}
		}
	}
	for _, memberID := range order.Values() {
		groupMember := members[memberID]
		if !server.LiveMembership(groupMember) {
			continue
		}
		groupID := jsString(groupMember.Get("groupId"))
		if core.StrictEquals(groupMember.Get("packageAssignmentId"), assignment.Get("id")) {
			if lengthening {
				if !containsString(groupIDs, groupID) {
					continue
				}
				if lengthenOnly != nil && !containsString(lengthenOnly, memberID) {
					continue
				}
			} else {
				owner, err := nextOwner(ctx, server, tx, tenantID, assignment.Get("identityId"), groupID, assignment.Get("id"))
				if err != nil {
					return nil, err
				}
				if owner != nil && endOf(owner.Get("expiresAt")) > endOf(end) {
					if err := handOver(ctx, tx, groupMember, jsString(owner.Get("id"))); err != nil {
						return nil, err
					}
					continue
				}
			}
			if _, err := tx.Put(ctx, "groupMembers", retime(groupMember)); err != nil {
				return nil, err
			}
		} else if lengthening && containsString(groupIDs, groupID) && endOf(groupMember.Get("expiresAt")) < endOf(end) {
			rest := groupMember.Spread()
			rest.Delete("packageAssignmentId")
			if _, err := tx.Put(ctx, "groupMembers", retime(rest).Set("packageAssignmentId", assignment.Get("id"))); err != nil {
				return nil, err
			}
			if membershipIDs := flowStrings(current.Get("membershipIds")); !containsString(membershipIDs, memberID) {
				current = current.Spread(core.NewObject("membershipIds", append(stringsOf(membershipIDs), groupMember.Get("id"))))
			}
		}
	}
	// Synced team memberships follow the new end of their source memberships (teams.ts).
	groups := newOrderedSet()
	for _, memberID := range order.Values() {
		groups.Add(jsString(members[memberID].Get("groupId")))
	}
	for _, groupID := range groups.Values() {
		if _, err := SyncTeamsFromGroups(ctx, server, tx, packageText(tenantID), core.NewObject("groupId", groupID, "actorId", "access-package")); err != nil {
			return nil, err
		}
	}
	return tx.Put(ctx, "packageAssignments", retime(current))
}

// RefreshAssignment (api/packages.ts refreshAssignment): Brings an automatic assignment up to its package and rule:
// bindings of roles no longer packaged, or issued under another authority than the rule's, are removed; memberships
// of groups no longer packaged are removed (or handed over); what is missing is materialized. Memberships that stay
// are untouched, so live activations survive. The result is `{ assignment, bindings, memberships, removedBindings,
// removedMemberships, skipped }`.
func RefreshAssignment(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, pkg *core.Object, assignment *core.Object, authority *core.Object) (result *core.Object, err error) {
	keptBindings := &packageIDList{items: []string{}}
	keptMemberships := &packageIDList{items: []string{}}
	removedBindings, removedMemberships := 0, 0
	roleIDs := flowStrings(pkg.Get("roleIds"))
	groupIDs := flowStrings(pkg.Get("groupIds"))
	for _, bindingID := range flowStrings(assignment.Get("bindingIds")) {
		binding, err := tx.Get(ctx, "bindings", bindingID)
		if err != nil {
			return nil, err
		}
		if binding == nil || !core.StrictEquals(binding.Get("packageAssignmentId"), assignment.Get("id")) {
			continue
		}
		if !containsString(roleIDs, jsString(binding.Get("roleId"))) || !core.StrictEquals(binding.Get("authorityId"), member(authority, "id")) {
			if err := removeTaggedBinding(ctx, tx, binding); err != nil {
				return nil, err
			}
			removedBindings++
		} else {
			keptBindings.push(jsString(binding.Get("id")))
		}
	}
	for _, membershipID := range flowStrings(assignment.Get("membershipIds")) {
		groupMember, err := tx.Get(ctx, "groupMembers", membershipID)
		if err != nil {
			return nil, err
		}
		if groupMember == nil || !core.StrictEquals(groupMember.Get("packageAssignmentId"), assignment.Get("id")) {
			continue
		}
		if !containsString(groupIDs, jsString(groupMember.Get("groupId"))) {
			removed, err := removeTaggedMembership(ctx, server, tx, groupMember, assignment.Get("id"))
			if err != nil {
				return nil, err
			}
			if removed {
				removedMemberships++
			}
		} else {
			keptMemberships.push(jsString(groupMember.Get("id")))
		}
	}
	// The working assignment's lists are the kept arrays themselves (JavaScript aliasing): what materialize pushes
	// before replacing a list counts as kept.
	lists := &packageLists{bindings: keptBindings, memberships: keptMemberships}
	working := assignment.Spread()
	skipped, err := materialize(ctx, server, tx, principal, pkg, jsString(working.Get("identityId")), working.Get("id"), lists, authority, working.Get("expiresAt"))
	if err != nil {
		return nil, err
	}
	working.Set("bindingIds", stringsOf(lists.bindings.items))
	working.Set("membershipIds", stringsOf(lists.memberships.items))
	working.Set("ruleRevision", member(pkg.Get("autoAssign"), "revision"))
	saved, err := tx.Put(ctx, "packageAssignments", working)
	if err != nil {
		return nil, err
	}
	added := func(ids []string, kept *packageIDList) int {
		count := 0
		for _, id := range ids {
			if !kept.includes(id) {
				count++
			}
		}
		return count
	}
	return core.NewObject(
		"assignment", saved,
		"bindings", added(flowStrings(saved.Get("bindingIds")), keptBindings),
		"memberships", added(flowStrings(saved.Get("membershipIds")), keptMemberships),
		"removedBindings", removedBindings,
		"removedMemberships", removedMemberships,
		"skipped", stringsOf(skipped),
	), nil
}

// packageSortNewest sorts records newest first by a timestamp member (`(a, b) => b[key] - a[key]`, stable).
func packageSortNewest(records []*core.Object, key string) {
	slices.SortStableFunc(records, func(a, b *core.Object) int {
		difference := jsNumber(b.Get(key)) - jsNumber(a.Get(key))
		switch {
		case difference < 0:
			return -1
		case difference > 0:
			return 1
		}
		return 0
	})
}

// summarize (api/packages.ts summarize): assignments as the API returns them, newest first.
func summarize(ctx context.Context, server *ServerContext, tx core.IamStore, assignments []*core.Object) ([]*core.Object, error) {
	packages := map[string]*core.Object{}
	identities := map[string]*core.Object{}
	summaries := make([]*core.Object, 0, len(assignments))
	for _, assignment := range assignments {
		packageID := jsString(assignment.Get("packageId"))
		if _, ok := packages[packageID]; !ok {
			pkg, err := tx.Get(ctx, "accessPackages", packageID)
			if err != nil {
				return nil, err
			}
			packages[packageID] = pkg
		}
		identityID := jsString(assignment.Get("identityId"))
		if _, ok := identities[identityID]; !ok {
			identity, err := tx.Get(ctx, "identities", identityID)
			if err != nil {
				return nil, err
			}
			identities[identityID] = identity
		}
		identity := identities[identityID]
		rest := assignment.Spread()
		rest.Delete("uniqueKey")
		ruleRevision := assignment.Get("ruleRevision")
		rest.Delete("ruleRevision")
		expired := !liveAssignment(server, assignment)
		summary := rest.Spread(core.NewObject(
			"packageName", coalesce(member(packages[packageID], "name"), assignment.Get("packageId")),
			"identityName", coalesce(member(identity, "name"), assignment.Get("identityId")),
		))
		if email := member(identity, "email"); truthy(email) {
			summary.Set("identityEmail", email)
		}
		summary.Set("expired", expired)
		broken := false
		if !expired {
			value, err := assignmentBroken(ctx, server, tx, assignment)
			if err != nil {
				return nil, err
			}
			broken = value
		}
		summary.Set("broken", broken)
		summary.Set("automatic", !isUndefined(ruleRevision))
		summaries = append(summaries, summary)
	}
	packageSortNewest(summaries, "assignedAt")
	return summaries, nil
}

// summarizeRequests (api/packages.ts summarizeRequests): requests as the API returns them, newest first. A pending
// request past its lapse time is reported as expired even before the purge worker marks it.
func summarizeRequests(ctx context.Context, tx core.IamStore, requests []*core.Object, now float64) ([]*core.Object, error) {
	packages := map[string]*core.Object{}
	identities := map[string]*core.Object{}
	summaries := make([]*core.Object, 0, len(requests))
	for _, request := range requests {
		packageID := jsString(request.Get("packageId"))
		if _, ok := packages[packageID]; !ok {
			pkg, err := tx.Get(ctx, "accessPackages", packageID)
			if err != nil {
				return nil, err
			}
			packages[packageID] = pkg
		}
		identityID := jsString(request.Get("identityId"))
		if _, ok := identities[identityID]; !ok {
			identity, err := tx.Get(ctx, "identities", identityID)
			if err != nil {
				return nil, err
			}
			identities[identityID] = identity
		}
		identity := identities[identityID]
		rest := request.Spread()
		rest.Delete("uniqueKey")
		status := request.Get("status")
		if status == "pending" && jsNumber(request.Get("expiresAt")) <= now {
			status = "expired"
		}
		summary := rest.Spread(core.NewObject(
			"status", status,
			"packageName", coalesce(member(packages[packageID], "name"), request.Get("packageId")),
			"identityName", coalesce(member(identity, "name"), request.Get("identityId")),
		))
		if email := member(identity, "email"); truthy(email) {
			summary.Set("identityEmail", email)
		}
		summaries = append(summaries, summary)
	}
	packageSortNewest(summaries, "requestedAt")
	return summaries, nil
}

// mayApprove (api/packages.ts mayApprove): whether the caller may decide on a request for this package: anyone
// holding the permission when the package names no approvers; otherwise root, the requester's manager
// (`managerApproval`), or a member of the approver group.
func mayApprove(ctx context.Context, server *ServerContext, tx core.IamStore, pkg *core.Object, principal *Principal, requesterID any) (bool, error) {
	if !truthy(pkg.Get("approverGroupId")) && !truthy(pkg.Get("managerApproval")) {
		return true, nil
	}
	root, err := server.RootPrincipal(ctx, tx, principal)
	if err != nil {
		return false, err
	}
	if root {
		return true, nil
	}
	if truthy(pkg.Get("managerApproval")) {
		requester, err := tx.Get(ctx, "identities", jsString(requesterID))
		if err != nil {
			return false, err
		}
		if core.StrictEquals(member(requester, "managerId"), principal.Identity.Get("id")) {
			return true, nil
		}
	}
	if !truthy(pkg.Get("approverGroupId")) {
		return false, nil
	}
	memberships, err := tx.Find(ctx, "groupMembers", core.NewObject(
		"tenantId", pkg.Get("tenantId"), "groupId", pkg.Get("approverGroupId"), "identityId", principal.Identity.Get("id"),
	), nil)
	if err != nil {
		return false, err
	}
	for _, membership := range memberships {
		if server.LiveMembership(membership) {
			return true, nil
		}
	}
	return false, nil
}

// approverIDs (api/packages.ts approverIds): who is emailed a request: live approver-group members and, with
// `managerApproval`, the requester's manager.
func approverIDs(ctx context.Context, server *ServerContext, tx core.IamStore, pkg *core.Object, requesterID string) (*orderedSet, error) {
	recipients := newOrderedSet()
	if truthy(pkg.Get("approverGroupId")) {
		memberships, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", pkg.Get("tenantId"), "groupId", pkg.Get("approverGroupId")), nil)
		if err != nil {
			return nil, err
		}
		for _, membership := range memberships {
			if server.LiveMembership(membership) {
				recipients.Add(jsString(membership.Get("identityId")))
			}
		}
	}
	if truthy(pkg.Get("managerApproval")) {
		requester, err := tx.Get(ctx, "identities", requesterID)
		if err != nil {
			return nil, err
		}
		if managerID := member(requester, "managerId"); truthy(managerID) {
			recipients.Add(jsString(managerID))
		}
	}
	recipients.Delete(requesterID)
	return recipients, nil
}

// packageNotify (api/packages.ts notify): queues an email through the host outbox when the deployment delivers
// email at all.
func packageNotify(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, to any, template string, payload *core.Object) error {
	options := server.Options
	if !truthy(to) || options == nil || options.Authentication == nil || options.Authentication.SendEmail == nil {
		return nil
	}
	_, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
		TenantID: tenantID, Kind: "email", To: jsString(to), Template: template, Payload: payload,
	})
	return err
}

// packagePublicView (api/packages.ts publicView): a package as the API returns it: holder counts and, for a rule
// package, the rule's view. env (nil: computed) is the rule environment.
func packagePublicView(ctx context.Context, server *ServerContext, reader core.IamStore, pkg *core.Object, env *core.Object) (*core.Object, error) {
	rest := pkg.Spread()
	rest.Delete("uniqueKey")
	autoAssign := pkg.Get("autoAssign")
	rest.Delete("autoAssign")
	live, err := packageAssignments(ctx, server, reader, pkg, false)
	if err != nil {
		return nil, err
	}
	automatic := 0
	for _, assignment := range live {
		if !isUndefined(assignment.Get("ruleRevision")) {
			automatic++
		}
	}
	view := rest.Spread(core.NewObject("assignments", len(live), "automaticAssignments", automatic))
	if truthy(autoAssign) {
		if env == nil {
			env, err = RuleEnvironment(ctx, server, reader, pkg)
			if err != nil {
				return nil, err
			}
		}
		rule, err := AutoAssignView(ctx, server, reader, pkg, env)
		if err != nil {
			return nil, err
		}
		view.Set("autoAssign", rule)
	}
	return view, nil
}

// packagesTenantID is the request's tenantId as the string the operation validated.
func packagesTenantID(body *core.Object) string { return packageText(body.Get("tenantId")) }

// afterRuleChange (api/packages.ts createPackagesApi afterRuleChange): runs the post-commit reconcile of a rule
// change; a failure never fails the call (the scheduler catches up). Returns the fresh view and the reconcile result
// (nil when it failed).
func (api *PackagesAPI) afterRuleChange(ctx context.Context, pkg *core.Object, requestedBy any) (*core.Object, *core.Object, error) {
	server := api.server
	reconcile, err := ReconcilePackageRules(ctx, server, core.NewObject(
		"tenantId", pkg.Get("tenantId"),
		"packageId", pkg.Get("id"),
		"limit", 200,
		"trigger", "rule-change",
		"requestedBy", requestedBy,
	))
	if err != nil {
		reconcile = nil
	}
	fresh, err := server.Store.Get(ctx, "accessPackages", jsString(pkg.Get("id")))
	if err != nil {
		return nil, nil, err
	}
	if fresh == nil {
		fresh = pkg
	}
	view, err := packagePublicView(ctx, server, server.Store, fresh, nil)
	if err != nil {
		return nil, nil, err
	}
	return view, reconcile, nil
}

// withReconcile is `{ ...view, ...(reconcile ? { reconcile } : {}) }`.
func withReconcile(view *core.Object, reconcile *core.Object) *core.Object {
	out := view.Spread()
	if reconcile != nil {
		out.Set("reconcile", reconcile)
	}
	return out
}

// decideRequest (api/packages.ts createPackagesApi decideRequest) approves or denies a pending request.
func (api *PackagesAPI) decideRequest(ctx context.Context, credential core.CredentialInput, input *core.Object, expiresAt any, decision string) (*core.Object, error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	existing, err := server.Scoped(ctx, server.Store, "packageRequests", input.Get("requestId"), tenantID)
	if err != nil {
		return nil, err
	}
	return Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:packages:approve", jsString(existing.Get("packageId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		request, err := server.Scoped(ctx, tx, "packageRequests", input.Get("requestId"), tenantID)
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		if !pendingRequest(request, now) {
			return nil, core.NewIamError("INVALID_TRANSITION", "This request is not awaiting a decision", 409)
		}
		if core.StrictEquals(request.Get("identityId"), principal.Identity.Get("id")) {
			return nil, invalidInput("You cannot decide on your own request")
		}
		// Two-person control: an administrator viewing as an approver must not decide in their name.
		if truthy(principal.Session.Get("impersonatorId")) {
			return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "Requests cannot be decided while impersonating", 403)
		}
		pkg, err := tx.Get(ctx, "accessPackages", jsString(request.Get("packageId")))
		if err != nil {
			return nil, err
		}
		if pkg == nil {
			return nil, core.NewIamError("INVALID_TRANSITION", "The package no longer exists", 409)
		}
		if decision == "approved" && !truthy(pkg.Get("requestable")) {
			return nil, core.NewIamError("INVALID_TRANSITION", "The package is no longer requestable", 409)
		}
		may, err := mayApprove(ctx, server, tx, pkg, principal, request.Get("identityId"))
		if err != nil {
			return nil, err
		}
		if !may {
			return nil, core.NewIamError("ACCESS_DENIED", "Only the designated approvers may decide", 403)
		}
		var note any = core.Undefined
		if value := input.Get("note"); !isUndefined(value) {
			text, err := Text(value, "note", 2048)
			if err != nil {
				return nil, err
			}
			note = text
		}
		decided := request.Spread(core.NewObject(
			"status", decision,
			"decidedBy", principal.Identity.Get("id"),
			"decidedAt", now,
		))
		if !isUndefined(note) {
			decided.Set("note", note)
		}
		metadata := core.NewObject(
			"requestId", request.Get("id"),
			"packageId", pkg.Get("id"),
			"packageName", pkg.Get("name"),
			"identityId", request.Get("identityId"),
		)
		if !isUndefined(note) {
			metadata.Set("note", note)
		}
		if decision == "approved" {
			assigned, err := AssignPackage(ctx, server, tx, principal, pkg, core.NewObject(
				"identityId", request.Get("identityId"),
				"expiresAt", coalesce(expiresAt, request.Get("desiredExpiresAt")),
				"justification", request.Get("justification"),
			), nil)
			if err != nil {
				return nil, err
			}
			assignment, _ := assigned.Get("assignment").(*core.Object)
			decided.Set("assignmentId", assignment.Get("id"))
			metadata.Set("assignmentId", assignment.Get("id"))
			metadata.Set("bindings", len(flowStrings(assignment.Get("bindingIds"))))
			metadata.Set("memberships", len(flowStrings(assignment.Get("membershipIds"))))
			metadata.Set("skipped", assigned.Get("skipped"))
			if assigned.Get("replacedAutomatic") == true {
				metadata.Set("replacedAutomatic", true)
			}
			if end := assignment.Get("expiresAt"); !isUndefined(end) {
				metadata.Set("expiresAt", end)
			}
		}
		if _, err := tx.Put(ctx, "packageRequests", decided); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "package:request-"+decision, tenantID, jsString(pkg.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		requester, err := tx.Get(ctx, "identities", jsString(request.Get("identityId")))
		if err != nil {
			return nil, err
		}
		payload := core.NewObject(
			"requestId", request.Get("id"),
			"packageId", pkg.Get("id"),
			"packageName", pkg.Get("name"),
			"decision", decision,
			"deciderName", principal.Identity.Get("name"),
		)
		if !isUndefined(note) {
			payload.Set("note", note)
		}
		if end, ok := metadata.Get("expiresAt").(float64); ok {
			payload.Set("expiresAt", jsString(end))
		}
		if err := packageNotify(ctx, server, tx, tenantID, member(requester, "email"), "package-decided", payload); err != nil {
			return nil, err
		}
		summaries, err := summarizeRequests(ctx, tx, []*core.Object{decided}, now)
		if err != nil {
			return nil, err
		}
		return summaries[0], nil
	}, false)
}

// ApproveRequest is POST {basePath}/packages/approveRequest. Grants a pending package request by assigning the package to the requester under your own authority.
func (api *PackagesAPI) ApproveRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesApproveRequestInput]) (Out[apitypes.PackagesApproveRequestOutput], error) {
	result, err := api.decideRequest(ctx, credential, input.Body, input.Get("expiresAt"), "approved")
	if err != nil {
		return Out[apitypes.PackagesApproveRequestOutput]{}, err
	}
	return Out[apitypes.PackagesApproveRequestOutput]{Value: result}, nil
}

// Assign is POST {basePath}/packages/assign. Grants a package to a person: one binding per role and one membership per group, all ending together.
func (api *PackagesAPI) Assign(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesAssignInput]) (Out[apitypes.PackagesAssignOutput], error) {
	server := api.server
	tenantID := packagesTenantID(input.Body)
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:packages:assign", jsString(input.Get("packageId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		pkg, err := server.Scoped(ctx, tx, "accessPackages", input.Get("packageId"), tenantID)
		if err != nil {
			return nil, err
		}
		assigned, err := AssignPackage(ctx, server, tx, principal, pkg, input.Body, nil)
		if err != nil {
			return nil, err
		}
		assignment, _ := assigned.Get("assignment").(*core.Object)
		skipped := assigned.Get("skipped")
		replacedAutomatic := assigned.Get("replacedAutomatic") == true
		created := core.NewObject(
			"bindings", len(flowStrings(assignment.Get("bindingIds"))),
			"memberships", len(flowStrings(assignment.Get("membershipIds"))),
		)
		metadata := core.NewObject(
			"packageId", pkg.Get("id"),
			"packageName", pkg.Get("name"),
			"identityId", assignment.Get("identityId"),
		).Assign(created)
		metadata.Set("skipped", skipped)
		if replacedAutomatic {
			metadata.Set("replacedAutomatic", true)
		}
		if end := assignment.Get("expiresAt"); !isUndefined(end) {
			metadata.Set("expiresAt", end)
		}
		if justification := assignment.Get("justification"); !isUndefined(justification) {
			metadata.Set("justification", justification)
		}
		if err := server.Events.Audit(ctx, tx, principal, "package:assign", tenantID, jsString(pkg.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		summaries, err := summarize(ctx, server, tx, []*core.Object{assignment})
		if err != nil {
			return nil, err
		}
		return summaries[0].Spread(core.NewObject("created", created, "skipped", skipped, "replacedAutomatic", replacedAutomatic)), nil
	}, false)
	if err != nil {
		return Out[apitypes.PackagesAssignOutput]{}, err
	}
	return Out[apitypes.PackagesAssignOutput]{Value: result}, nil
}

// CancelRequest is POST {basePath}/packages/cancelRequest. Withdraws one of your own pending package requests.
func (api *PackagesAPI) CancelRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesCancelRequestInput]) (Out[apitypes.PackagesCancelRequestOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.PackagesCancelRequestOutput]{}, err
	}
	existing, err := server.Scoped(ctx, server.Store, "packageRequests", input.Get("requestId"), tenantID)
	if err != nil {
		return Out[apitypes.PackagesCancelRequestOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:packages:request", jsString(existing.Get("packageId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		request, err := server.Scoped(ctx, tx, "packageRequests", input.Get("requestId"), tenantID)
		if err != nil {
			return nil, err
		}
		// Withdrawing acts in the requester's own right, like making the request: never through a role session or
		// session token.
		if !ActsInOwnRight(principal.Session) || !core.StrictEquals(principal.Session.Get("tenantId"), input.Get("tenantId")) {
			return nil, invalidInput("Requests are made from an ordinary session of the target tenant")
		}
		if !core.StrictEquals(request.Get("identityId"), principal.Identity.Get("id")) {
			return nil, core.NewIamError("ACCESS_DENIED", "Only the requester may cancel a request", 403)
		}
		now := float64(server.Now())
		if !pendingRequest(request, now) {
			return nil, core.NewIamError("INVALID_TRANSITION", "This request is not awaiting a decision", 409)
		}
		cancelled := request.Spread(core.NewObject("status", "cancelled", "decidedAt", now))
		if _, err := tx.Put(ctx, "packageRequests", cancelled); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "package:request-cancelled", tenantID, jsString(request.Get("packageId")), "allow", false,
			core.NewObject("requestId", request.Get("id"), "packageId", request.Get("packageId"))); err != nil {
			return nil, err
		}
		summaries, err := summarizeRequests(ctx, tx, []*core.Object{cancelled}, now)
		if err != nil {
			return nil, err
		}
		return summaries[0], nil
	}, false)
	if err != nil {
		return Out[apitypes.PackagesCancelRequestOutput]{}, err
	}
	return Out[apitypes.PackagesCancelRequestOutput]{Value: result}, nil
}

// Create is POST {basePath}/packages/create. Defines a package of roles and groups, optionally requestable or assigned automatically by a rule.
func (api *PackagesAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesCreateInput]) (Out[apitypes.PackagesCreateOutput], error) {
	server := api.server
	var ruled *core.Object
	var requestedBy any
	view, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:packages:create", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		pkg, err := CreatePackage(ctx, server, tx, input.Body, principal)
		if err != nil {
			return nil, err
		}
		if truthy(pkg.Get("autoAssign")) {
			approved, err := ApproveRule(ctx, server, tx, pkg)
			if err != nil {
				return nil, err
			}
			pkg, _ = approved.Get("pkg").(*core.Object)
			ruled, requestedBy = pkg, principal.Identity.Get("id")
		}
		return packagePublicView(ctx, server, tx, pkg, nil)
	}, false)
	if err != nil {
		return Out[apitypes.PackagesCreateOutput]{}, err
	}
	if ruled == nil {
		return Out[apitypes.PackagesCreateOutput]{Value: view}, nil
	}
	fresh, reconcile, err := api.afterRuleChange(ctx, ruled, requestedBy)
	if err != nil {
		return Out[apitypes.PackagesCreateOutput]{}, err
	}
	return Out[apitypes.PackagesCreateOutput]{Value: withReconcile(fresh, reconcile)}, nil
}

// Delete is POST {basePath}/packages/delete. Deletes a package nobody holds, together with its request history.
func (api *PackagesAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesDeleteInput]) (Out[apitypes.PackagesDeleteOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:packages:delete", jsString(input.Get("packageId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		pkg, err := server.Scoped(ctx, call.Tx, "accessPackages", input.Get("packageId"), packagesTenantID(input.Body))
		if err != nil {
			return nil, err
		}
		if err := DeletePackage(ctx, server, call.Tx, pkg); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	if err != nil {
		return Out[apitypes.PackagesDeleteOutput]{}, err
	}
	return Out[apitypes.PackagesDeleteOutput]{Value: result}, nil
}

// DenyRequest is POST {basePath}/packages/denyRequest. Refuses a pending package request, with an optional note to the requester.
func (api *PackagesAPI) DenyRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesDenyRequestInput]) (Out[apitypes.PackagesDenyRequestOutput], error) {
	result, err := api.decideRequest(ctx, credential, input.Body, core.Undefined, "denied")
	if err != nil {
		return Out[apitypes.PackagesDenyRequestOutput]{}, err
	}
	return Out[apitypes.PackagesDenyRequestOutput]{Value: result}, nil
}

// Extend is POST {basePath}/packages/extend. Moves the end of a person's manual assignment, for the assignment and every record it created at once.
func (api *PackagesAPI) Extend(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesExtendInput]) (Out[apitypes.PackagesExtendOutput], error) {
	server := api.server
	tenantID := packagesTenantID(input.Body)
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:packages:assign", jsString(input.Get("packageId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		pkg, err := server.Scoped(ctx, tx, "accessPackages", input.Get("packageId"), tenantID)
		if err != nil {
			return nil, err
		}
		identityID, err := Text(input.Get("identityId"), "identityId")
		if err != nil {
			return nil, err
		}
		assignment, err := packageFirst(ctx, tx, "packageAssignments", core.NewObject(
			"tenantId", tenantID, "uniqueKey", jsString(pkg.Get("id"))+":"+identityID,
		))
		if err != nil {
			return nil, err
		}
		if assignment == nil || !liveAssignment(server, assignment) {
			return nil, core.NewIamError("NOT_FOUND", "The package is not assigned to this identity", 404)
		}
		if !isUndefined(assignment.Get("ruleRevision")) {
			return nil, core.NewIamError("INVALID_TRANSITION", "Automatic assignments end when the person stops matching the rule; assign the package manually to set an end", 409)
		}
		value := input.Get("expiresAt")
		if isUndefined(value) {
			return nil, invalidInput("expiresAt is required (null for no end)")
		}
		if value == nil {
			value = core.Undefined
		}
		expiresAt, err := assignmentEnd(server, pkg, value)
		if err != nil {
			return nil, err
		}
		// Lengthening is granting: it needs the rights `assign` needs, and the bindings move to the extender's
		// authority so the longer grant is bounded by what the extender may give. Those rights are checked for the
		// package's current contents, so only records of those roles and groups are lengthened (and moved); the rest
		// keep their end and authority (retimeAssignment). Shortening needs no more than iam:packages:assign, like
		// revoking.
		if endOf(expiresAt) > endOf(assignment.Get("expiresAt")) {
			authority, err := AuthorizePackage(ctx, server, tx, principal, pkg, core.NewObject("groupAuthorities", true))
			if err != nil {
				return nil, err
			}
			if authority != nil {
				roleIDs := flowStrings(pkg.Get("roleIds"))
				for _, bindingID := range flowStrings(assignment.Get("bindingIds")) {
					binding, err := tx.Get(ctx, "bindings", bindingID)
					if err != nil {
						return nil, err
					}
					if !core.StrictEquals(member(binding, "packageAssignmentId"), assignment.Get("id")) ||
						core.StrictEquals(binding.Get("authorityId"), authority.Get("id")) ||
						!containsString(roleIDs, jsString(binding.Get("roleId"))) {
						continue
					}
					if _, err := tx.Put(ctx, "bindings", binding.Spread(core.NewObject(
						"authorityId", authority.Get("id"),
						"uniqueKey", jsString(binding.Get("subjectType"))+":"+jsString(binding.Get("subjectId"))+":"+jsString(binding.Get("roleId"))+":"+
							jsString(authority.Get("id"))+":package:"+jsString(assignment.Get("id")),
					))); err != nil {
						return nil, err
					}
				}
			}
		}
		updated, err := RetimeAssignment(ctx, server, tx, pkg, assignment, packageEndPointer(expiresAt), nil)
		if err != nil {
			return nil, err
		}
		metadata := core.NewObject(
			"packageId", pkg.Get("id"),
			"packageName", pkg.Get("name"),
			"identityId", assignment.Get("identityId"),
		)
		if previous := assignment.Get("expiresAt"); !isUndefined(previous) {
			metadata.Set("previousExpiresAt", previous)
		}
		if !isUndefined(expiresAt) {
			metadata.Set("expiresAt", expiresAt)
		}
		if err := server.Events.Audit(ctx, tx, principal, "package:extend", tenantID, jsString(pkg.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		summaries, err := summarize(ctx, server, tx, []*core.Object{updated})
		if err != nil {
			return nil, err
		}
		return summaries[0], nil
	}, false)
	if err != nil {
		return Out[apitypes.PackagesExtendOutput]{}, err
	}
	return Out[apitypes.PackagesExtendOutput]{Value: result}, nil
}

// Get is POST {basePath}/packages/get. Returns one package with its live holder counts and, for a rule package, the rule's state.
func (api *PackagesAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesGetInput]) (Out[apitypes.PackagesGetOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:packages:read", jsString(input.Get("packageId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		pkg, err := server.Scoped(ctx, call.Tx, "accessPackages", input.Get("packageId"), packagesTenantID(input.Body))
		if err != nil {
			return nil, err
		}
		return packagePublicView(ctx, server, call.Tx, pkg, nil)
	}, false)
	if err != nil {
		return Out[apitypes.PackagesGetOutput]{}, err
	}
	return Out[apitypes.PackagesGetOutput]{Value: result}, nil
}

// List is POST {basePath}/packages/list. Lists the tenant's packages by name, each with its live holder counts.
func (api *PackagesAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesListInput]) (Out[apitypes.PackagesListOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:packages:read", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) ([]any, error) {
		tx := call.Tx
		packages, err := tx.Find(ctx, "accessPackages", core.NewObject("tenantId", input.Get("tenantId")), nil)
		if err != nil {
			return nil, err
		}
		slices.SortStableFunc(packages, packageByName)
		listed := []any{}
		var env *core.Object
		for _, pkg := range packages {
			ruled := truthy(pkg.Get("autoAssign"))
			if ruled && env == nil {
				env, err = RuleEnvironment(ctx, server, tx, pkg)
				if err != nil {
					return nil, err
				}
			}
			var own *core.Object
			if ruled {
				own = env.Spread(core.NewObject("packagedGroups", stringsOf(unique(flowStrings(pkg.Get("groupIds"))))))
			}
			view, err := packagePublicView(ctx, server, tx, pkg, own)
			if err != nil {
				return nil, err
			}
			listed = append(listed, view)
		}
		return listed, nil
	}, false)
	if err != nil {
		return Out[apitypes.PackagesListOutput]{}, err
	}
	return Out[apitypes.PackagesListOutput]{Value: result}, nil
}

// ListApprovals is POST {basePath}/packages/listApprovals. Lists the pending package requests you may decide on.
func (api *PackagesAPI) ListApprovals(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesListApprovalsInput]) (Out[apitypes.PackagesListApprovalsOutput], error) {
	server := api.server
	tenantID := packagesTenantID(input.Body)
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:packages:approve", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) ([]any, error) {
		tx, principal := call.Tx, call.Principal
		now := float64(server.Now())
		packages := map[string]*core.Object{}
		pending := []*core.Object{}
		requests, err := tx.Find(ctx, "packageRequests", core.NewObject("tenantId", input.Get("tenantId"), "status", "pending"), nil)
		if err != nil {
			return nil, err
		}
		for _, request := range requests {
			if !pendingRequest(request, now) || core.StrictEquals(request.Get("identityId"), principal.Identity.Get("id")) {
				continue
			}
			packageID := jsString(request.Get("packageId"))
			if _, ok := packages[packageID]; !ok {
				pkg, err := tx.Get(ctx, "accessPackages", packageID)
				if err != nil {
					return nil, err
				}
				decidable := false
				if truthy(member(pkg, "requestable")) {
					decision, err := server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
						TenantID: tenantID, Action: "iam:packages:approve", Resource: ResourceTarget{Type: "iam", ID: jsString(pkg.Get("id"))},
					}, true)
					if err != nil {
						return nil, err
					}
					decidable = decision.Allowed
				}
				if decidable {
					packages[packageID] = pkg
				} else {
					packages[packageID] = nil
				}
			}
			pkg := packages[packageID]
			if pkg == nil {
				continue
			}
			may, err := mayApprove(ctx, server, tx, pkg, principal, request.Get("identityId"))
			if err != nil {
				return nil, err
			}
			if may {
				pending = append(pending, request)
			}
		}
		summaries, err := summarizeRequests(ctx, tx, pending, now)
		if err != nil {
			return nil, err
		}
		return objectList(summaries), nil
	}, false)
	if err != nil {
		return Out[apitypes.PackagesListApprovalsOutput]{}, err
	}
	return Out[apitypes.PackagesListApprovalsOutput]{Value: result}, nil
}

// ListAssignments is POST {basePath}/packages/listAssignments. Lists the holders of a package, or the packages of a person, newest first.
func (api *PackagesAPI) ListAssignments(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesListAssignmentsInput]) (Out[apitypes.PackagesListAssignmentsOutput], error) {
	server := api.server
	tenantID := packagesTenantID(input.Body)
	resourceID := coalesce(input.Get("packageId"), input.Get("tenantId"))
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:packages:read", jsString(resourceID), func(ctx context.Context, call MutationContext) ([]any, error) {
		tx := call.Tx
		source := input.Get("source")
		if !isUndefined(source) && source != "automatic" && source != "manual" {
			return nil, invalidInput("source must be automatic or manual")
		}
		filter := core.NewObject("tenantId", input.Get("tenantId"))
		if packageID := input.Get("packageId"); !isUndefined(packageID) {
			if _, err := server.Scoped(ctx, tx, "accessPackages", packageID, tenantID); err != nil {
				return nil, err
			}
			filter.Set("packageId", packageID)
		}
		if identityID := input.Get("identityId"); !isUndefined(identityID) {
			text, err := Text(identityID, "identityId")
			if err != nil {
				return nil, err
			}
			filter.Set("identityId", text)
		}
		records, err := tx.Find(ctx, "packageAssignments", filter, nil)
		if err != nil {
			return nil, err
		}
		includeExpired := input.Get("includeExpired") == true
		var assignments []*core.Object
		for _, assignment := range records {
			if (includeExpired || liveAssignment(server, assignment)) &&
				(isUndefined(source) || (source == "automatic") == !isUndefined(assignment.Get("ruleRevision"))) {
				assignments = append(assignments, assignment)
			}
		}
		summaries, err := summarize(ctx, server, tx, assignments)
		if err != nil {
			return nil, err
		}
		return objectList(summaries), nil
	}, false)
	if err != nil {
		return Out[apitypes.PackagesListAssignmentsOutput]{}, err
	}
	return Out[apitypes.PackagesListAssignmentsOutput]{Value: result}, nil
}

// ListMine is POST {basePath}/packages/listMine. Returns your self-service view: the requestable packages with your status on each, your assignments, and your recent requests.
func (api *PackagesAPI) ListMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesListMineInput]) (Out[apitypes.PackagesListMineOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:packages:request", jsString(input.Get("tenantId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := input.Get("tenantId")
		identityID := principal.Identity.Get("id")
		now := float64(server.Now())
		roles, err := tx.Find(ctx, "roles", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		roleNames := map[string]any{}
		for _, role := range roles {
			roleNames[jsString(role.Get("id"))] = role.Get("name")
		}
		groups, err := tx.Find(ctx, "groups", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		groupNames := map[string]any{}
		for _, group := range groups {
			groupNames[jsString(group.Get("id"))] = group.Get("name")
		}
		nameOf := func(names map[string]any, id string) any {
			if name, ok := names[id]; ok && !nullish(name) {
				return name
			}
			return id
		}
		held, err := tx.Find(ctx, "packageAssignments", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
		if err != nil {
			return nil, err
		}
		var live []*core.Object
		for _, assignment := range held {
			if liveAssignment(server, assignment) {
				live = append(live, assignment)
			}
		}
		assignments, err := summarize(ctx, server, tx, live)
		if err != nil {
			return nil, err
		}
		mine, err := tx.Find(ctx, "packageRequests", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
		if err != nil {
			return nil, err
		}
		requests, err := summarizeRequests(ctx, tx, mine, now)
		if err != nil {
			return nil, err
		}
		if len(requests) > 50 {
			requests = requests[:50]
		}
		all, err := tx.Find(ctx, "accessPackages", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		var requestable []*core.Object
		for _, pkg := range all {
			if truthy(pkg.Get("requestable")) {
				requestable = append(requestable, pkg)
			}
		}
		slices.SortStableFunc(requestable, packageByName)
		packages := []any{}
		for _, pkg := range requestable {
			rest := pkg.Spread()
			for _, key := range []string{"uniqueKey", "autoAssign", "roleIds", "groupIds"} {
				rest.Delete(key)
			}
			roleList := []any{}
			for _, roleID := range flowStrings(pkg.Get("roleIds")) {
				roleList = append(roleList, core.NewObject("id", roleID, "name", nameOf(roleNames, roleID)))
			}
			groupList := []any{}
			for _, groupID := range flowStrings(pkg.Get("groupIds")) {
				groupList = append(groupList, core.NewObject("id", groupID, "name", nameOf(groupNames, groupID)))
			}
			view := rest.Spread(core.NewObject("roles", roleList, "groups", groupList))
			if approverGroupID := pkg.Get("approverGroupId"); !isUndefined(approverGroupID) {
				view.Set("approverGroupName", nameOf(groupNames, jsString(approverGroupID)))
			}
			var assignment any = core.Undefined
			for _, candidate := range assignments {
				if core.StrictEquals(candidate.Get("packageId"), pkg.Get("id")) {
					assignment = candidate
					break
				}
			}
			view.Set("assignment", assignment)
			var pending any = core.Undefined
			for _, candidate := range requests {
				if core.StrictEquals(candidate.Get("packageId"), pkg.Get("id")) && pendingRequest(candidate, now) {
					pending = candidate
					break
				}
			}
			view.Set("pending", pending)
			packages = append(packages, view)
		}
		return core.NewObject("packages", packages, "assignments", objectList(assignments), "requests", objectList(requests)), nil
	}, false)
	if err != nil {
		return Out[apitypes.PackagesListMineOutput]{}, err
	}
	return Out[apitypes.PackagesListMineOutput]{Value: result}, nil
}

// ListRequests is POST {basePath}/packages/listRequests. Lists package requests for a package or a person, newest first, optionally by status.
func (api *PackagesAPI) ListRequests(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesListRequestsInput]) (Out[apitypes.PackagesListRequestsOutput], error) {
	server := api.server
	tenantID := packagesTenantID(input.Body)
	resourceID := coalesce(input.Get("packageId"), input.Get("tenantId"))
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:packages:read", jsString(resourceID), func(ctx context.Context, call MutationContext) ([]any, error) {
		tx := call.Tx
		filter := core.NewObject("tenantId", input.Get("tenantId"))
		if packageID := input.Get("packageId"); !isUndefined(packageID) {
			if _, err := server.Scoped(ctx, tx, "accessPackages", packageID, tenantID); err != nil {
				return nil, err
			}
			filter.Set("packageId", packageID)
		}
		if identityID := input.Get("identityId"); !isUndefined(identityID) {
			text, err := Text(identityID, "identityId")
			if err != nil {
				return nil, err
			}
			filter.Set("identityId", text)
		}
		status := input.Get("status")
		if !isUndefined(status) {
			text, ok := status.(string)
			if !ok || !packageRequestStatuses.Has(text) {
				return nil, invalidInput("Invalid status")
			}
		}
		// Filtered on the reported status, so a lapsed request counts as expired before the worker marks it.
		records, err := tx.Find(ctx, "packageRequests", filter, nil)
		if err != nil {
			return nil, err
		}
		summaries, err := summarizeRequests(ctx, tx, records, float64(server.Now()))
		if err != nil {
			return nil, err
		}
		out := []any{}
		for _, summary := range summaries {
			if isUndefined(status) || core.StrictEquals(summary.Get("status"), status) {
				out = append(out, summary)
			}
		}
		return out, nil
	}, false)
	if err != nil {
		return Out[apitypes.PackagesListRequestsOutput]{}, err
	}
	return Out[apitypes.PackagesListRequestsOutput]{Value: result}, nil
}

// PreviewAutoAssign is POST {basePath}/packages/previewAutoAssign. Shows what a package rule matches and, for a package, what a reconcile would change, without writing anything.
func (api *PackagesAPI) PreviewAutoAssign(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesPreviewAutoAssignInput]) (Out[apitypes.PackagesPreviewAutoAssignOutput], error) {
	server := api.server
	resourceID := coalesce(input.Get("packageId"), input.Get("tenantId"))
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:packages:read", jsString(resourceID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return PreviewRule(ctx, server, call.Tx, call.Principal, input.Body)
	}, false)
	if err != nil {
		return Out[apitypes.PackagesPreviewAutoAssignOutput]{}, err
	}
	return Out[apitypes.PackagesPreviewAutoAssignOutput]{Value: result}, nil
}

// packagesPrepared is what packages.reconcile checks inside its operation before the reconciler runs.
type packagesPrepared struct {
	limit     float64
	principal *Principal
}

// Reconcile is POST {basePath}/packages/reconcile. Runs the package-rule reconciler now for the tenant or one package, optionally confirming held-back changes.
func (api *PackagesAPI) Reconcile(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesReconcileInput]) (Out[apitypes.PackagesReconcileOutput], error) {
	server := api.server
	tenantID := packagesTenantID(input.Body)
	resourceID := coalesce(input.Get("packageId"), input.Get("tenantId"))
	prepared, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:packages:assign", jsString(resourceID), func(ctx context.Context, call MutationContext) (*packagesPrepared, error) {
		tx, principal := call.Tx, call.Principal
		packageID := input.Get("packageId")
		if !isUndefined(packageID) {
			if _, err := server.Scoped(ctx, tx, "accessPackages", packageID, tenantID); err != nil {
				return nil, err
			}
		}
		limit, err := Integer(coalesce(input.Get("limit"), 1000.0), "limit", 1, 10000)
		if err != nil {
			return nil, err
		}
		confirm := input.Get("confirm")
		if !isUndefined(confirm) {
			if _, err := packageBoolean(confirm, "confirm"); err != nil {
				return nil, err
			}
		}
		if confirm == true {
			if isUndefined(packageID) {
				return nil, invalidInput("confirm needs packageId")
			}
			pkg, err := tx.Get(ctx, "accessPackages", jsString(packageID))
			if err != nil {
				return nil, err
			}
			if !truthy(member(pkg, "autoAssign")) {
				return nil, core.NewIamError("INVALID_TRANSITION", "This package has no rule", 409)
			}
			// A confirmer must be able to grant the package by hand.
			if _, err := AuthorizePackage(ctx, server, tx, principal, pkg, core.NewObject("groupAuthorities", true)); err != nil {
				return nil, err
			}
		}
		return &packagesPrepared{limit: limit, principal: principal}, nil
	}, false)
	if err != nil {
		return Out[apitypes.PackagesReconcileOutput]{}, err
	}
	options := core.NewObject("tenantId", input.Get("tenantId"))
	if packageID := input.Get("packageId"); !isUndefined(packageID) {
		options.Set("packageId", packageID)
	}
	options.Set("limit", prepared.limit)
	options.Set("trigger", "manual")
	options.Set("requestedBy", prepared.principal.Identity.Get("id"))
	if input.Get("confirm") == true {
		options.SetRaw("confirmedBy", prepared.principal)
	}
	result, err := ReconcilePackageRules(ctx, server, options)
	if err != nil {
		return Out[apitypes.PackagesReconcileOutput]{}, err
	}
	return Out[apitypes.PackagesReconcileOutput]{Value: result}, nil
}

// Request is POST {basePath}/packages/request. Asks for a requestable package for yourself; approvers are notified and one of them decides.
func (api *PackagesAPI) Request(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesRequestInput]) (Out[apitypes.PackagesRequestOutput], error) {
	server := api.server
	tenantID := packagesTenantID(input.Body)
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:packages:request", jsString(input.Get("packageId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		pkg, err := server.Scoped(ctx, tx, "accessPackages", input.Get("packageId"), tenantID)
		if err != nil {
			return nil, err
		}
		if !truthy(pkg.Get("requestable")) {
			return nil, core.NewIamError("INVALID_TRANSITION", "This package cannot be requested", 409)
		}
		if !ActsInOwnRight(principal.Session) || !core.StrictEquals(principal.Session.Get("tenantId"), input.Get("tenantId")) {
			return nil, invalidInput("Requests are made from an ordinary session of the target tenant")
		}
		if truthy(principal.Session.Get("impersonatorId")) {
			return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "Packages cannot be requested while impersonating", 403)
		}
		identityID := jsString(principal.Identity.Get("id"))
		now := float64(server.Now())
		held, err := packageFirst(ctx, tx, "packageAssignments", core.NewObject(
			"tenantId", tenantID, "uniqueKey", jsString(pkg.Get("id"))+":"+identityID,
		))
		if err != nil {
			return nil, err
		}
		if held != nil && liveAssignment(server, held) {
			broken, err := assignmentBroken(ctx, server, tx, held)
			if err != nil {
				return nil, err
			}
			if !broken {
				return nil, core.NewIamError("CONFLICT", "You already hold this package", 409)
			}
		}
		open, err := tx.Find(ctx, "packageRequests", core.NewObject(
			"tenantId", tenantID, "packageId", pkg.Get("id"), "identityId", principal.Identity.Get("id"), "status", "pending",
		), nil)
		if err != nil {
			return nil, err
		}
		for _, request := range open {
			if pendingRequest(request, now) {
				return nil, core.NewIamError("CONFLICT", "Your request is still awaiting a decision", 409)
			}
		}
		desiredExpiresAt, err := assignmentEnd(server, pkg, input.Get("expiresAt"))
		if err != nil {
			return nil, err
		}
		justification, err := justificationFor(pkg, input.Get("justification"))
		if err != nil {
			return nil, err
		}
		// A request that names its approvers must reach at least one who can act on it.
		recipients, err := approverIDs(ctx, server, tx, pkg, identityID)
		if err != nil {
			return nil, err
		}
		var approvers []*core.Object
		for _, approverID := range recipients.Values() {
			approver, err := tx.Get(ctx, "identities", approverID)
			if err != nil {
				return nil, err
			}
			if member(approver, "status") == "active" {
				approvers = append(approvers, approver)
			}
		}
		if (truthy(pkg.Get("approverGroupId")) || truthy(pkg.Get("managerApproval"))) && len(approvers) == 0 {
			return nil, core.NewIamError("INVALID_TRANSITION", "Nobody can approve this request: the approver group is empty and you have no active manager", 409)
		}
		lifetime := jsNumber(coalesce(member(tenant.Get("accessPolicy"), "approvalLifetimeMs"), float64(DefaultApprovalLifetimeMs)))
		request := core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"packageId", pkg.Get("id"),
			"identityId", principal.Identity.Get("id"),
			"status", "pending",
			"requestedAt", now,
			// A request cannot outlive the access it asks for.
			"expiresAt", math.Min(now+lifetime, endOf(desiredExpiresAt)),
		)
		if !isUndefined(desiredExpiresAt) {
			request.Set("desiredExpiresAt", desiredExpiresAt)
		}
		if !isUndefined(justification) {
			request.Set("justification", justification)
		}
		if _, err := tx.Insert(ctx, "packageRequests", request); err != nil {
			return nil, err
		}
		metadata := core.NewObject(
			"requestId", request.Get("id"),
			"packageId", pkg.Get("id"),
			"packageName", pkg.Get("name"),
			"lapsesAt", request.Get("expiresAt"),
		)
		if !isUndefined(desiredExpiresAt) {
			metadata.Set("desiredExpiresAt", desiredExpiresAt)
		}
		if !isUndefined(justification) {
			metadata.Set("justification", justification)
		}
		if err := server.Events.Audit(ctx, tx, principal, "package:request", tenantID, jsString(pkg.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		for _, approver := range approvers {
			payload := core.NewObject(
				"requestId", request.Get("id"),
				"packageId", pkg.Get("id"),
				"packageName", pkg.Get("name"),
				"requesterName", principal.Identity.Get("name"),
			)
			if email := principal.Identity.Get("email"); truthy(email) {
				payload.Set("requesterEmail", email)
			}
			payload.Set("lapsesAt", jsString(request.Get("expiresAt")))
			if !isUndefined(desiredExpiresAt) {
				payload.Set("expiresAt", jsString(desiredExpiresAt))
			}
			if !isUndefined(justification) {
				payload.Set("justification", justification)
			}
			if err := packageNotify(ctx, server, tx, tenantID, approver.Get("email"), "package-request", payload); err != nil {
				return nil, err
			}
		}
		summaries, err := summarizeRequests(ctx, tx, []*core.Object{request}, now)
		if err != nil {
			return nil, err
		}
		return summaries[0], nil
	}, false)
	if err != nil {
		return Out[apitypes.PackagesRequestOutput]{}, err
	}
	return Out[apitypes.PackagesRequestOutput]{Value: result}, nil
}

// Revoke is POST {basePath}/packages/revoke. Removes a package from a person, taking away exactly the bindings and memberships the assignment still owns.
func (api *PackagesAPI) Revoke(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesRevokeInput]) (Out[apitypes.PackagesRevokeOutput], error) {
	server := api.server
	tenantID := packagesTenantID(input.Body)
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:packages:assign", jsString(input.Get("packageId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		pkg, err := server.Scoped(ctx, tx, "accessPackages", input.Get("packageId"), tenantID)
		if err != nil {
			return nil, err
		}
		identityID, err := Text(input.Get("identityId"), "identityId")
		if err != nil {
			return nil, err
		}
		assignment, err := packageFirst(ctx, tx, "packageAssignments", core.NewObject(
			"tenantId", tenantID, "uniqueKey", jsString(pkg.Get("id"))+":"+identityID,
		))
		if err != nil {
			return nil, err
		}
		if assignment == nil {
			return nil, core.NewIamError("NOT_FOUND", "The package is not assigned to this identity", 404)
		}
		if !isUndefined(assignment.Get("ruleRevision")) && truthy(pkg.Get("autoAssign")) && liveAssignment(server, assignment) {
			return nil, core.NewIamError("INVALID_TRANSITION",
				`Assigned by the package rule: exclude the person in the rule (exclude: [{ StringEquals: { "principal.id": "`+jsString(assignment.Get("identityId"))+
					`" } }]), change their attributes, or assign the package manually to take it over`, 409)
		}
		counts, err := RevokeAssignment(ctx, server, tx, assignment)
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "package:revoke", tenantID, jsString(pkg.Get("id")), "allow", false, core.NewObject(
			"packageId", pkg.Get("id"),
			"packageName", pkg.Get("name"),
			"identityId", assignment.Get("identityId"),
		).Assign(counts)); err != nil {
			return nil, err
		}
		return core.NewObject("revoked", true).Assign(counts), nil
	}, false)
	if err != nil {
		return Out[apitypes.PackagesRevokeOutput]{}, err
	}
	return Out[apitypes.PackagesRevokeOutput]{Value: result}, nil
}

// Update is POST {basePath}/packages/update. Changes a package's name, description, contents, request settings, or rule.
func (api *PackagesAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.PackagesUpdateInput]) (Out[apitypes.PackagesUpdateOutput], error) {
	server := api.server
	tenantID := packagesTenantID(input.Body)
	var ruled *core.Object
	var requestedBy any
	view, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:packages:update", jsString(input.Get("packageId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		before, err := server.Scoped(ctx, tx, "accessPackages", input.Get("packageId"), tenantID)
		if err != nil {
			return nil, err
		}
		pkg, err := UpdatePackage(ctx, server, tx, before, input.Body, principal)
		if err != nil {
			return nil, err
		}
		touched := !core.StrictEquals(member(before.Get("autoAssign"), "updatedAt"), member(pkg.Get("autoAssign"), "updatedAt")) ||
			truthy(before.Get("autoAssign")) != truthy(pkg.Get("autoAssign"))
		if touched {
			if truthy(pkg.Get("autoAssign")) {
				approved, err := ApproveRule(ctx, server, tx, pkg)
				if err != nil {
					return nil, err
				}
				pkg, _ = approved.Get("pkg").(*core.Object)
			}
			ruled, requestedBy = pkg, principal.Identity.Get("id")
		}
		return packagePublicView(ctx, server, tx, pkg, nil)
	}, false)
	if err != nil {
		return Out[apitypes.PackagesUpdateOutput]{}, err
	}
	if ruled == nil {
		return Out[apitypes.PackagesUpdateOutput]{Value: view}, nil
	}
	fresh, reconcile, err := api.afterRuleChange(ctx, ruled, requestedBy)
	if err != nil {
		return Out[apitypes.PackagesUpdateOutput]{}, err
	}
	return Out[apitypes.PackagesUpdateOutput]{Value: withReconcile(fresh, reconcile)}, nil
}
