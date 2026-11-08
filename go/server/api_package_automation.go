package server

// Port of packages/server/src/api/package-automation.ts: the reconciler of automatic (birthright) access packages:
// plans, per package, which identities should gain, keep, or lose the package under its rule, and applies each change
// in its own transaction under the rule owner's grant authority. Runs after identity changes and rule saves
// (post-commit), on demand, and as a scheduler job.
//
// Trust: a rule grants under its owner's authority to whoever matches, so whoever can change the facts it tests
// chooses the recipients, with no grant rights of their own. Declared attributes and managerId are set with
// iam:identities:update, and members of a group without role bindings with iam:groups:update alone; rules keyed on
// them are only as safe as those permissions (RuleWarnings says so on every such clause). Facts access packages
// create never count: package memberships, and team memberships synced from them (identityFacts, org_rules.go), so
// rules never chain onto another package or keep themselves alive.

import (
	"context"
	"math"
	"slices"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// ruleIdentityFacts is IdentityFacts: what one identity brings to a package's rule.
type ruleIdentityFacts struct {
	identity *core.Object
	// directGroupIDs are the live memberships no access package owns, with team backing groups only through a team
	// membership that counts: what a rule sees as identity.groups.
	directGroupIDs []string
	// org is what a rule sees as identity.teams, identity.departments and identity.licenses (org_rules.go).
	org         *core.Object
	memberships []*core.Object
	bindings    []*core.Object
	assignment  *core.Object
}

// ruleIssueMap is a JavaScript Map of package rule issues by uniqueKey (insertion order kept).
type ruleIssueMap struct {
	keys   []string
	values map[string]*core.Object
}

func newRuleIssueMap() *ruleIssueMap { return &ruleIssueMap{values: map[string]*core.Object{}} }

func (m *ruleIssueMap) set(key string, value *core.Object) {
	if _, ok := m.values[key]; !ok {
		m.keys = append(m.keys, key)
	}
	m.values[key] = value
}

func (m *ruleIssueMap) get(key string) *core.Object { return m.values[key] }

func (m *ruleIssueMap) has(key string) bool {
	_, ok := m.values[key]
	return ok
}

func (m *ruleIssueMap) delete(key string) {
	if _, ok := m.values[key]; !ok {
		return
	}
	delete(m.values, key)
	m.keys = slices.DeleteFunc(m.keys, func(item string) bool { return item == key })
}

// list is `[...map.values()]`.
func (m *ruleIssueMap) list() []*core.Object {
	out := make([]*core.Object, 0, len(m.keys))
	for _, key := range m.keys {
		out = append(out, m.values[key])
	}
	return out
}

// ruleTenantFacts is TenantFacts: everything the planner needs about a tenant.
type ruleTenantFacts struct {
	tenantID    string
	identities  []*core.Object
	memberships map[string][]*core.Object
	bindings    map[string][]*core.Object
	assignments map[string]*core.Object
	groupIDs    *orderedSet
	issues      *ruleIssueMap
	org         *TenantOrgFacts
}

// plannedStep is PlannedStep.
type plannedStep struct {
	packageID   string
	packageName string
	identityID  string
	change      string
	reason      string
	ruleKey     string
	matchedBy   []string
	hasIssue    bool
}

// planCounts is PackagePlan['counts'].
type planCounts struct {
	assign, refresh, restore, ending, revoke int
	manual, frozen, keep, matching, excluded int
	revokeRuleCleared                        int
}

func (c *planCounts) add(name string) {
	switch name {
	case "assign":
		c.assign++
	case "refresh":
		c.refresh++
	case "restore":
		c.restore++
	case "ending":
		c.ending++
	case "revoke":
		c.revoke++
	case "manual":
		c.manual++
	case "frozen":
		c.frozen++
	case "keep":
		c.keep++
	}
}

// packagePlan is PackagePlan.
type packagePlan struct {
	steps  []plannedStep
	counts planCounts
}

// ruleHealthResult is Health.
type ruleHealthResult struct {
	ok        bool
	principal *Principal
	authority *core.Object
	reason    string
	detail    string
}

// ruleRunState is the `{ principal?, authority? }` a step applies under.
type ruleRunState struct {
	principal *Principal
	authority *core.Object
}

// additiveChanges is `additive`.
var additiveChanges = newOrderedSet("assign", "refresh", "restore")

// ruleKeyOf is ruleKeyOf: `${rule.revision}:${rule.updatedAt}`, or 'none'.
func ruleKeyOf(rule *core.Object) string {
	if rule == nil {
		return "none"
	}
	return jsString(rule.Get("revision")) + ":" + jsString(rule.Get("updatedAt"))
}

func issueKeyFailed(packageID, identityID string) string {
	return packageID + ":identity:" + identityID
}
func issueKeySuspended(packageID string) string         { return packageID + ":suspended" }
func issueKeyBraked(packageID, direction string) string { return packageID + ":braked:" + direction }

// autoAssignOf is `pkg.autoAssign` (nil when absent).
func autoAssignOf(pkg *core.Object) *core.Object {
	rule, _ := member(pkg, "autoAssign").(*core.Object)
	return rule
}

// sameScalar is `a === b` for scalar model values.
func sameScalar(a, b any) bool {
	switch a.(type) {
	case nil, core.UndefinedType, bool, float64, string:
	default:
		return false
	}
	switch b.(type) {
	case nil, core.UndefinedType, bool, float64, string:
	default:
		return false
	}
	return a == b
}

// endOfValue is endOf over a stored `expiresAt` member.
func endOfValue(value any) (float64, error) {
	if number, ok := value.(float64); ok {
		return EndOf(&number)
	}
	return EndOf(nil)
}

// ruleErrorCode is `error instanceof IamError ? error.code : 'ERROR'`.
func ruleErrorCode(err error) string {
	if known, ok := asIamError(err); ok {
		return known.Code
	}
	return "ERROR"
}

// loadRuleFacts is loadFacts: everything the planner needs about a tenant, read once per collection (the store loads
// every row anyway). identityIDs nil reads every identity.
func loadRuleFacts(ctx context.Context, server *ServerContext, reader core.IamStore, tenantID string, identityIDs []string) (*ruleTenantFacts, error) {
	var wanted *orderedSet
	if identityIDs != nil {
		wanted = newOrderedSet(identityIDs...)
	}
	found, err := reader.Find(ctx, "identities", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	identities := []*core.Object{}
	for _, identity := range found {
		if identity.Get("status") != "deleted" && (wanted == nil || wanted.Has(jsString(identity.Get("id")))) {
			identities = append(identities, identity)
		}
	}
	slices.SortStableFunc(identities, func(a, b *core.Object) int {
		if compareUTF16(jsString(a.Get("id")), jsString(b.Get("id"))) < 0 {
			return -1
		}
		return 1
	})
	memberRecords, err := reader.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	memberships := map[string][]*core.Object{}
	for _, record := range memberRecords {
		identityID := jsString(record.Get("identityId"))
		memberships[identityID] = append(memberships[identityID], record)
	}
	bindingRecords, err := reader.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "identity"), nil)
	if err != nil {
		return nil, err
	}
	bindings := map[string][]*core.Object{}
	for _, binding := range bindingRecords {
		subjectID := jsString(binding.Get("subjectId"))
		bindings[subjectID] = append(bindings[subjectID], binding)
	}
	assignmentRecords, err := reader.Find(ctx, "packageAssignments", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	assignments := map[string]*core.Object{}
	for _, assignment := range assignmentRecords {
		assignments[jsString(assignment.Get("uniqueKey"))] = assignment
	}
	groupRecords, err := reader.Find(ctx, "groups", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	groupIDs := newOrderedSet()
	for _, group := range groupRecords {
		groupIDs.Add(jsString(group.Get("id")))
	}
	issueRecords, err := reader.Find(ctx, "packageRuleIssues", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	issues := newRuleIssueMap()
	for _, issue := range issueRecords {
		issues.set(jsString(issue.Get("uniqueKey")), issue)
	}
	org, err := LoadOrgFacts(ctx, reader, tenantID, server.Now())
	if err != nil {
		return nil, err
	}
	return &ruleTenantFacts{
		tenantID: tenantID, identities: identities, memberships: memberships, bindings: bindings,
		assignments: assignments, groupIDs: groupIDs, issues: issues, org: org,
	}, nil
}

// identityRuleFacts is identityFacts.
func identityRuleFacts(server *ServerContext, facts *ruleTenantFacts, identity *core.Object, packageID string) (*ruleIdentityFacts, error) {
	identityID := jsString(identity.Get("id"))
	memberships := facts.memberships[identityID]
	if memberships == nil {
		memberships = []*core.Object{}
	}
	var live []*core.Object
	for _, record := range memberships {
		if isUndefined(record.Get("packageAssignmentId")) && server.LiveMembership(record) {
			live = append(live, record)
		}
	}
	ordinary := []string{}
	for _, record := range live {
		if isUndefined(record.Get("teamId")) {
			ordinary = append(ordinary, jsString(record.Get("groupId")))
		}
	}
	org, err := facts.org.Of(identityID, ordinary)
	if err != nil {
		return nil, err
	}
	// A team's backing group copies the team's members, and team sync copies package memberships of its source groups
	// into the team: the backing membership counts only while the team membership behind it does (org.teams holds the
	// counted teams and every team above them, exactly the teams whose backing groups that membership fills).
	teams := newOrderedSet(modelStrings(org.Get("teams"))...)
	direct := append([]string{}, ordinary...)
	for _, record := range live {
		if teamID := record.Get("teamId"); !isUndefined(teamID) && teams.Has(jsString(teamID)) {
			direct = append(direct, jsString(record.Get("groupId")))
		}
	}
	bindings := facts.bindings[identityID]
	if bindings == nil {
		bindings = []*core.Object{}
	}
	return &ruleIdentityFacts{
		identity:       identity,
		memberships:    memberships,
		directGroupIDs: direct,
		org:            org,
		bindings:       bindings,
		assignment:     facts.assignments[packageID+":"+identityID],
	}, nil
}

// incompleteAssignment is incomplete: whether an automatic assignment lacks something its package and rule call for
// (a role binding of its own under the rule's authority, a membership lasting as long as it) or holds something they
// no longer call for. The same predicate materialize satisfies, so a refresh converges in one pass.
func incompleteAssignment(server *ServerContext, pkg, rule *core.Object, f *ruleIdentityFacts) (bool, error) {
	a := f.assignment
	assignmentID := a.Get("id")
	var own []*core.Object
	for _, binding := range f.bindings {
		if sameScalar(binding.Get("packageAssignmentId"), assignmentID) && !server.ExpiredBinding(binding) {
			own = append(own, binding)
		}
	}
	roleIDs := orgStrings(pkg, "roleIds")
	authorityID := rule.Get("authorityId")
	for _, roleID := range roleIDs {
		if !slices.ContainsFunc(own, func(binding *core.Object) bool {
			return binding.Get("roleId") == roleID && sameScalar(binding.Get("authorityId"), authorityID)
		}) {
			return true, nil
		}
	}
	if slices.ContainsFunc(own, func(binding *core.Object) bool {
		return !orgIncludes(pkg.Get("roleIds"), jsString(binding.Get("roleId"))) || !sameScalar(binding.Get("authorityId"), authorityID)
	}) {
		return true, nil
	}
	for _, groupID := range orgStrings(pkg, "groupIds") {
		var found *core.Object
		for _, candidate := range f.memberships {
			if candidate.Get("groupId") == groupID && server.LiveMembership(candidate) {
				found = candidate
				break
			}
		}
		if found == nil {
			return true, nil
		}
		if !sameScalar(found.Get("packageAssignmentId"), assignmentID) {
			memberEnd, err := endOfValue(found.Get("expiresAt"))
			if err != nil {
				return false, err
			}
			assignmentEnd, err := endOfValue(a.Get("expiresAt"))
			if err != nil {
				return false, err
			}
			if memberEnd < assignmentEnd {
				return true, nil
			}
		}
	}
	return slices.ContainsFunc(f.memberships, func(record *core.Object) bool {
		return sameScalar(record.Get("packageAssignmentId"), assignmentID) && server.LiveMembership(record) &&
			!orgIncludes(pkg.Get("groupIds"), jsString(record.Get("groupId")))
	}), nil
}

// ruleDecision is what decideChange answers.
type ruleDecision struct {
	change string
	reason string
	bucket string
	match  *ruleMatchResult
}

// decideChange is decideChange: what a run should do for one identity and package, or which bucket it falls into
// when nothing.
func decideChange(server *ServerContext, pkg *core.Object, doc *core.Object, f *ruleIdentityFacts) (ruleDecision, error) {
	a := f.assignment
	live := false
	if a != nil {
		var err error
		if live, err = LiveAssignment(server, a); err != nil {
			return ruleDecision{}, err
		}
	}
	automatic := live && !isUndefined(a.Get("ruleRevision"))
	rule := autoAssignOf(pkg)
	if live && !automatic {
		return ruleDecision{bucket: "manual"}, nil
	}
	if rule == nil || doc == nil {
		if automatic {
			return ruleDecision{change: "revoke", reason: "rule-cleared"}, nil
		}
		return ruleDecision{bucket: "none"}, nil
	}
	// Disabled and expired identities are frozen: never assigned or removed by a rule (offboarding handles leavers).
	if f.identity.Get("status") != "active" || server.IdentityExpired(f.identity) {
		return ruleDecision{bucket: "frozen"}, nil
	}
	context, err := RuleContext(f.identity, f.directGroupIDs, f.org)
	if err != nil {
		return ruleDecision{}, err
	}
	match, err := ruleMatchOf(doc, f.identity, context)
	if err != nil {
		return ruleDecision{}, err
	}
	if !match.matched {
		if !automatic {
			bucket := "none"
			if len(match.matchedBy) > 0 && len(match.excludedBy) > 0 {
				bucket = "excluded"
			}
			return ruleDecision{bucket: bucket, match: &match}, nil
		}
		if !truthy(rule.Get("graceMs")) {
			return ruleDecision{change: "revoke", reason: "no-longer-matches", match: &match}, nil
		}
		if !isUndefined(a.Get("expiresAt")) {
			return ruleDecision{bucket: "ending", match: &match}, nil
		}
		return ruleDecision{change: "ending", reason: "no-longer-matches", match: &match}, nil
	}
	if !live {
		return ruleDecision{change: "assign", reason: "matches", match: &match}, nil
	}
	if !isUndefined(a.Get("expiresAt")) {
		return ruleDecision{change: "restore", reason: "matches-again", match: &match}, nil
	}
	if !sameScalar(a.Get("ruleRevision"), rule.Get("revision")) {
		return ruleDecision{change: "refresh", reason: "revision", match: &match}, nil
	}
	incomplete, err := incompleteAssignment(server, pkg, rule, f)
	if err != nil {
		return ruleDecision{}, err
	}
	if incomplete {
		return ruleDecision{change: "refresh", reason: "incomplete", match: &match}, nil
	}
	return ruleDecision{bucket: "keep", match: &match}, nil
}

// planPackage is planPackage.
func planPackage(server *ServerContext, facts *ruleTenantFacts, pkg *core.Object) (*packagePlan, error) {
	rule := autoAssignOf(pkg)
	var doc *core.Object
	if rule != nil {
		var err error
		if doc, err = RuleDocument(rule); err != nil {
			return nil, err
		}
	}
	plan := &packagePlan{steps: []plannedStep{}}
	packageID := jsString(pkg.Get("id"))
	for _, identity := range facts.identities {
		f, err := identityRuleFacts(server, facts, identity, packageID)
		if err != nil {
			return nil, err
		}
		// Orphans of a cleared rule: only identities still holding an automatic assignment matter.
		if rule == nil && !(f.assignment != nil && !isUndefined(f.assignment.Get("ruleRevision"))) {
			continue
		}
		decision, err := decideChange(server, pkg, doc, f)
		if err != nil {
			return nil, err
		}
		if decision.match != nil && decision.match.matched {
			plan.counts.matching++
		}
		if decision.bucket == "excluded" {
			plan.counts.excluded++
		}
		if decision.bucket != "" && decision.bucket != "excluded" && decision.bucket != "none" {
			if decision.bucket == "ending" {
				plan.counts.add("keep")
			} else {
				plan.counts.add(decision.bucket)
			}
		}
		if decision.change == "" {
			continue
		}
		plan.counts.add(decision.change)
		if decision.change == "revoke" && decision.reason == "rule-cleared" {
			plan.counts.revokeRuleCleared++
		}
		matchedBy := []string{}
		if decision.match != nil {
			matchedBy = decision.match.matchedBy
		}
		identityID := jsString(identity.Get("id"))
		plan.steps = append(plan.steps, plannedStep{
			packageID:   packageID,
			packageName: jsString(pkg.Get("name")),
			identityID:  identityID,
			change:      decision.change,
			reason:      decision.reason,
			ruleKey:     ruleKeyOf(rule),
			matchedBy:   matchedBy,
			hasIssue:    facts.issues.has(issueKeyFailed(packageID, identityID)),
		})
	}
	return plan, nil
}

// ruleHealth is ruleHealth: whether the rule may add anything right now: its owner is active, their grant authority
// is intact and theirs, and (with `rights`) they still hold everything assigning the package by hand needs. Runs
// outside a transaction.
func ruleHealth(ctx context.Context, server *ServerContext, reader core.IamStore, pkg *core.Object, rights bool) (ruleHealthResult, error) {
	rule := autoAssignOf(pkg)
	ownerID := jsString(rule.Get("ownerId"))
	owner, err := reader.Get(ctx, "identities", ownerID)
	if err != nil {
		return ruleHealthResult{}, err
	}
	if owner == nil || owner.Get("status") != "active" || server.IdentityExpired(owner) {
		state := "expired"
		if owner == nil || owner.Get("status") == "deleted" {
			state = "deleted"
		} else if owner.Get("status") != "active" {
			state = "disabled"
		}
		return ruleHealthResult{
			reason: "owner-inactive",
			detail: "The rule owner " + jsString(coalesce(member(owner, "name"), rule.Get("ownerId"))) + " is " + state,
		}, nil
	}
	principal := server.Decisions.SimulatedPrincipal(owner, true)
	tenantID := jsString(pkg.Get("tenantId"))
	authority, failure := server.GrantingAuthority(ctx, reader, principal, tenantID, jsString(rule.Get("authorityId")))
	if failure != nil {
		return ruleHealthResult{
			reason: "authority-revoked",
			detail: "The rule owner’s grant authority is revoked or no longer theirs",
		}, nil
	}
	if rights {
		failure := Allow(ctx, server, reader, principal, tenantID, "iam:packages:assign", jsString(pkg.Get("id")), "assign this package")
		if failure == nil {
			_, failure = AuthorizePackage(ctx, server, reader, principal, pkg, core.NewObject(
				"groupAuthorities", true,
				"authorityId", rule.Get("authorityId"),
			))
		}
		if failure != nil {
			return ruleHealthResult{reason: "owner-lacks-rights", detail: errorMessage(failure)}, nil
		}
	}
	return ruleHealthResult{ok: true, principal: principal, authority: authority}, nil
}

// ruleIssue is the issue recordIssue records.
type ruleIssue struct {
	kind       string
	identityID string
	code       string
	message    string
}

// recordRuleIssue is recordIssue: records a problem once per transition (new, or a new code or revision): written
// and audited only then, so a persistent failure retried every run neither grows the audit log nor the table. Own
// transaction; never fails.
func recordRuleIssue(ctx context.Context, server *ServerContext, tenantID string, pkg *core.Object, issue ruleIssue, action string, metadata *core.Object) bool {
	packageID := jsString(pkg.Get("id"))
	var uniqueKey string
	switch issue.kind {
	case "failed":
		uniqueKey = issueKeyFailed(packageID, issue.identityID)
	case "suspended":
		uniqueKey = issueKeySuspended(packageID)
	default:
		uniqueKey = issueKeyBraked(packageID, issue.code)
	}
	var revision any = 0.0
	if rule := autoAssignOf(pkg); rule != nil {
		revision = coalesce(rule.Get("revision"), 0.0)
	}
	recorded, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (bool, error) {
		found, err := tx.Find(ctx, "packageRuleIssues", core.NewObject("tenantId", tenantID, "uniqueKey", uniqueKey), nil)
		if err != nil {
			return false, err
		}
		var existing *core.Object
		if len(found) > 0 {
			existing = found[0]
		}
		if existing != nil && existing.Get("code") == issue.code && sameScalar(existing.Get("revision"), revision) {
			return false, nil
		}
		recordID := ID()
		if existing != nil {
			recordID = jsString(existing.Get("id"))
		}
		record := core.NewObject(
			"id", recordID,
			"tenantId", tenantID,
			"uniqueKey", uniqueKey,
			"packageId", packageID,
			"kind", issue.kind,
		)
		if issue.identityID != "" {
			record.Set("identityId", issue.identityID)
		}
		record.Set("code", issue.code)
		record.Set("message", jsSlice(issue.message, 1024))
		record.Set("revision", revision)
		record.Set("since", float64(server.Now()))
		if existing != nil {
			if _, err := tx.Put(ctx, "packageRuleIssues", record); err != nil {
				return false, err
			}
		} else if _, err := tx.Insert(ctx, "packageRuleIssues", record); err != nil {
			return false, err
		}
		if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"actorId", "deployment-operator",
			"action", action,
			"resourceId", packageID,
			"timestamp", float64(server.Now()),
			"outcome", "deny",
			"metadata", metadata,
		)); err != nil {
			return false, err
		}
		return true, nil
	})
	if err != nil {
		return false
	}
	return recorded
}

// jsSlice is `text.slice(0, max)` in UTF-16 code units.
func jsSlice(text string, max int) string {
	if utf16Len(text) <= max {
		return text
	}
	return core.FromUTF16(core.ToUTF16(text)[:max])
}

// clearRuleIssues is clearIssues: deletes stored issues (own transaction; never fails).
func clearRuleIssues(ctx context.Context, server *ServerContext, ids []string) {
	if len(ids) == 0 {
		return
	}
	_ = server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		for _, issueID := range ids {
			found, err := tx.Get(ctx, "packageRuleIssues", issueID)
			if err != nil {
				return err
			}
			if found != nil {
				if err := tx.Delete(ctx, "packageRuleIssues", issueID); err != nil {
					return err
				}
			}
		}
		return nil
	})
	// A failure is retried next run.
}

// applyRuleStep is applyStep: applies one planned change in its own transaction, after re-deciding from fresh
// records: when the decision changed since planning, nothing is written ('stale'). A separation-of-duties conflict,
// or a newly broken enforced access invariant (INVARIANT_VIOLATION), that a grant would create rolls back only this
// change, which the caller records as a failed issue.
func applyRuleStep(ctx context.Context, server *ServerContext, tenantID string, step plannedStep, state ruleRunState, base *core.Object) (string, error) {
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (string, error) {
		pkg, err := tx.Get(ctx, "accessPackages", step.packageID)
		if err != nil {
			return "", err
		}
		if pkg == nil || pkg.Get("tenantId") != tenantID || ruleKeyOf(autoAssignOf(pkg)) != step.ruleKey {
			return "stale", nil
		}
		identity, err := tx.Get(ctx, "identities", step.identityID)
		if err != nil {
			return "", err
		}
		if identity == nil || identity.Get("tenantId") != tenantID || identity.Get("status") == "deleted" {
			return "stale", nil
		}
		packageID := jsString(pkg.Get("id"))
		identityID := jsString(identity.Get("id"))
		memberships, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
		if err != nil {
			return "", err
		}
		bindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "identity", "subjectId", identityID), nil)
		if err != nil {
			return "", err
		}
		assignments, err := tx.Find(ctx, "packageAssignments", core.NewObject("tenantId", tenantID, "uniqueKey", packageID+":"+identityID), nil)
		if err != nil {
			return "", err
		}
		var assignment *core.Object
		if len(assignments) > 0 {
			assignment = assignments[0]
		}
		assignmentMap := map[string]*core.Object{}
		if assignment != nil {
			assignmentMap[jsString(assignment.Get("uniqueKey"))] = assignment
		}
		org, err := LoadOrgFacts(ctx, tx, tenantID, server.Now())
		if err != nil {
			return "", err
		}
		f, err := identityRuleFacts(server, &ruleTenantFacts{
			memberships: map[string][]*core.Object{identityID: memberships},
			bindings:    map[string][]*core.Object{identityID: bindings},
			assignments: assignmentMap,
			org:         org,
		}, identity, packageID)
		if err != nil {
			return "", err
		}
		rule := autoAssignOf(pkg)
		var doc *core.Object
		if rule != nil {
			if doc, err = RuleDocument(rule); err != nil {
				return "", err
			}
		}
		decision, err := decideChange(server, pkg, doc, f)
		if err != nil {
			return "", err
		}
		if decision.change != step.change {
			return "stale", nil
		}
		var snapshot *SodSnapshotState
		if additiveChanges.Has(step.change) {
			allRules, err := tx.Find(ctx, "sodRules", core.NewObject("tenantId", tenantID), nil)
			if err != nil {
				return "", err
			}
			rules := []*core.Object{}
			for _, candidate := range allRules {
				if candidate.Get("mode") == "prevent" {
					rules = append(rules, candidate)
				}
			}
			closure := newOrderedSet(orgStrings(pkg, "roleIds")...)
			for _, groupID := range orgStrings(pkg, "groupIds") {
				groupBindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", groupID), nil)
				if err != nil {
					return "", err
				}
				for _, binding := range groupBindings {
					if !server.ExpiredBinding(binding) {
						closure.Add(jsString(binding.Get("roleId")))
					}
				}
			}
			if slices.ContainsFunc(rules, func(candidate *core.Object) bool {
				return slices.ContainsFunc(orgStrings(candidate, "roleIds"), closure.Has)
			}) {
				violations, err := SodViolations(ctx, server, tx, tenantID, rules, []string{identityID})
				if err != nil {
					return "", err
				}
				existing := map[string]bool{}
				for _, violation := range violations {
					existing[jsString(violation.Get("ruleId"))+":"+jsString(violation.Get("identityId"))] = true
				}
				snapshot = &SodSnapshotState{Rules: rules, Existing: existing}
			}
		}
		// Enforced access invariants bind automatic grants as they bind a manual assign (whose operation checks
		// them): this reconcile runs outside any operation, so it checks them itself.
		var guardrails *InvariantSnapshotState
		if additiveChanges.Has(step.change) {
			if guardrails, err = InvariantSnapshot(ctx, server, tx, tenantID, "iam:packages:assign"); err != nil {
				return "", err
			}
		}
		now := float64(server.Now())
		action := ""
		metadata := core.NewObject()
		switch step.change {
		case "assign":
			created, err := AssignPackage(ctx, server, tx, state.principal, pkg, core.NewObject("identityId", identityID), core.NewObject(
				"authority", state.authority,
				"ruleRevision", rule.Get("revision"),
			))
			if err != nil {
				return "", err
			}
			made, _ := created.Get("assignment").(*core.Object)
			bindingIDs, _ := member(made, "bindingIds").([]any)
			membershipIDs, _ := member(made, "membershipIds").([]any)
			action = "package:auto-assign"
			metadata = core.NewObject(
				"mode", "assign",
				"reason", step.reason,
				"bindings", float64(len(bindingIDs)),
				"memberships", float64(len(membershipIDs)),
				"skipped", created.Get("skipped"),
				"matchedBy", stringsOf(step.matchedBy),
			)
		case "refresh", "restore":
			current := assignment
			if step.change == "restore" {
				if current, err = RetimeAssignment(ctx, server, tx, pkg, current, nil, nil); err != nil {
					return "", err
				}
			}
			refreshed, err := RefreshAssignment(ctx, server, tx, state.principal, pkg, current, state.authority)
			if err != nil {
				return "", err
			}
			action = "package:auto-assign"
			metadata = core.NewObject(
				"mode", step.change,
				"reason", step.reason,
				"bindings", refreshed.Get("bindings"),
				"memberships", refreshed.Get("memberships"),
				"removedBindings", refreshed.Get("removedBindings"),
				"removedMemberships", refreshed.Get("removedMemberships"),
				"skipped", refreshed.Get("skipped"),
				"matchedBy", stringsOf(step.matchedBy),
			)
		case "ending":
			graceMs := jsNumber(rule.Get("graceMs"))
			endsAt := now + graceMs
			if _, err := RetimeAssignment(ctx, server, tx, pkg, assignment, &endsAt, nil); err != nil {
				return "", err
			}
			action = "package:auto-ending"
			metadata = core.NewObject("endsAt", endsAt, "graceMs", graceMs)
		case "revoke":
			counts, err := RevokeAssignment(ctx, server, tx, assignment)
			if err != nil {
				return "", err
			}
			action = "package:auto-revoke"
			metadata = core.NewObject("reason", step.reason).Assign(counts)
		}
		if err := SodVerify(ctx, server, tx, tenantID, snapshot, []string{identityID}); err != nil {
			return "", err
		}
		if err := InvariantVerify(ctx, server, tx, tenantID, guardrails); err != nil {
			return "", err
		}
		issues, err := tx.Find(ctx, "packageRuleIssues", core.NewObject("tenantId", tenantID, "uniqueKey", issueKeyFailed(packageID, identityID)), nil)
		if err != nil {
			return "", err
		}
		if len(issues) > 0 {
			if err := tx.Delete(ctx, "packageRuleIssues", jsString(issues[0].Get("id"))); err != nil {
				return "", err
			}
		}
		var revision any = 0.0
		if rule != nil {
			revision = coalesce(rule.Get("revision"), 0.0)
		}
		details := core.NewObject().Assign(base)
		details.Set("packageId", packageID)
		details.Set("packageName", pkg.Get("name"))
		details.Set("revision", revision)
		if rule != nil {
			details.Set("ownerId", rule.Get("ownerId"))
		}
		details.Set("identityId", identityID)
		details.Assign(metadata)
		if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"actorId", "deployment-operator",
			"action", action,
			"resourceId", packageID,
			"timestamp", now,
			"outcome", "allow",
			"metadata", details,
		)); err != nil {
			return "", err
		}
		return "applied", nil
	})
}

// ApproveRule (api/package-automation.ts approveRule): Writes the rule's approval: the grants and removals a run
// would make now, which unattended runs may then apply for the next day without tripping the brakes. Called when a
// person saves a rule or confirms held-back changes. The result is `{ pkg, grants, removals }`.
func ApproveRule(ctx context.Context, server *ServerContext, tx core.IamStore, pkg *core.Object) (result *core.Object, err error) {
	rule := autoAssignOf(pkg)
	unchanged := core.NewObject("pkg", pkg, "grants", 0.0, "removals", 0.0)
	if rule == nil {
		return unchanged, nil
	}
	env, err := RuleEnvironment(ctx, server, tx, pkg)
	if err != nil {
		return nil, err
	}
	problem, err := RuleProblem(rule, env)
	if err != nil {
		return nil, err
	}
	if problem != "" {
		return unchanged, nil
	}
	facts, err := loadRuleFacts(ctx, server, tx, jsString(pkg.Get("tenantId")), nil)
	if err != nil {
		return nil, err
	}
	plan, err := planPackage(server, facts, pkg)
	if err != nil {
		return nil, err
	}
	grants := float64(plan.counts.assign + plan.counts.refresh)
	removals := float64(plan.counts.ending + plan.counts.revoke - plan.counts.revokeRuleCleared)
	approvedRule := rule.Spread(core.NewObject("approved", core.NewObject(
		"grants", grants,
		"removals", removals,
		"until", float64(server.Now())+86_400_000,
	)))
	approved := pkg.Spread(core.NewObject("autoAssign", approvedRule))
	stored, err := tx.Put(ctx, "accessPackages", approved)
	if err != nil {
		return nil, err
	}
	return core.NewObject("pkg", stored, "grants", grants, "removals", removals), nil
}

// boundGroups is boundGroups: the tenant's groups with role bindings, for RuleWarnings: adding members to them needs
// the bindings' authorities, not iam:groups:update alone. Read only when the rule tests identity.groups.
func boundGroups(ctx context.Context, reader core.IamStore, tenantID string, rule *core.Object) ([]any, error) {
	tested, err := RuleGroupIDs(rule)
	if err != nil {
		return nil, err
	}
	if len(tested) == 0 {
		return []any{}, nil
	}
	bindings, err := reader.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "group"), nil)
	if err != nil {
		return nil, err
	}
	set := newOrderedSet()
	for _, binding := range bindings {
		set.Add(jsString(binding.Get("subjectId")))
	}
	return stringsOf(set.Values()), nil
}

// AutoAssignView (api/package-automation.ts autoAssignView): A rule as administrators see it: owner, whether it
// runs, warnings, and the latest problems.
func AutoAssignView(ctx context.Context, server *ServerContext, reader core.IamStore, pkg *core.Object, env *core.Object) (result *core.Object, err error) {
	rule := autoAssignOf(pkg)
	ownerID := jsString(rule.Get("ownerId"))
	owner, err := reader.Get(ctx, "identities", ownerID)
	if err != nil {
		return nil, err
	}
	tenantID := jsString(pkg.Get("tenantId"))
	issues, err := reader.Find(ctx, "packageRuleIssues", core.NewObject("tenantId", pkg.Get("tenantId"), "packageId", pkg.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(issues, func(a, b *core.Object) int {
		difference := jsNumber(b.Get("since")) - jsNumber(a.Get("since"))
		switch {
		case difference < 0:
			return -1
		case difference > 0:
			return 1
		}
		return 0
	})
	suspendedReason, suspendedDetail := "", ""
	problem, err := RuleProblem(rule, env)
	if err != nil {
		return nil, err
	}
	if problem != "" {
		suspendedReason, suspendedDetail = "invalid-rule", problem
	} else if owner == nil || owner.Get("status") != "active" || server.IdentityExpired(owner) {
		suspendedReason = "owner-inactive"
		suspendedDetail = "The rule owner " + jsString(coalesce(member(owner, "name"), rule.Get("ownerId"))) + " is not active"
	} else {
		authority, err := reader.Get(ctx, "grantAuthorities", jsString(rule.Get("authorityId")))
		if err != nil {
			return nil, err
		}
		broken := authority == nil || truthy(authority.Get("revoked")) ||
			(!sameScalar(authority.Get("identityId"), rule.Get("ownerId")) && !truthy(authority.Get("rootIssued")))
		if !broken {
			_, intact, err := server.AuthorityChain(ctx, reader, jsString(authority.Get("id")))
			if err != nil {
				return nil, err
			}
			broken = !intact
		}
		if broken {
			suspendedReason = "authority-revoked"
			suspendedDetail = "The rule owner’s grant authority is revoked or no longer theirs"
		} else {
			for _, issue := range issues {
				if issue.Get("kind") == "suspended" && issue.Get("code") == "owner-lacks-rights" {
					suspendedReason, suspendedDetail = "owner-lacks-rights", jsString(issue.Get("message"))
					break
				}
			}
		}
	}
	latest := issues
	if len(latest) > 20 {
		latest = latest[:20]
	}
	names := map[string]any{}
	for _, issue := range latest {
		identityID := issue.Get("identityId")
		if !truthy(identityID) {
			continue
		}
		key := jsString(identityID)
		if _, seen := names[key]; seen {
			continue
		}
		identity, err := reader.Get(ctx, "identities", key)
		if err != nil {
			return nil, err
		}
		names[key] = coalesce(member(identity, "name"), identityID)
	}
	bound, err := boundGroups(ctx, reader, tenantID, rule)
	if err != nil {
		return nil, err
	}
	warnings, err := RuleWarnings(rule, core.NewObject("boundGroups", bound))
	if err != nil {
		return nil, err
	}
	view := rule.Spread()
	view.Set("ownerName", coalesce(member(owner, "name"), rule.Get("ownerId")))
	if suspendedReason != "" {
		view.Set("status", "suspended")
		view.Set("suspendedReason", suspendedReason)
		view.Set("suspendedDetail", suspendedDetail)
	} else {
		view.Set("status", "active")
	}
	view.Set("warnings", stringsOf(warnings))
	view.Set("issueCount", float64(len(issues)))
	listed := make([]any, 0, len(latest))
	for _, issue := range latest {
		entry := core.NewObject("kind", issue.Get("kind"))
		if identityID := issue.Get("identityId"); truthy(identityID) {
			entry.Set("identityId", identityID)
			entry.Set("identityName", names[jsString(identityID)])
		}
		entry.Set("code", issue.Get("code"))
		entry.Set("message", issue.Get("message"))
		entry.Set("since", issue.Get("since"))
		listed = append(listed, entry)
	}
	view.Set("issues", listed)
	return view, nil
}

// emptyReconcileResult is emptyResult.
func emptyReconcileResult(trigger any) *core.Object {
	return core.NewObject(
		"trigger", trigger,
		"assigned", 0.0,
		"refreshed", 0.0,
		"restored", 0.0,
		"ending", 0.0,
		"revoked", 0.0,
		"stale", 0.0,
		"failed", []any{},
		"suspended", []any{},
		"braked", []any{},
		"skipped", core.NewObject("inactiveTenants", 0.0, "failedTenants", []any{}),
		"truncated", false,
	)
}

// reconcileOptions is ReconcileOptions read from the options object.
type reconcileOptions struct {
	tenantID       any
	packageID      any
	identityIDs    []string
	hasIdentityIDs bool
	limit          any
	trigger        any
	// confirmedBy is nil, the string 'deployment-operator', or the confirming *Principal.
	confirmedBy any
	requestedBy any
}

func readReconcileOptions(options *core.Object) reconcileOptions {
	read := reconcileOptions{
		tenantID:    member(options, "tenantId"),
		packageID:   member(options, "packageId"),
		limit:       member(options, "limit"),
		trigger:     member(options, "trigger"),
		requestedBy: member(options, "requestedBy"),
	}
	switch ids := member(options, "identityIds").(type) {
	case []string:
		read.identityIDs, read.hasIdentityIDs = append([]string{}, ids...), true
	case []any:
		read.identityIDs, read.hasIdentityIDs = modelStrings(ids), true
	}
	switch confirmer := member(options, "confirmedBy").(type) {
	case *Principal:
		if confirmer != nil {
			read.confirmedBy = confirmer
		}
	case *auth.Principal:
		if confirmer != nil {
			read.confirmedBy = PrincipalFromAuth(confirmer)
		}
	case string:
		if confirmer != "" {
			read.confirmedBy = confirmer
		}
	}
	return read
}

// ReconcilePackageRules (api/package-automation.ts reconcilePackageRules): The reconciler. Plans from plain reads
// (no transaction), then applies each change in its own transaction under the rule owner's authority, removals
// first. Never runs inside another transaction. options holds ReconcileOptions: `tenantId?`, `packageId?`,
// `identityIds?`, `limit?`, `trigger`, `confirmedBy?` (a *Principal, set with SetRaw, or 'deployment-operator') and
// `requestedBy?`. The result is a PackageReconcileResult.
func ReconcilePackageRules(ctx context.Context, server *ServerContext, options *core.Object) (result *core.Object, err error) {
	read := readReconcileOptions(options)
	result = emptyReconcileResult(read.trigger)
	var tenants []*core.Object
	if truthy(read.tenantID) {
		tenant, err := server.Tenant(ctx, server.Store, read.tenantID)
		if err != nil {
			return nil, err
		}
		tenants = []*core.Object{tenant}
	} else {
		found, err := server.Store.Find(ctx, "tenants", core.NewObject("status", "active"), nil)
		if err != nil {
			return nil, err
		}
		slices.SortStableFunc(found, func(a, b *core.Object) int {
			if compareUTF16(jsString(a.Get("id")), jsString(b.Get("id"))) < 0 {
				return -1
			}
			return 1
		})
		tenants = found
	}
	skipped, _ := result.Get("skipped").(*core.Object)
	for _, tenant := range tenants {
		if tenant.Get("status") != "active" {
			skipped.Set("inactiveTenants", jsNumber(skipped.Get("inactiveTenants"))+1)
			continue
		}
		if failure := reconcileTenant(ctx, server, jsString(tenant.Get("id")), read, result); failure != nil {
			failedTenants, _ := skipped.Get("failedTenants").([]any)
			skipped.Set("failedTenants", append(failedTenants, core.NewObject(
				"tenantId", tenant.Get("id"),
				"code", ruleErrorCode(failure),
				"message", errorMessage(failure),
			)))
		}
	}
	return result, nil
}

// resultAdd increments a counter of a PackageReconcileResult.
func resultAdd(result *core.Object, key string) {
	result.Set(key, jsNumber(result.Get(key))+1)
}

// resultPush appends an entry to a list of a PackageReconcileResult.
func resultPush(result *core.Object, key string, entry *core.Object) {
	list, _ := result.Get(key).([]any)
	result.Set(key, append(list, entry))
}

// queuedStep is one entry of the apply queue.
type queuedStep struct {
	step  plannedStep
	state ruleRunState
}

// changeRank is rank.
func changeRank(change string) int {
	switch change {
	case "revoke":
		return 0
	case "ending":
		return 1
	case "restore":
		return 2
	case "refresh":
		return 3
	}
	return 4
}

// reconcileTenant is reconcileTenant.
func reconcileTenant(ctx context.Context, server *ServerContext, tenantID string, options reconcileOptions, result *core.Object) error {
	reader := server.Store
	now := float64(server.Now())
	all, err := reader.Find(ctx, "accessPackages", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return err
	}
	scoped := all
	if truthy(options.packageID) {
		scoped = nil
		for _, pkg := range all {
			if sameScalar(pkg.Get("id"), options.packageID) {
				scoped = append(scoped, pkg)
			}
		}
	}
	rulePackages := 0
	for _, pkg := range scoped {
		if truthy(pkg.Get("autoAssign")) {
			rulePackages++
		}
	}
	if options.trigger == "identity-change" && rulePackages == 0 {
		return nil
	}
	var identityIDs []string
	if options.hasIdentityIDs {
		identityIDs = options.identityIDs
		if identityIDs == nil {
			identityIDs = []string{}
		}
	}
	facts, err := loadRuleFacts(ctx, server, reader, tenantID, identityIDs)
	if err != nil {
		return err
	}
	orphanIDs := newOrderedSet()
	for _, assignment := range facts.assignments {
		if isUndefined(assignment.Get("ruleRevision")) {
			continue
		}
		live, err := LiveAssignment(server, assignment)
		if err != nil {
			return err
		}
		if live {
			orphanIDs.Add(jsString(assignment.Get("packageId")))
		}
	}
	packages := []*core.Object{}
	for _, pkg := range scoped {
		if truthy(pkg.Get("autoAssign")) || orphanIDs.Has(jsString(pkg.Get("id"))) {
			packages = append(packages, pkg)
		}
	}
	slices.SortStableFunc(packages, func(a, b *core.Object) int {
		if order := localeCompare(jsString(a.Get("name")), jsString(b.Get("name"))); order != 0 {
			return order
		}
		if compareUTF16(jsString(a.Get("id")), jsString(b.Get("id"))) < 0 {
			return -1
		}
		return 1
	})
	base := core.NewObject("trigger", options.trigger)
	if truthy(options.requestedBy) {
		base.Set("requestedBy", options.requestedBy)
	}
	// A confirmation approves the package's planned counts and exempts this run from the brakes.
	confirmed := false
	if options.confirmedBy != nil && truthy(options.packageID) {
		targetIndex := slices.IndexFunc(packages, func(pkg *core.Object) bool { return sameScalar(pkg.Get("id"), options.packageID) })
		if targetIndex >= 0 && autoAssignOf(packages[targetIndex]) != nil {
			target := packages[targetIndex]
			confirmer := options.confirmedBy
			err := server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
				fresh, err := tx.Get(ctx, "accessPackages", jsString(target.Get("id")))
				if err != nil {
					return err
				}
				if autoAssignOf(fresh) == nil {
					return nil
				}
				approval, err := ApproveRule(ctx, server, tx, fresh)
				if err != nil {
					return err
				}
				approvedPkg, _ := approval.Get("pkg").(*core.Object)
				metadata := core.NewObject(
					"packageId", fresh.Get("id"),
					"packageName", fresh.Get("name"),
					"grants", approval.Get("grants"),
					"removals", approval.Get("removals"),
					"until", member(member(autoAssignOf(approvedPkg), "approved"), "until"),
				)
				if principal, ok := confirmer.(*Principal); ok {
					if err := server.Events.Audit(ctx, tx, principal, "package:auto-confirm", tenantID, jsString(fresh.Get("id")), "allow", false, metadata); err != nil {
						return err
					}
				} else if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
					"id", ID(),
					"tenantId", tenantID,
					"actorId", "deployment-operator",
					"action", "package:auto-confirm",
					"resourceId", fresh.Get("id"),
					"timestamp", float64(server.Now()),
					"outcome", "allow",
					"metadata", metadata,
				)); err != nil {
					return err
				}
				packages[targetIndex] = approvedPkg
				return nil
			})
			if err != nil {
				return err
			}
			confirmed = true
		}
	}
	braked := (options.trigger == "schedule" || options.trigger == "manual") && !confirmed
	var removals, additions []queuedStep
	resolvedIssues := []string{}
	attempted := newOrderedSet()
	for _, pkg := range packages {
		rule := autoAssignOf(pkg)
		packageID := jsString(pkg.Get("id"))
		if rule != nil {
			problem, err := RuleProblem(rule, core.NewObject(
				"identityAttributes", server.Catalog.IdentityAttributes,
				"groups", stringsOf(facts.groupIDs.Values()),
				"packagedGroups", stringsOf(orgStrings(pkg, "groupIds")),
				"org", core.NewObject(
					"teams", stringsOf(facts.org.TeamIDs),
					"departments", stringsOf(facts.org.DepartmentIDs),
					"licenses", stringsOf(facts.org.LicenseKeys),
				),
			))
			if err != nil {
				return err
			}
			if problem != "" {
				// A rule that cannot be evaluated freezes everything: never "matches nobody, revoke everyone".
				resultPush(result, "suspended", core.NewObject(
					"tenantId", tenantID,
					"packageId", packageID,
					"reason", "invalid-rule",
					"detail", problem,
				))
				recordRuleIssue(ctx, server, tenantID, pkg, ruleIssue{kind: "suspended", code: "invalid-rule", message: problem}, "package:auto-suspended",
					base.Spread(core.NewObject(
						"packageId", packageID,
						"packageName", pkg.Get("name"),
						"reason", "invalid-rule",
						"detail", problem,
					)))
				continue
			}
		}
		plan, err := planPackage(server, facts, pkg)
		if err != nil {
			return err
		}
		steps := plan.steps
		state := ruleRunState{}
		if rule != nil && slices.ContainsFunc(steps, func(step plannedStep) bool { return additiveChanges.Has(step.change) }) {
			health, err := ruleHealth(ctx, server, reader, pkg, true)
			if err != nil {
				return err
			}
			suspendedKey := issueKeySuspended(packageID)
			if !health.ok {
				// Removals continue: removing access needs no authority, so leavers still lose it when the owner has
				// left.
				steps = slices.DeleteFunc(slices.Clone(steps), func(step plannedStep) bool { return additiveChanges.Has(step.change) })
				resultPush(result, "suspended", core.NewObject(
					"tenantId", tenantID,
					"packageId", packageID,
					"reason", health.reason,
					"detail", health.detail,
				))
				recordRuleIssue(ctx, server, tenantID, pkg, ruleIssue{kind: "suspended", code: health.reason, message: health.detail}, "package:auto-suspended",
					base.Spread(core.NewObject(
						"packageId", packageID,
						"packageName", pkg.Get("name"),
						"reason", health.reason,
						"detail", health.detail,
					)))
			} else {
				state = ruleRunState{principal: health.principal, authority: health.authority}
				if stored := facts.issues.get(suspendedKey); stored != nil {
					err := server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
						storedID := jsString(stored.Get("id"))
						found, err := tx.Get(ctx, "packageRuleIssues", storedID)
						if err != nil {
							return err
						}
						if found != nil {
							if err := tx.Delete(ctx, "packageRuleIssues", storedID); err != nil {
								return err
							}
						}
						return server.Events.RecordAudit(ctx, tx, core.NewObject(
							"id", ID(),
							"tenantId", tenantID,
							"actorId", "deployment-operator",
							"action", "package:auto-resumed",
							"resourceId", packageID,
							"timestamp", float64(server.Now()),
							"outcome", "allow",
							"metadata", base.Spread(core.NewObject(
								"packageId", packageID,
								"packageName", pkg.Get("name"),
								"previousReason", stored.Get("code"),
							)),
						))
					})
					if err != nil {
						return err
					}
					facts.issues.delete(suspendedKey)
				}
			}
		}
		// Brakes: unattended runs hold back unusually large changes until a person confirms them.
		if rule != nil && braked {
			approved, _ := rule.Get("approved").(*core.Object)
			if approved != nil && !(jsNumber(approved.Get("until")) > now) {
				approved = nil
			}
			approvedGrants, approvedRemovals := 0.0, 0.0
			if approved != nil {
				approvedGrants = jsNumber(coalesce(approved.Get("grants"), 0.0))
				approvedRemovals = jsNumber(coalesce(approved.Get("removals"), 0.0))
			}
			thresholds := map[string]float64{
				"grants":   math.Max(jsNumber(coalesce(rule.Get("maxGrants"), float64(DefaultMaxGrants))), approvedGrants),
				"removals": math.Max(jsNumber(coalesce(rule.Get("maxRemovals"), float64(DefaultMaxRemovals))), approvedRemovals),
			}
			isGrant := func(step plannedStep) bool { return step.change == "assign" || step.change == "refresh" }
			isRemoval := func(step plannedStep) bool {
				return step.change == "ending" || (step.change == "revoke" && step.reason == "no-longer-matches")
			}
			for _, brake := range []struct {
				direction string
				test      func(plannedStep) bool
			}{{"grants", isGrant}, {"removals", isRemoval}} {
				planned := 0
				for _, step := range steps {
					if brake.test(step) {
						planned++
					}
				}
				key := issueKeyBraked(packageID, brake.direction)
				threshold := thresholds[brake.direction]
				if float64(planned) > threshold {
					steps = slices.DeleteFunc(slices.Clone(steps), brake.test)
					resultPush(result, "braked", core.NewObject(
						"tenantId", tenantID,
						"packageId", packageID,
						"direction", brake.direction,
						"planned", float64(planned),
						"threshold", threshold,
					))
					recordRuleIssue(ctx, server, tenantID, pkg, ruleIssue{
						kind:    "braked",
						code:    brake.direction,
						message: core.NumberString(float64(planned)) + " planned, threshold " + core.NumberString(threshold),
					}, "package:auto-braked", base.Spread(core.NewObject(
						"packageId", packageID,
						"packageName", pkg.Get("name"),
						"direction", brake.direction,
						"planned", float64(planned),
						"threshold", threshold,
					)))
				} else if stored := facts.issues.get(key); stored != nil {
					resolvedIssues = append(resolvedIssues, jsString(stored.Get("id")))
				}
			}
		}
		for _, step := range steps {
			if additiveChanges.Has(step.change) {
				additions = append(additions, queuedStep{step, state})
			} else {
				removals = append(removals, queuedStep{step, state})
			}
		}
		// Failed issues whose pair needs nothing any more are resolved.
		planned := newOrderedSet()
		for _, step := range plan.steps {
			planned.Add(step.identityID)
		}
		for _, issue := range facts.issues.list() {
			identityID := issue.Get("identityId")
			if issue.Get("kind") == "failed" && sameScalar(issue.Get("packageId"), pkg.Get("id")) && truthy(identityID) &&
				!planned.Has(jsString(identityID)) {
				if slices.ContainsFunc(facts.identities, func(identity *core.Object) bool { return sameScalar(identity.Get("id"), identityID) }) {
					resolvedIssues = append(resolvedIssues, jsString(issue.Get("id")))
				}
			}
		}
	}
	// Removals first (a mover's old access goes before their new access arrives), then additions; within each,
	// changes without a stored failure come first so persistent failures never starve fresh work.
	order := func(a, b queuedStep) int {
		if a.step.hasIssue != b.step.hasIssue {
			if a.step.hasIssue {
				return 1
			}
			return -1
		}
		if byName := localeCompare(a.step.packageName, b.step.packageName); byName != 0 {
			return byName
		}
		return compareUTF16(a.step.identityID, b.step.identityID)
	}
	byRank := func(a, b queuedStep) int {
		if difference := changeRank(a.step.change) - changeRank(b.step.change); difference != 0 {
			return difference
		}
		return order(a, b)
	}
	slices.SortStableFunc(removals, byRank)
	slices.SortStableFunc(additions, byRank)
	budget := math.Inf(1)
	if options.trigger != "identity-change" {
		budget = jsNumber(coalesce(options.limit, 1000.0))
	}
	queue := append(append([]queuedStep{}, removals...), additions...)
	stepBase := base.Spread()
	if confirmed {
		stepBase.Set("confirmed", true)
	}
	for _, entry := range queue {
		if budget <= 0 {
			result.Set("truncated", true)
			break
		}
		budget--
		step := entry.step
		attempted.Add(step.packageID + ":" + step.identityID)
		outcome, failure := applyRuleStep(ctx, server, tenantID, step, entry.state, stepBase)
		if failure == nil {
			switch {
			case outcome == "stale":
				resultAdd(result, "stale")
			case step.change == "assign":
				resultAdd(result, "assigned")
			case step.change == "refresh":
				resultAdd(result, "refreshed")
			case step.change == "restore":
				resultAdd(result, "restored")
			case step.change == "ending":
				resultAdd(result, "ending")
			default:
				resultAdd(result, "revoked")
			}
			continue
		}
		if known, ok := asIamError(failure); ok && known.Code == "CONFLICT" && step.change == "assign" {
			resultAdd(result, "stale")
			continue
		}
		code := ruleErrorCode(failure)
		message := errorMessage(failure)
		resultPush(result, "failed", core.NewObject(
			"tenantId", tenantID,
			"packageId", step.packageID,
			"identityId", step.identityID,
			"change", step.change,
			"code", code,
			"message", message,
		))
		var pkg *core.Object
		for _, candidate := range packages {
			if jsString(candidate.Get("id")) == step.packageID {
				pkg = candidate
				break
			}
		}
		recordRuleIssue(ctx, server, tenantID, pkg, ruleIssue{kind: "failed", identityID: step.identityID, code: code, message: message}, "package:auto-failed",
			base.Spread(core.NewObject(
				"packageId", pkg.Get("id"),
				"packageName", pkg.Get("name"),
				"identityId", step.identityID,
				"change", step.change,
				"code", code,
				"message", message,
			)))
	}
	// Full-tenant runs also forget issues of identities or packages that are gone.
	if !options.hasIdentityIDs && !truthy(options.packageID) {
		present := newOrderedSet()
		for _, identity := range facts.identities {
			present.Add(jsString(identity.Get("id")))
		}
		byID := map[string]*core.Object{}
		for _, pkg := range all {
			byID[jsString(pkg.Get("id"))] = pkg
		}
		for _, issue := range facts.issues.list() {
			pkg := byID[jsString(issue.Get("packageId"))]
			identityID := issue.Get("identityId")
			if pkg == nil || (truthy(identityID) && !present.Has(jsString(identityID))) ||
				(issue.Get("kind") != "failed" && !truthy(pkg.Get("autoAssign"))) {
				resolvedIssues = append(resolvedIssues, jsString(issue.Get("id")))
			}
		}
	}
	issueList := facts.issues.list()
	clear := []string{}
	for _, issueID := range unique(resolvedIssues) {
		var issue *core.Object
		for _, candidate := range issueList {
			if jsString(candidate.Get("id")) == issueID {
				issue = candidate
				break
			}
		}
		if issue == nil || !truthy(issue.Get("identityId")) ||
			!attempted.Has(jsString(issue.Get("packageId"))+":"+jsString(issue.Get("identityId"))) {
			clear = append(clear, issueID)
		}
	}
	clearRuleIssues(ctx, server, clear)
	return nil
}

// AfterIdentityChange (api/package-automation.ts afterIdentityChange): Reconciles the license seats and package
// rules for identities an administrator just changed; never fails (the schedules catch up). Returns result2.
func AfterIdentityChange(ctx context.Context, server *ServerContext, tenantID string, identityIDs []string, result2 any) (result any, err error) {
	if len(identityIDs) > 0 {
		// License seats follow the change first (licenses.ts): rules on identity.licenses then see them, and people a
		// released seat moved off the waiting list are reconciled too.
		seated, failure := ReconcileLicensesOf(ctx, server, tenantID, identityIDs, "deployment-operator")
		if failure == nil {
			ids := unique(append(append([]string{}, identityIDs...), seated...))
			// The scheduled reconcile catches up after a failure.
			_, _ = ReconcilePackageRules(ctx, server, core.NewObject(
				"tenantId", tenantID,
				"identityIds", stringsOf(ids),
				"trigger", "identity-change",
			))
		}
	}
	return result2, nil
}

// PreviewRule (api/package-automation.ts previewRule): What a rule matches (stored, candidate, or neither: keys
// only) and, for a package, what a run would change. Read-only; requires iam:identities:read (checked here) to
// evaluate a rule over the directory. input is `{ tenantId, packageId?, autoAssign?, sample? }`; the result is an
// AutoAssignPreview.
func PreviewRule(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, input *core.Object) (result *core.Object, err error) {
	sample, err := Integer(coalesce(input.Get("sample"), 20.0), "sample", 1, 100)
	if err != nil {
		return nil, err
	}
	keys, err := RuleKeys(server.Catalog.IdentityAttributes, core.NewObject("org", true))
	if err != nil {
		return nil, err
	}
	tenantID := jsString(input.Get("tenantId"))
	var pkg *core.Object
	if packageID := input.Get("packageId"); !isUndefined(packageID) {
		id, err := Text(packageID, "packageId")
		if err != nil {
			return nil, err
		}
		if pkg, err = server.Scoped(ctx, tx, "accessPackages", id, tenantID); err != nil {
			return nil, err
		}
	}
	var rule *core.Object
	kind := "none"
	if candidate := input.Get("autoAssign"); !isUndefined(candidate) {
		groupRecords, err := tx.Find(ctx, "groups", core.NewObject("tenantId", input.Get("tenantId")), nil)
		if err != nil {
			return nil, err
		}
		groupIDs := newOrderedSet()
		for _, group := range groupRecords {
			groupIDs.Add(jsString(group.Get("id")))
		}
		env := core.NewObject(
			"identityAttributes", server.Catalog.IdentityAttributes,
			"groups", stringsOf(groupIDs.Values()),
		)
		if pkg != nil {
			env.Set("packagedGroups", stringsOf(orgStrings(pkg, "groupIds")))
		}
		org, err := OrgRuleEnvironment(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		env.Set("org", org)
		if rule, err = ParseAutoAssign(candidate, env, ""); err != nil {
			return nil, err
		}
		kind = "candidate"
	} else if stored := autoAssignOf(pkg); stored != nil {
		rule = stored
		kind = "stored"
	}
	keyList := make([]any, len(keys))
	for index, key := range keys {
		keyList[index] = key
	}
	if rule == nil {
		return core.NewObject(
			"rule", kind,
			"keys", keyList,
			"warnings", []any{},
			"matching", 0.0,
			"excluded", 0.0,
			"frozen", 0.0,
			"sample", []any{},
		), nil
	}
	if err := Allow(ctx, server, tx, principal, tenantID, "iam:identities:read", tenantID, "list identities"); err != nil {
		return nil, err
	}
	facts, err := loadRuleFacts(ctx, server, tx, tenantID, nil)
	if err != nil {
		return nil, err
	}
	doc, err := RuleDocument(rule)
	if err != nil {
		return nil, err
	}
	type previewMatch struct {
		entry      *core.Object
		name       string
		identityID string
	}
	matches := []previewMatch{}
	excluded, frozen := 0, 0
	packageID := ""
	if pkg != nil {
		packageID = jsString(pkg.Get("id"))
	}
	for _, identity := range facts.identities {
		if identity.Get("status") != "active" || server.IdentityExpired(identity) {
			frozen++
			continue
		}
		f, err := identityRuleFacts(server, facts, identity, packageID)
		if err != nil {
			return nil, err
		}
		context, err := RuleContext(identity, f.directGroupIDs, f.org)
		if err != nil {
			return nil, err
		}
		match, err := ruleMatchOf(doc, identity, context)
		if err != nil {
			return nil, err
		}
		if match.matched {
			entry := core.NewObject("identityId", identity.Get("id"), "name", identity.Get("name"))
			if email := identity.Get("email"); truthy(email) {
				entry.Set("email", email)
			}
			entry.Set("kind", identity.Get("kind"))
			entry.Set("matchedBy", stringsOf(match.matchedBy))
			matches = append(matches, previewMatch{entry, jsString(identity.Get("name")), jsString(identity.Get("id"))})
		} else if len(match.matchedBy) > 0 && len(match.excludedBy) > 0 {
			excluded++
		}
	}
	slices.SortStableFunc(matches, func(a, b previewMatch) int {
		if order := localeCompare(a.name, b.name); order != 0 {
			return order
		}
		if compareUTF16(a.identityID, b.identityID) < 0 {
			return -1
		}
		return 1
	})
	bound, err := boundGroups(ctx, tx, tenantID, rule)
	if err != nil {
		return nil, err
	}
	warnings, err := RuleWarnings(rule, core.NewObject("boundGroups", bound))
	if err != nil {
		return nil, err
	}
	sampled := []any{}
	for index, match := range matches {
		if float64(index) >= sample {
			break
		}
		sampled = append(sampled, match.entry)
	}
	preview := core.NewObject(
		"rule", kind,
		"keys", keyList,
		"warnings", stringsOf(warnings),
		"matching", float64(len(matches)),
		"excluded", float64(excluded),
		"frozen", float64(frozen),
		"sample", sampled,
	)
	if pkg == nil {
		return preview, nil
	}
	// What a run would change: the package with the candidate (or stored) rule, planned against the directory.
	candidate := pkg
	storedRule := autoAssignOf(pkg)
	if kind == "candidate" {
		revision := 0.0
		ownerID := any(principal.Identity.Get("id"))
		var authorityID any = ""
		if storedRule != nil {
			revision = jsNumber(coalesce(storedRule.Get("revision"), 0.0))
			ownerID = coalesce(storedRule.Get("ownerId"), ownerID)
			authorityID = coalesce(storedRule.Get("authorityId"), "")
		}
		candidate = pkg.Spread(core.NewObject("autoAssign", rule.Spread(core.NewObject(
			"ownerId", ownerID,
			"authorityId", authorityID,
			"revision", revision+1,
			"updatedAt", float64(server.Now()),
		))))
	}
	plan, err := planPackage(server, facts, candidate)
	if err != nil {
		return nil, err
	}
	names := map[string]*core.Object{}
	for _, identity := range facts.identities {
		names[jsString(identity.Get("id"))] = identity
	}
	preview.Set("plan", core.NewObject(
		"assign", float64(plan.counts.assign),
		"refresh", float64(plan.counts.refresh),
		"restore", float64(plan.counts.restore),
		"ending", float64(plan.counts.ending),
		"revoke", float64(plan.counts.revoke),
		"manual", float64(plan.counts.manual),
		"keep", float64(plan.counts.keep),
	))
	changes := []any{}
	for index, step := range plan.steps {
		if float64(index) >= sample {
			break
		}
		identity := names[step.identityID]
		entry := core.NewObject("identityId", step.identityID, "name", identity.Get("name"))
		if email := identity.Get("email"); truthy(email) {
			entry.Set("email", email)
		}
		entry.Set("change", step.change)
		changes = append(changes, entry)
	}
	preview.Set("changes", changes)
	stored := autoAssignOf(candidate)
	approved, _ := stored.Get("approved").(*core.Object)
	if approved != nil && !(jsNumber(approved.Get("until")) > float64(server.Now())) {
		approved = nil
	}
	grants := float64(plan.counts.assign + plan.counts.refresh)
	removals := float64(plan.counts.ending + plan.counts.revoke - plan.counts.revokeRuleCleared)
	approvedGrants, approvedRemovals := 0.0, 0.0
	if approved != nil {
		approvedGrants = jsNumber(coalesce(approved.Get("grants"), 0.0))
		approvedRemovals = jsNumber(coalesce(approved.Get("removals"), 0.0))
	}
	grantThreshold := math.Max(jsNumber(coalesce(stored.Get("maxGrants"), float64(DefaultMaxGrants))), approvedGrants)
	removalThreshold := math.Max(jsNumber(coalesce(stored.Get("maxRemovals"), float64(DefaultMaxRemovals))), approvedRemovals)
	preview.Set("brake", core.NewObject(
		"grants", core.NewObject("planned", grants, "threshold", grantThreshold, "trips", grants > grantThreshold),
		"removals", core.NewObject("planned", removals, "threshold", removalThreshold, "trips", removals > removalThreshold),
	))
	if storedRule != nil {
		env, err := RuleEnvironment(ctx, server, tx, pkg)
		if err != nil {
			return nil, err
		}
		view, err := AutoAssignView(ctx, server, tx, pkg, env)
		if err != nil {
			return nil, err
		}
		status := core.NewObject("status", view.Get("status"))
		if reason := view.Get("suspendedReason"); truthy(reason) {
			status.Set("reason", reason)
			status.Set("detail", view.Get("suspendedDetail"))
		}
		preview.Set("status", status)
	}
	return preview, nil
}
