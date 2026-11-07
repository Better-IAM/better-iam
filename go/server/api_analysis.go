package server

// Port of packages/server/src/api/analysis.ts: access analysis. A read-only scan of a tenant's policies, roles,
// groups, bindings, trusts, and members that reports risky or stale configuration (unrestricted administrator
// policies, administrators without a second factor, dormant members who still hold access, trusts that skip MFA, and
// unused policies, roles, and groups) plus standing administrator bindings, eligible bindings never activated, broken
// manager links, and policy lint warnings. Findings can be suppressed with a recorded reason; suppressed findings stay
// listed on request.

import (
	"context"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// AnalysisAPI is the `analysis` API group (packages/server/src/api/analysis.ts createAnalysisApi): every method runs through the
// operation envelope; the router maps POST {basePath}/analysis/{method} onto it.
type AnalysisAPI struct {
	server *ServerContext
}

// CreateAnalysisAPI builds the `analysis` API group.
func CreateAnalysisAPI(server *ServerContext) *AnalysisAPI {
	return &AnalysisAPI{server: server}
}

// agentDenialThreshold is the refusals in a day from which an agent is reported (`agent-denials`).
const analysisAgentDenialThreshold = 20

const analysisDayMs = 86_400_000

var analysisSeverityRank = map[string]int{"high": 0, "medium": 1, "low": 2}

// analysisFindingID is deterministic: the same condition on the same subject always yields the same ID.
func analysisFindingID(kind, subject string) string { return Hash(kind + ":" + subject)[:24] }

// analysisFingerprint is what a suppression accepts: the finding's severity and evidence (its detail, unless the
// check names something steadier). A suppression only hides a finding whose fingerprint still matches.
func analysisFingerprint(severity, evidence string) string {
	return Hash(severity + "\n" + evidence)[:32]
}

func analysisSuppressionID(tenantID, finding string) string { return tenantID + ":" + finding }

// activationActions are the audit actions bindings.activate and approveActivation record for a live activation
// (resourceId is the binding ID).
var analysisActivationActions = newOrderedSet("binding:activate", "binding:activation-approved")

// recordedActivation is an activation the bindings API recorded. Anyone can make authorize() audit a denied decision
// under any action and resource ID, so only allowed events carrying the activation ID (which authorization decisions
// never have) count.
func analysisRecordedActivation(event *core.Object) bool {
	action, _ := event.Get("action").(string)
	_, activation := member(event.Get("metadata"), "activationId").(string)
	return analysisActivationActions.Has(action) && event.Get("outcome") == "allow" && activation
}

func analysisSystemPolicy(policy *core.Object) bool {
	key, ok := policy.Get("uniqueKey").(string)
	return ok && strings.HasPrefix(key, "system:")
}

// statementsOf is `document?.statements ?? []` as objects.
func analysisStatements(document any) []*core.Object {
	list, _ := member(document, "statements").([]any)
	statements := make([]*core.Object, 0, len(list))
	for _, item := range list {
		if statement, ok := item.(*core.Object); ok && statement != nil {
			statements = append(statements, statement)
		}
	}
	return statements
}

// UnrestrictedAdmin (api/analysis.ts unrestrictedAdmin): An allow statement without conditions over every action (or
// every platform action) on every resource.
func UnrestrictedAdmin(document *core.Object) (result bool, err error) {
	if document == nil {
		return false, nil
	}
	return analysisUnrestrictedAdmin(document), nil
}

func analysisUnrestrictedAdmin(document any) bool {
	for _, statement := range analysisStatements(document) {
		if statement.Get("effect") != "allow" || truthy(statement.Get("conditions")) {
			continue
		}
		everything := false
		for _, action := range stringList(statement.Get("actions")) {
			if action == "*" || action == "iam:*" {
				everything = true
				break
			}
		}
		if everything && containsString(stringList(statement.Get("resources")), "*") {
			return true
		}
	}
	return false
}

var analysisServiceWildcard = regexp.MustCompile(`(^|:)\*$`)

// broadActions are unconditional service-wide action wildcards (`documents:*`) that are not already full
// administration.
func analysisBroadActions(document any) []string {
	found := newOrderedSet()
	for _, statement := range analysisStatements(document) {
		if statement.Get("effect") == "allow" && !truthy(statement.Get("conditions")) {
			for _, action := range stringList(statement.Get("actions")) {
				if action != "*" && action != "iam:*" && analysisServiceWildcard.MatchString(action) {
					found.Add(action)
				}
			}
		}
	}
	return found.Values()
}

// isoDay is `new Date(ms).toISOString().slice(0, 10)`.
func analysisISODay(ms float64) string {
	return time.UnixMilli(int64(ms)).UTC().Format("2006-01-02")
}

// days is `Math.floor(ms / 86_400_000)` as JavaScript prints it.
func analysisDays(ms float64) string { return core.NumberString(math.Floor(ms / analysisDayMs)) }

// labelOf is `identity.email ?? identity.name`.
func analysisLabel(identity *core.Object) any {
	return coalesce(identity.Get("email"), identity.Get("name"))
}

// prefix is `value.slice(0, n)` for ASCII identifiers.
func analysisPrefix(value string, n int) string {
	units := core.ToUTF16(value)
	if len(units) <= n {
		return value
	}
	return core.FromUTF16(units[:n])
}

// lintContext is what the policy linter may assume for a tenant: the declared identity attributes and, when every
// resource is registered with IAM (no application resolver, which may return any attribute), the known resource
// attributes.
func (api *AnalysisAPI) lintContext(ctx context.Context, tx core.IamStore, tenantID string) (*core.Object, error) {
	server := api.server
	context := core.NewObject("identityAttributes", server.Catalog.IdentityAttributes)
	if server.Config.Clearances != nil {
		context.Set("clearances", true)
	}
	if server.Options == nil || server.Options.ResolveResource == nil {
		names := newOrderedSet()
		for _, name := range server.Catalog.ResourceTypeNames {
			if definition := server.Catalog.ResourceTypes[name]; definition != nil && definition.Attributes != nil {
				for _, key := range definition.Attributes.Keys() {
					names.Add(key)
				}
			}
		}
		records, err := tx.Find(ctx, "resourceTypes", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			if attributes, ok := record.Get("attributes").(*core.Object); ok && attributes != nil {
				for _, key := range attributes.Keys() {
					names.Add(key)
				}
			}
		}
		sorted := names.Values()
		sort.SliceStable(sorted, func(i, j int) bool { return compareUTF16(sorted[i], sorted[j]) < 0 })
		context.Set("resourceAttributes", stringsOf(sorted))
	}
	return context, nil
}

// analysisScan is every finding the checks report for the tenant now, before suppressions, with each finding's
// fingerprint (by ID): what a suppression of it accepts.
type analysisScan struct {
	now          int64
	findings     []*core.Object
	fingerprints map[string]string
}

func (api *AnalysisAPI) scan(ctx context.Context, tx core.IamStore, tenant *core.Object, dormantDays float64) (*analysisScan, error) {
	server := api.server
	tenantID := jsString(tenant.Get("id"))
	now := server.Now()
	nowMs := float64(now)
	window := dormantDays * analysisDayMs
	byTenant := core.NewObject("tenantId", tenantID)
	// Sequential reads: a transaction holds one database connection.
	policies, err := tx.Find(ctx, "policies", byTenant, nil)
	if err != nil {
		return nil, err
	}
	roles, err := tx.Find(ctx, "roles", byTenant, nil)
	if err != nil {
		return nil, err
	}
	bindings, err := tx.Find(ctx, "bindings", byTenant, nil)
	if err != nil {
		return nil, err
	}
	allMembers, err := tx.Find(ctx, "groupMembers", byTenant, nil)
	if err != nil {
		return nil, err
	}
	var members []*core.Object
	for _, member := range allMembers {
		if server.LiveMembership(member) {
			members = append(members, member)
		}
	}
	groups, err := tx.Find(ctx, "groups", byTenant, nil)
	if err != nil {
		return nil, err
	}
	identities, err := tx.Find(ctx, "identities", byTenant, nil)
	if err != nil {
		return nil, err
	}
	trusts, err := tx.Find(ctx, "trusts", byTenant, nil)
	if err != nil {
		return nil, err
	}
	var live []*core.Object
	for _, binding := range bindings {
		if server.LiveBinding(binding) {
			live = append(live, binding)
		}
	}
	policyByID := map[string]*core.Object{}
	for _, policy := range policies {
		policyByID[jsString(policy.Get("id"))] = policy
	}
	result := &analysisScan{now: now, findings: []*core.Object{}, fingerprints: map[string]string{}}
	// `evidence` (default: the detail) must not change while the condition stays the same, e.g. with time.
	report := func(kind, severity string, subject *core.Object, title, detail string, keyAndEvidence ...string) {
		key := jsString(subject.Get("type")) + ":" + jsString(subject.Get("id"))
		if len(keyAndEvidence) > 0 && keyAndEvidence[0] != "" {
			key = keyAndEvidence[0]
		}
		evidence := detail
		if len(keyAndEvidence) > 1 {
			evidence = keyAndEvidence[1]
		}
		id := analysisFindingID(kind, key)
		result.fingerprints[id] = analysisFingerprint(severity, evidence)
		result.findings = append(result.findings, core.NewObject(
			"id", id, "kind", kind, "severity", severity, "title", title, "detail", detail, "subject", subject,
		))
	}
	subjectOf := func(kind string, record *core.Object, name any) *core.Object {
		return core.NewObject("type", kind, "id", record.Get("id"), "name", name)
	}

	// Policies and inline role documents.
	attached := newOrderedSet()
	for _, role := range roles {
		for _, policyID := range stringList(role.Get("policyIds")) {
			attached.Add(policyID)
		}
	}
	for _, policy := range policies {
		system := analysisSystemPolicy(policy)
		name := jsString(policy.Get("name"))
		if !system && analysisUnrestrictedAdmin(policy.Get("document")) {
			report("unrestricted-admin-policy", "high", subjectOf("policy", policy, policy.Get("name")),
				"Policy "+name+" grants every action on every resource",
				"An unconditional allow of * (or iam:*) on * makes every holder a full administrator. Scope the actions and resources, or add conditions such as principal.mfa.")
		} else if broad := analysisBroadActions(policy.Get("document")); !system && len(broad) > 0 {
			report("broad-action-wildcard", "medium", subjectOf("policy", policy, policy.Get("name")),
				"Policy "+name+" uses service-wide action wildcards",
				"Unconditional "+strings.Join(broad, ", ")+" also grants actions added to those services later. List the actions holders need.")
		}
		if !system && !attached.Has(jsString(policy.Get("id"))) {
			report("unattached-policy", "low", subjectOf("policy", policy, policy.Get("name")),
				"Policy "+name+" is not attached to any role",
				"Unattached policies grant nothing; delete them or attach them where intended.")
		}
	}
	adminRoles := newOrderedSet()
	for _, role := range roles {
		roleID := jsString(role.Get("id"))
		name := jsString(role.Get("name"))
		admin := analysisUnrestrictedAdmin(role.Get("document"))
		for _, policyID := range stringList(role.Get("policyIds")) {
			if policy := policyByID[policyID]; policy != nil && analysisUnrestrictedAdmin(policy.Get("document")) {
				admin = true
			}
		}
		if admin {
			adminRoles.Add(roleID)
		}
		if truthy(role.Get("protected")) {
			continue
		}
		if analysisUnrestrictedAdmin(role.Get("document")) {
			report("unrestricted-admin-policy", "high", subjectOf("role", role, role.Get("name")),
				"Role "+name+" has an inline document granting every action on every resource",
				"Replace the inline * statement with scoped policies.")
		}
		attachedAny := false
		for _, policyID := range stringList(role.Get("policyIds")) {
			if _, ok := policyByID[policyID]; ok {
				attachedAny = true
			}
		}
		if !truthy(role.Get("document")) && !attachedAny {
			report("empty-role", "low", subjectOf("role", role, role.Get("name")),
				"Role "+name+" grants nothing",
				"The role has no inline document and no attached policies.")
		}
		bound := false
		for _, binding := range live {
			if binding.Get("roleId") == role.Get("id") {
				bound = true
				break
			}
		}
		trusted := false
		for _, trust := range trusts {
			if !truthy(trust.Get("revoked")) && trust.Get("roleId") == role.Get("id") {
				trusted = true
				break
			}
		}
		if !bound && !trusted {
			report("unused-role", "low", subjectOf("role", role, role.Get("name")),
				"Role "+name+" is not bound to anyone",
				"No identity, group, or trust uses this role; remove it if it is no longer needed.")
		}
	}

	// Groups that hold access but have no members.
	for _, group := range groups {
		holds := false
		for _, binding := range live {
			if binding.Get("subjectType") == "group" && binding.Get("subjectId") == group.Get("id") {
				holds = true
				break
			}
		}
		if !holds {
			continue
		}
		populated := false
		for _, member := range members {
			if member.Get("groupId") == group.Get("id") {
				populated = true
				break
			}
		}
		if !populated {
			report("empty-group-with-access", "low", subjectOf("group", group, group.Get("name")),
				"Group "+jsString(group.Get("name"))+" holds role bindings but has no members",
				"Anyone added later inherits the access immediately; review the bindings.")
		}
	}

	// Identities: effective bindings (direct and through groups), factor enrollment, and last sign-in.
	groupsOf := map[string]*orderedSet{}
	for _, member := range members {
		identityID := jsString(member.Get("identityId"))
		set := groupsOf[identityID]
		if set == nil {
			set = newOrderedSet()
			groupsOf[identityID] = set
		}
		set.Add(jsString(member.Get("groupId")))
	}
	tenantRequiresMfa := member(tenant.Get("authPolicy"), "requireMfa") == true
	for _, identity := range identities {
		if identity.Get("status") != "active" {
			continue
		}
		identityID := jsString(identity.Get("id"))
		memberOf := groupsOf[identityID]
		var held []*core.Object
		for _, binding := range live {
			if binding.Get("subjectType") == "identity" {
				if binding.Get("subjectId") == identity.Get("id") {
					held = append(held, binding)
				}
			} else if subjectID, ok := binding.Get("subjectId").(string); ok && memberOf.Has(subjectID) {
				held = append(held, binding)
			}
		}
		subject := subjectOf("identity", identity, analysisLabel(identity))
		admin := truthy(identity.Get("owner"))
		if !admin {
			for _, binding := range held {
				if adminRoles.Has(jsString(binding.Get("roleId"))) {
					admin = true
					break
				}
			}
		}
		name := jsString(identity.Get("name"))
		label := jsString(analysisLabel(identity))
		if admin && identity.Get("kind") == "service" {
			report("service-account-admin", "medium", subject,
				"Service account "+name+" has full administrator access",
				"A leaked API key would control the whole organization. Bind a role scoped to what the automation does.")
		}
		if admin && identity.Get("kind") == "agent" {
			report("agent-admin", "high", subject,
				"AI agent "+name+" has full administrator access",
				"An agent follows instructions it reads, so a prompt injection or a leaked key would control the whole organization. Bind a role scoped to its task and set a ceiling (agents.update boundary).")
		}
		if admin && identity.Get("kind") == "user" && !tenantRequiresMfa {
			mfa, err := tx.Get(ctx, "authMfa", identityID)
			if err != nil {
				return nil, err
			}
			factor := mfa != nil && mfa.Get("enabled") == true
			if !factor {
				passkeys, err := tx.Find(ctx, "authPasskeys", core.NewObject("tenantId", tenantID, "identityId", identity.Get("id")), nil)
				if err != nil {
					return nil, err
				}
				factor = len(passkeys) > 0
			}
			if !factor {
				report("admin-without-mfa", "high", subject,
					label+" is an administrator without a second factor",
					"Administrators should enroll an authenticator app or passkey; the tenant authentication policy can require MFA for everyone.")
			}
		}
		if identity.Get("kind") == "user" && (len(held) > 0 || truthy(identity.Get("owner"))) {
			signIns, err := tx.Find(ctx, "audit", core.NewObject("tenantId", tenantID, "actorId", identity.Get("id"), "action", "auth:session:create"), nil)
			if err != nil {
				return nil, err
			}
			// "View as" sessions are recorded on the member but are not the member signing in.
			last := 0.0
			for _, event := range signIns {
				if !truthy(event.Get("impersonatorId")) {
					last = analysisMax(last, jsNumber(event.Get("timestamp")))
				}
			}
			since := last
			if !truthy(last) {
				since = jsNumber(identity.Get("createdAt"))
			}
			if nowMs-since > window {
				title := label + " has never signed in"
				if truthy(last) {
					title = label + " has not signed in for " + analysisDays(nowMs-last) + " days"
				}
				ownership := ""
				if truthy(identity.Get("owner")) {
					ownership = " and ownership"
				}
				report("dormant-access", "medium", subject, title,
					"The account still holds "+strconv.Itoa(len(held))+" role binding(s)"+ownership+". Disable it or remove its access if it is no longer used.")
			}
		}
	}

	identityByID := map[string]*core.Object{}
	for _, identity := range identities {
		identityByID[jsString(identity.Get("id"))] = identity
	}
	roleName := map[string]string{}
	for _, role := range roles {
		roleName[jsString(role.Get("id"))] = jsString(role.Get("name"))
	}
	violations, err := SodViolations(ctx, server, tx, tenantID, nil, nil)
	if err != nil {
		return nil, err
	}
	for _, violation := range violations {
		identity := identityByID[jsString(violation.Get("identityId"))]
		if identity == nil || identity.Get("status") != "active" {
			continue
		}
		var held []string
		for _, roleID := range stringList(violation.Get("roleIds")) {
			if name, ok := roleName[roleID]; ok {
				held = append(held, name)
			} else {
				held = append(held, roleID)
			}
		}
		label := jsString(analysisLabel(identity))
		resolution := "; the conflict predates the rule, which now prevents new ones"
		if violation.Get("mode") == "detect" {
			resolution = ", or keep the rule in detect mode if the combination is accepted"
		}
		report("separation-of-duties", "high", subjectOf("identity", identity, analysisLabel(identity)),
			label+" holds conflicting roles ("+jsString(violation.Get("ruleName"))+")",
			strings.Join(held, " and ")+" must not be held together. Remove one of the bindings"+resolution+".",
			"identity:"+jsString(identity.Get("id"))+":"+jsString(violation.Get("ruleId")))
	}

	// API keys nobody has used for the dormant window (lastSeenAt only moves when a key authenticates).
	keys, err := tx.Find(ctx, "sessions", core.NewObject("tenantId", tenantID, "kind", "api-key"), nil)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		expiresAt := jsNumber(key.Get("expiresAt"))
		if expiresAt <= nowMs {
			continue
		}
		createdAt := jsNumber(key.Get("createdAt"))
		lastSeenAt := jsNumber(key.Get("lastSeenAt"))
		used := lastSeenAt > createdAt
		reference := createdAt
		if used {
			reference = lastSeenAt
		}
		if nowMs-reference <= window {
			continue
		}
		owner := identityByID[jsString(key.Get("identityId"))]
		label, ok := key.Get("name").(string)
		if !ok {
			label = analysisPrefix(jsString(key.Get("id")), 8)
		}
		title := "API key " + label + " has never been used"
		if used {
			title = "API key " + label + " has not been used for " + analysisDays(nowMs-lastSeenAt) + " days"
		}
		var ownerName any = key.Get("identityId")
		if owner != nil {
			ownerName = coalesce(owner.Get("name"), key.Get("identityId"))
		}
		report("stale-api-key", "medium", core.NewObject("type", "credential", "id", key.Get("id"), "name", label), title,
			"The key belongs to "+jsString(ownerName)+" and stays valid until "+analysisISODay(expiresAt)+". Revoke it if nothing depends on it.")
	}

	// AI agents: the person accountable for each, their ceilings, and the delegations people gave them.
	for _, agent := range identities {
		if agent.Get("kind") != "agent" || agent.Get("status") == "deleted" {
			continue
		}
		subject := subjectOf("identity", agent, agent.Get("name"))
		name := jsString(agent.Get("name"))
		standing, err := AgentStanding(ctx, server, tx, agent)
		if err != nil {
			return nil, err
		}
		settings := agent.Get("agent")
		if standing == "sponsor-missing" || standing == "sponsor-inactive" {
			report("agent-without-sponsor", "high", subject,
				"AI agent "+name+" has no active sponsor",
				"Its credentials are refused until someone is accountable for it. Name an active person as its sponsor (agents.update) or delete the agent.")
		} else if agent.Get("status") == "active" && !truthy(member(settings, "boundary")) && member(settings, "delegable") != false {
			report("unbounded-agent", "low", subject,
				"AI agent "+name+" accepts delegation without a ceiling",
				"Each delegation lets it do whatever the delegation scope and the person allow. A boundary policy caps what any delegation, and its own keys, can reach.")
		}
	}
	agentName := func(agentID any) string {
		if identity := identityByID[jsString(agentID)]; identity != nil {
			return jsString(coalesce(identity.Get("name"), agentID))
		}
		return jsString(agentID)
	}
	delegations, err := tx.Find(ctx, "delegations", byTenant, nil)
	if err != nil {
		return nil, err
	}
	for _, delegation := range delegations {
		if delegation.Get("status") != "active" || jsNumber(delegation.Get("expiresAt")) <= nowMs {
			continue
		}
		person := identityByID[jsString(delegation.Get("subjectId"))]
		var personName any = delegation.Get("subjectId")
		if person != nil {
			personName = coalesce(person.Get("email"), coalesce(person.Get("name"), delegation.Get("subjectId")))
		}
		name := jsString(personName) + " → " + agentName(delegation.Get("agentId"))
		subject := core.NewObject("type", "delegation", "id", delegation.Get("id"), "name", name)
		everything := false
		for _, statement := range analysisStatements(delegation.Get("policy")) {
			if statement.Get("effect") != "allow" {
				continue
			}
			for _, action := range stringList(statement.Get("actions")) {
				if action == "*" || action == "iam:*" {
					everything = true
				}
			}
		}
		if everything {
			report("broad-delegation", "medium", subject,
				name+": the agent may do anything the person can",
				"The delegation scope allows every action. Revoke it and grant the actions the agent needs.")
		}
		lastUsed := jsNumber(coalesce(delegation.Get("lastUsedAt"), coalesce(delegation.Get("decidedAt"), delegation.Get("createdAt"))))
		if nowMs-lastUsed > window {
			report("unused-delegation", "low", subject,
				name+": unused for "+analysisDays(nowMs-lastUsed)+" days",
				"The delegation stays active until "+analysisISODay(jsNumber(delegation.Get("expiresAt")))+". Revoke it if the agent no longer acts for this person.")
		}
		// Hand-offs to any agent at all (delegations.ts): the person's access can travel further than they chose.
		handoff := delegation.Get("handoff")
		if truthy(handoff) {
			agents := member(handoff, "agents")
			named := false
			if list, ok := agents.([]any); ok {
				named = len(list) > 0
			} else if text, ok := agents.(string); ok {
				named = text != ""
			}
			if !named {
				depth := member(handoff, "depth")
				severity, deeper := "low", ""
				if jsNumber(depth) > 1 {
					severity, deeper = "medium", ", "+jsString(depth)+" levels deep"
				}
				report("open-handoff", severity, subject,
					name+": the agent may hand the work on to any agent"+deeper,
					"Name the agents it may hand work to (handoff.agents), or grant the delegation without hand-offs.",
					// A deeper hand-off is a worse finding.
					"", "depth:"+jsString(depth))
			}
		}
	}

	// Agents refused often in the last day, with their own keys or acting for people: a sign of an agent looping,
	// misconfigured, or following instructions injected into what it reads.
	agentIDs := newOrderedSet()
	for _, identity := range identities {
		if identity.Get("kind") == "agent" {
			agentIDs.Add(jsString(identity.Get("id")))
		}
	}
	if agentIDs.Len() > 0 {
		counts := map[string]int{}
		var order []string
		from := nowMs - analysisDayMs
		limit := 10_000
		events, err := core.FindOrdered(ctx, tx, "audit", core.NewObject("tenantId", tenantID), core.OrderOptions{
			Field: "timestamp", Direction: "desc", From: &from, Limit: &limit,
		}, func(event *core.Object) bool { return event.Get("outcome") == "deny" })
		if err != nil {
			return nil, err
		}
		for _, event := range events {
			agentID := member(event.Get("sessionContext"), "agentId")
			if nullish(agentID) {
				agentID = core.Undefined
				if actor, ok := event.Get("actorId").(string); ok && agentIDs.Has(actor) {
					agentID = actor
				}
			}
			id, ok := agentID.(string)
			if truthy(agentID) && ok && agentIDs.Has(id) {
				if _, seen := counts[id]; !seen {
					order = append(order, id)
				}
				counts[id]++
			}
		}
		for _, agentID := range order {
			if count := counts[agentID]; count >= analysisAgentDenialThreshold {
				report("agent-denials", "medium", core.NewObject("type", "identity", "id", agentID, "name", agentName(agentID)),
					"AI agent "+agentName(agentID)+" was refused "+strconv.Itoa(count)+" times in the last day",
					"Check what it attempted (agents.activity). Suspend it if it is looping or following instructions it should not.")
			}
		}
	}

	// Teams and departments (teams.ts, departments.ts): who can hand out a team's access, and who leads.
	teams, err := tx.Find(ctx, TeamCollections.Teams, byTenant, nil)
	if err != nil {
		return nil, err
	}
	if len(teams) > 0 {
		teamByID := map[string]*core.Object{}
		for _, team := range teams {
			teamByID[jsString(team.Get("id"))] = team
		}
		storedMembers, err := tx.Find(ctx, TeamCollections.Members, byTenant, nil)
		if err != nil {
			return nil, err
		}
		var teamMembers []*core.Object
		for _, teamMember := range storedMembers {
			liveMember, err := LiveTeamMember(teamMember, now)
			if err != nil {
				return nil, err
			}
			if liveMember {
				teamMembers = append(teamMembers, teamMember)
			}
		}
		activePerson := func(identityID any) bool {
			identity := identityByID[jsString(identityID)]
			return identity != nil && identity.Get("status") == "active"
		}
		for _, team := range teams {
			chain, err := TeamChain(teamByID, jsString(team.Get("id")))
			if err != nil {
				return nil, err
			}
			inChain := func(field string, value any) bool {
				for _, holder := range chain {
					if holder.Get(field) == value {
						return true
					}
				}
				return false
			}
			name := jsString(team.Get("name"))
			subject := subjectOf("team", team, team.Get("name"))
			var maintainers []*core.Object
			for _, teamMember := range teamMembers {
				if teamMember.Get("role") == "maintainer" && inChain("id", teamMember.Get("teamId")) && activePerson(teamMember.Get("identityId")) {
					maintainers = append(maintainers, teamMember)
				}
			}
			var adminGrant *core.Object
			for _, binding := range live {
				if binding.Get("subjectType") == "group" && adminRoles.Has(jsString(binding.Get("roleId"))) &&
					!truthy(binding.Get("eligible")) && inChain("groupId", binding.Get("subjectId")) {
					adminGrant = binding
					break
				}
			}
			if adminGrant != nil && team.Get("memberManagement") != "admins" && len(maintainers) > 0 {
				held, ok := roleName[jsString(adminGrant.Get("roleId"))]
				if !ok {
					held = "an administrator role"
				}
				report("team-maintainers-grant-admin", "high", subject,
					"Maintainers of "+name+" can make anyone a full administrator",
					"The team holds "+held+" as standing access, and its "+strconv.Itoa(len(maintainers))+" maintainer(s) add members without an administrator's authority. Set memberManagement to admins, or make the binding eligible (just-in-time).")
			}
			direct := 0
			for _, teamMember := range teamMembers {
				if teamMember.Get("teamId") == team.Get("id") && activePerson(teamMember.Get("identityId")) {
					direct++
				}
			}
			if direct > 0 && len(maintainers) == 0 && team.Get("memberManagement") != "admins" {
				report("team-without-maintainer", "low", subject,
					"Team "+name+" has members but no maintainer",
					"Nobody but administrators can manage its membership or answer its join requests. Name a maintainer, or set memberManagement to admins to make that the rule.")
			}
		}
	}
	departments, err := tx.Find(ctx, DepartmentCollections.Departments, byTenant, nil)
	if err != nil {
		return nil, err
	}
	if len(departments) > 0 {
		placed := map[string]int{}
		departmentMembers, err := tx.Find(ctx, DepartmentCollections.Members, byTenant, nil)
		if err != nil {
			return nil, err
		}
		for _, departmentMember := range departmentMembers {
			if identity := identityByID[jsString(departmentMember.Get("identityId"))]; identity != nil && identity.Get("status") == "active" {
				placed[jsString(departmentMember.Get("departmentId"))]++
			}
		}
		for _, department := range departments {
			people := placed[jsString(department.Get("id"))]
			var head *core.Object
			if headID := department.Get("headId"); truthy(headID) {
				head = identityByID[jsString(headID)]
			}
			if people > 0 && (head == nil || head.Get("status") != "active") {
				name := jsString(department.Get("name"))
				title := "Department " + name + " has no head"
				if head != nil {
					title = "The head of " + name + " is no longer active"
				}
				noun := "people"
				if people == 1 {
					noun = "person"
				}
				report("department-without-head", "low", subjectOf("department", department, department.Get("name")), title,
					strconv.Itoa(people)+" "+noun+" in it have no department head to report to, so manager approvals routed through the org chart stop there. Name a head (departments.update).")
			}
		}
	}

	for _, trust := range trusts {
		if truthy(trust.Get("revoked")) {
			continue
		}
		// Web-identity trusts have no source session to verify; their claim conditions pin the workload.
		// Stored flags are read through the same fail-closed readers roles.assume enforces with.
		if trust.Get("kind") != "web-identity" && !TrustRequiresMfa(trust) {
			report("trust-without-mfa", "medium", core.NewObject("type", "trust", "id", trust.Get("id")),
				"A cross-tenant trust lets its source assume a role without MFA",
				"Recreate the trust with requireMfa so a stolen password alone cannot assume the role.")
		}
		// Another tenant controls the source identity's attributes, so they must not satisfy this tenant's
		// ABAC conditions. New cross-tenant trusts keep them out; legacy ones (no field) still pass them.
		if trust.Get("kind") != "web-identity" && trust.Get("sourceTenantId") != tenantID && TrustPassesSourceAttributes(trust) {
			report("trust-passes-foreign-attributes", "medium", core.NewObject("type", "trust", "id", trust.Get("id")),
				"A cross-tenant trust passes the source account’s attributes into role sessions",
				"The source tenant controls these attributes, so they can satisfy this tenant’s attribute conditions. Call trust.update({ passSourceAttributes: false }) and use session tags for the data role sessions need.")
		}
	}

	// Standing administrator access: direct, permanent, always-on bindings to administrator roles.
	roleByID := map[string]*core.Object{}
	for _, role := range roles {
		roleByID[jsString(role.Get("id"))] = role
	}
	for _, binding := range bindings {
		role := roleByID[jsString(binding.Get("roleId"))]
		var identity *core.Object
		if binding.Get("subjectType") == "identity" {
			identity = identityByID[jsString(binding.Get("subjectId"))]
		}
		if role == nil || truthy(role.Get("protected")) || !adminRoles.Has(jsString(role.Get("id"))) ||
			binding.Get("eligible") == true || !isUndefined(binding.Get("expiresAt")) ||
			identity == nil || identity.Get("kind") != "user" || identity.Get("status") != "active" {
			continue
		}
		label := jsString(analysisLabel(identity))
		report("standing-privileged-access", "medium", subjectOf("identity", identity, analysisLabel(identity)),
			label+" holds "+jsString(role.Get("name"))+" as standing administrator access",
			"The binding grants full administration permanently and without activation. Make it eligible (just-in-time activation) or give it an expiry.",
			"binding:"+jsString(binding.Get("id")))
	}

	// Eligible bindings nobody has ever activated. Bindings carry no creation time, so their age is bounded
	// from below by the subject's creation and from above by the first audit event naming the binding.
	var eligible []*core.Object
	for _, binding := range bindings {
		if binding.Get("eligible") == true && !server.ExpiredBinding(binding) {
			eligible = append(eligible, binding)
		}
	}
	if len(eligible) > 0 {
		ids := newOrderedSet()
		for _, binding := range eligible {
			ids.Add(jsString(binding.Get("id")))
		}
		activated := newOrderedSet()
		firstSeen := map[string]float64{}
		events, err := tx.Find(ctx, "audit", byTenant, nil)
		if err != nil {
			return nil, err
		}
		for _, event := range events {
			resourceID, ok := event.Get("resourceId").(string)
			if !ok || !ids.Has(resourceID) {
				continue
			}
			if analysisRecordedActivation(event) {
				activated.Add(resourceID)
			}
			earliest, seen := firstSeen[resourceID]
			if !seen {
				earliest = math.Inf(1)
			}
			firstSeen[resourceID] = analysisMin(earliest, jsNumber(event.Get("timestamp")))
		}
		stored, err := tx.Find(ctx, "bindingActivations", byTenant, nil)
		if err != nil {
			return nil, err
		}
		for _, activation := range stored {
			if status := activation.Get("status"); status != "pending" && status != "denied" {
				activated.Add(jsString(activation.Get("bindingId")))
			}
		}
		groupByID := map[string]*core.Object{}
		for _, group := range groups {
			groupByID[jsString(group.Get("id"))] = group
		}
		for _, binding := range eligible {
			bindingID := jsString(binding.Get("id"))
			if activated.Has(bindingID) {
				continue
			}
			var subject *core.Object
			notBefore := analysisMax(jsNumber(coalesce(tenant.Get("createdAt"), 0.0)), jsNumber(coalesce(binding.Get("startsAt"), 0.0)))
			if binding.Get("subjectType") == "identity" {
				identity := identityByID[jsString(binding.Get("subjectId"))]
				if identity == nil || identity.Get("status") != "active" {
					continue
				}
				subject = subjectOf("identity", identity, analysisLabel(identity))
				notBefore = analysisMax(notBefore, jsNumber(identity.Get("createdAt")))
			} else {
				group := groupByID[jsString(binding.Get("subjectId"))]
				if group == nil {
					continue
				}
				subject = subjectOf("group", group, group.Get("name"))
			}
			seen, known := firstSeen[bindingID]
			existedFor := nowMs - seen
			if (!known || existedFor <= window) && nowMs-notBefore <= window {
				continue
			}
			role, ok := roleName[jsString(binding.Get("roleId"))]
			if !ok {
				role = jsString(binding.Get("roleId"))
			}
			detail := "The audit trail shows no activation of this just-in-time binding. Remove it if the access is no longer needed."
			if known && existedFor > window {
				detail = "The just-in-time binding has existed for at least " + analysisDays(existedFor) + " days and was never activated. Remove it if the access is no longer needed."
			}
			report("unused-eligible-binding", "low", subject,
				"Eligible "+role+" binding for "+jsString(subject.Get("name"))+" has no recorded activation",
				detail, "binding:"+bindingID,
				// The detail counts days; the binding's role and subject are what the suppression accepts.
				"role:"+jsString(binding.Get("roleId")))
		}
	}

	// Manager links that lead nowhere or back to the person. Manager links form a functional graph (one
	// outgoing link each), so a single walk that marks people in progress and done finds every loop in linear
	// time, however deep the reporting chains are.
	type managerLoop struct {
		members  []*core.Object
		position int
	}
	loops := map[string]managerLoop{}
	walked := map[string]string{}
	managerOf := func(person *core.Object) *core.Object {
		if managerID := person.Get("managerId"); truthy(managerID) {
			return identityByID[jsString(managerID)]
		}
		return nil
	}
	for _, start := range identities {
		var path []*core.Object
		cursor := start
		for cursor != nil {
			if _, ok := walked[jsString(cursor.Get("id"))]; ok {
				break
			}
			walked[jsString(cursor.Get("id"))] = "walking"
			path = append(path, cursor)
			cursor = managerOf(cursor)
		}
		// Reaching someone still in progress closes a loop from them to the end of this walk.
		if cursor != nil && walked[jsString(cursor.Get("id"))] == "walking" {
			index := 0
			for position, person := range path {
				if person == cursor {
					index = position
					break
				}
			}
			loopMembers := path[index:]
			for position, person := range loopMembers {
				loops[jsString(person.Get("id"))] = managerLoop{members: loopMembers, position: position}
			}
		}
		for _, person := range path {
			walked[jsString(person.Get("id"))] = "done"
		}
	}
	for _, identity := range identities {
		if identity.Get("status") != "active" || isUndefined(identity.Get("managerId")) {
			continue
		}
		subject := subjectOf("identity", identity, analysisLabel(identity))
		subjectName := jsString(subject.Get("name"))
		manager := identityByID[jsString(identity.Get("managerId"))]
		if manager == nil || manager.Get("status") != "active" {
			title := subjectName + "'s manager no longer exists"
			if manager != nil {
				title = subjectName + "'s manager " + jsString(analysisLabel(manager)) + " is " + jsString(manager.Get("status"))
			}
			report("orphaned-manager", "low", subject, title,
				"Approvals routed to the manager and offboarding handoffs cannot reach them. Assign an active manager or clear the link.")
			continue
		}
		// Someone who only reports into a loop is not part of it; the loop is reported for its members.
		loop, ok := loops[jsString(identity.Get("id"))]
		if !ok {
			continue
		}
		// The loop as seen from this person, shortened when it is long.
		size := len(loop.members)
		var chain []string
		for step := 0; step < size && step < 10; step++ {
			chain = append(chain, jsString(analysisLabel(loop.members[(loop.position+step)%size])))
		}
		if size > 10 {
			chain[9] = "… " + strconv.Itoa(size-9) + " more"
		}
		chain = append(chain, jsString(analysisLabel(identity)))
		report("manager-cycle", "medium", subject,
			subjectName+"'s manager chain loops back to them",
			strings.Join(chain, " → ")+". Manager approvals and offboarding handoffs cannot resolve a loop; give someone in it a manager outside the chain.")
	}

	// Stored policies and inline role documents the linter warns about.
	linting, err := api.lintContext(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	lintFinding := func(subject *core.Object, label string, document any) error {
		linted, err := LintPolicy(document, linting)
		if err != nil {
			return err
		}
		var codes []string
		count := 0
		seen := newOrderedSet()
		warnings, _ := linted.Get("warnings").([]any)
		for _, item := range warnings {
			// unrestricted-admin already has its own high-severity finding.
			if member(item, "severity") != "warning" || member(item, "code") == "unrestricted-admin" {
				continue
			}
			count++
			seen.Add(jsString(member(item, "code")))
		}
		if count == 0 {
			return nil
		}
		codes = seen.Values()
		plural := "s"
		if count == 1 {
			plural = ""
		}
		shown := codes
		more := ""
		if len(codes) > 3 {
			shown = codes[:3]
			more = " and " + strconv.Itoa(len(codes)-3) + " more"
		}
		report("policy-lint", "low", subject,
			label+" has "+strconv.Itoa(count)+" lint warning"+plural,
			strings.Join(shown, ", ")+more+". Lint the document (analysis.lintPolicy) for details.")
		return nil
	}
	for _, policy := range policies {
		if !analysisSystemPolicy(policy) {
			if err := lintFinding(subjectOf("policy", policy, policy.Get("name")), "Policy "+jsString(policy.Get("name")), policy.Get("document")); err != nil {
				return nil, err
			}
		}
	}
	for _, role := range roles {
		if !truthy(role.Get("protected")) && truthy(role.Get("document")) {
			if err := lintFinding(subjectOf("role", role, role.Get("name")), "Role "+jsString(role.Get("name"))+"'s inline document", role.Get("document")); err != nil {
				return nil, err
			}
		}
	}
	return result, nil
}

// jsMax is Math.max over two numbers (NaN when either is NaN).
func analysisMax(a, b float64) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		return math.NaN()
	}
	return math.Max(a, b)
}

// jsMin is Math.min over two numbers (NaN when either is NaN).
func analysisMin(a, b float64) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		return math.NaN()
	}
	return math.Min(a, b)
}

// Findings is POST {basePath}/analysis/findings. Runs every check. `dormantDays` (default 90) sets when an unused
// account holding access is reported. A suppressed finding is hidden only while it is as it was when suppressed (same
// severity and detail).
func (api *AnalysisAPI) Findings(ctx context.Context, credential core.CredentialInput, input In[apitypes.AnalysisFindingsInput]) (Out[apitypes.AnalysisFindingsOutput], error) {
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:analysis:read", "analysis/*", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		dormantDays, err := Integer(coalesce(input.Get("dormantDays"), 90.0), "dormantDays", 1, 3650)
		if err != nil {
			return nil, err
		}
		scanned, err := api.scan(ctx, call.Tx, call.Tenant, dormantDays)
		if err != nil {
			return nil, err
		}
		// A suppression stands for the finding it was accepted for: once the finding changes, it shows again.
		rows, err := call.Tx.Find(ctx, "analysisSuppressions", core.NewObject("tenantId", call.Tenant.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		suppressions := map[string]*core.Object{}
		for _, row := range rows {
			stored := row.Get("fingerprint")
			current, ok := scanned.fingerprints[jsString(row.Get("findingId"))]
			if !isUndefined(stored) && ok && stored == current {
				suppressions[jsString(row.Get("findingId"))] = row
			}
		}
		annotated := []*core.Object{}
		for _, finding := range scanned.findings {
			if suppression := suppressions[jsString(finding.Get("id"))]; suppression != nil {
				finding = finding.Spread(core.NewObject("suppressed", core.NewObject(
					"reason", suppression.Get("reason"), "by", suppression.Get("createdBy"), "at", suppression.Get("createdAt"),
				)))
			}
			if input.Get("includeSuppressed") == true || !truthy(finding.Get("suppressed")) {
				annotated = append(annotated, finding)
			}
		}
		sort.SliceStable(annotated, func(i, j int) bool {
			a, b := annotated[i], annotated[j]
			if rank := analysisSeverityRank[jsString(a.Get("severity"))] - analysisSeverityRank[jsString(b.Get("severity"))]; rank != 0 {
				return rank < 0
			}
			if order := localeCompare(jsString(a.Get("kind")), jsString(b.Get("kind"))); order != 0 {
				return order < 0
			}
			return localeCompare(jsString(a.Get("id")), jsString(b.Get("id"))) < 0
		})
		summary := map[string]float64{"high": 0, "medium": 0, "low": 0, "suppressed": 0}
		for _, finding := range scanned.findings {
			if _, ok := suppressions[jsString(finding.Get("id"))]; ok {
				summary["suppressed"]++
			} else {
				summary[jsString(finding.Get("severity"))]++
			}
		}
		list := make([]any, len(annotated))
		for index, finding := range annotated {
			list[index] = finding
		}
		return core.NewObject(
			"generatedAt", float64(scanned.now), "dormantDays", dormantDays,
			"summary", core.NewObject("high", summary["high"], "medium", summary["medium"], "low", summary["low"], "suppressed", summary["suppressed"]),
			"findings", list,
		), nil
	}, false)
	return Out[apitypes.AnalysisFindingsOutput]{Value: result}, err
}

// LintPolicy is POST {basePath}/analysis/lintPolicy. Lints a candidate `document` or a stored policy (`policyId`,
// exactly one of the two): validation as storage applies it (unknown actions and resource types included) plus
// warnings about grants broader than intended and conditions that never match or fail open. A document storage would
// reject is reported without warnings. `contextKeys` names keys the application supplies through resolveContext.
// Requires iam:policies:read on the policy (or the tenant, for a candidate document).
func (api *AnalysisAPI) LintPolicy(ctx context.Context, credential core.CredentialInput, input In[apitypes.AnalysisLintPolicyInput]) (Out[apitypes.AnalysisLintPolicyOutput], error) {
	if isUndefined(input.Get("document")) == isUndefined(input.Get("policyId")) {
		return Out[apitypes.AnalysisLintPolicyOutput]{}, invalidInput("Provide either a document or a policyId")
	}
	var policyID *string
	if raw := input.Get("policyId"); !isUndefined(raw) {
		value, err := Text(raw, "policyId")
		if err != nil {
			return Out[apitypes.AnalysisLintPolicyOutput]{}, err
		}
		policyID = &value
	}
	var contextKeys []string
	if raw := input.Get("contextKeys"); !isUndefined(raw) {
		keys, err := Strings(raw, "contextKeys")
		if err != nil {
			return Out[apitypes.AnalysisLintPolicyOutput]{}, err
		}
		contextKeys = keys
	}
	resourceID := jsString(input.Get("tenantId"))
	if policyID != nil {
		resourceID = *policyID
	}
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:policies:read", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tenantID := jsString(call.Tenant.Get("id"))
		document := input.Get("document")
		if policyID != nil {
			policy, err := api.server.Scoped(ctx, call.Tx, "policies", *policyID, tenantID)
			if err != nil {
				return nil, err
			}
			document = policy.Get("document")
		}
		// Validation first: it rejects unknown actions and resource types cheaply, before any pattern matching.
		if err := api.server.Catalog.Validate(ctx, call.Tx, tenantID, document); err != nil {
			known, ok := asIamError(err)
			if !ok {
				return nil, err
			}
			return core.NewObject(
				"valid", false, "error", core.NewObject("code", known.Code, "message", known.Message), "warnings", []any{},
			), nil
		}
		linting, err := api.lintContext(ctx, call.Tx, tenantID)
		if err != nil {
			return nil, err
		}
		if contextKeys != nil {
			linting = linting.Spread(core.NewObject("contextKeys", stringsOf(contextKeys)))
		}
		return LintPolicy(document, linting)
	}, false)
	return Out[apitypes.AnalysisLintPolicyOutput]{Value: result}, err
}

var analysisFindingIDPattern = regexp.MustCompile(`^[0-9a-f]{24}$`)

// Suppress is POST {basePath}/analysis/suppress. Hides one finding the scan reports now from future results, with a
// reason kept for reviewers, for as long as the finding stays as it is (same severity and detail); if it changes, it
// shows again. `dormantDays` (default 90) must match the window the finding was listed with. Requires
// iam:analysis:update.
func (api *AnalysisAPI) Suppress(ctx context.Context, credential core.CredentialInput, input In[apitypes.AnalysisSuppressInput]) (Out[apitypes.AnalysisSuppressOutput], error) {
	findingID, err := Text(input.Get("findingId"), "findingId", 64)
	if err != nil {
		return Out[apitypes.AnalysisSuppressOutput]{}, err
	}
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:analysis:update", "analysis/"+findingID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		if !analysisFindingIDPattern.MatchString(findingID) {
			return nil, invalidInput("Unknown finding ID")
		}
		reason, err := Text(input.Get("reason"), "reason", 500)
		if err != nil {
			return nil, err
		}
		reason = core.JSTrim(reason)
		dormantDays, err := Integer(coalesce(input.Get("dormantDays"), 90.0), "dormantDays", 1, 3650)
		if err != nil {
			return nil, err
		}
		// Only a finding reported now can be accepted, and only as it is now: a predictable ID alone is not enough.
		scanned, err := api.scan(ctx, call.Tx, call.Tenant, dormantDays)
		if err != nil {
			return nil, err
		}
		current, ok := scanned.fingerprints[findingID]
		if !ok {
			return nil, invalidInput("Unknown finding ID: only a finding reported now can be suppressed")
		}
		tenantID := jsString(input.Get("tenantId"))
		record := core.NewObject(
			"id", analysisSuppressionID(tenantID, findingID), "tenantId", input.Get("tenantId"), "findingId", findingID,
			"reason", reason, "createdBy", call.Principal.Identity.Get("id"), "createdAt", float64(api.server.Now()),
			"fingerprint", current,
		)
		existing, err := call.Tx.Get(ctx, "analysisSuppressions", analysisSuppressionID(tenantID, findingID))
		if err != nil {
			return nil, err
		}
		if existing != nil {
			_, err = call.Tx.Put(ctx, "analysisSuppressions", record)
		} else {
			_, err = call.Tx.Insert(ctx, "analysisSuppressions", record)
		}
		if err != nil {
			return nil, err
		}
		return core.NewObject("suppressed", true), nil
	}, false)
	return Out[apitypes.AnalysisSuppressOutput]{Value: result}, err
}

// Unsuppress is POST {basePath}/analysis/unsuppress. Shows a suppressed finding again. Requires iam:analysis:update.
func (api *AnalysisAPI) Unsuppress(ctx context.Context, credential core.CredentialInput, input In[apitypes.AnalysisUnsuppressInput]) (Out[apitypes.AnalysisUnsuppressOutput], error) {
	findingID, err := Text(input.Get("findingId"), "findingId", 64)
	if err != nil {
		return Out[apitypes.AnalysisUnsuppressOutput]{}, err
	}
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:analysis:update", "analysis/"+findingID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		id := analysisSuppressionID(jsString(input.Get("tenantId")), findingID)
		existing, err := call.Tx.Get(ctx, "analysisSuppressions", id)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			if err := call.Tx.Delete(ctx, "analysisSuppressions", id); err != nil {
				return nil, err
			}
		}
		return core.NewObject("suppressed", false), nil
	}, false)
	return Out[apitypes.AnalysisUnsuppressOutput]{Value: result}, err
}
