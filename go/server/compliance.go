package server

// Port of packages/server/src/compliance.ts. The compliance center: automated checks over the IAM state (who has MFA,
// stale access, reviews, leavers, privileged access, audit integrity, ...), mapped to the requirements of common
// frameworks. Tenants turn checks into controls, evaluate them on a schedule, record exceptions with an expiry, and
// export signed evidence.
//
// Checks only read, and they read outside any transaction (`server.Store`), so an evaluation never holds the store's
// write lock while it walks a large tenant; only the results are written, in one short transaction. Findings name
// their subject by ID (`identity:{id}`); names are looked up when results are read, so stored results carry no
// personal data beyond pseudonymous IDs.

import (
	"context"
	"math"
	"strings"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const (
	complianceDay  = 86_400_000.0
	complianceHour = 3_600_000.0
	// auditPageSize audit events are verified per page, at most auditPages pages per evaluation (the rest continue
	// from the checkpoint on the next run).
	auditPageSize = 2_000
	auditPages    = 50
)

// compliancePlural is plural: `{count} {word}` with an `s` unless the count is one.
func compliancePlural(count float64, word string) string {
	suffix := "s"
	if count == 1 {
		suffix = ""
	}
	return core.NumberString(count) + " " + word + suffix
}

// checkFinding is a CheckFinding: what the finding is about and a plain-text detail without names.
func checkFinding(subject, detail string) *core.Object {
	return core.NewObject("subject", subject, "detail", detail)
}

// checkVerdict is the `{ status, summary }` a judge answers.
func checkVerdict(status, summary string) *core.Object {
	return core.NewObject("status", status, "summary", summary)
}

// checkParam is a CheckParam.
func checkParam(name, description string, defaultValue, min, max float64) *core.Object {
	return core.NewObject("name", name, "description", description, "default", defaultValue, "min", min, "max", max)
}

// paramOf is `params[name]` as a number.
func paramOf(params *core.Object, name string) float64 {
	if params == nil {
		return math.NaN()
	}
	return jsNumber(params.Get(name))
}

// complianceRound is Math.round: halves round toward +Infinity.
func complianceRound(value float64) float64 {
	floor := math.Floor(value)
	if value-floor >= 0.5 {
		return floor + 1
	}
	return floor
}

// findingSubject is a finding's subject.
func findingSubject(finding *core.Object) string {
	subject, _ := finding.Get("subject").(string)
	return subject
}

// complianceCountJudge passes when nothing remains, else fails with `{n} {what}s need attention`.
func complianceCountJudge(what, fine string) func(remaining []*core.Object) *core.Object {
	return func(remaining []*core.Object) *core.Object {
		if len(remaining) == 0 {
			return checkVerdict("pass", fine)
		}
		needs := "need"
		if len(remaining) == 1 {
			needs = "needs"
		}
		return checkVerdict("fail", compliancePlural(float64(len(remaining)), what)+" "+needs+" attention")
	}
}

// complianceAuthOptions is `ctx.options.authentication`.
func complianceAuthOptions(server *ServerContext) *auth.Options {
	if server == nil || server.Options == nil {
		return nil
	}
	return server.Options.Authentication
}

// compliancePeople is people: active, unexpired people.
func compliancePeople(ctx context.Context, server *ServerContext, store core.IamStore, tenantID any) ([]*core.Object, error) {
	identities, err := store.Find(ctx, "identities", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	people := make([]*core.Object, 0, len(identities))
	for _, identity := range identities {
		if identity.Get("kind") == "user" && identity.Get("status") == "active" && !server.IdentityExpired(identity) {
			people = append(people, identity)
		}
	}
	return people, nil
}

// complianceLive is `record.expiresAt === undefined || record.expiresAt > now`.
func complianceLive(record *core.Object, now float64) bool {
	expiresAt := record.Get("expiresAt")
	return isUndefined(expiresAt) || jsNumber(expiresAt) > now
}

// adminProbes are actions that together amount to administering a tenant: whoever may do all of them can grant
// themselves anything.
var adminProbes = []string{"iam:bindings:create", "iam:roles:update", "iam:policies:update"}

// complianceSafeMatch is matchPattern that answers false instead of failing.
func complianceSafeMatch(pattern, value any) (matched bool) {
	text, ok := pattern.(string)
	if !ok {
		return false
	}
	defer func() {
		if recover() != nil {
			matched = false
		}
	}()
	return core.MatchPattern(text, jsString(value), nil)
}

// complianceSomeMatch is `list.some((pattern) => complianceSafeMatch(pattern, value))`.
func complianceSomeMatch(list any, value string) bool {
	items, _ := list.([]any)
	for _, item := range items {
		if complianceSafeMatch(item, value) {
			return true
		}
	}
	return false
}

// Administers (compliance.ts administers): whether documents allow administering the tenant: one allow statement
// covering every admin probe action on the tenant's resource. Conditions are ignored on purpose: a condition (MFA,
// network, time) changes when someone may act, not who holds the power.
func Administers(documents []any, tenantID string) bool {
	resource := "iam/" + tenantID
	for _, document := range documents {
		statements, _ := coalesce(member(document, "statements"), []any{}).([]any)
		for _, statement := range statements {
			if member(statement, "effect") != "allow" {
				continue
			}
			every := true
			for _, probe := range adminProbes {
				if !complianceSomeMatch(member(statement, "actions"), probe) {
					every = false
					break
				}
			}
			if every && complianceSomeMatch(member(statement, "resources"), resource) {
				return true
			}
		}
	}
	return false
}

// complianceHolders is an insertion-ordered Map<string, string> of privileged holders.
type complianceHolders struct {
	keys []string
	via  map[string]string
}

func (h *complianceHolders) has(key string) bool {
	_, ok := h.via[key]
	return ok
}

func (h *complianceHolders) set(key, via string) {
	if !h.has(key) {
		h.keys = append(h.keys, key)
	}
	h.via[key] = via
}

// privilegedHolders is who holds full administration, by any path: owners and root administrators; live bindings
// (direct or through a group) to a role that administers the tenant itself or through the roles it inherits;
// eligible bindings to such a role while activated or when activation needs no approval; and trusts that let an
// identity or workload assume one.
func privilegedHolders(ctx context.Context, server *ServerContext, store core.IamStore, tenantID string, now float64) (*complianceHolders, float64, error) {
	holders := &complianceHolders{via: map[string]string{}}
	identities, err := store.Find(ctx, "identities", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, 0, err
	}
	var everyone []*core.Object
	for _, identity := range identities {
		if identity.Get("status") == "active" && !server.IdentityExpired(identity) {
			everyone = append(everyone, identity)
		}
	}
	for _, identity := range everyone {
		if truthy(identity.Get("owner")) || truthy(identity.Get("rootAdmin")) {
			via := "owner"
			if truthy(identity.Get("rootAdmin")) {
				via = "root administrator"
			}
			holders.set("identity:"+jsString(identity.Get("id")), via)
		}
	}
	policyList, err := store.Find(ctx, "policies", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, 0, err
	}
	policies := map[string]*core.Object{}
	for _, policy := range policyList {
		policies[jsString(policy.Get("id"))] = policy
	}
	roleList, err := store.Find(ctx, "roles", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, 0, err
	}
	roles := map[string]*core.Object{}
	for _, role := range roleList {
		roles[jsString(role.Get("id"))] = role
	}
	own := func(role *core.Object) []any {
		documents := []any{role.Get("document")}
		policyIDs, _ := coalesce(role.Get("policyIds"), []any{}).([]any)
		for _, policyID := range policyIDs {
			var document any = core.Undefined
			if id, ok := policyID.(string); ok {
				if policy, found := policies[id]; found {
					document = policy.Get("document")
				}
			}
			documents = append(documents, document)
		}
		return documents
	}
	// A role administers if it or any role it inherits (as decisions.ts follows them) does.
	adminRoles := map[string]string{}
	for _, role := range roleList {
		roleID := jsString(role.Get("id"))
		if roles[roleID] != role {
			// A later record with the same ID replaced this one in the map (Map iteration visits each key once).
			continue
		}
		seen := map[string]bool{roleID: true}
		queue := []*core.Object{role}
		for len(queue) > 0 && len(seen) <= 256 {
			current := queue[0]
			queue = queue[1:]
			if Administers(own(current), tenantID) {
				if current.Get("id") == role.Get("id") {
					adminRoles[roleID] = jsString(role.Get("name"))
				} else {
					adminRoles[roleID] = jsString(role.Get("name")) + ", through " + jsString(current.Get("name"))
				}
				break
			}
			inherits, _ := coalesce(current.Get("inherits"), []any{}).([]any)
			for _, item := range inherits {
				inheritedID, ok := item.(string)
				if !ok {
					continue
				}
				inherited, found := roles[inheritedID]
				if !found || truthy(inherited.Get("protected")) || seen[inheritedID] {
					continue
				}
				seen[inheritedID] = true
				queue = append(queue, inherited)
			}
		}
	}
	eligibleWithApproval := 0.0
	if len(adminRoles) == 0 {
		return holders, eligibleWithApproval, nil
	}
	members := map[string][]string{}
	memberList, err := store.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, 0, err
	}
	for _, member := range memberList {
		if complianceLive(member, now) {
			groupID := jsString(member.Get("groupId"))
			members[groupID] = append(members[groupID], jsString(member.Get("identityId")))
		}
	}
	activationList, err := store.Find(ctx, "bindingActivations", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, 0, err
	}
	var activations []*core.Object
	for _, activation := range activationList {
		status := activation.Get("status")
		if status != "pending" && status != "denied" && jsNumber(activation.Get("expiresAt")) > now {
			activations = append(activations, activation)
		}
	}
	active := map[string]bool{}
	for _, identity := range everyone {
		active[jsString(identity.Get("id"))] = true
	}
	bindings, err := store.Find(ctx, "bindings", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, 0, err
	}
	for _, binding := range bindings {
		roleID, _ := binding.Get("roleId").(string)
		role, found := adminRoles[roleID]
		if !found {
			continue
		}
		if startsAt := binding.Get("startsAt"); !isUndefined(startsAt) && jsNumber(startsAt) > now {
			continue
		}
		if expiresAt := binding.Get("expiresAt"); !isUndefined(expiresAt) && jsNumber(expiresAt) <= now {
			continue
		}
		var subjects []string
		if binding.Get("subjectType") == "identity" {
			subjects = []string{jsString(binding.Get("subjectId"))}
		} else {
			subjects = members[jsString(binding.Get("subjectId"))]
		}
		for _, subject := range subjects {
			key := "identity:" + subject
			if !active[subject] || holders.has(key) {
				continue
			}
			activated := false
			for _, item := range activations {
				if item.Get("bindingId") == binding.Get("id") && item.Get("identityId") == subject {
					activated = true
					break
				}
			}
			switch {
			case !truthy(binding.Get("eligible")):
				holders.set(key, "role "+role)
			case activated:
				holders.set(key, "role "+role+", activated")
			case !truthy(binding.Get("requireApproval")):
				holders.set(key, "role "+role+", eligible without approval")
			default:
				eligibleWithApproval++
			}
		}
	}
	trusts, err := store.Find(ctx, "trusts", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, 0, err
	}
	for _, trust := range trusts {
		roleID, _ := trust.Get("roleId").(string)
		role, found := adminRoles[roleID]
		if !found || truthy(trust.Get("revoked")) {
			continue
		}
		var via string
		switch {
		case trust.Get("kind") == "web-identity":
			via = "a workload federation trust assumes role " + role
		case trust.Get("sourceTenantId") == tenantID:
			via = "a trust lets identity " + jsString(trust.Get("sourceIdentityId")) + " assume role " + role
		default:
			via = "a trust lets identity " + jsString(trust.Get("sourceIdentityId")) + " of tenant " + jsString(trust.Get("sourceTenantId")) + " assume role " + role
		}
		holders.set("trust:"+jsString(trust.Get("id")), via)
	}
	return holders, eligibleWithApproval, nil
}

// checkEvaluator is ComplianceCheck.evaluate; `store` is read outside any transaction.
type checkEvaluator func(ctx context.Context, server *ServerContext, store core.IamStore, tenant *core.Object, params *core.Object, now float64) (*CheckOutcome, error)

// ComplianceChecks is compliance.ts complianceChecks: the built-in checks.
var ComplianceChecks = []*ComplianceCheck{
	{
		ID:          "mfa-enforced",
		Title:       "Multi-factor authentication is required",
		Description: "The organization’s sign-in policy requires a second factor for everyone (requireMfa).",
		Params:      []*core.Object{},
		evaluate:    evaluateMfaEnforced,
	},
	{
		ID:          "mfa-coverage",
		Title:       "People have a second factor",
		Description: "The share of active people with an authenticator app, or a passkey where the deployment accepts passkeys as a second factor.",
		Params:      []*core.Object{checkParam("minimumPercent", "Share of people that must be enrolled", 100, 50, 100)},
		evaluate:    evaluateMfaCoverage,
	},
	{
		ID:          "password-length",
		Title:       "Passwords are long enough",
		Description: "The minimum password length the organization enforces (never below 12, the deployment’s floor), or passwords are not allowed at all.",
		Params:      []*core.Object{checkParam("minimum", "Required minimum length", 12, 8, 64)},
		evaluate:    evaluatePasswordLength,
	},
	{
		ID:          "session-lifetime",
		Title:       "Sessions end",
		Description: "Sessions end within a maximum lifetime and after a period of inactivity.",
		Params: []*core.Object{
			checkParam("maxHours", "Longest session", 24*7, 1, 24*30),
			checkParam("idleMinutes", "Longest inactivity before sign-out", 24*60, 5, 24*60*7),
		},
		evaluate: evaluateSessionLifetime,
	},
	{
		ID:          "inactive-accounts",
		Title:       "Inactive accounts are removed",
		Description: "Active people who have not signed in for a while (their access should be reviewed or removed).",
		Params:      []*core.Object{checkParam("days", "Days without a sign-in", 90, 7, 730)},
		evaluate:    evaluateInactiveAccounts,
	},
	{
		ID:          "leaver-access",
		Title:       "Leavers lose access",
		Description: "Disabled or expired accounts hold no live sessions, API keys, role bindings or group memberships.",
		Params:      []*core.Object{},
		evaluate:    evaluateLeaverAccess,
	},
	{
		ID:          "stale-api-keys",
		Title:       "Unused API keys are revoked",
		Description: "Live API keys (service accounts and agents) that have not been used for a while.",
		Params:      []*core.Object{checkParam("days", "Days without use", 90, 7, 730)},
		evaluate:    evaluateStaleAPIKeys,
	},
	{
		ID:          "api-key-lifetime",
		Title:       "API keys expire",
		Description: "Live API keys whose lifetime exceeds the maximum.",
		Params:      []*core.Object{checkParam("maxDays", "Longest API key lifetime", 365, 1, 3650)},
		evaluate:    evaluateAPIKeyLifetime,
	},
	{
		ID:          "access-reviews",
		Title:       "Access is reviewed periodically",
		Description: "Within the interval, closed certification campaigns in which reviewers decided most items covered the roles people hold; no campaign is overdue. Campaigns closed with few human decisions do not count.",
		Params: []*core.Object{
			checkParam("intervalDays", "Longest time between completed reviews", 90, 7, 730),
			checkParam("minDecidedPercent", "Share of a campaign’s items a reviewer must decide for it to count", 80, 50, 100),
			checkParam("minCoveragePercent", "Share of the roles held today that counted reviews must have covered", 100, 50, 100),
		},
		evaluate: evaluateAccessReviews,
	},
	{
		ID:          "privileged-access",
		Title:       "Few people hold full administration",
		Description: "Everyone who can administer the organization — owners, root administrators, holders of admin roles (also through inherited roles, activated or approval-free eligible bindings) and trusts that assume them — against a maximum.",
		Params:      []*core.Object{checkParam("maxHolders", "Most people with full administration", 5, 1, 1000)},
		evaluate:    evaluatePrivilegedAccess,
	},
	{
		ID:          "owner-redundancy",
		Title:       "More than one owner",
		Description: "At least two active owners, so losing one account does not lock the organization out.",
		Params:      []*core.Object{},
		evaluate:    evaluateOwnerRedundancy,
	},
	{
		ID:          "separation-of-duties",
		Title:       "Separation of duties holds",
		Description: "Nobody holds two roles a separation-of-duties rule keeps apart. Without any rule the check warns.",
		Params:      []*core.Object{},
		evaluate:    evaluateSeparationOfDuties,
	},
	{
		ID:           "audit-integrity",
		Title:        "The audit log is intact",
		Description:  "The audit hash chain verifies: no event was changed, removed or inserted. Each evaluation continues from where the last one stopped (up to 100,000 events per run) and checks the newest event against the chain head; pruned prefixes must match their audit:prune record.",
		Params:       []*core.Object{},
		NoExceptions: flagTrue(),
		evaluate:     evaluateAuditIntegrity,
	},
	{
		ID:          "privacy-deadlines",
		Title:       "Data-subject requests are answered on time",
		Description: "No privacy request (access, erasure, ...) is past its statutory deadline.",
		Params:      []*core.Object{},
		evaluate:    evaluatePrivacyDeadlines,
	},
}

func flagTrue() *bool {
	value := true
	return &value
}

// CheckByID is compliance.ts checkById.
var CheckByID = func() map[string]*ComplianceCheck {
	byID := make(map[string]*ComplianceCheck, len(ComplianceChecks))
	for _, check := range ComplianceChecks {
		byID[check.ID] = check
	}
	return byID
}()

func evaluateMfaEnforced(_ context.Context, _ *ServerContext, _ core.IamStore, tenant *core.Object, _ *core.Object, _ float64) (*CheckOutcome, error) {
	policy := tenant.Get("authPolicy")
	tenantID := jsString(tenant.Get("id"))
	requireMfa := truthy(member(policy, "requireMfa"))
	ownersOnly := truthy(member(policy, "requireMfaForOwners"))
	findings := []*core.Object{}
	switch {
	case requireMfa:
	case ownersOnly:
		findings = append(findings, checkFinding("tenant:"+tenantID+":mfa-owners-only", "Only owners must use a second factor"))
	default:
		findings = append(findings, checkFinding("tenant:"+tenantID+":mfa-optional", "The sign-in policy does not require a second factor"))
	}
	required := 0.0
	if requireMfa {
		required = 1
	}
	return &CheckOutcome{
		Findings: findings,
		Metrics:  core.NewObject("required", required),
		judge: func(remaining []*core.Object) *core.Object {
			switch {
			case len(remaining) == 0 && requireMfa:
				return checkVerdict("pass", "Everyone must use a second factor")
			case len(remaining) == 0:
				return checkVerdict("pass", "Accepted by exception")
			case ownersOnly:
				return checkVerdict("warn", "Only owners must use a second factor")
			}
			return checkVerdict("fail", "A second factor is optional")
		},
	}, nil
}

func evaluateMfaCoverage(ctx context.Context, server *ServerContext, store core.IamStore, tenant *core.Object, params *core.Object, _ float64) (*CheckOutcome, error) {
	list, err := compliancePeople(ctx, server, store, tenant.Get("id"))
	if err != nil {
		return nil, err
	}
	// Passkeys satisfy MFA only when the deployment enables them (auth base.ts passkeyFactor).
	withPasskeys := map[string]bool{}
	if options := complianceAuthOptions(server); options != nil && options.Passkeys != nil {
		passkeys, err := store.Find(ctx, "authPasskeys", core.NewObject("tenantId", tenant.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		for _, passkey := range passkeys {
			withPasskeys[jsString(passkey.Get("identityId"))] = true
		}
	}
	findings := []*core.Object{}
	for _, person := range list {
		personID := jsString(person.Get("id"))
		mfa, err := store.Get(ctx, "authMfa", personID)
		if err != nil {
			return nil, err
		}
		if !truthy(member(mfa, "enabled")) && !withPasskeys[personID] {
			findings = append(findings, checkFinding("identity:"+personID, "Has no second factor"))
		}
	}
	total := float64(len(list))
	minimum := paramOf(params, "minimumPercent")
	return &CheckOutcome{
		Findings: findings,
		Metrics:  core.NewObject("people", total, "enrolled", total-float64(len(findings))),
		judge: func(remaining []*core.Object) *core.Object {
			percent := 100.0
			if total != 0 {
				percent = math.Floor(((total - float64(len(remaining))) / total) * 100)
			}
			if percent >= minimum {
				return checkVerdict("pass", core.NumberString(percent)+"% of people have a second factor")
			}
			return checkVerdict("fail", core.NumberString(percent)+"% of people have a second factor (at least "+core.NumberString(minimum)+"% required)")
		},
	}, nil
}

func evaluatePasswordLength(_ context.Context, _ *ServerContext, _ core.IamStore, tenant *core.Object, params *core.Object, _ float64) (*CheckOutcome, error) {
	policy := tenant.Get("authPolicy")
	passwordless := false
	if methods := member(policy, "allowedMethods"); !isUndefined(methods) {
		list, ok := methods.([]any)
		if !ok {
			if methods == nil {
				return nil, core.NewIamError("INTERNAL_ERROR", "Cannot read properties of null (reading 'includes')")
			}
			return nil, core.NewIamError("INTERNAL_ERROR", "policy.allowedMethods.includes is not a function")
		}
		passwordless = true
		for _, method := range list {
			if method == "password" {
				passwordless = false
				break
			}
		}
	}
	length := math.Max(12, jsNumber(coalesce(member(policy, "minPasswordLength"), 12.0)))
	minimum := paramOf(params, "minimum")
	ok := passwordless || length >= minimum
	findings := []*core.Object{}
	if !ok {
		findings = append(findings, checkFinding("tenant:"+jsString(tenant.Get("id"))+":password-length-"+core.NumberString(length), "Passwords may be "+core.NumberString(length)+" characters long"))
	}
	passwordlessMetric := 0.0
	if passwordless {
		passwordlessMetric = 1
	}
	return &CheckOutcome{
		Findings: findings,
		Metrics:  core.NewObject("minimumLength", length, "passwordless", passwordlessMetric),
		judge: func(remaining []*core.Object) *core.Object {
			if len(remaining) == 0 {
				switch {
				case passwordless:
					return checkVerdict("pass", "Passwords are not used")
				case ok:
					return checkVerdict("pass", "Passwords need "+core.NumberString(length)+" characters")
				}
				return checkVerdict("pass", "Accepted by exception")
			}
			return checkVerdict("fail", "Passwords need only "+core.NumberString(length)+" characters ("+core.NumberString(minimum)+" required)")
		},
	}, nil
}

func evaluateSessionLifetime(_ context.Context, server *ServerContext, _ core.IamStore, tenant *core.Object, params *core.Object, _ float64) (*CheckOutcome, error) {
	options := complianceAuthOptions(server)
	policy := tenant.Get("authPolicy")
	lifetime := 7 * 24 * complianceHour
	if options != nil && options.SessionLifetimeMs != nil {
		lifetime = float64(*options.SessionLifetimeMs)
	}
	lifetime = math.Min(lifetime, jsNumber(coalesce(member(policy, "sessionLifetimeMs"), math.Inf(1))))
	idle := math.Min(lifetime, 24*complianceHour)
	if options != nil && options.SessionIdleTimeoutMs != nil {
		idle = float64(*options.SessionIdleTimeoutMs)
	}
	idle = math.Min(idle, jsNumber(coalesce(member(policy, "sessionIdleTimeoutMs"), math.Inf(1))))
	hours := complianceRound(lifetime / complianceHour)
	minutes := complianceRound(idle / 60_000)
	tenantID := jsString(tenant.Get("id"))
	findings := []*core.Object{}
	if lifetime > paramOf(params, "maxHours")*complianceHour {
		findings = append(findings, checkFinding("tenant:"+tenantID+":lifetime-"+core.NumberString(hours)+"h", "Sessions last "+core.NumberString(hours)+" hours"))
	}
	if idle > paramOf(params, "idleMinutes")*60_000 {
		findings = append(findings, checkFinding("tenant:"+tenantID+":idle-"+core.NumberString(minutes)+"m", "Idle sessions last "+core.NumberString(minutes)+" minutes"))
	}
	return &CheckOutcome{
		Findings: findings,
		Metrics:  core.NewObject("lifetimeHours", hours, "idleMinutes", minutes),
		judge:    complianceCountJudge("session limit", "Sessions end on time"),
	}, nil
}

func evaluateInactiveAccounts(ctx context.Context, server *ServerContext, store core.IamStore, tenant *core.Object, params *core.Object, now float64) (*CheckOutcome, error) {
	days := paramOf(params, "days")
	cutoff := now - days*complianceDay
	findings := []*core.Object{}
	people, err := compliancePeople(ctx, server, store, tenant.Get("id"))
	if err != nil {
		return nil, err
	}
	for _, person := range people {
		if jsNumber(person.Get("createdAt")) > cutoff {
			continue
		}
		personID := jsString(person.Get("id"))
		record, err := store.Get(ctx, "authSignIns", personID)
		if err != nil {
			return nil, err
		}
		last := member(record, "lastAt")
		if isUndefined(last) || jsNumber(last) < cutoff {
			detail := "Has never signed in"
			if truthy(last) {
				detail = "Last signed in " + core.NumberString(math.Floor((now-jsNumber(last))/complianceDay)) + " days ago"
			}
			findings = append(findings, checkFinding("identity:"+personID, detail))
		}
	}
	return &CheckOutcome{
		Findings: findings,
		Metrics:  core.NewObject("inactive", float64(len(findings))),
		judge:    complianceCountJudge("inactive account", "Everyone signed in within "+core.NumberString(days)+" days"),
	}, nil
}

// countLive counts the records of a find that are live at now.
func countLive(ctx context.Context, store core.IamStore, collection string, filter *core.Object, live func(record *core.Object) bool) (float64, error) {
	records, err := store.Find(ctx, collection, filter, nil)
	if err != nil {
		return 0, err
	}
	count := 0.0
	for _, record := range records {
		if live(record) {
			count++
		}
	}
	return count, nil
}

func evaluateLeaverAccess(ctx context.Context, server *ServerContext, store core.IamStore, tenant *core.Object, _ *core.Object, now float64) (*CheckOutcome, error) {
	tenantID := tenant.Get("id")
	findings := []*core.Object{}
	identities, err := store.Find(ctx, "identities", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	for _, identity := range identities {
		status := identity.Get("status")
		leaving := status == "disabled" || (status == "active" && server.IdentityExpired(identity))
		if !leaving {
			continue
		}
		identityID := identity.Get("id")
		sessions, err := countLive(ctx, store, "sessions", core.NewObject("tenantId", tenantID, "identityId", identityID), func(session *core.Object) bool {
			return jsNumber(session.Get("expiresAt")) > now
		})
		if err != nil {
			return nil, err
		}
		live := func(record *core.Object) bool { return complianceLive(record, now) }
		bindings, err := countLive(ctx, store, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "identity", "subjectId", identityID), live)
		if err != nil {
			return nil, err
		}
		groups, err := countLive(ctx, store, "groupMembers", core.NewObject("tenantId", tenantID, "identityId", identityID), live)
		if err != nil {
			return nil, err
		}
		if sessions != 0 || bindings != 0 || groups != 0 {
			var held []string
			if sessions != 0 {
				held = append(held, compliancePlural(sessions, "session"))
			}
			if bindings != 0 {
				held = append(held, compliancePlural(bindings, "role binding"))
			}
			if groups != 0 {
				held = append(held, compliancePlural(groups, "group membership"))
			}
			state := "Expired"
			if status == "disabled" {
				state = "Disabled"
			}
			findings = append(findings, checkFinding("identity:"+jsString(identityID), state+" but still holds "+strings.Join(held, ", ")))
		}
	}
	return &CheckOutcome{
		Findings: findings,
		Metrics:  core.NewObject("leaversWithAccess", float64(len(findings))),
		judge:    complianceCountJudge("leaver with access", "Disabled and expired accounts hold no access"),
	}, nil
}

// apiKeyLabel is `Key "{name}"`, or `An API key` for a key without a name.
func apiKeyLabel(session *core.Object) string {
	if name := session.Get("name"); truthy(name) {
		return `Key "` + jsString(name) + `"`
	}
	return "An API key"
}

func evaluateStaleAPIKeys(ctx context.Context, _ *ServerContext, store core.IamStore, tenant *core.Object, params *core.Object, now float64) (*CheckOutcome, error) {
	days := paramOf(params, "days")
	cutoff := now - days*complianceDay
	findings := []*core.Object{}
	sessions, err := store.Find(ctx, "sessions", core.NewObject("tenantId", tenant.Get("id"), "kind", "api-key"), nil)
	if err != nil {
		return nil, err
	}
	for _, session := range sessions {
		if jsNumber(session.Get("expiresAt")) <= now {
			continue
		}
		last := jsNumber(coalesce(session.Get("lastSeenAt"), session.Get("createdAt")))
		if last < cutoff {
			findings = append(findings, checkFinding("session:"+jsString(session.Get("id")), apiKeyLabel(session)+" unused for "+core.NumberString(math.Floor((now-last)/complianceDay))+" days"))
		}
	}
	return &CheckOutcome{
		Findings: findings,
		Metrics:  core.NewObject("staleKeys", float64(len(findings))),
		judge:    complianceCountJudge("unused API key", "Every API key was used within "+core.NumberString(days)+" days"),
	}, nil
}

func evaluateAPIKeyLifetime(ctx context.Context, _ *ServerContext, store core.IamStore, tenant *core.Object, params *core.Object, now float64) (*CheckOutcome, error) {
	maxDays := paramOf(params, "maxDays")
	findings := []*core.Object{}
	sessions, err := store.Find(ctx, "sessions", core.NewObject("tenantId", tenant.Get("id"), "kind", "api-key"), nil)
	if err != nil {
		return nil, err
	}
	for _, session := range sessions {
		expiresAt := jsNumber(session.Get("expiresAt"))
		if expiresAt <= now {
			continue
		}
		days := math.Floor((expiresAt - jsNumber(session.Get("createdAt"))) / complianceDay)
		if days > maxDays {
			findings = append(findings, checkFinding("session:"+jsString(session.Get("id")), apiKeyLabel(session)+" lives "+core.NumberString(days)+" days"))
		}
	}
	return &CheckOutcome{
		Findings: findings,
		Metrics:  core.NewObject("longLivedKeys", float64(len(findings))),
		judge:    complianceCountJudge("long-lived API key", "Every API key expires within "+core.NumberString(maxDays)+" days"),
	}, nil
}

func evaluateAccessReviews(ctx context.Context, _ *ServerContext, store core.IamStore, tenant *core.Object, params *core.Object, now float64) (*CheckOutcome, error) {
	tenantID := tenant.Get("id")
	intervalDays := paramOf(params, "intervalDays")
	minDecided := paramOf(params, "minDecidedPercent")
	minCoverage := paramOf(params, "minCoveragePercent")
	since := now - intervalDays*complianceDay
	campaigns, err := store.Find(ctx, "certificationCampaigns", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	findings := []*core.Object{}
	// Roles covered by campaigns that count: closed within the interval, not empty, mostly decided by people.
	covered := map[string]bool{}
	qualifying := 0.0
	latestQualifying := 0.0
	latestClosed := 0.0
	lastDecidedPercent := -1.0
	for _, campaign := range campaigns {
		closedAtValue := campaign.Get("closedAt")
		if campaign.Get("status") != "closed" || isUndefined(closedAtValue) || jsNumber(closedAtValue) < since {
			continue
		}
		closedAt := jsNumber(closedAtValue)
		items, err := store.Find(ctx, "certificationItems", core.NewObject("tenantId", tenantID, "campaignId", campaign.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		decided := 0.0
		for _, item := range items {
			if !isUndefined(item.Get("decidedBy")) {
				decided++
			}
		}
		percent := 0.0
		if len(items) > 0 {
			percent = math.Floor((decided / float64(len(items))) * 100)
		}
		if closedAt >= latestClosed {
			latestClosed = closedAt
			lastDecidedPercent = percent
		}
		if len(items) == 0 || percent < minDecided {
			continue
		}
		qualifying++
		latestQualifying = math.Max(latestQualifying, closedAt)
		for _, item := range items {
			covered[jsString(item.Get("roleId"))] = true
		}
	}
	if qualifying == 0 {
		findings = append(findings, checkFinding("tenant:"+jsString(tenantID)+":no-review", "No review closed in the last "+core.NumberString(intervalDays)+" days with at least "+core.NumberString(minDecided)+"% of its items decided by a reviewer"))
	}
	// Roles held today (live bindings to unprotected roles); owners are the owner-redundancy and privileged checks'.
	roleList, err := store.Find(ctx, "roles", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	roles := map[string]*core.Object{}
	for _, role := range roleList {
		if !truthy(role.Get("protected")) {
			roles[jsString(role.Get("id"))] = role
		}
	}
	held := map[string]bool{}
	var heldOrder []string
	bindings, err := store.Find(ctx, "bindings", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	for _, binding := range bindings {
		roleID, ok := binding.Get("roleId").(string)
		if !ok {
			continue
		}
		if _, found := roles[roleID]; found && complianceLive(binding, now) && !held[roleID] {
			held[roleID] = true
			heldOrder = append(heldOrder, roleID)
		}
	}
	var uncovered []string
	for _, roleID := range heldOrder {
		if !covered[roleID] {
			uncovered = append(uncovered, roleID)
		}
	}
	sortStrings(uncovered)
	if qualifying != 0 {
		for _, roleID := range uncovered {
			findings = append(findings, checkFinding("role:"+roleID, `Role "`+jsString(roles[roleID].Get("name"))+`" is held but no counted review covered it`))
		}
	}
	for _, campaign := range campaigns {
		dueAt := campaign.Get("dueAt")
		if campaign.Get("status") == "open" && !isUndefined(dueAt) && jsNumber(dueAt) < now {
			findings = append(findings, checkFinding("campaign:"+jsString(campaign.Get("id")), `Review "`+jsString(campaign.Get("name"))+`" is `+core.NumberString(math.Floor((now-jsNumber(dueAt))/complianceDay))+" days overdue"))
		}
	}
	heldCount := float64(len(heldOrder))
	coverage := 100.0
	if heldCount != 0 {
		coverage = math.Floor(((heldCount - float64(len(uncovered))) / heldCount) * 100)
	}
	lastClosedDaysAgo := -1.0
	if latestQualifying != 0 {
		lastClosedDaysAgo = math.Floor((now - latestQualifying) / complianceDay)
	}
	return &CheckOutcome{
		Findings: findings,
		Metrics: core.NewObject(
			"campaigns", float64(len(campaigns)),
			"qualifying", qualifying,
			"rolesHeld", heldCount,
			"coveragePercent", coverage,
			"lastDecidedPercent", lastDecidedPercent,
			"lastClosedDaysAgo", lastClosedDaysAgo,
		),
		judge: func(remaining []*core.Object) *core.Object {
			noReview := false
			overdue, missing := 0.0, 0.0
			for _, finding := range remaining {
				subject := findingSubject(finding)
				if strings.HasSuffix(subject, ":no-review") {
					noReview = true
				}
				if strings.HasPrefix(subject, "campaign:") {
					overdue++
				}
				if strings.HasPrefix(subject, "role:") {
					missing++
				}
			}
			percent := 100.0
			if heldCount != 0 {
				percent = math.Floor(((heldCount - missing) / heldCount) * 100)
			}
			if noReview {
				return checkVerdict("fail", "No counted review within the interval")
			}
			if percent < minCoverage {
				return checkVerdict("fail", "Reviews covered "+core.NumberString(percent)+"% of the roles held ("+core.NumberString(minCoverage)+"% required)")
			}
			if overdue != 0 {
				return checkVerdict("fail", compliancePlural(overdue, "review")+" overdue")
			}
			return checkVerdict("pass", "Access was reviewed within "+core.NumberString(intervalDays)+" days ("+core.NumberString(percent)+"% of roles)")
		},
	}, nil
}

func evaluatePrivilegedAccess(ctx context.Context, server *ServerContext, store core.IamStore, tenant *core.Object, params *core.Object, now float64) (*CheckOutcome, error) {
	holders, eligibleWithApproval, err := privilegedHolders(ctx, server, store, jsString(tenant.Get("id")), now)
	if err != nil {
		return nil, err
	}
	findings := make([]*core.Object, 0, len(holders.keys))
	for _, subject := range holders.keys {
		findings = append(findings, checkFinding(subject, "Holds full administration ("+holders.via[subject]+")"))
	}
	maxHolders := paramOf(params, "maxHolders")
	return &CheckOutcome{
		Findings: findings,
		Metrics:  core.NewObject("holders", float64(len(holders.keys)), "eligibleWithApproval", eligibleWithApproval),
		judge: func(remaining []*core.Object) *core.Object {
			count := float64(len(remaining))
			if count <= maxHolders {
				return checkVerdict("pass", compliancePlural(count, "holder")+" of full administration")
			}
			return checkVerdict("fail", compliancePlural(count, "holder")+" of full administration (at most "+core.NumberString(maxHolders)+")")
		},
	}, nil
}

func evaluateOwnerRedundancy(ctx context.Context, server *ServerContext, store core.IamStore, tenant *core.Object, _ *core.Object, _ float64) (*CheckOutcome, error) {
	people, err := compliancePeople(ctx, server, store, tenant.Get("id"))
	if err != nil {
		return nil, err
	}
	owners := 0.0
	for _, identity := range people {
		if truthy(identity.Get("owner")) {
			owners++
		}
	}
	findings := []*core.Object{}
	if owners < 2 {
		findings = append(findings, checkFinding("tenant:"+jsString(tenant.Get("id"))+":owners-"+core.NumberString(owners), compliancePlural(owners, "active owner")))
	}
	return &CheckOutcome{
		Findings: findings,
		Metrics:  core.NewObject("owners", owners),
		judge: func(remaining []*core.Object) *core.Object {
			if len(remaining) == 0 {
				if owners >= 2 {
					return checkVerdict("pass", core.NumberString(owners)+" owners")
				}
				return checkVerdict("pass", "Accepted by exception")
			}
			if owners != 0 {
				return checkVerdict("warn", "Only one owner")
			}
			return checkVerdict("fail", "No active owner")
		},
	}, nil
}

func evaluateSeparationOfDuties(ctx context.Context, server *ServerContext, store core.IamStore, tenant *core.Object, _ *core.Object, _ float64) (*CheckOutcome, error) {
	tenantID := jsString(tenant.Get("id"))
	rules, err := store.Find(ctx, "sodRules", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return &CheckOutcome{
			Findings: []*core.Object{},
			Metrics:  core.NewObject("rules", 0.0),
			// Frameworks that map here (ISO 5.3, NIST AC-5) expect duties to be separated: no rule is not a pass.
			judge: func([]*core.Object) *core.Object {
				return checkVerdict("warn", "No separation-of-duties rules are defined")
			},
		}, nil
	}
	violations, err := SodViolations(ctx, server, store, tenantID, nil, nil)
	if err != nil {
		return nil, err
	}
	findings := make([]*core.Object, len(violations))
	for index, violation := range violations {
		findings[index] = checkFinding(
			"identity:"+jsString(violation.Get("identityId"))+":rule:"+jsString(violation.Get("ruleId")),
			`Breaks rule "`+jsString(violation.Get("ruleName"))+`"`,
		)
	}
	return &CheckOutcome{
		Findings: findings,
		Metrics:  core.NewObject("rules", float64(len(rules)), "violations", float64(len(violations))),
		judge:    complianceCountJudge("separation-of-duties violation", "No separation-of-duties violations"),
	}, nil
}

func evaluateAuditIntegrity(ctx context.Context, _ *ServerContext, store core.IamStore, tenant *core.Object, _ *core.Object, _ float64) (*CheckOutcome, error) {
	tenantID := jsString(tenant.Get("id"))
	head, err := store.Get(ctx, "auditChains", tenantID)
	if err != nil {
		return nil, err
	}
	checkpointKey, _ := CheckpointID(tenantID)
	saved, err := store.Get(ctx, "complianceCheckpoints", checkpointKey)
	if err != nil {
		return nil, err
	}
	sequence := jsNumber(coalesce(member(saved, "sequence"), 0.0))
	hash := member(saved, "hash")
	checked := 0.0
	failure := ""
	partial := false
	target := jsNumber(coalesce(member(head, "sequence"), 0.0))
	for failure == "" && sequence < target {
		if checked >= auditPageSize*auditPages {
			partial = true
			break
		}
		from, to, limit := sequence+1, target, auditPageSize
		events, err := core.FindOrdered(ctx, store, "audit", core.NewObject("tenantId", tenantID), core.OrderOptions{Field: "sequence", From: &from, To: &to, Limit: &limit}, nil)
		if err != nil {
			return nil, err
		}
		if len(events) == 0 {
			failure = "Events " + core.NumberString(sequence+1) + " to " + core.NumberString(target) + " are missing"
			break
		}
		first := events[0]
		firstSequence := jsNumber(first.Get("sequence"))
		previousHash := hash
		if firstSequence != sequence+1 {
			// A gap is only acceptable as a pruned prefix, which audit:prune recorded with the hash it ended on.
			prunes, err := store.Find(ctx, "audit", core.NewObject("tenantId", tenantID, "action", "audit:prune"), nil)
			if err != nil {
				return nil, err
			}
			pruned := false
			for _, event := range prunes {
				metadata := event.Get("metadata")
				if strictEquals(member(metadata, "prunedThroughSequence"), firstSequence-1) && strictEquals(member(metadata, "prunedThroughHash"), first.Get("previousHash")) {
					pruned = true
					break
				}
			}
			if !pruned {
				failure = "Events " + core.NumberString(sequence+1) + " to " + core.NumberString(firstSequence-1) + " are missing"
				break
			}
			previousHash = first.Get("previousHash")
		}
		options := core.VerifyAuditChainOptions{}
		if text, ok := previousHash.(string); ok {
			options.PreviousHash = &text
		}
		verification := core.VerifyAuditChain(events, options)
		if !verification.Valid {
			at, reason := "?", "unknown"
			if verification.Failure != nil {
				at = core.NumberString(verification.Failure.Sequence)
				if verification.Failure.Reason != "" {
					reason = string(verification.Failure.Reason)
				}
			}
			failure = "The chain breaks at sequence " + at + " (" + reason + ")"
			break
		}
		checked += float64(verification.Checked)
		if verification.Last == nil || verification.LastHash == nil {
			sequence, hash = math.NaN(), core.Undefined
			break
		}
		sequence = *verification.Last
		hash = *verification.LastHash
	}
	if failure == "" && !partial && head != nil && (!strictEquals(sequence, head.Get("sequence")) || !strictEquals(hash, head.Get("hash"))) {
		failure = "The newest event does not match the chain head"
	}
	findings := []*core.Object{}
	if failure != "" {
		findings = append(findings, checkFinding("tenant:"+tenantID+":audit-chain", failure))
	}
	outcome := &CheckOutcome{
		Findings: findings,
		Metrics:  core.NewObject("checked", checked, "verifiedThrough", sequence, "head", target),
		judge: func(remaining []*core.Object) *core.Object {
			switch {
			case len(remaining) != 0:
				return checkVerdict("fail", failure)
			case partial:
				return checkVerdict("warn", "Verified through event "+core.NumberString(sequence)+" of "+core.NumberString(target)+"; the next run continues")
			}
			return checkVerdict("pass", "The audit chain verifies through event "+core.NumberString(sequence))
		},
	}
	if failure == "" && !isUndefined(hash) && sequence > 0 {
		outcome.Checkpoint = core.NewObject("sequence", sequence, "hash", hash)
	}
	return outcome, nil
}

func evaluatePrivacyDeadlines(ctx context.Context, _ *ServerContext, store core.IamStore, tenant *core.Object, _ *core.Object, now float64) (*CheckOutcome, error) {
	requests, err := store.Find(ctx, "privacyRequests", core.NewObject("tenantId", tenant.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	var overdue []*core.Object
	for _, request := range requests {
		late, err := RequestOverdue(request, int64(now))
		if err != nil {
			return nil, err
		}
		if late {
			overdue = append(overdue, request)
		}
	}
	findings := make([]*core.Object, len(overdue))
	for index, request := range overdue {
		findings[index] = checkFinding(
			"request:"+jsString(request.Get("id")),
			jsString(request.Get("number"))+" ("+jsString(request.Get("type"))+") was due "+core.NumberString(math.Floor((now-jsNumber(request.Get("dueAt")))/complianceDay))+" days ago",
		)
	}
	return &CheckOutcome{
		Findings: findings,
		Metrics:  core.NewObject("requests", float64(len(requests)), "overdue", float64(len(overdue))),
		judge:    complianceCountJudge("overdue request", "No data-subject request is overdue"),
	}, nil
}

// CheckParams (compliance.ts checkParams): Validates check parameters, filling defaults.
func CheckParams(check *ComplianceCheck, value any) (result *core.Object, err error) {
	var input *core.Object
	switch v := value.(type) {
	case nil, core.UndefinedType:
		input = core.NewObject()
	case *core.Object:
		input = v
	}
	if input == nil {
		return nil, invalidInput("params must be an object")
	}
	for _, key := range input.Keys() {
		known := false
		for _, param := range check.Params {
			if param.Get("name") == key {
				known = true
				break
			}
		}
		if !known {
			return nil, invalidInput(check.ID + " has no parameter " + key)
		}
	}
	result = core.NewObject()
	for _, param := range check.Params {
		name := jsString(param.Get("name"))
		given := input.Get(name)
		if isUndefined(given) {
			result.Set(name, param.Get("default"))
			continue
		}
		number, err := Integer(given, "params."+name, jsNumber(param.Get("min")), jsNumber(param.Get("max")))
		if err != nil {
			return nil, err
		}
		result.Set(name, number)
	}
	return result, nil
}

// CheckpointID (compliance.ts checkpointId): the ID of a tenant's audit verification checkpoint
// (`complianceCheckpoints`, `audit:{tenantId}`).
func CheckpointID(tenantID string) (result string, err error) {
	return "audit:" + tenantID, nil
}

// EffectiveParams (compliance.ts effectiveParams): Stored parameters brought within the check's current bounds
// (bounds tighten over releases).
func EffectiveParams(check *ComplianceCheck, stored *core.Object) (result *core.Object, err error) {
	result = core.NewObject()
	for _, param := range check.Params {
		name := jsString(param.Get("name"))
		if stored == nil {
			return nil, core.NewIamError("INTERNAL_ERROR", "Cannot read properties of undefined (reading '"+name+"')")
		}
		value, ok := stored.Get(name).(float64)
		if ok && !math.IsNaN(value) && !math.IsInf(value, 0) {
			result.Set(name, math.Min(jsNumber(param.Get("max")), math.Max(jsNumber(param.Get("min")), math.Trunc(value))))
		} else {
			result.Set(name, param.Get("default"))
		}
	}
	return result, nil
}

// ExceptionActive (compliance.ts exceptionActive): Whether an exception covers findings now.
func ExceptionActive(exception *core.Object, now int64) (result bool, err error) {
	return exceptionActive(exception, float64(now)), nil
}

// exceptionActive is ExceptionActive without the error.
func exceptionActive(exception *core.Object, now float64) bool {
	status := exception.Get("status")
	return (isUndefined(status) || status == "approved") && jsNumber(exception.Get("expiresAt")) > now
}

// ComplianceFrameworks is compliance.ts complianceFrameworks.
var ComplianceFrameworks = mustModel(`[{"id":"soc2","name":"SOC 2 (Trust Services Criteria)","requirements":[{"id":"CC6.1","title":"Logical access security","checks":["mfa-enforced","mfa-coverage","password-length","session-lifetime","api-key-lifetime"]},{"id":"CC6.2","title":"Registration and deregistration of users","checks":["leaver-access","inactive-accounts"]},{"id":"CC6.3","title":"Role-based access, least privilege, and access review","checks":["access-reviews","privileged-access","separation-of-duties","stale-api-keys"]},{"id":"CC7.2","title":"Monitoring of system components","checks":["audit-integrity"]}]},{"id":"iso27001","name":"ISO/IEC 27001:2022 Annex A","requirements":[{"id":"5.3","title":"Segregation of duties","checks":["separation-of-duties"]},{"id":"5.16","title":"Identity management","checks":["leaver-access","inactive-accounts"]},{"id":"5.17","title":"Authentication information","checks":["password-length","api-key-lifetime"]},{"id":"5.18","title":"Access rights","checks":["access-reviews","stale-api-keys"]},{"id":"5.34","title":"Privacy and protection of PII","checks":["privacy-deadlines"]},{"id":"8.2","title":"Privileged access rights","checks":["privileged-access","owner-redundancy"]},{"id":"8.5","title":"Secure authentication","checks":["mfa-enforced","mfa-coverage","session-lifetime"]},{"id":"8.15","title":"Logging","checks":["audit-integrity"]}]},{"id":"nist-800-53","name":"NIST SP 800-53 Rev. 5","requirements":[{"id":"AC-2","title":"Account management","checks":["leaver-access","inactive-accounts"]},{"id":"AC-5","title":"Separation of duties","checks":["separation-of-duties"]},{"id":"AC-6","title":"Least privilege","checks":["privileged-access"]},{"id":"AC-6(7)","title":"Review of user privileges","checks":["access-reviews"]},{"id":"AC-12","title":"Session termination","checks":["session-lifetime"]},{"id":"IA-2(1)","title":"Multi-factor authentication","checks":["mfa-enforced","mfa-coverage"]},{"id":"IA-5","title":"Authenticator management","checks":["password-length","api-key-lifetime","stale-api-keys"]},{"id":"AU-9","title":"Protection of audit information","checks":["audit-integrity"]}]},{"id":"gdpr","name":"GDPR (selected articles)","requirements":[{"id":"Art. 12","title":"Responding to data subjects in time","checks":["privacy-deadlines"]},{"id":"Art. 32","title":"Security of processing","checks":["mfa-coverage","audit-integrity","leaver-access"]}]}]`)

// FrameworkByID is compliance.ts frameworkById.
var FrameworkByID = mustObject(`{"soc2":{"id":"soc2","name":"SOC 2 (Trust Services Criteria)","requirements":[{"id":"CC6.1","title":"Logical access security","checks":["mfa-enforced","mfa-coverage","password-length","session-lifetime","api-key-lifetime"]},{"id":"CC6.2","title":"Registration and deregistration of users","checks":["leaver-access","inactive-accounts"]},{"id":"CC6.3","title":"Role-based access, least privilege, and access review","checks":["access-reviews","privileged-access","separation-of-duties","stale-api-keys"]},{"id":"CC7.2","title":"Monitoring of system components","checks":["audit-integrity"]}]},"iso27001":{"id":"iso27001","name":"ISO/IEC 27001:2022 Annex A","requirements":[{"id":"5.3","title":"Segregation of duties","checks":["separation-of-duties"]},{"id":"5.16","title":"Identity management","checks":["leaver-access","inactive-accounts"]},{"id":"5.17","title":"Authentication information","checks":["password-length","api-key-lifetime"]},{"id":"5.18","title":"Access rights","checks":["access-reviews","stale-api-keys"]},{"id":"5.34","title":"Privacy and protection of PII","checks":["privacy-deadlines"]},{"id":"8.2","title":"Privileged access rights","checks":["privileged-access","owner-redundancy"]},{"id":"8.5","title":"Secure authentication","checks":["mfa-enforced","mfa-coverage","session-lifetime"]},{"id":"8.15","title":"Logging","checks":["audit-integrity"]}]},"nist-800-53":{"id":"nist-800-53","name":"NIST SP 800-53 Rev. 5","requirements":[{"id":"AC-2","title":"Account management","checks":["leaver-access","inactive-accounts"]},{"id":"AC-5","title":"Separation of duties","checks":["separation-of-duties"]},{"id":"AC-6","title":"Least privilege","checks":["privileged-access"]},{"id":"AC-6(7)","title":"Review of user privileges","checks":["access-reviews"]},{"id":"AC-12","title":"Session termination","checks":["session-lifetime"]},{"id":"IA-2(1)","title":"Multi-factor authentication","checks":["mfa-enforced","mfa-coverage"]},{"id":"IA-5","title":"Authenticator management","checks":["password-length","api-key-lifetime","stale-api-keys"]},{"id":"AU-9","title":"Protection of audit information","checks":["audit-integrity"]}]},"gdpr":{"id":"gdpr","name":"GDPR (selected articles)","requirements":[{"id":"Art. 12","title":"Responding to data subjects in time","checks":["privacy-deadlines"]},{"id":"Art. 32","title":"Security of processing","checks":["mfa-coverage","audit-integrity","leaver-access"]}]}}`)

// ComplianceCheck is compliance.ts ComplianceCheck.
type ComplianceCheck struct {
	server      *ServerContext
	ID          string
	Title       string
	Description string
	Params      []*core.Object
	// NoExceptions Exceptions may not cover this check's findings (a broken audit chain cannot be accepted).
	NoExceptions *bool
	evaluate     checkEvaluator
}

// noExceptions is `check.noExceptions` as a boolean.
func (s *ComplianceCheck) noExceptions() bool { return s.NoExceptions != nil && *s.NoExceptions }

// Evaluate (compliance.ts ComplianceCheck.evaluate): `store` is read outside any transaction.
func (s *ComplianceCheck) Evaluate(ctx context.Context, server *ServerContext, store core.IamStore, tenant *core.Object, params *core.Object, now int64) (result *CheckOutcome, err error) {
	return s.evaluate(ctx, server, store, tenant, params, float64(now))
}

// CheckOutcome is compliance.ts CheckOutcome.
type CheckOutcome struct {
	server   *ServerContext
	Findings []*core.Object
	Metrics  *core.Object
	// Checkpoint Audit verification progress to store (audit-integrity only).
	Checkpoint *core.Object
	judge      func(remaining []*core.Object) *core.Object
}

// Judge (compliance.ts CheckOutcome.judge): The status given the findings that no exception covers.
func (s *CheckOutcome) Judge(remaining []*core.Object) (result *core.Object, err error) {
	return s.judge(remaining), nil
}
