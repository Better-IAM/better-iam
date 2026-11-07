package server

// Port of packages/server/src/api/threats.ts: identity threat detection and response. Detection rules (sign-in
// attacks, session theft, account takeover, privilege escalation, mass changes, weakened guardrails, audit tampering)
// read each tenant's audit trail through the `iam.detectThreats()` job, group detections into incidents per subject,
// and raise a decaying risk score per identity that policies read as `principal.riskLevel` / `principal.riskScore`.
// Administrators tune the rules, investigate and resolve incidents, respond by hand (end sessions, forget devices,
// contain an identity, block a network, notify), and define playbooks that respond automatically. Reading needs
// `iam:threats:read`, tuning and triage `iam:threats:manage`, and acting on identities and networks
// `iam:threats:respond`, all on `iam/threats/...`; people report suspicious activity on their own account without a
// permission.
//
// Records are model values: ThreatDetection, ThreatIncident, ThreatNote, ThreatPlaybook, ThreatResponse, IdentityRisk
// and ThreatSettings as threats.ts defines them. A response request's `actor` is `{principal}` with the *Principal
// stored raw (SetRaw), as threat-response.ts's ResponseActor `{ principal: AuthenticatedPrincipal }`.

import (
	"context"
	"math"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// ThreatsAPI is the `threats` API group (packages/server/src/api/threats.ts createThreatsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/threats/{method} onto it.
type ThreatsAPI struct {
	server *ServerContext
}

// CreateThreatsAPI builds the `threats` API group.
func CreateThreatsAPI(server *ServerContext) *ThreatsAPI {
	return &ThreatsAPI{server: server}
}

const (
	threatsAPIMinute = 60_000.0
	threatsAPIHour   = 60 * threatsAPIMinute
	threatsAPIDay    = 24 * threatsAPIHour
	// threatsAPIMaxPlaybooks is how many playbooks a tenant may define.
	threatsAPIMaxPlaybooks = 50
	// threatsAPIMaxNotesPerIncident is how many notes one incident may hold.
	threatsAPIMaxNotesPerIncident = 500
	// threatsAPIMaxReportsPerDay is how many reports one person may file in 24 hours.
	threatsAPIMaxReportsPerDay = 5
	// threatsAPIMaxSafeInteger is Number.MAX_SAFE_INTEGER.
	threatsAPIMaxSafeInteger = 9_007_199_254_740_991
)

var (
	threatsAPIIncidentStatuses    = []string{"open", "investigating"}
	threatsAPIDetectionStatuses   = []string{"open", "dismissed", "resolved"}
	threatsAPIAllIncidentStatuses = []string{"open", "investigating", "resolved"}
	threatsAPIResolutions         = []string{"true-positive", "false-positive", "benign"}
	threatsAPIRaisedLevels        = []string{"low", "medium", "high"}
	threatsAPISubjectTypes        = []string{"identity", "network", "tenant", "connection"}
)

func threatsAPIDetectionResource(detectionID string) string {
	return "threats/detections/" + detectionID
}
func threatsAPIIncidentResource(incidentID string) string { return "threats/incidents/" + incidentID }
func threatsAPIRiskResource(identityID string) string     { return "threats/risk/" + identityID }
func threatsAPIPlaybookResource(playbookID string) string { return "threats/playbooks/" + playbookID }

// threatsAPIPersonLabel is how responses name a person: their name, else their email (as the response module does).
func threatsAPIPersonLabel(identity *core.Object) any {
	if name := identity.Get("name"); truthy(name) {
		return name
	}
	if email := identity.Get("email"); truthy(email) {
		return email
	}
	return identity.Get("id")
}

// threatsAPIDetectionLabel is how detections name a person: as the detection rules do, name and email.
func threatsAPIDetectionLabel(identity *core.Object) (string, error) {
	return IdentityLabel(identity, jsString(identity.Get("id")))
}

// threatsAPIRuleCatalog is threatRules: the rule catalog in display order (threatRuleIds keeps that order).
func threatsAPIRuleCatalog() ([]*core.Object, error) {
	ids := ThreatRuleIDs.Values()
	rules := make([]*core.Object, 0, len(ids))
	for _, ruleID := range ids {
		rule, err := ThreatRule(ruleID)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// threatsAPISlice is `text.slice(0, end)` over UTF-16 code units.
func threatsAPISlice(text string, end int) string {
	units := core.ToUTF16(text)
	if end >= len(units) {
		return text
	}
	return core.FromUTF16(units[:end])
}

// threatsAPIObjects is a list member as records (anything that is not an object reads as an empty one).
func threatsAPIObjects(value any) []*core.Object {
	list, _ := value.([]any)
	out := make([]*core.Object, 0, len(list))
	for _, item := range list {
		if record, ok := item.(*core.Object); ok && record != nil {
			out = append(out, record)
		} else {
			out = append(out, core.NewObject())
		}
	}
	return out
}

// threatsAPIList is a list of records as a model list.
func threatsAPIList(records []*core.Object) []any {
	out := make([]any, len(records))
	for index, record := range records {
		out[index] = record
	}
	return out
}

// threatsAPIPage is `records.slice(offset, offset + limit)`.
func threatsAPIPage(records []*core.Object, offset, limit float64) []*core.Object {
	start := int(math.Min(offset, float64(len(records))))
	end := int(math.Min(offset+limit, float64(len(records))))
	if end < start {
		end = start
	}
	return records[start:end]
}

// threatsAPIStrings is a model list of strings as Go strings (non-strings are left out).
func threatsAPIStrings(value any) []string {
	list, _ := value.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

// threatsAPIRule is `settings.rules[ruleId]` of resolved settings.
func threatsAPIRule(settings *core.Object, ruleID string) *core.Object {
	rule, _ := member(settings.Get("rules"), ruleID).(*core.Object)
	if rule == nil {
		return core.NewObject()
	}
	return rule
}

// threatsAPIHalfLife is `settings.riskHalfLifeHours`.
func threatsAPIHalfLife(settings *core.Object) float64 {
	return jsNumber(settings.Get("riskHalfLifeHours"))
}

// threatsAPIActor is the response actor `{ principal }`; the principal is kept raw, never normalized.
func threatsAPIActor(principal *Principal) *core.Object {
	return core.NewObject().SetRaw("principal", principal)
}

func threatsAPIOneOf(value any, allowed []string, name string) (string, error) {
	text, ok := value.(string)
	if !ok || !containsString(allowed, text) {
		return "", invalidInput(name + " must be one of " + strings.Join(allowed, ", "))
	}
	return text, nil
}

func threatsAPIRuleIDOf(value any, name string) (string, error) {
	text, ok := value.(string)
	if !ok || !ThreatRuleIDs.Has(text) {
		return "", invalidInput(name + " names an unknown detection rule")
	}
	return text, nil
}

func threatsAPIFlag(value any, name string) (bool, error) {
	flag, ok := value.(bool)
	if !ok {
		return false, invalidInput(name + " must be a boolean")
	}
	return flag, nil
}

// threatsAPICanonical is JSON with object keys sorted, to compare settings regardless of the order their keys were
// written in.
func threatsAPICanonical(value any) string { return core.CanonicalJSON(value) }

// threatsAPIStringify is JSON.stringify.
func threatsAPIStringify(value any) string {
	text, _, _ := core.Stringify(value)
	return text
}

// threatsAPIRuleSignature is the effective values of a resolved rule setting, for telling whether a change altered
// what the rule does.
func threatsAPIRuleSignature(setting *core.Object) string {
	return threatsAPIStringify([]any{
		setting.Get("enabled"),
		setting.Get("severity"),
		coalesce(setting.Get("threshold"), nil),
		coalesce(setting.Get("windowMs"), nil),
		setting.Get("everyone") == true,
	})
}

// threatsAPIWeakening is one way a settings change weakens detection or response (`threats.configure` reports it as
// guardrail-weakened): key is the setting as audit metadata names it, words what the caller did.
type threatsAPIWeakening struct {
	key   string
	words string
}

// threatsAPIListed is a few items in words: "a", "a and b", "a, b and 3 more".
func threatsAPIListed(items []string, limit int) string {
	shown := items
	if len(shown) > limit {
		shown = shown[:limit]
	}
	rest := len(items) - len(shown)
	if rest > 0 {
		return strings.Join(shown, ", ") + " and " + core.NumberString(float64(rest)) + " more"
	}
	if len(shown) <= 1 {
		return strings.Join(shown, "")
	}
	return strings.Join(shown[:len(shown)-1], ", ") + " and " + shown[len(shown)-1]
}

// threatsAPINumber is a number member: ok is false when it is absent (undefined).
func threatsAPINumber(record *core.Object, key string) (float64, bool) {
	value := record.Get(key)
	if isUndefined(value) {
		return 0, false
	}
	return jsNumber(value), true
}

// threatsAPIWeakenings is what a settings change weakens besides turning rules off (reported on its own): a rule that
// stays on made less sensitive (a higher threshold, a shorter window, a lower severity, new-network no longer
// reporting everyone), a shorter risk half-life (every score decays at once), a longer dormancy period, newly trusted
// networks (never reported, never blocked), a lower automatic containment brake, and fewer people emailed about
// incidents.
func threatsAPIWeakenings(before, after *core.Object) ([]threatsAPIWeakening, error) {
	found := []threatsAPIWeakening{}
	rules, err := threatsAPIRuleCatalog()
	if err != nil {
		return nil, err
	}
	for _, rule := range rules {
		ruleID := jsString(rule.Get("id"))
		was := threatsAPIRule(before, ruleID)
		is := threatsAPIRule(after, ruleID)
		if !truthy(was.Get("enabled")) || !truthy(is.Get("enabled")) {
			continue
		}
		key := "rules." + ruleID
		name := `"` + jsString(rule.Get("title")) + `"`
		wasThreshold, wasHas := threatsAPINumber(was, "threshold")
		isThreshold, isHas := threatsAPINumber(is, "threshold")
		if wasHas && isHas && isThreshold > wasThreshold {
			found = append(found, threatsAPIWeakening{
				key:   key + ".threshold",
				words: "raised the threshold of " + name + " from " + core.NumberString(wasThreshold) + " to " + core.NumberString(isThreshold),
			})
		}
		wasWindow, wasHas := threatsAPINumber(was, "windowMs")
		isWindow, isHas := threatsAPINumber(is, "windowMs")
		if wasHas && isHas && isWindow < wasWindow {
			found = append(found, threatsAPIWeakening{
				key: key + ".windowMs",
				words: "shortened the window of " + name + " from " + core.NumberString(jsMathRound(wasWindow/threatsAPIMinute)) +
					" to " + core.NumberString(jsMathRound(isWindow/threatsAPIMinute)) + " minutes",
			})
		}
		atLeast, err := SeverityAtLeast(jsString(is.Get("severity")), jsString(was.Get("severity")))
		if err != nil {
			return nil, err
		}
		if !atLeast {
			found = append(found, threatsAPIWeakening{
				key:   key + ".severity",
				words: "lowered the severity of " + name + " from " + jsString(was.Get("severity")) + " to " + jsString(is.Get("severity")),
			})
		}
		if was.Get("everyone") == true && is.Get("everyone") != true {
			found = append(found, threatsAPIWeakening{key: key + ".everyone", words: "stopped " + name + " reporting everyone"})
		}
	}
	beforeHalfLife, afterHalfLife := threatsAPIHalfLife(before), threatsAPIHalfLife(after)
	if afterHalfLife < beforeHalfLife {
		found = append(found, threatsAPIWeakening{
			key:   "riskHalfLifeHours",
			words: "shortened the risk half-life from " + core.NumberString(beforeHalfLife) + " to " + core.NumberString(afterHalfLife) + " hours",
		})
	}
	beforeDormant, afterDormant := jsNumber(before.Get("dormantDays")), jsNumber(after.Get("dormantDays"))
	if afterDormant > beforeDormant {
		found = append(found, threatsAPIWeakening{
			key:   "dormantDays",
			words: "lengthened the dormancy period from " + core.NumberString(beforeDormant) + " to " + core.NumberString(afterDormant) + " days",
		})
	}
	beforeTrusted := threatsAPIStrings(before.Get("trustedNetworks"))
	trusted := []string{}
	for _, network := range threatsAPIStrings(after.Get("trustedNetworks")) {
		if !containsString(beforeTrusted, network) {
			trusted = append(trusted, network)
		}
	}
	if len(trusted) > 0 {
		found = append(found, threatsAPIWeakening{key: "trustedNetworks", words: "trusted " + threatsAPIListed(trusted, 3)})
	}
	beforeBrake, afterBrake := jsNumber(before.Get("maxAutomaticContainments")), jsNumber(after.Get("maxAutomaticContainments"))
	if afterBrake < beforeBrake {
		found = append(found, threatsAPIWeakening{
			key:   "maxAutomaticContainments",
			words: "lowered the automatic containment limit from " + core.NumberString(beforeBrake) + " to " + core.NumberString(afterBrake),
		})
	}
	beforeNotify, _ := before.Get("notify").(*core.Object)
	afterNotify, _ := after.Get("notify").(*core.Object)
	afterEmails := threatsAPIStrings(member(afterNotify, "emails"))
	removed := 0
	for _, address := range threatsAPIStrings(member(beforeNotify, "emails")) {
		if !containsString(afterEmails, address) {
			removed++
		}
	}
	stoppedOwners := truthy(member(beforeNotify, "owners")) && !truthy(member(afterNotify, "owners"))
	if stoppedOwners || removed > 0 {
		words := "stopped emailing owners about incidents"
		if !stoppedOwners {
			plural := "s"
			if removed == 1 {
				plural = ""
			}
			words = "removed " + core.NumberString(float64(removed)) + " incident email recipient" + plural
		}
		found = append(found, threatsAPIWeakening{key: "notify", words: words})
	}
	return found, nil
}

// threatsAPIPaging is paging(): limit 1-1000 (default 100), offset 0-1,000,000 (default 0).
func threatsAPIPaging(input interface{ Get(string) any }) (limit, offset float64, err error) {
	if limit, err = Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 1000); err != nil {
		return 0, 0, err
	}
	if offset, err = Integer(coalesce(input.Get("offset"), 0.0), "offset", 0, 1_000_000); err != nil {
		return 0, 0, err
	}
	return limit, offset, nil
}

// threatsAPIIncidentStatusesOf is listIncidents' `status`: one status, or a list of one to three distinct ones.
func threatsAPIIncidentStatusesOf(value any) ([]string, error) {
	list, ok := value.([]any)
	if !ok {
		status, err := threatsAPIOneOf(value, threatsAPIAllIncidentStatuses, "status")
		if err != nil {
			return nil, err
		}
		return []string{status}, nil
	}
	if len(list) < 1 || len(list) > len(threatsAPIAllIncidentStatuses) {
		return nil, invalidInput("status must list 1-" + core.NumberString(float64(len(threatsAPIAllIncidentStatuses))) + " incident statuses")
	}
	statuses := newOrderedSet()
	for _, entry := range list {
		status, err := threatsAPIOneOf(entry, threatsAPIAllIncidentStatuses, "status")
		if err != nil {
			return nil, err
		}
		statuses.Add(status)
	}
	return statuses.Values(), nil
}

// threatsAPISubjectKinds is the identity kinds by id already looked up during one read (an absent kind, "", for an
// identity outside the tenant).
type threatsAPISubjectKinds map[string]any

// threatsAPIWithSubjectKinds is detections or incidents as the API returns them: identity subjects gain the identity's
// `kind` when the identity belongs to the tenant. Each identity is read once per read (pass the same kinds to share
// lookups between calls); the kind is never stored.
func threatsAPIWithSubjectKinds(ctx context.Context, tx core.IamStore, tenantID string, records []*core.Object, kinds threatsAPISubjectKinds) ([]*core.Object, error) {
	if kinds == nil {
		kinds = threatsAPISubjectKinds{}
	}
	for _, record := range records {
		subject := record.Get("subject")
		if member(subject, "type") != "identity" {
			continue
		}
		subjectID := jsString(member(subject, "id"))
		if _, seen := kinds[subjectID]; seen {
			continue
		}
		identity, err := tx.Get(ctx, "identities", subjectID)
		if err != nil {
			return nil, err
		}
		if identity != nil && identity.Get("tenantId") == tenantID {
			kinds[subjectID] = identity.Get("kind")
		} else {
			kinds[subjectID] = core.Undefined
		}
	}
	out := make([]*core.Object, len(records))
	for index, record := range records {
		subject := record.Get("subject")
		var kind any = core.Undefined
		if member(subject, "type") == "identity" {
			kind = kinds[jsString(member(subject, "id"))]
		}
		if !truthy(kind) {
			out[index] = record
			continue
		}
		subjectObject, _ := subject.(*core.Object)
		out[index] = record.Spread().Set("subject", subjectObject.Spread().Set("kind", kind))
	}
	return out, nil
}

// threatsAPIWithSubjectKind is one detection or incident as the API returns it (see threatsAPIWithSubjectKinds).
func threatsAPIWithSubjectKind(ctx context.Context, tx core.IamStore, tenantID string, record *core.Object, kinds threatsAPISubjectKinds) (*core.Object, error) {
	records, err := threatsAPIWithSubjectKinds(ctx, tx, tenantID, []*core.Object{record}, kinds)
	if err != nil {
		return nil, err
	}
	return records[0], nil
}

// threatsAPIMultiline is free text over several lines (notes, reports): line breaks are normalized to `\n`, tabs
// kept, every other control character dropped; 1 to max characters after trimming.
func threatsAPIMultiline(value any, name string, max int) (string, error) {
	text, ok := value.(string)
	if !ok || utf16Len(text) > max*4 {
		return "", invalidInput("Invalid " + name)
	}
	var cleaned strings.Builder
	previous := rune(0)
	for _, character := range text {
		code := character
		switch {
		case code == 13:
			cleaned.WriteByte('\n')
		case code == 10:
			if previous != 13 {
				cleaned.WriteByte('\n')
			}
		case code == 9 || (code >= 32 && code < 127) || code >= 160:
			cleaned.WriteRune(character)
		}
		previous = code
	}
	result := core.JSTrim(cleaned.String())
	if result == "" || utf16Len(result) > max {
		return "", invalidInput(name + " must be 1-" + core.NumberString(float64(max)) + " characters")
	}
	return result, nil
}

// threatsAPITooWide is true for a CIDR block wider than /8 (IPv4, including IPv4-mapped IPv6 blocks) or /32 (IPv6):
// trusting it would switch the network rules off, and exempt it from network blocks, for a large part of the
// internet.
func threatsAPITooWide(network string) bool {
	slash := strings.Index(network, "/")
	if slash < 0 {
		return false
	}
	address := network[:slash]
	prefix := stringToNumber(network[slash+1:])
	// IPCounterKey folds IPv4-mapped IPv6 addresses to their IPv4 form, so only real IPv6 keys keep a colon.
	key, ok := core.IPCounterKey(address)
	ipv6 := !ok || strings.Contains(key, ":")
	mapped := !ipv6 && strings.Contains(address, ":")
	floor := 8.0
	if ipv6 {
		floor = 32
	} else if mapped {
		floor = 104
	}
	return prefix < floor
}

func threatsAPITrustedNetworksOf(value any) ([]any, error) {
	list, ok := value.([]any)
	if !ok || len(list) > 50 {
		return nil, invalidInput("trustedNetworks must list at most 50 networks")
	}
	networks := newOrderedSet()
	for _, entry := range list {
		text, err := Text(entry, "trustedNetworks", 64)
		if err != nil {
			return nil, err
		}
		network := core.JSTrim(text)
		if !core.IsIPRange(network) {
			return nil, invalidInput("trustedNetworks entries must be IPv4/IPv6 addresses or CIDR blocks")
		}
		if threatsAPITooWide(network) {
			return nil, invalidInput("Trusted networks may be at most /8 (IPv4) or /32 (IPv6) wide")
		}
		networks.Add(network)
	}
	return stringsOf(networks.Values()), nil
}

func threatsAPINotifyOf(value any, current *core.Object) (*core.Object, error) {
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	for _, key := range input.Keys() {
		if key != "owners" && key != "emails" {
			return nil, invalidInput("Unknown notify setting " + threatsAPISlice(key, 64))
		}
	}
	currentEmails, _ := member(current, "emails").([]any)
	next := core.NewObject("owners", member(current, "owners"), "emails", append([]any{}, currentEmails...))
	if owners := input.Get("owners"); !isUndefined(owners) {
		flag, err := threatsAPIFlag(owners, "notify.owners")
		if err != nil {
			return nil, err
		}
		next.Set("owners", flag)
	}
	if raw := input.Get("emails"); !isUndefined(raw) {
		list, ok := raw.([]any)
		if !ok || len(list) > 20 {
			return nil, invalidInput("notify.emails must list at most 20 addresses")
		}
		addresses := make([]string, 0, len(list))
		for _, entry := range list {
			address, err := Email(entry)
			if err != nil {
				return nil, err
			}
			addresses = append(addresses, address)
		}
		next.Set("emails", stringsOf(unique(addresses)))
	}
	return next, nil
}

// threatsAPIMergeRules merges per-rule changes into a tenant's rule settings; a rule left without adjustments is
// dropped.
func threatsAPIMergeRules(current *core.Object, value any) (*core.Object, error) {
	next := current.Spread()
	changes, err := Object(value)
	if err != nil {
		return nil, err
	}
	for _, key := range changes.Keys() {
		change := changes.Get(key)
		ruleID, err := threatsAPIRuleIDOf(key, "rules")
		if err != nil {
			return nil, err
		}
		rule, err := ThreatRule(ruleID)
		if err != nil {
			return nil, err
		}
		if change == nil {
			next.Delete(ruleID)
			continue
		}
		existing, _ := next.Get(ruleID).(*core.Object)
		setting := existing.Spread()
		fields, err := Object(change)
		if err != nil {
			return nil, err
		}
		for _, field := range fields.Keys() {
			raw := fields.Get(field)
			name := "rules." + ruleID + "." + field
			switch field {
			case "enabled":
				if raw == nil {
					setting.Delete("enabled")
				} else {
					flag, err := threatsAPIFlag(raw, name)
					if err != nil {
						return nil, err
					}
					setting.Set("enabled", flag)
				}
			case "severity":
				if raw == nil {
					setting.Delete("severity")
				} else {
					severity, err := threatsAPIOneOf(raw, ThreatSeverities, name)
					if err != nil {
						return nil, err
					}
					setting.Set("severity", severity)
				}
			case "threshold", "windowMs":
				bounds, _ := member(rule.Get("tunable"), field).([]any)
				if raw == nil {
					setting.Delete(field)
				} else if bounds == nil {
					return nil, invalidInput("The " + ruleID + " rule has no adjustable " + field)
				} else {
					number, err := Integer(raw, name, jsNumber(bounds[0]), jsNumber(bounds[1]))
					if err != nil {
						return nil, err
					}
					setting.Set(field, number)
				}
			case "everyone":
				if ruleID != "new-network" {
					return nil, invalidInput("everyone applies to the new-network rule only")
				}
				if raw == nil {
					setting.Delete("everyone")
				} else {
					flag, err := threatsAPIFlag(raw, name)
					if err != nil {
						return nil, err
					}
					setting.Set("everyone", flag)
				}
			default:
				return nil, invalidInput("Unknown setting " + threatsAPISlice(field, 64) + " for " + ruleID)
			}
		}
		if setting.Len() > 0 {
			next.Set(ruleID, setting)
		} else {
			next.Delete(ruleID)
		}
	}
	return next, nil
}

func threatsAPIRuleView(rule *core.Object, settings *core.Object, stored *core.Object) *core.Object {
	ruleID := jsString(rule.Get("id"))
	effective := threatsAPIRule(settings, ruleID)
	var own any = core.Undefined
	if stored != nil {
		own = member(stored.Get("rules"), ruleID)
	}
	defaults := core.NewObject("enabled", rule.Get("enabledByDefault"), "severity", rule.Get("severity"))
	if threshold := rule.Get("threshold"); !isUndefined(threshold) {
		defaults.Set("threshold", threshold)
	}
	if windowMs := rule.Get("windowMs"); !isUndefined(windowMs) {
		defaults.Set("windowMs", windowMs)
	}
	view := core.NewObject(
		"id", rule.Get("id"),
		"title", rule.Get("title"),
		"description", rule.Get("description"),
		"category", rule.Get("category"),
		"subject", rule.Get("subject"),
		"technique", rule.Get("technique"),
		"defaults", defaults,
	)
	if tunable := rule.Get("tunable"); truthy(tunable) {
		view.Set("tunable", tunable)
	}
	view.Set("enabled", effective.Get("enabled"))
	view.Set("severity", effective.Get("severity"))
	if threshold := effective.Get("threshold"); !isUndefined(threshold) {
		view.Set("threshold", threshold)
	}
	if windowMs := effective.Get("windowMs"); !isUndefined(windowMs) {
		view.Set("windowMs", windowMs)
	}
	if ruleID == "new-network" {
		view.Set("everyone", effective.Get("everyone") == true)
	}
	customized := false
	if ownObject, ok := own.(*core.Object); ok && ownObject != nil {
		customized = ownObject.Len() > 0
	}
	view.Set("customized", customized)
	return view
}

func threatsAPISettingsView(tenantID string, stored *core.Object) (*core.Object, error) {
	resolved, err := ResolveThreatSettings(stored)
	if err != nil {
		return nil, err
	}
	view := core.NewObject("tenantId", tenantID, "configured", stored != nil)
	view.Assign(resolved)
	if stored != nil {
		view.SetRaw("updatedAt", stored.Get("updatedAt"))
		view.SetRaw("updatedBy", stored.Get("updatedBy"))
	}
	return view, nil
}

// threatsAPIStoredSettings is the tenant's stored settings (nil until `threats.configure` first saves them).
func threatsAPIStoredSettings(ctx context.Context, tx core.IamStore, tenantID string) (*core.Object, error) {
	stored, err := tx.Get(ctx, ThreatCollections.Settings, tenantID)
	if err != nil {
		return nil, err
	}
	if stored != nil && stored.Get("tenantId") == tenantID {
		return stored, nil
	}
	return nil, nil
}

// threatsAPISettings is resolveThreatSettings(await storedSettings(tx, tenantId)).
func threatsAPISettings(ctx context.Context, tx core.IamStore, tenantID string) (*core.Object, error) {
	stored, err := threatsAPIStoredSettings(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	return ResolveThreatSettings(stored)
}

func threatsAPIRiskRecord(ctx context.Context, tx core.IamStore, tenantID, identityID string) (*core.Object, error) {
	record, err := tx.Get(ctx, ThreatCollections.Risk, identityID)
	if err != nil {
		return nil, err
	}
	if record != nil && record.Get("tenantId") == tenantID {
		return record, nil
	}
	return nil, nil
}

// threatsAPIContainment is the containment in force: the risk record's mark while the identity is still disabled. An
// identity re-enabled outside the threats module (identities.setStatus, agents.resume) is no longer contained,
// whatever the mark says.
func threatsAPIContainment(identity *core.Object, record *core.Object) any {
	if identity.Get("status") == "disabled" && record != nil {
		return record.Get("contained")
	}
	return core.Undefined
}

func threatsAPIRiskView(identity *core.Object, record *core.Object, settings *core.Object, now int64) (*core.Object, error) {
	halfLife := threatsAPIHalfLife(settings)
	risk, err := EffectiveRisk(record, now, halfLife)
	if err != nil {
		return nil, err
	}
	view := core.NewObject("identityId", identity.Get("id"))
	if name := identity.Get("name"); truthy(name) {
		view.Set("name", name)
	}
	if email := identity.Get("email"); truthy(email) {
		view.Set("email", email)
	}
	view.Set("kind", identity.Get("kind"))
	view.Set("status", identity.Get("status"))
	view.Set("score", risk.Get("score"))
	view.Set("level", risk.Get("level"))
	var override any = core.Undefined
	if record != nil {
		override = record.Get("override")
	}
	if truthy(override) {
		overrideView := core.NewObject(
			"level", member(override, "level"),
			"reason", member(override, "reason"),
			"by", member(override, "by"),
			"at", member(override, "at"),
		)
		expiresAt := member(override, "expiresAt")
		if !isUndefined(expiresAt) {
			overrideView.Set("expiresAt", expiresAt)
		}
		overrideView.Set("active", isUndefined(expiresAt) || jsNumber(expiresAt) > float64(now))
		view.Set("override", overrideView)
	}
	if contained := threatsAPIContainment(identity, record); truthy(contained) {
		view.Set("contained", contained)
	}
	var contributions []*core.Object
	if record != nil {
		contributions = threatsAPIObjects(coalesce(record.Get("contributions"), []any{}))
	}
	views := make([]*core.Object, 0, len(contributions))
	for _, contribution := range contributions {
		current, err := RiskScore([]*core.Object{contribution}, now, halfLife)
		if err != nil {
			return nil, err
		}
		views = append(views, contribution.Spread().Set("current", current))
	}
	sort.SliceStable(views, func(i, j int) bool {
		return jsNumber(views[j].Get("at"))-jsNumber(views[i].Get("at")) < 0
	})
	view.Set("contributions", threatsAPIList(views))
	if record != nil {
		view.SetRaw("updatedAt", record.Get("updatedAt"))
	}
	return view, nil
}

// threatsAPIDropContributions takes the contributions of detectionIDs out of an identity's risk and recomputes it,
// auditing a level change under the caller; nothing happens when none of them contributes.
func (api *ThreatsAPI) dropContributions(ctx context.Context, tx core.IamStore, tenantID, identityID string, detectionIDs []string, settings *core.Object, now int64, actorID string) error {
	record, err := threatsAPIRiskRecord(ctx, tx, tenantID, identityID)
	if err != nil {
		return err
	}
	if record == nil {
		return nil
	}
	contributes := false
	for _, contribution := range threatsAPIObjects(record.Get("contributions")) {
		if detectionID, ok := contribution.Get("detectionId").(string); ok && containsString(detectionIDs, detectionID) {
			contributes = true
			break
		}
	}
	if !contributes {
		return nil
	}
	_, err = RecomputeRisk(ctx, api.server, tx, tenantID, identityID, settings, now, actorID, core.NewObject("drop", stringsOf(detectionIDs)))
	return err
}

func threatsAPIResponseActionsOf(value any, name string) ([]any, error) {
	list, ok := value.([]any)
	if !ok || len(list) < 1 || len(list) > 5 {
		return nil, invalidInput(name + " must list 1-5 response actions")
	}
	seen := map[string]bool{}
	actions := make([]any, 0, len(list))
	for _, entry := range list {
		input, err := Object(entry)
		if err != nil {
			return nil, err
		}
		for _, key := range input.Keys() {
			if key != "kind" && key != "durationMs" && key != "keepApiKeys" {
				return nil, invalidInput("Unknown response action field " + threatsAPISlice(key, 64))
			}
		}
		kind, err := threatsAPIOneOf(input.Get("kind"), ResponseActionKinds, name+" kind")
		if err != nil {
			return nil, err
		}
		if seen[kind] {
			return nil, invalidInput(name + " may list each kind of action once")
		}
		seen[kind] = true
		action := core.NewObject("kind", kind)
		if raw := input.Get("durationMs"); !isUndefined(raw) {
			if kind != "block-network" {
				return nil, invalidInput("durationMs applies to block-network only")
			}
			duration, err := Integer(raw, "durationMs", threatsAPIMinute, 30*threatsAPIDay)
			if err != nil {
				return nil, err
			}
			action.Set("durationMs", duration)
		}
		if raw := input.Get("keepApiKeys"); !isUndefined(raw) {
			if kind != "revoke-sessions" {
				return nil, invalidInput("keepApiKeys applies to revoke-sessions only")
			}
			keep, err := threatsAPIFlag(raw, "keepApiKeys")
			if err != nil {
				return nil, err
			}
			action.Set("keepApiKeys", keep)
		}
		actions = append(actions, action)
	}
	return actions, nil
}

func threatsAPISuspendsClearances(actions any) bool {
	for _, action := range threatsAPIObjects(actions) {
		if action.Get("kind") == "suspend-clearance" {
			return true
		}
	}
	return false
}

// assertMaySuspendClearances: a playbook that suspends clearances acts as a clearance officer would: it needs the
// `clearances` option (FEATURE_DISABLED otherwise), and whoever writes it must be allowed to suspend any clearance of
// the tenant (iam:clearances:suspend on iam/clearances, an audited ACCESS_DENIED otherwise), so holding
// iam:threats:manage alone never lets someone suspend people's clearances through the threat-detection actor.
func (api *ThreatsAPI) assertMaySuspendClearances(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string) error {
	if err := AssertClearances(api.server); err != nil {
		return err
	}
	decision, err := api.server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
		TenantID: tenantID, Action: "iam:clearances:suspend", Resource: ResourceTarget{Type: "iam", ID: "clearances"},
	}, true)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return NewOperationDenied("Playbooks that suspend clearances need iam:clearances:suspend")
	}
	return nil
}

func threatsAPIPlaybookName(value any) (string, error) {
	text, err := Text(value, "name", 100)
	if err != nil {
		return "", err
	}
	name := core.JSTrim(text)
	if name == "" {
		return "", invalidInput("name is required")
	}
	return name, nil
}

func threatsAPIPlaybookTrigger(value any) (*core.Object, error) {
	if isUndefined(value) {
		return nil, invalidInput("trigger is required ({} matches every detection)")
	}
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	trigger := core.NewObject()
	for _, key := range input.Keys() {
		if key != "ruleIds" && key != "minSeverity" && key != "subjectTypes" {
			return nil, invalidInput("Unknown trigger field " + threatsAPISlice(key, 64))
		}
	}
	ruleCount := ThreatRuleIDs.Len()
	if raw := input.Get("ruleIds"); !nullish(raw) {
		list, ok := raw.([]any)
		if !ok || len(list) == 0 || len(list) > ruleCount {
			return nil, invalidInput("trigger.ruleIds must list 1-" + core.NumberString(float64(ruleCount)) + " detection rules")
		}
		ruleIDs := newOrderedSet()
		for _, entry := range list {
			ruleID, err := threatsAPIRuleIDOf(entry, "trigger.ruleIds")
			if err != nil {
				return nil, err
			}
			ruleIDs.Add(ruleID)
		}
		trigger.Set("ruleIds", stringsOf(ruleIDs.Values()))
	}
	if raw := input.Get("minSeverity"); !nullish(raw) {
		severity, err := threatsAPIOneOf(raw, ThreatSeverities, "trigger.minSeverity")
		if err != nil {
			return nil, err
		}
		trigger.Set("minSeverity", severity)
	}
	if raw := input.Get("subjectTypes"); !nullish(raw) {
		list, ok := raw.([]any)
		if !ok || len(list) == 0 || len(list) > len(threatsAPISubjectTypes) {
			return nil, invalidInput("trigger.subjectTypes must list 1-" + core.NumberString(float64(len(threatsAPISubjectTypes))) + " subject types")
		}
		types := newOrderedSet()
		for _, entry := range list {
			subjectType, err := threatsAPIOneOf(entry, threatsAPISubjectTypes, "trigger.subjectTypes")
			if err != nil {
				return nil, err
			}
			types.Add(subjectType)
		}
		trigger.Set("subjectTypes", stringsOf(types.Values()))
	}
	return trigger, nil
}

// threatsAPIPlaybookMetadata is the audit metadata describing a playbook's settings.
func threatsAPIPlaybookMetadata(playbook *core.Object) *core.Object {
	trigger := playbook.Get("trigger")
	triggerView := core.NewObject()
	if ruleIDs := member(trigger, "ruleIds"); truthy(ruleIDs) {
		triggerView.Set("ruleIds", ruleIDs)
	}
	if minSeverity := member(trigger, "minSeverity"); truthy(minSeverity) {
		triggerView.Set("minSeverity", minSeverity)
	}
	if subjectTypes := member(trigger, "subjectTypes"); truthy(subjectTypes) {
		triggerView.Set("subjectTypes", subjectTypes)
	}
	actions := []any{}
	for _, action := range threatsAPIObjects(playbook.Get("actions")) {
		view := core.NewObject("kind", action.Get("kind"))
		if duration := action.Get("durationMs"); !isUndefined(duration) {
			view.Set("durationMs", duration)
		}
		if keep := action.Get("keepApiKeys"); !isUndefined(keep) {
			view.Set("keepApiKeys", keep)
		}
		actions = append(actions, view)
	}
	return core.NewObject("name", playbook.Get("name"), "enabled", playbook.Get("enabled"), "trigger", triggerView, "actions", actions)
}

// playbooksFor runs the tenant's playbooks for a detection the API itself recorded; nothing runs for a detection seen
// before.
func (api *ThreatsAPI) playbooksFor(ctx context.Context, tx core.IamStore, tenantID string, recorded *core.Object, settings *core.Object) ([]*core.Object, error) {
	if !truthy(recorded.Get("created")) {
		return []*core.Object{}, nil
	}
	detection, _ := recorded.Get("detection").(*core.Object)
	incident, _ := recorded.Get("incident").(*core.Object)
	return RunPlaybooks(ctx, api.server, tx, tenantID, detection, incident, settings, core.NewObject("contained", 0.0))
}

// clearsOwnRisk is true when one of identityIDs is the caller's own identity and the caller is not a root
// administrator: nobody else clears risk raised against themselves, so a compromised administrator account cannot
// erase its own signal.
func (api *ThreatsAPI) clearsOwnRisk(ctx context.Context, tx core.IamStore, principal *Principal, identityIDs []any) (bool, error) {
	own := principal.Identity.Get("id")
	for _, identityID := range identityIDs {
		if identityID == own {
			root, err := api.server.RootPrincipal(ctx, tx, principal)
			if err != nil {
				return false, err
			}
			return !root, nil
		}
	}
	return false, nil
}

// threatsAPIOutcome is a mutation's answer and the responses it took (run after commit through
// AfterThreatResponses).
type threatsAPIOutcome struct {
	value     any
	responses []*core.Object
}

// Rules is POST {basePath}/threats/rules. Every detection rule with its defaults and the setting in force for the
// tenant. Requires iam:threats:read on iam/threats/rules.
func (api *ThreatsAPI) Rules(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsRulesInput]) (Out[apitypes.ThreatsRulesOutput], error) {
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:threats:read", "threats/rules", func(ctx context.Context, call MutationContext) (any, error) {
		tenantID := jsString(call.Tenant.Get("id"))
		stored, err := threatsAPIStoredSettings(ctx, call.Tx, tenantID)
		if err != nil {
			return nil, err
		}
		settings, err := ResolveThreatSettings(stored)
		if err != nil {
			return nil, err
		}
		rules, err := threatsAPIRuleCatalog()
		if err != nil {
			return nil, err
		}
		views := make([]any, len(rules))
		for index, rule := range rules {
			views[index] = threatsAPIRuleView(rule, settings, stored)
		}
		return views, nil
	}, false)
	return Out[apitypes.ThreatsRulesOutput]{Value: result}, err
}

// GetSettings is POST {basePath}/threats/getSettings. The tenant's detection settings with defaults applied.
// Requires iam:threats:read on iam/threats/settings.
func (api *ThreatsAPI) GetSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsGetSettingsInput]) (Out[apitypes.ThreatsGetSettingsOutput], error) {
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:threats:read", "threats/settings", func(ctx context.Context, call MutationContext) (any, error) {
		tenantID := jsString(call.Tenant.Get("id"))
		stored, err := threatsAPIStoredSettings(ctx, call.Tx, tenantID)
		if err != nil {
			return nil, err
		}
		return threatsAPISettingsView(tenantID, stored)
	}, false)
	return Out[apitypes.ThreatsGetSettingsOutput]{Value: result}, err
}

// Configure is POST {basePath}/threats/configure. Tunes detection: per-rule `enabled`, `severity`, `threshold` and
// `windowMs` (within the rule's `tunable` bounds; `null` restores a default, a rule set to `null` drops all its
// adjustments), `everyone` for new-network, trusted networks, the dormancy period, the risk half-life, notification
// recipients and the automatic containment brake. Turning a rule off, or weakening detection or response otherwise,
// also records a `guardrail-weakened` detection against the caller, since the engine never reads the module's own
// events. Nobody shortens the half-life while detections raise their own risk (root administrators excepted).
// Requires iam:threats:manage on iam/threats/settings and recent authentication; audited as `threat:settings` with
// the changed keys, the rules turned off, and the weakened settings.
func (api *ThreatsAPI) Configure(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsConfigureInput]) (Out[apitypes.ThreatsConfigureOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.ThreatsConfigureOutput]{}, err
	}
	outcome, err := Operate(ctx, server.Operations, credential, tenantID, "iam:threats:manage", "threats/settings", func(ctx context.Context, call MutationContext) (threatsAPIOutcome, error) {
		tx, tenant, principal := call.Tx, call.Tenant, call.Principal
		realmID := jsString(tenant.Get("id"))
		principalID := jsString(principal.Identity.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return threatsAPIOutcome{}, err
		}
		stored, err := threatsAPIStoredSettings(ctx, tx, realmID)
		if err != nil {
			return threatsAPIOutcome{}, err
		}
		before, err := ResolveThreatSettings(stored)
		if err != nil {
			return threatsAPIOutcome{}, err
		}
		now := server.Now()
		var storedRules *core.Object
		if stored != nil {
			storedRules, _ = stored.Get("rules").(*core.Object)
		}
		var rules *core.Object
		if raw := input.Get("rules"); isUndefined(raw) {
			rules = storedRules.Spread()
		} else if rules, err = threatsAPIMergeRules(storedRules, raw); err != nil {
			return threatsAPIOutcome{}, err
		}
		trustedNetworks := before.Get("trustedNetworks")
		if raw := input.Get("trustedNetworks"); !isUndefined(raw) {
			networks, err := threatsAPITrustedNetworksOf(raw)
			if err != nil {
				return threatsAPIOutcome{}, err
			}
			trustedNetworks = networks
		}
		dormantDays := before.Get("dormantDays")
		if raw := input.Get("dormantDays"); !isUndefined(raw) {
			if dormantDays, err = Integer(raw, "dormantDays", 7, 3650); err != nil {
				return threatsAPIOutcome{}, err
			}
		}
		riskHalfLifeHours := before.Get("riskHalfLifeHours")
		if raw := input.Get("riskHalfLifeHours"); !isUndefined(raw) {
			if riskHalfLifeHours, err = Integer(raw, "riskHalfLifeHours", 1, 720); err != nil {
				return threatsAPIOutcome{}, err
			}
		}
		notify := before.Get("notify")
		if raw := input.Get("notify"); !isUndefined(raw) {
			current, _ := notify.(*core.Object)
			if notify, err = threatsAPINotifyOf(raw, current); err != nil {
				return threatsAPIOutcome{}, err
			}
		}
		maxAutomaticContainments := before.Get("maxAutomaticContainments")
		if raw := input.Get("maxAutomaticContainments"); !isUndefined(raw) {
			if maxAutomaticContainments, err = Integer(raw, "maxAutomaticContainments", 0, 100); err != nil {
				return threatsAPIOutcome{}, err
			}
		}
		next := core.NewObject(
			"id", realmID,
			"tenantId", realmID,
			"rules", rules,
			"trustedNetworks", trustedNetworks,
			"dormantDays", dormantDays,
			"riskHalfLifeHours", riskHalfLifeHours,
			"notify", notify,
			"maxAutomaticContainments", maxAutomaticContainments,
			"updatedAt", float64(now),
			"updatedBy", principalID,
		)
		// A shorter half-life decays every score at once, the caller's too: as with dismissals, nobody clears risk
		// raised against themselves.
		if jsNumber(riskHalfLifeHours) < threatsAPIHalfLife(before) {
			record, err := threatsAPIRiskRecord(ctx, tx, realmID, principalID)
			if err != nil {
				return threatsAPIOutcome{}, err
			}
			var contributions []*core.Object
			if record != nil {
				contributions = threatsAPIObjects(record.Get("contributions"))
			}
			score, err := RiskScore(contributions, now, threatsAPIHalfLife(before))
			if err != nil {
				return threatsAPIOutcome{}, err
			}
			if score > 0 {
				own, err := api.clearsOwnRisk(ctx, tx, principal, []any{principalID})
				if err != nil {
					return threatsAPIOutcome{}, err
				}
				if own {
					return threatsAPIOutcome{}, NewOperationDenied("While detections raise your own risk, another administrator shortens the risk half-life")
				}
			}
		}
		if stored != nil {
			_, err = tx.Put(ctx, ThreatCollections.Settings, next)
		} else {
			_, err = tx.Insert(ctx, ThreatCollections.Settings, next)
		}
		if err != nil {
			return threatsAPIOutcome{}, err
		}
		after, err := ResolveThreatSettings(next)
		if err != nil {
			return threatsAPIOutcome{}, err
		}
		catalog, err := threatsAPIRuleCatalog()
		if err != nil {
			return threatsAPIOutcome{}, err
		}
		changedRules := []string{}
		disabledRules := []string{}
		for _, rule := range catalog {
			ruleID := jsString(rule.Get("id"))
			if threatsAPIRuleSignature(threatsAPIRule(before, ruleID)) != threatsAPIRuleSignature(threatsAPIRule(after, ruleID)) {
				changedRules = append(changedRules, ruleID)
			}
		}
		changed := []string{}
		if len(changedRules) > 0 {
			changed = append(changed, "rules")
		}
		for _, key := range []string{"trustedNetworks", "dormantDays", "riskHalfLifeHours", "notify", "maxAutomaticContainments"} {
			if threatsAPICanonical(before.Get(key)) != threatsAPICanonical(after.Get(key)) {
				changed = append(changed, key)
			}
		}
		for _, rule := range catalog {
			ruleID := jsString(rule.Get("id"))
			if truthy(threatsAPIRule(before, ruleID).Get("enabled")) && !truthy(threatsAPIRule(after, ruleID).Get("enabled")) {
				disabledRules = append(disabledRules, ruleID)
			}
		}
		weakened, err := threatsAPIWeakenings(before, after)
		if err != nil {
			return threatsAPIOutcome{}, err
		}
		weakenedKeys := make([]string, len(weakened))
		for index, item := range weakened {
			weakenedKeys[index] = item.key
		}
		if err := server.Events.Audit(ctx, tx, principal, "threat:settings", realmID, "threats/settings", "allow", false, core.NewObject(
			"changed", stringsOf(changed),
			"changedRules", stringsOf(changedRules),
			"disabledRules", stringsOf(disabledRules),
			"weakened", stringsOf(weakenedKeys),
		)); err != nil {
			return threatsAPIOutcome{}, err
		}
		responses := []*core.Object{}
		// Judged by the guardrail rule as it stood before the change, so turning that rule off (or down) in the same
		// call is reported too; a tenant that had already turned it off is not.
		guardrail := threatsAPIRule(before, "guardrail-weakened")
		if (len(disabledRules) > 0 || len(weakened) > 0) && truthy(guardrail.Get("enabled")) {
			afterRules, _ := after.Get("rules").(*core.Object)
			reporting := after.Spread().Set("rules", afterRules.Spread().Set("guardrail-weakened", guardrail))
			titleList := make([]string, len(disabledRules))
			for index, ruleID := range disabledRules {
				rule, err := ThreatRule(ruleID)
				if err != nil {
					return threatsAPIOutcome{}, err
				}
				titleList[index] = jsString(rule.Get("title"))
			}
			plural := "s"
			if len(disabledRules) == 1 {
				plural = ""
			}
			count := core.NumberString(float64(len(disabledRules))) + " detection rule" + plural
			changes := []string{}
			if len(disabledRules) > 0 {
				changes = append(changes, "turned off "+count+": "+strings.Join(titleList, ", "))
			}
			for _, item := range weakened {
				changes = append(changes, item.words)
			}
			title := "Detection rules turned off"
			if len(weakened) > 0 {
				title = "Threat detection weakened"
			}
			label, err := threatsAPIDetectionLabel(principal.Identity)
			if err != nil {
				return threatsAPIOutcome{}, err
			}
			candidate := core.NewObject(
				"ruleId", "guardrail-weakened",
				"severity", guardrail.Get("severity"),
				"title", title,
				"summary", label+" "+threatsAPIListed(changes, 6)+".",
				"subject", core.NewObject("type", "tenant", "id", realmID, "name", tenant.Get("name")),
				"identityId", principalID,
				"dedupeKey", "settings:"+ID(),
				"occurredAt", float64(now),
				"evidence", core.NewObject(
					"eventIds", []any{},
					"count", float64(len(disabledRules)+len(weakened)),
					"firstAt", float64(now),
					"lastAt", float64(now),
					"identityIds", []any{principalID},
					"actions", []any{"threat:settings"},
				),
				"metadata", core.NewObject(
					"disabledRules", stringsOf(disabledRules),
					"weakened", stringsOf(weakenedKeys),
					"changedBy", principalID,
				),
			)
			recorded, err := RecordDetection(ctx, server, tx, realmID, candidate, reporting, now)
			if err != nil {
				return threatsAPIOutcome{}, err
			}
			if responses, err = api.playbooksFor(ctx, tx, realmID, recorded, reporting); err != nil {
				return threatsAPIOutcome{}, err
			}
		}
		view, err := threatsAPISettingsView(realmID, next)
		if err != nil {
			return threatsAPIOutcome{}, err
		}
		return threatsAPIOutcome{value: view, responses: responses}, nil
	}, false)
	if err != nil {
		return Out[apitypes.ThreatsConfigureOutput]{}, err
	}
	if err := AfterThreatResponses(ctx, server, tenantID, outcome.responses); err != nil {
		return Out[apitypes.ThreatsConfigureOutput]{}, err
	}
	return Out[apitypes.ThreatsConfigureOutput]{Value: outcome.value}, nil
}

// ListDetections is POST {basePath}/threats/listDetections. The tenant's detections, newest first, optionally
// narrowed by status, rule, severity, identity, incident and a `since` time (epoch milliseconds, by detection time).
// Requires iam:threats:read on iam/threats/detections.
func (api *ThreatsAPI) ListDetections(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsListDetectionsInput]) (Out[apitypes.ThreatsListDetectionsOutput], error) {
	fail := func(err error) (Out[apitypes.ThreatsListDetectionsOutput], error) {
		return Out[apitypes.ThreatsListDetectionsOutput]{}, err
	}
	limit, offset, err := threatsAPIPaging(input)
	if err != nil {
		return fail(err)
	}
	filter := core.NewObject()
	if raw := input.Get("status"); !isUndefined(raw) {
		status, err := threatsAPIOneOf(raw, threatsAPIDetectionStatuses, "status")
		if err != nil {
			return fail(err)
		}
		filter.Set("status", status)
	}
	if raw := input.Get("ruleId"); !isUndefined(raw) {
		ruleID, err := threatsAPIRuleIDOf(raw, "ruleId")
		if err != nil {
			return fail(err)
		}
		filter.Set("ruleId", ruleID)
	}
	if raw := input.Get("severity"); !isUndefined(raw) {
		severity, err := threatsAPIOneOf(raw, ThreatSeverities, "severity")
		if err != nil {
			return fail(err)
		}
		filter.Set("severity", severity)
	}
	if raw := input.Get("identityId"); !isUndefined(raw) {
		identityID, err := Text(raw, "identityId")
		if err != nil {
			return fail(err)
		}
		filter.Set("identityId", identityID)
	}
	if raw := input.Get("incidentId"); !isUndefined(raw) {
		incidentID, err := Text(raw, "incidentId")
		if err != nil {
			return fail(err)
		}
		filter.Set("incidentId", incidentID)
	}
	var since *float64
	if raw := input.Get("since"); !isUndefined(raw) {
		value, err := Integer(raw, "since", 0, threatsAPIMaxSafeInteger)
		if err != nil {
			return fail(err)
		}
		since = &value
	}
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:threats:read", "threats/detections", func(ctx context.Context, call MutationContext) (any, error) {
		tenantID := jsString(call.Tenant.Get("id"))
		detections, err := core.FindOrdered(ctx, call.Tx, ThreatCollections.Detections, filter.Spread().Set("tenantId", tenantID),
			core.OrderOptions{Field: "detectedAt", Direction: "desc", From: since}, nil)
		if err != nil {
			return nil, err
		}
		page, err := threatsAPIWithSubjectKinds(ctx, call.Tx, tenantID, threatsAPIPage(detections, offset, limit), nil)
		if err != nil {
			return nil, err
		}
		return core.NewObject("detections", threatsAPIList(page), "total", float64(len(detections))), nil
	}, false)
	return Out[apitypes.ThreatsListDetectionsOutput]{Value: result}, err
}

// GetDetection is POST {basePath}/threats/getDetection. One detection with its evidence. Requires iam:threats:read on
// iam/threats/detections/{id}.
func (api *ThreatsAPI) GetDetection(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsGetDetectionInput]) (Out[apitypes.ThreatsGetDetectionOutput], error) {
	detectionID, err := Text(input.Get("detectionId"), "detectionId")
	if err != nil {
		return Out[apitypes.ThreatsGetDetectionOutput]{}, err
	}
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:threats:read", threatsAPIDetectionResource(detectionID), func(ctx context.Context, call MutationContext) (any, error) {
		tenantID := jsString(call.Tenant.Get("id"))
		detection, err := api.server.Scoped(ctx, call.Tx, ThreatCollections.Detections, detectionID, tenantID)
		if err != nil {
			return nil, err
		}
		return threatsAPIWithSubjectKind(ctx, call.Tx, tenantID, detection, nil)
	}, false)
	return Out[apitypes.ThreatsGetDetectionOutput]{Value: result}, err
}

// DismissDetection is POST {basePath}/threats/dismissDetection. Marks an open detection as a false alarm and takes
// its points out of the identity's risk; the incident stays open for a person to resolve. Detections about the caller
// are dismissed by someone else (root administrators excepted). Requires iam:threats:manage on
// iam/threats/detections/{id} and recent authentication; audited as `threat:detection-dismiss`.
func (api *ThreatsAPI) DismissDetection(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsDismissDetectionInput]) (Out[apitypes.ThreatsDismissDetectionOutput], error) {
	server := api.server
	detectionID, err := Text(input.Get("detectionId"), "detectionId")
	if err != nil {
		return Out[apitypes.ThreatsDismissDetectionOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:threats:manage", threatsAPIDetectionResource(detectionID), func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		principalID := jsString(principal.Identity.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		text, err := Text(input.Get("reason"), "reason", 512)
		if err != nil {
			return nil, err
		}
		reason := core.JSTrim(text)
		detection, err := server.Scoped(ctx, tx, ThreatCollections.Detections, detectionID, tenantID)
		if err != nil {
			return nil, err
		}
		if detection.Get("status") != "open" {
			return nil, core.NewIamError("INVALID_TRANSITION", "Only open detections can be dismissed", 409)
		}
		own, err := api.clearsOwnRisk(ctx, tx, principal, []any{detection.Get("identityId")})
		if err != nil {
			return nil, err
		}
		if own {
			return nil, NewOperationDenied("Detections about yourself are dismissed by another administrator")
		}
		now := server.Now()
		next, err := tx.Put(ctx, ThreatCollections.Detections, detection.Spread().
			Set("status", "dismissed").
			Set("dismissedBy", principalID).
			Set("dismissedAt", float64(now)).
			Set("dismissReason", reason))
		if err != nil {
			return nil, err
		}
		if identityID := detection.Get("identityId"); truthy(identityID) {
			settings, err := threatsAPISettings(ctx, tx, tenantID)
			if err != nil {
				return nil, err
			}
			if err := api.dropContributions(ctx, tx, tenantID, jsString(identityID), []string{jsString(detection.Get("id"))}, settings, now, principalID); err != nil {
				return nil, err
			}
		}
		metadata := core.NewObject("ruleId", detection.Get("ruleId"), "severity", detection.Get("severity"), "reason", reason)
		if identityID := detection.Get("identityId"); truthy(identityID) {
			metadata.Set("identityId", identityID)
		}
		if incidentID := detection.Get("incidentId"); truthy(incidentID) {
			metadata.Set("incidentId", incidentID)
		}
		if err := server.Events.Audit(ctx, tx, principal, "threat:detection-dismiss", tenantID, threatsAPIDetectionResource(jsString(detection.Get("id"))), "allow", false, metadata); err != nil {
			return nil, err
		}
		return threatsAPIWithSubjectKind(ctx, tx, tenantID, next, nil)
	}, false)
	return Out[apitypes.ThreatsDismissDetectionOutput]{Value: result}, err
}

// ListIncidents is POST {basePath}/threats/listIncidents. The tenant's incidents, most recently active first,
// optionally narrowed by status (one, or a list such as `['open', 'investigating']` for every active incident),
// severity, assignee and identity. Requires iam:threats:read on iam/threats/incidents.
func (api *ThreatsAPI) ListIncidents(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsListIncidentsInput]) (Out[apitypes.ThreatsListIncidentsOutput], error) {
	fail := func(err error) (Out[apitypes.ThreatsListIncidentsOutput], error) {
		return Out[apitypes.ThreatsListIncidentsOutput]{}, err
	}
	limit, offset, err := threatsAPIPaging(input)
	if err != nil {
		return fail(err)
	}
	var wanted []string
	if raw := input.Get("status"); !isUndefined(raw) {
		if wanted, err = threatsAPIIncidentStatusesOf(raw); err != nil {
			return fail(err)
		}
	}
	// Every status is no narrowing at all; otherwise each status is read on its own (never the resolved backlog when
	// only active incidents are wanted) and the results merged.
	statuses := []any{core.Undefined}
	if wanted != nil && len(wanted) != len(threatsAPIAllIncidentStatuses) {
		statuses = stringsOf(wanted)
	}
	filter := core.NewObject()
	if raw := input.Get("severity"); !isUndefined(raw) {
		severity, err := threatsAPIOneOf(raw, ThreatSeverities, "severity")
		if err != nil {
			return fail(err)
		}
		filter.Set("severity", severity)
	}
	if raw := input.Get("assigneeId"); !isUndefined(raw) {
		assigneeID, err := Text(raw, "assigneeId")
		if err != nil {
			return fail(err)
		}
		filter.Set("assigneeId", assigneeID)
	}
	if raw := input.Get("identityId"); !isUndefined(raw) {
		identityID, err := Text(raw, "identityId")
		if err != nil {
			return fail(err)
		}
		filter.Set("identityId", identityID)
	}
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:threats:read", "threats/incidents", func(ctx context.Context, call MutationContext) (any, error) {
		tenantID := jsString(call.Tenant.Get("id"))
		incidents := []*core.Object{}
		for _, status := range statuses {
			query := filter.Spread()
			if !isUndefined(status) {
				query.Set("status", status)
			}
			query.Set("tenantId", tenantID)
			found, err := core.FindOrdered(ctx, call.Tx, ThreatCollections.Incidents, query, core.OrderOptions{Field: "lastDetectedAt", Direction: "desc"}, nil)
			if err != nil {
				return nil, err
			}
			incidents = append(incidents, found...)
		}
		if len(statuses) > 1 {
			sort.SliceStable(incidents, func(i, j int) bool {
				difference := jsNumber(incidents[j].Get("lastDetectedAt")) - jsNumber(incidents[i].Get("lastDetectedAt"))
				if difference != 0 && !math.IsNaN(difference) {
					return difference < 0
				}
				return ByID(incidents[i], incidents[j]) < 0
			})
		}
		page, err := threatsAPIWithSubjectKinds(ctx, call.Tx, tenantID, threatsAPIPage(incidents, offset, limit), nil)
		if err != nil {
			return nil, err
		}
		return core.NewObject("incidents", threatsAPIList(page), "total", float64(len(incidents))), nil
	}, false)
	return Out[apitypes.ThreatsListIncidentsOutput]{Value: result}, err
}

// GetIncident is POST {basePath}/threats/getIncident. An incident with its detections (up to 200, newest first),
// notes (oldest first), responses (newest first) and the risk of the identity it concerns. Requires iam:threats:read
// on iam/threats/incidents/{id}.
func (api *ThreatsAPI) GetIncident(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsGetIncidentInput]) (Out[apitypes.ThreatsGetIncidentOutput], error) {
	server := api.server
	incidentID, err := Text(input.Get("incidentId"), "incidentId")
	if err != nil {
		return Out[apitypes.ThreatsGetIncidentOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:threats:read", threatsAPIIncidentResource(incidentID), func(ctx context.Context, call MutationContext) (any, error) {
		tx := call.Tx
		tenantID := jsString(call.Tenant.Get("id"))
		incident, err := server.Scoped(ctx, tx, ThreatCollections.Incidents, incidentID, tenantID)
		if err != nil {
			return nil, err
		}
		limit := 200
		detections, err := core.FindOrdered(ctx, tx, ThreatCollections.Detections, core.NewObject("tenantId", tenantID, "incidentId", incident.Get("id")),
			core.OrderOptions{Field: "detectedAt", Direction: "desc", Limit: &limit}, nil)
		if err != nil {
			return nil, err
		}
		notes, err := tx.Find(ctx, ThreatCollections.Notes, core.NewObject("tenantId", tenantID, "incidentId", incident.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(notes, func(i, j int) bool { return ByNewest(notes[j], notes[i]) < 0 })
		responses, err := tx.Find(ctx, ThreatCollections.Responses, core.NewObject("tenantId", tenantID, "incidentId", incident.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(responses, func(i, j int) bool { return ByNewest(responses[i], responses[j]) < 0 })
		// The incident and its detections are mostly about one subject: each identity is looked up once.
		kinds := threatsAPISubjectKinds{}
		incidentView, err := threatsAPIWithSubjectKind(ctx, tx, tenantID, incident, kinds)
		if err != nil {
			return nil, err
		}
		detectionViews, err := threatsAPIWithSubjectKinds(ctx, tx, tenantID, detections, kinds)
		if err != nil {
			return nil, err
		}
		detail := core.NewObject(
			"incident", incidentView,
			"detections", threatsAPIList(detectionViews),
			"notes", threatsAPIList(notes),
			"responses", threatsAPIList(responses),
		)
		if identityID := incident.Get("identityId"); truthy(identityID) {
			identity, err := tx.Get(ctx, "identities", jsString(identityID))
			if err != nil {
				return nil, err
			}
			if identity != nil && identity.Get("tenantId") == tenantID {
				record, err := threatsAPIRiskRecord(ctx, tx, tenantID, jsString(identity.Get("id")))
				if err != nil {
					return nil, err
				}
				settings, err := threatsAPISettings(ctx, tx, tenantID)
				if err != nil {
					return nil, err
				}
				risk, err := threatsAPIRiskView(identity, record, settings, server.Now())
				if err != nil {
					return nil, err
				}
				detail.Set("risk", risk)
			}
		}
		return detail, nil
	}, false)
	return Out[apitypes.ThreatsGetIncidentOutput]{Value: result}, err
}

// UpdateIncident is POST {basePath}/threats/updateIncident. Triage: moves an incident between `open` and
// `investigating`, assigns it to an active identity of the tenant (`null` unassigns), or changes its severity.
// Resolved incidents are closed to changes. Requires iam:threats:manage on iam/threats/incidents/{id}; audited as
// `threat:incident-update`.
func (api *ThreatsAPI) UpdateIncident(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsUpdateIncidentInput]) (Out[apitypes.ThreatsUpdateIncidentOutput], error) {
	server := api.server
	incidentID, err := Text(input.Get("incidentId"), "incidentId")
	if err != nil {
		return Out[apitypes.ThreatsUpdateIncidentOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:threats:manage", threatsAPIIncidentResource(incidentID), func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		incident, err := server.Scoped(ctx, tx, ThreatCollections.Incidents, incidentID, tenantID)
		if err != nil {
			return nil, err
		}
		if incident.Get("status") == "resolved" {
			return nil, core.NewIamError("INVALID_TRANSITION", "Resolved incidents cannot be changed", 409)
		}
		status := incident.Get("status")
		if raw := input.Get("status"); !isUndefined(raw) {
			if status, err = threatsAPIOneOf(raw, threatsAPIIncidentStatuses, "status"); err != nil {
				return nil, err
			}
		}
		severity := incident.Get("severity")
		if raw := input.Get("severity"); !isUndefined(raw) {
			if severity, err = threatsAPIOneOf(raw, ThreatSeverities, "severity"); err != nil {
				return nil, err
			}
		}
		previousAssignee := incident.Get("assigneeId")
		rest := incident.Spread()
		rest.Delete("assigneeId")
		assigneeID := previousAssignee
		if raw := input.Get("assigneeId"); raw == nil {
			assigneeID = core.Undefined
		} else if !isUndefined(raw) {
			text, err := Text(raw, "assigneeId")
			if err != nil {
				return nil, err
			}
			assignee, err := server.ActiveIdentity(ctx, tx, text, tenantID)
			if err != nil {
				return nil, err
			}
			if assignee.Get("status") != "active" {
				return nil, invalidInput("Incidents are assigned to active identities")
			}
			assigneeID = assignee.Get("id")
		}
		changes := []string{}
		if status != incident.Get("status") {
			changes = append(changes, "status")
		}
		if severity != incident.Get("severity") {
			changes = append(changes, "severity")
		}
		if assigneeID != previousAssignee {
			changes = append(changes, "assigneeId")
		}
		record := rest.Set("status", status).Set("severity", severity)
		if !isUndefined(assigneeID) {
			record.Set("assigneeId", assigneeID)
		}
		record.Set("updatedAt", float64(server.Now()))
		next, err := tx.Put(ctx, ThreatCollections.Incidents, record)
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "threat:incident-update", tenantID, threatsAPIIncidentResource(jsString(incident.Get("id"))), "allow", false, core.NewObject(
			"changes", stringsOf(changes), "status", status, "severity", severity, "assigneeId", coalesce(assigneeID, nil),
		)); err != nil {
			return nil, err
		}
		return threatsAPIWithSubjectKind(ctx, tx, tenantID, next, nil)
	}, false)
	return Out[apitypes.ThreatsUpdateIncidentOutput]{Value: result}, err
}

// AddNote is POST {basePath}/threats/addNote. Adds an investigation note (1-4000 characters over several lines) to an
// incident, resolved ones included; at most 500 per incident. Requires iam:threats:manage on
// iam/threats/incidents/{id}; audited as `threat:note` (without the text).
func (api *ThreatsAPI) AddNote(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsAddNoteInput]) (Out[apitypes.ThreatsAddNoteOutput], error) {
	server := api.server
	incidentID, err := Text(input.Get("incidentId"), "incidentId")
	if err != nil {
		return Out[apitypes.ThreatsAddNoteOutput]{}, err
	}
	noteBody, err := threatsAPIMultiline(input.Get("body"), "body", 4000)
	if err != nil {
		return Out[apitypes.ThreatsAddNoteOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:threats:manage", threatsAPIIncidentResource(incidentID), func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		incident, err := server.Scoped(ctx, tx, ThreatCollections.Incidents, incidentID, tenantID)
		if err != nil {
			return nil, err
		}
		existing, err := tx.Find(ctx, ThreatCollections.Notes, core.NewObject("tenantId", tenantID, "incidentId", incident.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		if len(existing) >= threatsAPIMaxNotesPerIncident {
			return nil, core.NewIamError("LIMIT_EXCEEDED", "An incident holds at most "+core.NumberString(threatsAPIMaxNotesPerIncident)+" notes", 409)
		}
		note, err := tx.Insert(ctx, ThreatCollections.Notes, core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"incidentId", incident.Get("id"),
			"authorId", principal.Identity.Get("id"),
			"body", noteBody,
			"createdAt", float64(server.Now()),
		))
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "threat:note", tenantID, threatsAPIIncidentResource(jsString(incident.Get("id"))), "allow", false,
			core.NewObject("noteId", note.Get("id"), "length", float64(utf16Len(noteBody)))); err != nil {
			return nil, err
		}
		return note, nil
	}, false)
	return Out[apitypes.ThreatsAddNoteOutput]{Value: result}, err
}

// ResolveIncident is POST {basePath}/threats/resolveIncident. Closes an incident as `true-positive`,
// `false-positive` or `benign`, optionally with a closing note. Its open detections become resolved; a false positive
// or benign finding also takes their points out of the identities' risk (not for risk raised against the caller,
// unless a root administrator resolves). A new detection about the same subject opens a new incident. Requires
// iam:threats:manage on iam/threats/incidents/{id} and recent authentication; audited as `threat:incident-resolve`.
func (api *ThreatsAPI) ResolveIncident(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsResolveIncidentInput]) (Out[apitypes.ThreatsResolveIncidentOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.ThreatsResolveIncidentOutput], error) {
		return Out[apitypes.ThreatsResolveIncidentOutput]{}, err
	}
	incidentID, err := Text(input.Get("incidentId"), "incidentId")
	if err != nil {
		return fail(err)
	}
	resolution, err := threatsAPIOneOf(input.Get("resolution"), threatsAPIResolutions, "resolution")
	if err != nil {
		return fail(err)
	}
	note := ""
	hasNote := false
	if raw := input.Get("note"); !isUndefined(raw) {
		if note, err = threatsAPIMultiline(raw, "note", 4000); err != nil {
			return fail(err)
		}
		hasNote = true
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:threats:manage", threatsAPIIncidentResource(incidentID), func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		principalID := jsString(principal.Identity.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		incident, err := server.Scoped(ctx, tx, ThreatCollections.Incidents, incidentID, tenantID)
		if err != nil {
			return nil, err
		}
		if incident.Get("status") == "resolved" {
			return nil, core.NewIamError("INVALID_TRANSITION", "The incident is already resolved", 409)
		}
		detections, err := tx.Find(ctx, ThreatCollections.Detections, core.NewObject("tenantId", tenantID, "incidentId", incident.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		clears := resolution != "true-positive"
		if clears {
			identityIDs := make([]any, len(detections))
			for index, detection := range detections {
				identityIDs[index] = detection.Get("identityId")
			}
			own, err := api.clearsOwnRisk(ctx, tx, principal, identityIDs)
			if err != nil {
				return nil, err
			}
			if own {
				return nil, NewOperationDenied("Incidents that raised your own risk are closed as false positives by another administrator")
			}
		}
		now := server.Now()
		rest := incident.Spread()
		rest.Delete("uniqueKey")
		next, err := tx.Put(ctx, ThreatCollections.Incidents, rest.
			Set("status", "resolved").
			Set("resolution", resolution).
			Set("resolvedBy", principalID).
			Set("resolvedAt", float64(now)).
			Set("updatedAt", float64(now)))
		if err != nil {
			return nil, err
		}
		resolved := 0
		for _, detection := range detections {
			if detection.Get("status") == "open" {
				if _, err := tx.Put(ctx, ThreatCollections.Detections, detection.Spread().Set("status", "resolved")); err != nil {
					return nil, err
				}
				resolved++
			}
		}
		if clears {
			order := []string{}
			byIdentity := map[string][]string{}
			for _, detection := range detections {
				identityID := detection.Get("identityId")
				if !truthy(identityID) {
					continue
				}
				key := jsString(identityID)
				if _, seen := byIdentity[key]; !seen {
					order = append(order, key)
				}
				detectionID := jsString(detection.Get("id"))
				if !containsString(byIdentity[key], detectionID) {
					byIdentity[key] = append(byIdentity[key], detectionID)
				}
			}
			settings, err := threatsAPISettings(ctx, tx, tenantID)
			if err != nil {
				return nil, err
			}
			for _, identityID := range order {
				if err := api.dropContributions(ctx, tx, tenantID, identityID, byIdentity[identityID], settings, now, principalID); err != nil {
					return nil, err
				}
			}
		}
		if hasNote {
			if _, err := tx.Insert(ctx, ThreatCollections.Notes, core.NewObject(
				"id", ID(),
				"tenantId", tenantID,
				"incidentId", incident.Get("id"),
				"authorId", principalID,
				"body", note,
				"createdAt", float64(now),
			)); err != nil {
				return nil, err
			}
		}
		subject := incident.Get("subject")
		metadata := core.NewObject(
			"resolution", resolution,
			"severity", incident.Get("severity"),
			"subjectType", member(subject, "type"),
			"subjectId", member(subject, "id"),
			"detectionsResolved", float64(resolved),
		)
		if identityID := incident.Get("identityId"); truthy(identityID) {
			metadata.Set("identityId", identityID)
		}
		if err := server.Events.Audit(ctx, tx, principal, "threat:incident-resolve", tenantID, threatsAPIIncidentResource(jsString(incident.Get("id"))), "allow", false, metadata); err != nil {
			return nil, err
		}
		return threatsAPIWithSubjectKind(ctx, tx, tenantID, next, nil)
	}, false)
	return Out[apitypes.ThreatsResolveIncidentOutput]{Value: result}, err
}

// Respond is POST {basePath}/threats/respond. Responds by hand to an incident (its subject), an identity or a
// network: exactly one target, one to five actions (`revoke-sessions`, `forget-devices`, `contain`,
// `suspend-clearance`, `block-network` with `durationMs`, `notify`) run in order. A response to an identity or network
// with an open incident is filed under it. Actions that do not apply to the target, or that protections refuse, come
// back `skipped` with a reason. Requires iam:threats:respond on iam/threats/incidents/{id} (iam/threats/responses
// without an incident) and recent authentication, and `suspend-clearance` also iam:clearances:suspend on
// iam/clearances/{identityId} (and the `clearances` option); each action is audited as `threat:{action}`.
func (api *ThreatsAPI) Respond(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsRespondInput]) (Out[apitypes.ThreatsRespondOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.ThreatsRespondOutput], error) {
		return Out[apitypes.ThreatsRespondOutput]{}, err
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	var incidentID, identityID, network *string
	if raw := input.Get("incidentId"); !isUndefined(raw) {
		text, err := Text(raw, "incidentId")
		if err != nil {
			return fail(err)
		}
		incidentID = &text
	}
	if raw := input.Get("identityId"); !isUndefined(raw) {
		text, err := Text(raw, "identityId")
		if err != nil {
			return fail(err)
		}
		identityID = &text
	}
	if raw := input.Get("network"); !isUndefined(raw) {
		text, err := Text(raw, "network", 64)
		if err != nil {
			return fail(err)
		}
		trimmed := core.JSTrim(text)
		network = &trimmed
	}
	targets := 0
	for _, target := range []*string{incidentID, identityID, network} {
		if target != nil {
			targets++
		}
	}
	if targets != 1 {
		return fail(invalidInput("Respond to exactly one of incidentId, identityId or network"))
	}
	if network != nil && !core.IsIPRange(*network) {
		return fail(invalidInput("network must be an IPv4/IPv6 address or CIDR block"))
	}
	actions, err := threatsAPIResponseActionsOf(input.Get("actions"), "actions")
	if err != nil {
		return fail(err)
	}
	resource := "threats/responses"
	if incidentID != nil && *incidentID != "" {
		resource = threatsAPIIncidentResource(*incidentID)
	}
	responses, err := Operate(ctx, server.Operations, credential, tenantID, "iam:threats:respond", resource, func(ctx context.Context, call MutationContext) ([]*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		realmID := jsString(call.Tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		text, err := Text(input.Get("reason"), "reason", 512)
		if err != nil {
			return nil, err
		}
		reason := core.JSTrim(text)
		settings, err := threatsAPISettings(ctx, tx, realmID)
		if err != nil {
			return nil, err
		}
		openIncident := func(subject *core.Object) (*core.Object, error) {
			found, err := tx.Find(ctx, ThreatCollections.Incidents, core.NewObject(
				"tenantId", realmID,
				"uniqueKey", "open:"+jsString(subject.Get("type"))+":"+jsString(subject.Get("id")),
			), nil)
			if err != nil || len(found) == 0 {
				return nil, err
			}
			return found[0], nil
		}
		var target *core.Object
		switch {
		case incidentID != nil:
			incident, err := server.Scoped(ctx, tx, ThreatCollections.Incidents, *incidentID, realmID)
			if err != nil {
				return nil, err
			}
			target = core.NewObject("subject", incident.Get("subject"), "incidentId", incident.Get("id"))
			if identity := incident.Get("identityId"); truthy(identity) {
				target.Set("identityId", identity)
			}
			if incidentNetwork := incident.Get("network"); truthy(incidentNetwork) {
				target.Set("network", incidentNetwork)
			}
		case identityID != nil:
			identity, err := server.ActiveIdentity(ctx, tx, *identityID, realmID)
			if err != nil {
				return nil, err
			}
			subject := core.NewObject("type", "identity", "id", identity.Get("id"), "name", threatsAPIPersonLabel(identity))
			incident, err := openIncident(subject)
			if err != nil {
				return nil, err
			}
			target = core.NewObject("subject", subject, "identityId", identity.Get("id"))
			if incident != nil {
				target.Set("incidentId", incident.Get("id"))
			}
		default:
			subject := core.NewObject("type", "network", "id", *network)
			incident, err := openIncident(subject)
			if err != nil {
				return nil, err
			}
			target = core.NewObject("subject", subject, "network", *network)
			if incident != nil {
				target.Set("incidentId", incident.Get("id"))
			}
		}
		taken := []*core.Object{}
		for _, action := range actions {
			request := core.NewObject("action", action).Assign(target)
			request.Set("reason", reason)
			request.SetRaw("actor", threatsAPIActor(principal))
			response, err := ApplyResponse(ctx, server, tx, realmID, request, settings, nil)
			if err != nil {
				return nil, err
			}
			taken = append(taken, response)
		}
		return taken, nil
	}, false)
	if err != nil {
		return fail(err)
	}
	if err := AfterThreatResponses(ctx, server, tenantID, responses); err != nil {
		return fail(err)
	}
	return Out[apitypes.ThreatsRespondOutput]{Value: threatsAPIList(responses)}, nil
}

// Release is POST {basePath}/threats/release. Lifts a containment: the identity becomes active again and signs in as
// usual (its sessions stay ended, its API keys work again); its risk score is kept. Only an identity the threats
// module contained and that is still disabled can be released (INVALID_TRANSITION otherwise), a root administrator
// only by root. Requires iam:threats:respond on iam/threats/responses and recent authentication; audited as
// `threat:release`.
func (api *ThreatsAPI) Release(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsReleaseInput]) (Out[apitypes.ThreatsReleaseOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.ThreatsReleaseOutput], error) {
		return Out[apitypes.ThreatsReleaseOutput]{}, err
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	identityID, err := Text(input.Get("identityId"), "identityId")
	if err != nil {
		return fail(err)
	}
	note := ""
	if raw := input.Get("note"); !isUndefined(raw) {
		text, err := Text(raw, "note", 512)
		if err != nil {
			return fail(err)
		}
		note = core.JSTrim(text)
	}
	response, err := Operate(ctx, server.Operations, credential, tenantID, "iam:threats:respond", "threats/responses", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		if err := server.Auth.RequireRecent(call.Principal.Auth()); err != nil {
			return nil, err
		}
		return ReleaseIdentity(ctx, server, call.Tx, jsString(call.Tenant.Get("id")), identityID, threatsAPIActor(call.Principal), note)
	}, false)
	if err != nil {
		return fail(err)
	}
	if err := AfterThreatResponses(ctx, server, tenantID, []*core.Object{response}); err != nil {
		return fail(err)
	}
	return Out[apitypes.ThreatsReleaseOutput]{Value: response}, nil
}

// ListRisk is POST {basePath}/threats/listRisk. Identities whose effective risk is at least `minLevel` (default
// `low`), or that are contained, highest score first. Requires iam:threats:read on iam/threats/risk.
func (api *ThreatsAPI) ListRisk(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsListRiskInput]) (Out[apitypes.ThreatsListRiskOutput], error) {
	server := api.server
	limit, offset, err := threatsAPIPaging(input)
	if err != nil {
		return Out[apitypes.ThreatsListRiskOutput]{}, err
	}
	floor := "low"
	if raw := input.Get("minLevel"); !isUndefined(raw) {
		if floor, err = threatsAPIOneOf(raw, threatsAPIRaisedLevels, "minLevel"); err != nil {
			return Out[apitypes.ThreatsListRiskOutput]{}, err
		}
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:threats:read", "threats/risk", func(ctx context.Context, call MutationContext) (any, error) {
		tx := call.Tx
		tenantID := jsString(call.Tenant.Get("id"))
		settings, err := threatsAPISettings(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		now := server.Now()
		identities := []*core.Object{}
		records, err := tx.Find(ctx, ThreatCollections.Risk, core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			risk, err := EffectiveRisk(record, now, threatsAPIHalfLife(settings))
			if err != nil {
				return nil, err
			}
			atLeast, err := RiskLevelAtLeast(jsString(risk.Get("level")), floor)
			if err != nil {
				return nil, err
			}
			if !atLeast && !truthy(record.Get("contained")) {
				continue
			}
			identity, err := tx.Get(ctx, "identities", jsString(record.Get("identityId")))
			if err != nil {
				return nil, err
			}
			if identity == nil || identity.Get("tenantId") != tenantID || identity.Get("status") == "deleted" {
				continue
			}
			if atLeast || truthy(threatsAPIContainment(identity, record)) {
				view, err := threatsAPIRiskView(identity, record, settings, now)
				if err != nil {
					return nil, err
				}
				identities = append(identities, view)
			}
		}
		sort.SliceStable(identities, func(i, j int) bool {
			difference := jsNumber(identities[j].Get("score")) - jsNumber(identities[i].Get("score"))
			if difference != 0 && !math.IsNaN(difference) {
				return difference < 0
			}
			return compareUTF16(jsString(identities[i].Get("identityId")), jsString(identities[j].Get("identityId"))) < 0
		})
		return core.NewObject("identities", threatsAPIList(threatsAPIPage(identities, offset, limit)), "total", float64(len(identities))), nil
	}, false)
	return Out[apitypes.ThreatsListRiskOutput]{Value: result}, err
}

// GetRisk is POST {basePath}/threats/getRisk. One identity's risk (level `none` when nothing was ever detected).
// Requires iam:threats:read on iam/threats/risk/{id}.
func (api *ThreatsAPI) GetRisk(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsGetRiskInput]) (Out[apitypes.ThreatsGetRiskOutput], error) {
	server := api.server
	identityID, err := Text(input.Get("identityId"), "identityId")
	if err != nil {
		return Out[apitypes.ThreatsGetRiskOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:threats:read", threatsAPIRiskResource(identityID), func(ctx context.Context, call MutationContext) (any, error) {
		tx := call.Tx
		tenantID := jsString(call.Tenant.Get("id"))
		identity, err := server.Scoped(ctx, tx, "identities", identityID, tenantID)
		if err != nil {
			return nil, err
		}
		record, err := threatsAPIRiskRecord(ctx, tx, tenantID, jsString(identity.Get("id")))
		if err != nil {
			return nil, err
		}
		settings, err := threatsAPISettings(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		return threatsAPIRiskView(identity, record, settings, server.Now())
	}, false)
	return Out[apitypes.ThreatsGetRiskOutput]{Value: result}, err
}

// SetRisk is POST {basePath}/threats/setRisk. Sets an identity's risk by hand: `low`, `medium` or `high` sets a floor
// ("confirmed compromised") that holds until `expiresInMs` (one hour to 90 days) or indefinitely; `none` clears the
// override and every detection's contribution. Nobody sets their own risk. Requires iam:threats:respond on
// iam/threats/risk/{id} and recent authentication; audited as `threat:risk-override`, plus `threat:risk-change` when
// the effective level moves.
func (api *ThreatsAPI) SetRisk(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsSetRiskInput]) (Out[apitypes.ThreatsSetRiskOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.ThreatsSetRiskOutput], error) {
		return Out[apitypes.ThreatsSetRiskOutput]{}, err
	}
	identityID, err := Text(input.Get("identityId"), "identityId")
	if err != nil {
		return fail(err)
	}
	level, err := threatsAPIOneOf(input.Get("level"), RiskLevels, "level")
	if err != nil {
		return fail(err)
	}
	var expiresInMs *float64
	if raw := input.Get("expiresInMs"); !isUndefined(raw) {
		value, err := Integer(raw, "expiresInMs", threatsAPIHour, 90*threatsAPIDay)
		if err != nil {
			return fail(err)
		}
		expiresInMs = &value
	}
	if level == "none" && expiresInMs != nil {
		return fail(invalidInput("expiresInMs applies to a raised level only"))
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:threats:respond", threatsAPIRiskResource(identityID), func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		principalID := jsString(principal.Identity.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		text, err := Text(input.Get("reason"), "reason", 512)
		if err != nil {
			return nil, err
		}
		reason := core.JSTrim(text)
		identity, err := server.Scoped(ctx, tx, "identities", identityID, tenantID)
		if err != nil {
			return nil, err
		}
		subjectID := jsString(identity.Get("id"))
		if identity.Get("id") == principal.Identity.Get("id") {
			return nil, NewOperationDenied("Your own risk level is set by another administrator")
		}
		settings, err := threatsAPISettings(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		now := server.Now()
		record, err := threatsAPIRiskRecord(ctx, tx, tenantID, subjectID)
		if err != nil {
			return nil, err
		}
		cleared := 0
		var expiresAt any = core.Undefined
		if level == "none" {
			if record != nil {
				contributions, _ := record.Get("contributions").([]any)
				cleared = len(contributions)
				rest := record.Spread()
				rest.Delete("override")
				if _, err := tx.Put(ctx, ThreatCollections.Risk, rest.Set("contributions", []any{})); err != nil {
					return nil, err
				}
			}
		} else {
			if expiresInMs != nil {
				expiresAt = float64(now) + *expiresInMs
			}
			override := core.NewObject("level", level, "reason", reason, "by", principalID, "at", float64(now))
			if !isUndefined(expiresAt) {
				override.Set("expiresAt", expiresAt)
			}
			if record != nil {
				_, err = tx.Put(ctx, ThreatCollections.Risk, record.Spread().Set("override", override))
			} else {
				_, err = tx.Insert(ctx, ThreatCollections.Risk, core.NewObject(
					"id", subjectID,
					"tenantId", tenantID,
					"identityId", subjectID,
					"contributions", []any{},
					"score", 0.0,
					"level", "none",
					"override", override,
					"updatedAt", float64(now),
				))
			}
			if err != nil {
				return nil, err
			}
		}
		metadata := core.NewObject("level", level, "reason", reason)
		if !isUndefined(expiresAt) {
			metadata.Set("expiresAt", expiresAt)
		}
		if level == "none" {
			metadata.Set("clearedContributions", float64(cleared))
		}
		if err := server.Events.Audit(ctx, tx, principal, "threat:risk-override", tenantID, subjectID, "allow", false, metadata); err != nil {
			return nil, err
		}
		if _, err := RecomputeRisk(ctx, server, tx, tenantID, subjectID, settings, now, principalID, nil); err != nil {
			return nil, err
		}
		current, err := threatsAPIRiskRecord(ctx, tx, tenantID, subjectID)
		if err != nil {
			return nil, err
		}
		return threatsAPIRiskView(identity, current, settings, now)
	}, false)
	return Out[apitypes.ThreatsSetRiskOutput]{Value: result}, err
}

// Timeline is POST {basePath}/threats/timeline. The identity's recent audit trail, newest first: events it performed
// and events about it, from `since` up to and including `until` (epoch milliseconds, after `since`; default now),
// where `since` defaults to seven days before `until`; at most `limit` (default 200, up to 500). Requires
// iam:threats:read on iam/threats/risk/{id}.
func (api *ThreatsAPI) Timeline(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsTimelineInput]) (Out[apitypes.ThreatsTimelineOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.ThreatsTimelineOutput], error) {
		return Out[apitypes.ThreatsTimelineOutput]{}, err
	}
	identityID, err := Text(input.Get("identityId"), "identityId")
	if err != nil {
		return fail(err)
	}
	limit, err := Integer(coalesce(input.Get("limit"), 200.0), "limit", 1, 500)
	if err != nil {
		return fail(err)
	}
	var since, until *float64
	if raw := input.Get("since"); !isUndefined(raw) {
		value, err := Integer(raw, "since", 0, threatsAPIMaxSafeInteger)
		if err != nil {
			return fail(err)
		}
		since = &value
	}
	if raw := input.Get("until"); !isUndefined(raw) {
		value, err := Integer(raw, "until", 0, threatsAPIMaxSafeInteger)
		if err != nil {
			return fail(err)
		}
		until = &value
	}
	if since != nil && until != nil && *until <= *since {
		return fail(invalidInput("until must be after since"))
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:threats:read", threatsAPIRiskResource(identityID), func(ctx context.Context, call MutationContext) (any, error) {
		tx := call.Tx
		tenantID := jsString(call.Tenant.Get("id"))
		identity, err := server.Scoped(ctx, tx, "identities", identityID, tenantID)
		if err != nil {
			return nil, err
		}
		from := 0.0
		if since != nil {
			from = *since
		} else {
			end := float64(server.Now())
			if until != nil {
				end = *until
			}
			from = math.Max(0, end-7*threatsAPIDay)
		}
		count := int(limit)
		subject := identity.Get("id")
		events, err := core.FindOrdered(ctx, tx, "audit", core.NewObject("tenantId", tenantID),
			core.OrderOptions{Field: "timestamp", Direction: "desc", From: &from, To: until, Limit: &count},
			func(event *core.Object) bool {
				return event.Get("actorId") == subject || event.Get("resourceId") == subject || event.Get("originalActorId") == subject
			})
		if err != nil {
			return nil, err
		}
		return threatsAPIList(events), nil
	}, false)
	return Out[apitypes.ThreatsTimelineOutput]{Value: result}, err
}

// ListPlaybooks is POST {basePath}/threats/listPlaybooks. The tenant's playbooks by name. Requires iam:threats:read on
// iam/threats/playbooks.
func (api *ThreatsAPI) ListPlaybooks(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsListPlaybooksInput]) (Out[apitypes.ThreatsListPlaybooksOutput], error) {
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:threats:read", "threats/playbooks", func(ctx context.Context, call MutationContext) (any, error) {
		playbooks, err := call.Tx.Find(ctx, ThreatCollections.Playbooks, core.NewObject("tenantId", call.Tenant.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(playbooks, func(i, j int) bool {
			return localeCompare(jsString(playbooks[i].Get("name")), jsString(playbooks[j].Get("name"))) < 0
		})
		return threatsAPIList(playbooks), nil
	}, false)
	return Out[apitypes.ThreatsListPlaybooksOutput]{Value: result}, err
}

// CreatePlaybook is POST {basePath}/threats/createPlaybook. Defines an automatic response: when a new detection
// matches `trigger` (rules, minimum severity, subject types; fields left out match everything), `actions` run in
// order as the threat-detection actor. Automatic actions never contain owners or root administrators (nor suspend
// their clearances), and at most `maxAutomaticContainments` identities are contained per run. Names are unique per
// tenant; at most 50 playbooks. Requires iam:threats:manage on iam/threats/playbooks and recent authentication, plus
// iam:clearances:suspend on iam/clearances for a playbook that suspends clearances (FEATURE_DISABLED without the
// `clearances` option); audited as `threat:playbook-create`.
func (api *ThreatsAPI) CreatePlaybook(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsCreatePlaybookInput]) (Out[apitypes.ThreatsCreatePlaybookOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:threats:manage", "threats/playbooks", func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		principalID := jsString(principal.Identity.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		name, err := threatsAPIPlaybookName(input.Get("name"))
		if err != nil {
			return nil, err
		}
		description := ""
		if raw := input.Get("description"); !isUndefined(raw) {
			text, err := Text(raw, "description", 512)
			if err != nil {
				return nil, err
			}
			description = core.JSTrim(text)
		}
		enabled := true
		if raw := input.Get("enabled"); !isUndefined(raw) {
			if enabled, err = threatsAPIFlag(raw, "enabled"); err != nil {
				return nil, err
			}
		}
		trigger, err := threatsAPIPlaybookTrigger(input.Get("trigger"))
		if err != nil {
			return nil, err
		}
		actions, err := threatsAPIResponseActionsOf(input.Get("actions"), "actions")
		if err != nil {
			return nil, err
		}
		if threatsAPISuspendsClearances(actions) {
			if err := api.assertMaySuspendClearances(ctx, tx, principal, tenantID); err != nil {
				return nil, err
			}
		}
		uniqueKey := "name:" + core.JSLower(name)
		existing, err := tx.Find(ctx, ThreatCollections.Playbooks, core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		for _, playbook := range existing {
			if playbook.Get("uniqueKey") == uniqueKey {
				return nil, core.NewIamError("CONFLICT", "A playbook with this name exists", 409)
			}
		}
		if len(existing) >= threatsAPIMaxPlaybooks {
			return nil, core.NewIamError("LIMIT_EXCEEDED", "A tenant can define at most "+core.NumberString(threatsAPIMaxPlaybooks)+" playbooks", 409)
		}
		now := float64(server.Now())
		record := core.NewObject("id", ID(), "tenantId", tenantID, "uniqueKey", uniqueKey, "name", name)
		if description != "" {
			record.Set("description", description)
		}
		record.Set("enabled", enabled)
		record.Set("trigger", trigger)
		record.Set("actions", actions)
		record.Set("createdAt", now)
		record.Set("createdBy", principalID)
		record.Set("updatedAt", now)
		record.Set("updatedBy", principalID)
		record.Set("runs", 0.0)
		playbook, err := tx.Insert(ctx, ThreatCollections.Playbooks, record)
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "threat:playbook-create", tenantID, threatsAPIPlaybookResource(jsString(playbook.Get("id"))), "allow", false, threatsAPIPlaybookMetadata(playbook)); err != nil {
			return nil, err
		}
		return playbook, nil
	}, false)
	return Out[apitypes.ThreatsCreatePlaybookOutput]{Value: result}, err
}

// UpdatePlaybook is POST {basePath}/threats/updatePlaybook. Changes a playbook; fields left out keep their value and
// `description: null` clears the description. Requires iam:threats:manage on iam/threats/playbooks/{id} and recent
// authentication; audited as `threat:playbook-update` with the settings before and after.
func (api *ThreatsAPI) UpdatePlaybook(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsUpdatePlaybookInput]) (Out[apitypes.ThreatsUpdatePlaybookOutput], error) {
	server := api.server
	playbookID, err := Text(input.Get("playbookId"), "playbookId")
	if err != nil {
		return Out[apitypes.ThreatsUpdatePlaybookOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:threats:manage", threatsAPIPlaybookResource(playbookID), func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		playbook, err := server.Scoped(ctx, tx, ThreatCollections.Playbooks, playbookID, tenantID)
		if err != nil {
			return nil, err
		}
		name := playbook.Get("name")
		if raw := input.Get("name"); !isUndefined(raw) {
			if name, err = threatsAPIPlaybookName(raw); err != nil {
				return nil, err
			}
		}
		uniqueKey := "name:" + core.JSLower(jsString(name))
		others, err := tx.Find(ctx, ThreatCollections.Playbooks, core.NewObject("tenantId", tenantID, "uniqueKey", uniqueKey), nil)
		if err != nil {
			return nil, err
		}
		for _, other := range others {
			if other.Get("id") != playbook.Get("id") {
				return nil, core.NewIamError("CONFLICT", "A playbook with this name exists", 409)
			}
		}
		description := playbook.Get("description")
		if raw := input.Get("description"); raw == nil {
			description = core.Undefined
		} else if !isUndefined(raw) {
			text, err := Text(raw, "description", 512)
			if err != nil {
				return nil, err
			}
			description = core.JSTrim(text)
		}
		rest := playbook.Spread()
		rest.Delete("description")
		record := rest.Set("uniqueKey", uniqueKey).Set("name", name)
		if truthy(description) {
			record.Set("description", description)
		}
		enabled := playbook.Get("enabled")
		if raw := input.Get("enabled"); !isUndefined(raw) {
			if enabled, err = threatsAPIFlag(raw, "enabled"); err != nil {
				return nil, err
			}
		}
		record.Set("enabled", enabled)
		trigger := playbook.Get("trigger")
		if raw := input.Get("trigger"); !isUndefined(raw) {
			if trigger, err = threatsAPIPlaybookTrigger(raw); err != nil {
				return nil, err
			}
		}
		record.Set("trigger", trigger)
		actions := playbook.Get("actions")
		if raw := input.Get("actions"); !isUndefined(raw) {
			if actions, err = threatsAPIResponseActionsOf(raw, "actions"); err != nil {
				return nil, err
			}
		}
		record.Set("actions", actions)
		record.Set("updatedAt", float64(server.Now()))
		record.Set("updatedBy", principal.Identity.Get("id"))
		next, err := tx.Put(ctx, ThreatCollections.Playbooks, record)
		if err != nil {
			return nil, err
		}
		// Widening what a playbook that suspends clearances does (adding the action, changing what triggers it, or
		// switching it on) takes what writing one takes; renaming, describing or switching it off does not. A refusal
		// rolls the change back.
		if threatsAPISuspendsClearances(next.Get("actions")) &&
			(!threatsAPISuspendsClearances(playbook.Get("actions")) ||
				threatsAPIStringify(next.Get("trigger")) != threatsAPIStringify(playbook.Get("trigger")) ||
				(truthy(next.Get("enabled")) && !truthy(playbook.Get("enabled")))) {
			if err := api.assertMaySuspendClearances(ctx, tx, principal, tenantID); err != nil {
				return nil, err
			}
		}
		if err := server.Events.Audit(ctx, tx, principal, "threat:playbook-update", tenantID, threatsAPIPlaybookResource(jsString(playbook.Get("id"))), "allow", false,
			core.NewObject("before", threatsAPIPlaybookMetadata(playbook), "after", threatsAPIPlaybookMetadata(next))); err != nil {
			return nil, err
		}
		return next, nil
	}, false)
	return Out[apitypes.ThreatsUpdatePlaybookOutput]{Value: result}, err
}

// DeletePlaybook is POST {basePath}/threats/deletePlaybook. Deletes a playbook; responses it already took stay on
// their incidents. Requires iam:threats:manage on iam/threats/playbooks/{id} and recent authentication; audited as
// `threat:playbook-delete`.
func (api *ThreatsAPI) DeletePlaybook(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsDeletePlaybookInput]) (Out[apitypes.ThreatsDeletePlaybookOutput], error) {
	server := api.server
	playbookID, err := Text(input.Get("playbookId"), "playbookId")
	if err != nil {
		return Out[apitypes.ThreatsDeletePlaybookOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:threats:manage", threatsAPIPlaybookResource(playbookID), func(ctx context.Context, call MutationContext) (any, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		playbook, err := server.Scoped(ctx, tx, ThreatCollections.Playbooks, playbookID, tenantID)
		if err != nil {
			return nil, err
		}
		if err := tx.Delete(ctx, ThreatCollections.Playbooks, jsString(playbook.Get("id"))); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "threat:playbook-delete", tenantID, threatsAPIPlaybookResource(jsString(playbook.Get("id"))), "allow", false,
			core.NewObject("name", playbook.Get("name"))); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	return Out[apitypes.ThreatsDeletePlaybookOutput]{Value: result}, err
}

// Detect is POST {basePath}/threats/detect. Runs detection for the tenant now instead of waiting for the scheduled
// `iam.detectThreats()` job, and returns what the run did. Requires iam:threats:manage on iam/threats/detections.
func (api *ThreatsAPI) Detect(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsDetectInput]) (Out[apitypes.ThreatsDetectOutput], error) {
	// The engine opens its own transactions, so it runs once the permission check has committed.
	tenantID, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:threats:manage", "threats/detections", func(ctx context.Context, call MutationContext) (string, error) {
		return jsString(call.Tenant.Get("id")), nil
	}, false)
	if err != nil {
		return Out[apitypes.ThreatsDetectOutput]{}, err
	}
	run, err := DetectThreats(ctx, api.server, core.NewObject("tenantId", tenantID))
	if err != nil {
		return Out[apitypes.ThreatsDetectOutput]{}, err
	}
	return Out[apitypes.ThreatsDetectOutput]{Value: run}, nil
}

// threatsAPIIncrement is `counts[key]++` (an unknown key becomes NaN, as `undefined + 1`).
func threatsAPIIncrement(counts *core.Object, key string) {
	value := counts.Get(key)
	if isUndefined(value) {
		counts.Set(key, math.NaN())
		return
	}
	counts.Set(key, jsNumber(value)+1)
}

// Summary is POST {basePath}/threats/summary. Counts for a dashboard: open incidents by severity, incidents under
// investigation, identities by risk level, contained identities, detections in the last 24 hours by rule, and when
// detection last ran. Requires iam:threats:read on iam/threats/incidents.
func (api *ThreatsAPI) Summary(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsSummaryInput]) (Out[apitypes.ThreatsSummaryOutput], error) {
	server := api.server
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:threats:read", "threats/incidents", func(ctx context.Context, call MutationContext) (any, error) {
		tx := call.Tx
		tenantID := jsString(call.Tenant.Get("id"))
		now := server.Now()
		settings, err := threatsAPISettings(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		openIncidents := core.NewObject("low", 0.0, "medium", 0.0, "high", 0.0, "critical", 0.0)
		riskyIdentities := core.NewObject("low", 0.0, "medium", 0.0, "high", 0.0)
		byRule := core.NewObject()
		open, err := tx.Find(ctx, ThreatCollections.Incidents, core.NewObject("tenantId", tenantID, "status", "open"), nil)
		if err != nil {
			return nil, err
		}
		for _, incident := range open {
			threatsAPIIncrement(openIncidents, jsString(incident.Get("severity")))
		}
		investigating, err := tx.Find(ctx, ThreatCollections.Incidents, core.NewObject("tenantId", tenantID, "status", "investigating"), nil)
		if err != nil {
			return nil, err
		}
		contained := 0
		records, err := tx.Find(ctx, ThreatCollections.Risk, core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			risk, err := EffectiveRisk(record, now, threatsAPIHalfLife(settings))
			if err != nil {
				return nil, err
			}
			level := jsString(risk.Get("level"))
			if level == "none" && !truthy(record.Get("contained")) {
				continue
			}
			identity, err := tx.Get(ctx, "identities", jsString(record.Get("identityId")))
			if err != nil {
				return nil, err
			}
			if identity == nil || identity.Get("tenantId") != tenantID || identity.Get("status") == "deleted" {
				continue
			}
			if level != "none" {
				threatsAPIIncrement(riskyIdentities, level)
			}
			if truthy(threatsAPIContainment(identity, record)) {
				contained++
			}
		}
		from := float64(now) - threatsAPIDay
		detections, err := core.FindOrdered(ctx, tx, ThreatCollections.Detections, core.NewObject("tenantId", tenantID), core.OrderOptions{Field: "detectedAt", From: &from}, nil)
		if err != nil {
			return nil, err
		}
		for _, detection := range detections {
			ruleID := jsString(detection.Get("ruleId"))
			byRule.Set(ruleID, jsNumber(coalesce(byRule.Get(ruleID), 0.0))+1)
		}
		summary := core.NewObject(
			"openIncidents", openIncidents,
			"investigating", float64(len(investigating)),
			"riskyIdentities", riskyIdentities,
			"contained", float64(contained),
			"detections24h", float64(len(detections)),
			"byRule24h", byRule,
		)
		cursor, err := tx.Get(ctx, ThreatCollections.Cursors, tenantID)
		if err != nil {
			return nil, err
		}
		if cursor != nil && cursor.Get("tenantId") == tenantID {
			summary.SetRaw("lastRunAt", cursor.Get("updatedAt"))
		}
		return summary, nil
	}, false)
	return Out[apitypes.ThreatsSummaryOutput]{Value: result}, err
}

// ReportSuspicious is POST {basePath}/threats/reportSuspicious. "This wasn't me": the signed-in person reports
// suspicious activity on their own account, optionally with a note (up to 1000 characters) and the id of the session
// they do not recognize. Records a `user-reported` detection (raising their risk and opening an incident
// administrators see), ends every other session of the account except API keys (the reporting session stays) and its
// pending sign-in challenges, forgets remembered devices, and runs the tenant's playbooks. Needs only an ordinary
// sign-in session of the tenant (not an impersonation); at most five reports a day; refused with FEATURE_DISABLED
// when the tenant turned the rule off. Audited as `threat:user-report`, with the two responses as
// `threat:revoke-sessions` and `threat:forget-devices`.
func (api *ThreatsAPI) ReportSuspicious(ctx context.Context, credential core.CredentialInput, input In[apitypes.ThreatsReportSuspiciousInput]) (Out[apitypes.ThreatsReportSuspiciousOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.ThreatsReportSuspiciousOutput], error) {
		return Out[apitypes.ThreatsReportSuspiciousOutput]{}, err
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	var note any = core.Undefined
	if raw := input.Get("note"); !isUndefined(raw) {
		text, err := threatsAPIMultiline(raw, "note", 1000)
		if err != nil {
			return fail(err)
		}
		note = text
	}
	var sessionID any = core.Undefined
	if raw := input.Get("sessionId"); !isUndefined(raw) {
		text, err := Text(raw, "sessionId")
		if err != nil {
			return fail(err)
		}
		sessionID = text
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return fail(err)
	}
	outcome, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (threatsAPIOutcome, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return threatsAPIOutcome{}, err
		}
		if truthy(principal.Session.Get("impersonatorId")) {
			return threatsAPIOutcome{}, core.NewIamError("IMPERSONATION_RESTRICTED", "Suspicious activity cannot be reported while impersonating", 403)
		}
		identity, session := principal.Identity, principal.Session
		if session.Get("kind") != "user" || !ActsInOwnRight(session) || session.Get("tenantId") != tenantID || identity.Get("tenantId") != tenantID {
			return threatsAPIOutcome{}, core.NewIamError("ACCESS_DENIED", "Suspicious activity is reported from a sign-in session of the account’s own tenant", 403)
		}
		realm, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return threatsAPIOutcome{}, err
		}
		settings, err := threatsAPISettings(ctx, tx, tenantID)
		if err != nil {
			return threatsAPIOutcome{}, err
		}
		rule := threatsAPIRule(settings, "user-reported")
		if !truthy(rule.Get("enabled")) {
			return threatsAPIOutcome{}, core.NewIamError("FEATURE_DISABLED", "This organization does not take reports of suspicious activity", 403)
		}
		now := server.Now()
		identityID := identity.Get("id")
		from := float64(now) - threatsAPIDay
		recent, err := core.FindOrdered(ctx, tx, ThreatCollections.Detections, core.NewObject("tenantId", tenantID, "ruleId", "user-reported", "identityId", identityID),
			core.OrderOptions{Field: "detectedAt", From: &from}, nil)
		if err != nil {
			return threatsAPIOutcome{}, err
		}
		if len(recent) >= threatsAPIMaxReportsPerDay {
			return threatsAPIOutcome{}, core.NewIamError("LIMIT_EXCEEDED", "At most "+core.NumberString(threatsAPIMaxReportsPerDay)+" reports a day; administrators already have the earlier ones", 409)
		}
		if !isUndefined(sessionID) {
			reported, err := tx.Get(ctx, "sessions", jsString(sessionID))
			if err != nil {
				return threatsAPIOutcome{}, err
			}
			if reported != nil && (reported.Get("identityId") != identityID || reported.Get("tenantId") != tenantID) {
				return threatsAPIOutcome{}, core.NewIamError("NOT_FOUND", "Session not found", 404)
			}
		}
		label, err := threatsAPIDetectionLabel(identity)
		if err != nil {
			return threatsAPIOutcome{}, err
		}
		subject := core.NewObject("type", "identity", "id", identityID, "name", label)
		definition, err := ThreatRule("user-reported")
		if err != nil {
			return threatsAPIOutcome{}, err
		}
		metadata := core.NewObject()
		if !isUndefined(note) {
			metadata.Set("note", note)
		}
		if !isUndefined(sessionID) {
			metadata.Set("sessionId", sessionID)
		}
		candidate := core.NewObject(
			"ruleId", "user-reported",
			"severity", rule.Get("severity"),
			"title", definition.Get("title"),
			"summary", label+" reported activity on their account that was not them.",
			"subject", subject,
			"identityId", identityID,
			"dedupeKey", ID(),
			"occurredAt", float64(now),
			"evidence", core.NewObject(
				"eventIds", []any{},
				"count", 1.0,
				"firstAt", float64(now),
				"lastAt", float64(now),
				"identityIds", []any{identityID},
				"actions", []any{"threat:user-report"},
			),
			"metadata", metadata,
		)
		recorded, err := RecordDetection(ctx, server, tx, tenantID, candidate, settings, now)
		if err != nil {
			return threatsAPIOutcome{}, err
		}
		detection, _ := recorded.Get("detection").(*core.Object)
		incident, _ := recorded.Get("incident").(*core.Object)
		// The person's own responses, filed under the new incident: every other credential of the account ends (API
		// keys and the reporting session stay, pending sign-in challenges go), then remembered devices.
		own := func(action *core.Object) *core.Object {
			request := core.NewObject(
				"subject", subject,
				"identityId", identityID,
				"incidentId", member(incident, "id"),
				"detectionId", member(detection, "id"),
				"reason", "Reported by the account holder",
			)
			request.SetRaw("actor", threatsAPIActor(principal))
			request.Set("action", action)
			return request
		}
		revoked, err := ApplyResponse(ctx, server, tx, tenantID, own(core.NewObject("kind", "revoke-sessions", "keepApiKeys", true)), settings, nil)
		if err != nil {
			return threatsAPIOutcome{}, err
		}
		forgotten, err := ApplyResponse(ctx, server, tx, tenantID, own(core.NewObject("kind", "forget-devices")), settings, nil)
		if err != nil {
			return threatsAPIOutcome{}, err
		}
		count := func(response *core.Object, key string) float64 {
			if value, ok := member(response.Get("details"), key).(float64); ok {
				return value
			}
			return 0
		}
		report := core.NewObject(
			"detectionId", member(detection, "id"),
			"incidentId", member(incident, "id"),
			"sessionsEnded", count(revoked, "revoked"),
			"devicesForgotten", count(forgotten, "removed"),
		)
		auditMetadata := core.NewObject(
			"detectionId", report.Get("detectionId"),
			"incidentId", report.Get("incidentId"),
			"sessionsEnded", report.Get("sessionsEnded"),
			"devicesForgotten", report.Get("devicesForgotten"),
			"withNote", !isUndefined(note),
		)
		if !isUndefined(sessionID) {
			auditMetadata.Set("sessionId", sessionID)
		}
		if err := server.Events.Audit(ctx, tx, principal, "threat:user-report", jsString(realm.Get("id")), jsString(identityID), "allow", false, auditMetadata); err != nil {
			return threatsAPIOutcome{}, err
		}
		responses, err := api.playbooksFor(ctx, tx, tenantID, recorded, settings)
		if err != nil {
			return threatsAPIOutcome{}, err
		}
		return threatsAPIOutcome{value: report, responses: responses}, nil
	})
	if err != nil {
		return fail(err)
	}
	if err := AfterThreatResponses(ctx, server, tenantID, outcome.responses); err != nil {
		return fail(err)
	}
	return Out[apitypes.ThreatsReportSuspiciousOutput]{Value: outcome.value}, nil
}
